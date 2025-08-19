from __future__ import annotations

import stat
import struct
from functools import cached_property
from textwrap import dedent
from typing import TYPE_CHECKING, BinaryIO

from dissect.util import ts
from dissect.util.hash.jenkins import lookup8_quads
from dissect.util.stream import AlignedStream

from dissect.vmfs.address import (
    Address,
    FileBlockAddr,
    FileDescriptorAddr,
    SmallFileBlockAddr,
    address_fmt,
    address_type,
)
from dissect.vmfs.c_vmfs import FS3_AddrType, FS3_DescriptorType, FS3_ZeroLevelAddrType, FS6_DirBlockType, c_vmfs
from dissect.vmfs.exception import (
    FileNotFoundError,
    NotADirectoryError,
    NotAnRDMFileError,
    NotASymlinkError,
    VolumeNotAvailableError,
)
from dissect.vmfs.util import vmfs_uuid

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

    from dissect.vmfs.vmfs import VMFS


class DirEntry:
    """Directory entry representation.

    Args:
        vmfs: The VMFS instance this directory entry belongs to.
        address: The address of the file descriptor of this directory entry.
        name: The name of the directory entry.
        type: The type of the directory entry.
        raw: The raw directory entry struct, if available.
    """

    def __init__(
        self,
        vmfs: VMFS,
        address: int,
        name: str,
        type: FS3_DescriptorType,
        raw: c_vmfs.FS3_DirEntry | c_vmfs.FS6_DirEntry | None = None,
    ):
        self.vmfs = vmfs
        self.address = address
        self.name = name
        self.type = type
        self.raw = raw

    def __repr__(self) -> str:
        return f"<DirEntry name={self.name!r} address={address_fmt(self.address)} type={self.type}>"

    @property
    def file_descriptor(self) -> FileDescriptor:
        """Resolve this directory entry to its file descriptor."""
        return self.vmfs.file_descriptor(self.address)

    fd = file_descriptor


class FileDescriptor:
    """VMFS file descriptor implementation.

    See :class:`FileDescriptor5` and :class:`FileDescriptor6` for the VMFS5 and VMFS6 specific implementations.

    File descriptors are basically the inodes of VMFS and are all stored in the ``.fdc.sf`` resource.
    They are the combination of a lock block, a metadata block, and a bit of space for data.
    They start with lock information, which allows multiple ESXi hosts to stay in sync and place locks.
    This is followed by the ``FS3_FileMetadata`` structure is and contains fields that you would expect of an "inode".

    The file descriptor on disk roughly looks like the following:

    .. code-block:: c

        struct FS3_FileDescriptor {
            FS3_DiskLock lockBlock;
            FS3_FileMetadata metaBlock;
            char data[N];
        };

    On VMFS5, each block is 512 bytes large, and there's 1024 bytes of data.
    On VMFS6, the block size is determined by the metadata alignment. The entire file descriptor is
    two metadata blocks large, with the lock occupying the first metadata block, and the metadata and data
    occupying the second metadata block.

    Data is stored in a way that is also similar to many Unix filesystems. There is is some space at
    the end of the metadata for either a block pointer array, or some resident data.
    On VMFS5, the block pointer array and the data portion are stored in the same place, whereas on VMFS6,
    the block pointer array is aligned to the end of the file descriptor, and the data portion is aligned
    to the end of the metadata structure.

    The "zeroLevelAddrType" (or ZLA) determines how to interpret the block pointer array.
    They can generally be seperated into two kinds: direct and indirect. Like other filesystems, direct blocks refer
    directly to filesystem blocks, or offsets on disk, that contain data. With indirect blocks, you first need to go
    through one or more layers of indirection go get to the final filesystem block. View the documentation of
    :class:`BlockStream` for more information.

    Directory entries are also stored very differently between VMFS5 and VMFS6. Refer to :
    func:`FileDescriptor5._iterdir` and :func:`FileDescriptor6._iterdir` for more information on how these work.
    """

    def __init__(self, vmfs: VMFS, address: int):
        self.vmfs = vmfs
        self.address = address

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} address={address_fmt(self.address)}>"

    def debug(self) -> str:
        """Return a debug string for this file descriptor.

        Mimicks ``vmkfstool -D`` output.
        """

        fd = self.metadata
        li = self.lock_info

        type_str = {
            FS3_DescriptorType.DIRECTORY: "dir",
            FS3_DescriptorType.REGFILE: "reg",
            FS3_DescriptorType.SYSTEM: "sys",
            FS3_DescriptorType.RDM: "rdm",
        }.get(self.type, "oth")

        cluster, resource = FileDescriptorAddr.parse(self.address)
        affinity_cluster, affinity_resource = FileDescriptorAddr.parse(self.metadata.affinityFD)
        parent_cluster, parent_resource = FileDescriptorAddr.parse(self.metadata.parentFD)

        return dedent(f"""
        Lock [type {li.type:x} offset {li.addr.offset} v {li.token}, hb offset {li.hbAddr.offset}
        gen {li.hbGen.gen}, mode {li.mode}, owner {vmfs_uuid(li.owner)} mtime {li.mtime}
        num {li.numHolders} gblnum {li.gblNumHolders} gblgen {li.gblGen} gblbrk {li.gblBrk}]
        Addr <{address_type(self.address)}, {cluster}, {resource}>, gen {fd.generation}, links {fd.linkCount}, type {type_str}, flags {fd.flags:#x}, uid {fd.uid}, gid {fd.gid}, mode {fd.mode:o}
        len {fd.fileLength}, nb {fd.numBlocks} tbz {fd.numTBZBlocksLo | fd.numTBZBlocksHi << 32}, cow {fd.numCOWBlocksLo | fd.numCOWBlocksHi << 32}, newSinceEpoch {fd.newSinceEpochLo | fd.newSinceEpochHi << 32}, zla {fd.zeroLevelAddrType}, bs {fd.blockSize}
        affinityFD <{address_type(fd.affinityFD)},{affinity_cluster},{affinity_resource}>, parentFD <{address_type(fd.parentFD)},{parent_cluster},{parent_resource}>, tbzGranularityShift {fd.tbzGranularityShift}, numLFB {fd.numLFB}
        lastSFBClusterNum {fd.lastSFBClusterNum}, numPreAllocBlocks {fd.numPreAllocBlocks}, numPointerBlocks {fd.numPointerBlocks}
        """).strip()  # noqa: E501

    @staticmethod
    def from_bytes(vmfs: VMFS, address: int, buf: bytes) -> FileDescriptor | FileDescriptor5 | FileDescriptor6:
        """Create a :class:`FileDescriptor5` or :class:`FileDescriptor6` from a bytes buffer."""
        if vmfs.is_vmfs5:
            cls = FileDescriptor5
        elif vmfs.is_vmfs6:
            cls = FileDescriptor6
        else:
            cls = FileDescriptor

        obj = cls(vmfs, address)
        obj.raw = memoryview(buf)
        return obj

    @cached_property
    def raw(self) -> memoryview:
        """The raw buffer of this file descriptor."""
        return memoryview(self.vmfs.resources.FD.read(self.address))

    @cached_property
    def lock_info(self) -> c_vmfs.FS3_DiskLock:
        """The lock info of this file descriptor."""
        return c_vmfs.FS3_DiskLock(self.raw)

    @cached_property
    def metadata(self) -> c_vmfs.FS3_FileMetadata:
        """The file metadata of this file descriptor."""
        return c_vmfs.FS3_FileMetadata(self.raw[self.vmfs._fd_meta_offset :])

    @property
    def data(self) -> memoryview:
        """The data portion of this file descriptor."""
        return self.raw[self.vmfs._fd_data_offset : self.vmfs._fd_data_offset + self.vmfs._fd_data_size]

    @property
    def blocks(self) -> list[int]:
        """The block array of this file.

        Also referred to as the pointer array, or data addresses.

        On VMFS5, this is stored in the data portion of the file descriptor as an array of 32-bit integers.
        On VMFS6, it's aligned to the end of the file descriptor, and is an array of 64-bit integers.
        """
        ctype = c_vmfs.uint32 if self.vmfs.is_vmfs5 else c_vmfs.uint64
        return ctype[self.vmfs._fd_max_data_addrs](
            self.raw[self.vmfs._fd_data_addrs_offset : self.vmfs._fd_data_addrs_offset + self.vmfs._fd_data_addrs_size]
        )

    @property
    def rdm_mapping(self) -> c_vmfs.FS3_RawDiskMap:
        """The RDM mapping of this file, if this file is an RDM file.

        The RDM mapping is stored in the data portion of the file descriptor.
        """
        if not self.is_rdm():
            raise NotAnRDMFileError(f"{self} is not an RDM file")

        return c_vmfs.FS3_RawDiskMap(self.data)

    @property
    def parent(self) -> FileDescriptor | None:
        """The parent file descriptor of this file, if it has one."""
        parent_fd = self.metadata.parentFD
        return self.vmfs.file_descriptor(parent_fd) if parent_fd else None

    @property
    def size(self) -> int:
        """The size of this file."""
        return self.metadata.fileLength

    @property
    def type(self) -> int:
        """The type of this descriptor. Not to be confused with the file type."""
        return self.metadata.type

    @property
    def zla(self) -> FS3_ZeroLevelAddrType:
        """The "Zero Level Address" type of this file."""
        return FS3_ZeroLevelAddrType(self.metadata.zeroLevelAddrType)

    @property
    def mode(self) -> int:
        """The file mode of this file.

        The mode in the metadata only contains a type bit for directories, we add
        the appropriate type bits for regular files, symlinks and RDM files.

        Access the mode through the :attr:`metadata` attribute to get the raw mode value.
        """
        if stat.S_IFMT(self.metadata.mode):
            # If the mode already has a type bit set, return it as is
            return self.metadata.mode

        if self.is_dir():
            return self.metadata.mode | stat.S_IFDIR

        if self.is_symlink():
            return self.metadata.mode | stat.S_IFLNK

        if self.is_rdm():
            return self.metadata.mode | stat.S_IFBLK

        return self.metadata.mode | stat.S_IFREG

    @property
    def block_size(self) -> int:
        """The file specific block size of this file."""
        return self.metadata.blockSize

    @cached_property
    def atime(self) -> datetime:
        """The last access time of this file."""
        return ts.from_unix(self.metadata.atime)

    @cached_property
    def mtime(self) -> datetime:
        """The last modified time of this file."""
        return ts.from_unix(self.metadata.mtime)

    @cached_property
    def ctime(self) -> datetime:
        """The creation time of this file."""
        return ts.from_unix(self.metadata.ctime)

    @cached_property
    def link(self) -> str:
        """The destination of this symlink, if this file descriptor is a symlink."""
        if not self.is_symlink():
            raise NotASymlinkError(f"{self} is not a symlink")

        with self.open() as buf:
            return buf.read().decode("utf-8")

    def is_dir(self) -> bool:
        """Return whether this file descriptor is a directory."""
        return self.type == FS3_DescriptorType.DIRECTORY or (self.is_system() and stat.S_ISDIR(self.metadata.mode))

    def is_file(self) -> bool:
        """Return whether this file descriptor is a regular file."""
        return self.type == FS3_DescriptorType.REGFILE or (self.is_system() and not stat.S_ISDIR(self.metadata.mode))

    def is_symlink(self) -> bool:
        """Return whether this file descriptor is a symlink."""
        return self.type == FS3_DescriptorType.SYMLINK

    def is_system(self) -> bool:
        """Return whether this file descriptor is a system file."""
        return self.type == FS3_DescriptorType.SYSFILE

    def is_rdm(self) -> bool:
        """Return whether this file descriptor is an RDM file."""
        return self.type == FS3_DescriptorType.RDM

    def listdir(self) -> dict[str, DirEntry]:
        """A dictionary of the content of this directory, if this file descriptor is a directory."""
        return {n.name: n for n in self.iterdir()}

    def iterdir(self) -> Iterator[DirEntry]:
        """Iterate file descriptors of the directory entries, if this file descriptor is a directory."""
        if not self.is_dir():
            raise NotADirectoryError(repr(self))

        yield from self._iterdir()

    def _iterdir(self) -> Iterator[DirEntry]:
        raise NotImplementedError

    def get(self, name: str) -> DirEntry:
        """Get a child directory entry by name.

        Args:
            name: The name of the directory entry to get.
        """
        if not self.is_dir():
            raise NotADirectoryError(repr(self))

        return self._get(name)

    def _get(self, name: str) -> DirEntry:
        raise NotImplementedError

    def open(self) -> BlockStream:
        """Open a read-only stream for this file descriptor."""
        if self.is_rdm():
            # TODO: if we're running on the ESXi host, can we open the RDM file directly?
            # Something to look into later
            raise NotImplementedError(f"Can't open RDM file {self}")

        if self.vmfs.fh is None:
            return BestEffortBlockStream(self)

        return BlockStream(self)

    def _offset_to_block_address(self, offset: int) -> int:
        """Resolve a given offset to a block address."""
        raise NotImplementedError

    def _resolve_offset(self, offset: int) -> tuple[int, int]:
        """Resolve any offset in the file to an offset on disk."""
        raise NotImplementedError

    def _resolve_resident_offset(self, offset: int) -> int:
        """Resolve any offset in a file to an offset on disk for resident files.

        References:
            - ``Fil3_ResolveFileOffsetForSmallData``
        """
        if self.zla != FS3_ZeroLevelAddrType.FILE_DESCRIPTOR_RESIDENT:
            raise TypeError(f"Invalid ZLA type {self.zla} for resident file {self}")

        if offset > self.vmfs._fd_data_size:
            raise ValueError(f"Offset {offset} exceeds resident size {self.vmfs._fd_data_size} for {self}")

        return self.lock_info.addr.offset + self.vmfs._fd_data_offset + offset

    def _read_offset_sadpanda(self, offset: int, length: int) -> bytes:
        """Read a specific offset from a file descriptor, using only available system files.

        This is used when we opened the filesystem with Just a Bunch Of System Files (JBOSF, you heard it here first).
        We can't read any file blocks since we don't have a volume handle to read from the disk, but some system files
        (like the subblock file) can still be read directly. So we implement only those blocks here.

        This duplicates a little bit of code from the happy face code (:func:`_resolve_offset`), but that code is
        explicitly structured like that to be as close to the original VMFS "code" as possible.

        Since most of the subtleties of the differences between VMFS5 and VMFS6 are not relevant here, we
        implement this in a single function that handles both versions.
        """
        if self.zla == FS3_ZeroLevelAddrType.FILE_DESCRIPTOR_RESIDENT:
            if offset > self.vmfs._fd_data_size:
                raise ValueError(f"Offset {offset} exceeds resident size {self.vmfs._fd_data_size} for {self}")
            start = self.vmfs._fd_size - self.vmfs._fd_data_size + offset
            end = max(start + length, self.vmfs._fd_size)
            return self.raw[start:end]

        block = self._offset_to_block_address(offset)
        if self.vmfs.is_vmfs5:
            offset_in_block = offset & (self.block_size - 1)
        else:
            offset_in_block = offset & ((1 << self.vmfs._sub_block_size_shift) - 1)

        type = address_type(block)
        if type == FS3_AddrType.SUB_BLOCK and (resource := self.vmfs.resources.get(type)):
            block = resource.read(block)
            return block[offset_in_block : offset_in_block + length]

        raise VolumeNotAvailableError(f"Unsupported address type {FS3_AddrType(type)} for block {block:#x} in {self}")


class FileDescriptor5(FileDescriptor):
    """VMFS5 file descriptor implementation."""

    def _iterdir(self) -> Iterator[DirEntry]:
        """Iterate directory entries on VMFS5.

        On VMFS5, directories are stored as a simple array of directory entries.
        Each entry is a fixed size struct, which contains the address of the entry, its name and type.

        References:
            - ``Fil3_ReaddirVMFS5``
        """
        with self.open() as buf:
            for _ in range(self.size // len(c_vmfs.FS3_DirEntry)):
                if (dirent := c_vmfs.FS3_DirEntry(buf)).descAddr == 0:
                    continue

                yield DirEntry(
                    self.vmfs,
                    dirent.descAddr,
                    dirent.name.decode().strip("\x00"),
                    dirent.type,
                    raw=dirent,
                )

    def _get(self, name: str) -> DirEntry:
        """Get a child directory entry by name on VMFS5.

        For VMFS5, this just iterates over the directory entries until it finds the entry with the given name.
        """
        for entry in self.iterdir():
            if entry.name == name:
                return entry
        else:
            raise FileNotFoundError(f"File not found: {name!r} in {self}")

    def _offset_to_block_address(self, offset: int) -> int:
        """Resolve a given offset to a block address.

        References:
            - ``Fil3FileOffsetToBlockAddrCommonVMFS5``
            - ``PB3CacheFaultVMFS5``
            - ``Vol3OpenStage1VMFS5``
        """
        block_num = offset >> self.metadata.blockOffsetShift

        if self.zla in (FS3_ZeroLevelAddrType.FILE_BLOCK, FS3_ZeroLevelAddrType.SUB_BLOCK):
            return self.blocks[block_num]

        if self.zla in (FS3_ZeroLevelAddrType.POINTER_BLOCK, FS3_ZeroLevelAddrType.POINTER2_BLOCK):
            primary_num = block_num >> self.vmfs._ptr_block_num_shift
            secondary_num = block_num & ((1 << self.vmfs._ptr_block_num_shift) - 1)

            block = self.blocks[primary_num]
            pb_buf = self.vmfs.resources.read(block)

            return _get_uint32_index(pb_buf, secondary_num)

        if self.zla == FS3_ZeroLevelAddrType.POINTER_BLOCK_DOUBLE:
            primary_num = block_num >> (2 * self.vmfs._ptr_block_num_shift)
            secondary_num = (block_num >> self.vmfs._ptr_block_num_shift) & ((1 << self.vmfs._ptr_block_num_shift) - 1)
            tertiary_num = block_num & ((1 << self.vmfs._ptr_block_num_shift) - 1)

            block = self.blocks[primary_num]
            pb_buf = self.vmfs.resources.read(block)

            block = _get_uint32_index(pb_buf, secondary_num)
            pb_buf = self.vmfs.resources.read(block)

            return _get_uint32_index(pb_buf, tertiary_num)

        raise TypeError(f"Unsupported ZLA type {FS3_ZeroLevelAddrType(self.zla)} for VMFS5")

    def _resolve_offset(self, offset: int) -> tuple[int, int]:
        """Resolve any offset in a file to an offset on disk.

        Returns a tuple of the resolved offset on disk and the TBZ bit of the block.

        References:
            - ``Fil3_ResolveFileOffsetAndGetBlockTypeVMFS5``
        """
        if self.zla == FS3_ZeroLevelAddrType.FILE_DESCRIPTOR_RESIDENT:
            return self._resolve_resident_offset(offset), 0

        block = self._offset_to_block_address(offset)
        type = address_type(block)

        if resource := self.vmfs.resources.get(type):
            block_offset = resource.resolve_address(block)
        elif type == FS3_AddrType.FILE_BLOCK:
            # No resource available (yet), likely still in filesystem initialization phase
            block_offset = FileBlockAddr.parse(block) << self.metadata.blockOffsetShift
        else:
            raise TypeError(f"Invalid block {Address(block)} for offset {offset:#x} in {self}")

        offset_in_block = offset & (self.block_size - 1)

        tbz = 0
        if type == FS3_AddrType.FILE_BLOCK:
            # Mask directly instead of going through Address to avoid unnecessary overhead
            tbz = (block & 0x20) >> 5

        return block_offset + offset_in_block, tbz


class FileDescriptor6(FileDescriptor):
    """VMFS6 file descriptor implementation."""

    def _iterdir(self) -> Iterator[DirEntry]:
        """Iterate directory entries on VMFS6.

        On VMFS6, directories are stored in a more complex way. The directory buffer is block based with
        several different block types.

        The first block is a header, also refered to as the directory header block. It contains metadata about
        the directory, as well as the self (``.``) and parent (``..``) entries. The header also contains a
        list of allocation map blocks, and the hash table that is used to quickly find directory entries by name.
        The directory header block is ``0x10000`` bytes large.

        The hash table starts immediately after the ``FS6_DirHeader`` structure. A normal directory has space for
        ``16001`` hash entries, but the root directory has ``28`` reserved entries for system files. Each entry is
        a 32-bit integer that encodes the type, block and entry index of the directory entry.
        See :func:`_dir_parse_location` for more information on how to interpret these entries.
        A hash entry of type ``1`` (``DIRENT``) indicates that the block and entry index point directly to
        a directory entry block and entry index, respectively. A hash entry of type ``2`` (``LINK``) indicates
        that you have to go through a link block to find the directory entry.

        All other blocks start after the directory header block (offset ``0x10000``), and are of size ``mdAlignment``.
        All blocks start with a 64 byte block header, which contains some allocation information and an entry bitmap.
        This bitmap can be used to determine which entries in the block are allocated and which are free.

        The first block type (``1``) is the directory entry block. These blocks contain the actual directory entries.
        Each entry is a fixed size struct, which contains the address, name, type and some other metadata.
        Note that even though directory entries now have 256 bytes of space for the name, ESXi will still limit
        filenames to 127 characters.

        The second block type (``2``) is a link block. These blocks contain link groups that are used to create
        chains to other link groups or to a directory entry. In case of a conflict in the directory header hash table
        (which only allows for ~16k entries, so that's quite likely), a link block is created to resolve the conflict.
        Each link group contains the hash value of the conflicting entry, and up to 12 links to other link groups,
        or directly to a directory entry. If the link group is full, you will have to follow the ``nextGroup`` location.
        Each location is encoded the same way as the hash table entries.

        The last block type (``3``) is the allocation map block. These are used to track which blocks in the directory
        buffer are used and which type they are. This information is stored in a bitmap, where each entry is 4 bits.
        See :func:`_iter_dir_allocation_map` for more information.
        Iterating the allocation map block allows you to find allocated blocks of a specific type quickly.

        Reading directory contents should be done in the following manner:
            - Read the directory header to get the number of entries and allocation map blocks
            - Yield the self (``.``) and parent (``..``) entries from the header
            - Iterate the allocation map blocks to find all directory entry blocks
            - For each directory entry block
                - Read the block header to get the number of entries and the entry bitmap
                - Iterate the bitmap to find allocated entries
                - For each allocated entry, read the directory entry struct

        References:
            - ``Fil3_ReaddirVMFS6``
            - ``Fil3LookupIntVMFS6``
            - ``voma``
        """
        block_size = self.vmfs.md_alignment

        with self.open() as fh:
            header = c_vmfs.FS6_DirHeader(fh)
            if header.version not in (c_vmfs.FS6_DIR_HEADER_VERSION, c_vmfs.FS6_DIR_HEADER_DEBUG_VERSION):
                raise NotADirectoryError(f"Invalid directory version for {self}: {header.version:#x}")

            remaining_entries = header.numEntries

            # Yield the . and .. entries, which are stored in the header
            if header.selfEntry.address:
                yield DirEntry(
                    self.vmfs,
                    header.selfEntry.address,
                    header.selfEntry.name.decode().strip("\x00"),
                    header.selfEntry.type,
                    raw=header.selfEntry,
                )
                remaining_entries -= 1

            if remaining_entries == 0:
                return

            if header.parentEntry.address:
                yield DirEntry(
                    self.vmfs,
                    header.parentEntry.address,
                    header.parentEntry.name.decode().strip("\x00"),
                    header.parentEntry.type,
                    raw=header.parentEntry,
                )
                remaining_entries -= 1

            if remaining_entries == 0:
                return

            for type, block in _iter_dir_blocks(
                fh,
                header.allocationMapBlocks[: header.numAllocationMapBlocks],
                block_size,
            ):
                if type != FS6_DirBlockType.DIRENT:
                    # We only care about directory entry blocks, skip the others
                    continue

                fh.seek(c_vmfs.FS6_DIR_HEADER_BLOCK_SIZE + (block * block_size))
                block_buf = memoryview(fh.read(block_size))
                block_header = c_vmfs.FS6_DirBlockHeader(block_buf)
                block_entries = block_buf[len(c_vmfs.FS6_DirBlockHeader) :]

                for i in range(block_header.totalSlots):
                    # Test if the entry is allocated
                    # i >> 3 gets us the byte index, i & 7 gets us the bit index
                    if (block_header.bitmap[i >> 3] >> (i & 7)) & 1 == 0:
                        dirent = c_vmfs.FS6_DirEntry(block_entries[i * len(c_vmfs.FS6_DirEntry) :])
                        yield DirEntry(
                            self.vmfs,
                            dirent.address,
                            dirent.name.decode().strip("\x00"),
                            dirent.type,
                            raw=dirent,
                        )

                        remaining_entries -= 1

                    if remaining_entries == 0:
                        return

    def _get(self, name: str) -> DirEntry:
        """Get a child directory entry by name for VMFS6.

        Looking up a directory entry by name is done by calculating the hash of the name and looking it up in the
        hash table. The hash table entry will either point directly to a directory entry block, or to a link block.
        If the entry is a link block, you will have to follow the link chain to get to the actual directory entry.

        See :meth:`_iterdir_vmfs6` for more information on how directory entries are stored.

        References:
            - ``Fil3LookupIntVMFS6``
        """
        block_size = self.vmfs.md_alignment

        with self.open() as fh:
            header = c_vmfs.FS6_DirHeader(fh)
            if header.version not in (c_vmfs.FS6_DIR_HEADER_VERSION, c_vmfs.FS6_DIR_HEADER_DEBUG_VERSION):
                raise NotADirectoryError(f"Invalid directory version for {self}: {header.version:#x}")

            if name == "." and header.selfEntry.address:
                return DirEntry(
                    self.vmfs,
                    header.selfEntry.address,
                    header.selfEntry.name.decode().strip("\x00"),
                    header.selfEntry.type,
                    raw=header.selfEntry,
                )

            if name == ".." and header.parentEntry.address:
                return DirEntry(
                    self.vmfs,
                    header.parentEntry.address,
                    header.parentEntry.name.decode().strip("\x00"),
                    header.parentEntry.type,
                    raw=header.parentEntry,
                )

            is_root = self.address == c_vmfs.rootDirDescAddr
            link_hash, hash_idx = _dir_name_hash(name, in_root=is_root)
            type, block, slot = _dir_hash_get_location(fh, hash_idx)

            if not type:
                raise FileNotFoundError(f"File not found: {name!r} in {self}")

            # Resolve links first
            try:
                while type == FS6_DirBlockType.LINK:
                    type, block, slot = _dir_link_resolve(fh, block, slot, block_size, hash_idx, link_hash)
            except KeyError as e:
                raise FileNotFoundError(f"File not found: {name!r} in {self}") from e

            if type == FS6_DirBlockType.DIRENT:
                offset = (
                    # Block offset
                    (c_vmfs.FS6_DIR_HEADER_BLOCK_SIZE + (block * block_size))
                    # Block header size
                    + len(c_vmfs.FS6_DirBlockHeader)
                    # Slot offset
                    + (slot * len(c_vmfs.FS6_DirEntry))
                )

                fh.seek(offset)
                dirent = c_vmfs.FS6_DirEntry(fh)
                return DirEntry(
                    self.vmfs,
                    dirent.address,
                    dirent.name.decode().strip("\x00"),
                    dirent.type,
                    raw=dirent,
                )

        raise FileNotFoundError(f"File not found: {name!r} in {self}")

    def _offset_to_block_address(self, offset: int) -> int:
        """Resolve a given offset to a block address.

        References:
            - ``Fil3FileOffsetToBlockAddrCommonVMFS6``
            - ``PB3CacheFaultVMFS6``
            - ``Vol3OpenStage1VMFS6``
        """
        block_num = offset >> self.metadata.blockOffsetShift

        if self.zla in (FS3_ZeroLevelAddrType.FILE_BLOCK, FS3_ZeroLevelAddrType.SUB_BLOCK):
            return self.blocks[block_num]

        if self.zla in (FS3_ZeroLevelAddrType.POINTER_BLOCK, FS3_ZeroLevelAddrType.POINTER2_BLOCK):
            primary_num = block_num >> self.vmfs._ptr_block_num_shift
            secondary_num = block_num & ((1 << self.vmfs._ptr_block_num_shift) - 1)

            block = self.blocks[primary_num]

            # Pointer block data can be stored in the .pbc.sf file itself, in .sbc.sf or as regular file block
            # Use the address type to figure it out
            pb_buf = self.vmfs.resources.read(block)
            return _get_uint64_index(pb_buf, secondary_num)

        if self.zla == FS3_ZeroLevelAddrType.POINTER_BLOCK_DOUBLE:
            primary_num = block_num >> (2 * self.vmfs._ptr_block_num_shift)
            secondary_num = (block_num >> self.vmfs._ptr_block_num_shift) & ((1 << self.vmfs._ptr_block_num_shift) - 1)
            tertiary_num = block_num & ((1 << self.vmfs._ptr_block_num_shift) - 1)

            block = self.blocks[primary_num]
            pb_buf = self.vmfs.resources.read(block)

            block = _get_uint64_index(pb_buf, secondary_num)
            pb_buf = self.vmfs.resources.read(block)

            return _get_uint64_index(pb_buf, tertiary_num)

        raise TypeError(f"Unsupported ZLA type {FS3_ZeroLevelAddrType(self.zla)} for VMFS6")

    def _resolve_offset(self, offset: int) -> tuple[int, int]:
        """Resolve any offset in a file to an offset on disk.

        Returns a tuple of the offset on disk and the TBZ bitmap of the block.

        References:
            - ``Fil3_ResolveFileOffsetAndGetBlockTypeVMFS6``
        """
        if self.zla == FS3_ZeroLevelAddrType.FILE_DESCRIPTOR_RESIDENT:
            return self._resolve_resident_offset(offset), 0

        block = self._offset_to_block_address(offset)
        type = address_type(block)

        if resource := self.vmfs.resources.get(type):
            block_offset = resource.resolve_address(block)
        elif type == FS3_AddrType.SMALL_FILE_BLOCK:
            # No resource available (yet), likely still in filesystem initialization phase
            cluster, resource = SmallFileBlockAddr.parse(block)
            block_offset = ((cluster * self.vmfs._sfb_size) + resource) << self.metadata.blockOffsetShift
        else:
            raise TypeError(f"Invalid block {Address(block)} for offset {offset:#x} in {self}")

        if type == FS3_AddrType.LARGE_FILE_BLOCK:
            offset_in_block = offset & (
                (1 << (self.vmfs.descriptor.sfbToLfbShift + self.vmfs._file_block_size_shift)) - 1
            )
        elif type == FS3_AddrType.SMALL_FILE_BLOCK:
            offset_in_block = offset & ((1 << self.vmfs._file_block_size_shift) - 1)
        elif type == FS3_AddrType.SUB_BLOCK:
            offset_in_block = offset & ((1 << self.vmfs._sub_block_size_shift) - 1)
        else:
            raise TypeError(f"Invalid block {Address(block)} for offset {offset:#x} in {self}")

        tbz = 0
        if type in (FS3_AddrType.SMALL_FILE_BLOCK, FS3_AddrType.LARGE_FILE_BLOCK):
            # Mask directly instead of going through Address to avoid unnecessary overhead
            tbz = (block >> 7) & 0xFF

        return block_offset + offset_in_block, tbz


def _iter_dir_allocation_map(buf: bytes) -> Iterator[tuple[int, bool, bool]]:
    """Iterate over a VMFS6 directory allocation map.

    Each entry is 4 bits, with the following encoding:
    .. code-block:: text

        0b0011 (type)
        0b0100 (free)
        0b1000 (notWritten)

    References:
        - ``Fil3_ReaddirVMFS6``
        - ``voma``

    Args:
        buf: The buffer containing the allocation map data.

    Yields:
        Tuples containing the entry type, free status and not written status.
    """
    for byte in buf:
        for entry in (byte >> 4, byte & 0x0F):
            yield (
                entry & 0b0011,  # type
                bool(entry & 0b0100),  # free
                bool(entry & 0b1000),  # notWritten
            )


def _iter_dir_blocks(fh: BinaryIO, allocation_map_blocks: list[int], block_size: int) -> Iterator[int, int]:
    """Iterate over directory allocation map blocks to find blocks of a specific type.

    Args:
        fh: The file-like object of a directory.
        allocation_map_blocks: The list of allocation map blocks to iterate over.
        type: The type of directory block to find.
        block_size: The size of a directory block in bytes.
    """
    entries_per_alloc_block = (2 * block_size) - (len(c_vmfs.FS6_DirBlockHeader) * 2)

    for i, allocation_block in enumerate(allocation_map_blocks):
        allocation_block_offset = c_vmfs.FS6_DIR_HEADER_BLOCK_SIZE + (allocation_block * block_size)
        fh.seek(allocation_block_offset)
        block_buf = fh.read(block_size)

        # Skip the block header
        allocation_map = memoryview(block_buf)[len(c_vmfs.FS6_DirBlockHeader) :]
        for entry_idx, (entry_type, _, _) in enumerate(_iter_dir_allocation_map(allocation_map)):
            yield entry_type, ((i * entries_per_alloc_block) + entry_idx)


def _dir_hash_get_location(fh: BinaryIO, key: int) -> tuple[int, int, int]:
    """Lookup the location of a directory entry in the hash table.

    References:
        - ``Fil3DirGetCurLocation``
    """
    entry_offset = len(c_vmfs.FS6_DirHeader) + key * 4
    fh.seek(entry_offset)
    location = c_vmfs.uint32(fh)

    return _dir_parse_location(location)


def _dir_parse_location(pointer: int) -> tuple[int, int, int]:
    """Parse a directory entry location from a 32-bit integer.

    The location is encoded as follows:
    .. code-block:: text

        0b00000000 00000000 00000000 00000011  (type)
        0b00000000 11111111 11111111 11111100  (blkNum)
        0b11111111 00000000 00000000 00000000  (slotNum)

    Args:
        pointer: The pointer to parse.

    Returns:
        A tuple containing the type, block number and slot number.
    """
    return pointer & 3, (pointer >> 2) & 0x3FFFFF, pointer >> 24


_HASH_SALT = int.to_bytes(0x739A75C28E61B017, 8, "little")


# Reference: Fil3LookupIntVMFS6
_SYSTEM_FILE_HASHES = {
    ".fbb.sf": (0x3E66, 0x3E66),
    ".fdc.sf": (0x3E67, 0x3E67),
    ".pbc.sf": (0x3E68, 0x3E68),
    ".sbc.sf": (0x3E69, 0x3E69),
    ".vh.sf": (0x3E6A, 0x3E6A),
    ".pb2.sf": (0x3E6B, 0x3E6B),
    ".sdd.sf": (0x3E6C, 0x3E6C),
    ".jbc.sf": (0x3E6D, 0x3E6D),
    ".unmap.sf": (0x3E6E, 0x3E6E),
    ".dfd.sf": (0x3E6F, 0x3E6F),
}


def _dir_name_hash(name: str, in_root: bool = False) -> tuple[int, int]:
    """Calculate the lookup hashes for a directory entry name.

    Args:
        name: The name of the directory entry.
        in_root: Whether the current/parent directory is the root directory.

    References:
        - ``Fil3LookupIntVMFS6``

    Returns:
        A tuple containing the two hash values used for directory entry lookup.
    """
    if in_root and name in _SYSTEM_FILE_HASHES:
        return _SYSTEM_FILE_HASHES[name]

    name_raw = name.encode()

    key = bytearray(256)
    key[: len(name_raw)] = name_raw

    rounded_len = (len(name_raw) + 8) & 0xFFF8  # Round up to the next multiple of 8
    for i in range(rounded_len, 127, 8):
        key[i : i + 8] = _HASH_SALT

    result = lookup8_quads(key, 42)

    return ((result >> 16) & 0xFFFF), (
        result % (c_vmfs.FS6_DIR_HASH_MAX_ROOT_ENTRIES if in_root else c_vmfs.FS6_DIR_HASH_MAX_ENTRIES)
    )


def _dir_link_resolve(
    fh: BinaryIO, block: int, slot: int, block_size: int, hash_idx: int, link_hash: int
) -> tuple[int, int, int]:
    """Resolve a link group to find the actual directory entry, or the next link group.

    Args:
        fh: The file-like object of the directory.
        block: The block number of the link group.
        slot: The slot number of the link group.
        block_size: The size of a directory block in bytes.
        hash_idx: The hash index of the link group.
        link_hash: The hash value of the link to resolve.

    Returns:
        A tuple containing the type, block number and slot number of the resolved directory entry or next link group.

    Raises:
        KeyError: If the link group hash index does not match the expected hash index.
    """
    offset = (
        # Block offset
        c_vmfs.FS6_DIR_HEADER_BLOCK_SIZE
        + (block * block_size)
        # Block header size
        + len(c_vmfs.FS6_DirBlockHeader)
        # Slot offset
        + (slot * len(c_vmfs.FS6_DirLinkGroup))
    )

    fh.seek(offset)
    link_group = c_vmfs.FS6_DirLinkGroup(fh)
    if link_group.hashIndex != hash_idx:
        raise KeyError(f"Link group hash index {link_group.hashIndex} does not match expected {hash_idx}")

    for link_idx in range(link_group.totalLinks - link_group.freeLinks):
        link = link_group.links[link_idx]
        if link.hash == link_hash:
            return _dir_parse_location(link.location)
    else:
        return _dir_parse_location(link_group.nextGroup)


class BlockStream(AlignedStream):
    """Implements a file-like object for VMFS files.

    VMFS file content can be resident or divided over one or more file blocks. These blocks can be
    directly or indirectly referenced. If they're directly referenced, we can read immediately
    from the block, otherwise we need to go through one or more layers of indirection.

    Indirection is implemented using PB or PB2 blocks. The actual indirection algorithm differs
    slightly between VMFS versions.

    Eventual file blocks can also differ between FB (filesystem block), SB (sub/small block) and
    LFB (large filesystem block).

    See :func:`_resolve_offset_vmfs5` and :func:`_resolve_offset_vmfs6` for more information on how
    to resolve offsets.
    """

    def __init__(self, descriptor: FileDescriptor):
        self.descriptor = descriptor
        super().__init__(self.descriptor.size, align=self.descriptor.block_size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []
        fh = self.descriptor.vmfs.fh

        while length > 0:
            read_length = min(length, self.descriptor.block_size - offset % self.descriptor.block_size)

            read_offset, tbz = self.descriptor._resolve_offset(offset)
            if tbz:
                # If the TBZ bit is set, return a zeroed block
                result.append(b"\x00" * read_length)
            else:
                fh.seek(read_offset)
                result.append(fh.read(read_length))

            length -= read_length
            offset += read_length

        return b"".join(result)


class BestEffortBlockStream(AlignedStream):
    """Implements a file-like object for VMFS files in the case we don't have a volume available.

    If we don't have a volume handle, we can't read any file blocks on disk, but we can still read
    resident and sub-block data.

    This duplicates some code, but it gives us a cleaner implementation of the happy path
    while still allowing us to read some data in the case we only have a bunch of system files.
    """

    def __init__(self, descriptor: FileDescriptor):
        self.descriptor = descriptor
        super().__init__(self.descriptor.size, align=self.descriptor.block_size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        while length > 0:
            read_length = min(length, self.descriptor.block_size - offset % self.descriptor.block_size)
            read_buf = self.descriptor._read_offset_sadpanda(offset, length)
            result.append(read_buf)

            length -= read_length
            offset += read_length

        return b"".join(result)


_S32 = struct.Struct("<i")


def _get_uint32_index(buf: bytes, index: int) -> int:
    """Convenience function to index into a ``uint32`` sized array."""
    return _S32.unpack(buf[index * 4 : (index * 4) + 4])[0]


_S64 = struct.Struct("<Q")


def _get_uint64_index(buf: bytes, index: int) -> int:
    """Convenience function to index into a ``uint64`` sized array."""
    return _S64.unpack(buf[index * 8 : (index * 8) + 8])[0]
