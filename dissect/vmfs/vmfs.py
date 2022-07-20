# References:
# - /usr/lib/vmware/vmkmod/vmfs3
# - /bin/vmkfstools

import stat
import struct
from functools import cached_property, lru_cache
from io import BytesIO

from dissect.util import ts
from dissect.util.stream import AlignedStream

from dissect.vmfs.c_vmfs import (
    FileType,
    ResourceType,
    bsf,
    c_vmfs,
    type_to_mode,
    vmfs_uuid,
)
from dissect.vmfs.exceptions import (
    FileNotFoundError,
    InvalidHeader,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.vmfs.resource import (
    ResourceManager,
    address_fmt,
    address_tbz,
    address_type,
    parse_fb_address,
    parse_lfb_address,
    parse_sfb_address,
)


class VMFS:
    """VMFS filesystem implementation.

    Assumes that an LVM has already been loaded.

    We implement it quite a bit different from how ESXi seems to use it. ESXi doesn't really distinguish
    between disk partitions and LVM volumes. Everything is a VMFS volume, and it either contains a filesystem
    header at 0x01300000 or it doesn't. Either it contains an LVM that requires multiple extents or it doesn't.
    It's all VMFS, LVM doesn't really exist and it's really just an extra header that specifies if the _filesystem_
    requires multiple extents or not.

    This doesn't really fit with how the rest of dissect is architected, so we act like the LVM is a "proper LVM"
    that exposes a logical volume. We then load a "VMFS filesystem" on top of this logical volume. This volume is
    made up of one or more extents that are loaded beforehand.

    A lot of the math consists of bitwise shifts and masks, which translate to modulo or multiplication operations.
    For the sake of "maintainability" in relation to the original "code", we keep this as bitwise masks, at the
    sacrifice of some human readability. Comments explaining as such are placed where appropriate.
    """

    def __init__(self, volume=None, vh=None, fdc=None, fbb=None, sbc=None, pbc=None, pb2=None, jbc=None):
        self.fh = volume

        if volume:
            vh_fh = volume
        elif vh:
            vh_fh = vh
        else:
            raise ValueError("Need either volume or vh")

        vh_fh.seek(c_vmfs.VMFS_FS3_BASE)
        self.descriptor = c_vmfs.FS3_Descriptor(vh_fh)
        if self.descriptor.magic not in (c_vmfs.VMFS_FS3_MAGIC, c_vmfs.VMFSL_FS3_MAGIC):
            raise InvalidHeader("Invalid FS3 descriptor")

        self.block_size = self.descriptor.fileBlockSize
        # Shifting by block_offset_shift is the same as multiplying by block_size
        self._block_offset_shift = bsf(self.block_size)

        # VMFS6 = (0x18, 0x52)
        # VMFS5 = (0x0E, 0x51)
        self.major_version = self.descriptor.majorVersion
        self.minor_version = self.descriptor.minorVersion

        self.uuid = vmfs_uuid(self.descriptor.uuid)
        self.label = self.descriptor.fsLabel.split(b"\x00")[0].decode("utf-8")

        # Initialize some version specific variables
        if self.is_vmfs5:
            # Heartbeat region size, needed for calculating the initial offset of the FDC
            hb_region_size = c_vmfs.VMFS5_HB_REGION_SIZE

            # Sizes related to file descriptors and their contents
            self._fd_size = 2048
            self._fd_resident_size = 1024

            self._fd_block_count = 256
            self._fd_block_data_size = 1024

            # Size of a pointer block
            self._pb_size = 0x400
        else:
            # Heartbeat region size, needed for calculating the initial offset of the FDC
            hb_entry_size = c_vmfs.VMFS6_HB_ENTRY_SIZE
            if self.descriptor.diskBlockSize > hb_entry_size:
                hb_entry_size = self.descriptor.diskBlockSize
            hb_region_size = hb_entry_size << 10

            # In VMFS6, file blocks (FB) are now called small file blocks (SFB)
            # Instead of being a simple number for a block, they now consist of a cluster
            # and a resource. The cluster needs to be multiplied by the number of blocks
            # per cluster to get the real block number.
            self._sfb_cluster_size = 0x2000
            if 0x20000000 // self.descriptor.fileBlockSize <= 0x2000:
                self._sfb_cluster_size = 0x20000000 // self.descriptor.fileBlockSize

            # Sizes related to file descriptors and their contents
            self._fd_size = 2 * self.descriptor.mdAlignment
            self._fd_resident_size = self.descriptor.mdAlignment - 0x200

            if self.descriptor.mdAlignment < 0x1001:
                self._fd_block_count = 320
                self._fd_block_data_size = 2560
            else:
                self._fd_block_count = self.descriptor.mdAlignment >> 4
                self._fd_block_data_size = self.descriptor.mdAlignment >> 1

            # Size of a pointer block
            if self.descriptor.mdAlignment <= 0x10000:
                self._pb_size = 0x2000
            else:
                self._pb_size = self.descriptor.mdAlignment >> 3

        # Shifting by the bsf of a value is the same as multiplying or dividing by that value
        self._pb_index_shift = bsf(self._pb_size)

        # Calculate relevant offsets in file descriptor buffers
        self._fd_small_data_offset = self._fd_size - self._fd_resident_size
        self._fd_block_data_offset = self._fd_size - self._fd_block_data_size

        # Calculate the large file block (LFB) block size and offset shift
        self._lfb_block_size = self.descriptor.fileBlockSize << self.descriptor.sfbToLfbShift
        self._lfb_offset_shift = self._block_offset_shift + self.descriptor.sfbToLfbShift

        # While we're careful in the order we open resources, it's still possible that
        # a circular dependency happens. E.g. .pb2.sf relies on .pbc.sf.
        # Right now there's too many dependencies on other resource files to make this work.
        # VMFS seems to get around this by sometimes using hardcoded values if a filesystem
        # object isn't available.
        self.resources = ResourceManager(self)

        if fdc:
            self.resources.open(ResourceType.FD, fileobj=fdc)
        else:
            # Temporary FDC
            # Haven't figured out how to properly bootstrap this yet so do it the dirty way
            fdc_base = (c_vmfs.VMFS_HB_BASE + hb_region_size) // self.block_size
            self.fh.seek(fdc_base * self.block_size)
            self.resources.open(ResourceType.FD, fileobj=BytesIO(self.fh.read(self.block_size)))

        # Open the root directory
        self.root = self.file_descriptor(c_vmfs.ROOT_DIR_DESC_ADDR, "/")

        # Open all the resources

        # https://kb.vmware.com/s/article/1001618
        # .pb2.sf - pointer block 2.system file
        # Contains the pointer blocks, used for indirect block referencing.
        # These eventually point to offsets on disk.
        if pb2:
            self.resources.open(ResourceType.PB2, fileobj=pb2)
        else:
            self.resources.open(ResourceType.PB2, address=c_vmfs.PB2_DESC_ADDR)

        # .pbc.sf - pointer block cluster.system file
        # Also contains the pointer blocks, used for indirect block referencing. But different.
        # These eventually point to offsets on disk.
        if pbc:
            self.resources.open(ResourceType.PB, fileobj=pbc)
        else:
            self.resources.open(ResourceType.PB, address=c_vmfs.PBC_DESC_ADDR)

        # This is normally hardcoded to a specific value based on a global configuration
        # However, it turns out that this is the same as the resource size of the PBC resource
        # Originally, this is determined as PB3_VMFS5PBPageSize or PB3_VMFS6PBPageSize
        # PB3_VMFS5PBPageSize is always 0x1000, but PB3_VMFS6PBPageSize can be 0x1000 or 0x10000
        # This is determined by a global configuration setting.
        # We eagerly load the PBC anyway, so it's fine to use this. However, this will cause trouble
        # if we ever want to load the VMFS fully lazily.
        self._pbc_index_shift = bsf(self.resources.pbc.metadata.resourceSize >> 3)

        # .sbc.sf - sub-block cluster.system file
        # Contains sub-block/small-block data. Small file data is in here.
        if sbc:
            self.resources.open(ResourceType.SB, fileobj=sbc)
        else:
            self.resources.open(ResourceType.SB, address=c_vmfs.SB_DESC_ADDR)

        # .fbb.sf - file block bitmap.system file
        # Contains allocation information etc. for file blocks.
        if fbb:
            self.resources.open(ResourceType.LFB, fileobj=fbb)
            self.resources.open(ResourceType.FB, fileobj=fbb)
        else:
            self.resources.open(ResourceType.LFB, address=c_vmfs.FBB_DESC_ADDR)
            self.resources.open(ResourceType.FB, address=c_vmfs.FBB_DESC_ADDR)

        # .fdc.sf -  file descriptor cluster.system file
        # Contains all the file descriptors and their heartbeat/lock information.
        if not fdc:
            # If we had a fdc passed, we already have a full fdc
            self.resources.open(ResourceType.FD, address=c_vmfs.FDBC_DESC_ADDR)

        # .vh.sf - vmfs heartbeat/volume header.system file?
        # Seems to reference the entirety of the volume header. Kind of like $BOOT in NTFS.
        # 0x1400004

        # .sdd.sf - scsi device description.system file
        # 0x1C00004

        # .jbc.sf - journal block cluster.system file
        # 0x2000004
        if jbc:
            self.resources.open(ResourceType.JB, fileobj=jbc)
        else:
            self.resources.open(ResourceType.JB, address=c_vmfs.JB_DESC_ADDR)

    @property
    def is_vmfs5(self):
        return self.major_version <= 0x17

    @property
    def is_vmfs6(self):
        return self.major_version > 0x17

    def get(self, path, node=None):
        if isinstance(path, int):
            return self.file_descriptor(path)

        node = self.root if not node else node

        parts = path.split("/")
        for p in parts:
            if not p:
                continue

            for child in node.iterdir():
                if child.name == p:
                    node = child
                    break
            else:
                raise FileNotFoundError(f"File not found: {path}")

        return node

    @lru_cache(maxsize=4096)
    def file_descriptor(self, address, name=None, filetype=None):
        if address_type(address) != ResourceType.FD:
            raise TypeError(f"Invalid block type: {address_fmt(self, address)}")

        return FileDescriptor(self, address, name, filetype)

    def iter_fd(self):
        for cluster, resource in self.resources.fdc.iter_resource_locations():
            fd_addr = (cluster << 6) | (resource << 22) | ResourceType.FD.value
            yield self.file_descriptor(fd_addr)


class FileDescriptor:
    """VMFS FileDescriptor implementation.

    FileDescriptors are basically the inodes of VMFS and are all located in the fdc.sf resource.
    They start with heartbeat/lock information that describes their lock state so that multiple
    ESXi hosts can stay in sync and can't access files while they're in use.
    The actual FileDescriptor struct is at a specific offset (md/metadata alignment) and contains
    fields that you would expect of an "inode".

    Data is stored in a way that is also similar to many Unix filesystems. There is some space for
    resident data (actually quite large, between 1-4k) or blocks. The "ZLA" determines how to interpret
    these blocks. However, they can generally be seperated into two kinds: direct and indirect.
    Like other filesystems, direct blocks refer directly to the filesystem blocks containg the data,
    whereas with indirect blocks, you first need to go through one or more layers of indirection go get
    to the final filesystem block. This is where PB and PB2 addresses come into play.

    There are two methods of storing directory data. The "legacy" VMFS5 way and the newer VMFS6 way.
    The VMFS5 way is really just an array of directory entry structs, but the VMFS6 way is a bit
    more complex. The data contains blocks aligned on the metadata alignment. Each block contains
    different data, such as what appears to be a hash table, or a heartbeat/allocation bitmap.
    Eventually you'll also get to a block containing actual directory entries, which is once
    again (mostly) an array of directory entries.
    """

    def __init__(self, vmfs, address, name=None, filetype=None):
        self.vmfs = vmfs
        self.address = address
        self.name = name
        self._type = filetype

        self._buf = None
        self._lock_info = None
        self._desc = None

    def __repr__(self):
        return f"<FileDescriptor address={address_fmt(self.vmfs, self.address)} name={self.name}>"

    @cached_property
    def raw(self):
        """The raw buffer of this file descriptor."""
        return memoryview(self.vmfs.resources.fdc.get(self.address))

    @cached_property
    def lock_info(self):
        """The parsed lock info of this file descriptor."""
        return c_vmfs.FS3_DiskLockInfo(self.raw)

    @cached_property
    def descriptor(self):
        """The parsed file descriptor struct for this file descriptor."""
        desc_offset = self.vmfs.descriptor.mdAlignment or c_vmfs.VMFS5_MD_ALIGNMENT
        return c_vmfs.FS3_FileDescriptor(self.raw[desc_offset:])

    @property
    def parent(self):
        parent_fd = self.descriptor.parentFD
        return self.vmfs.file_descriptor(parent_fd) if parent_fd else None

    @property
    def size(self):
        """The size of this file."""
        return self.descriptor.length

    @property
    def type(self):
        """The type of this file."""
        return self._type or self.descriptor.type

    @property
    def zla(self):
        """The ZLA of this file."""
        # This is how vmfs-tool does it
        # Don't think this is actually how the ZLA works, but let's roll with it for now
        zla = self.descriptor.zla
        if zla >= c_vmfs.VMFS5_ZLA_BASE:
            zla -= c_vmfs.VMFS5_ZLA_BASE
        return zla

    @property
    def mode(self):
        """The file mode of this file."""
        if stat.S_IFMT(self.descriptor.mode) == stat.S_IFDIR:
            return self.descriptor.mode
        else:
            return self.descriptor.mode | type_to_mode(self.type)

    @property
    def block_size(self):
        """The file specific block size of this file."""
        return self.descriptor.blockSize

    @cached_property
    def blocks(self):
        """The block array of this file."""
        block_buf = self.raw[self.vmfs._fd_block_data_offset :]
        ctype = c_vmfs.uint32 if self.vmfs.is_vmfs5 else c_vmfs.uint64
        return ctype[self.vmfs._fd_block_count](block_buf)

    @cached_property
    def atime(self):
        """The last access time of this file."""
        return ts.from_unix(self.descriptor.accessTime)

    @cached_property
    def mtime(self):
        """The last modified time of this file."""
        return ts.from_unix(self.descriptor.modificationTime)

    @cached_property
    def ctime(self):
        """The creation time of this file."""
        return ts.from_unix(self.descriptor.creationTime)

    @cached_property
    def link(self):
        """The destination of this file, if it's a symlink."""
        if not self.is_symlink():
            raise NotASymlinkError(f"{self} is not a symlink")

        return self.open().read().decode("utf-8")

    def is_dir(self):
        """Is this file a directory?"""
        return self.type == FileType.Directory

    def is_file(self):
        """Is this file a regular file?"""
        return self.type == FileType.Regular

    def is_symlink(self):
        """Is this file a symlink?"""
        return self.type == FileType.Symlink

    def is_system(self):
        """Is this file a system file?"""
        return self.type == FileType.System

    def is_rdm(self):
        """Is this file a RDM file?"""
        return self.type == FileType.RDM

    def listdir(self):
        """A dictionary of the content of this directory, if this file is a directory."""
        return {n.name: n for n in self.iterdir()}

    def iterdir(self):
        """Iterate file descriptors of the directory entries, if this file is a directory."""
        if not self.is_dir():
            raise NotADirectoryError(repr(self))

        if self.vmfs.is_vmfs5:
            yield from self._iterdir_vmfs5()
        else:
            yield from self._iterdir_vmfs6()

    def _iterdir_vmfs5(self):
        buf = self.open()

        num_entries = self.size // c_vmfs.VMFS5_DIR_ENTRY_SIZE
        for _ in range(num_entries):
            dirent = c_vmfs.FS3_DirEntry(buf)
            if dirent.address == 0:
                continue

            yield self.vmfs.file_descriptor(dirent.address, dirent.name.split(b"\x00")[0].decode(), dirent.type)

    def _iterdir_vmfs6(self):
        # Directories in VMFS6 are a bit more complex.
        # They start out with a header/metadata block, which contains some useful info.
        # This block also contains the . and .. entries, as well as a bitmap?
        # After this everything is in blocks of mdAlignment size, with each block having a small header.
        # NOTE: Some blocks can be of different types. There are heartbeat, hash table and DirEntry blocks.
        buf = self.open()

        header = c_vmfs.FS6_DirHeader(buf)
        if header.version not in (c_vmfs.VMFS6_DIR_FS_VERSION, c_vmfs.VMFS6_DIR_FDC_VERSION):
            raise NotADirectoryError(f"Invalid directory version for {self}: 0x{header.version:x}")

        block_base = c_vmfs.VMFS6_DIR_BLOCK_BASE
        block_size = self.vmfs.descriptor.mdAlignment
        entry_size = c_vmfs.VMFS6_DIR_ENTRY_SIZE
        entries_per_block = block_size // entry_size

        # . and .. are stored in the header
        if header.selfEntry.address != 0:
            yield self.vmfs.file_descriptor(
                header.selfEntry.address, header.selfEntry.name.split(b"\x00")[0].decode(), header.selfEntry.type
            )

        if header.parentEntry.address != 0:
            yield self.vmfs.file_descriptor(
                header.parentEntry.address, header.parentEntry.name.split(b"\x00")[0].decode(), header.parentEntry.type
            )

        num_blocks = ((self.size - block_base) + (block_size - 1)) // block_size
        for block_idx in range(num_blocks):
            block_offset = block_base + (block_idx * block_size)
            buf.seek(block_offset)

            # NOTE: Don't really know how this works yet, for now just do what vmfs-tool does
            block_header = buf.read(0x40)

            # 0x30000 = block heartbeat bitmap
            # 0x20001 = hash table?
            # 0x10001 = directory entries
            if block_header[:4] != b"\x01\x00\x01\x00":
                continue

            for _ in range(entries_per_block):
                dirent = c_vmfs.FS6_DirEntry(buf)
                if dirent.address == 0:
                    # Deleted entries are zero'd
                    continue

                yield self.vmfs.file_descriptor(dirent.address, dirent.name.split(b"\x00")[0].decode(), dirent.type)

    def open(self):
        """Open this file and return a new file-like object."""
        if self.is_rdm():
            raise NotImplementedError(f"Can't open RDM file {self}")

        if self.zla == ResourceType.FD:
            # Resident data
            return BytesIO(self.raw[self.vmfs._fd_small_data_offset : self.vmfs._fd_small_data_offset + self.size])

        return BlockStream(self)


class BlockStream(AlignedStream):
    """Implements a file-like object for VMFS files.

    VMFS file content can be resident or divided over one or more file blocks. These blocks can be
    directly or indirectly referenced. If they're directly referenced, we can read immediately
    from the referenced block, otherwise we need to go through one or more layers of indirection.

    Indirection is implemented using PB or PB2 blocks. The actual indirection algorithm differs
    slightly between VMFS versions.

    Eventual file blocks can also differ between FB (filesystem block), SB (sub/small block) and
    LFB (large filesystem block).
    """

    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.vmfs = descriptor.vmfs
        self.blocks = self.descriptor.blocks
        self.block_size = self.descriptor.block_size
        self.block_offset_shift = self.descriptor.descriptor.blockOffsetShift or bsf(self.block_size)

        # Again, don't think this is how the ZLA works but lets roll with it for now
        zla = self.descriptor.descriptor.zla
        if zla >= c_vmfs.VMFS5_ZLA_BASE:
            self.vmfs5_extension = True
            zla -= c_vmfs.VMFS5_ZLA_BASE
        else:
            self.vmfs5_extension = False
        self.zla = ResourceType(zla)

        super().__init__(self.descriptor.size)

    def _offset_to_block(self, offset):
        idx = offset >> self.block_offset_shift
        if self.zla in (ResourceType.FB, ResourceType.SB):
            return self.blocks[idx]

        elif self.zla == ResourceType.PB:
            # This is equivalent to divmod(idx, addressesPerPb)
            if self.vmfs.is_vmfs5:
                # Don't think this really means "vmfs5_extension"
                if self.vmfs5_extension:
                    # Double indirection
                    primary_idx = idx >> (2 * self.vmfs._pb_index_shift)
                    secondary_idx = (idx >> self.vmfs._pb_index_shift) & ((1 << self.vmfs._pb_index_shift) - 1)
                    tertiary_idx = idx & ((1 << self.vmfs._pb_index_shift) - 1)

                    primary_block = self.blocks[primary_idx]
                    primary_pb_buf = self.vmfs.resources.pbc.get(primary_block)

                    secondary_block = _get_uint32_index(primary_pb_buf, secondary_idx)
                    secondary_pb_buf = self.vmfs.resources.pbc.get(secondary_block)

                    return _get_uint32_index(secondary_pb_buf, tertiary_idx)
                else:
                    # Single indirection
                    primary_idx = (idx >> self.vmfs._pb_index_shift) & ((1 << self.vmfs._pb_index_shift) - 1)
                    secondary_idx = idx & ((1 << self.vmfs._pb_index_shift) - 1)

                    primary_block = self.blocks[primary_idx]
                    primary_pb_buf = self.vmfs.resources.pbc.get(primary_block)

                    return _get_uint32_index(primary_pb_buf, secondary_idx)
            else:
                if self.vmfs5_extension:
                    # Double indirection
                    primary_idx = idx >> (2 * self.vmfs._pb_index_shift)
                    secondary_idx = (idx >> self.vmfs._pb_index_shift) & ((1 << self.vmfs._pbc_index_shift) - 1)
                    tertiary_idx = idx & ((1 << self.vmfs._pbc_index_shift) - 1)

                    primary_block = self.blocks[primary_idx]
                    primary_pb_buf = self.vmfs.resources.sbc.get(primary_block)

                    # NOTE: can become LFB here?
                    secondary_block = _get_uint64_index(primary_pb_buf, secondary_idx)

                    if address_type(secondary_block) == ResourceType.LFB:
                        return secondary_block

                    secondary_pb_buf = self.vmfs.resources.sbc.get(secondary_block)

                    # NOTE: there are some flags that can influence the final index
                    # NOTE: can become LFB here?
                    return _get_uint64_index(secondary_pb_buf, tertiary_idx)
                else:
                    # Single indirection
                    primary_idx = idx >> self.vmfs._pb_index_shift
                    secondary_idx = idx & ((1 << self.vmfs._pbc_index_shift) - 1)

                    # NOTE: can become LFB here?
                    primary_block = self.blocks[primary_idx]

                    if address_type(primary_block) == ResourceType.LFB:
                        return primary_block

                    primary_pb_buf = self.vmfs.resources.sbc.get(primary_block)

                    # NOTE: there are some flags that can influence the final index
                    # NOTE: can become LFB here?
                    return _get_uint64_index(primary_pb_buf, secondary_idx)

        elif self.zla == ResourceType.PB2:
            # This is equivalent to divmod(idx, addressesPerPb2)
            primary_idx = idx >> (2 * self.vmfs._pb_index_shift)
            secondary_idx = idx & ((1 << self.vmfs._pb_index_shift) - 1)

            primary_block = self.blocks[primary_idx]
            primary_pb_buf = self.vmfs.resources.pb2.get(primary_block)

            if self.vmfs.is_vmfs5:
                return _get_uint32_index(primary_pb_buf, secondary_idx)
            else:
                return _get_uint64_index(primary_pb_buf, secondary_idx)
        else:
            raise ValueError(f"Unexpected ZLA in {self.descriptor}: {self.zla}")

    def _read(self, offset, length):
        r = []
        while length > 0:
            block_address = self._offset_to_block(offset)
            block_type = address_type(block_address)

            if address_tbz(self.vmfs, block_address):
                block_type = 0

            read_offset = None
            read_length = None

            if block_type == ResourceType.NONE:
                _, read_length = _read_offset_and_length(offset, length, self.block_size)
                r.append(b"\x00" * read_length)

            elif block_type == ResourceType.FB:
                if self.vmfs.is_vmfs5:
                    block_num = parse_fb_address(self.vmfs, block_address)
                else:
                    cluster, resource = parse_sfb_address(self.vmfs, block_address)
                    block_num = self.vmfs._sfb_cluster_size * cluster + resource
                block_offset = block_num << self.vmfs._block_offset_shift

                read_offset, read_length = _read_offset_and_length(offset, length, self.block_size)
                self.vmfs.fh.seek(block_offset + read_offset)
                r.append(self.vmfs.fh.read(read_length))

            elif block_type == ResourceType.SB:
                read_offset, read_length = _read_offset_and_length(
                    offset, length, self.vmfs.resources.sbc.resource_size
                )

                block_buf = self.vmfs.resources.sbc.get(block_address)
                r.append(block_buf[read_offset : read_offset + read_length])

            elif block_type == ResourceType.LFB:
                block_num = parse_lfb_address(self.vmfs, block_address)
                read_offset, read_length = _read_offset_and_length(offset, length, self.vmfs._lfb_block_size)

                self.vmfs.fh.seek((block_num << self.vmfs._lfb_offset_shift) + read_offset)
                r.append(self.vmfs.fh.read(read_length))

            else:
                raise ValueError(
                    f"Unexpected block type while reading {self.descriptor}: {address_fmt(self.vmfs, block_address)}"
                )

            length -= read_length
            offset += read_length

        return b"".join(r)


def _read_offset_and_length(offset, length, block_size):
    """Convenience function to calculate in-block offsets and remaining read sizes."""
    offset_in_block = offset % block_size
    remaining_in_block = block_size - offset_in_block
    read_length = min(length, remaining_in_block)

    return offset_in_block, read_length


def _get_uint32_index(buf, index):
    """Convenience function to index into a uint32 sized array."""
    return struct.unpack("<I", buf[index * 4 : (index * 4) + 4])[0]


def _get_uint64_index(buf, index):
    """Convenience function to index into a uint64 sized array."""
    return struct.unpack("<Q", buf[index * 8 : (index * 8) + 8])[0]
