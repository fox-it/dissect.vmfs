from __future__ import annotations

from typing import ClassVar

from dissect.vmfs.c_vmfs import FS3_AddrType


def address_type(address: int) -> int:
    """Return the address type.

    Address type is encoded in the lower 3 bits.
    """
    return address & 0b111


def address_fmt(address: int) -> str:
    return repr(Address(address))


class Address:
    """Base class for VMFS addresses.

    This class primarily exists to provide an easy way to inspect addresses when debugging or testing interactively.
    For every other case where we actually parse addresses, we use the static methods of the subclasses.
    This is primarily for performance reasons, so we avoid the overhead of creating unnecessary class instances
    when we just want one or two integers.

    VMFS makes extensive use of opaque 32-bit and 64-bit integers to represent addresses.
    In VMFS5, exclusively 32-bit integers are used, while VMFS6 uses 64-bit integers for most address types.
    The lower 3 bits of an address determine the address type, while the remaining bits are address type specific.
    Some address types have additional bits for flags, such as copy-on-write (COW) or to-be-zeroed (TBZ).
    Most address types have a cluster and resource part, which are used to index into resource files.
    The file block and large file block addresses only have a block part, which points to somewhere on the volume.

    .. rubric :: Encoding
    .. code-block:: c

        struct FS3_Address {
            uint32 addrType : 3;
            uint32 addrSpecific : 29;
        };

        struct FS3_Address64 {
            uint64 addrType : 3;
            uint64 addrSpecific : 61;
        };

    References:
        - ``Addr3_AddrToStr``
        - ``Addr3_AddrToStr64``
        - ``Res3Parse*Addr*``
    """

    __type__ = FS3_AddrType.INVALID
    __known_types__: ClassVar[dict[int, type[Address]]] = {}

    def __init_subclass__(cls):
        cls.__known_types__[cls.__type__.value] = cls

    def __new__(
        cls, value: int = 0
    ) -> (
        Address
        | FileBlockAddr
        | SmallFileBlockAddr
        | SubBlockAddr
        | SubBlockAddr64
        | PointerBlockAddr
        | PointerBlockAddr64
        | FileDescriptorAddr
        | PointerBlock2Addr
        | PointerBlock2Addr64
        | JournalBlockAddr
        | LargeFileBlockAddr
    ):
        """Create an instance of the appropriate address type based on the value."""
        if cls is Address:
            if (addr_type := address_type(value)) not in cls.__known_types__:
                return super().__new__(cls)
            return cls.__known_types__[addr_type](value)
        return super().__new__(cls)

    def __init__(self, value: int = 0):
        self.value = value

    def __int__(self) -> int:
        return self.value

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Address):
            return self.value == other.value
        if isinstance(other, int):
            return self.value == other
        return False

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash(self.value)

    def __repr__(self) -> str:
        if self.value == 0:
            return "<Null address>"
        return f"<Invalid address {self.value:#x}>"

    @property
    def type(self) -> int:
        """Return the address type."""
        return address_type(self.value)

    @staticmethod
    def parse(address: int) -> tuple[int, int] | int:
        """Parse the address and return the cluster and resource.

        This method should be overridden by subclasses.
        """
        raise NotImplementedError("Subclasses must implement parse method.")

    @classmethod
    def make(cls, cluster: int, resource: int) -> int:
        """Create an address from a cluster and resource.

        This method should be overridden by subclasses.
        """
        raise NotImplementedError("Subclasses must implement make method.")

    @classmethod
    def make_type(cls, type: FS3_AddrType | int, cluster: int, resource: int) -> int:
        """Create an address from a type, cluster and resource."""
        return cls.__known_types__[int(type)].make(cluster, resource)


class FileBlockAddr(Address):
    """VMFS5 FB address.

    FB (file block) in VMFS5 are used to describe data blocks on the volume.

    A block in a lazily zeroed file, can have its TBZ (to-be-zeroed) flag set to 1, indicating that the block should be
    treated as zeroed when read. This is treated for the whole block.

    .. rubric :: Encoding
    .. code-block:: c

        struct FS3_FileBlockAddr {
            uint32 addrType     : 3;
            uint32 unused       : 1;
            uint32 copyOnWrite  : 1;
            uint32 toBeZeroed   : 1;
            uint32 blockNum     : 26;
        };

        0b00000000 00000000 00000000 00000111  (type)
        0b00000000 00000000 00000000 00001000  (unused/unknown)
        0b00000000 00000000 00000000 00010000  (cow)
        0b00000000 00000000 00000000 00100000  (tbz)
        0b11111111 11111111 11111111 11000000  (block)
    """

    __type__ = FS3_AddrType.FILE_BLOCK

    def __repr__(self) -> str:
        return f"<FB tbz={self.tbz} cow={self.cow} block={self.block}>"

    @property
    def cow(self) -> int:
        """Parse the FB address and return the copy-on-write value."""
        return (self.value >> 4) & 0x1

    @property
    def tbz(self) -> int:
        """Parse the FB address and return the to-be-zeroed value."""
        return (self.value >> 5) & 0x1

    @property
    def block(self) -> int:
        return self.parse(self.value)

    @staticmethod
    def parse(address: int) -> int:
        return (address >> 6) & 0x3FFFFFF

    @classmethod
    def make(
        cls,
        block: int,
        cow: int = 0,
        tbz: int = 0,
    ) -> int:
        """Create a VMFS5 FB address from a block."""
        return cls.__type__ | ((cow & 0x1) << 4) | ((tbz & 0x1) << 5) | ((block & 0x3FFFFFF) << 6)


class SmallFileBlockAddr(Address):
    """VMFS6 SFB address.

    SFB (small file block) in VMFS6 is what FB was in VMFS5. They are used to describe data blocks on the volume.
    Their encoding now consists of a cluster and resource part, which can be used to check allocation status
    in the resource file. See :class:`~dissect.vmfs.resource.SmallFileBlockResourceVMFS6` for more details.

    In this variant of the address, the TBZ (to-be-zeroed) flag is a bitmap that can be used to indicate
    different parts of the block that should be zeroed out. Though when reading the block, the whole block seems to
    be treated as zeroed when any bit is set to 1.

    .. rubric :: Encoding
    .. code-block:: c

        struct FS3_SmallFileBlockAddr64 {
            uint64 addrType         : 3;
            uint64 unused1          : 2;
            uint64 copyOnWrite      : 1;
            uint64 unused2          : 1;
            uint64 toBeZeroed       : 8;
            uint64 sfbClusterNum    : 31;
            uint64 unknown          : 5;
            uint64 sfbNum           : 13;
        };

        0b00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000111  (type)
        0b00000000 00000000 00000000 00000000 00000000 00000000 00000000 00011000  (unused/unknown)
        0b00000000 00000000 00000000 00000000 00000000 00000000 00000000 00100000  (cow)
        0b00000000 00000000 00000000 00000000 00000000 00000000 00000000 01000000  (unused/unknown)
        0b00000000 00000000 00000000 00000000 00000000 00000000 01111111 10000000  (tbz bitmap)
        0b00000000 00000000 00111111 11111111 11111111 11111111 10000000 00000000  (cluster)
        0b00000000 00000111 11000000 00000000 00000000 00000000 00000000 00000000  (unknown)
        0b11111111 11111000 00000000 00000000 00000000 00000000 00000000 00000000  (resource)
    """

    __type__ = FS3_AddrType.SMALL_FILE_BLOCK

    def __repr__(self) -> str:
        return f"<SFB tbz={self.tbz:#x} cow={self.cow} c{self.cluster} r{self.resource}>"

    @property
    def cow(self) -> int:
        """Parse the SFB address and return the copy-on-write value."""
        return (self.value >> 5) & 0x1

    @property
    def tbz(self) -> int:
        """Parse the SFB address and return the to-be-zeroed value."""
        return (self.value >> 7) & 0xFF

    @property
    def cluster(self) -> int:
        """Return the cluster part of the address."""
        cluster, _ = self.parse(self.value)
        return cluster

    @property
    def resource(self) -> int:
        """Return the resource part of the address."""
        _, resource = self.parse(self.value)
        return resource

    @staticmethod
    def parse(address: int) -> tuple[int, int]:
        """Parse the SFB address and return the cluster and resource."""
        cluster = (address >> 15) & 0x7FFFFFFF
        resource = (address >> 51) & 0x1FFF
        return cluster, resource

    @classmethod
    def make(cls, cluster: int, resource: int, cow: int = 0, tbz: int = 0) -> int:
        """Create a VMFS6 SFB address from a cluster and resource."""
        return (
            cls.__type__
            | ((cow & 0x1) << 5)
            | ((tbz & 0xFF) << 7)
            | ((cluster & 0x7FFFFFFF) << 15)
            | ((resource & 0x1FFF) << 51)
        )


class SubBlockAddr(Address):
    """VMFS5 SB address.

    SB (sub-block) describe small blocks of data which would be wasteful to store in a normal file block, and instead
    are stored in the ``.sbc.sf`` resource file.

    If the ``/config/VMFS3/intOpts/DenseSBPerCluster`` option is set, the resource part of the address
    is extended by 2 bits to allow more sub-block resources per cluster.

    .. rubric :: Encoding
    .. code-block:: c

        struct FS3_SubBlockAddr {
            uint32 addrType     : 3;
            uint32 sbNumHi      : 2;
            uint32 copyOnWrite  : 1;
            uint32 sbClusterNum : 22;
            uint32 sbNum        : 4;
        };

        0b00000000 00000000 00000000 00000111  (type)
        0b00000000 00000000 00000000 00011000  (resourceHi if FS3_Config.DENSE_SBPC is set)
        0b00000000 00000000 00000000 00100000  (cow)
        0b00001111 11111111 11111111 11000000  (cluster)
        0b11110000 00000000 00000000 00000000  (resource)
    """

    __type__ = FS3_AddrType.SUB_BLOCK

    def __repr__(self) -> str:
        return f"<SB cow={self.cow} c{self.cluster} r{self.resource}>"

    @property
    def cow(self) -> int:
        """Parse the SB address and return the copy-on-write value."""
        return (self.value >> 5) & 0x1

    @property
    def cluster(self) -> int:
        """Return the cluster part of the address."""
        cluster, _ = self.parse(self.value)
        return cluster

    @property
    def resource(self) -> int:
        """Return the resource part of the address."""
        _, resource = self.parse(self.value)
        return resource

    @staticmethod
    def parse(address: int, dense: bool = False) -> tuple[int, int]:
        """Parse the SB address and return the cluster and resource."""
        cluster = (address >> 6) & 0x3FFFFF
        resource = (address >> 28) & 0xF
        if dense:
            # In dense mode, an increased the number of sub-block resources are stored per cluster
            # /config/VMFS3/intOpts/DenseSBPerCluster
            resource |= (address & 0b11000) << 1
        return cluster, resource

    @classmethod
    def make(cls, cluster: int, resource: int, cow: int = 0) -> int:
        """Create a VMFS5 SB address from a cluster and resource."""
        return cls.__type__ | ((cow & 0x1) << 5) | ((cluster & 0x3FFFFF) << 6) | ((resource & 0xF) << 28)


class SubBlockAddr64(Address):
    """VMFS6 SB address.

    SB (sub-block) describe small blocks of data which would be wasteful to store in a normal file block, and instead
    are stored in the ``.sbc.sf`` resource file.

    .. rubric :: Encoding
    .. code-block:: c

        struct FS3_SubBlockAddr64 {
            uint64 addrType     : 3;
            uint64 unused       : 2;
            uint64 copyOnWrite  : 1;
            uint64 sbClusterNum : 36;
            uint64 unknown      : 14;
            uint64 sbNum        : 8;
        };

        0b00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000111  (type)
        0b00000000 00000000 00000000 00000000 00000000 00000000 00000000 00011000  (unused/unknown)
        0b00000000 00000000 00000000 00000000 00000000 00000000 00000000 00100000  (cow)
        0b00000000 00000000 00000000 11111111 11111111 11111111 11111111 11000000  (cluster)
        0b00000000 00000000 00000011 00000000 00000000 00000000 00000000 00000000  (cluster according to Addr3_AddrToStr64, but not Res3ParseSubBlockAddr64VMFS6)
        0b00000000 11111111 11111100 00000000 00000000 00000000 00000000 00000000  (unknown)
        0b11111111 00000000 00000000 00000000 00000000 00000000 00000000 00000000  (resource)
    """  # noqa: E501

    __type__ = FS3_AddrType.SUB_BLOCK

    def __repr__(self) -> str:
        return f"<SB cow={self.cow} c{self.cluster} r{self.resource}>"

    @property
    def cow(self) -> int:
        """Parse the SB address and return the copy-on-write value."""
        return (self.value >> 5) & 0x1

    @property
    def cluster(self) -> int:
        """Return the cluster part of the address."""
        cluster, _ = self.parse(self.value)
        return cluster

    @property
    def resource(self) -> int:
        """Return the resource part of the address."""
        _, resource = self.parse(self.value)
        return resource

    @staticmethod
    def parse(address: int) -> tuple[int, int]:
        """Parse the SB address and return the cluster and resource."""
        cluster = (address >> 6) & 0xFFFFFFFFF
        resource = (address >> 56) & 0xFF
        return cluster, resource

    @classmethod
    def make(cls, cluster: int, resource: int, cow: int = 0) -> int:
        """Create a VMFS6 SB address from a cluster and resource."""
        return cls.__type__ | ((cow & 0x1) << 5) | ((cluster & 0xFFFFFFFFF) << 6) | ((resource & 0xFF) << 56)


class PointerBlockAddr(Address):
    """VMFS5 PB/PB2 address.

    PB (pointer block) are used for indirect addressing of file blocks. They can point to other PBs or file blocks.

    .. rubric :: Encoding
    .. code-block:: c

        struct FS3_PtrBlockAddr {
            uint32 addrType     : 3;
            uint32 unused       : 2;
            uint32 copyOnWrite  : 1;
            uint32 pbClusterNum : 22;
            uint32 ptrBlockNum  : 4;
        };

        0b00000000 00000000 00000000 00000111  (type)
        0b00000000 00000000 00000000 00011000  (unused)
        0b00000000 00000000 00000000 00100000  (cow)
        0b00001111 11111111 11111111 11000000  (cluster)
        0b11110000 00000000 00000000 00000000  (resource)
    """

    __type__ = FS3_AddrType.POINTER_BLOCK

    def __repr__(self) -> str:
        return f"<PB cow={self.cow} c{self.cluster} r{self.resource}>"

    @property
    def cow(self) -> int:
        """Parse the PB address and return the copy-on-write value."""
        return (self.value >> 5) & 0x1

    @property
    def cluster(self) -> int:
        """Return the cluster part of the address."""
        cluster, _ = self.parse(self.value)
        return cluster

    @property
    def resource(self) -> int:
        """Return the resource part of the address."""
        _, resource = self.parse(self.value)
        return resource

    @staticmethod
    def parse(address: int) -> tuple[int, int]:
        """Parse the PB address and return the cluster and resource."""
        cluster = (address >> 6) & 0x3FFFFF
        resource = (address >> 28) & 0xF
        return cluster, resource

    @classmethod
    def make(cls, cluster: int, resource: int, cow: int = 0) -> int:
        """Create a VMFS5 PB address from a cluster and resource."""
        return cls.__type__ | ((cow & 0x1) << 5) | ((cluster & 0x3FFFFF) << 6) | ((resource & 0xF) << 28)


class PointerBlockAddr64(Address):
    """VMFS6 PB/PB2 address.

    PB (pointer block) are used for indirect addressing of file blocks. They can point to other PBs or file blocks.

    .. rubric :: Encoding
    .. code-block:: c

        struct FS3_PtrBlockAddr64 {
            uint64 addrType     : 3;
            uint64 unused       : 2;
            uint64 copyOnWrite  : 1;
            uint64 pbClusterNum : 36;
            uint64 unknown      : 14;
            uint64 ptrBlockNum  : 8;
        };

        0b00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000111  (type)
        0b00000000 00000000 00000000 00000000 00000000 00000000 00000000 00011000  (unused/unknown)
        0b00000000 00000000 00000000 00000000 00000000 00000000 00000000 00100000  (cow)
        0b00000000 00000000 00000011 11111111 11111111 11111111 11111111 11000000  (cluster)
        0b00000000 11111111 11111100 00000000 00000000 00000000 00000000 00000000  (unknown)
        0b11111111 00000000 00000000 00000000 00000000 00000000 00000000 00000000  (resource)
    """

    __type__ = FS3_AddrType.POINTER_BLOCK

    def __repr__(self) -> str:
        return f"<PB cow={self.cow} c{self.cluster} r{self.resource}>"

    @property
    def cow(self) -> int:
        """Parse the PB address and return the copy-on-write value."""
        return (self.value >> 5) & 0x1

    @property
    def cluster(self) -> int:
        """Return the cluster part of the address."""
        cluster, _ = self.parse(self.value)
        return cluster

    @property
    def resource(self) -> int:
        """Return the resource part of the address."""
        _, resource = self.parse(self.value)
        return resource

    @staticmethod
    def parse(address: int) -> tuple[int, int]:
        """Parse the PB address and return the cluster and resource."""
        cluster = (address >> 6) & 0xFFFFFFFFF
        resource = (address >> 56) & 0xFF
        return cluster, resource

    @classmethod
    def make(cls, cluster: int, resource: int, cow: int = 0) -> int:
        """Create a VMFS6 PB address from a cluster and resource."""
        return cls.__type__ | ((cow & 0x1) << 5) | ((cluster & 0xFFFFFFFFF) << 6) | ((resource & 0xFF) << 56)


class FileDescriptorAddr(Address):
    """FD address. Used in both VMFS5 and VMFS6.

    FD (file descriptor) addresses are used to reference file descriptors in the ``.fdc.sf`` resource file.
    They are similar to inode numbers in traditional filesystems.

    .. rubric :: Encoding
    .. code-block:: c

        struct FS3_FDAddr {
            uint32 addrType     : 3;
            uint32 unused       : 3;
            uint32 fdClusterNum : 16;
            uint32 fdNum        : 10;
        };

        0b00000000 00000000 00000000 00000111  (type)
        0b00000000 00000000 00000000 00111000  (unused)
        0b00000000 00111111 11111111 11000000  (cluster)
        0b11111111 11000000 00000000 00000000  (resource)
    """

    __type__ = FS3_AddrType.FILE_DESCRIPTOR

    def __repr__(self) -> str:
        return f"<FD c{self.cluster} r{self.resource}>"

    @property
    def cluster(self) -> int:
        """Return the cluster part of the address."""
        cluster, _ = self.parse(self.value)
        return cluster

    @property
    def resource(self) -> int:
        """Return the resource part of the address."""
        _, resource = self.parse(self.value)
        return resource

    @staticmethod
    def parse(address: int) -> tuple[int, int]:
        """Parse the FD address and return the cluster and resource."""
        cluster = (address >> 6) & 0xFFFF
        resource = (address >> 22) & 0x3FF
        return cluster, resource

    @classmethod
    def make(cls, cluster: int, resource: int) -> int:
        """Create a FD address from a cluster and resource."""
        return cls.__type__ | ((cluster & 0xFFFF) << 6) | ((resource & 0x3FF) << 22)


class PointerBlock2Addr(PointerBlockAddr):
    """PB2 address, 32-bit variant. Only used in VMFS5.

    PB (pointer block) are used for indirect addressing of file blocks. They can point to other PBs or file blocks.

    Encoding for PB and PB2 is the same, but the address type differs.
    """

    __type__ = FS3_AddrType.POINTER2_BLOCK

    def __repr__(self) -> str:
        return f"<PB2 cow={self.cow} c{self.cluster} r{self.resource}>"


class PointerBlock2Addr64(PointerBlockAddr64):
    """PB2 address, 64-bit variant. Only used in VMFS6.

    PB (pointer block) are used for indirect addressing of file blocks. They can point to other PBs or file blocks.

    Encoding for PB and PB2 is the same, but the address type differs.
    """

    __type__ = FS3_AddrType.POINTER2_BLOCK

    def __repr__(self) -> str:
        return f"<PB2 cow={self.cow} c{self.cluster} r{self.resource}>"


class JournalBlockAddr(Address):
    """JB address. Only used in VMFS6.

    .. rubric :: Encoding
    .. code-block:: c

        struct FS3_JournalBlockAddr {
            uint32 addrType     : 3;
            uint32 jbClusterNum : 13;
            uint32 unused       : 10;
            uint32 jbNum        : 6;
        };

        0b00000000 00000000 00000000 00000111  (type)
        0b00000000 00000000 11111111 11111000  (cluster)
        0b00000011 11111111 00000000 00000000  (unused/unknown)
        0b11111100 00000000 00000000 00000000  (resource)
    """

    __type__ = FS3_AddrType.JOURNAL_BLOCK

    def __repr__(self) -> str:
        return f"<JB c{self.cluster} r{self.resource}>"

    @property
    def cluster(self) -> int:
        """Return the cluster part of the address."""
        cluster, _ = self.parse(self.value)
        return cluster

    @property
    def resource(self) -> int:
        """Return the resource part of the address."""
        _, resource = self.parse(self.value)
        return resource

    @staticmethod
    def parse(address: int) -> tuple[int, int]:
        """Parse the JB address and return the cluster and resource."""
        cluster = (address >> 3) & 0x1FFF
        resource = (address >> 26) & 0x3F
        return cluster, resource

    @classmethod
    def make(cls, cluster: int, resource: int) -> int:
        """Create a JB address from a cluster and resource."""
        return cls.__type__ | ((cluster & 0x1FFF) << 3) | ((resource & 0x3F) << 26)


class LargeFileBlockAddr(Address):
    """LFB address. Only used in VMFS6.

    LFB (large file block) addresses are used to reference file blocks larger than the standard file block size.
    They are used for large files, such as virtual disks.

    .. rubric :: Encoding
    .. code-block:: c

        struct FS3_LargeFileBlockAddr64 {
            uint64 addrType     : 3;
            uint64 unused1      : 2;
            uint64 copyOnWrite  : 1;
            uint64 unused2      : 1;
            uint64 toBeZeroed   : 8;
            uint64 blockNum     : 31;
            uint64 unused3      : 18;
        };

        0b00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000111  (type)
        0b00000000 00000000 00000000 00000000 00000000 00000000 00000000 00011000  (unused/unknown)
        0b00000000 00000000 00000000 00000000 00000000 00000000 00000000 00100000  (cow)
        0b00000000 00000000 00000000 00000000 00000000 00000000 00000000 01000000  (unused/unknown)
        0b00000000 00000000 00000000 00000000 00000000 00000000 01111111 10000000  (tbz bitmap)
        0b00000000 00000000 00111111 11111111 11111111 11111111 10000000 00000000  (block)
        0b11111111 11111111 11000000 00000000 00000000 00000000 00000000 00000000  (unused/unknown)
    """

    __type__ = FS3_AddrType.LARGE_FILE_BLOCK

    def __repr__(self) -> str:
        return f"<LFB tbz={self.tbz:#x} cow={self.cow} {self.block}>"

    @property
    def cow(self) -> int:
        """Parse the LFB address and return the copy-on-write value."""
        return (self.value >> 5) & 0x1

    @property
    def tbz(self) -> int:
        """Parse the LFB address and return the to-be-zeroed value."""
        return (self.value >> 7) & 0xFF

    @property
    def block(self) -> int:
        return self.parse(self.value)

    @staticmethod
    def parse(address: int) -> int:
        """Parse the LFB address and return the block."""
        return (address >> 15) & 0x7FFFFFFF

    @classmethod
    def make(cls, block: int, cow: int = 0, tbz: int = 0) -> int:
        """Create a LFB address from a block."""
        return cls.__type__ | ((cow & 0x1) << 5) | ((tbz & 0xFF) << 7) | ((block & 0x7FFFFFFF) << 15)
