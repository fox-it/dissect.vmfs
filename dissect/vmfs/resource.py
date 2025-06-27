from __future__ import annotations

from textwrap import dedent
from typing import TYPE_CHECKING, BinaryIO

from dissect.vmfs.address import (
    FileBlockAddr,
    FileDescriptorAddr,
    JournalBlockAddr,
    LargeFileBlockAddr,
    PointerBlock2Addr,
    PointerBlock2Addr64,
    PointerBlockAddr,
    PointerBlockAddr64,
    SmallFileBlockAddr,
    SubBlockAddr,
    SubBlockAddr64,
    address_type,
)
from dissect.vmfs.c_vmfs import FS3_Config, FS3_DescriptorType, FS3_ResourceTypeID, c_vmfs
from dissect.vmfs.util import bsf

if TYPE_CHECKING:
    from dissect.vmfs.vmfs import VMFS, FileDescriptor


class ResourceFile:
    """VMFS resource file implementation.

    Resource files of different types need different interpretation of the resource data. Some may not have
    any resource data at all, using only the bitmaps in the resource file to track allocation.

    Resource files start with a metadata header (``FS3_ResFileMetadata``) that contains information about the layout
    of the file, such as the number of resources, their size, and their organization into clusters and cluster groups.

    Following the metadata header, at an offset defined in ``clusterGroupOffset``, starts the first cluster group.
    Each cluster group contains a ``clustersPerGroup`` number of clusters. Each cluster group starts with an
    array of ``FS3_ResourceCluster`` structures, one for every cluster in the group. This structure contains a lock
    and a cluster metadata header, which has resource allocation information about the cluster.
    The resource data starts after the cluster metadata headers. To get to the correct resource data,
    you need to calculate the offset based on the cluster group, cluster and resource indices.

    Args:
        vmfs: The VMFS instance this resource file belongs to.
        resource_type: The type of the resource file.
        address: The file descriptor address of the resource file.
        fh: A file-like object to read the resource data from.
        fd: An optional file descriptor for the resource file, if available.
        metadata_offset: The offset in the file where the resource metadata starts. Defaults to 0.
    """

    def __init__(
        self,
        vmfs: VMFS,
        resource_type: FS3_ResourceTypeID,
        address: int,
        fh: BinaryIO,
        fd: FileDescriptor | None = None,
        metadata_offset: int = 0,
    ):
        self.vmfs = vmfs
        self.type = resource_type
        self.address = address
        self.fh = fh
        self.fd = fd

        self.fh.seek(metadata_offset)
        self.metadata = c_vmfs.FS3_ResFileMetadata(self.fh)
        if self.vmfs.is_vmfs6 and self.metadata.signature != c_vmfs.FS3_RFMD_SIGNATURE:
            raise ValueError("Invalid resource metadata signature")

        self._resource_per_cluster_shift = bsf(self.metadata.resourcesPerCluster)

        # Resource clusters contain an array of lock and metadata headers for each cluster in the group
        # Roughly looks like this:
        # struct FS3_ResourceCluster {
        #     FS3_DiskBlock clusterLock;
        #     FS3_DiskBlock clusterMeta;
        # };
        # Resource data starts after the cluster metadata headers.
        if self.vmfs.is_vmfs5:
            # VMFS5 uses a fixed metadata alignment of 512 bytes
            # We have two disk blocks per cluster (lock and metadata header), so the total header size is 1024 bytes
            self._cluster_header_size = 1024
        else:
            # VMFS6 uses a variable metadata alignment
            # Still have two disk blocks per cluster, so the total header size is 2 * mdAlignment
            self._cluster_header_size = 2 * self.vmfs.descriptor.mdAlignment

        # The offset from a cluster group start to the resource data is the combined size of all cluster headers
        self._cluster_data_offset = self.metadata.clustersPerGroup * self._cluster_header_size
        self._cluster_size = self.metadata.resourcesPerCluster * self.metadata.resourceSize

    def debug(self) -> str:
        """Return a debug string for this resource file.

        Mimicks ``vmkfstool -D`` output.
        """
        md = self.metadata
        fd = self.vmfs.file_descriptor(self.address)

        return (
            fd.debug()
            + "\n"
            + dedent(f"""
        {(md.numResourcesHi << 32) | md.numResourcesLo} resources, each of size {md.resourceSize}
        Organized as {md.numClusterGroups} CGs, {md.clustersPerClusterGroup} C/CG and {md.resourcesPerCluster} R/C
        CGsize {md.clusterGroupSize}. 0th CG at {md.firstClusterGroupOffset}
        """).strip()
        )

    def parse_address(self, address: int) -> tuple[int, int]:
        """Parse an address into a cluster/resource pair to use for looking up a resource."""
        raise NotImplementedError

    def resolve_address(self, address: int) -> int:
        """Resolve an address to a volume address."""
        offset_in_file = self._resource_offset_from_address(address)
        if not self.fd:
            raise ValueError("Need a file descriptor to resolve to a volume address")
        return self.fd._resolve_offset(offset_in_file)[0]

    def _cluster_group_offset(self, group: int) -> int:
        """Calculate the offset of a cluster group in the resource file."""
        md = self.metadata

        if self.vmfs.is_vmfs5 or (self.vmfs.is_vmfs6 and md.flags & 2 == 0):
            return (
                # Base offset for cluster groups
                md.clusterGroupOffset
                # Offset for the cluster group
                + (group * md.clusterGroupSize)
            )

        parent_resources_per_group = (md.parentClustersPerGroup * md.parentResourcesPerCluster) // md.clustersPerGroup
        parent_group, parent_cluster_in_group = divmod(group, parent_resources_per_group)

        return (
            # Base offset for cluster groups
            md.clusterGroupOffset
            # Offset for the parent cluster group
            + (parent_group * md.parentClusterGroupSize)
            # Skip the cluster headers for the parent cluster group
            + (md.parentClustersPerGroup * self._cluster_header_size)
            # Offset for the cluster group within the parent cluster group
            + (parent_cluster_in_group * md.clusterGroupSize)
        )

    def _cluster_header_offset(self, cluster: int) -> int:
        """Calculate the offset of a cluster header in the resource file."""
        md = self.metadata

        if self.vmfs.is_vmfs5 or (self.vmfs.is_vmfs6 and md.flags & 2 == 0):
            group, cluster_in_group = divmod(cluster, md.clustersPerGroup)
            return (
                # Base offset for cluster groups
                md.clusterGroupOffset
                # Offset for the cluster group
                + (group * md.clusterGroupSize)
                # Offset for the cluster header within the group
                + (cluster_in_group * self._cluster_header_size)
            )

        parent_resources_per_group = md.parentClustersPerGroup * md.parentResourcesPerCluster
        parent_group, parent_cluster_in_group = divmod(cluster, parent_resources_per_group)

        return (
            # Base offset for cluster groups
            md.clusterGroupOffset
            # Offset for the parent cluster group
            + (parent_group * md.parentClusterGroupSize)
            # Skip the cluster headers for the parent cluster group
            + (md.parentClustersPerGroup * self._cluster_header_size)
            # Offset to the cluster in the parent cluster group
            + parent_cluster_in_group
        )

    def _resource_offset(self, cluster: int, resource: int) -> int:
        """Calculate the offset of a specific resource into the resource file based on its address."""
        md = self.metadata
        group, cluster_in_group = divmod(cluster, md.clustersPerGroup)

        return (
            # Base offset for cluster groups
            md.clusterGroupOffset
            # Offset for the cluster group
            + (group * md.clusterGroupSize)
            # Offset for the cluster header within the group
            + (cluster_in_group * self._cluster_size)
            # Offset for the resource data of the cluster
            + self._cluster_data_offset
            # Offset for the specific resource within the cluster
            + (resource * md.resourceSize)
        )

    def _resource_offset_from_address(self, address: int) -> int:
        """Calculate the offset of a specific resource into the resource file based on its address."""
        cluster, resource = self.parse_address(address)
        return self._resource_offset(cluster, resource)

    def read(self, address: int) -> bytes:
        """Read and return the resource belonging to the given address."""
        # Prefer reading from the volume if we have it
        if self.vmfs.fh:
            offset = self.resolve_address(address)
            self.vmfs.fh.seek(offset)
            return self.vmfs.fh.read(self.metadata.resourceSize)

        # Otherwise, read from the resource file
        offset = self._resource_offset_from_address(address)
        self.fh.seek(offset)
        return self.fh.read(self.metadata.resourceSize)


class FileBlockResourceVMFS5(ResourceFile):
    """(Small) file block resource (``.fbb.sf``)."""

    def parse_address(self, address: int) -> tuple[int, int]:
        block = FileBlockAddr.parse(address)
        return divmod(block, self.metadata.resourcesPerCluster)

    def resolve_address(self, address: int) -> int:
        """Resolve a file block address to a volume address."""
        block = FileBlockAddr.parse(address)
        return block * self.fd.block_size


class SmallFileBlockResourceVMFS6(ResourceFile):
    """Small file block resource (``.fbb.sf``) for VMFS6."""

    def parse_address(self, address: int) -> tuple[int, int]:
        return SmallFileBlockAddr.parse(address)

    def resolve_address(self, address: int) -> int:
        """Resolve a small file block address to a volume address."""
        cluster, resource = self.parse_address(address)
        return ((cluster * self.metadata.resourcesPerCluster) + resource) << self.vmfs._file_block_size_shift


class SubBlockResourceVMFS5(ResourceFile):
    """Sub-block resource (``.sbc.sf``) for VMFS5."""

    def parse_address(self, address: int) -> tuple[int, int]:
        return SubBlockAddr.parse(address, dense=FS3_Config.DENSE_SBPC in self.vmfs.descriptor.config)


class SubBlockResourceVMFS6(ResourceFile):
    """Sub-block resource (``.sbc.sf``) for VMFS6.

    Uses 64-bit addressing.
    """

    def parse_address(self, address: int) -> tuple[int, int]:
        return SubBlockAddr64.parse(address)


class PointerBlockResourceVMFS5(ResourceFile):
    """Pointer block resource (``.pbc.sf``)."""

    def parse_address(self, address: int) -> tuple[int, int]:
        return PointerBlockAddr.parse(address)


class PointerBlockResourceVMFS6(ResourceFile):
    """Pointer block resource (``.pbc.sf``) for VMFS6.

    Uses 64-bit addressing.
    """

    def parse_address(self, address: int) -> tuple[int, int]:
        return PointerBlockAddr64.parse(address)


class FileDescriptorResourceVMFS5(ResourceFile):
    """File descriptor resource (``.fdc.sf``) for VMFS5."""

    def parse_address(self, address: int) -> tuple[int, int]:
        return FileDescriptorAddr.parse(address)


class FileDescriptorResourceVMFS6(ResourceFile):
    """File descriptor resource (``.fdc.sf``) for VMFS6."""

    def parse_address(self, address: int) -> tuple[int, int]:
        return FileDescriptorAddr.parse(address)


class PointerBlock2ResourceVMFS5(ResourceFile):
    """Pointer block 2 resource (``.pb2.sf``) for VMFS5."""

    def parse_address(self, address: int) -> tuple[int, int]:
        return PointerBlock2Addr.parse(address)


class PointerBlock2ResourceVMFS6(ResourceFile):
    """Pointer block 2 resource (``.pb2.sf``) for VMFS6.

    Uses 64-bit addressing.
    """

    def parse_address(self, address: int) -> tuple[int, int]:
        return PointerBlock2Addr64.parse(address)


class JournalBlockResourceVMFS6(ResourceFile):
    """Journal block resource (``.jbc.sf``)."""

    def parse_address(self, address: int) -> tuple[int, int]:
        return JournalBlockAddr.parse(address)


class LargeFileBlockResourceVMFS6(ResourceFile):
    """Large file block resource (``.fbb.sf``)."""

    def parse_address(self, address: int) -> tuple[int, int]:
        block = LargeFileBlockAddr.parse(address)
        cluster = block >> self._resource_per_cluster_shift
        resource = block & (self.metadata.resourcesPerCluster - 1)
        return cluster, resource

    def resolve_address(self, address: int) -> int:
        """Resolve a large file block address to a volume address."""
        cluster, resource = self.parse_address(address)
        block_shift = self.vmfs._file_block_size_shift + self.vmfs.descriptor.sfbToLfbShift
        return ((cluster << self._resource_per_cluster_shift) + resource) << block_shift


RESOURCE_TYPE_MAP_VMFS5 = {
    FS3_ResourceTypeID.FILE_BLOCK: FileBlockResourceVMFS5,
    FS3_ResourceTypeID.SUB_BLOCK: SubBlockResourceVMFS5,
    FS3_ResourceTypeID.PTR_BLOCK: PointerBlockResourceVMFS5,
    FS3_ResourceTypeID.FILE_DESC: FileDescriptorResourceVMFS5,
    FS3_ResourceTypeID.PTR2_BLOCK: PointerBlock2ResourceVMFS5,
}

RESOURCE_TYPE_MAP_VMFS6 = {
    FS3_ResourceTypeID.SMALL_FILE_BLOCK: SmallFileBlockResourceVMFS6,
    FS3_ResourceTypeID.SUB_BLOCK: SubBlockResourceVMFS6,
    FS3_ResourceTypeID.PTR_BLOCK: PointerBlockResourceVMFS6,
    FS3_ResourceTypeID.FILE_DESC: FileDescriptorResourceVMFS6,
    FS3_ResourceTypeID.PTR2_BLOCK: PointerBlock2ResourceVMFS6,
    FS3_ResourceTypeID.JOURNAL_BLOCK: JournalBlockResourceVMFS6,
    FS3_ResourceTypeID.LARGE_FILE_BLOCK: LargeFileBlockResourceVMFS6,
}


RESOURCE_TYPE_ABBREVIATIONS = {
    FS3_ResourceTypeID.FILE_BLOCK: "FB",
    FS3_ResourceTypeID.SMALL_FILE_BLOCK: "SFB",
    FS3_ResourceTypeID.SUB_BLOCK: "SB",
    FS3_ResourceTypeID.PTR_BLOCK: "PB",
    FS3_ResourceTypeID.FILE_DESC: "FD",
    FS3_ResourceTypeID.PTR2_BLOCK: "PB2",
    FS3_ResourceTypeID.JOURNAL_BLOCK: "JB",
    FS3_ResourceTypeID.LARGE_FILE_BLOCK: "LFB",
}


class ResourceManager:
    """Manager for VMFS resources.

    Utility class for keeping track of opened resource files and providing access to them.
    """

    def __init__(self, vmfs: VMFS):
        self.vmfs = vmfs
        self.resources = {}

    def __repr__(self) -> str:
        return f"<ResourceManager {' '.join(RESOURCE_TYPE_ABBREVIATIONS[r] for r in self.resources)}>"

    def __getitem__(self, type: FS3_ResourceTypeID | int) -> ResourceFile:
        """Get a resource file by its type."""
        resource_type = FS3_ResourceTypeID(type)
        if resource_type not in self.resources:
            raise KeyError(f"No resource opened for type {resource_type}")
        return self.resources[resource_type.value]

    def open(
        self,
        type: FS3_ResourceTypeID,
        address: int | None = None,
        fileobj: BinaryIO | None = None,
        metadata_offset: int = 0,
    ) -> None:
        """Open a resource file of the given type.

        Args:
            type: The type of the resource to open.
            address: The address of the resource to open. If not provided, `fileobj` must be provided.
            fileobj: A file-like object to read the resource from. If not provided, `address` must be provided.
            metadata_offset: The offset in the file where the resource metadata starts. Defaults to 0.
                This is used for child metadata that share the same resource file.
        """
        if type.value in self.resources:
            raise ValueError(f"Resource already opened: {type}")

        resource_type_map = RESOURCE_TYPE_MAP_VMFS5 if self.vmfs.is_vmfs5 else RESOURCE_TYPE_MAP_VMFS6
        if type not in resource_type_map:
            raise TypeError(f"Don't know how to open resource: {type}")

        if not address and not fileobj:
            raise ValueError(f"No address or file object for resource: {type}")

        fd = None
        if not fileobj:
            # Open the system file descriptor
            fd = self.vmfs._get_sfd(address)
            # Do a sanity check on the file descriptor
            if (
                fd.metadata.descAddr != address
                or fd.block_size != self.vmfs.file_block_size
                or fd.type != FS3_DescriptorType.SYSFILE
            ):
                raise ValueError(f"Invalid file descriptor for resource {type}: {fd}")

            # Fix up metadata for older VMFS versions
            # Untested, but just in case
            if self.vmfs.major_version <= 19:
                fd.metadata.blockOffsetShift = bsf(fd.metadata.blockSize)
                fd.metadata.tbzGranularityShift = fd.metadata.blockOffsetShift

            fileobj = fd.open()

        self.resources[type.value] = resource_type_map[type](
            self.vmfs,
            type,
            address,
            fileobj,
            fd=fd,
            metadata_offset=metadata_offset,
        )

    def close(self, type: FS3_ResourceTypeID) -> None:
        """Close a resource file of the given type.

        Args:
            type: The type of the resource to close.
        """
        if type.value not in self.resources:
            raise ValueError(f"No resource opened for type {type}")

        del self.resources[type.value]

    def has(self, type: FS3_ResourceTypeID) -> bool:
        """Check if a resource of the given type is opened.

        Args:
            type: The type of the resource to check.
        """
        return type.value in self.resources

    def get(self, type: FS3_ResourceTypeID | int) -> ResourceFile | None:
        """Get a resource file by its type.

        Args:
            type: The type of the resource to get.
        """
        type = FS3_ResourceTypeID(type)
        return self.resources.get(type.value)

    def read(self, address: int) -> bytes:
        """Read a resource from the given address, automatically selecting the correct resource from the address.

        Args:
            address: The address of the resource to read.
        """
        return self.get(address_type(address)).read(address)

    @property
    def FB(self) -> FileBlockResourceVMFS5 | SmallFileBlockResourceVMFS6:
        """Get the file block resource (``.fbb.sf``, VMFS5)."""
        return self.get(FS3_ResourceTypeID.FILE_BLOCK)

    @property
    def SFB(self) -> FileBlockResourceVMFS5 | SmallFileBlockResourceVMFS6:
        """Get the small file block resource (``.fbb.sf``, VMFS6)."""
        return self.get(FS3_ResourceTypeID.SMALL_FILE_BLOCK)

    @property
    def SB(self) -> SubBlockResourceVMFS5 | SubBlockResourceVMFS6:
        """Get the sub-block resource (``.sbc.sf``)."""
        return self.get(FS3_ResourceTypeID.SUB_BLOCK)

    @property
    def PB(self) -> PointerBlockResourceVMFS5 | PointerBlockResourceVMFS6:
        """Get the pointer block resource (``.pbc.sf``)."""
        return self.get(FS3_ResourceTypeID.PTR_BLOCK)

    @property
    def FD(self) -> FileDescriptorResourceVMFS5 | FileDescriptorResourceVMFS6:
        """Get the file descriptor resource (``.fdc.sf``)."""
        return self.get(FS3_ResourceTypeID.FILE_DESC)

    @property
    def PB2(self) -> PointerBlock2ResourceVMFS5 | PointerBlock2ResourceVMFS6:
        """Get the pointer block 2 resource (``.pb2.sf``)."""
        return self.get(FS3_ResourceTypeID.PTR2_BLOCK)

    @property
    def JB(self) -> JournalBlockResourceVMFS6:
        """Get the journal block resource (``.jbc.sf``)."""
        return self.get(FS3_ResourceTypeID.JOURNAL_BLOCK)

    @property
    def LFB(self) -> LargeFileBlockResourceVMFS6:
        """Get the large file block resource (``.fbb.sf``)."""
        return self.get(FS3_ResourceTypeID.LARGE_FILE_BLOCK)
