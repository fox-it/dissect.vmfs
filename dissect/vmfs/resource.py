from dissect.vmfs.c_vmfs import FileType, ResourceType, c_vmfs
from dissect.vmfs.exceptions import FileNotFoundError


def address_type(addr):
    """Return the address type.

    Address type is encoded in the lower 3 bits.
    """
    return addr & 0b111


def address_fmt(vmfs, address):
    """Create a human readable representation of an address.

    References:
    - Addr3_AddrToStr and similar
    """
    addr_type = address_type(address)
    cow_mask = c_vmfs.ADDRESS_FLAG_COW

    if addr_type == ResourceType.FB:
        tbz = address_tbz(vmfs, address)
        cow = address & cow_mask != 0
        if vmfs.is_vmfs5:
            block = parse_fb_address(vmfs, address)
            return f"<FB tbz={tbz != 0} cow={cow} {block}>"
        else:
            cluster, resource = parse_sfb_address(vmfs, address)
            return f"<SFB tbz=0x{tbz:x} cow={cow} c{cluster} r{resource}>"

    elif addr_type == ResourceType.SB:
        cow = address & cow_mask != 0
        cluster, resource = parse_sb_address(vmfs, address)
        return f"<SB cow={cow} c{cluster} r{resource}>"

    elif addr_type == ResourceType.PB:
        cow = address & cow_mask != 0
        cluster, resource = parse_pb_address(vmfs, address)
        return f"<PB cow={cow} c{cluster} r{resource}>"

    elif addr_type == ResourceType.FD:
        cluster, resource = parse_fd_address(vmfs, address)
        return f"<FD c{cluster} r{resource}>"

    elif addr_type == ResourceType.PB2:
        cow = address & cow_mask != 0
        cluster, resource = parse_pb_address(vmfs, address)
        return f"<PB2 cow={cow} c{cluster} r{resource}>"

    elif addr_type == ResourceType.JB:
        cluster, resource = parse_jb_address(vmfs, address)
        return f"<JB c{cluster} r{resource}>"

    elif addr_type == ResourceType.LFB:
        tbz = address_tbz(vmfs, address)
        cow = address & cow_mask != 0
        block = parse_lfb_address(vmfs, address)
        return f"<LFB tbz=0x{tbz:x} cow={cow} {block}>"

    elif addr_type == 0:
        return "<Null address>"

    return f"<Invalid address 0x{address:x}>"


def address_tbz(vmfs, address):
    """Return whether the TBZ flag is set.

    The TBZ flag is only valid for FB and LFB addresses.
    """
    addr_type = address_type(address)

    if vmfs.is_vmfs5 and addr_type == ResourceType.FB:
        return address & c_vmfs.ADDRESS_FLAG_TBZ
    elif vmfs.is_vmfs6 and addr_type in (ResourceType.FB, ResourceType.LFB):
        return (address & c_vmfs.ADDRESS_FLAG_TBZ_VMFS6) >> 7
    return None


def parse_fb_address(vmfs, address):
    """Parse a FB address and return the block.

    VMFS5 encoding:
        0b11111111 11111111 11111111 11000000
    """
    return (address & 0xFFFFFFC0) >> 6


def parse_sfb_address(vmfs, address):
    """Parse a SFB address and return the cluster and resource.

    SFB (small file block) in VMFS6 is what FB was in VMFS5.

    VMFS6 encoding:
        0b00000000 00000000 00111111 11111111 11111111 11111111 10000000 00000000  (cluster)
        0b11111111 11111000 00000000 00000000 00000000 00000000 00000000 00000000  (resource)
    """
    cluster = (address & 0x00003FFFFFFF8000) >> 15
    resource = (address & 0xFFF8000000000000) >> 51
    return cluster, resource


def parse_sb_address(vmfs, address):
    """Parse a SB address and return the cluster and resource.

    VMFS5 encoding:
        0b00001111 11111111 11111111 11000000  (cluster)
        0b11110000 00000000 00000000 00000000  (resource)
        0b00000000 00000000 00000000 00011000  (resource if config flag set, << 4)

    VMFS6 encoding:
        0b00000000 00000000 00000000 11111111 11111111 11111111 11111111 11000000  (cluster)
        0b11111111 00000000 00000000 00000000 00000000 00000000 00000000 00000000  (resource)
    """
    if vmfs.is_vmfs5:
        cluster = (address & 0x0FFFFFC0) >> 6
        resource = (address & 0xF0000000) >> 28
        if vmfs.descriptor.config & 4:
            # Don't know what this flag means, maybe extended SB addressing?
            resource |= ((address & 0b11000) >> 3) << 4
    else:
        cluster = (address & 0x000000FFFFFFFFC0) >> 6
        resource = (address & 0xFF00000000000000) >> 56
    return cluster, resource


def parse_pb_address(vmfs, address):
    """Parse a PB address and return the cluster and resource.

    Encoding:
        0b00001111 11111111 11111111 11000000  (cluster)
        0b11110000 00000000 00000000 00000000  (resource)

    VMFS6 encoding:
        0b00000000 00000000 00000000 11111111 11111111 11111111 11111111 11000000  (cluster)
        0b11111111 00000000 00000000 00000000 00000000 00000000 00000000 00000000  (resource)
    """
    if vmfs.is_vmfs5:
        cluster = (address & 0x0FFFFFC0) >> 6
        resource = (address & 0xF0000000) >> 28
    else:
        cluster = (address & 0x00000FFFFFFFFC0) >> 6
        resource = (address & 0xFF00000000000000) >> 56
    return cluster, resource


def parse_fd_address(vmfs, address):
    """Parse a FD address and return the cluster and resource.

    Encoding:
        0b00000000 00111111 11111111 11000000  (cluster)
        0b11111111 11000000 00000000 00000000  (resource)
    """
    cluster = (address & 0x003FFFC0) >> 6
    resource = (address & 0xFFC00000) >> 22
    return cluster, resource


def parse_jb_address(vmfs, address):
    """Parse a JB address and return the cluster and resource.

    Encoding:
        0b11111100 00000000 00000000 00000000  (cluster)
        0b00000000 00000000 11111111 11111000  (resource)
    """
    cluster = (address & 0xFC000000) >> 2
    resource = (address & 0x0000FFF8) >> 3
    return cluster, resource


def parse_lfb_address(vmfs, address):
    """Parse a LFB address and return the block.

    Encoding:
        0b00000000 00000000 00111111 11111111 11111111 11111111 10000000 00000000  (block)
    """
    return (address & 0x3FFFFFFF8000) >> 15


class ResourceManager:
    def __init__(self, vmfs):
        self.vmfs = vmfs
        self.resources = {}

    def open(self, resource_type, address=None, fileobj=None):
        if resource_type in self.resources:
            raise ValueError(f"Resource already opened: {resource_type}")

        if resource_type not in RESOURCE_TYPE_MAP:
            raise TypeError(f"Don't know how to open resource: {resource_type}")

        if not address and not fileobj:
            raise ValueError(f"No address or file object for resource: {resource_type}")

        if not fileobj:
            try:
                fd = self.vmfs.file_descriptor(address)
            except FileNotFoundError:
                return None

            if (
                fd.descriptor.address != address
                or fd.block_size != self.vmfs.block_size
                or fd.type != FileType.System
                or fd.size == 0
            ):
                return None

            fileobj = fd.open()

        try:
            self.resources[resource_type.value] = RESOURCE_TYPE_MAP[resource_type](
                self.vmfs, resource_type, address, fileobj
            )
        except Exception:
            return None

    def _get_resource_for_resource_type(self, resource_type):
        if not isinstance(resource_type, int):
            resource_type = resource_type.value

        if resource_type not in self.resources:
            raise ValueError(f"No resource opened for type {ResourceType(resource_type)}")
        return self.resources[resource_type]

    def _get_resource_for_address(self, address):
        addr_type = address_type(address)
        return self._get_resource_for_resource_type(addr_type)

    def get(self, address):
        resource = self._get_resource_for_address(address)
        return resource.get(address)

    def get_resource(self, resource_type, cluster, resource):
        return self._get_resource_for_resource_type(resource_type).get_resource(cluster, resource)

    def parse_address(self, address):
        resource = self._get_resource_for_address(address)
        return resource.parse_address(address)

    def resolve_address(self, address):
        resource = self._get_resource_for_address(address)
        return resource.resolve_address(address)

    @property
    def fdc(self):
        return self._get_resource_for_resource_type(ResourceType.FD)

    @property
    def pb2(self):
        return self._get_resource_for_resource_type(ResourceType.PB2)

    @property
    def pbc(self):
        return self._get_resource_for_resource_type(ResourceType.PB)

    @property
    def sbc(self):
        return self._get_resource_for_resource_type(ResourceType.SB)

    @property
    def fbb(self):
        return self._get_resource_for_resource_type(ResourceType.FB)

    @property
    def lfb(self):
        return self._get_resource_for_resource_type(ResourceType.LFB)

    @property
    def jbc(self):
        return self._get_resource_for_resource_type(ResourceType.JB)


class ResourceFile:
    """VMFS resource file implementation.

    Resource files of different types need different interpretation of the resource data.

    Resource files are made up of a header and multiple cluster groups. A group is made
    up of the clusters ("bitmaps"), followed by the actual resource items.
    """

    def __init__(self, vmfs, resource_type, address, fh):
        self.vmfs = vmfs
        self.type = resource_type
        self.address = address
        self.fh = fh

        self.metadata = c_vmfs.Res3_Metadata(self.fh)
        if self.vmfs.is_vmfs6 and self.metadata.signature != c_vmfs.VMFS_RESOURCE_META_SIGNATURE:
            raise ValueError("Invalid resource metadata signature")

        # Clusters groups contain a meta header for each cluster, followed by the actual cluster data
        if self.vmfs.is_vmfs5:
            self._cluster_resource_offset = self.metadata.clustersPerClusterGroup << 10
        else:
            alignment = 2 * self.vmfs.descriptor.mdAlignment
            self._cluster_resource_offset = self.metadata.clustersPerClusterGroup * alignment
        self._cluster_size = self.metadata.resourcePerCluster * self.metadata.resourceSize

    def iter_resource_locations(self):
        resource_per_cluster = self.metadata.resourcePerCluster
        num_resources = (self.metadata.numResourcesHi << 32) | self.metadata.numResourcesLo
        for abs_resource in range(num_resources):
            yield divmod(abs_resource, resource_per_cluster)

    @property
    def resource_size(self):
        return self.metadata.resourceSize

    def _cluster_header_offset(self, cluster):
        """Calculate the offset of a specific cluster header into the resource file."""
        md = self.metadata
        if self.vmfs.is_vmfs5:
            group, rel_cluster = divmod(cluster, md.clustersPerClusterGroup)
            group_offset = group * md.clusterGroupSize
            cluster_offset = rel_cluster << 10
            return md.firstClusterGroupOffset + group_offset + cluster_offset
        elif md.flags & 2 == 0:
            group, rel_cluster = divmod(cluster, md.clustersPerClusterGroup)
            group_offset = group * md.clusterGroupSize
            cluster_offset = rel_cluster * (2 * self.vmfs.descriptor.mdAlignment)
            return md.firstClusterGroupOffset + group_offset + cluster_offset
        else:
            parent_r_per_cg = md.parentResourcesPerCluster * md.parentClustersPerClusterGroup
            group, rel_cluster = divmod(cluster, parent_r_per_cg)
            group_offset = group * md.parentClusterGroupSize
            cluster_offset = md.parentClustersPerClusterGroup * (2 * self.vmfs.descriptor.mdAlignment) + rel_cluster
            return md.firstClusterGroupOffset + group_offset + cluster_offset

    def _cluster_group_offset(self, group):
        """Calculate the offset of a specific cluster group into the resource file."""
        md = self.metadata
        if self.vmfs.is_vmfs5 or (md.flags & 2 == 0):
            # Don't know what this flag means, maybe a compatibility flag for VMFS6 to work with VMFS5 resource files?
            return md.firstClusterGroupOffset + (group * md.clusterGroupSize)
        else:
            parent_size = md.parentClustersPerClusterGroup * md.parentSourcesPerCluster // md.clustersPerClusterGroup
            parent, rel_group = divmod(group, parent_size)
            parent_offset = parent * md.parentClusterGroupSize
            alignment = md.parentClustersPerClusterGroup * (2 * self.vmfs.descriptor.mdAlignment)
            group_offset = rel_group * md.clusterGroupSize
            return md.firstClusterGroupOffset + parent_offset + group_offset + alignment

    def _resource_offset(self, cluster, resource):
        """Calculate the offset of a specific resource into the resource file."""
        md = self.metadata
        group, rel_cluster = divmod(cluster, md.clustersPerClusterGroup)
        group_offset = md.firstClusterGroupOffset + (group * md.clusterGroupSize)
        cluster_offset = rel_cluster * self._cluster_size
        resource_offset = resource * md.resourceSize
        return group_offset + self._cluster_resource_offset + cluster_offset + resource_offset

    def parse_address(self, address):
        """Parse an address into a cluster/resource pair to use for looking up a resource."""
        raise NotImplementedError("Needs to be implemented by subclasses")

    def get(self, address):
        """Get the resource belonging to the given address."""
        cluster, resource = self.parse_address(address)
        return self.get_resource(cluster, resource)

    def get_resource(self, cluster, resource):
        """Get the resource belonging to the given cluster/resource pair."""
        offset = self._resource_offset(cluster, resource)
        self.fh.seek(offset)
        return self.fh.read(self.metadata.resourceSize)


class SmallFileBlockResource(ResourceFile):
    def parse_address(self, address):
        if self.vmfs.is_vmfs5:
            block = parse_fb_address(self.vmfs, address)
            return divmod(block, self.metadata.resourcePerCluster)
        elif self.vmfs.is_vmfs6:
            return parse_sfb_address(self.vmfs, address)


class SubBlockResource(ResourceFile):
    def parse_address(self, address):
        return parse_sb_address(self.vmfs, address)


class PointerBlockResource(ResourceFile):
    def parse_address(self, address):
        return parse_pb_address(self.vmfs, address)


class FileDescriptorResource(ResourceFile):
    def parse_address(self, address):
        return parse_fd_address(self.vmfs, address)


class JournalBlockResource(ResourceFile):
    def parse_address(self, address):
        return parse_jb_address(self.vmfs, address)


class LargeFileBlockResource(ResourceFile):
    def parse_address(self, address):
        block = parse_lfb_address(self.vmfs, address)
        return divmod(block, self.metadata.resourcePerCluster)


RESOURCE_TYPE_MAP = {
    ResourceType.FB: SmallFileBlockResource,
    ResourceType.SB: SubBlockResource,
    ResourceType.PB: PointerBlockResource,
    ResourceType.FD: FileDescriptorResource,
    ResourceType.PB2: PointerBlockResource,
    ResourceType.JB: JournalBlockResource,
    ResourceType.LFB: LargeFileBlockResource,
}
