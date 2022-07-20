# References:
# - /usr/lib/vmware/vmkmod/lvmdriver

from bisect import bisect_right

from dissect.util.stream import AlignedStream

from dissect.vmfs.c_vmfs import c_vmfs, vmfs_uuid
from dissect.vmfs.exceptions import InvalidHeader

VMFS_LVM_PE_SIZE = c_vmfs.VMFS_LVM_PE_SIZE
VMFS_LVM_BASES = [
    0x100000,
    0x110000,
    0x200000,
    0x180000,
    0x900000,
]


class LVM(AlignedStream):
    """VMFS LVM implementation.

    Takes a list of file-like objects (or Extents) to construct a volume.

    VMFS should start at LVM dataOffset + 0x200000
    """

    def __init__(self, fh):
        fhs = [fh] if not type(fh) is list else fh

        size = None
        self.uuid = None
        self.version = None

        self.extents = []
        for fh in fhs:
            extent = Extent(fh) if not isinstance(fh, Extent) else fh

            if not self.uuid:
                size = extent.volume_info.size
                self.uuid = extent.uuid
                self.version = extent.metadata.majorVersion

            if extent.uuid != self.uuid:
                # Silently ignore extents from other LVMs
                continue

            self.extents.append(extent)

        if not self.extents:
            raise ValueError("No extents")

        self.extents.sort(key=lambda e: e.first_pe)
        self._extent_pe_offsets = [e.first_pe for e in self.extents if e.first_pe != 0]

        super().__init__(size)

    def _read(self, offset, length):
        r = []

        pe_offset = offset // VMFS_LVM_PE_SIZE

        extent_idx = bisect_right(self._extent_pe_offsets, pe_offset)
        while length > 0:
            extent = self.extents[extent_idx]

            offset_in_extent = offset - (extent.first_pe * VMFS_LVM_PE_SIZE)
            remaining_in_extent = extent.size - offset_in_extent

            read_length = min(length, remaining_in_extent)
            extent.seek(offset_in_extent)
            r.append(extent.read(read_length))

            length -= read_length
            offset += read_length
            extent_idx += 1

        return b"".join(r)


class Extent(AlignedStream):
    """VMFS LVM physical extent implementation.

    PE bitmap is at VMFS_LVM_PE_BITMAP_BASE + version dependent offset.


    It appears that the LVM can start at the following offsets, however that still needs to be verified:
    - 0x100000
    - 0x110000
    - 0x200000
    - 0x180000
    - 0x900000
    """

    def __init__(self, fh):
        self.fh = fh

        fh.seek(c_vmfs.VMFS_LVM_DEVICE_META_BASE)
        self.metadata = c_vmfs.LVM_DeviceMeta(fh)
        if self.metadata.magic != c_vmfs.VMFS_LVM_DEVICE_META_MAGIC:
            raise InvalidHeader(
                "Invalid extent header. "
                f"Expected 0x{c_vmfs.VMFS_LVM_DEVICE_META_MAGIC:08x}, got 0x{self.metadata.magic:08x}"
            )

        volume_info_offset = c_vmfs.VMFS_LVM_DEVICE_META_BASE + c_vmfs.VMFS5_LVM_INFO_OFFSET
        if self.metadata.majorVersion == 6:
            volume_info_offset = c_vmfs.VMFS_LVM_DEVICE_META_BASE + self.metadata.volumeInfoOffset

        device_name_offset = c_vmfs.VMFS_LVM_DEVICE_NAME_BASE + c_vmfs.VMFS5_LVM_INFO_OFFSET
        if self.metadata.majorVersion == 6:
            device_name_offset = c_vmfs.VMFS_LVM_DEVICE_NAME_BASE + self.metadata.volumeInfoOffset

        fh.seek(volume_info_offset)
        self.volume_info = c_vmfs.LVM_VolumeInfo(fh)

        fh.seek(device_name_offset)
        self.name = c_vmfs.char[None](fh).decode("utf-8")

        self.device_id = vmfs_uuid(self.metadata.deviceID)
        self.uuid = vmfs_uuid(self.volume_info.uuid)
        self.num_pe = self.volume_info.numPEs
        self.first_pe = self.volume_info.firstPE
        self.last_pe = self.volume_info.lastPE

        super().__init__(self.metadata.volumeSize)

    def _read(self, offset, length):
        self.fh.seek(self.metadata.dataOffset + offset)
        return self.fh.read(length)
