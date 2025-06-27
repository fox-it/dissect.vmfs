# References:
# - /usr/lib/vmware/vmkmod/lvmdriver
from __future__ import annotations

from bisect import bisect_right
from functools import cache
from operator import itemgetter
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import AlignedStream
from dissect.util.ts import from_unix_us

from dissect.vmfs.c_lvm import c_lvm
from dissect.vmfs.exception import InvalidHeader, VolumeNotAvailableError
from dissect.vmfs.util import vmfs_uuid

if TYPE_CHECKING:
    from collections.abc import Iterator


class LVM:
    """VMFS LVM implementation, supports LVM5 and LVM6.

    VMFS LVM is a logical volume manager that allows multiple physical devices to be combined into a single
    logical volume. Technically LVM supports multiple logical volumes, in fact LVM3 started with supporting 1024, later
    versions decreased it to 512. LVM6 only allows 1. In practice only one logical volume is ever used.

    Provide this class with file-like objects for all devices that make up the LVM, then access the
    :attr:`~LVM.volumes` attribute to get a list of logical volumes. A :class:`Volume` can be opened for reading
    by calling :meth:`Volume.open`.

    Args:
        fh: A file-like object or a list of file-like objects that constitute an LVM.
    """

    def __init__(self, fh: BinaryIO | Device | list[BinaryIO] | list[Device]):
        fhs = [fh] if type(fh) is not list else fh

        self.devices: list[Device] = []
        """List of :class:`Device` objects that make up the LVM."""
        self.volumes: list[Volume] = []
        """List of :class:`Volume` objects that are in the LVM."""

        for fh in fhs:
            device = Device(fh) if not isinstance(fh, Device) else fh
            self.devices.append(device)

        volume_map = {}
        for device in self.devices:
            for vol in device.volumes:
                lv_id = (vmfs_uuid(vol.volMeta.lvID.uuid), vol.volMeta.lvID.snapID)
                volume_map.setdefault(lv_id, []).append(device)

        self.volumes = [Volume(lv_uuid, lv_snap_id, devices) for (lv_uuid, lv_snap_id), devices in volume_map.items()]

    def __repr__(self) -> str:
        return f"<LVM devices={len(self.devices)} volumes={len(self.volumes)}>"


class Device:
    """VMFS LVM device implementation.

    Represents a single device in the LVM.

    LVM devices contain metadata that describes itself, the logical volumes and physical extents it contains.

    The metadata roughly looks like the following pseudo-structure:

    .. code-block:: c

        struct LVM_DeviceHeader {
            LVM_DevMetadata     devMeta;
            LVM_VolTableEntry   volTable[LVM_MAX_VOLUMES_PER_DEV];
            char                reserved[LVM_RESERVED_SIZE];
            LVM_SDTableEntry    sdTable[FS_PLIST_DEF_MAX_PARTITIONS];
            uint8               peBitmap[LVM_PE_BITMAP_SIZE];
            LVM_PETableEntry    peTable[LVM_PES_PER_BITMAP];
        };

    On versions prior to LVM6, it looks like the structure sizes are largely respected when calculating offsets to other
    tables. However, since LVM6 a specific field in ``LVM_DevMetadata`` is often used for this calculation.
    Because the real name of this field is unknown, we have decided to call it ``mdAlignment`` within this project,
    since it appears to be used in a similar way as in VMFS.

    The device metadata (``devMeta``) starts at a fixed offset (``0x00100000``), but since LVM6 may
    reference extended metadata at other offsets. The volume table (``volTable``) starts after ``devMeta``, which is
    ``0x00100000 + LVM_SIZEOF_LVM_DEVMETA``, where ``LVM_SIZEOF_LVM_DEVMETA`` is either ``512`` or since LVM6 the value
    of the ``mdAlignment`` field in the ``LVM_DevMetadata`` structure. Since LVM5 (I could not find evidence that LVM4
    exists) there exists a ``sdTable``, which is a table of device names, that starts at the end of the volume table.
    The ``peBitmap`` is a bitmap that describes which entries in the ``peTable`` are used, and starts at the end of the
    ``volTable``/``sdTable``. The ``peTable`` is a table of physical extents, which starts at the end of
    the ``peBitmap``. A pair of ``peBitmap`` and ``peTable`` repeats for ``numPEs`` times.

    The device metadata ``LVM_DevMetadata`` contains information about the device, including some identifiers and
    number of volumes and physical extents. There are also timestamps when the device was created and last modified.

    The volume descriptor ``LVM_VolDescriptor`` contains information about the logical volume, specific to that device.
    The ``LVM_VolMetadata`` structure contains metadata that is shared across all devices in the volume, but other
    fields in the descriptor are specific to that device (such as the first and last physical extent on that device).

    The "SD table" (storage device? SCSI disk?) is a table of device names that are part of the volume, which is only
    present in LVM5 and later, and only on the first device in the LVM (internally referred to as "devZero").

    The physical extent descriptors (``LVM_PEDescriptor``) contain information about the physical extents on the device,
    including the logical offset, physical offset and length of the extent, as well as a reference to the volume it
    belongs to. A device can have multiple physical extents, and the logical volume is constructed from these
    physical extents across all devices in the LVM.

    There can only be a maximum of 8 physical extent map/table pairs per metadata region (so 8 maps and 64k table
    entries). If more are needed, the device metadata will reference extended metadata regions, which are similarly
    laid out, but with a different offset. The extended metadata regions are linked together by the ``nextOffset`` field
    in the ``LVM_ExtDevMetadata`` structure.

    Args:
        fh: A file-like object of a LVM device.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        self.fh.seek(c_lvm.LVM_DEV_HEADER_OFFSET)
        self.metadata = c_lvm.LVM_DevMetadata(self.fh)
        self.ext_metadata = []

        if self.metadata.magic != c_lvm.LVM_MAGIC_NUMBER:
            raise InvalidHeader(
                f"Invalid device header. Expected 0x{c_lvm.LVM_MAGIC_NUMBER:08x}, got 0x{self.metadata.magic:08x}"
            )

        ext_dev_metadata_offset = self.metadata.extDevMetadataOffset
        while ext_dev_metadata_offset != 0:
            self.fh.seek(ext_dev_metadata_offset)
            ext_meta = c_lvm.LVM_ExtDevMetadata(self.fh)

            if ext_meta.magic != c_lvm.LVM_MAGIC_NUMBER:
                raise InvalidHeader(
                    "Invalid extended metadata header. "
                    f"Expected 0x{c_lvm.LVM_MAGIC_NUMBER:08x}, got 0x{ext_meta.magic:08x}"
                )

            self.ext_metadata.append(ext_meta)
            ext_dev_metadata_offset = ext_meta.nextOffset

        self.major_version = self.metadata.majorVersion
        self.minor_version = self.metadata.minorVersion
        self.uuid = vmfs_uuid(self.metadata.devID)
        self.size = self.metadata.totalBytes

        if self.major_version < 6:
            self._device_metadata_size = c_lvm.LVM_SIZEOF_LVM_DEVMETA_LVM5
            self._max_volumes_per_device = c_lvm.LVM_MAX_VOLUMES_PER_DEV_LVM5
            self._pe_bitmap_size = c_lvm.LVM_PE_BITMAP_SIZE_LVM5
        else:
            # LVM_SIZEOF_LVM_DEVMETA_LVM6(mdAlignment) (mdAlignment)
            self._device_metadata_size = self.metadata.mdAlignment
            self._max_volumes_per_device = c_lvm.LVM_MAX_VOLUMES_PER_DEV_LVM6
            # LVM_PE_BITMAP_SIZE_LVM6(mdAlignment)  (MAX(mdAlignment, LVM_PE_BITMAP_SIZE_LVM5))
            self._pe_bitmap_size = max(self.metadata.mdAlignment, c_lvm.LVM_PE_BITMAP_SIZE_LVM5)

        # LVM_UNUSED_MD_SECTORS (1024 - (LVM_MAX_VOLUMES_PER_DEV))
        self._unused_md_sectors = 1024 - self._max_volumes_per_device
        # LVM_UNUSED_MD_SIZE    LVM_UNUSED_MD_SECTORS * DISK_BLOCK_SIZE_512B
        self._unused_md_size = self._unused_md_sectors * c_lvm.DISK_BLOCK_SIZE_512B
        # LVM_RESERVED_SIZE     (LVM_UNUSED_MD_SIZE - LVM_SIZEOF_SDTENTRY * FS_PLIST_DEF_MAX_PARTITIONS)
        self._reserved_size = self._unused_md_size - (c_lvm.LVM_SIZEOF_SDTENTRY * c_lvm.FS_PLIST_DEF_MAX_PARTITIONS)

        # Basically offsetof(LVM_DeviceHeader, volTable)
        self._offset_to_volume_table = self._device_metadata_size
        # Basically offsetof(LVM_DeviceHeader, sdTable)
        self._offset_to_sd_table = (
            self._offset_to_volume_table
            # Size of volume table
            + (self._max_volumes_per_device * c_lvm.LVM_SIZEOF_VTENTRY)
            # Size of reserved space
            + self._reserved_size
        )
        # Basically offsetof(LVM_DeviceHeader, peBitmap)
        self._offset_to_pe_bitmap = (
            self._offset_to_sd_table
            # Size of SD table
            + (c_lvm.LVM_SIZEOF_SDTENTRY * c_lvm.FS_PLIST_DEF_MAX_PARTITIONS)
        )

        if self.metadata.numVolumes > self._max_volumes_per_device:
            raise ValueError(f"Unsupported number of volumes in LVM metadata: {self.metadata.numVolumes}")

        # Basically offsetof(LVM_DeviceHeader, volTable)
        # LVM_DEV_HEADER_OFFSET + LVM_SIZEOF_LVM_DEVMETA(majorVersion,mdAlignment)
        volume_table_offset = c_lvm.LVM_DEV_HEADER_OFFSET + self._device_metadata_size

        self.fh.seek(volume_table_offset)
        self.volumes = [entry.volDesc for entry in c_lvm.LVM_VolTableEntry[self.metadata.numVolumes](self.fh)]

    def __repr__(self) -> str:
        return f"<Device uuid={self.uuid} size={self.metadata.totalBytes}>"

    def _iter_pe_offsets(self) -> Iterator[tuple[int, int]]:
        """Iterate over the offsets of the physical extent bitmaps and data offsets."""
        num_pe_maps = self.metadata.numPEMaps or 1

        # Basically offsetof(LVM_DeviceHeader, peBitmap)
        pe_bitmap_offset = c_lvm.LVM_DEV_HEADER_OFFSET + self._offset_to_pe_bitmap
        pe_data_offset = self.metadata.dataOffset

        ext_dev_metadata_offset = self.metadata.extDevMetadataOffset
        ext_meta_it = iter(self.ext_metadata)

        pe_table_size = c_lvm.LVM_PES_PER_BITMAP * c_lvm.LVM_SIZEOF_PTENTRY

        while True:
            for i in range(num_pe_maps):
                map_offset = pe_bitmap_offset + (i * (self._pe_bitmap_size + pe_table_size))
                data_offset = pe_data_offset + ((i << 13) << 28)

                yield map_offset, data_offset

            if (ext_meta := next(ext_meta_it, None)) is None:
                break

            num_pe_maps = ext_meta.numPEMaps
            pe_bitmap_offset = ext_dev_metadata_offset + self._offset_to_pe_bitmap
            pe_data_offset = ext_meta.dataOffset

            ext_dev_metadata_offset = ext_meta.nextOffset

    def _iter_pe(self) -> Iterator[c_lvm.LVM_PETableEntry]:
        """Iterate over the physical extent entries in the device."""
        pe_idx = 0

        for map_offset, _ in self._iter_pe_offsets():
            table_offset = map_offset + self._pe_bitmap_size
            for _ in range(min(self.metadata.numPEs - pe_idx, c_lvm.LVM_PES_PER_BITMAP)):
                self.fh.seek(table_offset)
                yield c_lvm.LVM_PETableEntry(self.fh)
                table_offset += c_lvm.LVM_SIZEOF_PTENTRY
                pe_idx += 1

            if pe_idx == self.metadata.numPEs:
                break


class Volume:
    """Logical volume in a VMFS LVM.

    Represents a logical volume that is constructed from one or more devices.

    Args:
        uuid: The UUID of the volume.
        snap_id: The snapshot ID of the volume.
        devices: A list of :class:`Device` objects that make up the volume. Must contain at least one device.
    """

    def __init__(self, uuid: str, snap_id: int, devices: list[Device]):
        self.uuid = uuid
        self.snap_id = snap_id
        self.devices = devices

        if not devices:
            raise ValueError("Need at least one device to construct a volume")

        self._volume_descriptor_map = {}
        for device in devices:
            for volume in device.volumes:
                if (vmfs_uuid(volume.volMeta.lvID.uuid), volume.volMeta.lvID.snapID) == (uuid, snap_id):
                    self._volume_descriptor_map[device.uuid] = volume

        self.devices.sort(key=lambda d: self._volume_descriptor_map[d.uuid].firstPE)

        dev_zero = self.devices[0]
        vol_desc = self._volume_descriptor_map[dev_zero.uuid]
        self.size = vol_desc.volMeta.logicalSize
        self.generation = vol_desc.volMeta.generation
        self.state = vol_desc.volMeta.state
        self.name = vol_desc.volMeta.name.split(b"\x00", 1)[0].decode()
        self.creation_ts = from_unix_us(vol_desc.volMeta.creationTimeUS)

        # Valid devZero
        if dev_zero.major_version >= 5 and vol_desc.firstPE == 0:
            dev_zero.fh.seek(c_lvm.LVM_DEV_HEADER_OFFSET + dev_zero._offset_to_sd_table)

            self.device_names = [
                c_lvm.LVM_SDTableEntry(dev_zero.fh).deviceName.split(b"\x00", 1)[0].decode()
                for _ in range(vol_desc.extVolMeta.numDevs)
            ]
        else:
            self.device_names = []

        self.dataruns = cache(self.dataruns)

    def __repr__(self) -> str:
        return f"<Volume name={self.name!r} size={self.size} state={self.state.name}>"

    def is_valid(self) -> bool:
        """Check if the volume is valid and can be opened for reading."""
        # Should have at least one device
        if not self.devices:
            return False

        vol_desc = self._volume_descriptor_map.get(self.devices[0].uuid)

        # Should have devZero
        if vol_desc.firstPE != 0:
            return False

        # Should have the expected number of devices
        if vol_desc.extVolMeta.numDevs != len(self.devices):
            return False

        # Must have a continuous range of physical extents
        current_pe = 0
        for device in self.devices:
            if self._volume_descriptor_map[device.uuid].firstPE != current_pe:
                return False

            current_pe = self._volume_descriptor_map[device.uuid].lastPE + 1

        return True

    def _iter_pe(self) -> Iterator[tuple[int, int, int, Device]]:
        """Iterate over the physical extents that belong to this volume."""

        def _iter_pe_raw() -> Iterator[tuple[int, int, int, Device]]:
            for device in self.devices:
                vol_desc = self._volume_descriptor_map[device.uuid]

                for pe in device._iter_pe():
                    if not pe.used:
                        continue

                    pe_desc = pe.peDesc
                    if pe_desc.volumeID != vol_desc.volumeID:
                        continue

                    yield pe_desc.lOffset, pe_desc.pOffset, pe_desc.length, device

        yield from sorted(_iter_pe_raw(), key=itemgetter(0))

    def dataruns(self) -> list[tuple[int, int, int, Device]]:
        """Get the dataruns of the volume.

        Returns:
            A list of tuples of ``(logical_offset, physical_offset, size, device)`` for each run of contiguous data.
        """
        runs = []
        run_logical_offset = None
        run_physical_offset = None
        run_size = None
        run_device = None

        expected_offset = 0
        for logical_offset, physical_offset, length, device in self._iter_pe():
            if logical_offset != expected_offset:
                raise ValueError(
                    f"Found hole in volume physical extents: expected {expected_offset:#x}, got {logical_offset:#x}"
                )

            expected_offset += length

            if run_logical_offset is None:
                run_logical_offset = logical_offset
                run_physical_offset = physical_offset
                run_size = length
                run_device = device
                continue

            if run_physical_offset + run_size == physical_offset and run_device == device:
                # Extend the current run
                run_size += length
            else:
                # Save the current run and start a new one
                runs.append((run_logical_offset, run_physical_offset, run_size, run_device))
                run_logical_offset = logical_offset
                run_physical_offset = physical_offset
                run_size = length
                run_device = device

        if run_logical_offset is not None:
            runs.append((run_logical_offset, run_physical_offset, run_size, run_device))

        return runs

    def open(self) -> VolumeStream:
        """Open a read-only stream for the volume."""
        if not self.is_valid():
            raise VolumeNotAvailableError("Volume is in an invalid state and cannot be opened for reading")
        return VolumeStream(self)


class VolumeStream(AlignedStream):
    """Read-only stream that allows reading from VMFS LVM volumes.

    Args:
        volume: The :class:`Volume` to provide a stream for.
    """

    def __init__(self, volume: Volume):
        self.volume = volume
        self.runs = volume.dataruns()
        self._lookup = [logical_offset for logical_offset, _, _, _ in self.runs if logical_offset != 0]
        super().__init__(volume.size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        run_idx = bisect_right(self._lookup, offset)
        while length > 0:
            logical_offset, physical_offset, run_length, device = self.runs[run_idx]
            offset_in_run = offset - logical_offset
            remaining_in_run = run_length - offset_in_run

            read_length = min(length, remaining_in_run)
            device.fh.seek(physical_offset + offset_in_run)
            result.append(device.fh.read(read_length))

            length -= read_length
            offset += read_length
            run_idx += 1

        return b"".join(result)
