from __future__ import annotations

import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dissect.vmfs.c_lvm import c_lvm
    from dissect.vmfs.c_vmfs import c_vmfs


def bsf(value: int) -> int:
    """Count the number of zero bits in an integer of a given size."""
    return (value & -value).bit_length() - 1 if value else 0


def vmfs_uuid(buf: bytes | c_lvm.UUID | c_vmfs.UUID) -> str:
    """Convert a UUID structure or bytes to a string representation.

    UUIDs in VMFS are represented as a combination of time, random bits and the host MAC address.

    Args:
        buf: The UUID structure or bytes to convert.
    """
    if isinstance(buf, bytes):
        time_lo, time_hi, rand, mac_addr = struct.unpack("<IIH6s", buf)
    else:
        time_lo, time_hi, rand, mac_addr = buf.timeLo, buf.timeHi, buf.rand, buf.macAddr
    return f"{time_lo:08x}-{time_hi:08x}-{rand:04x}-{mac_addr.hex()}"
