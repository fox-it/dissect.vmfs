from __future__ import annotations

import gzip
import io

import pytest
from dissect.util.stream import MappingStream

from dissect.vmfs import lvm
from tests.conftest import absolute_path


@pytest.mark.parametrize(
    ("path", "version"),
    [
        pytest.param("lvm/lvm3.bin.gz", 3, id="lvm3"),
        pytest.param("lvm/lvm4.bin.gz", 4, id="lvm4"),
        pytest.param("lvm/lvm5.bin.gz", 5, id="lvm5"),
        pytest.param("lvm/lvm6.bin.gz", 6, id="lvm6"),
    ],
)
def test_lvm_basic(path: str, version: int) -> None:
    with gzip.open(absolute_path(f"_data/{path}"), "rb") as fh:
        vs = lvm.LVM(fh)

        assert len(vs.devices) == 1

        dev = vs.devices[0]
        assert dev.major_version == version

        assert len(vs.volumes) == 1

        vol = vs.volumes[0]
        assert vol.name == f"lvm{version}"
        assert vol.size == 512 * 1024 * 1024

        if dev.major_version >= 5:
            assert len(vol.device_names) == 1
            assert len(vol.device_names[0]) > 0
        else:
            assert len(vol.device_names) == 0

        vol_fh = vol.open()
        for i in range(vol.size // 1024 // 1024):
            assert vol_fh.read(1024 * 1024) == bytes([i % 256]) * 1024 * 1024, f"Failed at block {i}"


@pytest.mark.parametrize(
    ("paths", "version"),
    [
        pytest.param(["lvm/span/lvm3-span-0.bin.gz", "lvm/span/lvm3-span-1.bin.gz"], 3, id="lvm3"),
        pytest.param(["lvm/span/lvm4-span-0.bin.gz", "lvm/span/lvm4-span-1.bin.gz"], 4, id="lvm4"),
        pytest.param(["lvm/span/lvm5-span-0.bin.gz", "lvm/span/lvm5-span-1.bin.gz"], 5, id="lvm5"),
        pytest.param(["lvm/span/lvm6-span-0.bin.gz", "lvm/span/lvm6-span-1.bin.gz"], 6, id="lvm6"),
    ],
)
def test_lvm_span(paths: list[str], version: int) -> None:
    vs = lvm.LVM([gzip.open(absolute_path(f"_data/{p}"), "rb") for p in paths])  # noqa: SIM115

    assert len(vs.devices) == 2
    for dev in vs.devices:
        assert dev.major_version == version
        assert dev.size < 1024 * 1024 * 1024

    assert len(vs.volumes) == 1

    vol = vs.volumes[0]
    assert vol.name == f"lvm{version}-span"
    assert vol.size == 1024 * 1024 * 1024
    assert len({run[-1] for run in vol.dataruns()}) == 2

    if dev.major_version >= 5:
        assert len(vol.device_names) == 2
        assert len(vol.device_names[0]) > 0
        assert len(vol.device_names[1]) > 0
    else:
        assert len(vol.device_names) == 0

    vol_fh = vol.open()
    for i in range(vol.size // 1024 // 1024):
        assert vol_fh.read(1024 * 1024) == bytes([i % 256]) * 1024 * 1024, f"Failed at block {i}"


@pytest.mark.parametrize(
    ("path", "name", "version", "num_pe", "num_ext_metadata"),
    [
        pytest.param("lvm/huge/lvm5.csv.gz", "lvm5-huge", 5, 0x3FFFF, 3, id="lvm5"),
        pytest.param("lvm/huge/lvm6.csv.gz", "lvm6-huge", 6, 4, 0, id="lvm6"),
    ],
)
def test_huge(path: str, name: str, version: int, num_pe: int, num_ext_metadata: int) -> None:
    # The entire file is way too large, so only take just enough data that we actually need to make our parser happy
    # We use a MappingStream to stitch everything together at the correct offsets
    stream = MappingStream()
    with io.TextIOWrapper(gzip.open(absolute_path(f"_data/{path}"), "r")) as fh:
        for line in fh:
            offset, data = line.strip().split(",")
            buf = bytes.fromhex(data)
            stream.add(int(offset), len(buf), io.BytesIO(buf), 0)

    vs = lvm.LVM(stream)

    assert len(vs.devices) == 1

    dev = vs.devices[0]
    assert dev.major_version == version
    assert dev.metadata.numPEs == num_pe
    assert len(dev.ext_metadata) == num_ext_metadata

    assert len(vs.volumes) == 1

    vol = vs.volumes[0]
    assert vol.name == name
    assert vol.size == (64 * 1024 * 1024 * 1024 * 1024) - 0x10000000
    assert len(vol.dataruns()) == 4

    vol_fh = vol.open()

    vol_fh.seek(0)
    assert vol_fh.read(32).strip(b"\x00") == b"Logical offset 0"

    vol_fh.seek(0x100000000000)
    assert vol_fh.read(32).strip(b"\x00") == b"Logical offset 0x100000000000"

    vol_fh.seek(0x200000000000)
    assert vol_fh.read(32).strip(b"\x00") == b"Logical offset 0x200000000000"

    vol_fh.seek(0x300000000000)
    assert vol_fh.read(32).strip(b"\x00") == b"Logical offset 0x300000000000"
