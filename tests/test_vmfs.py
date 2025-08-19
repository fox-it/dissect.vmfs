from __future__ import annotations

import contextlib
import gzip
import stat

import pytest

from dissect.vmfs import lvm, vmfs
from dissect.vmfs.c_vmfs import FS3_Config, FS3_ZeroLevelAddrType, FS6_DirBlockType, c_vmfs
from dissect.vmfs.descriptor import _dir_hash_get_location, _dir_name_hash
from dissect.vmfs.exception import VolumeNotAvailableError
from tests.conftest import absolute_path


@pytest.mark.parametrize(
    ("path", "type"),
    [
        pytest.param("vmfs/vmfs5.bin.gz", "vmfs5", id="vmfs5"),
        pytest.param("vmfs/vmfs5l.bin.gz", "vmfs5l", id="vmfs5l"),
        pytest.param("vmfs/vmfs5d.bin.gz", "vmfs5d", id="vmfs5d"),
        pytest.param("vmfs/vmfs5ld.bin.gz", "vmfs5ld", id="vmfs5ld"),
        pytest.param("vmfs/vmfs6.bin.gz", "vmfs6", id="vmfs6"),
        pytest.param("vmfs/vmfs6l.bin.gz", "vmfs6l", id="vmfs6l"),
        pytest.param("vmfs/vmfs6d.bin.gz", "vmfs6d", id="vmfs6d"),
        pytest.param("vmfs/vmfs6ld.bin.gz", "vmfs6ld", id="vmfs6ld"),
        pytest.param("vmfs/vmfs5-resource-optimized.bin.gz", "vmfs5", id="vmfs5-resource-optimized"),
        pytest.param("vmfs/vmfs6-resource-optimized.bin.gz", "vmfs6", id="vmfs6-resource-optimized"),
        pytest.param("vmfs/vmfs5-no-dense-sbpc.bin.gz", "vmfs5", id="vmfs5-no-dense-sbpc"),
        pytest.param(["vmfs/span/vmfs5-span-0.bin.gz", "vmfs/span/vmfs5-span-1.bin.gz"], "vmfs5", id="vmfs5-span"),
        pytest.param(["vmfs/span/vmfs6-span-0.bin.gz", "vmfs/span/vmfs6-span-1.bin.gz"], "vmfs6", id="vmfs6-span"),
    ],
)
def test_vmfs_basic(path: str | list[str], type: str, request: pytest.FixtureRequest) -> None:
    """Test basic VMFS functionality and properties."""
    with contextlib.ExitStack() as stack:
        vs = None
        volume = None

        if not isinstance(path, list):
            path = [path]

        fhs = [stack.enter_context(gzip.open(absolute_path(f"_data/{p}"), "rb")) for p in path]

        if type in ("vmfs5d", "vmfs5ld", "vmfs6d", "vmfs6ld"):
            assert len(fhs) == 1
            volume = fhs[0]
        else:
            vs = lvm.LVM(fhs)
            assert len(vs.devices) == len(path)

        if vs is not None:
            assert len(vs.volumes) == 1
            volume = vs.volumes[0].open()

        fs = vmfs.VMFS(volume)

        if type.startswith("vmfs5"):
            assert fs.is_vmfs5
            assert not fs.is_vmfs6
        else:
            assert not fs.is_vmfs5
            assert fs.is_vmfs6

        if type in ("vmfs5l", "vmfs5ld", "vmfs6l", "vmfs6ld"):
            assert fs.is_local
        else:
            assert not fs.is_local

        assert fs.label == request.node.callspec.id
        if "no-dense-sbpc" in request.node.callspec.id:
            assert FS3_Config.DENSE_SBPC not in fs.descriptor.config
        else:
            assert FS3_Config.DENSE_SBPC in fs.descriptor.config

        root_dir = fs.get("/").listdir()
        for name in (".vh.sf", ".pb2.sf", ".pbc.sf", ".fbb.sf", ".fdc.sf", ".sbc.sf", ".sdd.sf") + (
            (".jbc.sf",) if fs.is_vmfs6 else ()
        ):
            assert name in root_dir, f"Expected {name} in root directory"

            fd = root_dir[name].fd
            assert fd.is_system(), f"{name} should be a system file"

            if name == ".sdd.sf":
                assert fd.is_dir(), f"{name} should be a directory"
                assert stat.S_ISDIR(fd.mode), f"{name} should be a directory"
            else:
                assert fd.is_file(), f"{name} should be a regular file"
                assert stat.S_ISREG(fd.mode), f"{name} should be a regular file"


@pytest.mark.parametrize(
    ("path"),
    [
        pytest.param("vmfs/vmfs5.bin.gz", id="vmfs5"),
        pytest.param("vmfs/vmfs6.bin.gz", id="vmfs6"),
    ],
)
def test_vmfs_content(path: str) -> None:
    """Test reading content from VMFS."""
    with gzip.open(absolute_path(f"_data/{path}"), "rb") as fh:
        vs = lvm.LVM(fh)
        fs = vmfs.VMFS(vs.volumes[0].open())

        # Test root
        fd = fs.get("/")
        assert fd.is_dir()
        assert stat.S_ISDIR(fd.mode)

        # Test a small file
        fd = fs.get("small")
        _assert_is_file(fd, 5, FS3_ZeroLevelAddrType.FILE_DESCRIPTOR_RESIDENT)
        assert fd.open().read() == b"tiny\n"

        # Test a big file
        fd = fs.get("big")
        _assert_is_file(fd, (1024 * 64 * 16) + 1, FS3_ZeroLevelAddrType.FILE_BLOCK)
        assert fd.open().read() == (b"Kusjes van SRT<3" * (1024 * 64)) + b"\n"

        # Test a bigger file
        fd = fs.get("bigger")
        _assert_is_file(fd, (1024 * 1024 * 128), FS3_ZeroLevelAddrType.FILE_BLOCK)
        assert fd.open().read() == b"".join((bytes([i % 256]) * 1024 * 1024) for i in range(128))

        # Test a symlink
        fd = fs.get("symlink")
        assert fd.is_symlink()
        assert stat.S_ISLNK(fd.mode)
        assert fd.link == f"/vmfs/volumes/{fs.label}/small"

        # Test a directory
        fd = fs.get("directory")
        assert fd.is_dir()
        assert stat.S_ISDIR(fd.mode)
        contents = fd.listdir()

        assert set(contents.keys()) == {f"file{i}" for i in range(1, 101)} | {".", ".."}, (
            "Expected 100 files in the directory"
        )

        for entry in contents.values():
            if entry.name in (".", ".."):
                continue
            content = f"File {entry.name[4:]}\n".encode()
            _assert_is_file(entry.fd, len(content), FS3_ZeroLevelAddrType.FILE_DESCRIPTOR_RESIDENT)
            assert entry.fd.open().read() == content

        # Test a small VMDK file
        fd = fs.get("normal-flat.vmdk")
        _assert_is_file(fd, 69 * 1024 * 1024 * 1024, FS3_ZeroLevelAddrType.POINTER_BLOCK)
        fh = fd.open()
        fh.seek(42 * 1024 * 1024 * 1024)
        assert fh.read(512) == b"\x42" * 512

        # Test a large VMDK file
        fd = fs.get("large-flat.vmdk")
        _assert_is_file(fd, 42 * 1024 * 1024 * 1024 * 1024, FS3_ZeroLevelAddrType.POINTER_BLOCK_DOUBLE)
        fh = fd.open()
        fh.seek(117 * 1024 * 1024 * 1024)
        assert fh.read(512) == b"\x42" * 512

        # Test a RDM file
        fd = fs.get("rdm-rdm.vmdk")
        assert fd.is_rdm()
        assert fd.size == 6969 * 1024 * 1024 * 1024
        assert fd.rdm_mapping.diskId.type == 1
        assert fd.rdm_mapping.diskId.len == 26
        assert fd.rdm_mapping.diskId.id[:26] == b"QM00015             QEMU H"

        # Test a directory with hash collisions (VMFS6 only, on VMFS5 this just iterates over the entries)
        fd = fs.get("collision")
        assert fd.is_dir()

        fh = fd.open()
        contents = fd.listdir()
        for name in contents:
            if fs.is_vmfs6 and name not in (".", ".."):
                # Manually verify that all the names are a hash collision
                assert _dir_name_hash(name, False)[1] == 0x26F7, name
                type, block, slot = _dir_hash_get_location(fh, 0x26F7)
                assert type == FS6_DirBlockType.LINK

                # And that we have enough hash collisions to fill a link group
                offset = (
                    # Block offset
                    c_vmfs.FS6_DIR_HEADER_BLOCK_SIZE
                    + (block * fs.md_alignment)
                    # Block header size
                    + len(c_vmfs.FS6_DirBlockHeader)
                    # Slot offset
                    + (slot * len(c_vmfs.FS6_DirLinkGroup))
                )
                fh.seek(offset)
                link_group = c_vmfs.FS6_DirLinkGroup(fh)
                assert link_group.nextGroup

            # Check that we can correctly retrieve the entry by name, following the link chain
            assert fd.get(name).name == name


def test_vmfs_jbosf() -> None:
    """Test reading a VMFS with JBOSF (Just a Bunch Of System Files)."""
    with gzip.open(absolute_path("_data/vmfs/vmfs5.bin.gz"), "rb") as fh:
        vs = lvm.LVM(fh)
        donor = vmfs.VMFS(vs.volumes[0].open())

        fs = vmfs.VMFS(
            vh=donor.get(".vh.sf").open(),
            fdc=donor.get(".fdc.sf").open(),
            fbb=donor.get(".fbb.sf").open(),
            sbc=donor.get(".sbc.sf").open(),
            pbc=donor.get(".pbc.sf").open(),
            pb2=donor.get(".pb2.sf").open(),
        )

        assert fs.is_vmfs5

        with pytest.raises(VolumeNotAvailableError):
            fs.get("small")

        fd = fs.get(donor.get("small").address)
        assert fd.open().read() == b"tiny\n"


def _assert_is_file(fd: vmfs.FileDescriptor, size: int, zla: FS3_ZeroLevelAddrType) -> None:
    """Assert that the file descriptor is a file with the given size and ZLA."""
    assert not fd.is_dir()
    assert fd.is_file()
    assert not fd.is_symlink()
    assert not fd.is_rdm()
    assert not fd.is_system()
    assert stat.S_ISREG(fd.mode)
    assert fd.size == size
    assert fd.zla == zla
