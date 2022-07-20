import io

from dissect.vmfs import lvm, vmfs


def test_vmfs5(vmfs5):
    fh = lvm.LVM(vmfs5)
    fs = vmfs.VMFS(fh)

    assert fs.block_size == 0x100000
    assert fs.major_version == 0xE
    assert fs.minor_version == 0x51

    assert fs.uuid == "61137dd5-df6bc2c8-f0e7-000c29801686"
    assert fs.label == "VMFS5 Test"

    assert fs._fd_size == 0x800
    assert fs._fd_resident_size == 0x400
    assert fs._fd_block_count == 0x100
    assert fs._fd_block_data_size == 0x400
    assert fs._pb_size == 0x400
    assert fs._pb_index_shift == 10
    assert fs._fd_small_data_offset == 0x400
    assert fs._fd_block_data_offset == 0x400

    assert fs.resources.fdc.resource_size == 0x800

    assert fs.root.size == 0x578

    verify_fs_content(fs)


def test_vmfs6(vmfs6):
    fh = lvm.LVM(vmfs6)
    fs = vmfs.VMFS(fh)

    assert fs.block_size == 0x100000
    assert fs.major_version == 0x18
    assert fs.minor_version == 0x52

    assert fs.uuid == "6113001e-a6377ebc-1d24-000c29801686"
    assert fs.label == "VMFS6 Test"

    assert fs._fd_size == 0x2000
    assert fs._fd_resident_size == 0xE00
    assert fs._fd_block_count == 0x140
    assert fs._fd_block_data_size == 0xA00
    assert fs._pb_size == 0x2000
    assert fs._pb_index_shift == 13
    assert fs._fd_small_data_offset == 0x1200
    assert fs._fd_block_data_offset == 0x1600
    assert fs._lfb_block_size == 0x20000000
    assert fs._lfb_offset_shift == 29

    assert fs.resources.fdc.resource_size == 0x2000

    assert fs.root.size == 0x12000

    verify_fs_content(fs)


def verify_fs_content(fs):
    root_entries = fs.root.listdir()

    assert ".fbb.sf" in root_entries
    assert ".fdc.sf" in root_entries
    assert ".vh.sf" in root_entries
    assert "directory" in root_entries
    assert root_entries["directory"].is_dir()

    if fs.is_vmfs6:
        assert root_entries["directory"].parent.address == fs.root.address

    dir_entries = fs.get("directory").listdir()

    assert set(dir_entries.keys()) == {
        ".",
        "..",
        "file1",
        "file2",
        "file3",
        "file4",
        "file5",
        "symlink",
    }

    for test_file in ("file1", "file2", "file3"):
        file_entry = dir_entries[test_file]
        assert file_entry.is_file()
        assert file_entry.size == 0

    file4 = dir_entries["file4"]
    assert file4.is_file()
    assert file4.size == 8
    file4_fh = file4.open()
    assert isinstance(file4_fh, io.BytesIO)
    assert file4_fh.read() == b"content\n"

    file5 = dir_entries["file5"]
    assert file5.is_file()
    assert file5.size == 8193
    file5_fh = file5.open()
    assert isinstance(file5_fh, vmfs.BlockStream)
    assert file5_fh.read() == (b"a" * 8192) + b"\n"

    symlink = dir_entries["symlink"]
    assert symlink.is_symlink()
    assert symlink.link == "file4"
