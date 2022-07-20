from dissect.vmfs import lvm


def test_lvm5(vmfs5):
    vs = lvm.LVM(vmfs5)

    assert vs.uuid == "61137dd5-d0727810-7ac2-000c29801686"
    assert vs.version == 5
    assert len(vs.extents) == 1

    extent = vs.extents[0]
    assert extent.name == "mpx.vmhba0:C0:T4:L0:1"
    assert extent.device_id == "61137dd5-dc4830ac-56f8-000c29801686"
    assert extent.uuid == "61137dd5-d0727810-7ac2-000c29801686"
    assert extent.num_pe == 1
    assert extent.first_pe == 0
    assert extent.last_pe == 0


def test_lvm6(vmfs6):
    vs = lvm.LVM(vmfs6)

    assert vs.uuid == "6113001e-95afd8fb-d830-000c29801686"
    assert vs.version == 6
    assert len(vs.extents) == 1

    extent = vs.extents[0]
    assert extent.name == "mpx.vmhba0:C0:T2:L0:1"
    assert extent.device_id == "6113001e-a232f065-7369-000c29801686"
    assert extent.uuid == "6113001e-95afd8fb-d830-000c29801686"
    assert extent.num_pe == 3
    assert extent.first_pe == 0
    assert extent.last_pe == 2
