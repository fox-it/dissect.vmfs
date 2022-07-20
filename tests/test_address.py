from unittest.mock import Mock

from dissect.vmfs.resource import address_type, address_fmt
from dissect.vmfs.c_vmfs import ResourceType


def test_address_type():
    assert address_type(0x00000001) == ResourceType.FB
    assert address_type(0x00000002) == ResourceType.SB
    assert address_type(0x00000003) == ResourceType.PB
    assert address_type(0x00000004) == ResourceType.FD
    assert address_type(0x00000005) == ResourceType.PB2
    assert address_type(0x00000006) == ResourceType.JB
    assert address_type(0x00000007) == ResourceType.LFB


def test_address_fmt_vmfs5():
    mock_vmfs5 = Mock()
    mock_vmfs5.is_vmfs5 = True
    mock_vmfs5.is_vmfs6 = False
    mock_vmfs5.descriptor.config = 0

    assert address_fmt(mock_vmfs5, 0x00000001) == "<FB tbz=False cow=False 0>"
    assert address_fmt(mock_vmfs5, 0x00000011) == "<FB tbz=False cow=True 0>"
    assert address_fmt(mock_vmfs5, 0x00000021) == "<FB tbz=True cow=False 0>"
    assert address_fmt(mock_vmfs5, 0xFFFFFFC1) == "<FB tbz=False cow=False 67108863>"

    assert address_fmt(mock_vmfs5, 0x00000002) == "<SB cow=False c0 r0>"
    assert address_fmt(mock_vmfs5, 0x00000012) == "<SB cow=True c0 r0>"
    assert address_fmt(mock_vmfs5, 0x00000002) == "<SB cow=False c0 r0>"
    assert address_fmt(mock_vmfs5, 0x0FFFFFC2) == "<SB cow=False c4194303 r0>"
    assert address_fmt(mock_vmfs5, 0xF0000002) == "<SB cow=False c0 r15>"
    assert address_fmt(mock_vmfs5, 0xFFFFFFC2) == "<SB cow=False c4194303 r15>"

    mock_vmfs5.descriptor.config = 4
    assert address_fmt(mock_vmfs5, 0x0FFFFFC2) == "<SB cow=False c4194303 r0>"
    assert address_fmt(mock_vmfs5, 0xFFFFFFDA) == "<SB cow=True c4194303 r63>"  # extended also set the COW flag?

    assert address_fmt(mock_vmfs5, 0x00000003) == "<PB cow=False c0 r0>"
    assert address_fmt(mock_vmfs5, 0x00000013) == "<PB cow=True c0 r0>"
    assert address_fmt(mock_vmfs5, 0x0FFFFFC3) == "<PB cow=False c4194303 r0>"
    assert address_fmt(mock_vmfs5, 0xF0000003) == "<PB cow=False c0 r15>"
    assert address_fmt(mock_vmfs5, 0xFFFFFFC3) == "<PB cow=False c4194303 r15>"

    assert address_fmt(mock_vmfs5, 0x00000004) == "<FD c0 r0>"
    assert address_fmt(mock_vmfs5, 0x003FFFC4) == "<FD c65535 r0>"
    assert address_fmt(mock_vmfs5, 0xFFC00004) == "<FD c0 r1023>"
    assert address_fmt(mock_vmfs5, 0xFFFFFFC4) == "<FD c65535 r1023>"

    assert address_fmt(mock_vmfs5, 0x00000005) == "<PB2 cow=False c0 r0>"
    assert address_fmt(mock_vmfs5, 0x00000015) == "<PB2 cow=True c0 r0>"
    assert address_fmt(mock_vmfs5, 0x0FFFFFC5) == "<PB2 cow=False c4194303 r0>"
    assert address_fmt(mock_vmfs5, 0xF0000005) == "<PB2 cow=False c0 r15>"
    assert address_fmt(mock_vmfs5, 0xFFFFFFC5) == "<PB2 cow=False c4194303 r15>"

    assert address_fmt(mock_vmfs5, 0x00000006) == "<JB c0 r0>"
    assert address_fmt(mock_vmfs5, 0xFC000006) == "<JB c1056964608 r0>"
    assert address_fmt(mock_vmfs5, 0x0000FFFE) == "<JB c0 r8191>"
    assert address_fmt(mock_vmfs5, 0xFC00FFFE) == "<JB c1056964608 r8191>"

    assert address_fmt(mock_vmfs5, 0x00000000) == "<Null address>"


def test_address_fmt_vmfs6():
    mock_vmfs6 = Mock()
    mock_vmfs6.is_vmfs5 = False
    mock_vmfs6.is_vmfs6 = True

    assert address_fmt(mock_vmfs6, 0x0000000000000001) == "<SFB tbz=0x0 cow=False c0 r0>"
    assert address_fmt(mock_vmfs6, 0x0000000000000011) == "<SFB tbz=0x0 cow=True c0 r0>"
    assert address_fmt(mock_vmfs6, 0x0000000000000081) == "<SFB tbz=0x1 cow=False c0 r0>"
    assert address_fmt(mock_vmfs6, 0x0000000000007F81) == "<SFB tbz=0xff cow=False c0 r0>"
    assert address_fmt(mock_vmfs6, 0x00003FFFFFFF8001) == "<SFB tbz=0x0 cow=False c2147483647 r0>"
    assert address_fmt(mock_vmfs6, 0xFFF8000000000001) == "<SFB tbz=0x0 cow=False c0 r8191>"
    assert address_fmt(mock_vmfs6, 0xFFF83FFFFFFF8001) == "<SFB tbz=0x0 cow=False c2147483647 r8191>"

    assert address_fmt(mock_vmfs6, 0x0000000000000002) == "<SB cow=False c0 r0>"
    assert address_fmt(mock_vmfs6, 0x0000000000000012) == "<SB cow=True c0 r0>"
    assert address_fmt(mock_vmfs6, 0x000000FFFFFFFFC2) == "<SB cow=False c17179869183 r0>"
    assert address_fmt(mock_vmfs6, 0xFF00000000000002) == "<SB cow=False c0 r255>"
    assert address_fmt(mock_vmfs6, 0xFF0000FFFFFFFFC2) == "<SB cow=False c17179869183 r255>"

    assert address_fmt(mock_vmfs6, 0x0000000000000003) == "<PB cow=False c0 r0>"
    assert address_fmt(mock_vmfs6, 0x0000000000000013) == "<PB cow=True c0 r0>"
    assert address_fmt(mock_vmfs6, 0x000000FFFFFFFFC3) == "<PB cow=False c17179869183 r0>"
    assert address_fmt(mock_vmfs6, 0xFF00000000000003) == "<PB cow=False c0 r255>"
    assert address_fmt(mock_vmfs6, 0xFF0000FFFFFFFFC3) == "<PB cow=False c17179869183 r255>"

    assert address_fmt(mock_vmfs6, 0x0000000000000005) == "<PB2 cow=False c0 r0>"
    assert address_fmt(mock_vmfs6, 0x0000000000000015) == "<PB2 cow=True c0 r0>"
    assert address_fmt(mock_vmfs6, 0x000000FFFFFFFFC5) == "<PB2 cow=False c17179869183 r0>"
    assert address_fmt(mock_vmfs6, 0xFF00000000000005) == "<PB2 cow=False c0 r255>"
    assert address_fmt(mock_vmfs6, 0xFF0000FFFFFFFFC5) == "<PB2 cow=False c17179869183 r255>"

    assert address_fmt(mock_vmfs6, 0x0000000000000007) == "<LFB tbz=0x0 cow=False 0>"
    assert address_fmt(mock_vmfs6, 0x0000000000000017) == "<LFB tbz=0x0 cow=True 0>"
    assert address_fmt(mock_vmfs6, 0x0000000000000087) == "<LFB tbz=0x1 cow=False 0>"
    assert address_fmt(mock_vmfs6, 0x0000000000007F87) == "<LFB tbz=0xff cow=False 0>"
    assert address_fmt(mock_vmfs6, 0x00003FFFFFFF8007) == "<LFB tbz=0x0 cow=False 2147483647>"
