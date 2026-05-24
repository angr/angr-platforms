from __future__ import annotations

import struct

from angr_platforms.X86_16.turbo_debug_tdinfo import TDInfoSymbolClass, parse_tdinfo_exe_bytes


def _build_minimal_tdinfo_image() -> bytes:
    data = bytearray(512)
    data[0:2] = b"MZ"
    struct.pack_into("<HH", data, 2, 512, 1)
    debug_offset = 512
    name_pool = b"func\x00MYTYPE\x00"
    data.extend(b"\x00" * 96)
    struct.pack_into(
        "<HBBIHHHHH",
        data,
        debug_offset,
        0x52FB,
        1,
        3,
        len(name_pool),
        2,
        0,
        0,
        2,
        0,
    )
    struct.pack_into("<H", data, debug_offset + 42, 0)
    sym_off = debug_offset + 44
    struct.pack_into("<HHHHB", data, sym_off, 1, 0, 0x10, 0x20, TDInfoSymbolClass.STATIC)
    struct.pack_into("<HHHHB", data, sym_off + 9, 2, 0, 0, 0, TDInfoSymbolClass.TYPEDEF)
    data[-len(name_pool) :] = name_pool
    return bytes(data)


def test_tdinfo_exposes_symbol_classes_and_type_names():
    parsed = parse_tdinfo_exe_bytes(_build_minimal_tdinfo_image())

    assert parsed is not None
    assert parsed.type_names == ("MYTYPE",)
    assert TDInfoSymbolClass.STATIC in parsed.symbols_by_class
    assert TDInfoSymbolClass.TYPEDEF in parsed.symbols_by_class
    assert parsed.code_labels


def _build_tdinfo_image_with_version(major: int, minor: int) -> bytes:
    """Build a minimal TDS image with specified version."""
    data = bytearray(512)
    data[0:2] = b"MZ"
    struct.pack_into("<HH", data, 2, 512, 1)
    debug_offset = 512
    name_pool = b"func\x00"
    data.extend(b"\x00" * 96)
    struct.pack_into(
        "<HBBIHHHHH",
        data,
        debug_offset,
        0x52FB,
        minor,
        major,
        len(name_pool),
        2,
        0,
        0,
        1,
        0,
    )
    struct.pack_into("<H", data, debug_offset + 42, 0)
    sym_off = debug_offset + 44
    struct.pack_into("<HHHHB", data, sym_off, 1, 0, 0x10, 0x20, TDInfoSymbolClass.STATIC)
    data[-len(name_pool) :] = name_pool
    return bytes(data)


def test_tdinfo_version_identification_tds_28():
    """Test TDS 2.8 version identification (TLink 2.0a/2.0b)."""
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_version(2, 8))
    assert parsed is not None
    assert parsed.tds_version_str == "2.8"
    assert "2.0" in parsed.tlink_version_str


def test_tdinfo_version_identification_tds_29():
    """Test TDS 2.9 version identification (TLink 3.0/3.01)."""
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_version(2, 9))
    assert parsed is not None
    assert parsed.tds_version_str == "2.9"
    assert "3.0" in parsed.tlink_version_str


def test_tdinfo_version_identification_tds_30():
    """Test TDS 3.0 version identification (TLink 4.0)."""
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_version(3, 0))
    assert parsed is not None
    assert parsed.tds_version_str == "3.0"
    assert "4.0" in parsed.tlink_version_str


def test_tdinfo_version_identification_tds_310():
    """Test TDS 3.10 version identification (TLink 5.0/5.1)."""
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_version(3, 10))
    assert parsed is not None
    assert parsed.tds_version_str == "3.10"
    assert "5.0" in parsed.tlink_version_str


def test_tdinfo_version_identification_tds_41():
    """Test TDS 4.1 version identification (TLink 6.00/7.0a)."""
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_version(4, 1))
    assert parsed is not None
    assert parsed.tds_version_str == "4.1"
    assert "6.00" in parsed.tlink_version_str


def test_tdinfo_version_identification_tds_43():
    """Test TDS 4.3 version identification (TLink 7.1.30.1/7.1.32.2)."""
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_version(4, 3))
    assert parsed is not None
    assert parsed.tds_version_str == "4.3"
    assert "7.1" in parsed.tlink_version_str


def test_tdinfo_version_identification_unknown_version():
    """Test unknown TDS version returns unknown tlink version."""
    parsed = parse_tdinfo_exe_bytes(_build_tdinfo_image_with_version(9, 99))
    assert parsed is not None
    assert parsed.tds_version_str == "9.99"
    assert parsed.tlink_version_str == "unknown"
