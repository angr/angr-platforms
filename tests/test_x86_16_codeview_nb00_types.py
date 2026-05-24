from __future__ import annotations

import struct

from angr_platforms.X86_16.codeview_nb00 import parse_codeview_nb00_bytes


def test_parse_codeview_nb00_type_subsection():
    data = bytearray(64)
    debug_base = 16
    subdir_offset = 8
    data[debug_base : debug_base + 4] = b"NB00"
    struct.pack_into("<I", data, debug_base + 4, subdir_offset)
    subdir = debug_base + subdir_offset
    struct.pack_into("<H", data, subdir, 1)
    struct.pack_into("<HHLH", data, subdir + 2, 0x103, 1, 20, 8)
    type_blob = bytes([1]) + struct.pack("<H", 5) + bytes([0x8D, 3]) + b"foo"
    data[debug_base + 20 : debug_base + 20 + len(type_blob)] = type_blob
    data.extend(b"NB00" + struct.pack("<I", len(data) - debug_base))

    parsed = parse_codeview_nb00_bytes(bytes(data))

    assert parsed is not None
    assert len(parsed.type_definitions) == 1
    assert parsed.type_definitions[0].index == 0x200
    assert parsed.type_definitions[0].leaves[0].kind == "string"
    assert parsed.type_definitions[0].leaves[0].value == "foo"

