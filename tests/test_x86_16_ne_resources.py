from __future__ import annotations

import struct

from angr_platforms.X86_16.ne_resources import parse_ne_resources_bytes


def _build_minimal_win16_ne_with_resource() -> bytes:
    data = bytearray(0x120)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x42] = b"NE"
    struct.pack_into("<H", data, 0x40 + 0x24, 0x40)
    data[0x40 + 0x36] = 0x02
    resource_table_offset = 0x40 + 0x40
    struct.pack_into("<H", data, resource_table_offset, 0)
    cursor = resource_table_offset + 2
    struct.pack_into("<H", data, cursor, 0x8003)
    cursor += 2
    struct.pack_into("<HI", data, cursor, 1, 0)
    cursor += 6
    struct.pack_into("<HHHHHH", data, cursor, 0x100, 0x08, 0, 0x8001, 0, 0)
    cursor += 12
    struct.pack_into("<H", data, cursor, 0)
    data[0x100:0x108] = b"ABCDEFGH"
    return bytes(data)


def test_parse_ne_resources_win16_named_group():
    parsed = parse_ne_resources_bytes(_build_minimal_win16_ne_with_resource())

    assert parsed is not None
    assert parsed.kind == "win16"
    assert parsed.groups[0].name == "ICON"
    assert parsed.groups[0].entries[0].name == "1"
    assert parsed.groups[0].entries[0].length == 8
    assert parsed.groups[0].entries[0].bytes_data == b"ABCDEFGH"
