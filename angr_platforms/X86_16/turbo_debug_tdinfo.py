from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

_TDINFO_MAGIC = 0x52FB
_PAGE_SIZE = 512

# TLink/TDS Version Identification Table
# Maps TDS major.minor version to TLink version, commandline format, and associated products
#
# OLD Format (1.0-1.1 did not contain TDS info):
#   TDS 2.8  -> TLink 2.0a (31.10.1988) - Turbo Assembler 1.0, Turbo C 2.0, Turbo C 2.01
#   TDS 2.8  -> TLink 2.0b (2.5.1989)  - Turbo Assembler 1.01
#   TDS 2.9  -> TLink 3.0 (7.5.1990)   - Turbo Assembler 2.0
#   TDS 2.9  -> TLink 3.01 (29.10.1990) - Turbo Assembler 2.01
#
# NEW Format:
#   TDS 3.0  -> TLink 4.0 (23.4.1991)  - Borland C++ 2.0
#   TDS 3.10 -> TLink 5.0 (11.11.1991) - Borland C++ 3.0
#   TDS 3.10 -> TLink 5.1 (10.6.1992)  - Borland C++ 3.1
#   TDS 4.1  -> TLink 6.00 (2.12.1993) - Turbo Assembler 4.0, Borland C++ 4.0
#   TDS 4.1  -> TLink 7.0a (17.11.1994) - Borland C++ 4.5, 4.52
#   TDS 4.3  -> TLink 7.1.30.1 (21.2.1996) - Turbo Assembler 5.0
#   TDS 4.3  -> TLink 7.1.32.2 (6.5.1997)  - Borland C++ 5.0, 5.02

_TDS_VERSION_MAP = {
    # (tds_major, tds_minor): (tds_version_str, tlink_version_str, commandline_hint, products)
    (2, 8): ("2.8", "2.0a/2.0b", "Turbo Link  Version 2.0  Copyright (c) 1987, 1988 Borland International", "Turbo Assembler 1.0/1.01, Turbo C 2.0/2.01"),
    (2, 9): ("2.9", "3.0/3.01", "Turbo Link  Version 3.0 Copyright (c) 1987, 1990 Borland International", "Turbo Assembler 2.0/2.01"),
    (3, 0): ("3.0", "4.0", "Turbo Link  Version 4.0 Copyright (c) 1991 Borland International", "Borland C++ 2.0"),
    (3, 10): ("3.10", "5.0/5.1", "Turbo Link  Version 5.0 Copyright (c) 1991 Borland International", "Borland C++ 3.0/3.1"),
    (4, 1): ("4.1", "6.00/7.0a", "Turbo Link  Version 6.00 Copyright (c) 1992, 1993 Borland International", "Turbo Assembler 4.0, Borland C++ 4.0/4.5/4.52"),
    (4, 3): ("4.3", "7.1.30.1/7.1.32.2", "Turbo Link  Version 7.1 Copyright (c) 1987, 1996 Borland International", "Turbo Assembler 5.0, Borland C++ 5.0/5.02"),
}

# TDS versions that have no TDS info (pre-2.0 format)
_OLD_FORMAT_NO_TDS = {(1, 0), (1, 1)}


class TDInfoSymbolClass(IntEnum):
    STATIC = 0
    ABSOLUTE = 1
    AUTO = 2
    PASCAL_VAR = 3
    REGISTER = 4
    CONSTANT = 5
    TYPEDEF = 6
    STRUCT_UNION_OR_ENUM = 7


@dataclass(frozen=True)
class TDInfoHeader:
    major_version: int
    minor_version: int
    names_pool_size_in_bytes: int
    names_count: int
    types_count: int
    members_count: int
    symbols_count: int
    globals_count: int
    extension_size: int


@dataclass(frozen=True)
class TDInfoSymbolRecord:
    index: int
    type_index: int
    offset: int
    segment: int
    symbol_class: TDInfoSymbolClass

    def linear_addr(self, *, load_base_linear: int) -> int:
        return load_base_linear + (self.segment << 4) + self.offset


@dataclass(frozen=True)
class TDInfoEXEInfo:
    header: TDInfoHeader
    debug_info_offset: int
    symbols: tuple[TDInfoSymbolRecord, ...]
    names: tuple[str, ...]
    symbols_by_class: dict[TDInfoSymbolClass, tuple[TDInfoSymbolRecord, ...]] = field(default_factory=dict)
    type_names: tuple[str, ...] = ()
    code_labels: dict[int, str] = field(default_factory=dict)
    data_labels: dict[int, str] = field(default_factory=dict)
    # TLink/TDS version identification
    tds_version_str: str = ""
    tlink_version_str: str = ""
    commandline_hint: str = ""
    products: str = ""


def parse_tdinfo_exe(path: Path, *, load_base_linear: int = 0) -> TDInfoEXEInfo | None:
    return parse_tdinfo_exe_bytes(path.read_bytes(), load_base_linear=load_base_linear)


def parse_tdinfo_exe_bytes(data: bytes, *, load_base_linear: int = 0) -> TDInfoEXEInfo | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None

    used_bytes_in_last_page, file_size_in_pages = struct.unpack_from("<HH", data, 2)
    if file_size_in_pages == 0:
        return None
    used_bytes = used_bytes_in_last_page or _PAGE_SIZE
    debug_info_offset = file_size_in_pages * _PAGE_SIZE - (_PAGE_SIZE - used_bytes)
    if debug_info_offset < 0 or debug_info_offset + 44 > len(data):
        return None

    magic_number = struct.unpack_from("<H", data, debug_info_offset)[0]
    if magic_number != _TDINFO_MAGIC:
        return None

    (
        _magic,
        minor_version,
        major_version,
        names_pool_size_in_bytes,
        names_count,
        types_count,
        members_count,
        symbols_count,
        globals_count,
    ) = struct.unpack_from("<HBBIHHHHH", data, debug_info_offset)
    extension_size = struct.unpack_from("<H", data, debug_info_offset + 42)[0]
    symbol_records_offset = debug_info_offset + 44 + extension_size
    if symbol_records_offset + symbols_count * 9 > len(data):
        return None
    names_pool_offset = len(data) - names_pool_size_in_bytes
    if names_pool_offset < symbol_records_offset or names_pool_offset < 0:
        return None

    header = TDInfoHeader(
        major_version=major_version,
        minor_version=minor_version,
        names_pool_size_in_bytes=names_pool_size_in_bytes,
        names_count=names_count,
        types_count=types_count,
        members_count=members_count,
        symbols_count=symbols_count,
        globals_count=globals_count,
        extension_size=extension_size,
    )
    names = _parse_tdinfo_name_pool(data[names_pool_offset:], expected_count=names_count)

    symbols: list[TDInfoSymbolRecord] = []
    symbols_by_class: dict[TDInfoSymbolClass, list[TDInfoSymbolRecord]] = {klass: [] for klass in TDInfoSymbolClass}
    code_labels: dict[int, str] = {}
    data_labels: dict[int, str] = {}
    type_names: list[str] = []
    for index in range(symbols_count):
        entry_offset = symbol_records_offset + index * 9
        name_index, type_index, offset, segment, bitfield = struct.unpack_from("<HHHHB", data, entry_offset)
        symbol_class = TDInfoSymbolClass(bitfield & 0x7)
        symbol = TDInfoSymbolRecord(
            index=name_index,
            type_index=type_index,
            offset=offset,
            segment=segment,
            symbol_class=symbol_class,
        )
        symbols.append(symbol)
        symbols_by_class.setdefault(symbol_class, []).append(symbol)
        if 1 <= symbol.index <= len(names) and symbol_class in {
            TDInfoSymbolClass.TYPEDEF,
            TDInfoSymbolClass.STRUCT_UNION_OR_ENUM,
        }:
            name = names[symbol.index - 1]
            if name and name != "?":
                type_names.append(name)
        if symbol.symbol_class is not TDInfoSymbolClass.STATIC:
            continue
        if not (1 <= symbol.index <= len(names)):
            continue
        name = names[symbol.index - 1]
        if not name or name == "?":
            continue
        linear = symbol.linear_addr(load_base_linear=load_base_linear)
        if _tdinfo_name_looks_like_code(name):
            code_labels.setdefault(linear, name.lstrip("_"))
        else:
            data_labels.setdefault(linear, name)

    # Lookup TLink/TDS version identification
    tds_key = (major_version, minor_version)
    if tds_key in _OLD_FORMAT_NO_TDS:
        tds_version_str = "N/A (pre-2.0 format)"
        tlink_version_str = "1.0/1.1"
        commandline_hint = "No TDS info in header"
        products = "Turbo C 1.0/1.5"
    elif tds_key in _TDS_VERSION_MAP:
        tds_version_str, tlink_version_str, commandline_hint, products = _TDS_VERSION_MAP[tds_key]
    else:
        tds_version_str = f"{major_version}.{minor_version}"
        tlink_version_str = "unknown"
        commandline_hint = ""
        products = ""

    return TDInfoEXEInfo(
        header=header,
        debug_info_offset=debug_info_offset,
        symbols=tuple(symbols),
        names=names,
        symbols_by_class={klass: tuple(items) for klass, items in symbols_by_class.items() if items},
        type_names=tuple(dict.fromkeys(type_names)),
        code_labels=code_labels,
        data_labels=data_labels,
        tds_version_str=tds_version_str,
        tlink_version_str=tlink_version_str,
        commandline_hint=commandline_hint,
        products=products,
    )


def _parse_tdinfo_name_pool(data: bytes, *, expected_count: int) -> tuple[str, ...]:
    names: list[str] = []
    for raw_name in data.split(b"\x00"):
        if len(names) >= expected_count:
            break
        names.append(raw_name.decode("ascii", errors="ignore"))
    while len(names) < expected_count:
        names.append("")
    return tuple(names)


def _tdinfo_name_looks_like_code(name: str) -> bool:
    lowered = name.lower()
    if lowered.startswith(("dgroup@", "byte_", "word_", "dword_", "off_", "stru_")):
        return False
    return True
