from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path


_WIN16_RESOURCE_TYPES: dict[int, tuple[str, str]] = {
    1: ("CURSOR", ".cur"),
    2: ("BITMAP", ".bmp"),
    3: ("ICON", ".ico"),
    4: ("MENU", ".bin"),
    5: ("DIALOG", ".bin"),
    6: ("STRING", ".bin"),
    7: ("FONTDIR", ".bin"),
    8: ("FONT", ".fon"),
    9: ("ACCELERATOR", ".bin"),
    10: ("RCDATA", ".bin"),
    11: ("MESSAGETABLE", ".bin"),
    12: ("GROUP_CURSOR", ".bin"),
    14: ("GROUP_ICON", ".bin"),
    15: ("NAMETABLE", ".bin"),
    16: ("VERSION", ".bin"),
}

_OS2_RESOURCE_TYPES: dict[int, tuple[str, str]] = {
    1: ("POINTER", ".ptr"),
    2: ("BITMAP", ".bmp"),
    3: ("MENU", ".bin"),
    4: ("DIALOG", ".bin"),
    5: ("STRING", ".bin"),
    6: ("FONTDIR", ".bin"),
    7: ("FONT", ".fon"),
    8: ("ACCELTABLE", ".bin"),
    9: ("RCDATA", ".bin"),
    10: ("MESSAGE", ".bin"),
}


@dataclass(frozen=True)
class NEResourceEntry:
    type_id: int
    type_name: str
    name: str
    file_offset: int
    length: int
    flags: int
    handle: int
    usage: int
    file_extension: str
    bytes_data: bytes = b""


@dataclass(frozen=True)
class NEResourceGroup:
    type_id: int
    name: str
    entries: tuple[NEResourceEntry, ...] = ()


@dataclass(frozen=True)
class NEResourceTable:
    kind: str
    alignment_shift: int
    groups: tuple[NEResourceGroup, ...] = ()

    @property
    def flat_entries(self) -> tuple[NEResourceEntry, ...]:
        return tuple(entry for group in self.groups for entry in group.entries)


def parse_ne_resources(path: Path) -> NEResourceTable | None:
    return parse_ne_resources_bytes(path.read_bytes())


def parse_ne_resources_bytes(data: bytes) -> NEResourceTable | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    ne_offset = int.from_bytes(data[0x3C:0x40], "little")
    if ne_offset <= 0 or ne_offset + 0x38 > len(data) or data[ne_offset : ne_offset + 2] != b"NE":
        return None
    resource_table_rel = struct.unpack_from("<H", data, ne_offset + 0x24)[0]
    resource_count = struct.unpack_from("<H", data, ne_offset + 0x34)[0]
    target_os = data[ne_offset + 0x36]
    if resource_table_rel == 0:
        return None
    resource_table_offset = ne_offset + resource_table_rel
    if target_os == 1:
        return _parse_os2_resource_table(data, resource_table_offset, resource_count)
    return _parse_win16_resource_table(data, resource_table_offset)


def _parse_win16_resource_table(data: bytes, resource_table_offset: int) -> NEResourceTable | None:
    if resource_table_offset + 2 > len(data):
        return None
    shift = struct.unpack_from("<H", data, resource_table_offset)[0]
    cursor = resource_table_offset + 2
    groups: list[NEResourceGroup] = []
    while cursor + 2 <= len(data):
        type_id = struct.unpack_from("<H", data, cursor)[0]
        cursor += 2
        if type_id == 0:
            break
        if cursor + 8 > len(data):
            break
        count, _reserved = struct.unpack_from("<HI", data, cursor)
        cursor += 6
        type_name, file_extension = _decode_win16_type(type_id)
        entries: list[NEResourceEntry] = []
        for _ in range(count):
            if cursor + 12 > len(data):
                break
            name_offset, name_length, flags, name_id, handle, usage = struct.unpack_from("<HHHHHH", data, cursor)
            cursor += 12
            file_offset = name_offset << shift
            length = name_length << shift
            entry_name = _decode_ne_name(data, resource_table_offset, name_id)
            payload = data[file_offset : file_offset + length] if file_offset + length <= len(data) else b""
            entries.append(
                NEResourceEntry(
                    type_id=type_id,
                    type_name=type_name,
                    name=entry_name,
                    file_offset=file_offset,
                    length=length,
                    flags=flags,
                    handle=handle,
                    usage=usage,
                    file_extension=file_extension,
                    bytes_data=payload,
                )
            )
        groups.append(NEResourceGroup(type_id=type_id, name=type_name, entries=tuple(entries)))
    return NEResourceTable(kind="win16", alignment_shift=shift, groups=tuple(groups))


def _parse_os2_resource_table(data: bytes, resource_table_offset: int, resource_count: int) -> NEResourceTable | None:
    if resource_table_offset < 0 or resource_table_offset + resource_count * 4 > len(data):
        return None
    entries_by_type: dict[int, list[NEResourceEntry]] = {}
    cursor = resource_table_offset
    table_entries = [struct.unpack_from("<HH", data, cursor + i * 4) for i in range(resource_count)]
    for index, (type_id, name_id) in enumerate(table_entries):
        type_name, file_extension = _decode_os2_type(type_id)
        entry = NEResourceEntry(
            type_id=type_id,
            type_name=type_name,
            name=str(name_id),
            file_offset=0,
            length=0,
            flags=0,
            handle=0,
            usage=0,
            file_extension=file_extension,
            bytes_data=b"",
        )
        entries_by_type.setdefault(type_id, []).append(entry)
    groups = tuple(
        NEResourceGroup(type_id=type_id, name=_decode_os2_type(type_id)[0], entries=tuple(entries))
        for type_id, entries in sorted(entries_by_type.items())
    )
    return NEResourceTable(kind="os2", alignment_shift=0, groups=groups)


def _decode_win16_type(type_id: int) -> tuple[str, str]:
    normalized = type_id & 0x7FFF
    return _WIN16_RESOURCE_TYPES.get(normalized, (f"TYPE_{normalized}", ".bin"))


def _decode_os2_type(type_id: int) -> tuple[str, str]:
    return _OS2_RESOURCE_TYPES.get(type_id, (f"OS2_TYPE_{type_id}", ".bin"))


def _decode_ne_name(data: bytes, resource_table_offset: int, name_id: int) -> str:
    if name_id & 0x8000:
        return str(name_id & 0x7FFF)
    name_offset = resource_table_offset + name_id
    if name_offset >= len(data):
        return "?"
    name_len = data[name_offset]
    start = name_offset + 1
    end = start + name_len
    if end > len(data):
        return "?"
    return data[start:end].decode("ascii", errors="ignore")


__all__ = ["NEResourceEntry", "NEResourceGroup", "NEResourceTable", "parse_ne_resources", "parse_ne_resources_bytes"]
