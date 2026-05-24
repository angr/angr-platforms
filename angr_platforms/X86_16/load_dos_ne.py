from __future__ import annotations

from dataclasses import dataclass

from archinfo import arch_from_id
from cle.backends import Blob, register_backend
from angr_platforms.X86_16.ne_resources import NEResourceTable, parse_ne_resources_bytes


def _read_mz_new_header_offset(stream) -> int | None:
    stream.seek(0)
    header = stream.read(0x40)
    if len(header) < 0x40 or header[:2] != b"MZ":
        return None
    return int.from_bytes(header[0x3C:0x40], "little")


@dataclass(frozen=True)
class DOSNEHeader:
    ne_header_offset: int
    entry_ip: int
    entry_segment: int
    stack_sp: int
    stack_segment: int
    segment_count: int
    segment_table_offset: int
    alignment_shift: int
    target_os: int

    @classmethod
    def from_stream(cls, stream) -> "DOSNEHeader":
        ne_header_offset = _read_mz_new_header_offset(stream)
        if ne_header_offset is None:
            raise ValueError("Not an MZ executable")
        stream.seek(ne_header_offset)
        header = stream.read(0x40)
        if len(header) < 0x37 or header[:2] != b"NE":
            raise ValueError("Not a DOS NE executable")

        return cls(
            ne_header_offset=ne_header_offset,
            entry_ip=int.from_bytes(header[0x14:0x16], "little"),
            entry_segment=int.from_bytes(header[0x16:0x18], "little"),
            stack_sp=int.from_bytes(header[0x18:0x1A], "little"),
            stack_segment=int.from_bytes(header[0x1A:0x1C], "little"),
            segment_count=int.from_bytes(header[0x1C:0x1E], "little"),
            segment_table_offset=int.from_bytes(header[0x22:0x24], "little"),
            alignment_shift=int.from_bytes(header[0x32:0x34], "little"),
            target_os=header[0x36],
        )


@dataclass(frozen=True)
class NESegmentRecord:
    segment_number: int
    file_offset: int
    length: int
    flags: int
    min_alloc: int


@dataclass(frozen=True)
class NESegmentMapping:
    segment_number: int
    selector: int
    mem_addr: int
    file_offset: int
    length: int
    flags: int
    min_alloc: int


class DOSNE(Blob):
    """
    Minimal segmented NE loader for smoke testing.

    NE uses selector indexes in its entry/stack fields rather than DOS real-mode
    paragraphs. For x86-16 recovery we synthesize paragraph-aligned selectors in a
    non-overlapping linear layout so `cs:ip` and `ss:sp` still reconstruct honest
    addresses without flattening the executable into one guessed object.
    """

    is_default = True

    DEFAULT_LOAD_BASE = 0x1000

    def __init__(self, *args, **kwargs):
        if len(args) < 2:
            raise ValueError("DOSNE expects binary path and binary stream")

        stream = args[1]
        header = DOSNEHeader.from_stream(stream)
        stream.seek(0)
        raw_data = stream.read()
        load_base = kwargs.pop("base_addr", self.DEFAULT_LOAD_BASE)
        arch = arch_from_id("86_16")
        arch.bits = max(arch.bits, 32)

        segment_records = self._read_segment_records(stream, header)
        segment_mappings = self._build_segment_mappings(segment_records, load_base)
        segments = [
            (mapping.file_offset, mapping.mem_addr, mapping.length)
            for mapping in segment_mappings
            if mapping.file_offset > 0 and mapping.length > 0
        ]

        selector_by_segment = {mapping.segment_number: mapping.selector for mapping in segment_mappings}
        entry_point = load_base
        if header.entry_segment in selector_by_segment:
            entry_point = (selector_by_segment[header.entry_segment] << 4) + header.entry_ip

        super().__init__(
            *args,
            arch=arch,
            segments=segments,
            entry_point=entry_point,
            base_addr=load_base,
            **kwargs,
        )

        for mapping in segment_mappings:
            if mapping.file_offset == 0 and mapping.length > 0:
                relative_addr = mapping.mem_addr - self.linked_base
                self.memory.add_backer(relative_addr, b"\x00" * mapping.length)
                self._max_addr = max(self._max_addr, mapping.mem_addr + mapping.length - 1)

        self.os = "DOS"
        self.ne_header_offset = header.ne_header_offset
        self.ne_header = header
        self.ne_segment_mappings = tuple(segment_mappings)
        self.ne_segment_selectors = selector_by_segment
        self.ne_resources: NEResourceTable | None = parse_ne_resources_bytes(raw_data)
        self.initial_register_values = {
            "cs": selector_by_segment.get(header.entry_segment, load_base >> 4),
            "ip": header.entry_ip,
            "ss": selector_by_segment.get(header.stack_segment, load_base >> 4),
            "sp": header.stack_sp,
        }

    @staticmethod
    def _read_segment_records(stream, header: DOSNEHeader) -> tuple[NESegmentRecord, ...]:
        records: list[NESegmentRecord] = []
        table_offset = header.ne_header_offset + header.segment_table_offset
        for segment_index in range(header.segment_count):
            stream.seek(table_offset + segment_index * 8)
            entry = stream.read(8)
            if len(entry) < 8:
                break
            sector_offset = int.from_bytes(entry[0:2], "little")
            length = int.from_bytes(entry[2:4], "little") or 0x10000
            flags = int.from_bytes(entry[4:6], "little")
            min_alloc = int.from_bytes(entry[6:8], "little")
            file_offset = sector_offset << header.alignment_shift if sector_offset else 0
            records.append(
                NESegmentRecord(
                    segment_number=segment_index + 1,
                    file_offset=file_offset,
                    length=length,
                    flags=flags,
                    min_alloc=min_alloc,
                )
            )
        return tuple(records)

    @staticmethod
    def _build_segment_mappings(
        records: tuple[NESegmentRecord, ...],
        load_base: int,
    ) -> tuple[NESegmentMapping, ...]:
        mappings: list[NESegmentMapping] = []
        current_addr = load_base
        for record in records:
            current_addr = (current_addr + 0xF) & ~0xF
            selector = current_addr >> 4
            mappings.append(
                NESegmentMapping(
                    segment_number=record.segment_number,
                    selector=selector,
                    mem_addr=current_addr,
                    file_offset=record.file_offset,
                    length=record.length,
                    flags=record.flags,
                    min_alloc=record.min_alloc,
                )
            )
            current_addr += max(record.length, 1)
        return tuple(mappings)

    @staticmethod
    def is_compatible(stream):
        ne_header_offset = _read_mz_new_header_offset(stream)
        if ne_header_offset is None:
            return False
        stream.seek(ne_header_offset)
        return stream.read(2) == b"NE"


register_backend("dos_ne", DOSNE)
