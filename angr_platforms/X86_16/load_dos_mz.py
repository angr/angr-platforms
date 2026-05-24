from __future__ import annotations

from dataclasses import dataclass

from archinfo import arch_from_id
from cle.backends import Blob, register_backend


def _read_mz_extended_signature(stream) -> bytes | None:
    stream.seek(0)
    header = stream.read(0x40)
    if len(header) < 0x40 or header[:2] != b"MZ":
        return None
    new_header_offset = int.from_bytes(header[0x3C:0x40], "little")
    if new_header_offset < 0x40:
        return None
    stream.seek(new_header_offset)
    signature = stream.read(2)
    if len(signature) < 2:
        return None
    return signature


@dataclass(frozen=True)
class DOSMZHeader:
    header_paragraphs: int
    relocation_count: int
    relocation_offset: int
    initial_ip: int
    initial_cs: int
    initial_sp: int
    initial_ss: int

    @classmethod
    def from_stream(cls, stream) -> "DOSMZHeader":
        stream.seek(0)
        header = stream.read(0x40)
        if len(header) < 0x1C or header[:2] != b"MZ":
            raise ValueError("Not a DOS MZ executable")

        return cls(
            header_paragraphs=int.from_bytes(header[0x08:0x0A], "little"),
            relocation_count=int.from_bytes(header[0x06:0x08], "little"),
            relocation_offset=int.from_bytes(header[0x18:0x1A], "little"),
            initial_ip=int.from_bytes(header[0x14:0x16], "little"),
            initial_cs=int.from_bytes(header[0x16:0x18], "little"),
            initial_sp=int.from_bytes(header[0x10:0x12], "little"),
            initial_ss=int.from_bytes(header[0x0E:0x10], "little"),
        )


@dataclass(frozen=True)
class MZSegmentSpan:
    segment: int
    start_linear: int
    end_linear: int
    evidence: tuple[str, ...]


class DOSMZ(Blob):
    """
    Minimal DOS MZ loader for 16-bit real-mode executables.

    The loaded image is mapped starting at linear address 0 so segment-relative
    references inside the executable line up with the relocated program image.
    """

    is_default = True

    DEFAULT_LOAD_BASE = 0x1000

    def __init__(self, *args, offset=None, **kwargs):
        if len(args) < 2:
            raise ValueError("DOSMZ expects binary path and binary stream")
        stream = args[1]
        header = DOSMZHeader.from_stream(stream)
        image_offset = header.header_paragraphs * 0x10 if offset is None else offset
        load_base = kwargs.pop("base_addr", self.DEFAULT_LOAD_BASE)
        image_end = self._image_end_linear(stream, image_offset, load_base)
        load_segment = load_base >> 4
        entry_point = load_base + (header.initial_cs << 4) + header.initial_ip
        arch = arch_from_id("86_16")
        # Real-mode code still executes with 16-bit registers, but MZ images can
        # span well beyond 64K in linear memory. CLE uses arch.bits for loader
        # address-space checks, so widen only the loader-visible address width.
        arch.bits = max(arch.bits, 32)

        super().__init__(
            *args,
            arch=arch,
            offset=image_offset,
            entry_point=entry_point,
            base_addr=load_base,
            **kwargs,
        )

        relocation_entries = self._read_relocation_entries(stream, header)
        self._apply_relocations(relocation_entries, load_base, load_segment)

        self.os = "DOS"
        self.initial_register_values = {
            "cs": header.initial_cs + load_segment,
            "ip": header.initial_ip,
            "ss": header.initial_ss + load_segment,
            "sp": header.initial_sp,
        }
        self.mz_header_paragraphs = header.header_paragraphs
        self.mz_image_offset = image_offset
        self.mz_load_segment = load_segment
        self.mz_relocation_entries = tuple(relocation_entries)
        self.mz_segment_spans = self._infer_segment_spans(
            header,
            relocation_entries,
            load_base=load_base,
            image_end=image_end,
        )

    @staticmethod
    def _image_end_linear(stream, image_offset: int, load_base: int) -> int:
        stream.seek(0, 2)
        return load_base + max(0, stream.tell() - image_offset)

    @staticmethod
    def _read_relocation_entries(stream, header: DOSMZHeader) -> list[tuple[int, int]]:
        entries: list[tuple[int, int]] = []
        for idx in range(header.relocation_count):
            entry_off = header.relocation_offset + idx * 4
            stream.seek(entry_off)
            reloc = stream.read(4)
            if len(reloc) < 4:
                break
            reloc_offset = int.from_bytes(reloc[0:2], "little")
            reloc_segment = int.from_bytes(reloc[2:4], "little")
            entries.append((reloc_offset, reloc_segment))
        return entries

    @staticmethod
    def _infer_segment_spans(
        header: DOSMZHeader,
        relocation_entries: list[tuple[int, int]],
        *,
        load_base: int,
        image_end: int,
    ) -> tuple[MZSegmentSpan, ...]:
        evidence_by_segment: dict[int, set[str]] = {
            header.initial_cs: {"entry_cs:ip"},
            header.initial_ss: {"stack_ss:sp"},
        }
        for _reloc_offset, reloc_segment in relocation_entries:
            evidence_by_segment.setdefault(reloc_segment, set()).add("relocation")

        ordered_segments = sorted(evidence_by_segment)
        spans: list[MZSegmentSpan] = []
        for idx, segment in enumerate(ordered_segments):
            start_linear = load_base + (segment << 4)
            next_start = image_end
            if idx + 1 < len(ordered_segments):
                next_start = load_base + (ordered_segments[idx + 1] << 4)
            # Adjacent real-mode segments can overlap by up to 15 bytes.
            end_linear = min(image_end, next_start + 0xF)
            if end_linear <= start_linear:
                end_linear = min(image_end, start_linear + 1)
            spans.append(
                MZSegmentSpan(
                    segment=segment,
                    start_linear=start_linear,
                    end_linear=end_linear,
                    evidence=tuple(sorted(evidence_by_segment[segment])),
                )
            )
        return tuple(spans)

    def _apply_relocations(self, relocation_entries: list[tuple[int, int]], load_base: int, load_segment: int) -> None:
        for reloc_offset, reloc_segment in relocation_entries:
            reloc_addr = load_base + (reloc_segment << 4) + reloc_offset
            relative_addr = reloc_addr - self.linked_base
            try:
                current_bytes = self.memory.load(relative_addr, 2)
            except KeyError:
                self.memory.add_backer(relative_addr, b"\x00\x00")
                self._max_addr = max(self._max_addr, reloc_addr + 1)
                current_bytes = b"\x00\x00"
            current = int.from_bytes(current_bytes, "little")
            patched = (current + load_segment) & 0xFFFF
            self.memory.store(relative_addr, patched.to_bytes(2, "little"))

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        magic = stream.read(2)
        if magic != b"MZ":
            return False
        # Reject MZ stubs that hand off to a distinct extended executable format.
        return _read_mz_extended_signature(stream) not in {b"NE", b"PE", b"LE", b"LX"}


register_backend("dos_mz", DOSMZ)
