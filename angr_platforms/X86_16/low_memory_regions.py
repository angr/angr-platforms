from __future__ import annotations

from dataclasses import dataclass
import re

__all__ = [
    "LowMemoryAccess",
    "classify_x86_16_low_memory_access",
    "format_x86_16_low_memory_access",
    "linearize_x86_16_segment_offset",
]


@dataclass(frozen=True, slots=True)
class LowMemoryAccess:
    access_kind: str
    raw_access: str
    region: str
    label: str
    linear: int
    segment: int
    offset: int
    size: int | None = None

    def brief(self) -> str:
        return f"{self.label} ({self.segment:#x}:{self.offset:#x} -> {self.linear:#x})"

    def to_dict(self) -> dict[str, object]:
        return {
            "access_kind": self.access_kind,
            "raw_access": self.raw_access,
            "region": self.region,
            "label": self.label,
            "linear": self.linear,
            "segment": self.segment,
            "offset": self.offset,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class _FieldSpec:
    linear: int
    size: int
    label: str


_SEG_OFF_RE = re.compile(
    r"^(?P<seg>0x[0-9a-fA-F]+|\d+):(?P<off>0x[0-9a-fA-F]+|\d+)(?:/(?P<size>\d+))?$"
)
_LINEAR_RE = re.compile(r"^(?P<addr>0x[0-9a-fA-F]+|\d+)(?:/(?P<size>\d+))?$")

_FIELD_SPECS: tuple[_FieldSpec, ...] = (
    _FieldSpec(0x400, 2, "bda.com1_port"),
    _FieldSpec(0x402, 2, "bda.com2_port"),
    _FieldSpec(0x404, 2, "bda.com3_port"),
    _FieldSpec(0x406, 2, "bda.com4_port"),
    _FieldSpec(0x408, 2, "bda.lpt1_port"),
    _FieldSpec(0x40A, 2, "bda.lpt2_port"),
    _FieldSpec(0x40C, 2, "bda.lpt3_port"),
    _FieldSpec(0x40E, 2, "bda.ebda_segment"),
    _FieldSpec(0x410, 2, "bda.equipment_flags"),
    _FieldSpec(0x413, 2, "bda.memory_size_kb"),
    _FieldSpec(0x417, 1, "bda.keyboard_flags0"),
    _FieldSpec(0x418, 1, "bda.keyboard_flags1"),
    _FieldSpec(0x419, 1, "bda.alt_keypad"),
    _FieldSpec(0x41A, 2, "bda.keyboard_buffer_head"),
    _FieldSpec(0x41C, 2, "bda.keyboard_buffer_tail"),
    _FieldSpec(0x41E, 32, "bda.keyboard_buffer"),
    _FieldSpec(0x449, 1, "bda.video_mode"),
    _FieldSpec(0x44A, 2, "bda.screen_columns"),
    _FieldSpec(0x44C, 2, "bda.video_regen_buffer_size"),
    _FieldSpec(0x44E, 2, "bda.video_page_offset"),
    _FieldSpec(0x462, 1, "bda.active_display_page"),
    _FieldSpec(0x463, 2, "bda.video_controller_base_port"),
    _FieldSpec(0x46C, 4, "bda.daily_timer_counter"),
    _FieldSpec(0x470, 1, "bda.clock_rollover_flag"),
    _FieldSpec(0x471, 1, "bda.break_flag"),
    _FieldSpec(0x472, 2, "bda.soft_reset_flag"),
    _FieldSpec(0x475, 1, "bda.hard_disk_count"),
    _FieldSpec(0x480, 2, "bda.keyboard_buffer_start"),
    _FieldSpec(0x482, 2, "bda.keyboard_buffer_end"),
    _FieldSpec(0x497, 1, "bda.keyboard_led_flags"),
    _FieldSpec(0x500, 1, "bios.print_screen_status"),
)


def linearize_x86_16_segment_offset(segment: int, offset: int) -> int:
    return ((segment & 0xFFFF) << 4) + (offset & 0xFFFF)


def _parse_access(access: str) -> tuple[int, int, int | None] | None:
    text = access.strip().lower()
    seg_match = _SEG_OFF_RE.fullmatch(text)
    if seg_match is not None:
        segment = int(seg_match.group("seg"), 0)
        offset = int(seg_match.group("off"), 0)
        size = int(seg_match.group("size")) if seg_match.group("size") else None
        return segment, offset, size
    linear_match = _LINEAR_RE.fullmatch(text)
    if linear_match is None:
        return None
    linear = int(linear_match.group("addr"), 0)
    size = int(linear_match.group("size")) if linear_match.group("size") else None
    return 0, linear, size


def _region_for_linear(linear: int) -> tuple[str, str]:
    if 0x0000 <= linear <= 0x03FF:
        vec = linear // 4
        slot = linear % 4
        return "ivt", f"ivt.vector_{vec:02x}+0x{slot:x}"
    if 0x0400 <= linear <= 0x04FF:
        return "bda", f"bda+0x{linear - 0x400:x}"
    if 0x0500 <= linear <= 0x07BFF:
        return "lowmem", f"lowmem+0x{linear - 0x500:x}"
    if 0x07C00 <= linear <= 0x07DFF:
        return "boot", f"boot+0x{linear - 0x7c00:x}"
    if 0x0A0000 <= linear <= 0x0AFFFF:
        return "video_ram", f"video_ram.a000+0x{linear - 0xA0000:x}"
    if 0x0B0000 <= linear <= 0x0B7FFF:
        return "video_ram", f"video_ram.b000+0x{linear - 0xB0000:x}"
    if 0x0B8000 <= linear <= 0x0BFFFF:
        return "video_ram", f"video_ram.b800+0x{linear - 0xB8000:x}"
    if 0x0C0000 <= linear <= 0x0EFFFF:
        return "rom", f"adapter_rom+0x{linear - 0xC0000:x}"
    if 0x0F0000 <= linear <= 0x0FFFFF:
        return "rom", f"system_rom+0x{linear - 0xF0000:x}"
    return "other", f"mem+0x{linear:x}"


def classify_x86_16_low_memory_access(
    access: str,
    *,
    access_kind: str = "access",
    size: int | None = None,
) -> LowMemoryAccess | None:
    parsed = _parse_access(access)
    if parsed is None:
        return None
    segment, offset, parsed_size = parsed
    effective_size = size if size is not None else parsed_size
    linear = linearize_x86_16_segment_offset(segment, offset)
    for spec in _FIELD_SPECS:
        if linear != spec.linear:
            continue
        if effective_size is not None and effective_size != spec.size:
            continue
        region = spec.label.split(".", 1)[0]
        return LowMemoryAccess(
            access_kind=access_kind,
            raw_access=access.strip(),
            region=region,
            label=spec.label,
            linear=linear,
            segment=segment,
            offset=offset,
            size=effective_size,
        )
    region, label = _region_for_linear(linear)
    if region == "other":
        return None
    return LowMemoryAccess(
        access_kind=access_kind,
        raw_access=access.strip(),
        region=region,
        label=label,
        linear=linear,
        segment=segment,
        offset=offset,
        size=effective_size,
    )


def format_x86_16_low_memory_access(access: str, *, size: int | None = None) -> str:
    classified = classify_x86_16_low_memory_access(access, size=size)
    if classified is None:
        return access
    return classified.brief()
