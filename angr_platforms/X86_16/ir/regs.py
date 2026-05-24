from __future__ import annotations

__all__ = ["REG16_OFFSET_MAP", "register_name_from_offset", "segment_space_for_base"]


REG16_OFFSET_MAP = {
    0: "ax",
    2: "cx",
    4: "dx",
    6: "bx",
    8: "sp",
    10: "bp",
    12: "si",
    14: "di",
    16: "ip",
    18: "flags",
    20: "cs",
    22: "ds",
    24: "es",
    26: "fs",
    28: "gs",
    30: "ss",
}


def register_name_from_offset(offset: int) -> str:
    return REG16_OFFSET_MAP.get(int(offset), f"r{offset}")


def segment_space_for_base(name: str | None) -> str:
    if name in {"bp", "sp"}:
        return "ss"
    if name == "di":
        return "es"
    if name in {"si", "bx"}:
        return "ds"
    return "unknown"
