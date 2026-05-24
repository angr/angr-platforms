from __future__ import annotations

# Layer: Alias
# Responsibility: canonical alias-domain helpers.
# Forbidden: lowering and rewrite ownership.

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class DomainKey:
    kind: Literal["reg"]
    name: str


@dataclass(frozen=True)
class View:
    bit_offset: int
    bit_width: int

    @property
    def bit_end(self) -> int:
        return self.bit_offset + self.bit_width

    def can_join(self, other: "View") -> bool:
        return self.bit_end == other.bit_offset or other.bit_end == self.bit_offset

    def join(self, other: "View") -> "View | None":
        if not self.can_join(other):
            return None
        first, second = (self, other) if self.bit_offset <= other.bit_offset else (other, self)
        return View(first.bit_offset, first.bit_width + second.bit_width)


FULL16 = View(0, 16)
LOW8 = View(0, 8)
HIGH8 = View(8, 8)

AX = DomainKey("reg", "AX")
BX = DomainKey("reg", "BX")
CX = DomainKey("reg", "CX")
DX = DomainKey("reg", "DX")

REGISTER_VIEWS: dict[str, tuple[DomainKey, View]] = {
    "ax": (AX, FULL16),
    "al": (AX, LOW8),
    "ah": (AX, HIGH8),
    "bx": (BX, FULL16),
    "bl": (BX, LOW8),
    "bh": (BX, HIGH8),
    "cx": (CX, FULL16),
    "cl": (CX, LOW8),
    "ch": (CX, HIGH8),
    "dx": (DX, FULL16),
    "dl": (DX, LOW8),
    "dh": (DX, HIGH8),
}

REGISTER_OFFSETS: dict[str, int] = {
    "ax": 0,
    "cx": 2,
    "dx": 4,
    "bx": 6,
}

REGISTER_PAIR_NAMES: dict[str, str] = {
    "al": "ax",
    "ah": "ax",
    "bl": "bx",
    "bh": "bx",
    "cl": "cx",
    "ch": "cx",
    "dl": "dx",
    "dh": "dx",
}


def register_domain_for_name(name: str | None) -> DomainKey | None:
    if not isinstance(name, str):
        return None
    return REGISTER_VIEWS.get(name.lower(), (None, None))[0]


def register_view_for_name(name: str | None) -> View | None:
    if not isinstance(name, str):
        return None
    return REGISTER_VIEWS.get(name.lower(), (None, None))[1]


def register_pair_name(name: str | None) -> str | None:
    if not isinstance(name, str):
        return None
    name = name.lower()
    if name in REGISTER_PAIR_NAMES:
        return REGISTER_PAIR_NAMES[name]
    if name in REGISTER_OFFSETS:
        return name
    return None


def register_offset_for_name(name: str | None) -> int | None:
    if not isinstance(name, str):
        return None
    return REGISTER_OFFSETS.get(name.lower())


def register_views_can_join(left: View, right: View) -> bool:
    return left.can_join(right)


def join_register_views(left: View, right: View) -> View | None:
    return left.join(right)


__all__ = [
    "AX",
    "BX",
    "CX",
    "DX",
    "DomainKey",
    "FULL16",
    "HIGH8",
    "LOW8",
    "REGISTER_OFFSETS",
    "REGISTER_PAIR_NAMES",
    "REGISTER_VIEWS",
    "View",
    "join_register_views",
    "register_domain_for_name",
    "register_offset_for_name",
    "register_pair_name",
    "register_view_for_name",
    "register_views_can_join",
]
