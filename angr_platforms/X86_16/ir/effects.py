from __future__ import annotations

# Layer: IR
# Responsibility: typed memory and register effect records (LOAD, STORE, REG_WRITE).
# Forbidden: semantic recovery ownership, text-pattern semantics, postprocess cleanup.

from dataclasses import dataclass, field
from enum import Enum

from .core import IRAddress, IRValue, MemSpace

__all__ = [
    "EffectKind",
    "LoadEffect",
    "StoreEffect",
    "RegisterWriteEffect",
    "FlagWriteEffect",
    "effect_to_ir_instr_op_8616",
]


class EffectKind(Enum):
    """Kinds of typed effects."""

    LOAD = "load"
    STORE = "store"
    REG_WRITE = "reg_write"
    FLAG_WRITE = "flag_write"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class LoadEffect:
    """A typed memory LOAD: read from an address into a value."""

    address: IRAddress
    dst: IRValue | None = None
    width_bits: int = 0
    addr: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "load",
            "address": self.address.to_dict(),
            "dst": None if self.dst is None else self.dst.to_dict(),
            "width_bits": self.width_bits,
            "addr": self.addr,
        }


@dataclass(frozen=True, slots=True)
class StoreEffect:
    """A typed memory STORE: write a value to an address."""

    address: IRAddress
    value: IRValue
    width_bits: int = 0
    addr: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "store",
            "address": self.address.to_dict(),
            "value": self.value.to_dict(),
            "width_bits": self.width_bits,
            "addr": self.addr,
        }


@dataclass(frozen=True, slots=True)
class RegisterWriteEffect:
    """A typed register write: assign a value to a named register."""

    register: str
    value: IRValue
    width_bits: int = 0
    addr: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "reg_write",
            "register": self.register,
            "value": self.value.to_dict(),
            "width_bits": self.width_bits,
            "addr": self.addr,
        }


@dataclass(frozen=True, slots=True)
class FlagWriteEffect:
    """A typed flag write: set a CPU flag to a value."""

    flag: str
    value: IRValue | None = None
    width_bits: int = 0
    addr: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "flag_write",
            "flag": self.flag,
            "value": None if self.value is None else self.value.to_dict(),
            "width_bits": self.width_bits,
            "addr": self.addr,
        }


_EFFECT_TO_IR_INSTR_OP_8616: dict[str, str] = {
    "store": "STORE",
    "load": "LOAD",
    "reg_write": "REG_WRITE",
    "flag_write": "FLAG_WRITE",
}


def effect_to_ir_instr_op_8616(kind: str) -> str:
    """Map an effect kind to an IRInstr op string."""
    return _EFFECT_TO_IR_INSTR_OP_8616.get(kind, "UNKNOWN")