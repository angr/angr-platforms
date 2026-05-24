from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TypeAlias

__all__ = [
    "AddressStatus",
    "SegmentOrigin",
    "IRAddress",
    "is_stack_address_8616",
    "IRAtom",
    "IRBlock",
    "IRCondition",
    "IRFunctionArtifact",
    "IRInstr",
    "IRRefusal",
    "IRValue",
    "MemSpace",
]


class MemSpace(Enum):
    REG = "reg"
    DS = "ds"
    ES = "es"
    SS = "ss"
    CONST = "const"
    TMP = "tmp"
    UNKNOWN = "unknown"


class AddressStatus(Enum):
    STABLE = "stable"
    PROVISIONAL = "provisional"
    UNKNOWN = "unknown"


class SegmentOrigin(Enum):
    PROVEN = "proven"
    DEFAULTED = "defaulted"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class IRValue:
    space: MemSpace
    name: str | None = None
    offset: int = 0
    const: int | None = None
    size: int = 0
    version: int | None = None
    expr: tuple[str, ...] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "value",
            "space": self.space.value,
            "name": self.name,
            "offset": self.offset,
            "const": self.const,
            "size": self.size,
            "version": self.version,
            "expr": self.expr,
        }


@dataclass(frozen=True, slots=True)
class IRAddress:
    space: MemSpace
    base: tuple[str, ...] = ()
    offset: int = 0
    size: int = 0
    status: AddressStatus = AddressStatus.UNKNOWN
    segment_origin: SegmentOrigin = SegmentOrigin.UNKNOWN
    expr: tuple[str, ...] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "address",
            "space": self.space.value,
            "base": list(self.base),
            "offset": self.offset,
            "size": self.size,
            "status": self.status.value,
            "segment_origin": self.segment_origin.value,
            "expr": self.expr,
        }


def is_stack_address_8616(addr: IRAddress) -> bool:
    """Return True if addr is a proven or likely SS:BP/SP stack slot.

    AGENTS rule: SS:BP+offset MUST become a stack slot, never fallback to memory.
    """
    if addr.space != MemSpace.SS:
        return False
    # Proven segment origin: explicit SS segment instruction
    if addr.segment_origin == SegmentOrigin.PROVEN:
        base_set = set(addr.base)
        if {"ss"} & base_set or {"bp"} & base_set or {"sp"} & base_set:
            return True
    # Expression-based: BP or SP appears in the expression tuple
    if addr.expr:
        expr_set = set(addr.expr)
        if {"bp", "sp", "ss"} & expr_set:
            return True
    # Defaulted segment with BP base hint
    if addr.segment_origin == SegmentOrigin.DEFAULTED and addr.space == MemSpace.SS:
        base_set = set(addr.base)
        if {"bp"} & base_set:
            return True
    return False


@dataclass(frozen=True, slots=True)
class IRCondition:
    op: str
    args: tuple["IRAtom", ...]
    expr: tuple[str, ...] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "condition",
            "op": self.op,
            "args": [_atom_to_dict(arg) for arg in self.args],
            "expr": self.expr,
        }


IRAtom: TypeAlias = IRValue | IRAddress | IRCondition


def _atom_to_dict(atom: IRAtom) -> dict[str, object]:
    return atom.to_dict()


@dataclass(frozen=True, slots=True)
class IRInstr:
    op: str
    dst: IRValue | None
    args: tuple[IRAtom, ...]
    size: int = 0
    addr: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "op": self.op,
            "dst": None if self.dst is None else self.dst.to_dict(),
            "args": [_atom_to_dict(arg) for arg in self.args],
            "size": self.size,
            "addr": self.addr,
        }


@dataclass(frozen=True, slots=True)
class IRRefusal:
    kind: str
    detail: str
    block_addr: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "block_addr": self.block_addr,
        }


@dataclass(frozen=True, slots=True)
class IRBlock:
    addr: int
    instrs: tuple[IRInstr, ...] = ()
    refusals: tuple[IRRefusal, ...] = ()
    successor_addrs: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "addr": self.addr,
            "instrs": [instr.to_dict() for instr in self.instrs],
            "refusals": [item.to_dict() for item in self.refusals],
            "successor_addrs": list(self.successor_addrs),
        }


@dataclass(frozen=True, slots=True)
class IRFunctionArtifact:
    function_addr: int
    blocks: tuple[IRBlock, ...] = ()
    refusals: tuple[IRRefusal, ...] = ()
    summary: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "function_addr": self.function_addr,
            "blocks": [block.to_dict() for block in self.blocks],
            "refusals": [item.to_dict() for item in self.refusals],
            "summary": dict(self.summary),
        }
