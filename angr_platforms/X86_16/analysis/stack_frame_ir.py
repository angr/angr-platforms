from __future__ import annotations

from dataclasses import dataclass

from ..ir.core import IRAddress, IRFunctionArtifact, MemSpace

__all__ = [
    "FrameAccessArtifact",
    "StackFrameSlot",
    "build_x86_16_ir_frame_access_artifact",
]


@dataclass(frozen=True, slots=True)
class StackFrameSlot:
    base: str
    offset: int
    role: str
    size: int

    def to_dict(self) -> dict[str, object]:
        return {
            "base": self.base,
            "offset": self.offset,
            "role": self.role,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class FrameAccessArtifact:
    slots: tuple[StackFrameSlot, ...] = ()
    refusals: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "slots": [item.to_dict() for item in self.slots],
            "refusals": list(self.refusals),
        }


def _slot_role(base: str, offset: int) -> str:
    if base == "bp":
        if offset >= 4:
            return "arg"
        if offset < 0:
            return "local"
        return "frame_meta"
    return "sp_relative"


def build_x86_16_ir_frame_access_artifact(artifact: IRFunctionArtifact) -> FrameAccessArtifact:
    slots: dict[tuple[str, int, int], StackFrameSlot] = {}
    refusals: list[str] = []
    for block in artifact.blocks:
        for instr in block.instrs:
            values = tuple(arg for arg in instr.args if isinstance(arg, IRAddress) and arg.space == MemSpace.SS)
            for value in values:
                base = value.base[0] if len(value.base) == 1 else None
                if base not in {"bp", "sp"}:
                    refusals.append("non_frame_ss_access")
                    continue
                size = int(value.size or instr.size or 0)
                key = (base or "", value.offset, size)
                slots.setdefault(
                    key,
                    StackFrameSlot(
                        base=base or "sp",
                        offset=value.offset,
                        role=_slot_role(base or "sp", value.offset),
                        size=size,
                    ),
                )
    return FrameAccessArtifact(
        slots=tuple(sorted(slots.values(), key=lambda item: (item.base, item.offset, item.size))),
        refusals=tuple(sorted(set(refusals))),
    )
