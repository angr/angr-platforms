from __future__ import annotations

from dataclasses import dataclass

from .core import IRFunctionArtifact, IRInstr, IRValue, MemSpace, SegmentOrigin
from .ssa_function import SSAFunctionArtifact

__all__ = [
    "SegmentRegisterState",
    "SegmentStateArtifact",
    "apply_x86_16_segment_state_artifact",
    "build_x86_16_segment_state_artifact",
]

_SEGMENT_REGS = ("cs", "ds", "es", "ss", "fs", "gs")


@dataclass(frozen=True, slots=True)
class SegmentRegisterState:
    register: str
    value_kind: str
    source: str | None
    origin: SegmentOrigin

    def to_dict(self) -> dict[str, object]:
        return {
            "register": self.register,
            "value_kind": self.value_kind,
            "source": self.source,
            "origin": self.origin.value,
        }


@dataclass(frozen=True, slots=True)
class SegmentStateArtifact:
    entry_states: dict[int, dict[str, SegmentRegisterState]]
    exit_states: dict[int, dict[str, SegmentRegisterState]]
    summary: dict[str, object]

    def state_for_register(self, register: str) -> SegmentRegisterState | None:
        for state_map in self.exit_states.values():
            state = state_map.get(register)
            if state is not None and state.origin == SegmentOrigin.PROVEN:
                return state
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "entry_states": {
                hex(addr): {name: state.to_dict() for name, state in sorted(states.items())}
                for addr, states in sorted(self.entry_states.items())
            },
            "exit_states": {
                hex(addr): {name: state.to_dict() for name, state in sorted(states.items())}
                for addr, states in sorted(self.exit_states.items())
            },
            "summary": dict(self.summary),
        }


def _unknown_state(register: str) -> SegmentRegisterState:
    return SegmentRegisterState(register=register, value_kind="unknown", source=None, origin=SegmentOrigin.UNKNOWN)


def _join_register_states(states: tuple[SegmentRegisterState, ...], register: str) -> SegmentRegisterState:
    known = [state for state in states if state.origin != SegmentOrigin.UNKNOWN]
    if not known:
        return _unknown_state(register)
    first = known[0]
    if all((state.value_kind, state.source, state.origin) == (first.value_kind, first.source, first.origin) for state in known[1:]):
        return first
    return SegmentRegisterState(register=register, value_kind="merged", source=None, origin=SegmentOrigin.UNKNOWN)


def _join_entry_state(
    predecessor_map: dict[int, tuple[int, ...]],
    exit_states: dict[int, dict[str, SegmentRegisterState]],
    block_addr: int,
) -> dict[str, SegmentRegisterState]:
    preds = predecessor_map.get(block_addr, ())
    if not preds:
        return {register: _unknown_state(register) for register in _SEGMENT_REGS}
    return {
        register: _join_register_states(tuple(exit_states.get(pred, {}).get(register, _unknown_state(register)) for pred in preds), register)
        for register in _SEGMENT_REGS
    }


def _written_segment_state(dst_name: str, src: IRValue, state: dict[str, SegmentRegisterState]) -> SegmentRegisterState:
    if src.space == MemSpace.CONST and src.const is not None:
        return SegmentRegisterState(dst_name, "const_write", hex(int(src.const)), SegmentOrigin.PROVEN)
    if src.space == MemSpace.REG and src.name in _SEGMENT_REGS:
        inherited = state.get(src.name)
        if inherited is not None and inherited.origin == SegmentOrigin.PROVEN:
            return SegmentRegisterState(dst_name, "segment_copy", src.name, SegmentOrigin.PROVEN)
        return SegmentRegisterState(dst_name, "segment_copy", src.name, SegmentOrigin.PROVEN)
    if src.space == MemSpace.REG and src.name is not None:
        return SegmentRegisterState(dst_name, "register_write", src.name, SegmentOrigin.PROVEN)
    return SegmentRegisterState(dst_name, "unknown_write", None, SegmentOrigin.UNKNOWN)


def _transfer_block(block, entry_state: dict[str, SegmentRegisterState]) -> dict[str, SegmentRegisterState]:
    state = dict(entry_state)
    for instr in tuple(getattr(block, "instrs", ()) or ()):
        if not isinstance(instr, IRInstr):
            continue
        dst = getattr(instr, "dst", None)
        if not isinstance(dst, IRValue) or dst.space != MemSpace.REG or dst.name not in _SEGMENT_REGS:
            continue
        src = instr.args[0] if instr.args else None
        if not isinstance(src, IRValue):
            state[dst.name] = _unknown_state(dst.name)
            continue
        state[dst.name] = _written_segment_state(dst.name, src, state)
    return state


def build_x86_16_segment_state_artifact(
    artifact: IRFunctionArtifact,
    function_ssa: SSAFunctionArtifact | None = None,
) -> SegmentStateArtifact:
    blocks_by_addr = {block.addr: block for block in artifact.blocks}
    predecessor_map = (
        dict(getattr(function_ssa, "predecessor_map", {}) or {})
        if function_ssa is not None
        else {block.addr: () for block in artifact.blocks}
    )
    entry_states = {addr: {register: _unknown_state(register) for register in _SEGMENT_REGS} for addr in blocks_by_addr}
    exit_states = {addr: {register: _unknown_state(register) for register in _SEGMENT_REGS} for addr in blocks_by_addr}

    changed = True
    while changed:
        changed = False
        for block_addr in sorted(blocks_by_addr):
            new_entry = _join_entry_state(predecessor_map, exit_states, block_addr)
            new_exit = _transfer_block(blocks_by_addr[block_addr], new_entry)
            if new_entry != entry_states[block_addr]:
                entry_states[block_addr] = new_entry
                changed = True
            if new_exit != exit_states[block_addr]:
                exit_states[block_addr] = new_exit
                changed = True

    explicit_write_count = sum(
        1
        for states in exit_states.values()
        for state in states.values()
        if state.value_kind in {"const_write", "register_write", "segment_copy"}
    )
    summary = {
        "block_count": len(blocks_by_addr),
        "explicit_write_count": explicit_write_count,
        "proven_register_count": sum(
            1 for states in exit_states.values() for state in states.values() if state.origin == SegmentOrigin.PROVEN
        ),
        "unknown_register_count": sum(
            1 for states in exit_states.values() for state in states.values() if state.origin == SegmentOrigin.UNKNOWN
        ),
    }
    return SegmentStateArtifact(entry_states=entry_states, exit_states=exit_states, summary=summary)


def apply_x86_16_segment_state_artifact(project, codegen) -> bool:  # noqa: ARG001
    artifact = getattr(codegen, "_inertia_vex_ir_artifact", None)
    if not isinstance(artifact, IRFunctionArtifact):
        return False
    function_ssa = getattr(codegen, "_inertia_vex_ir_function_ssa", None)
    segment_artifact = build_x86_16_segment_state_artifact(artifact, function_ssa=function_ssa)
    setattr(codegen, "_inertia_segment_state_artifact", segment_artifact)
    return False
