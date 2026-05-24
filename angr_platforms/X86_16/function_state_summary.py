from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .low_memory_regions import LowMemoryAccess, classify_x86_16_low_memory_access

__all__ = [
    "FunctionStateSummary",
    "summarize_x86_16_function_state",
]

_SEGMENT_REGS = frozenset({"cs", "ds", "es", "ss", "fs", "gs"})
_FLAG_NAMES = frozenset({"cf", "pf", "af", "zf", "sf", "tf", "if", "df", "of"})


@dataclass(frozen=True, slots=True)
class FunctionStateSummary:
    gp_register_inputs: tuple[str, ...] = ()
    gp_register_outputs: tuple[str, ...] = ()
    segment_register_inputs: tuple[str, ...] = ()
    segment_register_outputs: tuple[str, ...] = ()
    flag_inputs: tuple[str, ...] = ()
    flag_outputs: tuple[str, ...] = ()
    frame_stack_reads: tuple[int, ...] = ()
    frame_stack_writes: tuple[int, ...] = ()
    memory_reads: tuple[str, ...] = ()
    memory_writes: tuple[str, ...] = ()
    low_memory_reads: tuple[LowMemoryAccess, ...] = ()
    low_memory_writes: tuple[LowMemoryAccess, ...] = ()
    direct_call_count: int = 0
    indirect_call_count: int = 0
    direct_branch_count: int = 0
    indirect_branch_count: int = 0
    return_kind: str = "unknown"

    def touches_segments(self) -> bool:
        return bool(self.segment_register_inputs or self.segment_register_outputs)

    def touches_flags(self) -> bool:
        return bool(self.flag_inputs or self.flag_outputs)

    def has_memory_effects(self) -> bool:
        return bool(
            self.frame_stack_reads
            or self.frame_stack_writes
            or self.memory_reads
            or self.memory_writes
        )

    def brief(self) -> str:
        return (
            f"gp_in={len(self.gp_register_inputs)} "
            f"gp_out={len(self.gp_register_outputs)} "
            f"seg_in={len(self.segment_register_inputs)} "
            f"seg_out={len(self.segment_register_outputs)} "
            f"flags_in={len(self.flag_inputs)} "
            f"flags_out={len(self.flag_outputs)} "
            f"mem_r={len(self.memory_reads)} "
            f"mem_w={len(self.memory_writes)} "
            f"low_mem_r={len(self.low_memory_reads)} "
            f"low_mem_w={len(self.low_memory_writes)} "
            f"calls={self.direct_call_count + self.indirect_call_count} "
            f"branches={self.direct_branch_count + self.indirect_branch_count} "
            f"return={self.return_kind}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "gp_register_inputs": list(self.gp_register_inputs),
            "gp_register_outputs": list(self.gp_register_outputs),
            "segment_register_inputs": list(self.segment_register_inputs),
            "segment_register_outputs": list(self.segment_register_outputs),
            "flag_inputs": list(self.flag_inputs),
            "flag_outputs": list(self.flag_outputs),
            "frame_stack_reads": list(self.frame_stack_reads),
            "frame_stack_writes": list(self.frame_stack_writes),
            "memory_reads": list(self.memory_reads),
            "memory_writes": list(self.memory_writes),
            "low_memory_reads": [item.to_dict() for item in self.low_memory_reads],
            "low_memory_writes": [item.to_dict() for item in self.low_memory_writes],
            "direct_call_count": self.direct_call_count,
            "indirect_call_count": self.indirect_call_count,
            "direct_branch_count": self.direct_branch_count,
            "indirect_branch_count": self.indirect_branch_count,
            "return_kind": self.return_kind,
        }


def _value(source: Any, name: str, default: Any) -> Any:
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def _sorted_str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list, set)):
        return ()
    return tuple(sorted(str(item).lower() for item in value))


def _sorted_raw_str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list, set)):
        return ()
    items = [str(item) for item in value]
    return tuple(sorted(items, key=str.lower))


def _sorted_int_tuple(value: Any) -> tuple[int, ...]:
    if not isinstance(value, (tuple, list, set)):
        return ()
    ints = [item for item in value if isinstance(item, int)]
    return tuple(sorted(ints))


def _count(source: Any, name: str) -> int:
    value = _value(source, name, 0)
    if value is None:
        return 0
    return int(value)


def _partition_registers(registers: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    gp: list[str] = []
    seg: list[str] = []
    flags: list[str] = []
    for name in registers:
        if name in _SEGMENT_REGS:
            seg.append(name)
        elif name in _FLAG_NAMES:
            flags.append(name)
        else:
            gp.append(name)
    return tuple(gp), tuple(seg), tuple(flags)


def _low_memory_access_sort_key(item: LowMemoryAccess) -> tuple[int, int, int, str, str, str]:
    exact_hit = 0 if "+" not in item.label else 1
    return (item.linear, exact_hit, item.segment, item.offset, item.label, item.raw_access)


def _collect_low_memory_accesses(raw_accesses: tuple[str, ...], *, access_kind: str) -> tuple[LowMemoryAccess, ...]:
    accesses: list[LowMemoryAccess] = []
    for raw_access in raw_accesses:
        classified = classify_x86_16_low_memory_access(raw_access, access_kind=access_kind)
        if classified is None:
            continue
        accesses.append(classified)
    return tuple(sorted(accesses, key=_low_memory_access_sort_key))


def summarize_x86_16_function_state(source: Any) -> FunctionStateSummary:
    raw_inputs = _sorted_str_tuple(_value(source, "register_inputs", ()))
    raw_outputs = _sorted_str_tuple(_value(source, "register_outputs", ()))
    explicit_seg_inputs = _sorted_str_tuple(_value(source, "segment_register_inputs", ()))
    explicit_seg_outputs = _sorted_str_tuple(_value(source, "segment_register_outputs", ()))
    explicit_flag_inputs = _sorted_str_tuple(_value(source, "flag_inputs", ()))
    explicit_flag_outputs = _sorted_str_tuple(_value(source, "flag_outputs", ()))
    gp_inputs, seg_inputs, flag_inputs = _partition_registers(raw_inputs)
    gp_outputs, seg_outputs, flag_outputs = _partition_registers(raw_outputs)
    return FunctionStateSummary(
        gp_register_inputs=gp_inputs,
        gp_register_outputs=gp_outputs,
        segment_register_inputs=tuple(sorted(set(seg_inputs).union(explicit_seg_inputs))),
        segment_register_outputs=tuple(sorted(set(seg_outputs).union(explicit_seg_outputs))),
        flag_inputs=tuple(sorted(set(flag_inputs).union(explicit_flag_inputs))),
        flag_outputs=tuple(sorted(set(flag_outputs).union(explicit_flag_outputs))),
        frame_stack_reads=_sorted_int_tuple(_value(source, "frame_stack_reads", ())),
        frame_stack_writes=_sorted_int_tuple(_value(source, "frame_stack_writes", ())),
        memory_reads=_sorted_raw_str_tuple(_value(source, "memory_reads", ())),
        memory_writes=_sorted_raw_str_tuple(_value(source, "memory_writes", ())),
        low_memory_reads=_collect_low_memory_accesses(
            _sorted_raw_str_tuple(_value(source, "memory_reads", ())),
            access_kind="read",
        ),
        low_memory_writes=_collect_low_memory_accesses(
            _sorted_raw_str_tuple(_value(source, "memory_writes", ())),
            access_kind="write",
        ),
        direct_call_count=_count(source, "direct_call_count"),
        indirect_call_count=_count(source, "indirect_call_count"),
        direct_branch_count=_count(source, "direct_branch_count"),
        indirect_branch_count=_count(source, "indirect_branch_count"),
        return_kind=str(_value(source, "return_kind", "unknown")),
    )
