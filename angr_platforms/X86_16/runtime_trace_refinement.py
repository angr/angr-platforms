from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .ir_readiness import summarize_x86_16_ir_readiness

__all__ = [
    "RuntimeTraceRefinementSummary",
    "summarize_x86_16_runtime_trace_refinement",
]

_SEGMENT_REGS = frozenset({"cs", "ds", "es", "ss", "fs", "gs"})


@dataclass(frozen=True, slots=True)
class RuntimeTraceRefinementSummary:
    provenance: str = "none"
    segment_register_values: dict[str, int] | None = None
    refined_unknown_segment_count: int = 0
    remaining_unknown_segment_count: int = 0
    memory_read_count: int = 0
    memory_write_count: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "provenance": self.provenance,
            "segment_register_values": dict(sorted((self.segment_register_values or {}).items())),
            "refined_unknown_segment_count": self.refined_unknown_segment_count,
            "remaining_unknown_segment_count": self.remaining_unknown_segment_count,
            "memory_read_count": self.memory_read_count,
            "memory_write_count": self.memory_write_count,
        }


def _value(source: Any, name: str, default: Any = None) -> Any:
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def summarize_x86_16_runtime_trace_refinement(source: Any) -> RuntimeTraceRefinementSummary:
    trace = _value(source, "runtime_trace", None)
    if not isinstance(trace, Mapping):
        return RuntimeTraceRefinementSummary()
    segment_values = {
        str(name).lower(): int(value)
        for name, value in dict(trace.get("segment_registers", {}) or {}).items()
        if str(name).lower() in _SEGMENT_REGS and isinstance(value, int)
    }
    memory_reads = tuple(trace.get("memory_reads", ()) or ())
    memory_writes = tuple(trace.get("memory_writes", ()) or ())
    readiness = summarize_x86_16_ir_readiness(source)
    refined = min(readiness.unknown_segment_count, len(segment_values))
    return RuntimeTraceRefinementSummary(
        provenance="runtime_trace",
        segment_register_values=dict(sorted(segment_values.items())),
        refined_unknown_segment_count=refined,
        remaining_unknown_segment_count=max(0, readiness.unknown_segment_count - refined),
        memory_read_count=len(memory_reads),
        memory_write_count=len(memory_writes),
    )
