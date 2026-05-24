from __future__ import annotations

"""Layer: Lowering.

Responsibility: typed stack lowering result with hard-fail enforcement.

AGENTS rule: SS:BP+offset → stack slot → variable.
If a proven SS stack slot cannot be materialized as a named variable,
the function is marked invalid rather than silently continuing.
"""

from dataclasses import dataclass, field
from typing import Any


__all__ = [
    "StackLoweringResult",
    "StackSlotFailure",
    "materialization_diagnostics_8616",
]


@dataclass(frozen=True, slots=True)
class StackSlotFailure:
    """A proven SS stack slot that could not be materialized as a named variable."""

    offset: int
    size: int
    reason: str
    evidence: tuple[str, ...] = ()


@dataclass(slots=True)
class StackLoweringResult:
    """Outcome of a stack lowering pass with mandatory hard-fail tracking.

    If status != "ok", the pipeline MUST stop before rewrite and emit
    honest partial output with diagnostic information.
    """

    status: str = "ok"  # "ok" | "failed" | "partial"
    failures: list[StackSlotFailure] = field(default_factory=list)
    materialized: list[tuple[int, str]] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    @property
    def is_ok(self) -> bool:
        return self.status == "ok"

    @property
    def is_failed(self) -> bool:
        return self.status == "failed"

    @property
    def failure_count(self) -> int:
        return len(self.failures)

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "failure_count": self.failure_count,
            "materialized_count": len(self.materialized),
            "failures": [
                {
                    "offset": f.offset,
                    "size": f.size,
                    "reason": f.reason,
                }
                for f in self.failures
            ],
            "materialized": [
                {"offset": offset, "name": name}
                for offset, name in self.materialized
            ],
            "diagnostics": list(self.diagnostics),
        }


def materialization_diagnostics_8616(result: StackLoweringResult) -> str:
    """Format a readable diagnostic summary for stack lowering failure."""
    lines: list[str] = [f"Stack lowering: {result.status}"]
    if result.materialized:
        lines.append(f"  Materialized: {len(result.materialized)} slots")
    if result.failures:
        lines.append(f"  Failures: {len(result.failures)} slots not materialized")
        for f in result.failures:
            lines.append(f"    SS:BP{f.offset:+d} ({f.size} bytes): {f.reason}")
    return "\n".join(lines)