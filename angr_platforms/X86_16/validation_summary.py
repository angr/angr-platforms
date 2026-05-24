from __future__ import annotations

"""Layer: Validation (cross-cutting governance).

Responsibility: ensure validation attribution remains honest — uncollected,
fallback, and timeout identities must stay visible in aggregate.
Forbidden: collapsing uncollected into success, hiding fallback identities."""

from dataclasses import dataclass, field
from enum import Enum


__all__ = [
    "ValidationState",
    "ValidationRecord",
    "ValidationAggregate",
    "build_validation_record_8616",
    "aggregate_validation_records_8616",
    "format_validation_aggregate_report_8616",
]


class ValidationState(Enum):
    """Tracked validation outcome for a single function/stage."""

    PASSED = "passed"
    CHANGED = "changed"
    UNCOLLECTED = "uncollected"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"
    FALLBACK = "fallback"
    CRASH = "crash"


@dataclass(slots=True)
class ValidationRecord:
    """A single-function validation attribution record."""

    function_name: str
    function_addr: int = 0
    structuring_state: ValidationState = ValidationState.UNCOLLECTED
    postprocess_state: ValidationState = ValidationState.UNCOLLECTED
    fallback_mode: str | None = None
    proc_identity: str | None = None
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "function_name": self.function_name,
            "function_addr": self.function_addr,
            "structuring": self.structuring_state.value,
            "postprocess": self.postprocess_state.value,
            "fallback_mode": self.fallback_mode,
            "proc_identity": self.proc_identity,
            "note": self.note,
        }

    @property
    def is_clean(self) -> bool:
        return (
            self.structuring_state == ValidationState.PASSED
            and self.postprocess_state == ValidationState.PASSED
        )

    @property
    def has_uncollected(self) -> bool:
        return (
            self.structuring_state == ValidationState.UNCOLLECTED
            or self.postprocess_state == ValidationState.UNCOLLECTED
        )


@dataclass(slots=True)
class ValidationAggregate:
    """Aggregated validation stats across a corpus."""

    records: list[ValidationRecord] = field(default_factory=list)
    total_functions: int = 0
    passed: int = 0
    changed: int = 0
    uncollected: int = 0
    unknown: int = 0
    timeout: int = 0
    fallback: int = 0
    crash: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "total_functions": self.total_functions,
            "passed": self.passed,
            "changed": self.changed,
            "uncollected": self.uncollected,
            "unknown": self.unknown,
            "timeout": self.timeout,
            "fallback": self.fallback,
            "crash": self.crash,
            "records": [r.to_dict() for r in self.records],
        }


def build_validation_record_8616(
    function_name: str,
    *,
    function_addr: int = 0,
    structuring_state: str | None = None,
    postprocess_state: str | None = None,
    fallback_mode: str | None = None,
    proc_identity: str | None = None,
    note: str = "",
) -> ValidationRecord:
    """Build a single validation record from tail_validation state strings."""
    _struct = _parse_validation_state_8616(structuring_state)
    _post = _parse_validation_state_8616(postprocess_state)
    return ValidationRecord(
        function_name=function_name,
        function_addr=function_addr,
        structuring_state=_struct,
        postprocess_state=_post,
        fallback_mode=fallback_mode,
        proc_identity=proc_identity,
        note=note,
    )


def aggregate_validation_records_8616(
    records: list[ValidationRecord],
) -> ValidationAggregate:
    """Build an aggregate summary from individual validation records."""
    agg = ValidationAggregate()
    agg.records = records
    agg.total_functions = len(records)

    for r in records:
        _count_record_into_aggregate_8616(agg, r)
    return agg


def format_validation_aggregate_report_8616(agg: ValidationAggregate) -> str:
    """Format an honest aggregate report — uncollected stays visible."""
    lines: list[str] = [
        f"Validation Aggregate ({agg.total_functions} functions)",
        "=" * 50,
        f"  passed:       {agg.passed}",
        f"  changed:      {agg.changed}",
        f"  uncollected:  {agg.uncollected}  <-- NOT hidden",
        f"  unknown:      {agg.unknown}",
        f"  timeout:      {agg.timeout}",
        f"  fallback:     {agg.fallback}",
        f"  crash:        {agg.crash}",
    ]
    if agg.uncollected > 0:
        uncollected_names = [r.function_name for r in agg.records if r.has_uncollected]
        if uncollected_names:
            lines.append("")
            lines.append("  Uncollected functions:")
            for name in sorted(uncollected_names):
                lines.append(f"    - {name}")
    return "\n".join(lines)


def _parse_validation_state_8616(v: str | None) -> ValidationState:
    if not isinstance(v, str) or not v:
        return ValidationState.UNCOLLECTED
    v_lower = v.strip().lower()
    for s in ValidationState:
        if s.value == v_lower:
            return s
    if v_lower in ("stable",):
        return ValidationState.PASSED
    if v_lower in ("changed",):
        return ValidationState.CHANGED
    return ValidationState.UNKNOWN


def _count_record_into_aggregate_8616(agg: ValidationAggregate, r: ValidationRecord) -> None:
    """Count the worst state for a record into the aggregate.

    A record contributes to the worst category it falls into:
      crash > timeout > fallback > uncollected > changed > passed

    Only the worst state is counted — one record = one bucket.
    """
    # Order: worst first
    worst: ValidationState | None = None
    for state in (r.structuring_state, r.postprocess_state):
        if state in (ValidationState.CRASH,):
            worst = ValidationState.CRASH
            break
        if state == ValidationState.TIMEOUT and worst not in (ValidationState.CRASH,):
            worst = ValidationState.TIMEOUT
        elif state == ValidationState.FALLBACK and worst not in (ValidationState.CRASH, ValidationState.TIMEOUT):
            worst = ValidationState.FALLBACK
        elif state == ValidationState.UNCOLLECTED and worst not in (
            ValidationState.CRASH, ValidationState.TIMEOUT, ValidationState.FALLBACK,
        ):
            worst = ValidationState.UNCOLLECTED
        elif state == ValidationState.CHANGED and worst not in (
            ValidationState.CRASH, ValidationState.TIMEOUT, ValidationState.FALLBACK, ValidationState.UNCOLLECTED,
        ):
            worst = ValidationState.CHANGED
        elif state == ValidationState.PASSED and worst is None:
            worst = ValidationState.PASSED

    if worst is None:
        worst = ValidationState.UNCOLLECTED

    if worst == ValidationState.PASSED:
        agg.passed += 1
    elif worst == ValidationState.CHANGED:
        agg.changed += 1
    elif worst == ValidationState.UNCOLLECTED:
        agg.uncollected += 1
    elif worst == ValidationState.UNKNOWN:
        agg.unknown += 1
    elif worst == ValidationState.TIMEOUT:
        agg.timeout += 1
    elif worst == ValidationState.FALLBACK:
        agg.fallback += 1
    elif worst == ValidationState.CRASH:
        agg.crash += 1