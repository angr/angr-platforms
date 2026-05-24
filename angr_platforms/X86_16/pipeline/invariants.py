from __future__ import annotations

"""Layer: Pipeline governance.

Responsibility: pre-rewrite invariant checks that ensure semantic correctness
before formatting/cleanup.

AGENTS rule: Rewrite must not hide bad alias/type/condition recovery.
If invariants fail, rewrite is skipped and honest partial output is emitted.

Forbidden: semantic recovery, type inference, condition reconstruction."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


__all__ = [
    "InvariantStatus",
    "InvariantCheck",
    "InvariantReport",
    "validate_before_rewrite_8616",
    "format_invariant_report_8616",
]


class InvariantStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True, slots=True)
class InvariantCheck:
    name: str
    status: InvariantStatus
    detail: str = ""
    evidence: tuple[str, ...] = ()

    @property
    def is_blocking(self) -> bool:
        return self.status == InvariantStatus.FAILED


@dataclass(slots=True)
class InvariantReport:
    function_addr: int = 0
    function_name: str = ""
    checks: list[InvariantCheck] = field(default_factory=list)
    rewrite_blocked: bool = False
    skip_reason: str = ""

    @property
    def all_passed(self) -> bool:
        return not self.rewrite_blocked and all(
            c.status != InvariantStatus.FAILED for c in self.checks
        )

    @property
    def failed_checks(self) -> list[InvariantCheck]:
        return [c for c in self.checks if c.is_blocking]

    def to_dict(self) -> dict[str, object]:
        return {
            "function_addr": self.function_addr,
            "function_name": self.function_name,
            "rewrite_blocked": self.rewrite_blocked,
            "skip_reason": self.skip_reason,
            "checks": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "detail": c.detail,
                    "evidence": list(c.evidence),
                }
                for c in self.checks
            ],
        }


def validate_before_rewrite_8616(
    codegen: Any,
    *,
    c_text: str = "",
    project: Any = None,
) -> InvariantReport:
    """Run pre-rewrite invariant checks against a function ready for rewrite.

    Checks:
        1. No linear ``(ss << 4)`` expressions surviving in generated C.
        2. No ``stack[...]`` indexing — all SS:BP offsets must be named variables.
        3. No ``if (tmp_*)`` conditions when typed ConditionIR is available.
        4. No ``if (flags & ...)`` raw flag conditions.
        5. No ``uncollected`` validation treated as success.
        6. All proven SS stack slots materialized as named variables.

    Returns InvariantReport.  If ``rewrite_blocked`` is True, the caller MUST skip
    rewrite/formatting and emit honest partial output.
    """
    report = InvariantReport()
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is not None:
        report.function_addr = getattr(cfunc, "addr", 0)
        report.function_name = getattr(cfunc, "name", "") or ""

    # Check 1: No linear SS expressions in output
    _check_no_ss_linear_expr(c_text, report)

    # Check 2: No stack[...] indexing
    _check_no_stack_indexing(c_text, report)

    # Check 3: No tmp-based conditions when typed IR exists
    _check_no_tmp_conditions(c_text, codegen, report)

    # Check 4: No raw flag conditions
    _check_no_raw_flag_conditions(c_text, report)

    # Check 5: Validation uncollected not treated as success
    _check_validation_not_uncollected(codegen, report)

    # Check 6: Proven stack slots materialized
    _check_stack_slots_materialized(codegen, report)

    # Check 7: Stack facts consumed (quantitative gate)
    _check_stack_facts_consumed(codegen, report)

    # Check 8: Condition facts consumed (quantitative gate)
    _check_condition_facts_consumed(codegen, report)

    # Determine if rewrite should be blocked
    failed = report.failed_checks
    if failed:
        report.rewrite_blocked = True
        report.skip_reason = (
            f"{len(failed)} invariant(s) failed: "
            + ", ".join(c.name for c in failed)
        )

    return report


def format_invariant_report_8616(report: InvariantReport) -> str:
    """Format an invariant report for diagnostic output."""
    lines: list[str] = [
        f"Pre-rewrite invariant report ({report.function_name or hex(report.function_addr)})",
        "=" * 60,
    ]
    for c in report.checks:
        status_mark = "PASS" if c.status == InvariantStatus.PASSED else c.status.value.upper()
        lines.append(f"  [{status_mark:>8}] {c.name}")
        if c.detail:
            lines.append(f"           {c.detail}")
    if report.rewrite_blocked:
        lines.append("")
        lines.append(f"  REWRITE BLOCKED: {report.skip_reason}")
    else:
        lines.append("")
        lines.append("  All invariants passed — rewrite allowed.")
    return "\n".join(lines)


# ── individual check implementations ──


def _check_no_ss_linear_expr(c_text: str, report: InvariantReport) -> None:
    """Check: no ``(ss << 4)`` linear expressions in generated C."""
    import re
    pattern = re.compile(r"\(\s*ss\s*<<\s*4\s*\)", re.IGNORECASE)
    matches = pattern.findall(c_text) if c_text else []
    if matches:
        report.checks.append(
            InvariantCheck(
                name="no_ss_linear_expr",
                status=InvariantStatus.FAILED,
                detail=f"found {len(matches)} linear SS expressions in output",
                evidence=tuple(matches[:5]),
            )
        )
    else:
        report.checks.append(
            InvariantCheck(name="no_ss_linear_expr", status=InvariantStatus.PASSED)
        )


def _check_no_stack_indexing(c_text: str, report: InvariantReport) -> None:
    """Check: no ``stack[...]`` syntax in output — all SS:BP mapped to named variables."""
    import re
    pattern = re.compile(r"stack\[", re.IGNORECASE)
    matches = pattern.findall(c_text) if c_text else []
    if matches:
        report.checks.append(
            InvariantCheck(
                name="no_stack_indexing",
                status=InvariantStatus.FAILED,
                detail=f"found {len(matches)} stack[...] indexings",
                evidence=tuple(matches[:5]),
            )
        )
    else:
        report.checks.append(
            InvariantCheck(name="no_stack_indexing", status=InvariantStatus.PASSED)
        )


def _check_no_tmp_conditions(c_text: str, codegen: Any, report: InvariantReport) -> None:
    """Check: no ``if (tmp_*)`` when typed ConditionIR is available."""
    import re
    pattern = re.compile(r"tmp_\d+", re.IGNORECASE)
    matches = pattern.findall(c_text) if c_text else []

    # Check if typed conditions exist in the function
    has_typed_conditions = bool(
        getattr(codegen, "_inertia_typed_conditions", None)
        or getattr(codegen, "_inertia_condition_facts", None)
    )

    if matches and has_typed_conditions:
        report.checks.append(
            InvariantCheck(
                name="no_tmp_conditions",
                status=InvariantStatus.FAILED,
                detail=f"found {len(matches)} tmp-based condition(s) despite available typed conditions",
                evidence=tuple(sorted(set(matches))[:5]),
            )
        )
    elif matches:
        report.checks.append(
            InvariantCheck(
                name="no_tmp_conditions",
                status=InvariantStatus.UNCERTAIN,
                detail=f"found {len(matches)} tmp-based condition(s) — no typed conditions available",
            )
        )
    else:
        report.checks.append(
            InvariantCheck(name="no_tmp_conditions", status=InvariantStatus.PASSED)
        )


def _check_no_raw_flag_conditions(c_text: str, report: InvariantReport) -> None:
    """Check: no ``if (flags & ...)`` raw flag conditions."""
    import re
    pattern = re.compile(r"\b(flags|eflags)\s*&", re.IGNORECASE)
    matches = pattern.findall(c_text) if c_text else []
    if matches:
        report.checks.append(
            InvariantCheck(
                name="no_raw_flag_conditions",
                status=InvariantStatus.FAILED,
                detail=f"found {len(matches)} raw flag condition(s)",
                evidence=tuple(matches[:5]),
            )
        )
    else:
        report.checks.append(
            InvariantCheck(name="no_raw_flag_conditions", status=InvariantStatus.PASSED)
        )


def _check_validation_not_uncollected(codegen: Any, report: InvariantReport) -> None:
    """Check: uncollected validation is not treated as success."""
    validation_passed = bool(getattr(codegen, "_inertia_validation_passed", False))
    validation_uncollected = bool(getattr(codegen, "_inertia_validation_uncollected", False))
    validation_verdict = getattr(codegen, "_inertia_validation_verdict", None)

    if validation_uncollected and validation_passed:
        report.checks.append(
            InvariantCheck(
                name="validation_not_uncollected",
                status=InvariantStatus.FAILED,
                detail="uncollected treated as passed",
            )
        )
    elif validation_uncollected:
        report.checks.append(
            InvariantCheck(
                name="validation_not_uncollected",
                status=InvariantStatus.UNCERTAIN,
                detail=f"validation uncollected (verdict={validation_verdict})",
            )
        )
    else:
        report.checks.append(
            InvariantCheck(
                name="validation_not_uncollected",
                status=InvariantStatus.PASSED,
            )
        )


def _check_stack_slots_materialized(codegen: Any, report: InvariantReport) -> None:
    """Check: all proven SS stack slots have been materialized as named variables."""
    semantic_alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
    if not semantic_alias_facts:
        report.checks.append(
            InvariantCheck(
                name="stack_slots_materialized",
                status=InvariantStatus.SKIPPED,
                detail="no semantic alias facts available for verification",
            )
        )
        return

    # Check if any AliasFailure records exist for proven SS
    from ..alias.alias_model_impl import AliasFailure, AliasStorageFacts

    def _canonical_stack_offset_8616(offset):
        if not isinstance(offset, int):
            return offset
        if 0x8000 <= offset <= 0xFFFF:
            return offset - 0x10000
        return offset

    failures: list[str] = []
    provisional_count = 0
    for fact in semantic_alias_facts:
        if isinstance(fact, AliasFailure):
            # PROVISIONAL SS addresses (push/pop/call/ret traffic) are stack
            # activity, not stack variables.  Per AGENTS rule: stack activity
            # may exist while stack_facts = 0 — this is valid and must not be
            # treated as failure.
            if "provisional" in fact.reason.lower():
                provisional_count += 1
                continue
            failures.append(
                f"SS offset={fact.offset} reason={fact.reason}"
            )
        elif isinstance(fact, AliasStorageFacts):
            if fact.identity and fact.identity[0] == "stack":
                # Stack slot identified — check if it's been materialized
                identity_val = fact.identity[1]
                offset = _canonical_stack_offset_8616(getattr(identity_val, "offset", None))
                if offset is not None:
                    cfunc = getattr(codegen, "cfunc", None)
                    variables = getattr(cfunc, "variables_in_use", {}) if cfunc else {}
                    # Check if any variable matches this offset
                    from angr.sim_variable import SimStackVariable
                    found = any(
                        isinstance(v, SimStackVariable)
                        and _canonical_stack_offset_8616(getattr(v, "offset", None)) == offset
                        for v in variables
                    )
                    if not found:
                        failures.append(
                            f"stack slot offset={offset} identified but not materialized in variables_in_use"
                        )

    if failures:
        report.checks.append(
            InvariantCheck(
                name="stack_slots_materialized",
                status=InvariantStatus.FAILED,
                detail=f"{len(failures)} un-materialized stack slot(s)",
                evidence=tuple(failures[:5]),
            )
        )
    else:
        report.checks.append(
            InvariantCheck(name="stack_slots_materialized", status=InvariantStatus.PASSED)
        )


def _check_stack_facts_consumed(codegen: Any, report: InvariantReport) -> None:
    """Quantitative gate: if stack alias facts exist, at least one must be materialized.

    AGENTS rule: facts produced but not consumed is a pipeline failure.
    If stack_fact_count > 0 and stack_materialized_count == 0, block rewrite
    with a precise diagnostic indicating the next missing layer.
    """
    stack_facts = getattr(codegen, "_inertia_semantic_stack_fact_count", 0)
    materialized = getattr(codegen, "_inertia_semantic_stack_materialized_count", 0)

    if stack_facts == 0:
        report.checks.append(
            InvariantCheck(
                name="stack_facts_consumed",
                status=InvariantStatus.SKIPPED,
                detail="no stack alias facts produced — nothing to consume",
            )
        )
    elif stack_facts > 0 and materialized == 0:
        report.checks.append(
            InvariantCheck(
                name="stack_facts_consumed",
                status=InvariantStatus.FAILED,
                detail=f"stack_facts={stack_facts} but stack_materialized=0 — facts NOT consumed",
                evidence=(),
            )
        )
    else:
        report.checks.append(
            InvariantCheck(
                name="stack_facts_consumed",
                status=InvariantStatus.PASSED,
                detail=f"stack_facts={stack_facts}, stack_materialized={materialized}",
            )
        )


def _check_condition_facts_consumed(codegen: Any, report: InvariantReport) -> None:
    """Quantitative gate: if condition facts exist, at least one must be consumed.

    AGENTS rule: condition facts produced but no condition replacements applied
    means the materialization pass is missing.  Block rewrite so the problem
    is visible.
    """
    condition_facts = getattr(codegen, "_inertia_semantic_condition_fact_count", 0)
    materialized = getattr(codegen, "_inertia_semantic_condition_materialized_count", 0)

    if condition_facts == 0:
        report.checks.append(
            InvariantCheck(
                name="condition_facts_consumed",
                status=InvariantStatus.SKIPPED,
                detail="no condition facts produced — nothing to consume",
            )
        )
    elif condition_facts > 0 and materialized == 0:
        report.checks.append(
            InvariantCheck(
                name="condition_facts_consumed",
                status=InvariantStatus.FAILED,
                detail=(
                    f"condition_facts={condition_facts} but condition_materialized=0 "
                    f"— facts NOT consumed"
                ),
                evidence=(),
            )
        )
    else:
        report.checks.append(
            InvariantCheck(
                name="condition_facts_consumed",
                status=InvariantStatus.PASSED,
                detail=f"condition_facts={condition_facts}, condition_materialized={materialized}",
            )
        )


def classify_stack_blocker_8616(diag) -> str | None:
    """Classify stack-materialization blockers from diagnostics.

    Returns a human-readable blocker label, or None if no hard blocker is found.
    This is the canonical blocker taxonomy for stack lowering.
    """
    if diag.get("ss_stack_accesses", 0) > 0 and diag.get("stack_facts", 0) == 0:
        if diag.get("bp_stable_accesses", 0) == 0:
            return "stack activity detected but no stable frame"

    if diag.get("stack_facts", 0) > 0 and diag.get("stack_materialized", 0) == 0:
        return "stack facts not materialized"

    return None
