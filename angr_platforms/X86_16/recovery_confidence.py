from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Mapping

from .function_effect_summary import FunctionEffectSummary, summarize_x86_16_function_effects
from .function_state_summary import FunctionStateSummary, summarize_x86_16_function_state
from .helper_family_routing import summarize_x86_16_helper_family_routes
from .helper_effect_summary import HelperEligibilitySummary, summarize_x86_16_helper_eligibility
from .ir_readiness import summarize_x86_16_ir_readiness

__all__ = [
    "FunctionEffectSummary",
    "FunctionStateSummary",
    "HelperEligibilitySummary",
    "RecoveryAssumption",
    "RecoveryConfidenceSummary",
    "RecoveryEvidence",
    "RECOVERY_CONFIDENCE_AXES",
    "classify_x86_16_recovery_confidence",
    "describe_x86_16_recovery_confidence_axes",
    "summarize_recovery_confidence",
]


@dataclass(frozen=True, slots=True)
class RecoveryEvidence:
    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class RecoveryAssumption:
    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class RecoveryConfidenceSummary:
    status: str
    evidence: tuple[RecoveryEvidence, ...] = ()
    assumptions: tuple[RecoveryAssumption, ...] = ()
    diagnostics: tuple[str, ...] = ()
    scan_safe_classification: str = "unknown"
    helper_summary: HelperEligibilitySummary | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "evidence": [{"kind": item.kind, "detail": item.detail} for item in self.evidence],
            "assumptions": [{"kind": item.kind, "detail": item.detail} for item in self.assumptions],
            "diagnostics": list(self.diagnostics),
            "scan_safe_classification": self.scan_safe_classification,
            "helper_summary": None if self.helper_summary is None else self.helper_summary.to_dict(),
        }


def _value(source: Any, name: str, default: Any = None) -> Any:
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def _count(source: Any, name: str) -> int:
    value = _value(source, name, 0)
    if value is None:
        return 0
    return int(value)


def classify_x86_16_recovery_confidence(source: Any) -> RecoveryConfidenceSummary:
    ok = bool(_value(source, "ok", False))
    decompiled_count = _count(source, "decompiled_count")
    fallback_kind = _value(source, "fallback_kind", None)
    has_far_call_reloc = bool(_value(source, "has_far_call_reloc", False))
    rewrite_failed = bool(_value(source, "rewrite_failed", False))
    regeneration_failed = bool(_value(source, "regeneration_failed", False))
    structuring_failed = bool(_value(source, "structuring_failed", False))
    interrupt_unresolved_wrapper_count = _count(source, "interrupt_unresolved_wrapper_count")
    interrupt_wrapper_call_count = _count(source, "interrupt_wrapper_call_count")
    interrupt_dos_helper_count = _count(source, "interrupt_dos_helper_count")
    interrupt_bios_helper_count = _count(source, "interrupt_bios_helper_count")
    last_structuring_pass = _value(source, "last_structuring_pass", None)
    last_postprocess_pass = _value(source, "last_postprocess_pass", None)
    reason = _value(source, "reason", None)
    failure_class = _value(source, "failure_class", None)
    stage_reached = _value(source, "stage_reached", None)
    effect_summary = summarize_x86_16_function_effects(source)
    state_summary = summarize_x86_16_function_state(source)
    helper_summary = summarize_x86_16_helper_eligibility(source)
    ir_readiness = summarize_x86_16_ir_readiness(source)

    evidence: list[RecoveryEvidence] = []
    assumptions: list[RecoveryAssumption] = []
    diagnostics: list[str] = []

    if ok and decompiled_count > 0:
        evidence.append(RecoveryEvidence("decompiled_output", "decompiler produced structured C output"))
    if interrupt_dos_helper_count or interrupt_bios_helper_count:
        evidence.append(
            RecoveryEvidence(
                "helper_lowering",
                f"{interrupt_dos_helper_count} DOS helper(s), {interrupt_bios_helper_count} BIOS helper(s)",
            )
        )
    if last_structuring_pass:
        evidence.append(RecoveryEvidence("structuring_pass", f"last structuring pass: {last_structuring_pass}"))
    if last_postprocess_pass:
        evidence.append(RecoveryEvidence("postprocess_pass", f"last postprocess pass: {last_postprocess_pass}"))
    if (
        effect_summary.register_inputs
        or effect_summary.register_outputs
        or effect_summary.direct_call_count
        or effect_summary.indirect_call_count
        or effect_summary.direct_branch_count
        or effect_summary.indirect_branch_count
        or effect_summary.frame_stack_reads
        or effect_summary.frame_stack_writes
        or effect_summary.memory_reads
        or effect_summary.memory_writes
    ):
        evidence.append(RecoveryEvidence("function_effect_summary", effect_summary.brief()))
    if (
        state_summary.gp_register_inputs
        or state_summary.gp_register_outputs
        or state_summary.segment_register_inputs
        or state_summary.segment_register_outputs
        or state_summary.flag_inputs
        or state_summary.flag_outputs
    ):
        evidence.append(RecoveryEvidence("function_state_summary", state_summary.brief()))
    if helper_summary.status == "eligible":
        evidence.append(RecoveryEvidence("helper_eligibility", helper_summary.brief()))
    if ir_readiness.level != "missing":
        evidence.append(
            RecoveryEvidence(
                "typed_ir_readiness",
                (
                    f"level={ir_readiness.level} "
                    f"cond={ir_readiness.condition_count} "
                    f"phi={ir_readiness.phi_node_count} "
                    f"defaulted={ir_readiness.defaulted_segment_count} "
                    f"proven={ir_readiness.proven_segment_count}"
                ),
            )
        )
    if (
        ok
        and fallback_kind == "cfg_only"
        and _value(source, "semantic_family", None) == "stack_control"
        and _value(source, "stage_reached", None) == "cleanup"
    ):
        evidence.append(
            RecoveryEvidence(
                "bounded_recovery",
                "scan-safe helper lane completed at cleanup without requiring decompilation",
            )
        )

    if interrupt_unresolved_wrapper_count > 0:
        assumptions.append(
            RecoveryAssumption(
                "helper_guessed_from_weak_evidence",
                f"{interrupt_unresolved_wrapper_count} unresolved wrapper call(s) still need helper signatures",
            )
        )
    elif interrupt_wrapper_call_count > 0 and interrupt_dos_helper_count == 0 and interrupt_bios_helper_count == 0:
        assumptions.append(
            RecoveryAssumption(
                "helper_guessed_from_weak_evidence",
                f"{interrupt_wrapper_call_count} wrapper call(s) were observed without a settled helper mapping",
            )
        )
        if helper_summary.status != "eligible":
            assumptions.append(
                RecoveryAssumption(
                    "helper_shape_refused",
                    helper_summary.brief(),
                )
            )

    if has_far_call_reloc and (not ok or fallback_kind not in (None, "none")):
        assumptions.append(
            RecoveryAssumption(
                "far_pointer_unresolved",
                "far pointer / far call evidence still needs a stable target association",
            )
        )

    if rewrite_failed or regeneration_failed:
        assumptions.append(
            RecoveryAssumption(
                "return_shape_uncertain",
                "postprocess rewrite/regeneration still needs a stable return-shape boundary",
            )
        )
    if structuring_failed:
        assumptions.append(
            RecoveryAssumption(
                "structuring_failure",
                "control-flow structuring still needs a stable downstream boundary",
            )
        )
    if effect_summary.has_indirect_control():
        assumptions.append(
            RecoveryAssumption(
                "indirect_control_flow",
                "indirect call/branch behavior still needs an explicit effect-summary consumer",
            )
        )
    if helper_summary.status == "refused" and interrupt_unresolved_wrapper_count > 0:
        assumptions.append(
            RecoveryAssumption(
                "helper_shape_refused",
                helper_summary.brief(),
            )
        )
    if state_summary.touches_segments():
        assumptions.append(
            RecoveryAssumption(
                "segment_state_needs_tracking",
                "segment-register dataflow should stay explicit across CFG and call boundaries",
            )
        )
    if state_summary.touches_flags() and ir_readiness.condition_count == 0:
        assumptions.append(
            RecoveryAssumption(
                "live_flags_need_typed_conditions",
                "live flag dependencies still need typed condition recovery at branch and loop boundaries",
            )
        )
    if ir_readiness.unknown_segment_count > 0:
        assumptions.append(
            RecoveryAssumption(
                "typed_ir_segment_unknown",
                f"{ir_readiness.unknown_segment_count} typed address(es) still have unknown segment identity",
            )
        )
    elif ir_readiness.defaulted_segment_count > 0 and ir_readiness.proven_segment_count == 0:
        assumptions.append(
            RecoveryAssumption(
                "typed_ir_segment_defaulted",
                f"{ir_readiness.defaulted_segment_count} typed address(es) still rely on default segment identity",
            )
        )
    if ir_readiness.block_count > 1 and ir_readiness.phi_node_count == 0:
        assumptions.append(
            RecoveryAssumption(
                "typed_ir_cross_block_ssa_missing",
                "typed IR is still block-local across CFG joins",
            )
        )
    if ir_readiness.condition_count == 0 and ir_readiness.block_count > 0:
        assumptions.append(
            RecoveryAssumption(
                "typed_ir_conditions_missing",
                "typed IR still lacks lifted branch/loop conditions",
            )
        )

    if reason:
        diagnostics.append(str(reason))
    if failure_class:
        diagnostics.append(f"failure_class={failure_class}")
    if stage_reached:
        diagnostics.append(f"stage_reached={stage_reached}")
    if effect_summary != summarize_x86_16_function_effects({}):
        diagnostics.append(f"function_effects={effect_summary.brief()}")
    if state_summary != summarize_x86_16_function_state({}):
        diagnostics.append(f"function_state={state_summary.brief()}")
    if helper_summary.status != "no_signal":
        diagnostics.append(f"helper_summary={helper_summary.brief()}")
    if ir_readiness.level != "missing":
        diagnostics.append(
            "ir_readiness="
            f"{ir_readiness.level}"
            f":cond={ir_readiness.condition_count}"
            f":phi={ir_readiness.phi_node_count}"
            f":defaulted={ir_readiness.defaulted_segment_count}"
            f":unknown={ir_readiness.unknown_segment_count}"
        )

    if (
        ok
        and fallback_kind == "cfg_only"
        and _value(source, "semantic_family", None) == "stack_control"
        and _value(source, "stage_reached", None) == "cleanup"
        and not assumptions
    ):
        status = "bounded_recovery"
    elif rewrite_failed or regeneration_failed:
        status = "return_shape_uncertain"
    elif structuring_failed and ok:
        status = "partial_recovery"
    elif has_far_call_reloc and (assumptions or not ok):
        status = "far_pointer_unresolved"
    elif interrupt_unresolved_wrapper_count > 0 or (
        interrupt_wrapper_call_count > 0 and interrupt_dos_helper_count == 0 and interrupt_bios_helper_count == 0
    ):
        status = "helper_guessed_weak"
    elif ok and fallback_kind not in (None, "none"):
        status = "partial_recovery"
    elif ok and decompiled_count > 0 and not fallback_kind:
        status = "target_recovered_strong"
    elif ok and decompiled_count > 0:
        status = "partial_recovery"
    else:
        status = "target_unrecovered"

    if status == "target_recovered_strong":
        scan_safe_classification = "strong"
    elif status == "bounded_recovery":
        scan_safe_classification = "strong"
    elif status in {"partial_recovery", "helper_guessed_weak"}:
        scan_safe_classification = "partial"
    else:
        scan_safe_classification = "unresolved"

    return RecoveryConfidenceSummary(
        status=status,
        evidence=tuple(evidence),
        assumptions=tuple(assumptions),
        diagnostics=tuple(diagnostics),
        scan_safe_classification=scan_safe_classification,
        helper_summary=helper_summary,
    )


def summarize_recovery_confidence(results: list[Any]) -> dict[str, object]:
    summaries = [classify_x86_16_recovery_confidence(result) for result in results]
    status_counter = Counter(summary.status for summary in summaries)
    scan_safe_counter = Counter(summary.scan_safe_classification for summary in summaries)
    assumption_counter = Counter(item.kind for summary in summaries for item in summary.assumptions)
    evidence_counter = Counter(item.kind for summary in summaries for item in summary.evidence)
    helper_status_counter = Counter(
        summary.helper_summary.status for summary in summaries if summary.helper_summary is not None
    )
    helper_candidate_counter = Counter(
        summary.helper_summary.candidate_kind
        for summary in summaries
        if summary.helper_summary is not None and summary.helper_summary.candidate_kind != "none"
    )
    helper_refusal_counter = Counter(
        refusal.kind
        for summary in summaries
        if summary.helper_summary is not None
        for refusal in summary.helper_summary.refusals
    )
    helper_family_rows = tuple(
        item.to_dict()
        for item in summarize_x86_16_helper_family_routes(
            summary.helper_summary
            for summary in summaries
            if summary.helper_summary is not None
        )
    )

    return {
        "status_counts": dict(sorted(status_counter.items())),
        "scan_safe_counts": dict(sorted(scan_safe_counter.items())),
        "assumption_counts": dict(sorted(assumption_counter.items())),
        "evidence_counts": dict(sorted(evidence_counter.items())),
        "helper_status_counts": dict(sorted(helper_status_counter.items())),
        "helper_candidate_counts": dict(sorted(helper_candidate_counter.items())),
        "helper_refusal_counts": dict(sorted(helper_refusal_counter.items())),
        "helper_family_rows": list(helper_family_rows),
    }


RECOVERY_CONFIDENCE_AXES: tuple[tuple[str, str], ...] = (
    ("target_recovered_strong", "Recovered output with stable evidence and no active assumptions."),
    ("bounded_recovery", "Bounded scan-safe recovery completed without requiring decompilation."),
    ("helper_guessed_weak", "Helper signatures still need stronger evidence."),
    ("far_pointer_unresolved", "Far-pointer or far-call association is not yet stable."),
    ("return_shape_uncertain", "Postprocess still depends on an unstable return-shape boundary."),
    ("target_unrecovered", "The target could not be recovered with the current evidence."),
)


def describe_x86_16_recovery_confidence_axes() -> tuple[tuple[str, str], ...]:
    return RECOVERY_CONFIDENCE_AXES
