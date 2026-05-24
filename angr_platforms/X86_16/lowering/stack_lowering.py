from __future__ import annotations

# Layer: Lowering
# Responsibility: canonical stack/local lowering from typed alias evidence.
# Forbidden: rendered-text parsing and CLI guessing.

from collections.abc import Callable
import logging
import os

from .stack_lowering_impl import (
    _canonicalize_stack_cvar_expr,
    _canonicalize_stack_cvars,
    _materialize_stack_cvar_at_offset,
    _resolve_stack_cvar_at_offset,
    _resolve_stack_cvar_from_addr_expr,
)
from .stack_lowering_result import (
    StackLoweringResult,
    StackSlotFailure,
    materialization_diagnostics_8616,
)
from .real_mode_linear import (
    lower_stable_ds_es_linear_global_addresses_8616,
    lower_stable_ds_es_linear_global_dereferences_8616,
    lower_stable_ss_linear_stack_dereferences_8616,
)
from .segmented_memory_lowering import apply_runtime_segment_lowering_8616
from .stack_probe_return_facts import (
    TypedStackProbeReturnFact8616,
    build_typed_stack_probe_return_facts_8616,
)
from ..stack_probe_fact_trace import (
    record_stable_ss_lowering_refusal_8616,
    record_stable_ss_lowering_replacement_8616,
)

log = logging.getLogger(__name__)


def run_stack_lowering_pass_8616(
    *,
    rewrite_ss_stack_byte_offsets: Callable[[], bool],
    canonicalize_stack_cvars: Callable[[], bool],
    lower_stable_ss_stack_accesses: Callable[[], bool] | None = None,
    codegen=None,
    project=None,
    typed_stack_probe_return_facts: dict[int, TypedStackProbeReturnFact8616] | None = None,
    max_rounds: int = 2,
) -> bool:
    if codegen is not None:
        codegen._inertia_typed_stack_probe_return_facts = (
            build_typed_stack_probe_return_facts_8616(codegen)
            if typed_stack_probe_return_facts is None
            else typed_stack_probe_return_facts
        )
        codegen._inertia_ss_lowering_refusal_log = []
        debug_stats = getattr(codegen, "_inertia_stack_lowering_debug", None)
        if not isinstance(debug_stats, dict):
            debug_stats = {}
            codegen._inertia_stack_lowering_debug = debug_stats
        debug_stats.setdefault("candidate_text_match_count", 0)
        debug_stats.setdefault("candidate_ast_match_count", 0)
        debug_stats.setdefault("lowering_replacements", 0)
        debug_stats.setdefault("lowering_refusals", 0)
        debug_stats.setdefault("stable_ss_lowering_refusal_reasons", {})
    typed_fact_count = len(getattr(codegen, "_inertia_typed_stack_probe_return_facts", {}) or {}) if codegen is not None else 0
    changed = False
    for _ in range(max(max_rounds, 1)):
        round_changed = False
        # ── SS linear stack dereference lowering ──
        # Converts *(ss << 4 + stack_offset) dereferences to named stack
        # variables.  This is the canonical path that reverses segment
        # linearization produced by the VEX lifter for SS-relative accesses.
        if codegen is not None:
            if lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project):
                record_stable_ss_lowering_replacement_8616(codegen)
                round_changed = True
        # ── DS/ES linear global dereference lowering ──
        # Keep global DS/ES accesses as typed memory variables in the IR
        # whenever a stable real-mode segment expression is available.
        if codegen is not None:
            if lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=project):
                record_stable_ss_lowering_replacement_8616(codegen)
                round_changed = True
            if lower_stable_ds_es_linear_global_addresses_8616(codegen, project=project):
                record_stable_ss_lowering_replacement_8616(codegen)
                round_changed = True
        if codegen is not None and apply_runtime_segment_lowering_8616(
            codegen,
            target=str(getattr(project, "_inertia_c_target", "portable-flat") or "portable-flat"),
        ):
            record_stable_ss_lowering_replacement_8616(codegen)
            round_changed = True
        if lower_stable_ss_stack_accesses is not None:
            lowered = lower_stable_ss_stack_accesses()
            if lowered:
                if codegen is not None:
                    record_stable_ss_lowering_replacement_8616(codegen)
                round_changed = True
            elif codegen is not None and typed_fact_count > 0:
                debug_stats = getattr(codegen, "_inertia_stack_lowering_debug", None)
                if isinstance(debug_stats, dict):
                    debug_stats["lowering_refusals"] = int(debug_stats.get("lowering_refusals", 0) or 0) + 1
                    reasons = debug_stats.setdefault("stable_ss_lowering_refusal_reasons", {})
                    reasons["no_codegen_match"] = int(reasons.get("no_codegen_match", 0) or 0) + 1
                record_stable_ss_lowering_refusal_8616(codegen)
        if rewrite_ss_stack_byte_offsets():
            if codegen is not None:
                record_stable_ss_lowering_replacement_8616(codegen)
            round_changed = True
        if canonicalize_stack_cvars():
            if codegen is not None:
                record_stable_ss_lowering_replacement_8616(codegen)
            round_changed = True
        if not round_changed:
            break
        changed = True
    # Diagnostic: dump refusal log
    if codegen is not None:
        refusal_log = getattr(codegen, "_inertia_ss_lowering_refusal_log", None)
        if isinstance(refusal_log, list) and refusal_log:
            if not hasattr(codegen, "_inertia_ss_lowering_refusal_summary"):
                codegen._inertia_ss_lowering_refusal_summary = []
            codegen._inertia_ss_lowering_refusal_summary.extend(refusal_log)
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            debug_stats = getattr(codegen, "_inertia_stack_lowering_debug", None)
            if isinstance(debug_stats, dict):
                log.warning(
                    "[stack-lowering] function=%#x stable_stack_fact_count=%d stable_bp_fact_count=%d stack_binding_count=%d candidate_text_match_count=%d candidate_ast_match_count=%d lowering_replacements=%d lowering_refusals=%d reasons=%r",
                    getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
                    int(debug_stats.get("stable_stack_fact_count", 0) or 0),
                    int(debug_stats.get("stable_bp_fact_count", 0) or 0),
                    int(debug_stats.get("stack_binding_count", 0) or 0),
                    int(debug_stats.get("candidate_text_match_count", 0) or 0),
                    int(debug_stats.get("candidate_ast_match_count", 0) or 0),
                    int(debug_stats.get("lowering_replacements", 0) or 0),
                    int(debug_stats.get("lowering_refusals", 0) or 0),
                    debug_stats.get("stable_ss_lowering_refusal_reasons", {}),
                )
    return changed


__all__ = (
    "_canonicalize_stack_cvar_expr",
    "_canonicalize_stack_cvars",
    "_materialize_stack_cvar_at_offset",
    "_resolve_stack_cvar_at_offset",
    "_resolve_stack_cvar_from_addr_expr",
    "TypedStackProbeReturnFact8616",
    "build_typed_stack_probe_return_facts_8616",
    "run_stack_lowering_pass_8616",
)
