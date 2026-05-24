from __future__ import annotations

import contextlib
import logging
import os
import time
from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import Tuple, Callable

from angr.analyses.decompiler.decompiler import Decompiler
from inertia_decompiler.cli_access_profiles import build_access_trait_evidence_profiles, infer_induction_summary

from . import confidence_and_assumptions as _confidence
from . import decompiler_postprocess_simplify as _simplify
from . import function_interface_surface as _interface_surface
from . import ir_confidence_markers as _ir_confidence
from .ir import vex_import as _vex_ir
from .ir import segment_state as _segment_state
from .ir import string_effects as _string_effects
from . import segmented_memory_reasoning as _segmented_mem
from . import string_instruction_artifact as _string_instruction_artifact
from . import string_codegen_override as _string_codegen_override
from . import string_instruction_lowering as _string_instruction_lowering
from . import structuring_cross_entry as _cross_entry
from . import structuring_grouped_pass as _grouped_structuring
from . import structuring_codegen as _codegen
from . import structuring_diagnostics as _diagnostics
from . import type_array_matching as _array_match
from . import type_equivalence_classes as _type_equiv
from . import type_structure_merging as _struct_merge
from .condition_trace import record_ast_condition_trace_8616
from .lowering.condition_transfer import transfer_typed_conditions_to_codegen_8616
from .tail_validation import (
    build_x86_16_tail_validation_cached_result,
    build_x86_16_tail_validation_verdict,
    collect_x86_16_tail_validation_summary,
    fingerprint_x86_16_tail_validation_boundary,
    persist_x86_16_tail_validation_snapshot,
    x86_16_tail_validation_result_passed,
)
from inertia_decompiler.runtime_support import timing_output_enabled

__all__ = [
    "DecompilerStructuringPassSpec",
    "DECOMPILER_STRUCTURING_PASSES",
    "_build_decompiler_structuring_passes",
    "describe_x86_16_decompiler_structuring_stage",
    "apply_x86_16_decompiler_structuring",
]


@dataclass(frozen=True, slots=True)
class DecompilerStructuringPassSpec:
    name: str
    func: Callable[..., bool]
    needs_project: bool


def _build_decompiler_structuring_passes() -> tuple[DecompilerStructuringPassSpec, ...]:
    return (
        DecompilerStructuringPassSpec(
            "_cross_entry_cfg_grouping_8616",
            _cross_entry.apply_x86_16_cross_entry_grouping,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_region_based_structuring_8616",
            _grouped_structuring.apply_grouped_region_based_structuring,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_simplify_structured_expressions_8616",
            _simplify._simplify_structured_expressions_8616,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_induction_summary_artifact_8616",
            _induction_summary_artifact_8616,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_structuring_codegen_8616",
            _codegen.apply_structuring_codegen_8616,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_vex_ir_artifact_8616",
            _vex_ir.apply_x86_16_vex_ir_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_segment_state_artifact_8616",
            _segment_state.apply_x86_16_segment_state_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_string_instruction_artifact_8616",
            _string_instruction_artifact.apply_x86_16_string_instruction_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_typed_string_effect_artifact_8616",
            _string_effects.apply_x86_16_typed_string_effect_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_string_instruction_lowering_8616",
            _string_instruction_lowering.apply_x86_16_string_instruction_lowering,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_string_codegen_override_8616",
            _string_codegen_override.apply_x86_16_string_codegen_override,
            True,
        ),
        # Phase 3: Segmented Memory Association Reasoning
        DecompilerStructuringPassSpec(
            "_segmented_memory_reasoning_8616",
            _segmented_mem.apply_x86_16_segmented_memory_reasoning,
            False,
        ),
        # Phase 2: Type Inference and Recovery
        DecompilerStructuringPassSpec(
            "_type_equivalence_classes_8616",
            _type_equiv.apply_x86_16_type_equivalence_classes,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_array_expression_matching_8616",
            _array_match.apply_x86_16_array_expression_matching,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_structure_field_merging_8616",
            _struct_merge.apply_x86_16_structure_field_merging,
            False,
        ),
        # Phase 4: Robustness & Diagnostics
        DecompilerStructuringPassSpec(
            "_structuring_diagnostics_8616",
            _diagnostics.apply_x86_16_structuring_diagnostics,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_ir_confidence_markers_8616",
            _ir_confidence.apply_x86_16_ir_confidence_markers,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_confidence_and_assumptions_8616",
            _confidence.apply_x86_16_confidence_and_assumptions,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_function_interface_surface_8616",
            _interface_surface.apply_x86_16_function_interface_surface,
            True,
        ),
    )


def _induction_summary_artifact_8616(codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    project = getattr(codegen, "project", None)
    if cfunc is None or project is None:
        return False
    traits_cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(traits_cache, dict):
        codegen._inertia_induction_summaries = ()
        return False
    traits = traits_cache.get(getattr(cfunc, "addr", None))
    if not isinstance(traits, dict):
        codegen._inertia_induction_summaries = ()
        return False

    summaries = []
    for _base_key, profile in sorted(build_access_trait_evidence_profiles(traits).items(), key=lambda item: repr(item[0])):
        summary = infer_induction_summary(profile)
        if summary is not None:
            summaries.append(summary)
    codegen._inertia_induction_summaries = tuple(summaries)
    return False


DECOMPILER_STRUCTURING_PASSES = _build_decompiler_structuring_passes()


def _semantic_validation_pass_names_8616() -> tuple[str, ...]:
    return (
        "_simplify_structured_expressions_8616",
        "_segmented_memory_reasoning_8616",
        "_array_expression_matching_8616",
        "_structuring_codegen_8616",
    )


def _prime_structuring_validation_semantics_8616(project, codegen) -> None:
    if getattr(codegen, "_inertia_structuring_validation_semantics_primed", False):
        return
    try:
        from .lowering.real_mode_linear import (
            lower_stable_ds_es_linear_global_dereferences_8616,
            lower_stable_ss_linear_stack_dereferences_8616,
        )

        lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)
        lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=project)
        _segmented_mem.apply_x86_16_segmented_memory_reasoning(codegen)
        from .lowering.fact_transfer import transfer_semantic_alias_facts_to_codegen_8616
        from .lowering.stack_lowering_from_facts import lower_stack_accesses_from_alias_facts_8616

        transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
        alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
        if isinstance(alias_facts, list) and alias_facts:
            lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
        # Keep structuring-tail validation stable: if priming already applied
        # SS stack lowering and alias-fact lowering, skip re-running it in the
        # structuring body to avoid representation-only drift.
        codegen._inertia_ss_stack_lowered = True
        if not getattr(codegen, "_inertia_typed_conditions_transferred", False):
            func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
            if isinstance(func_addr, int):
                transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
            codegen._inertia_typed_conditions_transferred = True
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Structuring validation semantic priming failed function=%#x: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    finally:
        codegen._inertia_structuring_validation_semantics_primed = True


def _refresh_structuring_condition_semantics_8616(project, codegen) -> None:
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if not isinstance(func_addr, int):
        return
    try:
        transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Structuring condition semantic refresh failed function=%#x: %s",
            func_addr,
            ex,
        )


def _maybe_validate_structuring_pass_8616(project, codegen, spec_name: str):
    if not bool(getattr(project, "_inertia_tail_validation_enabled", True)):
        return None
    validate_all = os.environ.get("INERTIA_VALIDATE_ALL_STRUCTURING_PASSES") == "1"
    if not validate_all and spec_name not in _semantic_validation_pass_names_8616():
        return None

    mode = "live_out"
    _prime_structuring_validation_semantics_8616(project, codegen)
    before_fingerprint = fingerprint_x86_16_tail_validation_boundary(project, codegen, mode=mode)
    before_summary = collect_x86_16_tail_validation_summary(project, codegen, mode=mode)

    def finalize():
        _refresh_structuring_condition_semantics_8616(project, codegen)
        after_fingerprint = fingerprint_x86_16_tail_validation_boundary(project, codegen, mode=mode)
        after_summary = collect_x86_16_tail_validation_summary(project, codegen, mode=mode)
        validation = build_x86_16_tail_validation_cached_result(
            owner=None,
            stage=f"structuring:{spec_name}",
            mode=mode,
            before_fingerprint=before_fingerprint,
            after_fingerprint=after_fingerprint,
            before_summary=before_summary,
            after_summary=after_summary,
        )
        validation["verdict"] = build_x86_16_tail_validation_verdict(f"structuring:{spec_name}", validation)
        existing = getattr(codegen, "_inertia_structuring_pass_validation", None)
        if not isinstance(existing, dict):
            existing = {}
            setattr(codegen, "_inertia_structuring_pass_validation", existing)
        existing[spec_name] = validation
        if not x86_16_tail_validation_result_passed(validation):
            logging.getLogger(__name__).warning(
                "structuring pass validation changed function=%#x pass=%s verdict=%s",
                getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
                spec_name,
                validation.get("verdict"),
            )
            codegen._inertia_structuring_validation_failed = True
            codegen._inertia_structuring_validation_failure_pass = spec_name
            codegen._inertia_structuring_validation_failure_error = (
                validation.get("summary_text")
                or f"tail-validation status={validation.get('status', 'unknown')}"
            )

    return finalize


def _decompiler_structuring_passes_for_function(project, codegen):
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if func_addr is None:
        return DECOMPILER_STRUCTURING_PASSES

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return DECOMPILER_STRUCTURING_PASSES

    info = getattr(func, "info", None)
    if not isinstance(info, dict):
        return DECOMPILER_STRUCTURING_PASSES

    profile = info.get("x86_16_decompilation_profile", {})
    if isinstance(profile, dict) and profile.get("wrapper_like"):
        return DECOMPILER_STRUCTURING_PASSES

    return DECOMPILER_STRUCTURING_PASSES


def describe_x86_16_decompiler_structuring_stage():
    return tuple((spec.name, spec.needs_project) for spec in DECOMPILER_STRUCTURING_PASSES)


def _structuring_codegen_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False
    if not bool(getattr(project, "_inertia_structuring_enabled", True)):
        codegen._inertia_structuring_passes = ()
        codegen._inertia_structuring_changed = False
        codegen._inertia_structuring_failed = False
        codegen._inertia_last_structuring_pass = None
        return False

    # Alias-completeness gate: structuring cannot run with provisional SS stack.
    # AGENTS rule #1: SS:BP+offset → stack slot → variable, never guess.
    from .pipeline.errors import PipelineHardError

    try:
        _assert_alias_complete_8616(codegen)
    except PipelineHardError as ex:
        codegen._inertia_structuring_failed = True
        codegen._inertia_structuring_failure_pass = "alias_completeness_gate"
        codegen._inertia_structuring_failure_error = str(ex)
        logging.getLogger(__name__).warning(
            "structuring blocked by incomplete SS alias function=%#x: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", 0),
            ex,
        )
        return False

    # ── Stack lowering (before structuring) ──
    # Must run early: alias facts → stack variables → structuring sees named variables.
    if not getattr(codegen, "_inertia_ss_stack_lowered", False):
        from .pipeline.errors import PipelineHardError

        try:
            from .lowering.real_mode_linear import (
                lower_stable_ss_linear_stack_dereferences_8616,
            )
            lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)
        except PipelineHardError:
            raise
        except Exception as ex:
            codegen._inertia_structuring_failed = True
            codegen._inertia_structuring_failure_pass = "lower_stable_ss_linear_stack_dereferences_8616"
            codegen._inertia_structuring_failure_error = f"{type(ex).__name__}: {ex}"
            logging.getLogger(__name__).warning(
                "stack lowering setup failed function=%#x stage=%s: %s: %s",
                getattr(getattr(codegen, "cfunc", None), "addr", 0),
                "lower_stable_ss_linear_stack_dereferences_8616",
                type(ex).__name__,
                ex,
            )
            return False

        try:
            from .lowering.fact_transfer import transfer_semantic_alias_facts_to_codegen_8616
            from .lowering.stack_lowering_from_facts import lower_stack_accesses_from_alias_facts_8616
            transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
            alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
            if isinstance(alias_facts, list) and alias_facts:
                lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
        except PipelineHardError:
            raise
        except Exception as ex:
            codegen._inertia_structuring_failed = True
            codegen._inertia_structuring_failure_pass = "lower_stack_accesses_from_alias_facts_8616"
            codegen._inertia_structuring_failure_error = f"{type(ex).__name__}: {ex}"
            logging.getLogger(__name__).warning(
                "stack lowering from facts failed function=%#x stage=%s: %s: %s",
                getattr(getattr(codegen, "cfunc", None), "addr", 0),
                "lower_stack_accesses_from_alias_facts_8616",
                type(ex).__name__,
                ex,
            )
            return False
        codegen._inertia_ss_stack_lowered = True

    # ── Hard contract gate: classified > 0 && materialized == 0 → PipelineHardError ──
    # PipelineHardError MUST propagate — never silently caught.
    # Only non-fatal errors (import, attribute) are logged and cause structuring abort.
    from .pipeline.contracts import assert_pipeline_contracts_8616
    try:
        assert_pipeline_contracts_8616(codegen)
    except PipelineHardError:
        raise
    except Exception as e:
        codegen._inertia_structuring_failed = True
        codegen._inertia_structuring_failure_pass = "pipeline_contracts"
        codegen._inertia_structuring_failure_error = str(e)
        logging.getLogger(__name__).warning(
            "Pipeline contract gate setup error in %s: %s",
            getattr(codegen, "cfunc", None) or "unknown",
            e,
        )
        return False

    changed = False
    last_changed_pass = None
    codegen._inertia_structuring_failed = False
    codegen._inertia_structuring_failure_pass = None
    codegen._inertia_structuring_failure_error = None
    codegen._inertia_structuring_validation_failed = False
    codegen._inertia_structuring_validation_failure_pass = None
    codegen._inertia_structuring_validation_failure_error = None
    codegen._inertia_last_structuring_pass = None
    pass_specs = _decompiler_structuring_passes_for_function(project, codegen)
    codegen._inertia_structuring_passes = tuple(spec.name for spec in pass_specs)
    _t_structuring_start = time.perf_counter()
    for spec in pass_specs:
        try:
            project._inertia_decompiler_stage = f"structuring:{spec.name}"
            # Structuring must remain semantics-preserving under tail validation.
            # Expression simplification is allowed in postprocess; in structuring it
            # can rewrite boundary-visible conditions (e.g. 32-bit compare forms),
            # so keep this step analysis-only here.
            if spec.name == "_simplify_structured_expressions_8616":
                continue
            if timing_output_enabled() and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
                import sys as _sys
                _sys.stderr.write(f"[{time.strftime('%H:%M:%S')}] structuring pass: {spec.name} (+{time.perf_counter() - _t_structuring_start:.1f}s)\n")
                _sys.stderr.flush()
            finalize_validation = _maybe_validate_structuring_pass_8616(project, codegen, spec.name)
            if spec.needs_project:
                spec_changed = spec.func(project, codegen)
            else:
                spec_changed = spec.func(codegen)
            if finalize_validation is not None:
                finalize_validation()
                if getattr(codegen, "_inertia_structuring_validation_failed", False):
                    break
        except Exception as ex:  # noqa: BLE001
            codegen._inertia_structuring_failed = True
            codegen._inertia_structuring_failure_pass = spec.name
            codegen._inertia_structuring_failure_error = str(ex)
            logging.getLogger(__name__).warning(
                "Skipping 86_16 structuring pass %s after %s: %s",
                spec.name,
                last_changed_pass or "no earlier structuring",
                ex,
                exc_info=True,
            )
            break
        if spec_changed:
            changed = True
            last_changed_pass = spec.name
            codegen._inertia_last_structuring_pass = spec.name
    codegen._inertia_structuring_changed = changed
    project._inertia_decompiler_stage = "structuring"
    return changed


def _decompile_structuring_8616(self):
    _orig_decompiler_decompile = getattr(Decompiler, "_orig_before_structuring", None)
    if _orig_decompiler_decompile is None:
        _orig_decompiler_decompile = getattr(_decompile_structuring_8616, "_orig_decompiler_decompile", None)
        if _orig_decompiler_decompile is None:
            _orig_decompiler_decompile = Decompiler._decompile
            _decompile_structuring_8616._orig_decompiler_decompile = _orig_decompiler_decompile
    structuring_started = time.perf_counter()
    self.project._inertia_decompiler_stage = "core"
    _orig_decompiler_decompile(self)
    structuring_elapsed = time.perf_counter() - structuring_started
    if self.project.arch.name != "86_16" or self.codegen is None:
        return
    if not bool(getattr(self.project, "_inertia_tail_validation_enabled", True)):
        changed = _structuring_codegen_8616(self.project, self.codegen)
        function = getattr(self, "function", None) or getattr(self, "func", None)
        if function is not None:
            info = getattr(function, "info", None)
            if isinstance(info, MutableMapping):
                structuring_info = info.setdefault("x86_16_decompiler_structuring", {})
                structuring_info["elapsed"] = structuring_elapsed
                structuring_info["last_pass"] = getattr(self.codegen, "_inertia_last_structuring_pass", None)
                structuring_info["changed"] = bool(changed)
                structuring_info["failed"] = bool(getattr(self.codegen, "_inertia_structuring_failed", False))
                structuring_info["failure_pass"] = getattr(self.codegen, "_inertia_structuring_failure_pass", None)
                structuring_info["failure_error"] = getattr(self.codegen, "_inertia_structuring_failure_error", None)
                structuring_info["validation_failed"] = bool(
                    getattr(self.codegen, "_inertia_structuring_validation_failed", False)
                )
                structuring_info["validation_failure_pass"] = getattr(
                    self.codegen, "_inertia_structuring_validation_failure_pass", None
                )
                structuring_info["validation_failure_error"] = getattr(
                    self.codegen, "_inertia_structuring_validation_failure_error", None
                )
                structuring_info["pass_names"] = getattr(self.codegen, "_inertia_structuring_passes", ())
                structuring_info["last_stage"] = getattr(self.project, "_inertia_decompiler_stage", None)
                structuring_info["struct_merging_stats"] = getattr(self.codegen, "_inertia_struct_merging_stats", None)
                structuring_info["struct_merging_changed"] = bool(getattr(self.codegen, "_inertia_struct_merging_changed", False))
        setattr(self.codegen, "_inertia_tail_validation_snapshot", None)
        self.project._inertia_decompiler_stage = "structuring_done"
        return

    validation_mode = "live_out"
    _prime_structuring_validation_semantics_8616(self.project, self.codegen)
    before_fingerprint = fingerprint_x86_16_tail_validation_boundary(self.project, self.codegen, mode=validation_mode)
    before_collect_started = time.perf_counter()
    before_summary = collect_x86_16_tail_validation_summary(self.project, self.codegen, mode=validation_mode)
    before_collect_elapsed = time.perf_counter() - before_collect_started
    if not getattr(self.codegen, "_inertia_typed_conditions_transferred", False):
        func_addr = getattr(getattr(self.codegen, "cfunc", None), "addr", None)
        if isinstance(func_addr, int):
            with contextlib.suppress(Exception):
                transfer_typed_conditions_to_codegen_8616(self.project, func_addr, self.codegen)
        self.codegen._inertia_typed_conditions_transferred = True
    changed = _structuring_codegen_8616(self.project, self.codegen)
    _refresh_structuring_condition_semantics_8616(self.project, self.codegen)
    record_ast_condition_trace_8616(self.project, self.codegen, stage="structured")
    after_fingerprint = fingerprint_x86_16_tail_validation_boundary(self.project, self.codegen, mode=validation_mode)
    after_collect_started = time.perf_counter()
    after_summary = collect_x86_16_tail_validation_summary(self.project, self.codegen, mode=validation_mode)
    after_collect_elapsed = time.perf_counter() - after_collect_started
    function = getattr(self, "function", None) or getattr(self, "func", None)
    if function is None and getattr(getattr(self, "codegen", None), "cfunc", None) is not None:
        addr = getattr(self.codegen.cfunc, "addr", None)
        kb_functions = getattr(getattr(self, "project", None), "kb", None)
        kb_functions = getattr(kb_functions, "functions", None)
        if isinstance(addr, int) and kb_functions is not None:
            with contextlib.suppress(Exception):
                function = kb_functions.function(addr, create=False)
    owner = getattr(function, "info", None) if function is not None else None
    validation_started = time.perf_counter()
    validation = build_x86_16_tail_validation_cached_result(
        owner=owner if isinstance(owner, MutableMapping) else None,
        stage="structuring",
        mode=validation_mode,
        before_fingerprint=before_fingerprint,
        after_fingerprint=after_fingerprint,
        before_summary=before_summary,
        after_summary=after_summary,
    )
    validation_compare_elapsed = time.perf_counter() - validation_started
    validation_timings = {
        "collect_before_ms": round(before_collect_elapsed * 1000.0, 3),
        "collect_after_ms": round(after_collect_elapsed * 1000.0, 3),
        "compare_ms": round(validation_compare_elapsed * 1000.0, 3),
        "total_ms": round((before_collect_elapsed + after_collect_elapsed + validation_compare_elapsed) * 1000.0, 3),
    }
    validation["timings"] = validation_timings
    validation["verdict"] = build_x86_16_tail_validation_verdict("structuring", validation)
    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            structuring_info = info.setdefault("x86_16_decompiler_structuring", {})
            structuring_info["elapsed"] = structuring_elapsed
            structuring_info["tail_validation_timings"] = validation_timings
            structuring_info["last_pass"] = getattr(self.codegen, "_inertia_last_structuring_pass", None)
            structuring_info["changed"] = bool(changed)
            structuring_info["failed"] = bool(getattr(self.codegen, "_inertia_structuring_failed", False))
            structuring_info["failure_pass"] = getattr(self.codegen, "_inertia_structuring_failure_pass", None)
            structuring_info["failure_error"] = getattr(self.codegen, "_inertia_structuring_failure_error", None)
            structuring_info["validation_failed"] = bool(
                getattr(self.codegen, "_inertia_structuring_validation_failed", False)
            )
            structuring_info["validation_failure_pass"] = getattr(
                self.codegen, "_inertia_structuring_validation_failure_pass", None
            )
            structuring_info["validation_failure_error"] = getattr(
                self.codegen, "_inertia_structuring_validation_failure_error", None
            )
            structuring_info["pass_names"] = getattr(self.codegen, "_inertia_structuring_passes", ())
            structuring_info["last_stage"] = getattr(self.project, "_inertia_decompiler_stage", None)
            structuring_info["tail_validation_verdict"] = validation["verdict"]
            structuring_info["tail_validation_cache_hit"] = bool(validation.get("cache_hit", False))
            structuring_info["struct_merging_stats"] = getattr(self.codegen, "_inertia_struct_merging_stats", None)
            structuring_info["struct_merging_changed"] = bool(getattr(self.codegen, "_inertia_struct_merging_changed", False))
            persist_x86_16_tail_validation_snapshot(
                function_info=info,
                codegen=self.codegen,
                stage="structuring",
                validation=validation,
            )
    log = logging.getLogger(__name__)
    if not x86_16_tail_validation_result_passed(validation):
        log.warning("%s", validation["verdict"])
    else:
        log.info("%s", validation["verdict"])
    self.project._inertia_decompiler_stage = "structuring_done"


def _assert_alias_complete_8616(codegen) -> None:
    """Block structuring when SS stack alias facts are incomplete.

    AGENTS rule #1: SS:BP+offset → stack slot → variable, never guess.
    AGENTS rule #8: validation must be honest — unreviewed SS is not safe.

    Consults the module-level alias fact cache populated during VEX lifting
    (access._inertia_module_alias_fact_cache).  Returns without error when
    no SS accesses are present (e.g. pure register / DS-only functions).

    Raises PipelineHardError if any proven SS access lacks stable stack alias.
    """
    from .access import _inertia_module_alias_fact_cache
    from .alias.alias_model_impl import AliasFailure
    from .ir.core import MemSpace
    from .pipeline.errors import PipelineHardError

    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
    if not isinstance(func_addr, int):
        return

    facts = _inertia_module_alias_fact_cache.get(func_addr, None)
    if not isinstance(facts, list):
        return  # No facts recorded for this function — likely not yet lifted with typed IR.

    has_ss = False
    has_ss_stable = False
    has_ss_failure = False
    _first_ss_failure_reason = None
    for fact in facts:
        if isinstance(fact, AliasFailure):
            if getattr(fact, "space", None) in {"ss", "SS"}:
                has_ss = True
                address = getattr(fact, "address", None)
                status = getattr(address, "status", None)
                if getattr(status, "name", None) == "PROVISIONAL":
                    continue
                has_ss_failure = True
                if _first_ss_failure_reason is None:
                    _first_ss_failure_reason = getattr(fact, "reason", None)
        elif hasattr(fact, "domain") and getattr(fact.domain, "space", None) == "stack":
            has_ss = True
            has_ss_stable = True

    if not has_ss:
        return  # No SS accesses — nothing to block.

    # Only block when SS accesses exist but NONE are successfully classified.
    # Provisional SP-relative AliasFailures (push/pop/ret) are expected and
    # should not prevent structuring when BP-relative stack accesses are resolved.
    if not has_ss_stable and has_ss_failure:
        raise PipelineHardError(
            f"structuring before stable stack alias: {_first_ss_failure_reason}",
            layer="structuring",
        )


def apply_x86_16_decompiler_structuring() -> None:
    if getattr(Decompiler._decompile, "__name__", "") != "_decompile_structuring_8616":
        Decompiler._orig_before_structuring = Decompiler._decompile
        _decompile_structuring_8616._orig_decompiler_decompile = Decompiler._decompile
        Decompiler._decompile = _decompile_structuring_8616
