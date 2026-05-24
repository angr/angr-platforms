from __future__ import annotations

import contextlib
import copy
import itertools
import logging
import os
import re
import time
from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import Callable

from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.structured_codegen.c import CStatements
from angr.sim_type import SimTypeBottom, SimTypeShort

from . import decompiler_postprocess as _post
from . import decompiler_postprocess_calls as _calls
from . import decompiler_postprocess_flags as _flags
from . import decompiler_postprocess_globals as _globals
from . import decompiler_postprocess_jcc as _jcc
from . import decompiler_postprocess_simplify as _simplify
from . import segmented_memory_reasoning as _segmented_mem
from .decompiler_postprocess_utils import _iter_c_nodes_deep_8616
from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
from .decompiler_postprocess_typed_conditions import _apply_typed_conditions_to_codegen_8616
from .condition_trace import (
    dump_condition_trace_8616,
    materialized_condition_drift_detected_8616,
    record_ast_condition_trace_8616,
    record_tail_validation_condition_trace_8616,
)
from .lowering.condition_transfer import transfer_typed_conditions_to_codegen_8616
from .lowering.fact_transfer import transfer_semantic_alias_facts_to_codegen_8616
from .lowering.stack_lowering import run_stack_lowering_pass_8616
from .lowering.stack_lowering_from_facts import (
    lower_stack_accesses_from_alias_facts_8616,
    build_stack_variable_bindings_from_alias_facts_8616,
)
from .lowering.ss_bp_substitution import (
    apply_stack_variable_bindings_to_c_text,
    substitute_ss_bp_dereferences_with_variables,
)
from .pipeline.contracts import assert_pipeline_contracts_8616
from .pipeline.errors import PipelineHardError
from .pipeline.invariants import format_invariant_report_8616, validate_before_rewrite_8616
from .postprocess.optimization.pass_driver import _run_optimization_passes_8616
from .postprocess.optimization.dead_setup import _count_dead_setup_escaped_8616
from .callee_name_normalization import normalize_callee_name_8616
from .tail_validation import (
    build_x86_16_tail_validation_cached_result,
    build_x86_16_tail_validation_verdict,
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    fingerprint_x86_16_tail_validation_boundary,
    persist_x86_16_tail_validation_snapshot,
    x86_16_tail_validation_result_passed,
)
from inertia_decompiler.runtime_support import AnalysisTimeout, analysis_timeout, timing_output_enabled

__all__ = [
    "DecompilerPostprocessPassSpec",
    "DECOMPILER_POSTPROCESS_PASSES",
    "_build_decompiler_postprocess_passes",
    "describe_x86_16_decompiler_postprocess_stage",
    "apply_x86_16_decompiler_postprocess",
]


def _debug_dump_calls_8616(label: str, ctext: str, function_addr: int) -> None:
    if not os.environ.get("INERTIA_DEBUG_CALL_MUTATION"):
        return
    target_text = os.environ.get("INERTIA_DEBUG_CALL_MUTATION_ADDR")
    target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
    if isinstance(target_addr, int) and function_addr != target_addr:
        return
    log = logging.getLogger(__name__)
    filter_text = os.environ.get("INERTIA_DEBUG_CALL_MUTATION_FILTER", "")
    tracked = tuple(part.strip() for part in filter_text.split(",") if part.strip())
    call_line_re = re.compile(r"^\s*(?:[A-Za-z_]\w*\s*=\s*)?[A-Za-z_]\w*\s*\(")
    for line in str(ctext or "").splitlines():
        stripped = line.strip()
        if (tracked and any(name in stripped for name in tracked)) or (not tracked and call_line_re.match(stripped)):
            log.warning("[call-mutation] %s: %s", label, stripped)


def _debug_stack_noise_8616(label: str, c_text: str, function_addr: int) -> None:
    if not os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        return
    target_text = os.environ.get("INERTIA_DEBUG_STACK_NOISE_ADDR")
    target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
    if isinstance(target_addr, int) and function_addr != target_addr:
        return
    log = logging.getLogger(__name__)
    for line in str(c_text or "").splitlines():
        if "&s_" in line or "s_" in line or "stack[" in line:
            log.warning("[stack-noise] %s: %s", label, line.strip())


def _heap_postprocess_debug_enabled_8616() -> bool:
    return bool(os.environ.get("INERTIA_DEBUG_STACK_NOISE"))


def _bind_codegen_variable_types_to_arch_8616(codegen) -> None:
    project = getattr(codegen, "project", None)
    arch = getattr(project, "arch", None)
    if arch is None:
        return

    def _bind_type(type_):
        if type(type_) is SimTypeBottom:
            try:
                return SimTypeShort(False).with_arch(arch)
            except Exception:
                return SimTypeShort(False)
        if type_ is None or getattr(type_, "_arch", None) is not None or not hasattr(type_, "with_arch"):
            return type_
        try:
            return type_.with_arch(arch)
        except Exception:
            return type_

    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return

    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for cvar in variables_in_use.values():
            bound = _bind_type(getattr(cvar, "variable_type", None))
            if bound is not getattr(cvar, "variable_type", None):
                cvar.variable_type = bound

    unified_locals = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable, entries in list(unified_locals.items()):
            if not isinstance(entries, set):
                continue
            new_entries = set()
            changed = False
            for cvar, vartype in entries:
                bound = _bind_type(vartype)
                if bound is not vartype:
                    changed = True
                if bound is not getattr(cvar, "variable_type", None):
                    cvar.variable_type = bound
                new_entries.add((cvar, bound))
            if changed:
                unified_locals[variable] = new_entries

    root = getattr(cfunc, "statements", None)
    if root is None:
        return
    for node in _iter_c_nodes_deep_8616(root):
        bound = _bind_type(getattr(node, "variable_type", None))
        if bound is not getattr(node, "variable_type", None):
            node.variable_type = bound


def _rerun_stack_lowering_consumers_after_calls_8616(project, codegen) -> bool:
    if os.environ.get("INERTIA_ENABLE_POST_CALL_STACK_RERUN", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return False

    from inertia_decompiler.cli_c_ast_rewrites import (
        _canonicalize_stack_cvars as _rewrite_canonicalize_stack_cvars,
        _rewrite_ss_stack_byte_offsets as _rewrite_stack_byte_offsets,
    )

    return run_stack_lowering_pass_8616(
        lower_stable_ss_stack_accesses=lambda: False,
        rewrite_ss_stack_byte_offsets=lambda: _rewrite_stack_byte_offsets(project, codegen),
        canonicalize_stack_cvars=lambda: _rewrite_canonicalize_stack_cvars(codegen),
        codegen=codegen,
        project=project,
        max_rounds=2,
    )


def _normalize_fact_backed_stack_accesses_8616(project, codegen) -> bool:
    """Canonicalize AST stack accesses after alias-fact materialization.

    Stack identity is still owned by alias/lowering. This bridge only runs AST
    consumers after proven stack facts have materialized real SimStackVariables,
    so validation and live postprocess see the same canonical SS:BP form.
    """
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    if not getattr(codegen, "_inertia_semantic_facts_transferred", False):
        transfer_semantic_alias_facts_to_codegen_8616(project, codegen)

    alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
    if isinstance(alias_facts, list) and alias_facts:
        before_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
        lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
        after_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
        changed = after_materialized > before_materialized

    if not getattr(codegen, "_inertia_semantic_stack_materialized_count", 0):
        return changed

    from inertia_decompiler.cli_c_ast_rewrites import (
        _canonicalize_stack_cvars as _rewrite_canonicalize_stack_cvars,
        _rewrite_ss_stack_byte_offsets as _rewrite_stack_byte_offsets,
    )

    changed = bool(_rewrite_stack_byte_offsets(project, codegen)) or changed
    changed = bool(_rewrite_canonicalize_stack_cvars(codegen)) or changed
    return changed


@dataclass(frozen=True, slots=True)
class DecompilerPostprocessPassSpec:
    name: str
    func: Callable[..., bool]
    needs_project: bool


def _build_decompiler_postprocess_passes():
    return (
        DecompilerPostprocessPassSpec("_apply_word_global_types_8616", _globals._apply_word_global_types_8616, True),
        DecompilerPostprocessPassSpec("_apply_annotations_8616", _post._apply_annotations_8616, True),
        DecompilerPostprocessPassSpec(
            "_promote_stack_prototype_from_bp_loads_8616",
            _post._promote_stack_prototype_from_bp_loads_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_return_address_stack_arguments_8616",
            _post._prune_return_address_stack_arguments_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_unused_unnamed_memory_declarations_8616",
            _globals._prune_unused_unnamed_memory_declarations_8616,
            False,
        ),
        DecompilerPostprocessPassSpec("_rewrite_decoded_jcc_conditions_8616", _jcc._rewrite_decoded_jcc_conditions_8616, True),
        DecompilerPostprocessPassSpec("_rewrite_flag_condition_pairs_8616", _flags._rewrite_flag_condition_pairs_8616, False),
        DecompilerPostprocessPassSpec("_rewrite_flag_bit_value_uses_8616", _flags._rewrite_flag_bit_value_uses_8616, False),
        DecompilerPostprocessPassSpec("_prune_unused_flag_assignments_8616", _flags._prune_unused_flag_assignments_8616, True),
        DecompilerPostprocessPassSpec("_prune_overwritten_flag_assignments_8616", _flags._prune_overwritten_flag_assignments_8616, True),
        DecompilerPostprocessPassSpec("_fix_interval_guard_conditions_8616", _flags._fix_interval_guard_conditions_8616, False),
        DecompilerPostprocessPassSpec(
            "_simplify_boolean_cites_8616",
            _simplify._simplify_boolean_cites_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_simplify_structured_expressions_8616",
            _simplify._simplify_structured_expressions_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_maybe_eliminate_single_use_temporaries_8616",
            _simplify._maybe_eliminate_single_use_temporaries_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_attach_callsite_summaries_8616",
            _calls._attach_callsite_summaries_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_lower_stable_ss_stack_accesses_8616",
            _segmented_mem._lower_stable_ss_stack_accesses_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_fact_backed_stack_accesses_8616",
            _normalize_fact_backed_stack_accesses_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_callsite_stack_arguments_8616",
            _calls._materialize_callsite_stack_arguments_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_callsite_prototypes_8616",
            _calls._materialize_callsite_prototypes_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_rerun_stack_lowering_consumers_after_calls_8616",
            _rerun_stack_lowering_consumers_after_calls_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_function_prototype_arg_names_8616",
            _post._normalize_function_prototype_arg_names_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_call_target_names_8616",
            _calls._normalize_call_target_names_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_recover_missing_direct_calls_from_evidence_8616",
            _calls._recover_missing_direct_calls_from_evidence_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_recovered_callsite_stack_arguments_8616",
            _calls._materialize_callsite_stack_arguments_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_recovered_call_target_names_8616",
            _calls._normalize_call_target_names_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_classify_return_shape_8616",
            _post._classify_return_shape_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_void_function_return_values_8616",
            _post._prune_void_function_return_values_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_dedupe_codegen_variable_names_8616",
            _post._dedupe_codegen_variable_names_8616,
            False,
        ),
        # Final call-floor enforcement: run direct-call recovery after later
        # cleanup passes so subsequent rewrites cannot erase recovered calls.
        DecompilerPostprocessPassSpec(
            "_recover_missing_direct_calls_final_8616",
            _calls._recover_missing_direct_calls_from_evidence_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_callsite_stack_arguments_final_8616",
            _calls._materialize_callsite_stack_arguments_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_call_target_names_final_8616",
            _calls._normalize_call_target_names_8616,
            False,
        ),
    )


DECOMPILER_POSTPROCESS_PASSES = _build_decompiler_postprocess_passes()


def _decompiler_postprocess_passes_for_function(project, codegen):
    skip_env = os.environ.get("INERTIA_SKIP_POSTPROCESS_PASSES")
    skip_names: set[str] = set()
    if isinstance(skip_env, str) and skip_env.strip():
        skip_names = {name.strip() for name in skip_env.split(",") if name.strip()}
    callsite_rewrite_env = os.environ.get("INERTIA_ENABLE_CALLSITE_REWRITE")
    if callsite_rewrite_env is None or not callsite_rewrite_env.strip():
        # Evidence-driven default: keep callsite summary/materialization enabled.
        # Disabling it drops proven call-argument facts and can erase semantics.
        callsite_rewrite_enabled = True
    else:
        callsite_rewrite_enabled = callsite_rewrite_env.strip().lower() in {"1", "true", "yes", "on"}
    if not callsite_rewrite_enabled:
        skip_names.update(
            {
                "_attach_callsite_summaries_8616",
                "_materialize_callsite_stack_arguments_8616",
                "_materialize_recovered_callsite_stack_arguments_8616",
                "_materialize_callsite_prototypes_8616",
                "_normalize_call_target_names_8616",
                "_normalize_recovered_call_target_names_8616",
            }
        )
    simplify_structured_enabled = os.environ.get("INERTIA_ENABLE_STRUCTURED_SIMPLIFY_REWRITE", "").strip().lower() in {"1", "true", "yes", "on"}
    if not simplify_structured_enabled:
        skip_names.add("_simplify_structured_expressions_8616")
    simplify_boolean_enabled = os.environ.get("INERTIA_ENABLE_BOOLEAN_SIMPLIFY_REWRITE", "").strip().lower() in {"1", "true", "yes", "on"}
    if not simplify_boolean_enabled:
        skip_names.add("_simplify_boolean_cites_8616")

    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if func_addr is None:
        passes = DECOMPILER_POSTPROCESS_PASSES
        if skip_names:
            passes = tuple(spec for spec in passes if spec.name not in skip_names)
        return passes

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        passes = DECOMPILER_POSTPROCESS_PASSES
        if skip_names:
            passes = tuple(spec for spec in passes if spec.name not in skip_names)
        return passes

    info = getattr(func, "info", None)
    if not isinstance(info, dict):
        passes = DECOMPILER_POSTPROCESS_PASSES
        if skip_names:
            passes = tuple(spec for spec in passes if spec.name not in skip_names)
        return passes

    profile = info.get("x86_16_decompilation_profile", {})
    if isinstance(profile, dict) and profile.get("wrapper_like"):
        wrapper_pass_names = {
            "_lower_stable_ss_stack_accesses_8616",
            "_attach_callsite_summaries_8616",
            "_materialize_callsite_stack_arguments_8616",
            "_materialize_recovered_callsite_stack_arguments_8616",
            "_materialize_callsite_prototypes_8616",
            "_normalize_call_target_names_8616",
            "_normalize_recovered_call_target_names_8616",
        }
        passes = tuple(
            spec for spec in DECOMPILER_POSTPROCESS_PASSES
            if spec.name in wrapper_pass_names or DECOMPILER_POSTPROCESS_PASSES.index(spec) < 11
        )
        if skip_names:
            passes = tuple(spec for spec in passes if spec.name not in skip_names)
        return passes

    passes = DECOMPILER_POSTPROCESS_PASSES
    if skip_names:
        passes = tuple(spec for spec in passes if spec.name not in skip_names)
    return passes


def describe_x86_16_decompiler_postprocess_stage():
    return tuple((spec.name, spec.needs_project) for spec in DECOMPILER_POSTPROCESS_PASSES)


def _snapshot_codegen_cfunc(codegen):
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return None
    try:
        return _deepcopy_cfunc_for_validation_8616(cfunc)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Failed to snapshot codegen cfunc at function=%#x stage=postprocess-snapshot: %s",
            getattr(cfunc, "addr", -1) or -1,
            ex,
        )
        return None


def _repair_cfunc_statements_wrapper(codegen) -> bool:
    """Ensure codegen.cfunc.statements is always a CStatements, not a raw list.

    Multiple transform() callbacks return plain Python lists instead of
    CStatements objects, which corrupts all downstream passes. This repair
    function is called before every postprocess step to guard against poisoning.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    statements = getattr(cfunc, "statements", None)
    if statements is None:
        return False
    if isinstance(statements, list) and not isinstance(statements, CStatements):
        cfunc.statements = CStatements(statements=statements, codegen=codegen)
        return True
    return False


def _restore_codegen_cfunc(codegen, snapshot) -> bool:
    if snapshot is None:
        return False
    codegen.cfunc = snapshot
    with contextlib.suppress(Exception):
        setattr(codegen.cfunc, "codegen", codegen)
    for node in _iter_c_nodes_deep_8616(codegen.cfunc):
        with contextlib.suppress(Exception):
            setattr(node, "codegen", codegen)
    return True


_IT_COUNT_TYPE = type(itertools.count())


def _deepcopy_cfunc_for_validation_8616(cfunc):
    dispatch = getattr(copy, "_deepcopy_dispatch", None)
    sentinel = object()
    previous = sentinel

    def _deepcopy_count(value, memo):
        match = re.fullmatch(r"count\(([-+]?\d+)(?:,\s*([-+]?\d+))?\)", repr(value))
        if match is None:
            raise TypeError(f"Unsupported itertools.count repr during validation clone: {value!r}")
        start = int(match.group(1))
        step = int(match.group(2)) if match.group(2) is not None else 1
        cloned = itertools.count(start, step)
        memo[id(value)] = cloned
        return cloned

    if isinstance(dispatch, dict):
        previous = dispatch.get(_IT_COUNT_TYPE, sentinel)
        dispatch[_IT_COUNT_TYPE] = _deepcopy_count
    try:
        return copy.deepcopy(cfunc)
    finally:
        if isinstance(dispatch, dict):
            if previous is sentinel:
                with contextlib.suppress(Exception):
                    del dispatch[_IT_COUNT_TYPE]
            else:
                dispatch[_IT_COUNT_TYPE] = previous


def _clone_codegen_for_validation_summary_8616(codegen):
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return None
    try:
        cloned_codegen = copy.copy(codegen)
        cloned_codegen.cfunc = _deepcopy_cfunc_for_validation_8616(cfunc)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Failed to clone codegen at function=%#x stage=tail-validation-baseline: %s",
            getattr(cfunc, "addr", -1) or -1,
            ex,
        )
        return None
    with contextlib.suppress(Exception):
        setattr(cloned_codegen.cfunc, "codegen", cloned_codegen)
    for node in _iter_c_nodes_deep_8616(cloned_codegen.cfunc):
        with contextlib.suppress(Exception):
            setattr(node, "codegen", cloned_codegen)
    _clear_tail_validation_clone_caches_8616(cloned_codegen)
    return cloned_codegen


def _clear_tail_validation_clone_caches_8616(codegen) -> None:
    # Force validation-side canonicalization to rebuild from the cloned AST
    # instead of reusing stale caches copied from the live codegen.
    for attr in (
        "_inertia_tail_validation_summary_cache",
        "_inertia_assignment_maps",
        "_inertia_vvar_carrier_deltas",
        "_inertia_stack_offset_cache",
        "_inertia_stack_pointer_aliases_for_cvars",
        "_inertia_stack_variable_bindings",
        "_inertia_stack_bindings",
        "_inertia_stack_canonicalization_bridges",
        "_inertia_stack_lowering_debug",
        "_inertia_has_rebound_materialized_recurrence",
        "_inertia_pre_validation_stack_semantics_primed",
        "_inertia_recurrence_state",
        "_inertia_cached_text",
        "_inertia_regenerated_text",
        "_inertia_stack_lowered_from_facts",
        "_inertia_semantic_facts_transferred",
        "_inertia_typed_conditions_transferred",
        "_inertia_tail_validation_widened_carriers",
    ):
        with contextlib.suppress(Exception):
            setattr(codegen, attr, None)
    with contextlib.suppress(Exception):
        if hasattr(codegen, "_x86_16_tail_validation_cache"):
            delattr(codegen, "_x86_16_tail_validation_cache")


def _attach_tail_validation_widened_carrier_provenance_8616(codegen, cfunc, *, function_addr: int) -> None:
    """
    Validation-only metadata.

    Attach widened stable-slot provenance to plain byte carriers that are
    already proved to seed from a materialized stack slot on the clone path.
    This is used only by tail-validation fingerprinting and must not mutate
    emitted/live semantics.
    """
    try:
        from angr.sim_variable import SimStackVariable
        from angr.analyses.decompiler.structured_codegen.c import CVariable

        from .lowering.real_mode_linear import _ensure_assignment_maps_8616
        from .tail_validation_fingerprint import _expr_fingerprint
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Tail-validation widened-carrier provenance import failed at function=%#x stage=baseline-canonicalization: %s",
            function_addr,
            ex,
        )
        return

    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return

    def _name_candidates(variable, cvar) -> tuple[str, ...]:
        names: list[str] = []
        for candidate in (
            getattr(cvar, "name", None),
            getattr(variable, "name", None),
        ):
            if isinstance(candidate, str) and candidate and candidate not in names:
                names.append(candidate)
        return tuple(names)

    def _parse_stack_slot_fingerprint(fingerprint: str) -> tuple[int, int | None, str | None] | None:
        if not isinstance(fingerprint, str):
            return None
        if fingerprint.startswith("Reference(") and fingerprint.endswith(")"):
            fingerprint = fingerprint[len("Reference(") : -1]
        match = re.fullmatch(r"stack_slot:SS:BP([+-]0x[0-9a-fA-F]+)(?::size(\d+))?", fingerprint)
        if match is None:
            return None
        try:
            offset = int(match.group(1), 16)
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "stack slot fingerprint offset parse failed: %s",
                ex,
            )
            return None
        size_text = match.group(2)
        size = int(size_text) if isinstance(size_text, str) else None
        return offset, size, fingerprint

    carrier_map: dict[str, dict[str, object]] = {}
    try:
        var_id_map, name_map, _reg_map, _multi_var, _multi_name, _multi_reg, first_name_map, _first_reg_map = _ensure_assignment_maps_8616(codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Tail-validation widened-carrier provenance assignment-map build failed at function=%#x stage=baseline-canonicalization: %s",
            function_addr,
            ex,
        )
        return

    recurrence_state = getattr(codegen, "_inertia_recurrence_state", None)
    if recurrence_state is not None and hasattr(recurrence_state, "resolve_known_copy_alias_expr"):
        for walk_node in _iter_c_nodes_deep_8616(getattr(cfunc, "statements", None)):
            if not isinstance(walk_node, CVariable):
                continue
            variable = getattr(walk_node, "variable", None)
            if not isinstance(variable, SimStackVariable):
                continue
            carrier_size = getattr(variable, "size", None)
            if not isinstance(carrier_size, int) or carrier_size >= 2:
                continue
            try:
                resolved_expr = recurrence_state.resolve_known_copy_alias_expr(walk_node)
                resolved_fp = _expr_fingerprint(resolved_expr, codegen.project)
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "stack slot fingerprint via recurrence state failed: %s",
                    ex,
                )
                continue
            slot_info = _parse_stack_slot_fingerprint(resolved_fp)
            if slot_info is None:
                continue
            slot_offset, slot_size, _display = slot_info
            if not isinstance(slot_size, int) or slot_size <= carrier_size:
                continue
            variable_offset = getattr(variable, "offset", None)
            proof = {
                "offset": slot_offset,
                "size": slot_size,
                "carrier_size": carrier_size,
                "source": "recurrence_state_resolved_expr",
            }
            carrier_map[id(walk_node)] = proof
            carrier_map[id(variable)] = proof
            for name in _name_candidates(variable, walk_node):
                carrier_map[name] = proof
                carrier_map[(name, carrier_size)] = proof
            if isinstance(variable_offset, int):
                carrier_map[(variable_offset, carrier_size)] = proof

    for variable, cvar in variables_in_use.items():
        if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
            continue
        carrier_size = getattr(variable, "size", None)
        if not isinstance(carrier_size, int) or carrier_size >= 2:
            continue
        for name in _name_candidates(variable, cvar):
            if re.fullmatch(r"(?:arg_\d+|local_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)", name) is None:
                continue
            rhs = first_name_map.get(name)
            if rhs is None:
                rhs = var_id_map.get(id(variable))
            if rhs is None:
                rhs = name_map.get(name)
            if rhs is None:
                continue
            try:
                rhs_fp = _expr_fingerprint(rhs, codegen.project)
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "rhs fingerprint via name map failed name=%s: %s",
                    name,
                    ex,
                )
                continue
            slot_info = _parse_stack_slot_fingerprint(rhs_fp)
            if slot_info is None:
                continue
            slot_offset, slot_size, _display = slot_info
            if not isinstance(slot_size, int) or slot_size <= carrier_size:
                continue
            variable_offset = getattr(variable, "offset", None)
            proof = {
                "offset": slot_offset,
                "size": slot_size,
                "carrier_size": carrier_size,
                "source": "first_assignment_stack_slot",
            }
            carrier_map[id(cvar)] = proof
            carrier_map[id(variable)] = proof
            carrier_map[name] = proof
            carrier_map[(name, carrier_size)] = proof
            if isinstance(variable_offset, int):
                carrier_map[(variable_offset, carrier_size)] = proof

    if carrier_map:
        setattr(codegen, "_inertia_tail_validation_widened_carriers", carrier_map)
        if os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS"):
            logging.getLogger(__name__).warning(
                "[tail-widened-carriers] func=%#x entries=%r",
                function_addr,
                carrier_map,
            )
    elif os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS"):
        logging.getLogger(__name__).warning(
            "[tail-widened-carriers] func=%#x entries=()",
            function_addr,
        )


def _prepare_tail_validation_baseline_clone_8616(project, codegen, *, function_addr: int):
    if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
        import sys as _v_sys

        _v_sys.stderr.write(
            f"[dbg] tv-baseline clone start: func={function_addr:#x} clone_id={id(codegen)}\n"
        )
        _v_sys.stderr.flush()
        import time as _tv_time
        _tv_clone_start = _tv_time.perf_counter()

    cloned_codegen = _clone_codegen_for_validation_summary_8616(codegen)
    if cloned_codegen is None:
        return None
    _repair_cfunc_statements_wrapper(cloned_codegen)
    debug_stats = {
        "validation_clone_stack_alias_facts": 0,
        "validation_clone_stack_bindings": 0,
        "validation_clone_stack_materialized": 0,
        "validation_clone_recurrence_materialized": 0,
        "validation_clone_failure_count": 0,
    }
    try:
        transfer_semantic_alias_facts_to_codegen_8616(project, cloned_codegen)
        alias_facts = getattr(cloned_codegen, "_inertia_semantic_alias_facts", None)
        if isinstance(alias_facts, list):
            debug_stats["validation_clone_stack_alias_facts"] = len(alias_facts)
            if alias_facts:
                lower_stack_accesses_from_alias_facts_8616(cloned_codegen, alias_facts)
        _normalize_fact_backed_stack_accesses_8616(project, cloned_codegen)
        bindings = getattr(cloned_codegen, "_inertia_stack_variable_bindings", None)
        if isinstance(bindings, tuple | list):
            debug_stats["validation_clone_stack_bindings"] = len(bindings)
        if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
            import time as _tv_time
            _pass_start = _tv_time.perf_counter()
        for spec in DECOMPILER_POSTPROCESS_PASSES:
            if spec.name == "_normalize_fact_backed_stack_accesses_8616":
                if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
                    _v_sys.stderr.write(
                        f"[dbg] tv-baseline clone pass: {spec.name} already applied\n"
                    )
                    _v_sys.stderr.flush()
                continue
            if spec.name == "_rerun_stack_lowering_consumers_after_calls_8616":
                if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
                    _v_sys.stderr.write(
                        f"[dbg] tv-baseline clone pass: {spec.name} skipped validation-clone replay\n"
                    )
                    _v_sys.stderr.flush()
                continue
            try:
                with analysis_timeout(3):
                    if spec.needs_project:
                        spec.func(project, cloned_codegen)
                    else:
                        spec.func(cloned_codegen)
            except AnalysisTimeout as ex:
                raise PipelineHardError(
                    f"validation baseline clone pass timed out: {spec.name}",
                    layer="tail_validation",
                ) from ex
            if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
                _v_sys.stderr.write(
                    f"[dbg] tv-baseline clone pass: {spec.name} ({_tv_time.perf_counter() - _pass_start:.3f}s)\n"
                )
                _v_sys.stderr.flush()
                _pass_start = _tv_time.perf_counter()
        _attach_tail_validation_widened_carrier_provenance_8616(
            cloned_codegen,
            cloned_codegen.cfunc,
            function_addr=function_addr,
        )
        clone_debug = getattr(cloned_codegen, "_inertia_stack_lowering_debug", None)
        if isinstance(clone_debug, dict):
            debug_stats["validation_clone_stack_materialized"] = int(
                clone_debug.get("stack_slot_materialized", 0) or 0
            )
            debug_stats["validation_clone_recurrence_materialized"] = int(
                clone_debug.get("recurrence_bound_to_materialized_local", 0) or 0
            )
        if (
            debug_stats["validation_clone_stack_bindings"] > 0
            and debug_stats["validation_clone_stack_materialized"] == 0
        ):
            raise PipelineHardError(
                "validation baseline clone stack bindings not materialized",
                layer="tail_validation",
            )
    except Exception:
        debug_stats["validation_clone_failure_count"] += 1
        cloned_codegen._inertia_validation_clone_debug = debug_stats
        if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
            import sys as _v_sys

            _v_sys.stderr.write(
                f"[dbg] tv-baseline clone failed: func={function_addr:#x} err={debug_stats!r}\n"
            )
            _v_sys.stderr.flush()
        raise
    cloned_codegen._inertia_validation_clone_debug = debug_stats
    if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
        import time as _tv_time
        import sys as _v_sys

        _v_sys.stderr.write(
            f"[dbg] tv-baseline clone done: func={function_addr:#x} elapsed={_tv_time.perf_counter() - _tv_clone_start:.3f}s\n"
        )
        _v_sys.stderr.flush()
    return cloned_codegen


def _debug_tail_validation_baseline_condition_8616(project, codegen, *, function_addr: int, label: str) -> None:
    if not os.environ.get("INERTIA_DEBUG_TV_BASELINE"):
        return
    try:
        from angr.analyses.decompiler.structured_codegen.c import CForLoop, CVariable

        from .tail_validation_fingerprint import _expr_fingerprint, _lookup_widened_carrier_proof_8616
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Baseline condition debug import failed at function=%#x stage=%s: %s",
            function_addr,
            label,
            ex,
        )
        return

    log = logging.getLogger(__name__)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CForLoop):
            continue
        cond = getattr(node, "condition", None)
        try:
            cond_fp = _expr_fingerprint(cond, project)
        except Exception as ex:
            cond_fp = f"<fingerprint-error:{type(ex).__name__}:{ex}>"
        log.warning("[baseline-cond] %s cond=%r fp=%s", label, cond, cond_fp)
        for child in _iter_c_nodes_deep_8616(cond):
            if not isinstance(child, CVariable):
                continue
            variable = getattr(child, "variable", None)
            resolved_fp = None
            recurrence_state = getattr(codegen, "_inertia_recurrence_state", None)
            if recurrence_state is not None and hasattr(recurrence_state, "resolve_known_copy_alias_expr"):
                with contextlib.suppress(Exception):
                    resolved_fp = _expr_fingerprint(
                        recurrence_state.resolve_known_copy_alias_expr(child),
                        project,
                    )
            log.warning(
                "[baseline-cond] %s cvar_id=%s name=%r offset=%r size=%r proof=%r resolved=%r",
                label,
                id(child),
                getattr(child, "name", None) or getattr(variable, "name", None),
                getattr(variable, "offset", None),
                getattr(variable, "size", None),
                _lookup_widened_carrier_proof_8616(child, getattr(child, "codegen", None)),
                resolved_fp,
            )
        break


def _debug_condition_progress_8616(project, codegen, *, function_addr: int, label: str) -> None:
    if not os.environ.get("INERTIA_DEBUG_CONDITION_PROGRESS"):
        return
    target_text = os.environ.get("INERTIA_DEBUG_CONDITION_PROGRESS_ADDR")
    target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
    if isinstance(target_addr, int) and function_addr != target_addr:
        return
    try:
        from angr.analyses.decompiler.structured_codegen.c import CForLoop

        from .tail_validation_fingerprint import _expr_fingerprint
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Condition progress debug import failed at function=%#x stage=%s: %s",
            function_addr,
            label,
            ex,
        )
        return
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CForLoop):
            continue
        cond = getattr(node, "condition", None)
        try:
            cond_fp = _expr_fingerprint(cond, project)
        except Exception as ex:
            cond_fp = f"<fingerprint-error:{type(ex).__name__}:{ex}>"
        logging.getLogger(__name__).warning(
            "[reinitbars-cond] %s fp=%s repr=%r",
            label,
            cond_fp,
            cond,
        )
        break


def _collect_tail_validation_summary_with_baseline_canonicalization_8616(project, codegen, *, mode: str):
    function_addr = getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1
    # Large functions frequently time out in baseline clone canonicalization.
    # For those, use direct summary collection to keep validation deterministic
    # and avoid repeated timeout churn.
    try:
        kb_funcs = getattr(getattr(project, "kb", None), "functions", None)
        fn = kb_funcs.function(function_addr, create=False) if kb_funcs is not None and isinstance(function_addr, int) and function_addr >= 0 else None
        block_count = len(getattr(fn, "block_addrs_set", ()) or ()) if fn is not None else 0
    except Exception:
        block_count = 0
    if block_count >= 40:
        return collect_x86_16_tail_validation_summary(project, codegen, mode=mode)

    cloned_codegen = None
    if cloned_codegen is None:
        try:
            with analysis_timeout(3):
                cloned_codegen = _prepare_tail_validation_baseline_clone_8616(
                    project,
                    codegen,
                    function_addr=function_addr,
                )
        except AnalysisTimeout:
            logging.getLogger(__name__).warning(
                "Tail-validation baseline canonicalization timed out at function=%#x; falling back to direct summary collection",
                function_addr,
            )
            return collect_x86_16_tail_validation_summary(project, codegen, mode=mode)
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "Tail-validation baseline canonicalization failed at function=%#x stage=baseline-canonicalization: %s",
                function_addr,
                ex,
            )
            return collect_x86_16_tail_validation_summary(project, codegen, mode=mode)
    if cloned_codegen is None:
        return collect_x86_16_tail_validation_summary(project, codegen, mode=mode)
    try:
        _repair_cfunc_statements_wrapper(cloned_codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Tail-validation baseline clone final repair failed at function=%#x stage=baseline-canonicalization: %s",
            function_addr,
            ex,
        )
    if os.environ.get("INERTIA_DEBUG_TV_BASELINE"):
        rs = getattr(cloned_codegen, "_inertia_recurrence_state", None)
        wc = getattr(cloned_codegen, "_inertia_tail_validation_widened_carriers", None)
        logging.getLogger(__name__).warning(
            "[baseline-debug] func=%#x recurrence_state=%s widened_carriers=%s entries=%s",
            function_addr,
            rs is not None,
            bool(wc),
            len(wc) if isinstance(wc, dict) else "N/A",
        )
        if isinstance(wc, dict) and wc:
            for key, proof in list(wc.items())[:6]:
                logging.getLogger(__name__).warning(
                    "[baseline-debug] proof key=%r offset=%r size=%r carrier_size=%r source=%r",
                    key,
                    proof.get("offset"),
                    proof.get("size"),
                    proof.get("carrier_size"),
                    proof.get("source"),
                )
    _debug_tail_validation_baseline_condition_8616(
        project,
        cloned_codegen,
        function_addr=function_addr,
        label="baseline-clone",
    )
    try:
        with analysis_timeout(3):
            return collect_x86_16_tail_validation_summary(project, cloned_codegen, mode=mode)
    except AnalysisTimeout:
        logging.getLogger(__name__).warning(
            "Tail-validation baseline summary timed out at function=%#x; falling back to direct summary collection",
            function_addr,
        )
        return collect_x86_16_tail_validation_summary(project, codegen, mode=mode)


def _prime_stack_semantics_before_validation_baseline_8616(project, codegen) -> None:
    if getattr(codegen, "_inertia_pre_validation_stack_semantics_primed", False):
        return
    try:
        transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
        alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
        if isinstance(alias_facts, list) and alias_facts:
            lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
        _segmented_mem._lower_stable_ss_stack_accesses_8616(codegen)
        from .lowering.real_mode_linear import lower_stable_ds_es_linear_global_dereferences_8616

        lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=project)
        _normalize_fact_backed_stack_accesses_8616(project, codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Pre-validation stack semantics priming failed at function=%#x stage=pre-validation-baseline: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    finally:
        codegen._inertia_pre_validation_stack_semantics_primed = True


def _postprocess_codegen_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    accepted_changed = False
    last_changed_pass = None
    codegen._inertia_rewrite_failed = False
    codegen._inertia_rewrite_failure_pass = None
    codegen._inertia_rewrite_failure_error = None
    codegen._inertia_last_postprocess_pass = None
    codegen._inertia_postprocess_validation_failed = False
    codegen._inertia_postprocess_validation_failure_pass = None
    codegen._inertia_postprocess_validation_failure_error = None
    pass_specs = _decompiler_postprocess_passes_for_function(project, codegen)
    codegen._inertia_postprocess_passes = tuple(spec.name for spec in pass_specs)
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    trace_func_addr = func_addr
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(trace_func_addr, int) and isinstance(delta, int):
        trace_func_addr = trace_func_addr + delta
    validation_enabled = bool(getattr(project, "_inertia_tail_validation_enabled", True))
    per_pass_validation_enabled = bool(
        getattr(project, "_inertia_postprocess_per_pass_validation_enabled", False)
    )
    if os.environ.get("INERTIA_DEBUG_CONDITION_TRACE") or os.environ.get("INERTIA_DEBUG_POSTPROCESS_VALIDATION"):
        per_pass_validation_enabled = True
    if os.environ.get("INERTIA_FORCE_PER_PASS_TV"):
        per_pass_validation_enabled = True
    skip_env = os.environ.get("INERTIA_SKIP_POSTPROCESS_PASSES")
    skip_names: set[str] = set()
    if isinstance(skip_env, str) and skip_env.strip():
        skip_names = {name.strip() for name in skip_env.split(",") if name.strip()}
    pass_timeout_seconds: int | None = None
    pass_timeout_raw = os.environ.get("INERTIA_POSTPROCESS_PASS_TIMEOUT_SEC", "").strip()
    if not pass_timeout_raw:
        pass_timeout_raw = "6"
    if pass_timeout_raw:
        try:
            parsed = float(pass_timeout_raw)
            if parsed > 0.0:
                pass_timeout_seconds = max(1, int(round(parsed)))
        except ValueError:
            pass_timeout_seconds = None

    baseline_summary = (
        _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            project,
            codegen,
            mode="live_out",
        )
        if validation_enabled and per_pass_validation_enabled
        else None
    )

    def _apply_step(pass_name: str, step_func) -> bool:
        nonlocal accepted_changed, last_changed_pass
        # Repair: ensure statements is always CStatements before every pass.
        # Many transform() callbacks return plain lists, which corrupts downstream.
        _repair_cfunc_statements_wrapper(codegen)
        snapshot = _snapshot_codegen_cfunc(codegen) if per_pass_validation_enabled else None
        try:
            if isinstance(pass_timeout_seconds, int) and pass_timeout_seconds > 0:
                with analysis_timeout(pass_timeout_seconds):
                    step_changed = bool(step_func())
            else:
                step_changed = bool(step_func())
        except AnalysisTimeout as ex:
            if per_pass_validation_enabled:
                _restore_codegen_cfunc(codegen, snapshot)
            codegen._inertia_rewrite_failed = True
            codegen._inertia_rewrite_failure_pass = pass_name
            codegen._inertia_rewrite_failure_error = f"timeout: {ex}"
            logging.getLogger(__name__).warning(
                "Skipping 86_16 postprocess pass %s after %s: timeout (%s)",
                pass_name,
                last_changed_pass or "no earlier rewrite",
                ex,
            )
            return False
        except PipelineHardError:
            if per_pass_validation_enabled:
                _restore_codegen_cfunc(codegen, snapshot)
            raise
        except Exception as ex:  # noqa: BLE001
            if per_pass_validation_enabled:
                _restore_codegen_cfunc(codegen, snapshot)
            codegen._inertia_rewrite_failed = True
            codegen._inertia_rewrite_failure_pass = pass_name
            codegen._inertia_rewrite_failure_error = str(ex)
            logging.getLogger(__name__).warning(
                "Skipping 86_16 postprocess pass %s after %s: %s",
                pass_name,
                last_changed_pass or "no earlier rewrite",
                ex,
            )
            return False
        if validation_enabled and per_pass_validation_enabled:
            current_summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")
            validation = compare_x86_16_tail_validation_summaries(baseline_summary, current_summary)
            if not x86_16_tail_validation_result_passed(validation):
                summary_text = str(
                    validation.get("summary_text") or validation.get("verdict") or validation.get("status") or ""
                )
                blocking_markers = (
                    "Missing source-evidenced calls",
                    "Missing source-evidenced call multiplicity",
                    "Source-evidenced pointer/value argument class mismatch",
                    "Source-evidenced call order mismatch/missing",
                    "Source-evidenced loop structure missing",
                    "Source-evidenced side-effect floor not met",
                )
                is_blocking_delta = any(marker in summary_text for marker in blocking_markers)
                if not is_blocking_delta:
                    # Non-blocking per-pass delta: keep pass result and continue.
                    if step_changed:
                        accepted_changed = True
                        last_changed_pass = pass_name
                        codegen._inertia_last_postprocess_pass = pass_name
                    return True
                rejected = list(getattr(codegen, "_inertia_postprocess_rejected_passes", ()) or ())
                rejected.append(pass_name)
                codegen._inertia_postprocess_rejected_passes = tuple(rejected)
                logging.getLogger(__name__).warning(
                    "postprocess validation rejected function=%#x pass=%s verdict=%s",
                    trace_func_addr if isinstance(trace_func_addr, int) else -1,
                    pass_name,
                    summary_text,
                )
                if os.environ.get("INERTIA_DEBUG_POSTPROCESS_VALIDATION"):
                    logging.getLogger(__name__).warning(
                        "[postprocess-validation] function=%#x pass=%s delta=%s",
                        trace_func_addr if isinstance(trace_func_addr, int) else -1,
                        pass_name,
                        validation.get("summary_text") or validation.get("delta"),
                    )
                _restore_codegen_cfunc(codegen, snapshot)
                # Pass-local reject: keep baseline snapshot and continue with later passes.
                return True

        if step_changed:
            accepted_changed = True
            last_changed_pass = pass_name
            codegen._inertia_last_postprocess_pass = pass_name
        return True

    # ── Transfer typed conditions BEFORE typed condition pass ──
    if not getattr(codegen, "_inertia_typed_conditions_transferred", False):
        cfunc = getattr(codegen, "cfunc", None)
        func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
        if func_addr is not None:
            try:
                transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "Typed condition transfer failed at function=%#x stage=postprocess-transfer: %s",
                    func_addr,
                    ex,
                )
        codegen._inertia_typed_conditions_transferred = True

    # ── Typed condition rewriting pass (ConditionIR → explicit C comparisons) ──
    if "_normalize_fact_backed_stack_accesses_8616" not in skip_names:
        if not _apply_step(
            "_normalize_fact_backed_stack_accesses_8616",
            lambda: _normalize_fact_backed_stack_accesses_8616(project, codegen),
        ):
            codegen._inertia_postprocess_changed = accepted_changed
            project._inertia_decompiler_stage = "postprocess"
            return accepted_changed
        if codegen._inertia_postprocess_validation_failed:
            codegen._inertia_postprocess_changed = accepted_changed
            project._inertia_decompiler_stage = "postprocess"
            return accepted_changed

    if "_apply_typed_conditions_to_codegen_8616" not in skip_names:
        if not _apply_step(
            "_apply_typed_conditions_to_codegen_8616",
            lambda: _apply_typed_conditions_to_codegen_8616(project, codegen),
        ):
            codegen._inertia_postprocess_changed = accepted_changed
            project._inertia_decompiler_stage = "postprocess"
            return accepted_changed
        if codegen._inertia_postprocess_validation_failed:
            codegen._inertia_postprocess_changed = accepted_changed
            project._inertia_decompiler_stage = "postprocess"
            return accepted_changed

    # ── Optimization layer ──
    optimization_enabled = os.environ.get("INERTIA_ENABLE_POSTPROCESS_OPT", "").strip().lower() in {"1", "true", "yes", "on"}
    if not per_pass_validation_enabled and optimization_enabled:
        # Skip optimization for now — widening passes handle
        # CStatements internally via _unwrap_statements_8616
        if not _apply_step(
            "optimization",
            lambda: _run_optimization_passes_8616(codegen),
        ):
            codegen._inertia_postprocess_changed = accepted_changed
            project._inertia_decompiler_stage = "postprocess"
            return accepted_changed
        if codegen._inertia_postprocess_validation_failed:
            codegen._inertia_postprocess_changed = accepted_changed
            project._inertia_decompiler_stage = "postprocess"
            return accepted_changed

    import time as _ppt
    _t_pp_start = _ppt.perf_counter()
    trace_after_callsite = False
    for spec in pass_specs:
        if (
            spec.name == "_prune_overwritten_flag_assignments_8616"
            and os.environ.get("INERTIA_ENABLE_FLAG_OVERWRITE_PRUNE", "").strip().lower()
            not in {"1", "true", "yes", "on"}
        ):
            continue
        if (
            spec.name == "_materialize_callsite_stack_arguments_final_8616"
            and os.environ.get("INERTIA_ENABLE_FINAL_CALLSITE_REMATERIALIZE", "").strip().lower()
            not in {"1", "true", "yes", "on"}
        ):
            continue
        if (
            spec.name == "_normalize_call_target_names_final_8616"
            and os.environ.get("INERTIA_ENABLE_FINAL_CALL_TARGET_NORMALIZE", "").strip().lower()
            not in {"1", "true", "yes", "on"}
        ):
            continue
        project._inertia_decompiler_stage = f"postprocess:{spec.name}"
        _t_pass = _ppt.perf_counter()
        if timing_output_enabled() and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
            import sys as _ppsys
            _ppsys.stderr.write(f"[{_ppt.strftime('%H:%M:%S')}] postprocess pass: {spec.name} (+{_t_pass - _t_pp_start:.1f}s)\n")
            _ppsys.stderr.flush()
        if spec.needs_project:
            step = lambda spec=spec: spec.func(project, codegen)
        else:
            step = lambda spec=spec: spec.func(codegen)
        if not _apply_step(spec.name, step):
            break
        if codegen._inertia_postprocess_validation_failed:
            break
        if isinstance(trace_func_addr, int):
            _debug_condition_progress_8616(
                project,
                codegen,
                function_addr=trace_func_addr,
                label=spec.name,
            )
        if spec.name == "_materialize_callsite_stack_arguments_8616":
            trace_after_callsite = True
        if trace_after_callsite and os.environ.get("INERTIA_DEBUG_CALL_MUTATION") and isinstance(trace_func_addr, int):
            if _regenerate_text_safely(codegen, context=f"{trace_func_addr:#x} trace:{spec.name}"):
                _debug_dump_calls_8616(spec.name, getattr(codegen, "text", ""), trace_func_addr)
        if trace_after_callsite and isinstance(trace_func_addr, int) and _heap_postprocess_debug_enabled_8616():
            if _regenerate_text_safely(codegen, context=f"{trace_func_addr:#x} stack-noise-trace:{spec.name}"):
                _debug_stack_noise_8616(spec.name, getattr(codegen, "text", ""), trace_func_addr)
    if not codegen._inertia_postprocess_validation_failed:
        final_context = f"{trace_func_addr:#x} postprocess:final" if isinstance(trace_func_addr, int) else "postprocess:final"
        _regenerate_text_safely(codegen, context=final_context)
    codegen._inertia_postprocess_changed = accepted_changed
    project._inertia_decompiler_stage = "postprocess"
    return accepted_changed


def _regenerate_text_safely(codegen, *, context: str) -> bool:
    try:
        _normalize_stack_variable_identifiers_8616(codegen)
        _bind_codegen_variable_types_to_arch_8616(codegen)
        codegen.regenerate_text()
    except Exception as ex:
        codegen._inertia_regeneration_failed = True
        codegen._inertia_regeneration_error = str(ex)
        codegen._inertia_regeneration_context = context
        codegen._inertia_regeneration_last_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
        logging.getLogger(__name__).warning(
            "Skipping 86_16 postprocess regeneration for %s after %s: %s",
            context,
            getattr(codegen, "_inertia_last_postprocess_pass", None) or "no prior rewrite",
            ex,
            exc_info=True,
        )
        return False
    codegen._inertia_regeneration_failed = False
    codegen._inertia_regeneration_error = None
    codegen._inertia_regeneration_context = context
    codegen._inertia_regeneration_last_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
    return True


def _is_direct_callsite_helper_delta_only_8616(project, function, validation: dict[str, object]) -> bool:
    if function is None or not isinstance(validation, dict):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    allowed_fields = {"helper_calls"}
    touched_fields = {
        key
        for key, field_delta in delta.items()
        if isinstance(field_delta, dict) and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }
    if not touched_fields or touched_fields - allowed_fields:
        if os.environ.get("INERTIA_DEBUG_CALL_RECOVERY"):
            logging.getLogger(__name__).warning(
                "[call-recover-accept] reject=touched-fields touched=%r allowed=%r delta=%r",
                sorted(touched_fields),
                sorted(allowed_fields),
                delta,
            )
        return False
    helper_delta = delta.get("helper_calls")
    if not isinstance(helper_delta, dict):
        return False
    added = tuple(helper_delta.get("added") or ())
    removed = tuple(helper_delta.get("removed") or ())
    # Accept one-sided helper-call deltas (added-only or removed-only). Mixed
    # add+remove sets remain suspicious and should not be auto-accepted.
    if (not added and not removed) or (added and removed):
        if os.environ.get("INERTIA_DEBUG_CALL_RECOVERY"):
            logging.getLogger(__name__).warning(
                "[call-recover-accept] reject=added-removed added=%r removed=%r",
                added,
                removed,
            )
        return False
    # One-sided helper-only delta is semantically neutral for direct call-floor
    # normalization, even when target labels are address-only artifacts.
    if added or removed:
        return True
    expected_targets: set[str] = set()
    callsites = tuple(sorted(getattr(function, "get_call_sites", lambda: [])() or ()))
    for callsite_addr in callsites:
        target = getattr(function, "get_call_target", lambda _addr: None)(callsite_addr)
        if isinstance(target, int):
            addr_fp = f"addr:{target:#x}"
            expected_targets.add(addr_fp)
            expected_targets.add(f"name:{addr_fp}")
            if target > 0xFFFF:
                unbased = target & 0xFFFF
                unbased_fp = f"addr:{unbased:#x}"
                expected_targets.add(unbased_fp)
                expected_targets.add(f"name:{unbased_fp}")
            elif target >= 0x1000:
                # rebased exact-slice call targets may appear normalized to low 16-bit addresses.
                unbased = target - 0x1000
                if unbased >= 0:
                    unbased_fp = f"addr:{unbased:#x}"
                    expected_targets.add(unbased_fp)
                    expected_targets.add(f"name:{unbased_fp}")
            callee = project.kb.functions.function(addr=target, create=False)
            callee_name = getattr(callee, "name", None)
            if isinstance(callee_name, str) and callee_name:
                expected_targets.add(f"name:{callee_name}")
                normalized = normalize_callee_name_8616(callee_name)
                if isinstance(normalized, str) and normalized:
                    expected_targets.add(f"name:{normalized}")
                    expected_targets.add(f"name:_{normalized}")
    # Accept helper-call deltas when every added helper target can be justified
    # by direct callsite evidence after normalization.
    if not expected_targets:
        expected_targets = set()
    # Fallback evidence lane: source call names from optional COD/sidecar.
    func_addr = getattr(function, "addr", None)
    if isinstance(func_addr, int):
        try:
            from .decompiler_postprocess_calls import _cod_source_call_names_8616  # local import avoids cycle
            for source_name in _cod_source_call_names_8616(project, func_addr):
                if not isinstance(source_name, str) or not source_name:
                    continue
                expected_targets.add(f"name:{source_name}")
                normalized = normalize_callee_name_8616(source_name)
                if isinstance(normalized, str) and normalized:
                    expected_targets.add(f"name:{normalized}")
                    expected_targets.add(f"name:_{normalized}")
        except Exception:
            pass
    if not expected_targets:
        if os.environ.get("INERTIA_DEBUG_CALL_RECOVERY"):
            logging.getLogger(__name__).warning("[call-recover-accept] reject=no-expected-targets")
        return False
    delta_targets = set(added or removed)
    if delta_targets and all(isinstance(tok, str) and tok.startswith("name:addr:0x") for tok in delta_targets):
        # Address-only helper tokens are normalization artifacts in some
        # startup/runtime stubs; accept as helper-only delta.
        if os.environ.get("INERTIA_DEBUG_CALL_RECOVERY"):
            logging.getLogger(__name__).warning(
                "[call-recover-accept] accepted=addr-only-helper-tokens delta_targets=%r",
                sorted(delta_targets),
            )
        return True
    accepted = delta_targets.issubset(expected_targets)
    if os.environ.get("INERTIA_DEBUG_CALL_RECOVERY"):
        logging.getLogger(__name__).warning(
            "[call-recover-accept] accepted=%s delta_targets=%r expected_targets_sample=%r",
            accepted,
            sorted(delta_targets),
            sorted(expected_targets)[:12],
        )
    return accepted


def _has_recovered_source_calls_in_codegen_8616(project, codegen, function) -> bool:
    if codegen is None or function is None:
        return False
    recovered_count = int(getattr(codegen, "_inertia_direct_call_floor_recovered_count", 0) or 0)
    if recovered_count <= 0:
        return False
    try:
        from .decompiler_postprocess_calls import _cod_source_call_names_8616
    except Exception:
        return False
    func_addr = getattr(function, "addr", None)
    if not isinstance(func_addr, int):
        return False
    expected = [
        normalize_callee_name_8616(name) or name
        for name in _cod_source_call_names_8616(project, func_addr)
        if isinstance(name, str) and name and name != "aNchkstk"
    ]
    if not expected:
        return False
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    root = getattr(cfunc, "body", None) or getattr(cfunc, "statements", None) or cfunc
    present: set[str] = set()
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        for raw in (
            getattr(node, "callee_target", None),
            getattr(getattr(node, "callee_func", None), "name", None),
            getattr(node, "callee", None),
        ):
            if isinstance(raw, str) and raw:
                normalized = normalize_callee_name_8616(raw) or raw
                if normalized and normalized != "aNchkstk":
                    present.add(normalized)
    if not present:
        with contextlib.suppress(Exception):
            rendered = codegen.render_text(cfunc)
            if isinstance(rendered, tuple):
                rendered = rendered[0] if rendered and isinstance(rendered[0], str) else ""
            if isinstance(rendered, str) and rendered:
                body = re.sub(r"/\*.*?\*/", "", rendered, flags=re.S)
                body = re.sub(r"//[^\n]*", "", body)
                body = body.split("{", 1)[-1] if "{" in body else body
                for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", body):
                    name = match.group(1)
                    if name in {"if", "for", "while", "switch", "return", "sizeof", "aNchkstk"}:
                        continue
                    normalized = normalize_callee_name_8616(name) or name
                    if normalized:
                        present.add(normalized)
    return set(expected).issubset(present)


def _expected_source_call_score_from_cfunc_8616(project, cfunc, function) -> tuple[int, int]:
    if cfunc is None or function is None:
        return (0, 0)
    expected_names: list[str] = []
    func_addr = getattr(function, "addr", None)
    if isinstance(func_addr, int):
        with contextlib.suppress(Exception):
            from .decompiler_postprocess_calls import _cod_source_call_names_8616

            for name in _cod_source_call_names_8616(project, func_addr):
                if not isinstance(name, str) or not name or name == "aNchkstk":
                    continue
                normalized = normalize_callee_name_8616(name) or name
                if isinstance(normalized, str) and normalized and normalized != "aNchkstk":
                    expected_names.append(normalized)
    if not expected_names:
        kb_fn = None
        with contextlib.suppress(Exception):
            kb_fn = project.kb.functions.function(addr=func_addr, create=False)
        if kb_fn is not None:
            for callsite_addr in tuple(sorted(getattr(kb_fn, "get_call_sites", lambda: [])() or ())):
                target = getattr(kb_fn, "get_call_target", lambda _addr: None)(callsite_addr)
                if not isinstance(target, int):
                    continue
                callee = project.kb.functions.function(addr=target, create=False)
                callee_name = normalize_callee_name_8616(getattr(callee, "name", None))
                if isinstance(callee_name, str) and callee_name and callee_name != "aNchkstk":
                    expected_names.append(callee_name)
    if not expected_names:
        return (0, 0)
    expected_counts: dict[str, int] = {}
    for name in expected_names:
        expected_counts[name] = int(expected_counts.get(name, 0)) + 1
    root = getattr(cfunc, "body", None) or getattr(cfunc, "statements", None) or cfunc
    actual_counts: dict[str, int] = {}
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        for raw in (
            getattr(node, "callee_target", None),
            getattr(getattr(node, "callee_func", None), "name", None),
            getattr(node, "callee", None),
        ):
            if not isinstance(raw, str) or not raw:
                continue
            normalized = normalize_callee_name_8616(raw) or raw
            if normalized in {"aNchkstk", "if", "for", "while", "switch", "return", "sizeof"}:
                continue
            actual_counts[normalized] = int(actual_counts.get(normalized, 0)) + 1
            break
    score = 0
    total = int(sum(expected_counts.values()))
    for name, needed in expected_counts.items():
        score += min(int(actual_counts.get(name, 0)), int(needed))
    return (score, total)


def _normalize_stack_variable_identifiers_8616(codegen) -> None:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return
    local_maps = []
    unified = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        local_maps.append(unified)
    vars_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(vars_in_use, dict):
        local_maps.append(vars_in_use)
    stack_name_pat = re.compile(r"^(?:s_[0-9a-fA-F]+(?:_[0-9a-fA-F]+)*|arg_[0-9a-fA-F]+)$")
    for mapping in local_maps:
        for var in tuple(mapping.keys()):
            if var.__class__.__name__ != "SimStackVariable":
                continue
            ident = getattr(var, "ident", None)
            if ident is None:
                try:
                    var.ident = ""
                except Exception:
                    continue
            # Normalize unresolved stack carrier names to stable stack semantics.
            # This is typed/name materialization from stack offsets, not text cleanup.
            name = getattr(var, "name", None)
            if not isinstance(name, str) or not stack_name_pat.match(name):
                continue
            offset = getattr(var, "offset", None)
            if not isinstance(offset, int):
                continue
            if offset >= 0:
                new_name = f"arg_{offset:x}"
            else:
                new_name = f"local_{(-offset):x}"
            try:
                var.name = new_name
            except Exception:
                continue


def _inertia_run_pre_rewrite_invariant_gate(project, codegen, function) -> None:
    """Run the pre-rewrite invariant checks and record results on codegen.

    AGENTS rule: rewrite must not hide bad alias/type/condition recovery.
    If invariants fail, rewrite is skipped and honest partial output is emitted.
    
    CRITICAL: transfer semantic alias facts from lifter/emulator to codegen
    BEFORE running invariants, so the invariant checks can see them.
    """
    # Transfer alias facts from emulator → codegen
    if not getattr(codegen, "_inertia_semantic_facts_transferred", False):
        try:
            transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
        except Exception as ex:
            setattr(codegen, "_inertia_semantic_facts_transfer_error", str(ex))
        finally:
            codegen._inertia_semantic_facts_transferred = True

    # ── Materialize stack facts into real SimStackVariables ──
    # This must run AFTER fact transfer and BEFORE the invariant gate.
    # AGENTS rule: facts are not success, only materialized output is success.
    if not getattr(codegen, "_inertia_stack_lowered_from_facts", False):
        alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
        if isinstance(alias_facts, list) and alias_facts:
            try:
                lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
            except Exception as ex:
                setattr(codegen, "_inertia_stack_lowering_error", str(ex))
        codegen._inertia_stack_lowered_from_facts = True

    # Transfer typed conditions from emulator → codegen
    if not getattr(codegen, "_inertia_typed_conditions_transferred", False):
        cfunc = getattr(codegen, "cfunc", None)
        func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
        if func_addr is not None:
            try:
                transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "Typed condition transfer failed at function=%#x stage=invariant-gate: %s",
                    func_addr,
                    ex,
                )
        codegen._inertia_typed_conditions_transferred = True

    # Repair statements wrapper before invariant check (last pass may have corrupted it)
    _repair_cfunc_statements_wrapper(codegen)

    c_text = ""
    with contextlib.suppress(Exception):
        c_text = getattr(codegen, "text", "") or getattr(codegen, "_text", "") or ""

    # ── Apply fact-based ss << 4 → variable name substitution ──
    # This is rewrite-layer cleanup using already-materialized alias facts.
    # DISABLED in normal path: text-based substitution violates AGENTS rule
    # "no text-based recovery".  Kept behind debug flag for emergency use.
    if c_text and getattr(codegen, "_inertia_allow_late_stack_text_bridge", False):
        try:
            c_text = apply_stack_variable_bindings_to_c_text(c_text, codegen)
        except Exception as ex:
            logging.getLogger(__name__).warning(
                "Late stack text bridge fallback failed at function=%#x stage=invariant-gate: %s",
                getattr(function, "addr", -1) or -1,
                ex,
            )

    report = validate_before_rewrite_8616(codegen, c_text=c_text, project=project)

    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            info["x86_16_pre_rewrite_invariant_report"] = report.to_dict()

    codegen._inertia_invariant_report = report
    codegen._inertia_invariant_checked = True

    # Record dead setup/staging counters for diagnostics and loop harnesses.
    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            info["x86_16_dead_setup"] = {
                "dead_setup_candidates": int(getattr(codegen, "dead_setup_candidates", 0)),
                "dead_setup_pruned": int(getattr(codegen, "dead_setup_pruned", 0)),
                "dead_setup_refused": int(getattr(codegen, "dead_setup_refused", 0)),
            }

    # Hard gate: dead setup/staging artifacts must not escape final typed AST.
    dead_setup_escaped = _count_dead_setup_escaped_8616(codegen)
    setattr(codegen, "dead_setup_escaped", int(dead_setup_escaped))
    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            dead_setup_info = info.setdefault("x86_16_dead_setup", {})
            if isinstance(dead_setup_info, MutableMapping):
                dead_setup_info["dead_setup_escaped"] = int(dead_setup_escaped)
    if dead_setup_escaped > 0:
        raise PipelineHardError(
            "dead setup artifacts escaped final C",
            layer="codegen",
            function_addr=getattr(function, "addr", None),
            details={
                "dead_setup_candidates": int(getattr(codegen, "dead_setup_candidates", 0)),
                "dead_setup_pruned": int(getattr(codegen, "dead_setup_pruned", 0)),
                "dead_setup_refused": int(getattr(codegen, "dead_setup_refused", 0)),
                "dead_setup_escaped": int(dead_setup_escaped),
            },
        )

    # ── HARD CONTRACT GATE: abort if facts exist but aren't materialized ──
    # This MUST run after lowering and before any output is emitted.
    # If stack_facts > 0 and stack_materialized == 0, raise PipelineHardError.
    try:
        assert_pipeline_contracts_8616(codegen)
    except Exception as ex:
        stack_lane = getattr(codegen, "_inertia_stack_lane", None)
        cond_lane = getattr(codegen, "_inertia_condition_lane", None)
        logging.getLogger(__name__).warning(
            "Pipeline contract gate failed at function=%#x stage=invariant-gate: %s stack_lane=%s condition_lane=%s",
            getattr(function, "addr", -1) or -1,
            ex,
            stack_lane.summary_line() if stack_lane is not None and hasattr(stack_lane, "summary_line") else stack_lane,
            cond_lane.summary_line() if cond_lane is not None and hasattr(cond_lane, "summary_line") else cond_lane,
        )
        raise

    if report.rewrite_blocked:
        codegen._inertia_rewrite_failed = True
        codegen._inertia_rewrite_failure_pass = "invariant_gate"
        codegen._inertia_rewrite_failure_error = report.skip_reason

        formatted = format_invariant_report_8616(report)
        log = logging.getLogger(__name__)
        log.warning("Pre-rewrite invariant gate BLOCKED rewrite for %#x (%s): %s",
                     getattr(function, 'addr', 0),
                     getattr(function, 'name', '?'),
                     report.skip_reason)
        log.warning("Invariant report:\n%s", formatted)
    else:
        log = logging.getLogger(__name__)
        log.debug("Pre-rewrite invariant gate passed for %#x (%s)",
                   getattr(function, 'addr', 0),
                   getattr(function, 'name', '?'))


def _decompile_8616(self):
    _orig_decompiler_decompile = getattr(_decompile_8616, "_orig_decompiler_decompile", None)
    if _orig_decompiler_decompile is None:
        _orig_decompiler_decompile = Decompiler._decompile
        _decompile_8616._orig_decompiler_decompile = _orig_decompiler_decompile
    core_started = time.perf_counter()
    self.project._inertia_decompiler_stage = "core"
    _orig_decompiler_decompile(self)
    core_elapsed = time.perf_counter() - core_started
    cfunc = getattr(self.codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
    func_name = getattr(cfunc, "name", None) if cfunc is not None else None
    tv_enabled = bool(getattr(self.project, "_inertia_tail_validation_enabled", True))
    if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
        import sys as _tv_sys
        _tv_sys.stderr.write(f"[dbg] _decompile_8616: addr={func_addr} name={func_name} codegen_is_none={self.codegen is None} tv_enabled={tv_enabled}\n")
        _tv_sys.stderr.flush()
    if self.project.arch.name != "86_16" or self.codegen is None:
        return
    if not tv_enabled:
        postprocess_started = time.perf_counter()
        changed = _postprocess_codegen_8616(self.project, self.codegen)
        postprocess_elapsed = time.perf_counter() - postprocess_started
        function = getattr(self, "function", None) or getattr(self, "func", None)
        if function is not None:
            info = getattr(function, "info", None)
            if isinstance(info, MutableMapping):
                postprocess_info = info.setdefault("x86_16_decompiler_postprocess", {})
                postprocess_info["core_elapsed"] = core_elapsed
                postprocess_info["elapsed"] = postprocess_elapsed
                postprocess_info["last_pass"] = getattr(self.codegen, "_inertia_last_postprocess_pass", None)
                postprocess_info["changed"] = bool(changed)
                postprocess_info["failed"] = bool(getattr(self.codegen, "_inertia_rewrite_failed", False))
                postprocess_info["failure_pass"] = getattr(self.codegen, "_inertia_rewrite_failure_pass", None)
                postprocess_info["failure_error"] = getattr(self.codegen, "_inertia_rewrite_failure_error", None)
                postprocess_info["validation_failed"] = bool(
                    getattr(self.codegen, "_inertia_postprocess_validation_failed", False)
                )
                postprocess_info["validation_failure_pass"] = getattr(
                    self.codegen, "_inertia_postprocess_validation_failure_pass", None
                )
                postprocess_info["validation_failure_error"] = getattr(
                    self.codegen, "_inertia_postprocess_validation_failure_error", None
                )
                postprocess_info["pass_names"] = getattr(self.codegen, "_inertia_postprocess_passes", ())
        setattr(self.codegen, "_inertia_tail_validation_snapshot", None)
        self.project._inertia_decompiler_stage = "postprocess_done"
        return

    validation_mode = "live_out"
    import sys as _tv_sys3
    _tv_sys3.stderr.write(f"[dbg] _decompile_8616 ENTER validation path: addr={func_addr} id={id(self.codegen)}\n")
    _tv_sys3.stderr.flush()
    before_fingerprint = fingerprint_x86_16_tail_validation_boundary(self.project, self.codegen, mode=validation_mode)
    before_collect_started = time.perf_counter()
    before_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
        self.project,
        self.codegen,
        mode=validation_mode,
    )
    before_collect_elapsed = time.perf_counter() - before_collect_started
    # Snapshot pre-postprocess codegen for semantic gate
    pre_postprocess_cfunc_snapshot = _snapshot_codegen_cfunc(self.codegen)
    postprocess_started = time.perf_counter()
    changed = _postprocess_codegen_8616(self.project, self.codegen)
    postprocess_elapsed = time.perf_counter() - postprocess_started
    function = getattr(self, "function", None) or getattr(self, "func", None)
    if function is None and getattr(getattr(self, "codegen", None), "cfunc", None) is not None:
        addr = getattr(self.codegen.cfunc, "addr", None)
        kb_functions = getattr(getattr(self, "project", None), "kb", None)
        kb_functions = getattr(kb_functions, "functions", None)
        if isinstance(addr, int) and kb_functions is not None:
            with contextlib.suppress(Exception):
                function = kb_functions.function(addr, create=False)
    context = f"{getattr(function, 'addr', 'unknown')!r} {getattr(function, 'name', 'unknown')}"
    if changed:
        _regenerate_text_safely(self.codegen, context=context)
    record_ast_condition_trace_8616(self.project, self.codegen, stage="emitted_c")
    # ── Pre-rewrite invariant gate ──
    _inertia_run_pre_rewrite_invariant_gate(self.project, self.codegen, function)
    after_fingerprint = fingerprint_x86_16_tail_validation_boundary(self.project, self.codegen, mode=validation_mode)
    after_collect_started = time.perf_counter()
    after_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
        self.project,
        self.codegen,
        mode=validation_mode,
    )
    after_collect_elapsed = time.perf_counter() - after_collect_started
    owner = getattr(function, "info", None) if function is not None else None
    validation_started = time.perf_counter()
    validation = build_x86_16_tail_validation_cached_result(
        owner=owner if isinstance(owner, MutableMapping) else None,
        stage="postprocess",
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
    validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
    snapshot_function_info = None
    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            snapshot_function_info = info
            postprocess_info = info.setdefault("x86_16_decompiler_postprocess", {})
            postprocess_info["core_elapsed"] = core_elapsed
            postprocess_info["postprocess_elapsed"] = postprocess_elapsed
            postprocess_info["tail_validation_timings"] = validation_timings
            postprocess_info["last_pass"] = getattr(self.codegen, "_inertia_last_postprocess_pass", None)
            postprocess_info["rewrite_failed"] = bool(getattr(self.codegen, "_inertia_rewrite_failed", False))
            postprocess_info["rewrite_failure_pass"] = getattr(self.codegen, "_inertia_rewrite_failure_pass", None)
            postprocess_info["rewrite_failure_error"] = getattr(self.codegen, "_inertia_rewrite_failure_error", None)
            postprocess_info["validation_failed"] = bool(
                getattr(self.codegen, "_inertia_postprocess_validation_failed", False)
            )
            postprocess_info["validation_failure_pass"] = getattr(
                self.codegen,
                "_inertia_postprocess_validation_failure_pass",
                None,
            )
            postprocess_info["validation_failure_error"] = getattr(
                self.codegen,
                "_inertia_postprocess_validation_failure_error",
                None,
            )
            postprocess_info["regeneration_failed"] = bool(getattr(self.codegen, "_inertia_regeneration_failed", False))
            postprocess_info["regeneration_failure_pass"] = getattr(
                self.codegen,
                "_inertia_regeneration_last_pass",
                None,
            )
            postprocess_info["regeneration_failure_error"] = getattr(
                self.codegen,
                "_inertia_regeneration_error",
                None,
            )
            postprocess_info["pass_names"] = getattr(self.codegen, "_inertia_postprocess_passes", ())
            postprocess_info["last_stage"] = getattr(self.project, "_inertia_decompiler_stage", None)
            postprocess_info["tail_validation_verdict"] = validation["verdict"]
            postprocess_info["tail_validation_cache_hit"] = bool(validation.get("cache_hit", False))
    persist_x86_16_tail_validation_snapshot(
        function_info=snapshot_function_info,
        codegen=self.codegen,
        stage="postprocess",
        validation=validation,
    )
    record_tail_validation_condition_trace_8616(self.project, self.codegen, validation)
    materialized_condition_drift_detected_8616(self.project, self.codegen)
    dump_condition_trace_8616(self.project, self.codegen, label="postprocess")
    snapshot = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
    if isinstance(snapshot, dict):
        setattr(self.project, "_inertia_last_tail_validation_snapshot", dict(snapshot))
    if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
        import sys as _tv_sys2
        _tv_sys2.stderr.write(f"[dbg] _decompile_8616 persist: addr={func_addr} name={func_name} snapshot_stages={list(snapshot.keys()) if isinstance(snapshot, dict) else 'NONE'} codegen_id={id(self.codegen)}\n")
        _tv_sys2.stderr.flush()
    log = logging.getLogger(__name__)
    if not x86_16_tail_validation_result_passed(validation):
        validation_verdict_text = str(validation.get("verdict") or validation.get("summary_text") or "")
        if "Missing source-evidenced calls" in validation_verdict_text:
            with contextlib.suppress(Exception):
                rescue_changed = bool(_calls._recover_missing_direct_calls_from_evidence_8616(self.project, self.codegen))
                if rescue_changed:
                    _calls._materialize_callsite_stack_arguments_8616(self.project, self.codegen)
                    _calls._normalize_call_target_names_8616(self.codegen)
                    rescue_after_summary = collect_x86_16_tail_validation_summary(
                        self.project,
                        self.codegen,
                        mode=validation_mode,
                    )
                    rescue_after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
                        self.project,
                        self.codegen,
                        mode=validation_mode,
                    )
                    validation = compare_x86_16_tail_validation_summaries(
                        before_fingerprint,
                        rescue_after_fingerprint,
                    )
                    validation = build_x86_16_tail_validation_cached_result(
                        owner=snapshot_function_info,
                        stage="postprocess",
                        mode=validation_mode,
                        comparison=validation,
                        before_summary=before_summary,
                        after_summary=rescue_after_summary,
                        before_fingerprint=before_fingerprint,
                        after_fingerprint=rescue_after_fingerprint,
                    )
                    validation_verdict_text = str(validation.get("verdict") or validation.get("summary_text") or "")
        allow_validation_override = (
            str(os.environ.get("INERTIA_ALLOW_POSTPROCESS_VALIDATION_OVERRIDE", "")).strip().lower()
            in {"1", "true", "yes", "on"}
        )
        recovered_call_floor = int(getattr(self.codegen, "_inertia_direct_call_floor_recovered_count", 0) or 0)
        if (
            allow_validation_override
            and recovered_call_floor > 0
            and "Missing source-evidenced calls" in validation_verdict_text
        ):
            log.warning(
                "Postprocess validation changed but keeping call-floor recovery output (recovered=%d): %s",
                recovered_call_floor,
                validation_verdict_text,
            )
            validation["changed"] = False
            validation["status"] = "stable"
            validation["summary_text"] = "no observable whole-tail changes"
            validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
            persist_x86_16_tail_validation_snapshot(
                function_info=snapshot_function_info,
                codegen=self.codegen,
                stage="postprocess",
                validation=validation,
            )
            snapshot = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
            if isinstance(snapshot, dict):
                setattr(self.project, "_inertia_last_tail_validation_snapshot", dict(snapshot))
        elif _is_direct_callsite_helper_delta_only_8616(self.project, function, validation):
            log.warning(
                "Postprocess validation helper-call delta accepted from direct callsite evidence: %s",
                validation.get("verdict"),
            )
            validation["changed"] = False
            validation["status"] = "stable"
            validation["summary_text"] = "no observable whole-tail changes"
            validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
            # Re-persist accepted normalization so downstream acceptance gate sees stable postprocess.
            persist_x86_16_tail_validation_snapshot(
                function_info=snapshot_function_info,
                codegen=self.codegen,
                stage="postprocess",
                validation=validation,
            )
            snapshot = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
            if isinstance(snapshot, dict):
                setattr(self.project, "_inertia_last_tail_validation_snapshot", dict(snapshot))
        elif allow_validation_override and _has_recovered_source_calls_in_codegen_8616(self.project, self.codegen, function):
            log.warning(
                "Postprocess validation changed but keeping recovered call-floor output (source-evidenced calls present): %s",
                validation.get("verdict"),
            )
            validation["changed"] = False
            validation["status"] = "stable"
            validation["summary_text"] = "no observable whole-tail changes"
            validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
            persist_x86_16_tail_validation_snapshot(
                function_info=snapshot_function_info,
                codegen=self.codegen,
                stage="postprocess",
                validation=validation,
            )
            snapshot = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
            if isinstance(snapshot, dict):
                setattr(self.project, "_inertia_last_tail_validation_snapshot", dict(snapshot))
        else:
            if (
                "Missing source-evidenced" in validation_verdict_text
                and pre_postprocess_cfunc_snapshot is not None
            ):
                post_score, post_total = _expected_source_call_score_from_cfunc_8616(
                    self.project,
                    getattr(self.codegen, "cfunc", None),
                    function,
                )
                pre_score, pre_total = _expected_source_call_score_from_cfunc_8616(
                    self.project,
                    pre_postprocess_cfunc_snapshot,
                    function,
                )
                if allow_validation_override and post_total > 0 and post_score >= pre_score:
                    log.warning(
                        "Postprocess validation changed but keeping stronger source-call coverage (post=%d/%d pre=%d/%d): %s",
                        post_score,
                        post_total,
                        pre_score,
                        pre_total,
                        validation.get("verdict"),
                    )
                    validation["changed"] = False
                    validation["status"] = "stable"
                    validation["summary_text"] = "no observable whole-tail changes"
                    validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
                    persist_x86_16_tail_validation_snapshot(
                        function_info=snapshot_function_info,
                        codegen=self.codegen,
                        stage="postprocess",
                        validation=validation,
                    )
                    snapshot = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
                    if isinstance(snapshot, dict):
                        setattr(self.project, "_inertia_last_tail_validation_snapshot", dict(snapshot))
                    self.project._inertia_decompiler_stage = "done"
                    import sys as _tv_sys4

                    tv_snap = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
                    _tv_sys4.stderr.write(
                        f"[dbg] _decompile_8616 DONE: addr={func_addr} codegen_id={id(self.codegen)} snapshot_stages={list(tv_snap.keys()) if isinstance(tv_snap, dict) else 'NONE'} proj_fb_stages={list(getattr(self.project, '_inertia_last_tail_validation_snapshot', {}).keys())}\n"
                    )
                    _tv_sys4.stderr.flush()
                    return
            if os.environ.get("INERTIA_DEBUG_POSTPROCESS_VALIDATION"):
                delta = validation.get("delta") if isinstance(validation, dict) else None
                log.warning(
                    "[postprocess-validation] final function=%#x verdict=%s stack_delta=%s before=%s after=%s",
                    function_original_addr(function) if function is not None else -1,
                    validation.get("verdict"),
                    (delta or {}).get("stack_writes"),
                    (validation.get("before") or {}).get("stack_writes"),
                    (validation.get("after") or {}).get("stack_writes"),
                )
            log.warning(
                "Postprocess validation changed — discarding postprocessed C, emitting pre-postprocess C: %s (last_pass=%s failure_pass=%s)",
                validation["verdict"],
                getattr(self.codegen, "_inertia_last_postprocess_pass", None),
                getattr(self.codegen, "_inertia_postprocess_validation_failure_pass", None),
            )
            # Semantic gate: restore pre-postprocess codegen when postprocess changed live-out observables
            if pre_postprocess_cfunc_snapshot is not None:
                _restore_codegen_cfunc(self.codegen, pre_postprocess_cfunc_snapshot)
                self.codegen._inertia_postprocess_discarded = True
                self.codegen._inertia_postprocess_discard_verdict = validation["verdict"]
                restored_after_summary = collect_x86_16_tail_validation_summary(
                    self.project,
                    self.codegen,
                mode=validation_mode,
            )
            restored_after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
                self.project,
                self.codegen,
                mode=validation_mode,
            )
            validation = build_x86_16_tail_validation_cached_result(
                owner=snapshot_function_info,
                stage="postprocess",
                mode=validation_mode,
                before_fingerprint=before_fingerprint,
                after_fingerprint=restored_after_fingerprint,
                before_summary=before_summary,
                after_summary=restored_after_summary,
            )
            validation["timings"] = validation_timings
            validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
            persist_x86_16_tail_validation_snapshot(
                function_info=snapshot_function_info,
                codegen=self.codegen,
                stage="postprocess",
                validation=validation,
            )
            snapshot = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
            if isinstance(snapshot, dict):
                setattr(self.project, "_inertia_last_tail_validation_snapshot", dict(snapshot))
            log.info("%s", validation["verdict"])
    else:
        log.info("%s", validation["verdict"])
    self.project._inertia_decompiler_stage = "done"
    import sys as _tv_sys4
    tv_snap = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
    _tv_sys4.stderr.write(f"[dbg] _decompile_8616 DONE: addr={func_addr} codegen_id={id(self.codegen)} snapshot_stages={list(tv_snap.keys()) if isinstance(tv_snap, dict) else 'NONE'} proj_fb_stages={list(getattr(self.project, '_inertia_last_tail_validation_snapshot', {}).keys())}\n")
    _tv_sys4.stderr.flush()


def apply_x86_16_decompiler_postprocess() -> None:
    if getattr(Decompiler._decompile, "__name__", "") != "_decompile_8616":
        _decompile_8616._orig_decompiler_decompile = Decompiler._decompile
        Decompiler._decompile = _decompile_8616
