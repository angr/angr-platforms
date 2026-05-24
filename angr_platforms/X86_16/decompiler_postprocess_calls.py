from __future__ import annotations

from copy import copy
from collections import Counter
import contextlib
from dataclasses import dataclass, replace
from enum import Enum
import logging
import os
import re
from pathlib import Path

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CFunctionCall, CTypeCast, CUnaryOp
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .analysis_helpers import patch_direct_call_sites, preferred_known_helper_signature_decl
from .cod_extract import extract_cod_proc_metadata
from .callee_name_normalization import normalize_callee_name_8616
from .callsite_summary import summarize_x86_16_callsite
from .callsite_stack_metadata import prune_materialized_callsite_segment_metadata_8616
from .lowering.stack_probe_return_facts import (
    TypedStackProbeReturnFact8616,
    build_typed_stack_probe_return_facts_8616,
)
from .lowering.real_mode_linear import _stack_offset_from_expr_8616
from .lowering.stack_lowering_from_facts import _materialize_stack_cvar_at_offset as _materialize_stack_cvar_at_offset_from_facts_8616
from .decompiler_postprocess import _normalize_arg_names_8616
from .decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _match_bp_stack_dereference_8616,
    _match_bp_stack_load_8616,
    _match_real_mode_linear_expr_8616,
    _match_real_mode_segmented_store_shape_8616,
    _replace_c_children_8616,
    _segment_reg_name_8616,
    _match_segmented_dereference_8616,
    _same_c_expression_8616,
)
from .stack_probe_fact_trace import (
    ensure_stack_probe_fact_stats_8616,
    record_callsite_summary_fact_8616,
    record_callsite_summary_map_facts_8616,
    record_stack_arg_materialization_8616,
)
from .pipeline.errors import PipelineHardError

__all__ = [
    "_attach_callsite_summaries_8616",
    "_recover_missing_direct_calls_from_evidence_8616",
    "_materialize_callsite_stack_arguments_8616",
    "_materialize_callsite_prototypes_8616",
    "_normalize_call_target_names_8616",
]

_SUB_TARGET_RE = re.compile(r"^(?:sub_|0x)(?P<addr>[0-9a-fA-F]+)$")
_NAMESPACED_TARGET_RE = re.compile(r"^::0x(?P<addr>[0-9a-fA-F]+)::")
log = logging.getLogger(__name__)
_RUNTIME_SEGMENT_HELPERS_8616 = frozenset({"SEG_U8", "SEG_U16", "SEG_U32", "MK_FP", "SEG_PTR"})
_CALL_TOKEN_RE_8616 = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _structured_root_8616(cfunc):
    return getattr(cfunc, "body", None) or getattr(cfunc, "statements", None) or cfunc


def _recover_missing_direct_calls_from_evidence_8616(project, codegen) -> bool:
    debug_enabled = bool(os.environ.get("INERTIA_DEBUG_CALL_RECOVERY"))
    context_tag = getattr(codegen, "_inertia_call_recover_context", "postprocess")
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        if debug_enabled:
            log.warning("[call-recover] context=%s skip=no-cfunc codegen_id=%#x", context_tag, id(codegen))
        return False
    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
    root_statements = getattr(root, "statements", None)
    if not isinstance(root_statements, (list, tuple)):
        if debug_enabled:
            log.warning(
                "[call-recover] context=%s skip=bad-root-statements codegen_id=%#x root=%s root_statements=%s",
                context_tag,
                id(codegen),
                type(root).__name__,
                type(root_statements).__name__ if root_statements is not None else "None",
            )
        return False
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        if debug_enabled:
            log.warning("[call-recover] context=%s skip=bad-func-addr codegen_id=%#x", context_tag, id(codegen))
        return False
    function = project.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        if debug_enabled:
            log.warning("[call-recover] context=%s skip=no-kb-function addr=%r codegen_id=%#x", context_tag, func_addr, id(codegen))
        return False

    expected_names: list[str] = []
    expected_summary_by_name: dict[str, list[object]] = {}
    callsite_addrs = tuple(sorted(getattr(function, "get_call_sites", lambda: [])() or ()))
    for callsite_addr in callsite_addrs:
        target = getattr(function, "get_call_target", lambda _addr: None)(callsite_addr)
        if not isinstance(target, int):
            continue
        callee = project.kb.functions.function(addr=target, create=False)
        callee_name = getattr(callee, "name", None)
        if not isinstance(callee_name, str) or not callee_name:
            continue
        if callee_name in _RUNTIME_SEGMENT_HELPERS_8616:
            continue
        normalized_name = normalize_callee_name_8616(callee_name) or callee_name
        expected_names.append(normalized_name)
        summary = summarize_x86_16_callsite(function, callsite_addr)
        if summary is not None:
            expected_summary_by_name.setdefault(normalized_name, []).append(summary)
    # Optional sidecar/COD evidence: adds call floor when call-target recovery is
    # incomplete in structured output.
    source_call_names = list(_cod_source_call_names_8616(project, func_addr))
    if not source_call_names:
        source_call_names = list(_cod_source_call_names_for_symbol_8616(project, getattr(cfunc, "name", None)))
    for source_name in source_call_names:
        if isinstance(source_name, str) and source_name:
            expected_names.append(source_name)

    if not expected_names:
        if debug_enabled:
            log.warning("[call-recover] context=%s skip=no-expected-names addr=%#x codegen_id=%#x", context_tag, func_addr, id(codegen))
        return False

    # Presence/missing checks should prefer emitted body text.
    # If rendering fails, fall back to AST call names as best-effort evidence.
    present_names, rendered_ok = _rendered_call_names_8616(codegen, cfunc)
    if not rendered_ok:
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, CFunctionCall):
                continue
            for raw in (
                getattr(node, "callee_target", None),
                getattr(getattr(node, "callee_func", None), "name", None),
                getattr(node, "callee", None),
            ):
                if isinstance(raw, str) and raw:
                    present_names.append(raw)
                    break

    source_sequence = [
        (normalize_callee_name_8616(name) or name)
        for name in source_call_names
        if isinstance(name, str) and name and name != "aNchkstk"
    ]
    actual_sequence = [
        (normalize_callee_name_8616(name) or name)
        for name in present_names
        if isinstance(name, str) and name and name != "aNchkstk"
    ]
    missing: list[str] = []
    if source_sequence:
        # Evidence-based ordered recovery: only insert calls that are missing in
        # source call order after greedy alignment with current emitted sequence.
        j = 0
        for expected_name in source_sequence:
            while j < len(actual_sequence) and actual_sequence[j] != expected_name:
                j += 1
            if j < len(actual_sequence) and actual_sequence[j] == expected_name:
                j += 1
            else:
                missing.append(expected_name)
    else:
        expected_counts = Counter(
            (normalize_callee_name_8616(name) or name) for name in expected_names if name != "aNchkstk"
        )
        present_counts = Counter(actual_sequence)
        for name, needed in expected_counts.items():
            have = int(present_counts.get(name, 0))
            if have < needed:
                missing.extend([name] * (needed - have))
    if not missing:
        cfunc_statements = getattr(cfunc, "statements", None)
        cfunc_body = getattr(cfunc, "body", None)
        body_statements = getattr(cfunc_body, "statements", None)
        if root is not cfunc and isinstance(root_statements, (list, tuple)):
            if hasattr(root, "statements"):
                with contextlib.suppress(Exception):
                    cfunc.body = root
            if isinstance(cfunc_statements, (list, tuple)) and cfunc_statements is not root_statements:
                cfunc.statements = list(root_statements) if isinstance(cfunc_statements, list) else tuple(root_statements)
            if cfunc_body is not None and isinstance(body_statements, (list, tuple)) and body_statements is not root_statements:
                cfunc_body.statements = list(root_statements) if isinstance(body_statements, list) else tuple(root_statements)
        if debug_enabled:
            log.warning("[call-recover] context=%s skip=no-missing addr=%#x codegen_id=%#x", context_tag, func_addr, id(codegen))
        return False

    insert_at = len(root_statements)
    mutable_statements = list(root_statements)
    for idx, stmt in enumerate(mutable_statements):
        if isinstance(stmt, structured_c.CReturn):
            insert_at = idx
            break

    summary_map = dict(getattr(codegen, "_inertia_callsite_summaries", {}) or {})
    changed = False
    # Metadata-first by default: avoid rewriting callee identities here unless
    # explicitly enabled for debugging.
    allow_call_target_rewrites = bool(int(os.environ.get("INERTIA_ENABLE_CALLSITE_TARGET_REWRITES", "0")))
    # Callsite summary attachment should be metadata-first. Rewriting callee
    # identities here can perturb later passes and leak semantic deltas.
    allow_call_target_rewrites = bool(int(os.environ.get("INERTIA_ENABLE_CALLSITE_TARGET_REWRITES", "0")))
    first_empty_loop_body = _first_empty_loop_body_8616(mutable_statements)
    # Preserve source call ordering when recovering missing calls.
    # Build a replay queue by scanning source order and selecting only calls that
    # still need insertion according to `missing` multiset.
    missing_counts = Counter(missing)
    ordered_missing: list[str] = []
    if source_sequence:
        for name in source_sequence:
            if missing_counts.get(name, 0) > 0:
                ordered_missing.append(name)
                missing_counts[name] -= 1
    else:
        ordered_missing = list(missing)
    def _summary_looks_loop_carried_arg_8616(summary_obj) -> bool:
        if summary_obj is None:
            return False
        raw_sources = tuple(getattr(summary_obj, "arg_sources", ()) or ())
        for src in raw_sources:
            if not isinstance(src, tuple) or len(src) != 2:
                continue
            base, disp = src
            if base == "bp" and isinstance(disp, int):
                return True
        return False

    for idx, name in enumerate(ordered_missing):
        callee_func = project.kb.functions.function(name=name, create=False)
        seeded_args = _known_default_args_for_missing_8616(name, codegen)
        call_args = list(seeded_args) if isinstance(seeded_args, tuple) else []
        call = CFunctionCall(name, callee_func, call_args, codegen=codegen)
        call_stmt = structured_c.CExpressionStatement(call, codegen=codegen)
        inserted_in_loop = False
        summary_candidates = expected_summary_by_name.get(normalize_callee_name_8616(name) or name, [])
        preferred_summary = summary_candidates[0] if summary_candidates else None
        loop_carried_missing = _summary_looks_loop_carried_arg_8616(preferred_summary)
        if (
            (
                idx == 0
                and source_sequence
                and source_sequence[0] == name
            )
            or loop_carried_missing
        ) and first_empty_loop_body is not None:
            loop_body_statements = list(getattr(first_empty_loop_body, "statements", ()) or ())
            loop_body_statements.append(call_stmt)
            first_empty_loop_body.statements = loop_body_statements
            inserted_in_loop = True
        if not inserted_in_loop:
            mutable_statements.insert(insert_at, call_stmt)
        if summary_candidates:
            summary_map[id(call)] = summary_candidates.pop(0)
        if not inserted_in_loop:
            insert_at += 1
        changed = True
    if changed:
        updated_statements = mutable_statements if isinstance(root_statements, list) else tuple(mutable_statements)
        root.statements = updated_statements
        if hasattr(root, "statements"):
            with contextlib.suppress(Exception):
                cfunc.body = root
        cfunc_statements = getattr(cfunc, "statements", None)
        if root is not cfunc_statements and isinstance(cfunc_statements, (list, tuple)):
            cfunc.statements = list(updated_statements) if isinstance(cfunc_statements, list) else tuple(updated_statements)
        cfunc_body = getattr(cfunc, "body", None)
        body_statements = getattr(cfunc_body, "statements", None)
        if cfunc_body is not None and cfunc_body is not root and isinstance(body_statements, (list, tuple)):
            cfunc_body.statements = list(updated_statements) if isinstance(body_statements, list) else tuple(updated_statements)
        if debug_enabled:
            cfunc_calls = []
            cfunc_root_now = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
            for node in _iter_c_nodes_deep_8616(cfunc_root_now):
                if isinstance(node, CFunctionCall):
                    cfunc_calls.append(_call_node_name_8616(node))
            log.warning(
                "[call-recover] context=%s function=%#x codegen_id=%#x recovered=%r root=%s root_id=%#x cfunc_root=%s cfunc_root_id=%#x calls=%r",
                context_tag,
                getattr(cfunc, "addr", 0) or 0,
                id(codegen),
                ordered_missing,
                type(root).__name__,
                id(root),
                type(cfunc_root_now).__name__,
                id(cfunc_root_now),
                cfunc_calls,
            )
        codegen._inertia_callsite_summaries = summary_map
        setattr(
            codegen,
            "_inertia_direct_call_floor_recovered_count",
            int(getattr(codegen, "_inertia_direct_call_floor_recovered_count", 0)) + len(missing),
        )
    if source_sequence:
        current_statements = getattr(root, "statements", None)
        if not isinstance(current_statements, (list, tuple)):
            current_statements = root_statements
        empty_loop_bodies = _empty_loop_bodies_8616(current_statements)
        if len(empty_loop_bodies) >= 2:
            mutable_statements = list(current_statements)
            first_return_idx = None
            for idx, stmt in enumerate(mutable_statements):
                if isinstance(stmt, structured_c.CReturn):
                    first_return_idx = idx
                    break
            if first_return_idx is not None:
                scan_slice = list(enumerate(mutable_statements[first_return_idx + 1 :], start=first_return_idx + 1))
            else:
                scan_slice = list(enumerate(mutable_statements))
            call_stmt_indexes: list[int] = []
            call_stmt_names: list[str] = []
            for idx, stmt in scan_slice:
                expr = getattr(stmt, "expr", None)
                if not isinstance(expr, CFunctionCall):
                    continue
                normalized = normalize_callee_name_8616(_call_node_name_8616(expr)) or _call_node_name_8616(expr)
                if not isinstance(normalized, str) or not normalized:
                    continue
                call_stmt_indexes.append(idx)
                call_stmt_names.append(normalized)
            expected = [name for name in source_sequence if isinstance(name, str) and name]
            if expected and call_stmt_names[: len(expected)] == expected:
                first_body = empty_loop_bodies[0]
                second_body = empty_loop_bodies[1]
                first_idx = call_stmt_indexes[0]
                second_indexes = call_stmt_indexes[1: len(expected)]
                first_body_statements = list(getattr(first_body, "statements", ()) or ())
                second_body_statements = list(getattr(second_body, "statements", ()) or ())
                first_body_statements.append(mutable_statements[first_idx])
                for idx in second_indexes:
                    second_body_statements.append(mutable_statements[idx])
                first_body.statements = first_body_statements
                second_body.statements = second_body_statements
                remove_indexes = {first_idx, *second_indexes}
                mutable_statements = [
                    stmt for idx, stmt in enumerate(mutable_statements) if idx not in remove_indexes
                ]
                updated_statements = mutable_statements if isinstance(root_statements, list) else tuple(mutable_statements)
                root.statements = updated_statements
                if hasattr(root, "statements"):
                    with contextlib.suppress(Exception):
                        cfunc.body = root
                cfunc_statements = getattr(cfunc, "statements", None)
                if root is not cfunc_statements and isinstance(cfunc_statements, (list, tuple)):
                    cfunc.statements = list(updated_statements) if isinstance(cfunc_statements, list) else tuple(updated_statements)
                cfunc_body = getattr(cfunc, "body", None)
                body_statements = getattr(cfunc_body, "statements", None)
                if cfunc_body is not None and cfunc_body is not root and isinstance(body_statements, (list, tuple)):
                    cfunc_body.statements = list(updated_statements) if isinstance(body_statements, list) else tuple(updated_statements)
                changed = True
                # Preserve reachable control flow: remove early top-level return
                # when it now precedes only relocated callsites.
                if first_return_idx is not None and first_return_idx < len(mutable_statements):
                    with contextlib.suppress(Exception):
                        updated_top = list(getattr(root, "statements", ()) or ())
                        if first_return_idx < len(updated_top) and isinstance(updated_top[first_return_idx], structured_c.CReturn):
                            del updated_top[first_return_idx]
                            root.statements = updated_top if isinstance(getattr(root, "statements", None), list) else tuple(updated_top)
    return changed


def _first_empty_loop_body_8616(statements) -> object | None:
    for stmt in statements:
        body = getattr(stmt, "body", None)
        body_statements = getattr(body, "statements", None)
        if isinstance(body_statements, (list, tuple)) and len(body_statements) == 0:
            # Loop-like nodes expose condition fields in structured_codegen nodes.
            if hasattr(stmt, "condition") or hasattr(stmt, "cond"):
                return body
    return None


def _empty_loop_bodies_8616(statements) -> list[object]:
    bodies: list[object] = []
    for stmt in statements:
        body = getattr(stmt, "body", None)
        body_statements = getattr(body, "statements", None)
        if not isinstance(body_statements, (list, tuple)):
            continue
        if not (hasattr(stmt, "condition") or hasattr(stmt, "cond")):
            continue
        if len(body_statements) == 0:
            bodies.append(body)
            continue
        has_call = False
        only_placeholder_effects = True
        for body_stmt in body_statements:
            expr = getattr(body_stmt, "expr", None)
            if isinstance(expr, CFunctionCall):
                has_call = True
                only_placeholder_effects = False
                break
            if isinstance(expr, CBinaryOp):
                # Keep conservative: loop bodies with binary expression side-effects
                # are not safe anchors.
                only_placeholder_effects = False
                break
            if isinstance(expr, structured_c.CAssignment):
                lhs = getattr(expr, "lhs", None)
                rhs = getattr(expr, "rhs", None)
                if _same_c_expression_8616(lhs, rhs):
                    continue
                only_placeholder_effects = False
                break
            # Unknown loop statement kind: refuse anchoring.
            only_placeholder_effects = False
            break
        if (not has_call) and only_placeholder_effects:
            bodies.append(body)
    return bodies


def _rendered_call_names_8616(codegen, cfunc) -> tuple[list[str], bool]:
    try:
        rendered = codegen.render_text(cfunc)
    except Exception:
        return ([], False)
    if isinstance(rendered, tuple):
        rendered = rendered[0] if rendered and isinstance(rendered[0], str) else ""
    if not isinstance(rendered, str) or not rendered:
        return ([], False)
    # Presence checks must only inspect executable body text.
    # Embedded original-source evidence comments (/// ...) include call names
    # that can otherwise mask genuinely missing recovered calls.
    text_wo_comments = re.sub(r"/\*.*?\*/", "", rendered, flags=re.S)
    text_wo_comments = re.sub(r"//[^\n]*", "", text_wo_comments)
    text_wo_comments = "\n".join(
        line for line in text_wo_comments.splitlines() if not line.lstrip().startswith("///")
    )
    body = text_wo_comments.split("{", 1)[-1] if "{" in text_wo_comments else text_wo_comments
    names: list[str] = []
    for name in _CALL_TOKEN_RE_8616.findall(body):
        if name in {"if", "for", "while", "switch", "return", "sizeof"}:
            continue
        names.append(name)
    return (names, True)


@dataclass(slots=True)
class CallsiteMaterializationStats:
    callsite_count: int = 0
    call_target_fact_count: int = 0
    call_target_materialized_count: int = 0
    call_arg_fact_count: int = 0
    call_arg_materialized_count: int = 0
    bp_slot_arg_value_normalized_count: int = 0
    pointer_arg_materialized_count: int = 0
    push_order_reversed_count: int = 0
    consumed_outgoing_stack_placeholder_count: int = 0
    stale_target_rejected_count: int = 0
    known_prototype_arg_mismatch_count: int = 0
    failure_count: int = 0


class CallArgSemanticKind8616(Enum):
    UNKNOWN = "unknown"
    POINTER = "pointer"
    VALUE = "value"


_KNOWN_HELPER_ARG_KIND_CACHE_8616: dict[str, dict[int, CallArgSemanticKind8616]] = {}


def _ensure_callsite_materialization_stats_8616(codegen) -> CallsiteMaterializationStats:
    stats = getattr(codegen, "_inertia_callsite_materialization_stats", None)
    if not isinstance(stats, CallsiteMaterializationStats):
        stats = CallsiteMaterializationStats()
        codegen._inertia_callsite_materialization_stats = stats
    return stats


def _sync_callsite_materialization_stats_8616(codegen) -> CallsiteMaterializationStats:
    stats = _ensure_callsite_materialization_stats_8616(codegen)
    raw = ensure_stack_probe_fact_stats_8616(codegen)
    for key in (
        "callsite_count",
        "call_target_fact_count",
        "call_target_materialized_count",
        "call_arg_fact_count",
        "call_arg_materialized_count",
        "bp_slot_arg_value_normalized_count",
        "pointer_arg_materialized_count",
        "push_order_reversed_count",
        "consumed_outgoing_stack_placeholder_count",
        "stale_target_rejected_count",
        "known_prototype_arg_mismatch_count",
        "failure_count",
    ):
        raw[key] = int(getattr(stats, key, 0) or 0)
    return stats


def _is_stack_probe_call_name_8616(name: str | None) -> bool:
    if not isinstance(name, str):
        return False
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return False
    lowered = normalized.lower()
    return lowered in {
        "anchkstk",
        "chkstk",
        "_chkstk",
        "__chkstk",
        "__aNchkstk".lower(),
    }


def _lookup_callee_function_8616(project, target_addr: int, *, allow_containing: bool = False):
    def _lookup_exact_or_containing(candidate_project, candidate_addr: int):
        functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
        lookup = getattr(functions, "function", lambda **_: None)
        function = lookup(addr=candidate_addr, create=False)
        floor_func = getattr(functions, "floor_func", None)
        ceiling_addr = getattr(functions, "ceiling_addr", None)

        def _contains_addr(containing, *, allow_range: bool) -> bool:
            if containing is None:
                return False
            start_addr = getattr(containing, "addr", None)
            if not isinstance(start_addr, int):
                return allow_range is False
            if not isinstance(start_addr, int) or start_addr > candidate_addr:
                return False
            block_addrs = tuple(getattr(containing, "block_addrs_set", ()) or ())
            if candidate_addr in block_addrs:
                return True
            if start_addr == candidate_addr:
                return True
            if allow_range and callable(ceiling_addr):
                try:
                    next_addr = ceiling_addr(start_addr + 1)
                except Exception as ex:
                    log.debug(
                        "ceiling_addr lookup failed target=%#x candidate_start=%#x: %s",
                        candidate_addr,
                        start_addr,
                        ex,
                    )
                    next_addr = None
                if isinstance(next_addr, int):
                    return start_addr <= candidate_addr < next_addr
            return False

        if _contains_addr(function, allow_range=False):
            return function
        if not allow_containing or not callable(floor_func):
            return None
        try:
            containing = floor_func(candidate_addr)
        except Exception as ex:
            log.debug("floor_func lookup failed target=%#x: %s", candidate_addr, ex)
            containing = None
        if containing is None or not _contains_addr(containing, allow_range=True):
            return None
        return containing

    candidate_addrs = [target_addr]
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(original_delta, int):
        candidate_addrs.append(target_addr + original_delta)
        rebased = target_addr - original_delta
        if rebased >= 0:
            candidate_addrs.append(rebased)
    ordered_addrs: list[int] = []
    for addr in candidate_addrs:
        if addr not in ordered_addrs:
            ordered_addrs.append(addr)

    for candidate_project in (project, getattr(project, "_inertia_original_project", None)):
        for candidate_addr in ordered_addrs:
            function = _lookup_exact_or_containing(candidate_project, candidate_addr)
            if function is not None:
                return function
    return None


def _sidecar_label_for_target_8616(project, target_addr: int) -> str | None:
    candidates: list[str] = []
    lookup_addrs = {target_addr}
    original_project = getattr(project, "_inertia_original_project", None)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(original_delta, int):
        lookup_addrs.add(target_addr + original_delta)
        rebased = target_addr - original_delta
        if rebased >= 0:
            lookup_addrs.add(rebased)

    for lookup_addr in sorted(lookup_addrs):
        for labels in (
            getattr(getattr(project, "_inertia_lst_metadata", None), "code_labels", None),
            getattr(getattr(project, "kb", None), "labels", None),
        ):
            if labels is None:
                continue
            label = getattr(labels, "get", lambda _addr: None)(lookup_addr)
            if isinstance(label, str) and label:
                candidates.append(label)

    if original_project is not None and isinstance(original_delta, int):
        for lookup_addr in sorted(lookup_addrs):
            for labels in (
                getattr(getattr(original_project, "_inertia_lst_metadata", None), "code_labels", None),
                getattr(getattr(original_project, "kb", None), "labels", None),
            ):
                if labels is None:
                    continue
                label = getattr(labels, "get", lambda _addr: None)(lookup_addr)
                if isinstance(label, str) and label:
                    candidates.append(label)

    for label in candidates:
        normalized = normalize_callee_name_8616(label.lstrip("_"))
        if isinstance(normalized, str) and normalized and not normalized.startswith("sub_"):
            return normalized
    return None


def _function_matches_target_addr_8616(function, target_addr: int | None) -> bool:
    if function is None or not isinstance(target_addr, int):
        return False
    start_addr = getattr(function, "addr", None)
    if not isinstance(start_addr, int):
        return False
    if start_addr == target_addr:
        return True
    block_addrs = tuple(getattr(function, "block_addrs_set", ()) or ())
    return target_addr in block_addrs


def _expected_arg_count_for_known_callee_8616(name: str) -> int | None:
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return None
    table = {
        "aNchkstk": 0,
        "__aNchkstk": 0,
        "clock": 0,
        "memset": 3,
        "_memset": 3,
        "settextcolor": 1,
        "_settextcolor": 1,
        "settextposition": 2,
        "_settextposition": 2,
        "outtext": 1,
        "_outtext": 1,
        "outtextxy": 3,
        "_outtextxy": 3,
        "settextrows": 1,
        "clearscreen": 1,
        "displaycursor": 1,
        "setvideomode": 1,
        "PercolateUp": 1,
        "_PercolateUp": 1,
        "PercolateDown": 1,
        "_PercolateDown": 1,
        "SwapBars": 2,
        "_SwapBars": 2,
        "Swaps": 2,
        "_Swaps": 2,
        "DrawBar": 1,
        "_DrawBar": 1,
        "DrawTime": 1,
        "_DrawTime": 1,
    }
    if normalized in table:
        return table[normalized]
    decl = preferred_known_helper_signature_decl(normalized)
    if isinstance(decl, str):
        m = re.search(r"\((?P<args>[^)]*)\)", decl)
        arg_text = m.group("args").strip() if m is not None else ""
        if not arg_text or arg_text == "void":
            return 0
        return len([part for part in arg_text.split(",") if part.strip()])
    return None


def _known_default_args_for_missing_8616(name: str, codegen) -> tuple | None:
    """Compiler/runtime helper ABI defaults used when a known helper omits pushes."""
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return None
    defaults = {
        "clearscreen": (0,),
        "displaycursor": (0,),
        "setvideomode": (0xFFFF,),
    }
    if normalized in {"Swaps", "_Swaps"}:
        project = getattr(codegen, "project", None)
        arch = getattr(project, "arch", None)
        reg_info = getattr(arch, "registers", {}).get("ds") if arch is not None else None
        if isinstance(reg_info, tuple) and len(reg_info) >= 1:
            ds_reg = structured_c.CVariable(
                SimRegisterVariable(reg_info[0], 2, name="ds"),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            )
            off = structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen)
            ptr1 = structured_c.CFunctionCall("SEG_PTR", None, [copy(ds_reg), off], codegen=codegen)
            ptr2 = structured_c.CFunctionCall("SEG_PTR", None, [copy(ds_reg), copy(off)], codegen=codegen)
            return (ptr1, ptr2)
    values = defaults.get(normalized)
    if values is None:
        return None
    return tuple(structured_c.CConstant(value, SimTypeShort(False), codegen=codegen) for value in values)


def _callee_expects_pointer_arg_8616(name: str, arg_index: int) -> bool:
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return False
    return _call_arg_semantic_kind_8616(normalized, arg_index) is CallArgSemanticKind8616.POINTER


def _call_arg_semantic_kind_8616(callee: str, arg_index: int) -> CallArgSemanticKind8616:
    normalized = normalize_callee_name_8616(callee)
    if not isinstance(normalized, str):
        return CallArgSemanticKind8616.UNKNOWN
    cached = _KNOWN_HELPER_ARG_KIND_CACHE_8616.get(normalized)
    if cached is None:
        cached = {}
        decl = preferred_known_helper_signature_decl(normalized)
        if isinstance(decl, str):
            m = re.search(r"\((?P<args>[^)]*)\)", decl)
            arg_text = m.group("args").strip() if m is not None else ""
            if arg_text and arg_text != "void":
                parts = [part.strip() for part in arg_text.split(",") if part.strip()]
                for idx, part in enumerate(parts):
                    kind = CallArgSemanticKind8616.POINTER if ("*" in part or "[" in part) else CallArgSemanticKind8616.VALUE
                    cached[idx] = kind
        _KNOWN_HELPER_ARG_KIND_CACHE_8616[normalized] = cached
    return cached.get(arg_index, CallArgSemanticKind8616.UNKNOWN)


def _callee_name_should_yield_to_sidecar_8616(callee_func, sidecar_label: str | None) -> bool:
    if callee_func is None or not isinstance(sidecar_label, str):
        return False
    callee_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
    if callee_name is None or callee_name.startswith("sub_"):
        return True
    if callee_name == sidecar_label:
        return False
    block_addrs = tuple(getattr(callee_func, "block_addrs_set", ()) or ())
    return len(block_addrs) == 0


def _cod_metadata_for_function_8616(project, func_addr: int):
    original_project = getattr(project, "_inertia_original_project", None)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    project_variants = [project]
    if original_project is not None:
        project_variants.append(original_project)

    addr_candidates = [func_addr]
    if isinstance(original_delta, int):
        addr_candidates.append(func_addr + original_delta)
        rebased = func_addr - original_delta
        if rebased >= 0:
            addr_candidates.append(rebased)

    normalized_addr_candidates: list[int] = []
    for candidate in addr_candidates:
        if candidate not in normalized_addr_candidates:
            normalized_addr_candidates.append(candidate)

    for candidate_project in project_variants:
        lst_metadata = getattr(candidate_project, "_inertia_lst_metadata", None)
        cod_path = getattr(lst_metadata, "cod_path", None)
        if not cod_path:
            continue
        binary_path = getattr(getattr(getattr(candidate_project, "loader", None), "main_object", None), "binary", None)
        cache = getattr(candidate_project, "_inertia_sidecar_cod_metadata_cache", None)
        if not isinstance(cache, dict):
            cache = {}
            setattr(candidate_project, "_inertia_sidecar_cod_metadata_cache", cache)

        for candidate_addr in normalized_addr_candidates:
            function = getattr(getattr(candidate_project, "kb", None), "functions", None)
            function = getattr(function, "function", lambda **_: None)(addr=candidate_addr, create=False)
            function_name = getattr(function, "name", None)
            if not isinstance(function_name, str) or not function_name:
                function_name = _sidecar_label_for_target_8616(project, candidate_addr)
            if not isinstance(function_name, str) or not function_name:
                continue

            proc_kind = (getattr(lst_metadata, "cod_proc_kinds", {}).get(candidate_addr) or "NEAR").upper()
            name_candidates = [function_name]
            if function_name.startswith("_"):
                stripped = function_name.lstrip("_")
                if stripped:
                    name_candidates.append(stripped)
            else:
                name_candidates.append(f"_{function_name}")

            for candidate in name_candidates:
                cache_key = (str(cod_path), candidate, proc_kind)
                if cache_key in cache:
                    return cache[cache_key]
                try:
                    metadata = extract_cod_proc_metadata(Path(cod_path), candidate, proc_kind)
                except Exception as ex:
                    log.debug(
                        "COD metadata lookup failed path=%s candidate=%s kind=%s: %s",
                        cod_path,
                        candidate,
                        proc_kind,
                        ex,
                    )
                    continue
                cache[cache_key] = metadata
                if binary_path is not None:
                    cache[(str(binary_path), candidate, proc_kind)] = metadata
                return metadata
    return None


def _candidate_target_addrs_from_call_8616(node) -> tuple[int, ...]:
    addrs: list[int] = []
    callee_func = getattr(node, "callee_func", None)
    callee_addr = getattr(callee_func, "addr", None)
    if isinstance(callee_addr, int):
        addrs.append(callee_addr)

    for target in (
        getattr(node, "callee_target", None),
        getattr(callee_func, "name", None),
    ):
        if not isinstance(target, str):
            continue
        normalized = normalize_callee_name_8616(target)
        if not isinstance(normalized, str):
            continue
        match = _SUB_TARGET_RE.match(normalized)
        if match is None:
            match = _NAMESPACED_TARGET_RE.match(target)
        if match is None:
            continue
        try:
            addrs.append(int(match.group("addr"), 16))
        except ValueError:
            continue

    ordered: list[int] = []
    for addr in addrs:
        if addr not in ordered:
            ordered.append(addr)
    return tuple(ordered)


def _rename_call_node_from_sidecar_8616(project, node) -> bool:
    if project is None:
        return False
    renamed = False
    replacement = None
    for target_addr in _candidate_target_addrs_from_call_8616(node):
        replacement = _sidecar_label_for_target_8616(project, target_addr)
        if isinstance(replacement, str):
            break
    if not isinstance(replacement, str):
        return False

    callee_func = getattr(node, "callee_func", None)
    current_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
    current_target = normalize_callee_name_8616(getattr(node, "callee_target", None))
    if callee_func is not None and (current_name is None or current_name.startswith("sub_")):
        callee_func.name = replacement
        renamed = True
    if current_target is None or current_target.startswith("sub_"):
        node.callee_target = replacement
        renamed = True
    return renamed


def _call_node_name_8616(node) -> str | None:
    callee_func = getattr(node, "callee_func", None)
    for raw in (
        getattr(callee_func, "name", None),
        getattr(node, "callee_target", None),
    ):
        normalized = normalize_callee_name_8616(raw)
        if isinstance(normalized, str) and normalized:
            return normalized
    return None


def _is_runtime_segment_helper_call_8616(node) -> bool:
    tags = getattr(node, "tags", None)
    marker_name = tags.get("inertia_x86_16_runtime_segment_helper") if isinstance(tags, dict) else None
    if isinstance(marker_name, str) and marker_name.upper() in _RUNTIME_SEGMENT_HELPERS_8616:
        return True
    call_name = _call_node_name_8616(node)
    return isinstance(call_name, str) and call_name.upper() in _RUNTIME_SEGMENT_HELPERS_8616


def _call_name_is_unknown_8616(name: str | None) -> bool:
    return name is None or name.startswith("sub_") or name == "CallReturn"


def _resolve_dirty_virtual_expr_8616(node):
    dirty = getattr(node, "dirty", None)
    if dirty is None:
        return None
    varid = getattr(dirty, "varid", None)
    if not isinstance(varid, int):
        return None
    codegen = getattr(node, "codegen", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return None
    target_name = f"vvar_{varid}"
    matches = []
    for stmt in _iter_c_nodes_deep_8616(root):
        if not isinstance(stmt, structured_c.CAssignment):
            continue
        lhs = getattr(stmt, "lhs", None)
        if not isinstance(lhs, structured_c.CVariable):
            continue
        lhs_name = getattr(lhs, "name", None) or getattr(getattr(lhs, "variable", None), "name", None)
        if lhs_name != target_name:
            continue
        matches.append(getattr(stmt, "rhs", None))
        if len(matches) > 1:
            return None
    return matches[0] if len(matches) == 1 else None


def _call_node_matches_summary_8616(project, node, summary) -> bool:
    if node is None or summary is None:
        return False
    call_name = _call_node_name_8616(node)
    if bool(getattr(summary, "stack_probe_helper", False)) and _is_stack_probe_call_name_8616(call_name):
        return True

    target_addr = getattr(summary, "target_addr", None)
    if isinstance(target_addr, int):
        for candidate_addr in _candidate_target_addrs_from_call_8616(node):
            if candidate_addr == target_addr:
                return True
        for candidate_name in (
            _sidecar_label_for_target_8616(project, target_addr),
            normalize_callee_name_8616(getattr(_lookup_callee_function_8616(project, target_addr), "name", None)),
        ):
            if isinstance(candidate_name, str) and candidate_name == call_name:
                return True
    return False


def _source_name_matches_target_8616(project, target_addr: int | None, expected_source_name: str | None) -> bool:
    if not isinstance(expected_source_name, str) or not expected_source_name:
        return False
    normalized_expected = normalize_callee_name_8616(expected_source_name)
    if not isinstance(normalized_expected, str):
        return False
    if not isinstance(target_addr, int):
        return False
    for candidate_name in (
        _sidecar_label_for_target_8616(project, target_addr),
        normalize_callee_name_8616(getattr(_lookup_callee_function_8616(project, target_addr), "name", None)),
    ):
        if isinstance(candidate_name, str) and candidate_name == normalized_expected:
            return True
    functions = getattr(getattr(project, "kb", None), "functions", None)
    lookup = getattr(functions, "function", None)
    try:
        function = lookup(name=normalized_expected, create=False) if callable(lookup) else None
    except TypeError:
        function = None
    return getattr(function, "addr", None) == target_addr


def _align_cod_call_names_8616(project, codegen) -> bool:
    # Evidence-based rename from optional COD/debug metadata.
    # Safe by default: if no metadata exists, this pass is a no-op.
    if os.environ.get("INERTIA_DISABLE_COD_CALL_NAME_ALIGNMENT"):
        return False
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return False
    cod_metadata = _cod_metadata_for_function_8616(project, func_addr)
    cod_call_names = tuple(
        normalize_callee_name_8616(name)
        for name in getattr(cod_metadata, "call_names", ()) or ()
        if isinstance(normalize_callee_name_8616(name), str)
    )
    if not cod_call_names:
        return False

    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
    call_nodes = [
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CFunctionCall) and not _is_runtime_segment_helper_call_8616(node)
    ]
    if not call_nodes:
        return False

    changed = False
    cod_idx = 0
    for node in call_nodes:
        current_name = _call_node_name_8616(node)
        if not _call_name_is_unknown_8616(current_name):
            if cod_idx < len(cod_call_names) and cod_call_names[cod_idx] == current_name:
                cod_idx += 1
            elif cod_idx == 0 and current_name in cod_call_names:
                # Initial alignment tolerance: allow one-time seek when the first
                # emitted call appears later in the COD sequence (e.g., stack probe skipped).
                cod_idx = cod_call_names.index(current_name) + 1
            continue
        if cod_idx >= len(cod_call_names):
            break
        replacement = cod_call_names[cod_idx]
        cod_idx += 1
        if not isinstance(replacement, str) or not replacement or replacement.startswith("sub_"):
            continue
        callee_func = getattr(node, "callee_func", None)
        if callee_func is not None and getattr(callee_func, "name", None) != replacement:
            callee_func.name = replacement
            changed = True
        if getattr(node, "callee_target", None) != replacement:
            node.callee_target = replacement
            changed = True
    return changed


def _normalize_call_target_names_8616(codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    project = getattr(codegen, "project", None)
    changed = False
    allow_call_target_rewrites = bool(int(os.environ.get("INERTIA_ENABLE_CALLSITE_TARGET_REWRITES", "0")))
    stats = _ensure_callsite_materialization_stats_8616(codegen)
    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        summary_map = {}
    else:
        _refresh_callsite_summary_node_ids_8616(codegen, summary_map)
    source_call_names = _cod_source_call_names_8616(project, getattr(cfunc, "addr", None))
    source_call_idx = 0
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        if _is_runtime_segment_helper_call_8616(node):
            continue
        summary = summary_map.get(id(node))
        expected_source_name = None
        is_stack_probe_helper = bool(getattr(summary, "stack_probe_helper", False)) if summary is not None else False
        if not is_stack_probe_helper and source_call_idx < len(source_call_names):
            expected_source_name = source_call_names[source_call_idx]
            source_call_idx += 1
        target_addr = getattr(summary, "target_addr", None) if summary is not None else None
        summary_arg_count = int(getattr(summary, "arg_count", 0) or 0) if summary is not None else 0

        callee_target = getattr(node, "callee_target", None)
        normalized_target = normalize_callee_name_8616(callee_target)
        if isinstance(normalized_target, str) and normalized_target != callee_target:
            node.callee_target = normalized_target
            changed = True

        callee_func = getattr(node, "callee_func", None)
        callee_name = getattr(callee_func, "name", None)
        normalized_name = normalize_callee_name_8616(callee_name)
        if callee_func is not None and isinstance(normalized_name, str) and normalized_name != callee_name:
            callee_func.name = normalized_name
            changed = True
            callee_name = normalized_name

        # Evidence reconciliation: if source call names exist for this function and
        # the current helper identity disagrees, prefer source-evidenced call name.
        # This is conservative: only applies to known helpers with matching arity.
        if isinstance(expected_source_name, str) and expected_source_name:
            expected_arity = _expected_arg_count_for_known_callee_8616(expected_source_name)
            current_call_name = _call_node_name_8616(node)
            current_arity = len(tuple(getattr(node, "args", ()) or ()))
            current_expected_arity = (
                _expected_arg_count_for_known_callee_8616(current_call_name)
                if isinstance(current_call_name, str) and current_call_name
                else None
            )
            callsite_arity = summary_arg_count if summary_arg_count > 0 else current_arity
            current_is_unknown = _call_name_is_unknown_8616(current_call_name)
            source_name_proved = _source_name_matches_target_8616(project, target_addr, expected_source_name)
            if (
                isinstance(expected_arity, int)
                and expected_arity >= 0
                and callsite_arity == expected_arity
                and isinstance(current_call_name, str)
                and current_call_name
                and current_call_name != expected_source_name
                and (current_is_unknown or source_name_proved)
                and (
                    current_expected_arity is None
                    or current_expected_arity != expected_arity
                    or current_expected_arity == callsite_arity
                )
            ):
                if getattr(node, "callee_func", None) is not None:
                    node.callee_func = None
                    changed = True
                if getattr(node, "callee_target", None) != expected_source_name:
                    node.callee_target = expected_source_name
                    changed = True

        if isinstance(target_addr, int):
            candidate = _lookup_callee_function_8616(project, target_addr)
            if candidate is not None and getattr(node, "callee_func", None) is not candidate:
                current_call_name = _call_node_name_8616(node)
                candidate_name = normalize_callee_name_8616(getattr(candidate, "name", None))
                # Target-address evidence is the primary owner for direct-call identity.
                # Only refuse replacement when source-evidenced name is proved for this
                # exact target and conflicts with the target-derived candidate name.
                source_conflict = (
                    isinstance(expected_source_name, str)
                    and expected_source_name
                    and _source_name_matches_target_8616(project, target_addr, expected_source_name)
                    and isinstance(candidate_name, str)
                    and candidate_name
                    and expected_source_name != candidate_name
                )
                if not source_conflict:
                    node.callee_func = candidate
                    changed = True
                    callee_func = candidate
            current_addr = getattr(getattr(node, "callee_func", None), "addr", None)
            matched_function = candidate if candidate is not None else getattr(node, "callee_func", None)
            if (
                not _function_matches_target_addr_8616(matched_function, target_addr)
                and isinstance(expected_source_name, str)
                and isinstance(current_addr, int)
            ):
                stats.stale_target_rejected_count += 1
                node.callee_func = None
                if getattr(node, "callee_target", None) != expected_source_name:
                    node.callee_target = expected_source_name
                    changed = True
                changed = True
                callee_func = None
            elif (
                isinstance(expected_source_name, str)
                and callee_func is not None
            and _source_name_matches_target_8616(project, target_addr, expected_source_name)
            ):
                current_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
                if current_name != expected_source_name:
                    callee_func.name = expected_source_name
                    changed = True
                if getattr(node, "callee_target", None) != expected_source_name:
                    node.callee_target = expected_source_name
                    changed = True

        if (
            isinstance(expected_source_name, str)
            and expected_source_name
            and _call_name_is_unknown_8616(_call_node_name_8616(node))
        ):
            if getattr(node, "callee_target", None) != expected_source_name:
                node.callee_target = expected_source_name
                changed = True
            callee_func = getattr(node, "callee_func", None)
            if callee_func is not None and getattr(callee_func, "name", None) != expected_source_name:
                callee_func.name = expected_source_name
                changed = True

        if _rename_call_node_from_sidecar_8616(project, node):
            changed = True

    if _align_cod_call_names_8616(project, codegen):
        changed = True

    _finalize_callsite_materialization_stats_8616(codegen)
    return changed


def _finalize_callsite_materialization_stats_8616(codegen) -> CallsiteMaterializationStats:
    previous = _ensure_callsite_materialization_stats_8616(codegen)
    stats = CallsiteMaterializationStats(
        bp_slot_arg_value_normalized_count=int(
            getattr(previous, "bp_slot_arg_value_normalized_count", 0) or 0
        ),
        pointer_arg_materialized_count=int(
            getattr(previous, "pointer_arg_materialized_count", 0) or 0
        ),
        push_order_reversed_count=int(
            getattr(previous, "push_order_reversed_count", 0) or 0
        ),
        consumed_outgoing_stack_placeholder_count=int(
            getattr(previous, "consumed_outgoing_stack_placeholder_count", 0) or 0
        ),
        stale_target_rejected_count=int(
            getattr(previous, "stale_target_rejected_count", 0) or 0
        ),
    )
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        summary_map = {}
    else:
        _refresh_callsite_summary_node_ids_8616(codegen, summary_map)
    project = getattr(codegen, "project", None)
    source_call_names = _cod_source_call_names_8616(project, getattr(cfunc, "addr", None))
    source_call_idx = 0
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        summary = summary_map.get(id(node))
        if summary is None or bool(getattr(summary, "stack_probe_helper", False)):
            continue
        expected_source_name = None
        if source_call_idx < len(source_call_names):
            expected_source_name = source_call_names[source_call_idx]
            source_call_idx += 1
        stats.callsite_count += 1
        target_addr = getattr(summary, "target_addr", None)
        if isinstance(target_addr, int):
            stats.call_target_fact_count += 1
            if _function_matches_target_addr_8616(getattr(node, "callee_func", None), target_addr):
                stats.call_target_materialized_count += 1
            else:
                for candidate_addr in _candidate_target_addrs_from_call_8616(node):
                    if candidate_addr == target_addr:
                        stats.call_target_materialized_count += 1
                        break
                else:
                    call_name = _call_node_name_8616(node)
                    if isinstance(expected_source_name, str) and call_name == expected_source_name:
                        stats.call_target_materialized_count += 1
        known_arg_count = _expected_arg_count_for_known_callee_8616(_call_node_name_8616(node) or "")
        arg_fact_count = int(getattr(summary, "arg_count", 0) or 0)
        if known_arg_count == 0:
            arg_fact_count = 0
        if arg_fact_count > 0:
            stats.call_arg_fact_count += arg_fact_count
            materialized_args = tuple(getattr(node, "args", ()) or ())
            stats.call_arg_materialized_count += min(arg_fact_count, len(materialized_args))

        expected_arg_count = known_arg_count
        if expected_arg_count is not None and len(tuple(getattr(node, "args", ()) or ())) != expected_arg_count:
            stats.known_prototype_arg_mismatch_count += 1
            stats.failure_count += 1

    if stats.call_target_fact_count > stats.call_target_materialized_count:
        stats.failure_count += stats.call_target_fact_count - stats.call_target_materialized_count
    if stats.call_arg_fact_count > stats.call_arg_materialized_count:
        stats.failure_count += stats.call_arg_fact_count - stats.call_arg_materialized_count

    codegen._inertia_callsite_materialization_stats = stats
    _sync_callsite_materialization_stats_8616(codegen)

    if stats.known_prototype_arg_mismatch_count:
        raise PipelineHardError("known prototype call argument mismatch", layer="callsite")
    # Callsite summary evidence can be partial (especially for tiny helpers /
    # aggressively transformed CFG edges). Keep this as a diagnostic counter
    # instead of hard-aborting the whole function decompilation.
    if stats.call_target_fact_count > stats.call_target_materialized_count:
        log.debug(
            "callsite materialization incomplete: targets fact=%d materialized=%d",
            stats.call_target_fact_count,
            stats.call_target_materialized_count,
        )
    if stats.call_arg_fact_count > stats.call_arg_materialized_count:
        log.debug(
            "callsite materialization incomplete: args fact=%d materialized=%d",
            stats.call_arg_fact_count,
            stats.call_arg_materialized_count,
        )
    return stats


def _cod_source_call_names_8616(project, func_addr: int) -> tuple[str, ...]:
    cod_metadata = _cod_metadata_for_function_8616(project, func_addr)
    if cod_metadata is None:
        return ()
    names: list[str] = []
    for item in getattr(cod_metadata, "call_sources", ()) or ():
        if not isinstance(item, tuple) or len(item) != 2:
            continue
        normalized = normalize_callee_name_8616(item[0])
        if isinstance(normalized, str) and normalized and not normalized.startswith("sub_"):
            names.append(normalized)
    if not names:
        for raw_name in getattr(cod_metadata, "call_names", ()) or ():
            normalized = normalize_callee_name_8616(raw_name)
            if isinstance(normalized, str) and normalized and not normalized.startswith("sub_"):
                names.append(normalized)
    return tuple(names)


def _cod_source_call_names_for_symbol_8616(project, symbol_name: str | None) -> tuple[str, ...]:
    if not isinstance(symbol_name, str) or not symbol_name:
        return ()
    lst_metadata = getattr(project, "_inertia_lst_metadata", None)
    cod_path = getattr(lst_metadata, "cod_path", None)
    if not cod_path:
        return ()
    proc_kind = "NEAR"
    for candidate in (symbol_name, symbol_name.lstrip("_"), f"_{symbol_name.lstrip('_')}"):
        if not candidate:
            continue
        try:
            metadata = extract_cod_proc_metadata(Path(cod_path), candidate, proc_kind)
        except Exception:
            continue
        names: list[str] = []
        for raw_name in getattr(metadata, "call_names", ()) or ():
            normalized = normalize_callee_name_8616(raw_name)
            if isinstance(normalized, str) and normalized and not normalized.startswith("sub_"):
                names.append(normalized)
        if names:
            return tuple(names)
    return ()


def _summary_type_8616(project, width: int):
    arch = getattr(project, "arch", None)
    if width >= 4:
        ty = SimTypeLong(False)
    else:
        ty = SimTypeShort(False)
    return ty.with_arch(arch) if arch is not None and hasattr(ty, "with_arch") else ty


def _word_type_8616(project):
    return _summary_type_8616(project, 2)


def _summary_return_type_8616(project, summary):
    if getattr(summary, "return_register", None) == "ax" and getattr(summary, "return_used", None) is True:
        return _summary_type_8616(project, 2)
    ty = SimTypeBottom(label="void")
    arch = getattr(project, "arch", None)
    return ty.with_arch(arch) if arch is not None and hasattr(ty, "with_arch") else ty


def _prototype_needs_summary_8616(prototype) -> bool:
    if prototype is None:
        return True
    args = tuple(getattr(prototype, "args", ()) or ())
    return_type = getattr(prototype, "returnty", None)
    if args:
        return False
    return type(return_type) is SimTypeBottom


def _apply_summary_prototype_8616(project, callee_func, summary) -> bool:
    if callee_func is None or not _prototype_needs_summary_8616(getattr(callee_func, "prototype", None)):
        return False
    arg_count = getattr(summary, "arg_count", None)
    if not isinstance(arg_count, int):
        return False
    arg_widths = tuple(getattr(summary, "arg_widths", ()) or ())
    known_arg_count = _expected_arg_count_for_known_callee_8616(getattr(callee_func, "name", None) or "")
    if isinstance(known_arg_count, int) and known_arg_count > arg_count:
        arg_count = known_arg_count
    if len(arg_widths) < arg_count:
        arg_widths = arg_widths + tuple(2 for _ in range(arg_count - len(arg_widths)))
    elif len(arg_widths) > arg_count:
        arg_widths = arg_widths[:arg_count]
    arg_types = [_summary_type_8616(project, width) for width in arg_widths]
    arg_names = _normalize_arg_names_8616(None, len(arg_types))
    prototype = SimTypeFunction(
        arg_types,
        _summary_return_type_8616(project, summary),
        arg_names=arg_names,
        variadic=False,
    )
    arch = getattr(project, "arch", None)
    if arch is not None and hasattr(prototype, "with_arch"):
        prototype = prototype.with_arch(arch)
    callee_func.prototype = prototype
    callee_func.is_prototype_guessed = True
    return True


def _attach_callsite_summaries_8616(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return False
    function = project.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        return False
    patch_direct_call_sites(function)

    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
    call_nodes = [
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CFunctionCall) and not _is_runtime_segment_helper_call_8616(node)
    ]
    callsite_addrs = tuple(sorted(getattr(function, "get_call_sites", lambda: [])() or ()))
    if not call_nodes or not callsite_addrs:
        return False

    def _node_callsite_addr(node) -> int | None:
        tags = getattr(node, "tags", None)
        if isinstance(tags, dict):
            for key in ("ins_addr", "insn_addr", "stmt_addr", "addr"):
                value = tags.get(key)
                if isinstance(value, int):
                    return value
        value = getattr(node, "addr", None)
        return value if isinstance(value, int) else None

    changed = False
    allow_call_target_rewrites = bool(int(os.environ.get("INERTIA_ENABLE_CALLSITE_TARGET_REWRITES", "0")))
    stats = _ensure_callsite_materialization_stats_8616(codegen)
    summary_map = dict(getattr(codegen, "_inertia_callsite_summaries", {}) or {})
    source_call_names = _cod_source_call_names_8616(project, func_addr)
    source_call_idx = 0
    debug_callsites = bool(os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"))
    if debug_callsites:
        try:
            callsite_dbg = []
            for cs_addr in callsite_addrs:
                tgt = getattr(function, "get_call_target", lambda _addr: None)(cs_addr)
                callee = project.kb.functions.function(addr=tgt, create=False) if isinstance(tgt, int) else None
                callsite_dbg.append(
                    (
                        hex(cs_addr),
                        hex(tgt) if isinstance(tgt, int) else None,
                        normalize_callee_name_8616(getattr(callee, "name", None)) if callee is not None else None,
                    )
                )
            log.warning(
                "[callsite-summary] function=%#x callsites=%r source_calls=%r",
                int(func_addr),
                callsite_dbg,
                tuple(source_call_names),
            )
        except Exception:
            pass
    nodes_by_callsite: dict[int, list[CFunctionCall]] = {}
    remaining_nodes: list[CFunctionCall] = []
    for node in call_nodes:
        callsite_addr = _node_callsite_addr(node)
        if isinstance(callsite_addr, int):
            nodes_by_callsite.setdefault(callsite_addr, []).append(node)
        else:
            remaining_nodes.append(node)

    ordered_pairs: list[tuple[CFunctionCall, int]] = []
    used_node_ids: set[int] = set()
    unmatched_callsites: list[int] = []
    for callsite_addr in callsite_addrs:
        matched_nodes = nodes_by_callsite.get(callsite_addr)
        if matched_nodes:
            summary = summarize_x86_16_callsite(function, callsite_addr)
            chosen_index = None
            if summary is not None:
                for idx, node in enumerate(matched_nodes):
                    if _call_node_matches_summary_8616(project, node, summary):
                        chosen_index = idx
                        break
            if chosen_index is not None:
                node = matched_nodes.pop(chosen_index)
                ordered_pairs.append((node, callsite_addr))
                used_node_ids.add(id(node))
            else:
                # Do not force-bind by stale/ambiguous callsite tags.
                # Leave this callsite for evidence-based matching in the next lane.
                unmatched_callsites.append(callsite_addr)
        else:
            unmatched_callsites.append(callsite_addr)

    remaining_nodes.extend(node for node in call_nodes if id(node) not in used_node_ids and node not in remaining_nodes)
    still_unmatched_callsites: list[int] = []
    if remaining_nodes and unmatched_callsites:
        available_nodes = list(remaining_nodes)
        for callsite_addr in unmatched_callsites:
            summary = summarize_x86_16_callsite(function, callsite_addr)
            matched_index = None
            if summary is not None:
                for idx, node in enumerate(available_nodes):
                    if _call_node_matches_summary_8616(project, node, summary):
                        matched_index = idx
                        break
            if matched_index is None:
                still_unmatched_callsites.append(callsite_addr)
                continue
            node = available_nodes.pop(matched_index)
            ordered_pairs.append((node, callsite_addr))
            used_node_ids.add(id(node))
        remaining_nodes = available_nodes
    if len(remaining_nodes) == 1 and len(still_unmatched_callsites) == 1:
        ordered_pairs.append((remaining_nodes[0], still_unmatched_callsites[0]))

    for node, callsite_addr in ordered_pairs:
        summary = summarize_x86_16_callsite(function, callsite_addr)
        if summary is None:
            continue
        if debug_callsites:
            log.warning(
                "[callsite-summary] map node_id=%#x callsite=%#x target=%r name_before=%r",
                id(node),
                callsite_addr,
                getattr(summary, "target_addr", None),
                _call_node_name_8616(node),
            )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-attach] function=%#x node=%s callsite=%#x summary_args=%r summary_sources=%r",
                func_addr,
                _call_node_name_8616(node),
                callsite_addr,
                getattr(summary, "arg_widths", None),
                getattr(summary, "push_arg_sources", None),
            )
        expected_source_name = None
        if not bool(getattr(summary, "stack_probe_helper", False)) and source_call_idx < len(source_call_names):
            expected_source_name = source_call_names[source_call_idx]
            source_call_idx += 1
        if summary_map.get(id(node)) != summary:
            summary_map[id(node)] = summary
            record_callsite_summary_fact_8616(codegen, summary, node_id=id(node), attached=True)
            # Metadata-only update: do not mark AST as changed.
        target_addr = summary.target_addr
        if not isinstance(target_addr, int):
            continue
        if not allow_call_target_rewrites:
            continue
        callee_func = getattr(node, "callee_func", None)
        candidate = _lookup_callee_function_8616(project, target_addr)
        if candidate is not None:
            current_addr = getattr(callee_func, "addr", None)
            candidate_addr = getattr(candidate, "addr", None)
            if callee_func is None or (isinstance(current_addr, int) and isinstance(candidate_addr, int) and current_addr != candidate_addr):
                node.callee_func = candidate
                changed = True
                callee_func = candidate
        sidecar_label = _sidecar_label_for_target_8616(project, target_addr)
        if callee_func is None and isinstance(sidecar_label, str) and getattr(node, "callee_target", None) != sidecar_label:
            node.callee_target = sidecar_label
            changed = True
        if _callee_name_should_yield_to_sidecar_8616(callee_func, sidecar_label):
            callee_func.name = sidecar_label
            changed = True
        callee_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
        current_addr = getattr(callee_func, "addr", None)
        matched_function = candidate if candidate is not None else callee_func
        if (
            not _function_matches_target_addr_8616(matched_function, target_addr)
            and isinstance(expected_source_name, str)
            and isinstance(target_addr, int)
            and isinstance(current_addr, int)
        ):
            stats.stale_target_rejected_count += 1
            node.callee_func = None
            callee_func = None
            callee_name = None
            changed = True
        if (
            isinstance(expected_source_name, str)
            and callee_func is not None
            and _source_name_matches_target_8616(project, target_addr, expected_source_name)
            and callee_name != expected_source_name
        ):
            callee_func.name = expected_source_name
            changed = True
        callee_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
        if callee_name is not None and getattr(node, "callee_target", None) != callee_name:
            node.callee_target = callee_name
            changed = True
        elif (
            callee_name is None
            and isinstance(expected_source_name, str)
            and _source_name_matches_target_8616(project, target_addr, expected_source_name)
            and getattr(node, "callee_target", None) != expected_source_name
        ):
            node.callee_target = expected_source_name
            changed = True
        elif _rename_call_node_from_sidecar_8616(project, node):
            changed = True
    if summary_map:
        codegen._inertia_callsite_summaries = summary_map
    return changed


def _refresh_callsite_summary_node_ids_8616(codegen, summary_map: dict[int, object]) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
    if root is None:
        return False

    def _node_callsite_addr(node) -> int | None:
        tags = getattr(node, "tags", None)
        if isinstance(tags, dict):
            for key in ("ins_addr", "insn_addr", "stmt_addr", "addr"):
                value = tags.get(key)
                if isinstance(value, int):
                    return value
        value = getattr(node, "addr", None)
        return value if isinstance(value, int) else None

    call_nodes = [
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CFunctionCall) and not _is_runtime_segment_helper_call_8616(node)
    ]
    nodes_by_callsite: dict[int, CFunctionCall] = {}
    current_node_ids: set[int] = set()
    for node in call_nodes:
        current_node_ids.add(id(node))
        callsite_addr = _node_callsite_addr(node)
        if isinstance(callsite_addr, int) and callsite_addr not in nodes_by_callsite:
            nodes_by_callsite[callsite_addr] = node

    changed = False
    refreshed = dict(summary_map)
    for node_id, summary in tuple(summary_map.items()):
        if node_id in current_node_ids:
            continue
        callsite_addr = getattr(summary, "callsite_addr", None)
        if not isinstance(callsite_addr, int):
            continue
        node = nodes_by_callsite.get(callsite_addr)
        if node is None:
            continue
        refreshed[id(node)] = summary
        refreshed.pop(node_id, None)
        changed = True

    if changed:
        codegen._inertia_callsite_summaries = refreshed
        summary_map.clear()
        summary_map.update(refreshed)
    return changed


def _materialize_callsite_prototypes_8616(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict) or not summary_map:
        return False
    def _ctype_for_width(width: object) -> str:
        if isinstance(width, int) and width >= 4:
            return "unsigned long"
        if isinstance(width, int) and width == 1:
            return "unsigned char"
        return "unsigned short"

    def _prototype_decl_from_summary(name: str, summary) -> str | None:
        if not isinstance(name, str) or re.fullmatch(r"[A-Za-z_]\w*", name) is None:
            return None
        arg_count = getattr(summary, "arg_count", None)
        if not isinstance(arg_count, int) or arg_count < 0:
            return None
        arg_widths = tuple(getattr(summary, "arg_widths", ()) or ())
        if len(arg_widths) != arg_count:
            arg_widths = tuple(2 for _ in range(arg_count))
        args = "void" if arg_count == 0 else ", ".join(
            f"{_ctype_for_width(width)} a{idx}" for idx, width in enumerate(arg_widths)
        )
        return_type = (
            _ctype_for_width(2)
            if getattr(summary, "return_register", None) == "ax" and getattr(summary, "return_used", None) is True
            else "int"
        )
        return f"{return_type} {name}({args});"

    prototype_decls: list[str] = []
    seen_decls: set[str] = set(getattr(codegen, "_inertia_callsite_prototype_decls", ()) or ())
    changed = False
    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None)
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        summary = summary_map.get(id(node))
        if summary is None:
            continue
        if getattr(summary, "arg_count", None) == 0 and tuple(getattr(node, "args", ()) or ()):
            continue
        call_name = _call_node_name_8616(node)
        if preferred_known_helper_signature_decl(call_name or "") is not None:
            continue
        if _apply_summary_prototype_8616(project, getattr(node, "callee_func", None), summary):
            changed = True
        if bool(getattr(summary, "stack_probe_helper", False)):
            continue
        if getattr(summary, "arg_count", None) == 0:
            continue
        decl = _prototype_decl_from_summary(call_name or "", summary)
        if decl is not None and decl not in seen_decls:
            seen_decls.add(decl)
            prototype_decls.append(decl)
    if prototype_decls:
        existing = tuple(getattr(codegen, "_inertia_callsite_prototype_decls", ()) or ())
        codegen._inertia_callsite_prototype_decls = existing + tuple(prototype_decls)
    return changed


def _materialize_callsite_stack_arguments_8616(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    func_addr = getattr(cfunc, "addr", None)
    cod_metadata = _cod_metadata_for_function_8616(project, func_addr) if isinstance(func_addr, int) else None
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        summary_map = {}
    _refresh_callsite_summary_node_ids_8616(codegen, summary_map)
    typed_stack_probe_facts = build_typed_stack_probe_return_facts_8616(codegen)
    record_callsite_summary_map_facts_8616(codegen, summary_map)
    stats = _ensure_callsite_materialization_stats_8616(codegen)

    changed = False
    materialized_callsite_metadata_ids: dict[int, tuple[int, ...]] = {}
    synthetic_stack_cvars: dict[int, structured_c.CVariable] = {}

    def _arg_width_from_expr(expr) -> int:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        type_ = getattr(node, "type", None)
        bits = getattr(type_, "size", None)
        arch = getattr(getattr(codegen, "project", None), "arch", None)
        byte_width = getattr(arch, "byte_width", None)
        if isinstance(bits, int) and bits > 0 and isinstance(byte_width, int) and byte_width > 0:
            return max(bits // byte_width, 1)
        variable = getattr(node, "variable", None)
        size = getattr(variable, "size", None)
        if isinstance(size, int) and size > 0:
            return size
        return 2

    def _is_segment_register_value_expr(expr) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, CBinaryOp) and node.op in {"Shr", "Shl", "And", "Or"}:
            return _is_segment_register_value_expr(node.lhs)
        variable = getattr(node, "variable", None)
        name = getattr(variable, "name", None) or getattr(node, "name", None)
        if isinstance(name, str) and name.lower() in {"cs", "ds", "es", "ss"}:
            return True
        return False

    def _all_arg_exprs_are_non_segment_registers(args) -> bool:
        return bool(args) and all(not _is_segment_register_value_expr(arg) for arg in args)

    def _is_plain_register_value_expr(expr) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, structured_c.CVariable):
            return False
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimRegisterVariable):
            return False
        return not _is_segment_register_value_expr(node)

    def _plain_register_expr_key(expr):
        if not _is_plain_register_value_expr(expr):
            return None
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        variable = getattr(node, "variable", None)
        if variable is None:
            return None
        return (
            getattr(variable, "reg", None),
            getattr(variable, "size", None),
        )

    def _outgoing_stack_value_expr_key(expr):
        if not _is_outgoing_stack_value_carrier_expr(expr):
            return None
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        variable = getattr(node, "variable", None)
        if variable is None:
            return None
        return (
            getattr(variable, "offset", None),
            getattr(variable, "size", None),
            getattr(variable, "base", None),
            getattr(variable, "name", None) or getattr(node, "name", None),
        )

    def _value_expr_key(expr):
        return _plain_register_expr_key(expr) or _outgoing_stack_value_expr_key(expr)

    def _same_value_carrier_identity_expr(expr_a, expr_b) -> bool:
        node_a = expr_a
        while isinstance(node_a, CTypeCast):
            node_a = node_a.expr
        node_b = expr_b
        while isinstance(node_b, CTypeCast):
            node_b = node_b.expr
        if not isinstance(node_a, structured_c.CVariable) or not isinstance(node_b, structured_c.CVariable):
            return False
        key_a = _value_expr_key(node_a)
        key_b = _value_expr_key(node_b)
        if key_a is None or key_b is None or key_a != key_b:
            return False
        var_a = getattr(node_a, "variable", None)
        var_b = getattr(node_b, "variable", None)
        name_a = getattr(var_a, "name", None) or getattr(node_a, "name", None)
        name_b = getattr(var_b, "name", None) or getattr(node_b, "name", None)
        return name_a == name_b

    def _is_outgoing_stack_value_carrier_expr(expr) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, structured_c.CVariable):
            return False
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return False
        offset = getattr(variable, "offset", None)
        if not isinstance(offset, int):
            return False
        if offset < 0 or offset > 2:
            return False
        return True

    def _is_c_ast_node(value) -> bool:
        return type(value).__module__.startswith("angr.analyses.decompiler.structured_codegen")

    def _clone_c_ast_tree(node):
        if not _is_c_ast_node(node):
            return node
        cloned = copy(node)
        for attr in (
            "lhs",
            "rhs",
            "expr",
            "operand",
            "condition",
            "cond",
            "iftrue",
            "iffalse",
            "variable",
            "index",
        ):
            if not hasattr(cloned, attr):
                continue
            value = getattr(cloned, attr, None)
            if _is_c_ast_node(value):
                setattr(cloned, attr, _clone_c_ast_tree(value))
        for attr in ("args", "operands"):
            if not hasattr(cloned, attr):
                continue
            items = getattr(cloned, attr, None)
            if not isinstance(items, (list, tuple)):
                continue
            rebuilt = [_clone_c_ast_tree(item) if _is_c_ast_node(item) else item for item in items]
            setattr(cloned, attr, tuple(rebuilt) if isinstance(items, tuple) else rebuilt)
        return cloned

    def _resolve_recent_value_assignment(expr, statements_prefix: list):
        if not (_is_plain_register_value_expr(expr) or _is_outgoing_stack_value_carrier_expr(expr)):
            return expr, len(statements_prefix)
        expr_value_key = _value_expr_key(expr)
        for stmt_idx in range(len(statements_prefix) - 1, -1, -1):
            stmt = statements_prefix[stmt_idx]
            for assignment in reversed(_iter_assignment_nodes(stmt)):
                lhs, rhs = _assignment_lhs_rhs(assignment)
                if lhs is None or rhs is None:
                    continue
                lhs_value_key = _value_expr_key(lhs)
                if not _same_c_expression_8616(lhs, expr) and not (
                    expr_value_key is not None and lhs_value_key is not None and lhs_value_key == expr_value_key
                ):
                    continue
                if _assignment_lhs_writes_memory(lhs) or _is_segment_register_value_expr(rhs):
                    return None, stmt_idx
                if _same_value_carrier_identity_expr(rhs, expr):
                    return None, stmt_idx
                return rhs, stmt_idx
        return None, None

    def _expr_contains_plain_register_uses(expr) -> bool:
        stack = [expr]
        while stack:
            node = stack.pop()
            if node is None:
                continue
            while isinstance(node, CTypeCast):
                node = node.expr
            if _is_plain_register_value_expr(node) or _is_outgoing_stack_value_carrier_expr(node):
                return True
            for attr in ("lhs", "rhs", "operand", "expr", "condition", "iftrue", "iffalse", "variable", "index"):
                child = getattr(node, attr, None)
                if child is not None:
                    stack.append(child)
            for attr in ("args", "operands"):
                items = getattr(node, attr, None)
                if isinstance(items, (list, tuple)):
                    stack.extend(item for item in items if item is not None)
        return False

    def _resolve_register_carriers_in_expr(expr, statements_prefix: list, seen_keys: set | None = None):
        if not _expr_contains_plain_register_uses(expr):
            return expr

        if seen_keys is None:
            seen_keys = set()
        rewritten = _clone_c_ast_tree(expr)
        failed = False

        def transform(node):
            nonlocal failed
            if failed or not (_is_plain_register_value_expr(node) or _is_outgoing_stack_value_carrier_expr(node)):
                return node
            key = _value_expr_key(node)
            scoped_key = (key, len(statements_prefix)) if key is not None else None
            if scoped_key is not None and scoped_key in seen_keys:
                failed = True
                return node
            resolved, resolved_stmt_idx = _resolve_recent_value_assignment(node, statements_prefix)
            if resolved is None:
                failed = True
                return node
            next_seen = set(seen_keys)
            current_prefix_len = len(statements_prefix)
            next_prefix = (
                statements_prefix[:resolved_stmt_idx]
                if isinstance(resolved_stmt_idx, int) and resolved_stmt_idx >= 0
                else statements_prefix
            )
            if key is not None:
                # Guard only against revisiting the same register identity at the
                # same search horizon. When the horizon shrinks, we still want to
                # walk earlier same-register carriers (ax_9 -> ax_7 -> iParent).
                next_seen.add((key, current_prefix_len))
            resolved = _resolve_register_carriers_in_expr(resolved, next_prefix, next_seen)
            if resolved is None or _expr_contains_plain_register_uses(resolved):
                failed = True
                return node
            return _clone_c_ast_tree(resolved)

        new_root = transform(rewritten)
        if new_root is not rewritten:
            rewritten = new_root
        if failed:
            return None
        _replace_c_children_8616(rewritten, transform)
        if failed or _expr_contains_plain_register_uses(rewritten):
            return None
        return rewritten

    def _stack_slot_fallback_name(offset: int) -> str:
        stack_aliases = getattr(cod_metadata, "stack_aliases", None)
        if isinstance(stack_aliases, dict):
            alias_name = stack_aliases.get(offset)
            if not isinstance(alias_name, str) and isinstance(offset, int):
                alias_name = stack_aliases.get(offset + 1)
            if isinstance(alias_name, str) and alias_name:
                return alias_name
        if offset >= 0:
            slot_index = max(offset // 2, 1)
            return f"arg_{slot_index}"
        slot_index = max(((-offset) + 1) // 2, 1)
        return f"local_{slot_index}"

    def _stack_name_preference(name: str | None) -> int:
        if not isinstance(name, str) or not name:
            return 0
        if name.startswith(("vvar_", "tmp_", "ir_", "s_", "stack_bp_", "stack_sp_")):
            return 1
        if name.startswith(("local_", "arg_")):
            return 3
        return 4

    def _iter_stack_cvar_candidates():
        yielded: set[int] = set()
        variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable, cvar in variables_in_use.items():
                if isinstance(variable, SimStackVariable) and isinstance(cvar, structured_c.CVariable):
                    yielded.add(id(cvar))
                    yield cvar
        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is not None:
            for node in _iter_c_nodes_deep_8616(root):
                if not isinstance(node, structured_c.CVariable):
                    continue
                variable = getattr(node, "variable", None)
                if not isinstance(variable, SimStackVariable):
                    continue
                if id(node) in yielded:
                    continue
                yielded.add(id(node))
                yield node

    def _stack_cvar_for_offset(offset: int, *, size_hint: int = 2, allow_best_match: bool = True):
        existing_synthetic = synthetic_stack_cvars.get(offset)
        if existing_synthetic is not None:
            return _clone_c_ast_tree(existing_synthetic)

        def _register_synthetic_stack_cvar(name: str, variable_type):
            cvar = _materialize_stack_cvar_at_offset_from_facts_8616(codegen, offset, max(size_hint, 1))
            variable = getattr(cvar, "variable", None)
            bound_variable_type = variable_type or _word_type_8616(project)
            if not isinstance(cvar, structured_c.CVariable) or not isinstance(variable, SimStackVariable):
                variable = SimStackVariable(
                    offset,
                    max(size_hint, 1),
                    base="bp",
                    name=name,
                    region=getattr(getattr(codegen, "cfunc", None), "addr", None),
                )
                cvar = structured_c.CVariable(
                    variable,
                    variable_type=bound_variable_type,
                    codegen=codegen,
                )
            else:
                if getattr(variable, "name", None) != name:
                    variable.name = name
                if getattr(cvar, "variable_type", None) is None:
                    cvar.variable_type = bound_variable_type
            synthetic_stack_cvars[offset] = cvar
            variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
            if isinstance(variables_in_use, dict):
                variables_in_use[variable] = cvar
            unified_locals = getattr(getattr(codegen, "cfunc", None), "unified_local_vars", None)
            if isinstance(unified_locals, dict):
                unified_locals[variable] = {(cvar, getattr(cvar, "variable_type", None))}
            return cvar

        stack_aliases = getattr(cod_metadata, "stack_aliases", None)
        exact_alias_name = None
        if isinstance(stack_aliases, dict):
            maybe_alias = stack_aliases.get(offset)
            if not isinstance(maybe_alias, str) and isinstance(offset, int):
                maybe_alias = stack_aliases.get(offset + 1)
            if isinstance(maybe_alias, str) and maybe_alias:
                exact_alias_name = maybe_alias
        if exact_alias_name is not None:
            for cvar in _iter_stack_cvar_candidates():
                variable = getattr(cvar, "variable", None)
                base_offset = getattr(variable, "offset", None)
                name = getattr(variable, "name", None) or getattr(cvar, "name", None)
                if isinstance(variable, SimStackVariable) and base_offset == offset and name == exact_alias_name:
                    return _clone_c_ast_tree(cvar)
            return _clone_c_ast_tree(_register_synthetic_stack_cvar(exact_alias_name, _word_type_8616(project)))

        exact_match = None
        exact_match_score = None
        for cvar in _iter_stack_cvar_candidates():
            variable = getattr(cvar, "variable", None)
            if not isinstance(variable, SimStackVariable):
                continue
            base_offset = getattr(variable, "offset", None)
            if base_offset != offset or not isinstance(base_offset, int):
                continue
            name = getattr(variable, "name", None) or getattr(cvar, "name", None)
            name_pref = _stack_name_preference(name)
            size_hint_ok = 1 if isinstance(size_hint, int) and getattr(variable, "size", None) is not None and int(getattr(variable, "size", 0)) >= int(size_hint) else 0
            score = (name_pref, size_hint_ok, getattr(variable, "size", 0))
            if exact_match_score is None or score > exact_match_score:
                exact_match = cvar
                exact_match_score = score
        if exact_match is not None:
            exact_name = getattr(getattr(exact_match, "variable", None), "name", None) or getattr(exact_match, "name", None)
            if _stack_name_preference(exact_name) <= 1:
                return _clone_c_ast_tree(
                    _register_synthetic_stack_cvar(
                        _stack_slot_fallback_name(offset),
                        getattr(exact_match, "variable_type", None) or _word_type_8616(project),
                    )
                )
            return _clone_c_ast_tree(exact_match)

        best = None
        best_score = None
        if allow_best_match:
            for cvar in _iter_stack_cvar_candidates():
                variable = getattr(cvar, "variable", None)
                if not isinstance(variable, SimStackVariable):
                    continue
                base_offset = getattr(variable, "offset", None)
                size = getattr(variable, "size", None)
                if not isinstance(base_offset, int) or not isinstance(size, int) or size <= 0:
                    continue
                relation = 0
                if base_offset == offset:
                    relation = 4
                elif base_offset <= offset < base_offset + size:
                    relation = 3
                elif abs(base_offset - offset) == 1:
                    relation = 2
                if relation == 0:
                    continue
                name = getattr(variable, "name", None) or getattr(cvar, "name", None)
                name_pref = _stack_name_preference(name)
                score = (
                    1 if name_pref >= 3 else 0,
                    relation,
                    name_pref,
                    1 if isinstance(size_hint, int) and size >= size_hint else 0,
                    size,
                    -abs(base_offset - offset),
                )
                if best_score is None or score > best_score:
                    best = cvar
                    best_score = score

        if best is not None:
            best_name = getattr(getattr(best, "variable", None), "name", None) or getattr(best, "name", None)
            if _stack_name_preference(best_name) <= 1:
                return _clone_c_ast_tree(
                    _register_synthetic_stack_cvar(
                        _stack_slot_fallback_name(offset),
                        getattr(best, "variable_type", None) or _word_type_8616(project),
                    )
                )
            return _clone_c_ast_tree(best)

        return _clone_c_ast_tree(_register_synthetic_stack_cvar(_stack_slot_fallback_name(offset), _word_type_8616(project)))

    def _segment_register_expr(seg_name: str):
        register = getattr(getattr(project, "arch", None), "registers", {}).get(seg_name.lower())
        if not isinstance(register, tuple) or not register:
            return None
        return structured_c.CVariable(
            SimRegisterVariable(register[0], 2, name=seg_name.lower()),
            variable_type=_word_type_8616(project),
            codegen=codegen,
        )

    def _plain_stack_slot_address_offset(node) -> int | None:
        term_root = node
        while isinstance(term_root, CTypeCast):
            term_root = term_root.expr

        def resolve_stack_offset(expr) -> int | None:
            while isinstance(expr, CTypeCast):
                expr = expr.expr
            if isinstance(expr, structured_c.CVariable):
                variable = getattr(expr, "variable", None)
                offset = getattr(variable, "offset", None)
                if isinstance(variable, SimStackVariable) and isinstance(offset, int):
                    return offset
                return None
            if isinstance(expr, structured_c.CIndexedVariable):
                base_expr = getattr(expr, "variable", None)
                index_expr = getattr(expr, "index", None)
                while isinstance(base_expr, CTypeCast):
                    base_expr = base_expr.expr
                if isinstance(base_expr, CUnaryOp) and base_expr.op == "Reference":
                    base_expr = base_expr.operand
                base_offset = resolve_stack_offset(base_expr)
                index_value = getattr(index_expr, "value", None)
                if isinstance(base_offset, int) and isinstance(index_value, int):
                    if index_value % 2 == 0 and abs(index_value) >= 2:
                        return base_offset + index_value // 2
                    return base_offset + index_value
            return None

        def flatten(term, sign: int = 1):
            while isinstance(term, CTypeCast):
                term = term.expr
            if isinstance(term, CBinaryOp) and term.op == "Add":
                return flatten(term.lhs, sign) + flatten(term.rhs, sign)
            if isinstance(term, CBinaryOp) and term.op == "Sub":
                return flatten(term.lhs, sign) + flatten(term.rhs, -sign)
            return [(term, sign)]

        const_total = 0
        stack_offsets: list[int] = []
        for term, sign in flatten(term_root):
            value = getattr(term, "value", None) if isinstance(term, structured_c.CConstant) else None
            if isinstance(value, int):
                const_total += sign * value
                continue
            if isinstance(term, CUnaryOp) and term.op == "Reference":
                inner = term.operand
                offset = resolve_stack_offset(inner)
                if isinstance(offset, int):
                    stack_offsets.append(sign * offset)
                    continue
            offset = resolve_stack_offset(term)
            if isinstance(offset, int):
                stack_offsets.append(sign * offset)
                continue
            return None
        if len(stack_offsets) != 1:
            return None
        return stack_offsets[0] + const_total

    def _plain_bp_stack_load_offset(node) -> int | None:
        node = _clone_c_ast_tree(node)
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, CUnaryOp) or node.op != "Dereference":
            return None
        return _plain_stack_slot_address_offset(node.operand)

    def _normalize_bp_slot_value_arg_8616(expr, *, stack_bindings=None, pointer_arg: bool = False) -> tuple[object, int]:
        replacements = 0
        debug_materialization = bool(os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"))

        def transform(node):
            nonlocal replacements
            displacement = _match_bp_stack_load_8616(node, project)
            if displacement is None:
                displacement = _plain_bp_stack_load_offset(node)
            if displacement is None:
                plain_slot_offset = _plain_stack_slot_address_offset(node)
                if isinstance(plain_slot_offset, int) and (
                    not pointer_arg
                    or _node_contains_placeholder_stack_8616(node)
                    or _node_contains_stable_named_stack_value_8616(node)
                ):
                    displacement = plain_slot_offset
            if displacement is None:
                return node
            replacement = None
            if isinstance(stack_bindings, dict):
                replacement = stack_bindings.get(displacement)
            if replacement is None:
                replacement = _stack_cvar_for_offset(displacement)
            if replacement is None:
                return node
            replacements += 1
            if debug_materialization:
                log.warning(
                    "[call-bp-normalize] function=%#x displacement=%r pointer_arg=%s node=%r replacement=%r",
                    getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                    displacement,
                    pointer_arg,
                    node,
                    replacement,
                )
            return _clone_c_ast_tree(replacement)

        rewritten = _clone_c_ast_tree(expr)
        for _ in range(3):
            changed = False
            new_root = transform(rewritten)
            if new_root is not rewritten:
                rewritten = new_root
                changed = True
            if _replace_c_children_8616(rewritten, transform):
                changed = True
            if not changed:
                break
        return rewritten, replacements

    def _materialize_pointer_arg_8616(expr, *, target_name: str, arg_index: int):
        if not _callee_expects_pointer_arg_8616(target_name, arg_index):
            return expr, False
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, CFunctionCall) and getattr(node, "callee_target", None) in {"SEG_PTR", "MK_FP"}:
            return expr, False
        ds_expr = _segment_register_expr("ds")
        if ds_expr is None:
            return None, False
        target = str(getattr(getattr(codegen, "project", None), "_inertia_c_target", "portable-flat") or "portable-flat")
        helper = "SEG_PTR" if target == "portable-flat" else "MK_FP"
        return (
            structured_c.CFunctionCall(
                helper,
                None,
                [ds_expr, _clone_c_ast_tree(expr)],
                codegen=codegen,
            ),
            True,
        )

    def _direct_expr_from_push_source_8616(source, *, call_name: str | None, arg_index: int):
        if not isinstance(source, tuple) or len(source) < 2:
            return None
        source_kind, source_value = source[0], source[1]
        if source_kind == "bp" and isinstance(source_value, int):
            return _stack_cvar_for_offset(source_value, allow_best_match=False)
        if source_kind == "imm" and isinstance(source_value, int):
            return structured_c.CConstant(source_value, SimTypeShort(False), codegen=codegen)
        if source_kind == "expr" and len(source) == 3 and isinstance(source_value, tuple):
            expr = _direct_expr_from_push_source_8616(source_value, call_name=call_name, arg_index=arg_index)
            if expr is None:
                return None
            for op_name, op_value in source[2]:
                if not isinstance(op_name, str) or not isinstance(op_value, int):
                    return None
                if op_name not in {"add", "sub", "shl", "shr"}:
                    return None
                c_op = {"add": "Add", "sub": "Sub", "shl": "Shl", "shr": "Shr"}[op_name]
                expr = CBinaryOp(
                    c_op,
                    expr,
                    structured_c.CConstant(op_value, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                )
            return expr
        return None

    def _node_contains_stable_named_stack_value_8616(node) -> bool:
        stack = [node]
        while stack:
            current = stack.pop()
            while isinstance(current, CTypeCast):
                current = current.expr
            if _is_stable_named_stack_value_expr_8616(current):
                return True
            for attr in ("lhs", "rhs", "operand", "expr", "condition", "iftrue", "iffalse", "variable", "index"):
                child = getattr(current, attr, None)
                if child is not None:
                    stack.append(child)
            for attr in ("args", "operands"):
                items = getattr(current, attr, None)
                if isinstance(items, (list, tuple)):
                    stack.extend(item for item in items if item is not None)
        return False

    def _node_contains_placeholder_stack_8616(node) -> bool:
        stack = [node]
        while stack:
            current = stack.pop()
            while isinstance(current, CTypeCast):
                current = current.expr
            if isinstance(current, structured_c.CFakeVariable) and getattr(current, "name", None) == "stack_base":
                return True
            if isinstance(current, structured_c.CVariable):
                variable = getattr(current, "variable", None)
                name = getattr(variable, "name", None) or getattr(current, "name", None)
                if name == "stack_base":
                    return True
                if isinstance(variable, SimStackVariable) and isinstance(name, str) and name.startswith(
                    ("arg_", "s_", "stack_", "vvar_", "tmp_", "ir_")
                ):
                    return True
            if current.__class__.__name__ == "CDirtyExpression":
                return True
            for attr in ("lhs", "rhs", "operand", "expr", "condition", "iftrue", "iffalse", "variable", "index"):
                child = getattr(current, attr, None)
                if child is not None:
                    stack.append(child)
            for attr in ("args", "operands"):
                items = getattr(current, attr, None)
                if isinstance(items, (list, tuple)):
                    stack.extend(item for item in items if item is not None)
        return False

    def _debug_expr_8616(node):
        if isinstance(node, CTypeCast):
            return f"Cast({_debug_expr_8616(node.expr)})"
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            name = getattr(variable, "name", None) or getattr(node, "name", None) or "var"
            offset = getattr(variable, "offset", None)
            if isinstance(variable, SimStackVariable) and isinstance(offset, int):
                return f"{name}@{offset}"
            reg = getattr(variable, "reg", None)
            if isinstance(variable, SimRegisterVariable) and reg is not None:
                return f"{name}#{reg}"
            return name
        if isinstance(node, structured_c.CIndexedVariable):
            return f"Index({_debug_expr_8616(node.variable)},{_debug_expr_8616(node.index)})"
        if isinstance(node, structured_c.CConstant):
            return repr(getattr(node, "value", None))
        if isinstance(node, CUnaryOp):
            return f"{node.op}({_debug_expr_8616(node.operand)})"
        if isinstance(node, CBinaryOp):
            return f"{node.op}({_debug_expr_8616(node.lhs)},{_debug_expr_8616(node.rhs)})"
        if isinstance(node, CFunctionCall):
            name = getattr(node, "callee_target", None) or getattr(getattr(node, "callee_func", None), "name", None) or "call"
            return f"{name}({','.join(_debug_expr_8616(arg) for arg in (getattr(node, 'args', ()) or ()))})"
        return node.__class__.__name__

    def _call_arg_semantic_key_8616(node):
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, structured_c.CConstant):
            value = getattr(node, "value", None)
            return ("const", int(value)) if isinstance(value, int) else None
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimStackVariable):
                offset = getattr(variable, "offset", None)
                return ("stack", int(offset)) if isinstance(offset, int) else None
            if isinstance(variable, SimRegisterVariable):
                reg = getattr(variable, "reg", None)
                size = getattr(variable, "size", None)
                return ("reg", int(reg), int(size or 0)) if isinstance(reg, int) else None
            name = getattr(variable, "name", None) or getattr(node, "name", None)
            return ("var", str(name)) if isinstance(name, str) and name else None
        if isinstance(node, CUnaryOp):
            operand_key = _call_arg_semantic_key_8616(node.operand)
            return ("unary", node.op, operand_key) if operand_key is not None else None
        if isinstance(node, CBinaryOp):
            lhs_key = _call_arg_semantic_key_8616(node.lhs)
            rhs_key = _call_arg_semantic_key_8616(node.rhs)
            if lhs_key is None or rhs_key is None:
                return None
            return ("binary", node.op, lhs_key, rhs_key)
        if isinstance(node, CFunctionCall):
            arg_keys = tuple(_call_arg_semantic_key_8616(arg) for arg in getattr(node, "args", ()) or ())
            if any(key is None for key in arg_keys):
                return None
            return ("call", getattr(node, "callee_target", None), arg_keys)
        return None

    def _arg_semantic_quality_8616(arg_name: str | None, arg_index: int, node) -> int:
        kind = _call_arg_semantic_kind_8616(arg_name or "", arg_index)
        raw = node
        while isinstance(raw, CTypeCast):
            raw = raw.expr
        if kind is CallArgSemanticKind8616.POINTER:
            if _node_contains_placeholder_stack_8616(raw) or _expr_contains_plain_register_uses(raw):
                return 0
            if isinstance(raw, CFunctionCall) and getattr(raw, "callee_target", None) in {"SEG_PTR", "MK_FP"}:
                return 8
            if isinstance(raw, CUnaryOp) and raw.op == "Reference":
                return 7
            return 2
        if kind is CallArgSemanticKind8616.VALUE:
            if _node_contains_placeholder_stack_8616(raw):
                return 0
            if _node_contains_stable_named_stack_value_8616(raw):
                return 8
            if isinstance(raw, structured_c.CConstant):
                return 4
            if isinstance(raw, CFunctionCall) and getattr(raw, "callee_target", None) in {"SEG_PTR", "MK_FP"}:
                return 0
            return 3
        if _is_stable_named_stack_value_expr_8616(raw):
            return 6
        if isinstance(raw, structured_c.CConstant):
            return 4
        if isinstance(raw, CFunctionCall):
            return 4
        if _node_contains_placeholder_stack_8616(raw):
            return 0
        return 2

    def _normalize_materialized_call_args(
        rhs_values: list,
        source_indices: list[int],
        statements: list,
        *,
        call_name: str | None = None,
        stack_bindings: dict[int, object] | None = None,
    ):
        if not rhs_values:
            return None
        debug_materialization = bool(os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"))
        normalized = []

        def _expr_int_constants(node) -> set[int]:
            values: set[int] = set()
            for current in (node, *_iter_c_nodes_deep_8616(node)):
                if isinstance(current, structured_c.CConstant):
                    value = getattr(current, "value", None)
                    if isinstance(value, int):
                        values.add(value)
            return values

        def _recent_dirty_value_rhs(expr, prefix: list):
            expr_node = expr
            while isinstance(expr_node, CTypeCast):
                expr_node = expr_node.expr
            expr_op = getattr(expr_node, "op", None) if isinstance(expr_node, CBinaryOp) else None
            expr_consts = _expr_int_constants(expr_node)
            matches: list[tuple[tuple[int, int], object]] = []
            seen_assignments: set[int] = set()
            for stmt_idx in range(len(prefix) - 1, -1, -1):
                stmt = prefix[stmt_idx]
                for assignment in reversed(_iter_assignment_nodes(stmt)):
                    assignment_id = id(assignment)
                    if assignment_id in seen_assignments:
                        continue
                    seen_assignments.add(assignment_id)
                    lhs, rhs_stmt = _assignment_lhs_rhs(assignment)
                    if lhs is None or rhs_stmt is None or _assignment_lhs_writes_memory(lhs):
                        continue
                    if lhs.__class__.__name__ != "CDirtyExpression":
                        continue
                    if _is_segment_register_value_expr(rhs_stmt) or _expr_contains_plain_register_uses(rhs_stmt):
                        continue
                    rhs_node = rhs_stmt
                    while isinstance(rhs_node, CTypeCast):
                        rhs_node = rhs_node.expr
                    rhs_op = getattr(rhs_node, "op", None) if isinstance(rhs_node, CBinaryOp) else None
                    if expr_op is not None and rhs_op != expr_op:
                        continue
                    rhs_consts = _expr_int_constants(rhs_node)
                    if expr_consts and rhs_consts and expr_consts.isdisjoint(rhs_consts):
                        continue
                    score = (
                        1 if _node_contains_stable_named_stack_value_8616(rhs_node) else 0,
                        0 if _node_contains_placeholder_stack_8616(rhs_node) else 1,
                        stmt_idx,
                    )
                    matches.append((score, rhs_stmt))
            if not matches:
                return None
            matches.sort(key=lambda item: item[0], reverse=True)
            if len(matches) > 1 and matches[0][0] == matches[1][0]:
                return None
            return matches[0][1]

        if len(source_indices) != len(rhs_values):
            source_indices = [-1] * len(rhs_values)
        for rhs, source_idx in zip(rhs_values, source_indices):
            if _is_segment_register_value_expr(rhs):
                return None
            if not _expr_contains_plain_register_uses(rhs):
                normalized.append(_clone_c_ast_tree(rhs))
                continue
            prefix = statements[: source_idx + 1] if isinstance(source_idx, int) and source_idx >= 0 else statements
            resolved = _resolve_register_carriers_in_expr(rhs, prefix)
            if debug_materialization:
                log.warning(
                    "[call-normalize] function=%#x target=%s rhs=%s resolved=%s source_idx=%r",
                    getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                    call_name,
                    _debug_expr_8616(rhs),
                    _debug_expr_8616(resolved) if resolved is not None else None,
                    source_idx,
                )
            if resolved is None:
                dirty_rhs = _recent_dirty_value_rhs(rhs, prefix)
                if dirty_rhs is not None:
                    if debug_materialization:
                        log.warning(
                            "[call-normalize-dirty-fallback] function=%#x target=%s rhs=%s fallback=%s source_idx=%r",
                            getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                            call_name,
                            _debug_expr_8616(rhs),
                            _debug_expr_8616(dirty_rhs),
                            source_idx,
                        )
                    resolved = dirty_rhs
                elif debug_materialization:
                    window_start = max(0, len(prefix) - 6)
                    for stmt_idx, stmt in enumerate(prefix[window_start:], start=window_start):
                        for assignment in _iter_assignment_nodes(stmt):
                            lhs, rhs_stmt = _assignment_lhs_rhs(assignment)
                            if lhs is None or rhs_stmt is None:
                                continue
                            log.warning(
                                "[call-normalize-prefix] function=%#x target=%s stmt_idx=%d lhs=%s rhs=%s memory_lhs=%s",
                                getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                                call_name,
                                stmt_idx,
                                _debug_expr_8616(lhs),
                                _debug_expr_8616(rhs_stmt),
                                _assignment_lhs_writes_memory(lhs),
                            )
            raw_expr = _clone_c_ast_tree(rhs)
            raw_node = raw_expr
            while isinstance(raw_node, CTypeCast):
                raw_node = raw_node.expr
            if resolved is None and not (
                isinstance(raw_node, CFunctionCall)
                and getattr(raw_node, "callee_target", None) in {"SEG_PTR", "MK_FP"}
            ):
                return None
            expr = _clone_c_ast_tree(resolved) if resolved is not None else raw_expr
            if isinstance(expr, CFunctionCall) and getattr(expr, "callee_target", None) in {"SEG_PTR", "MK_FP"}:
                helper_args = list(getattr(expr, "args", ()) or ())
                if len(helper_args) >= 2:
                    helper_offset = helper_args[1]
                    if _expr_contains_plain_register_uses(helper_offset):
                        resolved_offset = _resolve_register_carriers_in_expr(helper_offset, prefix)
                        if debug_materialization:
                            log.warning(
                                "[call-helper-offset-normalize] function=%#x target=%s offset=%s resolved=%s source_idx=%r",
                                getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                                call_name,
                                _debug_expr_8616(helper_offset),
                                _debug_expr_8616(resolved_offset) if resolved_offset is not None else None,
                                source_idx,
                            )
                        if resolved_offset is None:
                            dirty_offset = _recent_dirty_value_rhs(helper_offset, prefix)
                            if dirty_offset is not None:
                                resolved_offset = dirty_offset
                        if resolved_offset is not None:
                            helper_offset = _clone_c_ast_tree(resolved_offset)
                    rewritten_offset, replacement_count = _normalize_bp_slot_value_arg_8616(
                        helper_offset,
                        stack_bindings=stack_bindings,
                        pointer_arg=True,
                    )
                    if replacement_count:
                        stats.bp_slot_arg_value_normalized_count += replacement_count
                    helper_args[1] = rewritten_offset
                    expr.args = helper_args
            if _is_segment_register_value_expr(expr) or _expr_contains_plain_register_uses(expr):
                return None
            normalized.append(expr)
        for idx, expr in enumerate(tuple(normalized)):
            source_idx = source_indices[idx] if idx < len(source_indices) else -1
            prefix = statements[: source_idx + 1] if isinstance(source_idx, int) and source_idx >= 0 else statements
            pointer_arg = _callee_expects_pointer_arg_8616(call_name or "", idx)
            rewritten, replacement_count = _normalize_bp_slot_value_arg_8616(
                expr,
                stack_bindings=stack_bindings,
                pointer_arg=pointer_arg,
            )
            if replacement_count:
                stats.bp_slot_arg_value_normalized_count += replacement_count
                if _expr_contains_plain_register_uses(rewritten):
                    resolved_rewritten = _resolve_register_carriers_in_expr(rewritten, prefix)
                    if debug_materialization:
                        log.warning(
                            "[call-post-bp-resolve] function=%#x target=%s rewritten=%s resolved=%s source_idx=%r",
                            getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                            call_name,
                            _debug_expr_8616(rewritten),
                            _debug_expr_8616(resolved_rewritten) if resolved_rewritten is not None else None,
                            source_idx,
                        )
                    if resolved_rewritten is not None:
                        rewritten = _clone_c_ast_tree(resolved_rewritten)
            pointer_expr, pointer_materialized = _materialize_pointer_arg_8616(
                rewritten,
                target_name=call_name or "",
                arg_index=idx,
            )
            if pointer_expr is None:
                return None
            if pointer_materialized:
                stats.pointer_arg_materialized_count += 1
            normalized[idx] = pointer_expr
        return normalized

    def _normalize_existing_call_args_8616(call, statements: list, *, call_name: str | None) -> bool:
        args = tuple(getattr(call, "args", ()) or ())
        if not args:
            return False
        normalized_args = _normalize_materialized_call_args(
            list(args),
            [-1] * len(args),
            statements,
            call_name=call_name,
        )
        if normalized_args is None:
            return False
        if tuple(normalized_args) == args:
            return False
        _set_materialized_call_args(call, normalized_args, call_name=call_name)
        return True

    def _set_materialized_call_args(call, args, *, call_name: str | None, force_replace: bool = False):
        def _protected_call_arg_state():
            protected = getattr(codegen, "_inertia_protected_call_args_8616", None)
            if not isinstance(protected, dict):
                protected = {}
                codegen._inertia_protected_call_args_8616 = protected
            return protected

        args_before = tuple(getattr(call, "args", ()) or ())
        args_after = tuple(args)
        if args_before and not force_replace:
            before_score = sum(_arg_semantic_quality_8616(call_name, idx, arg) for idx, arg in enumerate(args_before))
            after_score = sum(_arg_semantic_quality_8616(call_name, idx, arg) for idx, arg in enumerate(args_after))
            if after_score < before_score:
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-materialized-skip] function=%#x target=%s before_score=%d after_score=%d args_before=%s args_after=%s",
                        getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                        call_name,
                        before_score,
                        after_score,
                        tuple(_debug_expr_8616(arg) for arg in args_before),
                        tuple(_debug_expr_8616(arg) for arg in args_after),
                    )
                return
        if not args_before and len(args_after) > 1:
            stats.push_order_reversed_count += 1
        call.args = list(args_after)
        protected = _protected_call_arg_state()
        for idx, arg in enumerate(args_after):
            key = (id(call), idx)
            score = _arg_semantic_quality_8616(call_name, idx, arg)
            current = protected.get(key)
            if not isinstance(current, tuple) or len(current) != 2 or score >= int(current[1]):
                protected[key] = (_clone_c_ast_tree(arg), score)
        log.debug(
            "callarg-normalized function=%#x target=%s args_before=%s args_after=%s",
            getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
            call_name,
            tuple(_debug_expr_8616(arg) for arg in args_before),
            tuple(_debug_expr_8616(arg) for arg in args_after),
        )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-materialized] function=%#x target=%s args_before=%s args_after=%s",
                getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                call_name,
                tuple(_debug_expr_8616(arg) for arg in args_before),
                tuple(_debug_expr_8616(arg) for arg in args_after),
            )

    def _prototype_arg_count(call) -> int | None:
        callee_func = getattr(call, "callee_func", None)
        prototype = getattr(callee_func, "prototype", None)
        args = getattr(prototype, "args", None)
        if isinstance(args, (list, tuple)):
            return len(args)
        return None

    def _is_stable_named_stack_value_expr_8616(expr) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, structured_c.CVariable):
            return False
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return False
        offset = getattr(variable, "offset", None)
        name = getattr(variable, "name", None) or getattr(node, "name", None)
        if not isinstance(offset, int) or not isinstance(name, str) or not name:
            return False
        if name.startswith(("arg_", "s_", "stack_", "vvar_", "tmp_", "ir_")):
            return False
        return True

    def _call_args_need_rematerialization_8616(call, push_arg_sources=()) -> bool:
        args = tuple(getattr(call, "args", ()) or ())
        if not args:
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                log.warning(
                    "[call-remat] function=%#x target=%s reason=no-args",
                    getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                    getattr(call, "callee_target", None),
                )
            return True
        if (
            isinstance(push_arg_sources, tuple)
            and len(push_arg_sources) == len(args)
            and all(
                isinstance(source, tuple)
                and len(source) >= 2
                and source[0] == "bp"
                and isinstance(source[1], int)
                for source in push_arg_sources
            )
        ):
            expected_offsets = [
                int(source[1])
                for source in (reversed(push_arg_sources) if len(push_arg_sources) > 1 else push_arg_sources)
            ]
            actual_offsets: list[int | None] = []
            for arg in args:
                node = arg
                while isinstance(node, CTypeCast):
                    node = node.expr
                actual_offsets.append(_plain_stack_slot_address_offset(node))
            if all(isinstance(offset, int) for offset in actual_offsets):
                normalized_actual = [int(offset) for offset in actual_offsets]
                if normalized_actual != expected_offsets:
                    if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                        log.warning(
                            "[call-remat] function=%#x target=%s reason=push-source-mismatch actual=%s expected=%s",
                            getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                            getattr(call, "callee_target", None),
                            tuple(normalized_actual),
                            tuple(expected_offsets),
                        )
                    return True
        if (
            isinstance(push_arg_sources, tuple)
            and len(push_arg_sources) == len(args)
            and any(source is not None for source in push_arg_sources)
        ):
            ordered_sources = list(reversed(push_arg_sources)) if len(push_arg_sources) > 1 else list(push_arg_sources)
            expected_args = [
                _direct_expr_from_push_source_8616(source, call_name=getattr(call, "callee_target", None), arg_index=idx)
                for idx, source in enumerate(ordered_sources)
            ]
            if all(expected is not None for expected in expected_args):
                expected_keys = tuple(_call_arg_semantic_key_8616(expected) for expected in expected_args)
                actual_keys = tuple(_call_arg_semantic_key_8616(arg) for arg in args)
                if all(key is not None for key in expected_keys) and all(key is not None for key in actual_keys):
                    if actual_keys != expected_keys:
                        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                            log.warning(
                                "[call-remat] function=%#x target=%s reason=derived-push-source-mismatch actual=%s expected=%s",
                                getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                                getattr(call, "callee_target", None),
                                actual_keys,
                                expected_keys,
                            )
                        return True
        for arg in args:
            node = arg
            while isinstance(node, CTypeCast):
                node = node.expr
            if _node_contains_placeholder_stack_8616(node):
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-remat] function=%#x target=%s reason=stack-placeholder-expression",
                        getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                        getattr(call, "callee_target", None),
                    )
                return True
            if _is_stable_named_stack_value_expr_8616(node):
                continue
            if _plain_bp_stack_load_offset(node) is not None:
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning("[call-remat] function=%#x target=%s reason=bp-load", getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0, getattr(call, "callee_target", None))
                return True
            if _plain_stack_slot_address_offset(node) is not None:
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning("[call-remat] function=%#x target=%s reason=stack-slot-address", getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0, getattr(call, "callee_target", None))
                return True
            if isinstance(node, structured_c.CVariable):
                variable = getattr(node, "variable", None)
                name = getattr(variable, "name", None) or getattr(node, "name", None)
                if isinstance(variable, SimStackVariable):
                    if isinstance(name, str) and (
                        name.startswith("arg_")
                        or name.startswith("stack_")
                        or name.startswith("s_")
                    ):
                        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                            log.warning("[call-remat] function=%#x target=%s reason=stack-placeholder name=%s offset=%r", getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0, getattr(call, "callee_target", None), name, getattr(variable, "offset", None))
                        return True
                    offset = getattr(variable, "offset", None)
                    if isinstance(offset, int) and offset <= 2:
                        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                            log.warning("[call-remat] function=%#x target=%s reason=small-stack-offset offset=%r", getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0, getattr(call, "callee_target", None), offset)
                        return True
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-remat] function=%#x target=%s reason=keep-existing args=%s",
                getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                getattr(call, "callee_target", None),
                tuple(getattr(getattr(arg, "variable", None), "name", None) or getattr(arg, "name", None) or arg.__class__.__name__ for arg in args),
            )
        return False

    def _refresh_summary_arg_shape(call, summary) -> None:
        nonlocal changed
        if summary is None:
            return
        args = tuple(getattr(call, "args", ()) or ())
        arg_widths_live = tuple(_arg_width_from_expr(arg) for arg in args)
        existing_count = getattr(summary, "arg_count", None)
        existing_widths = tuple(getattr(summary, "arg_widths", ()) or ())
        floor_count = existing_count if isinstance(existing_count, int) and existing_count >= 0 else 0
        call_name = _call_node_name_8616(call) or ""
        known_count = _expected_arg_count_for_known_callee_8616(call_name)
        if isinstance(known_count, int) and known_count > floor_count:
            floor_count = known_count
        next_count = max(len(arg_widths_live), floor_count)
        if len(arg_widths_live) < next_count:
            padded = list(arg_widths_live)
            while len(padded) < next_count:
                if len(existing_widths) > len(padded) and isinstance(existing_widths[len(padded)], int):
                    padded.append(int(existing_widths[len(padded)]))
                else:
                    padded.append(2)
            arg_widths = tuple(padded)
        else:
            arg_widths = arg_widths_live
        updated = replace(summary, arg_count=next_count, arg_widths=arg_widths)
        if summary_map.get(id(call)) != updated:
            summary_map[id(call)] = updated
            changed = True

    def _record_prunable_segment_metadata_ids(call, statements: list, consumed_indices: list[int]) -> None:
        if call is None or not consumed_indices:
            return
        tail_ids: list[int] = []
        scan = max(consumed_indices) + 1
        while scan < len(statements):
            stmt = statements[scan]
            if _is_segment_register_metadata_store(stmt):
                tail_ids.append(id(stmt))
                scan += 1
                continue
            if _is_stack_carrier_temp_assignment(stmt):
                scan += 1
                continue
            break
        if tail_ids:
            materialized_callsite_metadata_ids[id(call)] = tuple(tail_ids)

    def _call_from_statement(stmt):
        if isinstance(stmt, CFunctionCall):
            return stmt
        expr = getattr(stmt, "expr", None)
        if isinstance(expr, CFunctionCall):
            return expr
        rhs = getattr(stmt, "rhs", None)
        if isinstance(rhs, CFunctionCall):
            return rhs
        src = getattr(stmt, "src", None)
        if isinstance(src, CFunctionCall):
            return src
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)) and len(nested_statements) == 1:
            return _call_from_statement(nested_statements[0])
        return None

    def _statement_contains_call(stmt) -> bool:
        if isinstance(stmt, CFunctionCall):
            return True
        expr = getattr(stmt, "expr", None)
        if isinstance(expr, CFunctionCall):
            return True
        for node in _iter_c_nodes_deep_8616(stmt):
            if isinstance(node, CFunctionCall):
                return True
        return False

    def _assignment_lhs_rhs(node):
        lhs = getattr(node, "lhs", None)
        rhs = getattr(node, "rhs", None)
        if lhs is None and hasattr(node, "dst"):
            lhs = getattr(node, "dst", None)
            rhs = getattr(node, "src", None)
        return lhs, rhs

    def _is_assignment_node(node) -> bool:
        class_name = node.__class__.__name__
        if class_name == "CAssignment" or class_name.endswith("Assignment"):
            return True
        return hasattr(node, "dst") and hasattr(node, "src")

    def _iter_assignment_nodes(stmt):
        candidates = []
        if _is_assignment_node(stmt):
            candidates.append(stmt)
        for node in _iter_c_nodes_deep_8616(stmt):
            if _is_assignment_node(node):
                candidates.append(node)
        return candidates

    def _stack_store_rhs_from_statement(stmt):
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)):
            for nested in reversed(tuple(nested_statements)):
                rhs = _stack_store_rhs_from_statement(nested)
                if rhs is not None:
                    return rhs
                nested_children = getattr(nested, "statements", None)
                if isinstance(nested_children, (list, tuple)):
                    continue
                if _is_stack_carrier_temp_assignment(nested) or _is_non_memory_assignment(nested):
                    continue
            return None

        project = getattr(codegen, "project", None)

        def _contains_ss_evidence(term) -> bool:
            if term is None:
                return False
            nodes = (term, *_iter_c_nodes_deep_8616(term))
            for raw_node in nodes:
                node = raw_node
                while isinstance(node, CTypeCast):
                    node = node.expr
                variable = getattr(node, "variable", None)
                register_name = getattr(variable, "name", None)
                if isinstance(register_name, str) and register_name.lower() == "ss":
                    return True
                seg_name, _linear = _match_real_mode_linear_expr_8616(node, project)
                if seg_name == "ss":
                    return True
                segment_selector = getattr(node, "segment_selector", None)
                if isinstance(segment_selector, str) and segment_selector.lower() == "ss":
                    return True
            return False

        def _contains_ss_dereference(term) -> bool:
            if term is None:
                return False
            nodes = (term, *_iter_c_nodes_deep_8616(term))
            for raw_node in nodes:
                node = raw_node
                while isinstance(node, CTypeCast):
                    node = node.expr
                if isinstance(node, CUnaryOp) and node.op == "Dereference" and _contains_ss_evidence(
                    getattr(node, "operand", None)
                ):
                    return True
            return False

        def _contains_dirty_expr(term) -> bool:
            nodes = (term, *_iter_c_nodes_deep_8616(term))
            for raw_node in nodes:
                if raw_node.__class__.__name__ == "CDirtyExpression":
                    return True
            return False

        def _is_virtual_dirty_expr(term) -> bool:
            dirty = getattr(term, "dirty", None)
            if isinstance(dirty, str):
                return dirty.startswith("vvar_") or dirty.startswith("tmp_") or dirty.startswith("ir_")
            if dirty is None:
                return False
            varid = getattr(dirty, "varid", None)
            if isinstance(varid, int):
                return True
            name = getattr(dirty, "name", None)
            return isinstance(name, str) and (
                name.startswith("vvar_") or name.startswith("tmp_") or name.startswith("ir_")
            )

        def _contains_unresolved_dirty_expr(term) -> bool:
            nodes = (term, *_iter_c_nodes_deep_8616(term))
            for raw_node in nodes:
                if raw_node.__class__.__name__ != "CDirtyExpression":
                    continue
                if _is_virtual_dirty_expr(raw_node):
                    continue
                return True
            return False

        for assignment in reversed(_iter_assignment_nodes(stmt)):
            lhs, rhs = _assignment_lhs_rhs(assignment)
            if lhs is None:
                continue
            if _contains_unresolved_dirty_expr(lhs):
                continue
            seg_name, _offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, project)
            if seg_name == "ss":
                return rhs
            if _match_bp_stack_dereference_8616(lhs, project, codegen) is not None:
                return rhs
            seg_name, _linear = _match_segmented_dereference_8616(lhs, project)
            if seg_name == "ss":
                return rhs
            deref = lhs
            while isinstance(deref, CTypeCast):
                deref = deref.expr
            if not isinstance(deref, CUnaryOp) or deref.op != "Dereference":
                if _contains_ss_dereference(lhs):
                    return rhs
                continue
            if isinstance(_stack_offset_from_expr_8616(getattr(deref, "operand", None), project, codegen), int):
                return rhs
            if _contains_ss_evidence(getattr(deref, "operand", None)):
                return rhs
        return None

    def _store_matches_typed_stack_probe_fact(lhs, fact: TypedStackProbeReturnFact8616 | None) -> bool:
        if lhs is None or fact is None:
            return False
        seg_name, _offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, project)
        if seg_name == fact.segment_space:
            def _contains_dirty_expr(term) -> bool:
                nodes = (term, *_iter_c_nodes_deep_8616(term))
                for raw_node in nodes:
                    if raw_node.__class__.__name__ == "CDirtyExpression":
                        return True
                return False

            return not any(_contains_dirty_expr(term) for _sign, term in _offset_terms)

        deref = lhs
        while isinstance(deref, CTypeCast):
            deref = deref.expr
        if not isinstance(deref, CUnaryOp) or deref.op != "Dereference":
            return False
        stack_offset = _stack_offset_from_expr_8616(getattr(deref, "operand", None), project, codegen)
        return isinstance(stack_offset, int)

    def _typed_stack_store_rhs_from_statement(stmt, fact: TypedStackProbeReturnFact8616 | None):
        if fact is None:
            return None
        for assignment in reversed(_iter_assignment_nodes(stmt)):
            lhs, rhs = _assignment_lhs_rhs(assignment)
            if not _assignment_lhs_writes_memory(lhs):
                continue
            if _is_segment_register_value_expr(rhs):
                continue
            if _store_matches_typed_stack_probe_fact(lhs, fact):
                return rhs
        return None

    def _stack_store_rhss_from_statement(stmt, *, max_collect: int = 4) -> list:
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)):
            rhss: list = []
            for nested in reversed(tuple(nested_statements)):
                nested_rhss = _stack_store_rhss_from_statement(nested, max_collect=max_collect)
                if nested_rhss:
                    rhss.extend(reversed(nested_rhss))
                    if len(rhss) >= max_collect:
                        break
                    continue
                nested_children = getattr(nested, "statements", None)
                if isinstance(nested_children, (list, tuple)):
                    continue
                if _is_stack_carrier_temp_assignment(nested) or _is_non_memory_assignment(nested):
                    continue
            rhss.reverse()
            return rhss[:max_collect]
        rhs = _stack_store_rhs_from_statement(stmt)
        return [rhs] if rhs is not None else []

    def _typed_stack_store_rhss_from_statement(
        stmt,
        fact: TypedStackProbeReturnFact8616 | None,
        *,
        max_collect: int = 4,
    ) -> list:
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)):
            rhss: list = []
            for nested in reversed(tuple(nested_statements)):
                nested_rhss = _typed_stack_store_rhss_from_statement(nested, fact, max_collect=max_collect)
                if nested_rhss:
                    rhss.extend(reversed(nested_rhss))
                    if len(rhss) >= max_collect:
                        break
                    continue
                nested_children = getattr(nested, "statements", None)
                if isinstance(nested_children, (list, tuple)):
                    continue
                if _is_stack_carrier_temp_assignment(nested) or _is_non_memory_assignment(nested):
                    continue
            rhss.reverse()
            return rhss[:max_collect]
        rhs = _typed_stack_store_rhs_from_statement(stmt, fact)
        return [rhs] if rhs is not None else []

    def _is_stack_carrier_temp_assignment(stmt) -> bool:
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, rhs = _assignment_lhs_rhs(candidates[-1])
        if lhs is None:
            return False
        variable = getattr(lhs, "variable", None)
        name = getattr(variable, "name", None) or getattr(lhs, "name", None)
        if not isinstance(name, str) or not (
            name.startswith("vvar_") or name.startswith("ir_") or name.startswith("tmp_")
        ):
            return False
        rhs_node = rhs
        while isinstance(rhs_node, CTypeCast):
            rhs_node = rhs_node.expr
        # Carrier temps are arithmetic/address shuttles only.
        if isinstance(rhs_node, CUnaryOp) and rhs_node.op in {"Reference", "Dereference"}:
            return True
        if isinstance(rhs_node, CBinaryOp):
            return rhs_node.op in {"Add", "Sub", "Mul", "Shl", "Shr", "And", "Or", "Xor"}
        return False

    def _is_non_memory_assignment(stmt) -> bool:
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, _rhs = _assignment_lhs_rhs(candidates[-1])
        return isinstance(lhs, structured_c.CVariable)

    def _value_carrier_assignment_rhs_from_statement(stmt):
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return None
        lhs, rhs = _assignment_lhs_rhs(candidates[-1])
        if lhs is None or rhs is None or _assignment_lhs_writes_memory(lhs):
            return None
        lhs_node = lhs
        while isinstance(lhs_node, CTypeCast):
            lhs_node = lhs_node.expr
        if not isinstance(lhs_node, structured_c.CVariable):
            return None
        variable = getattr(lhs_node, "variable", None)
        name = getattr(variable, "name", None) or getattr(lhs_node, "name", None)
        if not isinstance(name, str) or not (
            name.startswith("vvar_") or name.startswith("tmp_") or name.startswith("ir_")
        ):
            return None
        if _is_segment_register_value_expr(rhs):
            return None
        return rhs

    def _outgoing_arg_placeholder_rhs_from_statement(stmt):
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return None
        lhs, rhs = _assignment_lhs_rhs(candidates[-1])
        if lhs is None or rhs is None:
            return None
        lhs_node = lhs
        while isinstance(lhs_node, CTypeCast):
            lhs_node = lhs_node.expr
        if not isinstance(lhs_node, structured_c.CVariable):
            return None
        variable = getattr(lhs_node, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        offset = getattr(variable, "offset", None)
        if not isinstance(offset, int) or offset >= 0:
            return None
        name = getattr(variable, "name", None) or getattr(lhs_node, "name", None)
        if not isinstance(name, str) or not (
            name.startswith("s_") or name.startswith("stack_bp_") or name.startswith("stack_sp_")
        ):
            return None
        rhs_node = rhs
        while isinstance(rhs_node, CTypeCast):
            rhs_node = rhs_node.expr
        if rhs_node.__class__.__name__ == "CDirtyExpression":
            resolved = _resolve_dirty_virtual_expr_8616(rhs_node)
            if resolved is not None:
                rhs = resolved
        if _is_segment_register_value_expr(rhs):
            return None
        return rhs

    def _is_outgoing_segment_return_store_statement(stmt) -> bool:
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, rhs = _assignment_lhs_rhs(candidates[-1])
        if lhs is None or rhs is None:
            return False
        segment_name, _offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, project)
        if segment_name != "ss":
            return False
        return _is_segment_register_value_expr(rhs)

    def _offset_terms_include_stack_base_placeholder(offset_terms) -> bool:
        for _sign, term in tuple(offset_terms or ()):
            if _node_contains_placeholder_stack_8616(term):
                return True
        return False

    def _is_stack_probe_frame_artifact_store_statement(stmt) -> bool:
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, _rhs = _assignment_lhs_rhs(candidates[-1])
        if lhs is None:
            return False
        segment_name, offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, project)
        if segment_name != "ss":
            return False
        return _offset_terms_include_stack_base_placeholder(offset_terms)

    def _prune_stack_probe_frame_artifacts(statements: list, *, stack_probe_seen: bool) -> list:
        if not stack_probe_seen:
            return statements
        pruned = []
        for stmt in statements:
            if _is_stack_probe_frame_artifact_store_statement(stmt):
                stats.consumed_outgoing_stack_placeholder_count += 1
                continue
            pruned.append(stmt)
        return pruned

    def _assignment_lhs_writes_memory(lhs) -> bool:
        if lhs is None:
            return False
        nodes = (lhs, *_iter_c_nodes_deep_8616(lhs))
        for raw_node in nodes:
            node = raw_node
            while isinstance(node, CTypeCast):
                node = node.expr
            if isinstance(node, CUnaryOp) and node.op == "Dereference":
                return True
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimMemoryVariable):
                return True
        return False

    def _is_value_only_assignment(stmt) -> bool:
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, _rhs = _assignment_lhs_rhs(candidates[-1])
        return not _assignment_lhs_writes_memory(lhs)

    def _is_segment_register_metadata_store(stmt) -> bool:
        candidates = _iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, rhs = _assignment_lhs_rhs(candidates[-1])
        return _assignment_lhs_writes_memory(lhs) and _is_segment_register_value_expr(rhs)

    def _collect_backtracked_stack_args(
        statements: list,
        *,
        wanted_count: int | None = None,
        max_count: int = 4,
        typed_probe_fact: TypedStackProbeReturnFact8616 | None = None,
    ) -> tuple[list, list]:
        def _trailing_stack_store_rhss_after_last_call(stmt, *, max_collect: int) -> list:
            nested_statements = getattr(stmt, "statements", None)
            if not isinstance(nested_statements, (list, tuple)):
                return []
            sequence = list(nested_statements)
            last_call_idx = None
            for seq_idx, node in enumerate(sequence):
                if _statement_contains_call(node):
                    last_call_idx = seq_idx
            if last_call_idx is None:
                return []

            rhss: list = []
            skipped_carriers = 0
            skipped_value_assignments = 0
            for node in sequence[last_call_idx + 1 :]:
                if _statement_contains_call(node):
                    break
                nested_rhss = (
                    _typed_stack_store_rhss_from_statement(node, typed_probe_fact, max_collect=max_collect)
                    if typed_probe_fact is not None
                    else _stack_store_rhss_from_statement(node, max_collect=max_collect)
                )
                if nested_rhss:
                    rhss.extend(nested_rhss)
                    if len(rhss) >= max_collect:
                        break
                    continue
                placeholder_rhs = _outgoing_arg_placeholder_rhs_from_statement(node)
                if placeholder_rhs is not None:
                    rhss.append(placeholder_rhs)
                    if len(rhss) >= max_collect:
                        break
                    continue
                if _is_segment_register_metadata_store(node):
                    skipped_carriers += 1
                    if skipped_carriers > 4:
                        break
                    continue
                if _is_stack_carrier_temp_assignment(node):
                    skipped_carriers += 1
                    if skipped_carriers > 4:
                        break
                    continue
                if _is_non_memory_assignment(node) or _is_value_only_assignment(node):
                    skipped_value_assignments += 1
                    if skipped_value_assignments > 8:
                        break
                    continue
                break
            return rhss[:max_collect]

        rhs_values: list = []
        consumed_indices: list[int] = []
        skipped_carriers = 0
        skipped_value_assignments = 0
        limit = max_count if wanted_count is None else max(wanted_count, 1)
        idx = len(statements) - 1
        while idx >= 0 and len(rhs_values) < limit:
            stmt = statements[idx]
            if _statement_contains_call(stmt):
                trailing_rhss = _trailing_stack_store_rhss_after_last_call(
                    stmt,
                    max_collect=max(0, limit - len(rhs_values)),
                )
                if trailing_rhss:
                    if len(trailing_rhss) > 1:
                        stats.push_order_reversed_count += 1
                    rhs_values.extend(trailing_rhss)
                    consumed_indices.append(idx)
                break
            rhss = (
                _typed_stack_store_rhss_from_statement(stmt, typed_probe_fact, max_collect=max_count)
                if typed_probe_fact is not None
                else _stack_store_rhss_from_statement(stmt, max_collect=max_count)
            )
            if rhss:
                if all(_is_segment_register_value_expr(rhs) for rhs in rhss):
                    skipped_carriers += 1
                    if skipped_carriers > 4:
                        break
                    idx -= 1
                    continue
                if len(rhss) > 1:
                    stats.push_order_reversed_count += 1
                rhs_values.extend(rhss)
                consumed_indices.append(idx)
                idx -= 1
                continue
            placeholder_rhs = _outgoing_arg_placeholder_rhs_from_statement(stmt)
            if placeholder_rhs is not None:
                stats.consumed_outgoing_stack_placeholder_count += 1
                rhs_values.append(placeholder_rhs)
                consumed_indices.append(idx)
                idx -= 1
                continue
            if _is_segment_register_metadata_store(stmt):
                skipped_carriers += 1
                if skipped_carriers > 4:
                    break
                idx -= 1
                continue
            if _is_stack_carrier_temp_assignment(stmt):
                skipped_carriers += 1
                if skipped_carriers > 4:
                    break
                idx -= 1
                continue
            if _is_non_memory_assignment(stmt) or _is_value_only_assignment(stmt):
                skipped_value_assignments += 1
                if skipped_value_assignments > 8:
                    break
                idx -= 1
                continue
            break
        if wanted_count is not None and len(rhs_values) != wanted_count:
            return [], []
        if len(rhs_values) > 1:
            stats.push_order_reversed_count += 1
        return rhs_values, consumed_indices

    def _collect_backtracked_value_carrier_args(
        statements: list,
        *,
        wanted_count: int,
    ) -> tuple[list, list]:
        if not isinstance(wanted_count, int) or wanted_count <= 0:
            return [], []
        rhs_values: list = []
        consumed_indices: list[int] = []
        idx = len(statements) - 1
        while idx >= 0 and len(rhs_values) < wanted_count:
            stmt = statements[idx]
            if _statement_contains_call(stmt):
                break
            rhs = _value_carrier_assignment_rhs_from_statement(stmt)
            if rhs is not None:
                rhs_values.append(rhs)
                consumed_indices.append(idx)
                idx -= 1
                continue
            placeholder_rhs = _outgoing_arg_placeholder_rhs_from_statement(stmt)
            if placeholder_rhs is not None:
                stats.consumed_outgoing_stack_placeholder_count += 1
                rhs_values.append(placeholder_rhs)
                consumed_indices.append(idx)
                idx -= 1
                continue
            if _is_stack_carrier_temp_assignment(stmt):
                idx -= 1
                continue
            break
        if len(rhs_values) != wanted_count:
            return [], []
        return rhs_values, consumed_indices

    def _extract_inline_stack_store_args(stmt, call, arg_count: int) -> tuple | None:
        if not isinstance(arg_count, int) or arg_count <= 0:
            return None
        nested_statements = getattr(stmt, "statements", None)
        if not isinstance(nested_statements, (list, tuple)):
            return None
        if not nested_statements:
            return None

        sequence = list(nested_statements)

        def _contains_call(node) -> bool:
            if node is call:
                return True
            expr = getattr(node, "expr", None)
            if expr is call:
                return True
            for sub in _iter_c_nodes_deep_8616(node):
                if sub is call:
                    return True
            return False

        call_idx = None
        for idx, node in enumerate(sequence):
            if _contains_call(node):
                call_idx = idx
                break
        if call_idx is None:
            return None

        rhs_values = []
        consumed_indices = []
        scan = call_idx - 1
        skipped_carriers = 0
        while scan >= 0 and len(rhs_values) < arg_count:
            rhs = _stack_store_rhs_from_statement(sequence[scan])
            if rhs is None:
                rhs = _outgoing_arg_placeholder_rhs_from_statement(sequence[scan])
                if rhs is not None:
                    stats.consumed_outgoing_stack_placeholder_count += 1
            if rhs is None:
                if _is_stack_carrier_temp_assignment(sequence[scan]):
                    skipped_carriers += 1
                    if skipped_carriers > 4:
                        break
                    scan -= 1
                    continue
                break
            rhs_values.append(rhs)
            consumed_indices.append(scan)
            scan -= 1
        if len(rhs_values) != arg_count:
            return None

        for idx in sorted(consumed_indices, reverse=True):
            del sequence[idx]
        stmt.statements = sequence if isinstance(nested_statements, list) else tuple(sequence)
        if len(rhs_values) > 1:
            stats.push_order_reversed_count += 1
        return tuple(rhs_values)

    def _restore_protected_call_args_8616(block) -> bool:
        protected = getattr(codegen, "_inertia_protected_call_args_8616", None)
        if not isinstance(protected, dict):
            return False
        restored = False
        for node in _iter_c_nodes_deep_8616(block):
            if not isinstance(node, CFunctionCall):
                continue
            call_name = _call_node_name_8616(node) or ""
            current_args = list(getattr(node, "args", ()) or ())
            if not current_args:
                continue
            updated = False
            for idx, current_arg in enumerate(tuple(current_args)):
                key = (id(node), idx)
                protected_entry = protected.get(key)
                if not isinstance(protected_entry, tuple) or len(protected_entry) != 2:
                    continue
                protected_arg, protected_score = protected_entry
                current_score = _arg_semantic_quality_8616(call_name, idx, current_arg)
                if current_score < int(protected_score):
                    current_args[idx] = _clone_c_ast_tree(protected_arg)
                    updated = True
            if updated:
                node.args = current_args
                restored = True
        return restored

    def _rewrite_block(
        block,
        *,
        inherited_stack_probe_seen: bool = False,
        inherited_stack_probe_address_seen: bool = False,
        inherited_typed_stack_probe_fact: TypedStackProbeReturnFact8616 | None = None,
    ) -> tuple[bool, bool, TypedStackProbeReturnFact8616 | None]:
        nonlocal changed
        statements = getattr(block, "statements", None)
        if not isinstance(statements, (list, tuple)):
            return inherited_stack_probe_seen, inherited_stack_probe_address_seen, inherited_typed_stack_probe_fact
        statements = list(statements)
        new_statements = []
        i = 0
        typed_stack_probe_fact = inherited_typed_stack_probe_fact
        stack_probe_seen = inherited_stack_probe_seen or any(
            bool(getattr(item, "stack_probe_helper", False)) for item in summary_map.values()
        )
        stack_probe_address_seen = inherited_stack_probe_address_seen or typed_stack_probe_fact is not None
        while i < len(statements):
            stmt = statements[i]
            if _is_outgoing_segment_return_store_statement(stmt):
                stats.consumed_outgoing_stack_placeholder_count += 1
                changed = True
                i += 1
                continue
            call = _call_from_statement(stmt)
            if call is not None and _is_runtime_segment_helper_call_8616(call):
                new_statements.append(stmt)
                i += 1
                continue
            summary = summary_map.get(id(call)) if call is not None else None
            arg_count = getattr(summary, "arg_count", None) if summary is not None else None
            call_name = _call_node_name_8616(call) if call is not None else None
            prototype_arg_count = _prototype_arg_count(call) if call is not None else None
            normalized_call_name = normalize_callee_name_8616(call_name) if isinstance(call_name, str) else None
            known_arg_count = (
                _expected_arg_count_for_known_callee_8616(call_name or "")
                if call is not None
                else None
            )
            if known_arg_count is None and isinstance(normalized_call_name, str) and normalized_call_name:
                known_arg_count = _expected_arg_count_for_known_callee_8616(normalized_call_name)
            is_stack_probe_helper = bool(getattr(summary, "stack_probe_helper", False))
            push_arg_sources = getattr(summary, "push_arg_sources", ()) if summary is not None else ()
            if call is not None and not is_stack_probe_helper and _is_stack_probe_call_name_8616(call_name):
                is_stack_probe_helper = True
            if is_stack_probe_helper:
                stack_probe_seen = True
                typed_stack_probe_fact = typed_stack_probe_facts.get(id(call)) if call is not None else None
                if typed_stack_probe_fact is not None:
                    stack_probe_address_seen = True
                else:
                    # When no typed fact exists for this probe, keep the generic
                    # stack-arg backtracker enabled for subsequent calls.
                    stack_probe_address_seen = True
            # A typed stack-probe fact is strong evidence for a helper-returned SS
            # address. If no typed fact exists, direct segmented SS stores before the
            # call remain valid evidence and the generic stack-arg backtracker must
            # stay enabled.
            typed_stack_probe_materialization = (
                typed_stack_probe_fact is not None and stack_probe_seen and not is_stack_probe_helper
            )
            expected_arg_count = arg_count
            if isinstance(prototype_arg_count, int) and prototype_arg_count > 0:
                if not isinstance(expected_arg_count, int) or expected_arg_count <= 0:
                    expected_arg_count = prototype_arg_count
                elif typed_stack_probe_materialization and prototype_arg_count > expected_arg_count:
                    expected_arg_count = prototype_arg_count
            if isinstance(known_arg_count, int):
                if not isinstance(expected_arg_count, int):
                    expected_arg_count = known_arg_count
                elif known_arg_count > expected_arg_count:
                    expected_arg_count = known_arg_count
                elif known_arg_count == 0:
                    expected_arg_count = 0
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION") and call is not None:
                log.warning(
                    "[call-summary] function=%#x target=%s expected_arg_count=%r push_arg_sources=%r",
                    getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                    call_name,
                    expected_arg_count,
                    push_arg_sources,
                )
            if os.environ.get("INERTIA_DEBUG_PERCOLATEUP_CALLSITE") and call is not None and call_name == "PercolateUp":
                log.warning(
                    "[percolateup-callsite] function=%#x expected_arg_count=%r prototype_arg_count=%r known_arg_count=%r remat=%r push_arg_sources=%r args=%r",
                    getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                    expected_arg_count,
                    prototype_arg_count,
                    known_arg_count,
                    rematerialize_call_args if 'rematerialize_call_args' in locals() else None,
                    push_arg_sources,
                    tuple(_debug_expr_8616(arg) for arg in tuple(getattr(call, "args", ()) or ())),
                )
            # When a stack-probe helper was seen but its segment space is not SS
            # (e.g. "ds"), the probe return address is not a stack address.
            # Reject backward-scan materialization for calls after the probe.
            probe_seen_without_ss_address = stack_probe_seen and not stack_probe_address_seen
            rematerialize_call_args = (
                _call_args_need_rematerialization_8616(call, push_arg_sources=push_arg_sources)
                if call is not None
                else False
            )
            if (
                call is not None
                and isinstance(expected_arg_count, int)
                and expected_arg_count >= 0
                and len(tuple(getattr(call, "args", ()) or ())) != expected_arg_count
            ):
                rematerialize_call_args = True
            if typed_stack_probe_materialization:
                rematerialize_call_args = True
            has_exact_direct_push_sources = (
                isinstance(expected_arg_count, int)
                and expected_arg_count > 0
                and isinstance(push_arg_sources, tuple)
                and len(push_arg_sources) == expected_arg_count
                and any(source is not None for source in push_arg_sources)
            )
            has_safe_non_stack_fallback = (
                isinstance(expected_arg_count, int)
                and expected_arg_count > 0
                and _known_default_args_for_missing_8616(call_name or "", codegen) is not None
            )
            # Do not destructively clear existing call args when inferred arg-count
            # drops to zero. Zero can be an unproven placeholder; preserving current
            # args keeps call semantics stable until stronger evidence rematerializes.
            if (
                call is not None
                and not is_stack_probe_helper
                and expected_arg_count == 0
                and tuple(getattr(call, "args", ()) or ())
                and not probe_seen_without_ss_address
            ):
                rematerialize_call_args = False
            if os.environ.get("INERTIA_DEBUG_PERCOLATEUP_CALLSITE") and call is not None and call_name == "PercolateUp":
                log.warning(
                    "[percolateup-callsite-post-zero] function=%#x expected_arg_count=%r remat=%r args=%r",
                    getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
                    expected_arg_count,
                    rematerialize_call_args,
                    tuple(_debug_expr_8616(arg) for arg in tuple(getattr(call, "args", ()) or ())),
                )
            if (
                call is not None
                and tuple(getattr(call, "args", ()) or ())
                and _normalize_existing_call_args_8616(call, new_statements, call_name=call_name)
            ):
                _refresh_summary_arg_shape(call, summary)
                changed = True
            if (
                call is not None
                and isinstance(expected_arg_count, int)
                and expected_arg_count > 0
                and rematerialize_call_args
                and (not probe_seen_without_ss_address or has_exact_direct_push_sources or has_safe_non_stack_fallback)
            ):
                strict_arg_shape_applied = False
                if (
                    isinstance(push_arg_sources, tuple)
                    and len(push_arg_sources) == expected_arg_count
                    and any(source is not None for source in push_arg_sources)
                ):
                    ordered_push_sources = list(reversed(push_arg_sources)) if len(push_arg_sources) > 1 else list(push_arg_sources)
                    direct_args = []
                    direct_bindings = {}
                    strict_push_sources = all(
                        isinstance(source, tuple)
                        and len(source) >= 2
                        and source[0] == "bp"
                        and isinstance(source[1], int)
                        for source in ordered_push_sources
                    )
                    if strict_push_sources:
                        for source in ordered_push_sources:
                            source_value = source[1]
                            cvar = _stack_cvar_for_offset(source_value, allow_best_match=False)
                            if cvar is None:
                                break
                            direct_args.append(_clone_c_ast_tree(cvar))
                            direct_bindings[source_value] = _clone_c_ast_tree(cvar)
                    else:
                        direct_args = [
                            _direct_expr_from_push_source_8616(source, call_name=call_name, arg_index=idx)
                            for idx, source in enumerate(ordered_push_sources)
                        ]
                    if all(arg is not None for arg in direct_args):
                        normalized_args = _normalize_materialized_call_args(
                            direct_args,
                            [-1] * len(direct_args),
                            new_statements,
                            call_name=call_name,
                            stack_bindings=direct_bindings or None,
                        )
                        if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                            _set_materialized_call_args(
                                call,
                                normalized_args,
                                call_name=call_name,
                                force_replace=all(
                                    isinstance(source, tuple)
                                    and len(source) >= 2
                                    and source[0] == "bp"
                                    and isinstance(source[1], int)
                                    for source in push_arg_sources
                                ),
                            )
                            record_stack_arg_materialization_8616(codegen, len(normalized_args))
                            _refresh_summary_arg_shape(call, summary)
                            changed = True
                            strict_arg_shape_applied = True
                if len(new_statements) >= expected_arg_count:
                    candidate_stmts = new_statements[-expected_arg_count:]
                    candidate_rhs = []
                    for candidate in candidate_stmts:
                        rhs = _stack_store_rhs_from_statement(candidate)
                        if rhs is None:
                            rhs = _outgoing_arg_placeholder_rhs_from_statement(candidate)
                        candidate_rhs.append(rhs)
                    candidate_indices = list(range(len(new_statements) - expected_arg_count, len(new_statements)))
                    if len(candidate_rhs) > 1:
                        candidate_rhs = list(reversed(candidate_rhs))
                        candidate_indices = list(reversed(candidate_indices))
                    normalized_args = (
                        _normalize_materialized_call_args(
                            candidate_rhs,
                            candidate_indices,
                            new_statements,
                            call_name=call_name,
                        )
                        if all(rhs is not None for rhs in candidate_rhs)
                        else None
                    )
                    if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                        _set_materialized_call_args(call, normalized_args, call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
                        _record_prunable_segment_metadata_ids(
                            call,
                            new_statements,
                            candidate_indices,
                        )
                        del new_statements[-expected_arg_count:]
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if (
                    not strict_arg_shape_applied
                    and typed_stack_probe_fact is not None
                    and stack_probe_seen
                    and not is_stack_probe_helper
                ):
                    expanded_rhs, consumed_indices = _collect_backtracked_stack_args(
                        new_statements,
                        wanted_count=None,
                        max_count=4,
                        typed_probe_fact=typed_stack_probe_fact,
                    )
                    normalized_args = _normalize_materialized_call_args(
                        expanded_rhs,
                        consumed_indices,
                        new_statements,
                        call_name=call_name,
                    )
                    if (
                        normalized_args is not None
                        and len(normalized_args) > expected_arg_count
                        and _all_arg_exprs_are_non_segment_registers(normalized_args)
                    ):
                        _set_materialized_call_args(call, normalized_args, call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
                        _record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                        for consume_idx in sorted(consumed_indices, reverse=True):
                            del new_statements[consume_idx]
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if (
                    not strict_arg_shape_applied
                    and typed_stack_probe_fact is not None
                    and stack_probe_seen
                    and not is_stack_probe_helper
                ):
                    typed_rhs, consumed_indices = _collect_backtracked_stack_args(
                        new_statements,
                        wanted_count=expected_arg_count,
                        max_count=max(expected_arg_count, 1),
                        typed_probe_fact=typed_stack_probe_fact,
                    )
                    normalized_args = _normalize_materialized_call_args(
                        typed_rhs,
                        consumed_indices,
                        new_statements,
                        call_name=call_name,
                    )
                    if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                        _set_materialized_call_args(call, normalized_args, call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
                        _record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                        for consume_idx in sorted(consumed_indices, reverse=True):
                            del new_statements[consume_idx]
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if not strict_arg_shape_applied and not typed_stack_probe_materialization:
                    backtracked_rhs, consumed_indices = _collect_backtracked_stack_args(
                        new_statements,
                        wanted_count=expected_arg_count,
                    )
                    normalized_args = _normalize_materialized_call_args(
                        backtracked_rhs,
                        consumed_indices,
                        new_statements,
                        call_name=call_name,
                    )
                    if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                        _set_materialized_call_args(call, normalized_args, call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
                        _record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                        for consume_idx in sorted(consumed_indices, reverse=True):
                            del new_statements[consume_idx]
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if not strict_arg_shape_applied and not typed_stack_probe_materialization:
                    inline_rhs = _extract_inline_stack_store_args(stmt, call, expected_arg_count)
                    normalized_args = (
                        _normalize_materialized_call_args(
                            list(inline_rhs),
                            list(range(max(0, i - len(inline_rhs)), i)),
                            new_statements,
                            call_name=call_name,
                        )
                        if inline_rhs is not None
                        else None
                    )
                    if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                        _set_materialized_call_args(call, normalized_args, call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if (
                    not strict_arg_shape_applied
                    and not typed_stack_probe_materialization
                    and isinstance(expected_arg_count, int)
                    and expected_arg_count > 0
                ):
                    carrier_rhs, consumed_indices = _collect_backtracked_value_carrier_args(
                        new_statements,
                        wanted_count=expected_arg_count,
                    )
                    normalized_args = _normalize_materialized_call_args(
                        carrier_rhs,
                        consumed_indices,
                        new_statements,
                        call_name=call_name,
                    )
                    if normalized_args is not None and _all_arg_exprs_are_non_segment_registers(normalized_args):
                        _set_materialized_call_args(call, normalized_args, call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, len(normalized_args))
                        for consume_idx in sorted(consumed_indices, reverse=True):
                            del new_statements[consume_idx]
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if (
                    not strict_arg_shape_applied
                    and expected_arg_count == 1
                    and typed_stack_probe_fact is not None
                    and stack_probe_seen
                    and not is_stack_probe_helper
                    and len(new_statements) >= 1
                ):
                    candidate_rhs, consumed_indices = _collect_backtracked_stack_args(
                        new_statements,
                        wanted_count=1,
                        max_count=1,
                        typed_probe_fact=typed_stack_probe_fact,
                    )
                    normalized_args = _normalize_materialized_call_args(
                        candidate_rhs,
                        consumed_indices,
                        new_statements,
                        call_name=call_name,
                    )
                    if normalized_args is not None and not _is_segment_register_value_expr(normalized_args[0]):
                        _set_materialized_call_args(call, [normalized_args[0]], call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, 1)
                        _record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                        for consume_idx in sorted(consumed_indices, reverse=True):
                            del new_statements[consume_idx]
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
                if (
                    not strict_arg_shape_applied
                    and call_name is not None
                    and isinstance(expected_arg_count, int)
                    and expected_arg_count > 0
                ):
                    default_args = _known_default_args_for_missing_8616(call_name, codegen)
                    if default_args is not None and len(default_args) == expected_arg_count:
                        _set_materialized_call_args(call, list(default_args), call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, len(default_args))
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
                        strict_arg_shape_applied = True
            elif (
                call is not None
                and not is_stack_probe_helper
                and (not isinstance(arg_count, int) or arg_count <= 0)
                and rematerialize_call_args
                and len(new_statements) >= 1
            ):
                fallback_args = None
                if isinstance(expected_arg_count, int) and expected_arg_count > 0:
                    if isinstance(push_arg_sources, tuple) and len(push_arg_sources) == expected_arg_count:
                        ordered_push_sources = list(reversed(push_arg_sources)) if len(push_arg_sources) > 1 else list(push_arg_sources)
                        direct_args = [
                            _direct_expr_from_push_source_8616(source, call_name=call_name, arg_index=idx)
                            for idx, source in enumerate(ordered_push_sources)
                        ]
                        if all(arg is not None for arg in direct_args):
                            fallback_args = tuple(direct_args)
                    if fallback_args is None:
                        fallback_args = _known_default_args_for_missing_8616(call_name or "", codegen)
                if fallback_args is not None and isinstance(expected_arg_count, int) and len(fallback_args) == expected_arg_count:
                    _set_materialized_call_args(call, list(fallback_args), call_name=call_name)
                    record_stack_arg_materialization_8616(codegen, len(fallback_args))
                    _refresh_summary_arg_shape(call, summary)
                    changed = True
                    new_statements.append(stmt)
                    i += 1
                    continue
                candidate_rhs, consumed_indices = _collect_backtracked_stack_args(
                    new_statements,
                    wanted_count=None,
                    max_count=4,
                    typed_probe_fact=typed_stack_probe_fact if stack_probe_seen else None,
                )
                normalized_args = _normalize_materialized_call_args(
                    candidate_rhs,
                    consumed_indices,
                    new_statements,
                    call_name=call_name,
                )
                if (
                    normalized_args is not None
                    and _all_arg_exprs_are_non_segment_registers(normalized_args)
                    and (
                        (typed_stack_probe_fact is not None and stack_probe_address_seen and stack_probe_seen)
                        or (not typed_stack_probe_materialization)
                        or (typed_stack_probe_fact is None and stack_probe_seen and stack_probe_address_seen and not is_stack_probe_helper)
                    )
                ):
                    _set_materialized_call_args(call, normalized_args, call_name=call_name)
                    record_stack_arg_materialization_8616(codegen, len(normalized_args))
                    _record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                    for consume_idx in sorted(consumed_indices, reverse=True):
                        del new_statements[consume_idx]
                    _refresh_summary_arg_shape(call, summary)
                    changed = True
                else:
                    inline_rhs = _extract_inline_stack_store_args(stmt, call, 1)
                    normalized_args = (
                        _normalize_materialized_call_args(
                            list(inline_rhs),
                            [max(i - 1, 0)],
                            new_statements,
                            call_name=call_name,
                        )
                        if inline_rhs
                        else None
                    )
                    if (
                        normalized_args is not None
                        and _all_arg_exprs_are_non_segment_registers(normalized_args)
                        and (
                            (typed_stack_probe_fact is not None and stack_probe_address_seen and stack_probe_seen)
                            or (not typed_stack_probe_materialization)
                            or (typed_stack_probe_fact is None and stack_probe_seen and stack_probe_address_seen and not is_stack_probe_helper)
                        )
                    ):
                        _set_materialized_call_args(call, [normalized_args[0]], call_name=call_name)
                        record_stack_arg_materialization_8616(codegen, 1)
                        _refresh_summary_arg_shape(call, summary)
                        changed = True
            new_statements.append(stmt)
            i += 1
        pruned_statements = _prune_stack_probe_frame_artifacts(
            new_statements,
            stack_probe_seen=stack_probe_seen,
        )
        if pruned_statements != new_statements:
            new_statements = pruned_statements
            changed = True

        if new_statements != statements:
            block.statements = new_statements

        for stmt in getattr(block, "statements", ()) or ():
            nested_statements = getattr(stmt, "statements", None)
            if isinstance(nested_statements, (list, tuple)):
                stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact = _rewrite_block(
                    stmt,
                    inherited_stack_probe_seen=stack_probe_seen,
                    inherited_stack_probe_address_seen=stack_probe_address_seen,
                    inherited_typed_stack_probe_fact=typed_stack_probe_fact,
                )
            nested = getattr(stmt, "body", None)
            if isinstance(getattr(nested, "statements", None), (list, tuple)):
                _rewrite_block(
                    nested,
                    inherited_stack_probe_seen=stack_probe_seen,
                    inherited_stack_probe_address_seen=stack_probe_address_seen,
                    inherited_typed_stack_probe_fact=typed_stack_probe_fact,
                )
            else_node = getattr(stmt, "else_node", None)
            if isinstance(getattr(else_node, "statements", None), (list, tuple)):
                _rewrite_block(
                    else_node,
                    inherited_stack_probe_seen=stack_probe_seen,
                    inherited_stack_probe_address_seen=stack_probe_address_seen,
                    inherited_typed_stack_probe_fact=typed_stack_probe_fact,
                )
            for pair in getattr(stmt, "condition_and_nodes", ()) or ():
                if isinstance(pair, tuple) and len(pair) == 2:
                    branch = pair[1]
                    if isinstance(getattr(branch, "statements", None), (list, tuple)):
                        _rewrite_block(
                            branch,
                            inherited_stack_probe_seen=stack_probe_seen,
                            inherited_stack_probe_address_seen=stack_probe_address_seen,
                            inherited_typed_stack_probe_fact=typed_stack_probe_fact,
                        )
        return stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact

    root = _structured_root_8616(cfunc)
    if isinstance(getattr(root, "statements", None), (list, tuple)):
        _rewrite_block(root)
        # Last-resort stability guard: known helpers must not be left as empty
        # calls after materialization. Use summary evidence/defaults to seed arity.
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, CFunctionCall) or _is_runtime_segment_helper_call_8616(node):
                continue
            call_name = _call_node_name_8616(node) or ""
            known_count = _expected_arg_count_for_known_callee_8616(call_name)
            if not (isinstance(known_count, int) and known_count > 0):
                continue
            if tuple(getattr(node, "args", ()) or ()):
                continue
            summary = summary_map.get(id(node))
            push_sources = getattr(summary, "push_arg_sources", ()) if summary is not None else ()
            seeded_args = None
            if isinstance(push_sources, tuple) and len(push_sources) == known_count:
                ordered_sources = list(reversed(push_sources)) if len(push_sources) > 1 else list(push_sources)
                direct_args = [
                    _direct_expr_from_push_source_8616(source, call_name=call_name, arg_index=idx)
                    for idx, source in enumerate(ordered_sources)
                ]
                if all(arg is not None for arg in direct_args):
                    seeded_args = tuple(direct_args)
            if seeded_args is None:
                defaults = _known_default_args_for_missing_8616(call_name, codegen)
                if defaults is not None and len(defaults) == known_count:
                    seeded_args = tuple(defaults)
            # No guessing: if we cannot recover arguments from push sources and
            # have no explicit helper defaults, keep the original call shape.
            if seeded_args is None:
                continue
            _set_materialized_call_args(node, seeded_args, call_name=call_name, force_replace=True)
            _refresh_summary_arg_shape(node, summary)
            changed = True
        if _restore_protected_call_args_8616(root):
            changed = True
    codegen._inertia_materialized_callsite_metadata_ids = materialized_callsite_metadata_ids
    if prune_materialized_callsite_segment_metadata_8616(project, codegen):
        changed = True
    return changed
