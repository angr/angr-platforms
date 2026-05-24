from __future__ import annotations

import hashlib
import contextlib
import json
import os
from collections import Counter
from collections.abc import MutableMapping
from dataclasses import asdict, dataclass
import re
from typing import Callable, Mapping, Sequence, TypeVar

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CContinue,
    CDoWhileLoop,
    CForLoop,
    CFunctionCall,
    CGoto,
    CIfBreak,
    CIfElse,
    CReturn,
    CStatements,
    CSwitchCase,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .decompiler_postprocess_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from .decompiler_postprocess_flags import _split_ordering_if_chain_replacement_condition_8616
from .ir.condition_ir import (
    _INVERTED_COMPARISON_OPS_8616,
    normalize_condition_fingerprint_algebraic_8616,
    normalize_condition_fingerprint_string_8616,
)
from .tail_validation_condition_context import build_x86_16_contextual_condition_fingerprints
from .tail_validation_fingerprint import (
    TAIL_VALIDATION_FINGERPRINT_VERSION,
    _bool_projection_fingerprint,
    _c_constant_int_value,
    _expr_fingerprint,
    _call_target_name,
    _collect_direct_capstone_callsite_addrs_8616,
    _extract_same_zero_compare_expr_8616,
    _extract_zero_flag_source_expr_8616,
    _function_for_call_context_8616,
    _is_runtime_segment_helper_call_8616,
    _lookup_function_for_call_context_8616,
    _location_fingerprint,
    _normalize_zero_flag_comparison_8616,
    _register_name,
    _wrap_not_fingerprint,
    build_x86_16_contextual_call_fingerprints,
)
from .callsite_summary import summarize_x86_16_callsite
from .tail_validation_stack_policy import include_x86_16_tail_validation_stack_write
from .tail_validation_routing import build_tail_validation_family_routing

__all__ = [
    "X86_16TailValidationSummary",
    "X86_16ValidationCacheDescriptor",
    "annotate_x86_16_tail_validation_surface_with_baseline",
    "build_x86_16_tail_validation_aggregate",
    "build_x86_16_tail_validation_baseline",
    "build_x86_16_tail_validation_surface",
    "build_x86_16_tail_validation_cached_result",
    "build_x86_16_validation_cache_descriptor",
    "check_x86_16_tail_validation_surface_consistency",
    "compare_x86_16_tail_validation_baseline",
    "persist_x86_16_tail_validation_snapshot",
    "fingerprint_x86_16_tail_validation_boundary",
    "extract_x86_16_tail_validation_snapshot",
    "x86_16_tail_validation_snapshot_passed",
    "resolve_x86_16_validation_cached_artifact",
    "summarize_x86_16_tail_validation_records",
    "collect_x86_16_tail_validation_summary",
    "compare_x86_16_tail_validation_summaries",
    "build_x86_16_tail_validation_verdict",
    "format_x86_16_tail_validation_diff",
    "describe_x86_16_tail_validation_scope",
]

_TAIL_VALIDATION_MODES = {"coarse", "live_out"}
_TAIL_VALIDATION_AGGREGATE_CACHE: dict[str, dict[str, object]] = {}
_T = TypeVar("_T")
_TAIL_VALIDATION_OBSERVABLE_FIELDS = (
    "helper_calls",
    "register_writes",
    "stack_writes",
    "global_writes",
    "segmented_writes",
    "returns",
    "conditions",
    "control_flow_effects",
)


@dataclass(frozen=True, slots=True)
class X86_16TailValidationSummary:
    helper_calls: tuple[str, ...]
    register_writes: tuple[str, ...]
    stack_writes: tuple[str, ...]
    global_writes: tuple[str, ...]
    segmented_writes: tuple[str, ...]
    returns: tuple[str, ...]
    conditions: tuple[str, ...]
    control_flow_effects: tuple[str, ...]

    def as_dict(self) -> dict[str, tuple[str, ...]]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class X86_16ValidationCacheDescriptor:
    namespace: str
    fingerprint: str
    cache_key: str


def build_x86_16_validation_cache_descriptor(namespace: str, payload: object) -> X86_16ValidationCacheDescriptor:
    fingerprint = _json_fingerprint({"namespace": namespace, "payload": payload})
    return X86_16ValidationCacheDescriptor(
        namespace=namespace,
        fingerprint=fingerprint,
        cache_key=f"{namespace}:{fingerprint}",
    )


def resolve_x86_16_validation_cached_artifact(
    *,
    cache: MutableMapping[str, object] | None,
    descriptor: X86_16ValidationCacheDescriptor,
    build: Callable[[], _T],
    clone_on_hit: Callable[[_T], _T] | None = None,
    store_value: Callable[[_T], object] | None = None,
) -> dict[str, object]:
    if cache is not None:
        cached = cache.get(descriptor.cache_key)
        if cached is not None:
            value = clone_on_hit(cached) if clone_on_hit is not None else cached
            return {
                "cache_key": descriptor.cache_key,
                "cache_hit": True,
                "fingerprint": descriptor.fingerprint,
                "value": value,
            }

    value = build()
    if cache is not None:
        cache[descriptor.cache_key] = store_value(value) if store_value is not None else value
    return {
        "cache_key": descriptor.cache_key,
        "cache_hit": False,
        "fingerprint": descriptor.fingerprint,
        "value": value,
    }




def _codegen_root(codegen):
    cfunc = getattr(codegen, "cfunc", None)
    for attr in ("body", "statements", "stmt"):
        value = getattr(cfunc, attr, None)
        if value is not None:
            return value
    return cfunc


def _sorted_unique(values: set[str]) -> tuple[str, ...]:
    return tuple(sorted(values))


def _json_fingerprint(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _canonicalize_summary_field_values_8616(field_name: str, values: set[str]) -> set[str]:
    """Canonicalize condition/control-flow fingerprint strings for comparison.

    Delegates to two IR-layer normalizers:
    1. ``normalize_condition_fingerprint_string_8616`` inverts ``Not(CmpEQ(...))`` → ``CmpNE(...)``
    2. ``normalize_condition_fingerprint_algebraic_8616`` canonicalizes ``CmpEQ(Sub(x,const:c),const:0)`` → ``CmpEQ(x,const:c)``

    These are validation-only; they do not mutate IR or feed results back into recovery.
    """
    if field_name not in {"conditions", "control_flow_effects"}:
        return values
    normalized: set[str] = set()
    for value in values:
        v1 = normalize_condition_fingerprint_string_8616(value)
        v2 = normalize_condition_fingerprint_algebraic_8616(v1)
        normalized.add(v2)
    return normalized


def _invert_condition_fingerprint_8616(node, project, contextual_condition_fingerprints: Mapping[int, str]) -> str | None:
    if isinstance(node, CBinaryOp):
        inverted_op = _INVERTED_COMPARISON_OPS_8616.get(node.op)
        if inverted_op is not None:
            lhs = _expr_fingerprint(node.lhs, project)
            rhs = _expr_fingerprint(node.rhs, project)
            return f"{inverted_op}({lhs},{rhs})"
    if isinstance(node, CUnaryOp) and node.op == "Not":
        return contextual_condition_fingerprints.get(id(node.operand), _expr_fingerprint(node.operand, project))
    fingerprint = contextual_condition_fingerprints.get(id(node), _expr_fingerprint(node, project))
    return _wrap_not_fingerprint(fingerprint)


def _extract_loop_break_guard_normalization_8616(
    loop, project, contextual_condition_fingerprints: Mapping[int, str]
) -> tuple[str, set[int]] | None:
    condition = getattr(loop, "condition", None)
    if _c_constant_int_value(condition) != 1:
        return None

    body = getattr(loop, "body", None)
    statements = tuple(getattr(body, "statements", ()) or ())
    if not statements:
        return None

    first_stmt = statements[0]
    break_cond = None
    suppressed_node_ids = {id(first_stmt)}

    if isinstance(first_stmt, CIfBreak):
        break_cond = getattr(first_stmt, "condition", None)
    elif isinstance(first_stmt, CIfElse):
        branches = tuple(getattr(first_stmt, "condition_and_nodes", ()) or ())
        if len(branches) != 1 or getattr(first_stmt, "else_node", None) is not None:
            return None
        break_cond, branch_node = branches[0]
        branch_statements = tuple(getattr(branch_node, "statements", ()) or ())
        if len(branch_statements) != 1 or not isinstance(branch_statements[0], CBreak):
            return None
        suppressed_node_ids.add(id(branch_statements[0]))
    else:
        return None

    if break_cond is None:
        return None
    normalized = _invert_condition_fingerprint_8616(break_cond, project, contextual_condition_fingerprints)
    if normalized is None:
        return None
    return normalized, suppressed_node_ids


def _normalized_if_chain_condition_8616(pairs, idx: int, codegen):
    if idx <= 0 or idx >= len(pairs):
        return None
    prev_cond, _prev_body = pairs[idx - 1]
    curr_cond, _curr_body = pairs[idx]
    return _split_ordering_if_chain_replacement_condition_8616(prev_cond, curr_cond, codegen)


def _normalized_call_target_addr_8616(project, target_addr: int | None) -> int | None:
    if not isinstance(target_addr, int):
        return None
    main_object = getattr(getattr(project, "loader", None), "main_object", None)
    linked_base = getattr(main_object, "linked_base", None)
    max_addr = getattr(main_object, "max_addr", None)
    image_end = linked_base + max_addr + 1 if isinstance(linked_base, int) and isinstance(max_addr, int) else None
    return _normalize_direct_call_target_8616(target_addr, linked_base, image_end)


def _call_summary_target_addr_8616(project, summary) -> int | None:
    if isinstance(summary, Mapping):
        return _normalized_call_target_addr_8616(project, summary.get("target_addr"))
    return _normalized_call_target_addr_8616(project, getattr(summary, "target_addr", None))


def _node_callsite_addr_8616(node) -> int | None:
    tags = getattr(node, "tags", None)
    if isinstance(tags, dict):
        for key in ("ins_addr", "insn_addr", "stmt_addr", "addr"):
            value = tags.get(key)
            if isinstance(value, int):
                return value
    value = getattr(node, "addr", None)
    return value if isinstance(value, int) else None


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
        match = re.search(r"0x([0-9a-fA-F]+)", target)
        if match is None:
            continue
        try:
            addrs.append(int(match.group(1), 16))
        except ValueError:
            continue
    ordered: list[int] = []
    for addr in addrs:
        if addr not in ordered:
            ordered.append(addr)
    return tuple(ordered)


def _call_node_matches_summary_8616(project, node, summary) -> bool:
    if node is None or summary is None:
        return False
    target_addr = _call_summary_target_addr_8616(project, summary)
    if not isinstance(target_addr, int):
        return False
    return target_addr in {
        _normalized_call_target_addr_8616(project, candidate_addr)
        for candidate_addr in _candidate_target_addrs_from_call_8616(node)
        if isinstance(candidate_addr, int)
    }


def _ordered_contextual_call_pairs_8616(root, project) -> list[tuple[CFunctionCall, int]]:
    function = _function_for_call_context_8616(root, project)
    if function is None:
        return []
    callsite_addrs = tuple(sorted(getattr(function, "get_call_sites", lambda: [])() or ()))
    if not callsite_addrs:
        callsite_addrs = _collect_direct_capstone_callsite_addrs_8616(function)
    call_nodes = list(_iter_observable_call_nodes_for_validation_8616(root))
    if not callsite_addrs or not call_nodes:
        return []

    nodes_by_callsite: dict[int, list[CFunctionCall]] = {}
    remaining_nodes: list[CFunctionCall] = []
    for node in call_nodes:
        callsite_addr = _node_callsite_addr_8616(node)
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
            node = matched_nodes.pop(0)
            ordered_pairs.append((node, callsite_addr))
            used_node_ids.add(id(node))
        else:
            unmatched_callsites.append(callsite_addr)

    remaining_nodes.extend(node for node in call_nodes if id(node) not in used_node_ids and node not in remaining_nodes)
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
            continue
        node = available_nodes.pop(matched_index)
        ordered_pairs.append((node, callsite_addr))
    return ordered_pairs


def _node_boundary_fingerprint(
    node,
    project,
    contextual_call_fingerprints: Mapping[int, str] | None = None,
    contextual_call_summaries: Mapping[int, object] | None = None,
):
    if node is None:
        return None
    contextual_condition_fingerprints = getattr(
        project,
        "_inertia_tail_validation_contextual_condition_fingerprints",
        None,
    )
    if isinstance(contextual_condition_fingerprints, Mapping):
        condition_fingerprint = contextual_condition_fingerprints.get(id(node))
        if isinstance(condition_fingerprint, str):
            return ("condition", condition_fingerprint)
    if isinstance(node, CConstant):
        return ("const", node.value)
    if isinstance(node, CVariable):
        return ("var", _location_fingerprint(node, project))
    if isinstance(node, CTypeCast):
        return (
            "cast",
            _node_boundary_fingerprint(
                node.expr,
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
        )
    if isinstance(node, CUnaryOp):
        return (
            "unary",
            node.op,
            _node_boundary_fingerprint(
                node.operand,
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
        )
    if isinstance(node, CBinaryOp):
        return (
            "binary",
            node.op,
            _node_boundary_fingerprint(
                node.lhs,
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
            _node_boundary_fingerprint(
                node.rhs,
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
        )
    if isinstance(node, CFunctionCall):
        if _is_runtime_segment_helper_call_8616(node):
            return ("expr", _expr_fingerprint(node, project))
        call_fingerprint = None
        if isinstance(contextual_call_fingerprints, Mapping):
            call_fingerprint = contextual_call_fingerprints.get(id(node))
        if call_fingerprint is None and isinstance(contextual_call_summaries, Mapping):
            summary = contextual_call_summaries.get(id(node))
            target_addr = _call_summary_target_addr_8616(project, summary)
            if isinstance(target_addr, int):
                call_fingerprint = f"addr:{target_addr:#x}"
        return (
            "call",
            call_fingerprint or _call_target_name(node, project),
            tuple(
                _node_boundary_fingerprint(
                    arg,
                    project,
                    contextual_call_fingerprints,
                    contextual_call_summaries,
                )
                for arg in (getattr(node, "args", ()) or ())
            ),
        )
    if isinstance(node, CAssignment):
        return (
            "assign",
            _node_boundary_fingerprint(
                node.lhs,
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
            _node_boundary_fingerprint(
                node.rhs,
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
        )
    if isinstance(node, CReturn):
        return (
            "return",
            _node_boundary_fingerprint(
                getattr(node, "retval", None),
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
        )
    if isinstance(node, CIfElse):
        return (
            "ifelse",
            tuple(
                (
                    _node_boundary_fingerprint(
                        cond,
                        project,
                        contextual_call_fingerprints,
                        contextual_call_summaries,
                    ),
                    _node_boundary_fingerprint(
                        body,
                        project,
                        contextual_call_fingerprints,
                        contextual_call_summaries,
                    ),
                )
                for cond, body in (getattr(node, "condition_and_nodes", ()) or ())
            ),
            _node_boundary_fingerprint(
                getattr(node, "else_node", None),
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
        )
    if isinstance(node, CIfBreak):
        return (
            "ifbreak",
            _node_boundary_fingerprint(
                getattr(node, "condition", None),
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
        )
    if isinstance(node, CWhileLoop):
        return (
            "while",
            _node_boundary_fingerprint(
                getattr(node, "condition", None),
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
            _node_boundary_fingerprint(
                getattr(node, "body", None),
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
        )
    if isinstance(node, CDoWhileLoop):
        return (
            "dowhile",
            _node_boundary_fingerprint(
                getattr(node, "condition", None),
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
            _node_boundary_fingerprint(
                getattr(node, "body", None),
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
        )
    if isinstance(node, CForLoop):
        return (
            "for",
            _node_boundary_fingerprint(
                getattr(node, "initializer", None),
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
            _node_boundary_fingerprint(
                getattr(node, "condition", None),
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
            _node_boundary_fingerprint(
                getattr(node, "iterator", None),
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
            _node_boundary_fingerprint(
                getattr(node, "body", None),
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
        )
    if isinstance(node, CSwitchCase):
        cases = getattr(node, "cases", None)
        case_items = ()
        if isinstance(cases, dict):
            case_items = tuple(
                (
                    _switch_case_fingerprint(case_value, project),
                    _node_boundary_fingerprint(case_body, project),
                )
                for case_value, case_body in sorted(cases.items(), key=lambda item: _switch_case_fingerprint(item[0], project))
            )
        return (
            "switch",
            _node_boundary_fingerprint(
                getattr(node, "switch", None),
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
            case_items,
            _node_boundary_fingerprint(
                getattr(node, "default", None),
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
        )
    if isinstance(node, CGoto):
        return ("goto", getattr(node, "target", None), getattr(node, "target_idx", None))
    if isinstance(node, CBreak):
        return ("break",)
    if isinstance(node, CContinue):
        return ("continue",)
    if type(node).__name__ == "CStatements":
        return (
            "statements",
            tuple(
                _node_boundary_fingerprint(
                    stmt,
                    project,
                    contextual_call_fingerprints,
                    contextual_call_summaries,
                )
                for stmt in (getattr(node, "statements", ()) or ())
            ),
        )

    fields = []
    for attr in ("condition", "cond", "body", "else_node", "iftrue", "iffalse", "lhs", "rhs", "expr", "operand", "retval"):
        if hasattr(node, attr):
            fields.append((attr, _node_boundary_fingerprint(getattr(node, attr, None), project)))
    return (type(node).__name__, tuple(fields))


def _tail_validation_summary_cache_store(codegen) -> dict[str, object]:
    cache = getattr(codegen, "_inertia_tail_validation_summary_cache", None)
    if not isinstance(cache, dict):
        cache = {}
        codegen._inertia_tail_validation_summary_cache = cache
    stats = cache.setdefault("stats", {"hits": 0, "misses": 0})
    if not isinstance(stats, dict):
        cache["stats"] = {"hits": 0, "misses": 0}
    cache.setdefault("entries", {})
    return cache


def _clone_tail_validation_aggregate_payload(value: Mapping[str, object]) -> dict[str, object]:
    surface = value.get("surface")
    return {
        "summary": dict(value["summary"]),
        "surface": dict(surface) if isinstance(surface, Mapping) else None,
    }


def _records_with_uncollected_placeholders(
    records: Sequence[Mapping[str, object]],
    *,
    scanned: int,
) -> list[Mapping[str, object]]:
    normalized = [record for record in records if isinstance(record, Mapping)]
    missing_records = max(0, int(scanned or 0) - len(normalized))
    if missing_records <= 0:
        return normalized
    return normalized + [{} for _ in range(missing_records)]


def _tail_validation_validation_cache_store(owner) -> dict[str, object]:
    if owner is None:
        return {}
    if isinstance(owner, MutableMapping):
        cache = owner.setdefault("_x86_16_tail_validation_cache", {})
        if not isinstance(cache, MutableMapping):
            cache = {}
            owner["_x86_16_tail_validation_cache"] = cache
        cache.setdefault("comparisons", {})
        return cache
    return {}


def _tail_validation_records_fingerprint(records: Sequence[Mapping[str, object]], *, scanned: int) -> str:
    payload = {
        "scanned": int(scanned or 0),
        "records": [
            {
                "cod_file": record.get("cod_file"),
                "proc_name": record.get("proc_name"),
                "proc_kind": record.get("proc_kind"),
                "structuring": record.get("structuring"),
                "postprocess": record.get("postprocess"),
                "tail_validation_uncollected": record.get("tail_validation_uncollected"),
                "exit_kind": record.get("exit_kind"),
                "exit_detail": record.get("exit_detail"),
            }
            for record in records
        ],
    }
    return build_x86_16_validation_cache_descriptor("tail_validation.aggregate.records", payload).fingerprint


def _tail_validation_changed_observable_fields(entry: Mapping[str, object]) -> tuple[str, ...]:
    delta = entry.get("delta")
    changed_fields: list[str] = []
    if isinstance(delta, Mapping):
        for field_name in _TAIL_VALIDATION_OBSERVABLE_FIELDS:
            field_delta = delta.get(field_name)
            if not isinstance(field_delta, Mapping):
                continue
            added = field_delta.get("added", ()) or ()
            removed = field_delta.get("removed", ()) or ()
            if added or removed:
                changed_fields.append(field_name)
        if changed_fields:
            return tuple(changed_fields)

    text_parts = []
    for key in ("summary_text", "verdict"):
        value = entry.get(key)
        if isinstance(value, str):
            text_parts.append(value)
    combined = " ".join(text_parts)
    return tuple(field_name for field_name in _TAIL_VALIDATION_OBSERVABLE_FIELDS if f"{field_name}:" in combined)


def _tail_validation_changed_families(entry: Mapping[str, object]) -> tuple[str, ...]:
    fields = set(_tail_validation_changed_observable_fields(entry))
    families: list[str] = []
    if "helper_calls" in fields:
        families.append("helper call delta")
    if "register_writes" in fields:
        families.append("live-out register delta")
    if "stack_writes" in fields:
        families.append("stack write delta")
    if {"global_writes", "segmented_writes"} <= fields:
        families.append("segmented/global write delta")
    else:
        if "global_writes" in fields:
            families.append("global write delta")
        if "segmented_writes" in fields:
            families.append("segmented write delta")
    if "returns" in fields:
        families.append("return delta")
    if "conditions" in fields or "control_flow_effects" in fields:
        families.append("control-flow/guard delta")
    if not families:
        families.append("unclassified observable delta")
    return tuple(families)


def _tail_validation_changed_family_summary(changed_functions: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    rows: dict[str, dict[str, object]] = {}
    for item in changed_functions:
        if not isinstance(item, Mapping):
            continue
        stage = item.get("stage")
        function_key = (item.get("cod_file"), item.get("proc_name"), item.get("proc_kind"))
        function_label = {
            "cod_file": item.get("cod_file"),
            "proc_name": item.get("proc_name"),
            "proc_kind": item.get("proc_kind"),
        }
        families = item.get("families")
        if not isinstance(families, Sequence) or isinstance(families, (str, bytes)):
            families = ("unclassified observable delta",)
        for family in families:
            if not isinstance(family, str) or not family:
                continue
            row = rows.setdefault(
                family,
                {
                    "family": family,
                    "count": 0,
                    "stages": set(),
                    "functions": set(),
                    "examples": [],
                },
            )
            row["count"] += 1
            if isinstance(stage, str) and stage:
                row["stages"].add(stage)
            row["functions"].add(function_key)
            if len(row["examples"]) < 5 and function_label not in row["examples"]:
                row["examples"].append(function_label)

    summarized = []
    for row in rows.values():
        summarized.append(
            {
                "family": row["family"],
                "count": row["count"],
                "function_count": len(row["functions"]),
                "stages": tuple(sorted(row["stages"])),
                "examples": tuple(row["examples"]),
            }
        )
    return sorted(summarized, key=lambda item: (-int(item["count"]), item["family"]))


def _tail_validation_sort_value(value: object) -> str:
    return value if isinstance(value, str) else ""


def _tail_validation_function_sort_key(item: Mapping[str, object]) -> tuple[str, str, str, str]:
    return (
        "" if isinstance(item.get("cod_file"), str) else "~",
        _tail_validation_sort_value(item.get("cod_file")),
        _tail_validation_sort_value(item.get("proc_name")),
        _tail_validation_sort_value(item.get("proc_kind")),
    )


def _tail_validation_stage_status(entry: object) -> str:
    if not isinstance(entry, Mapping):
        return "uncollected"
    status = entry.get("status")
    if isinstance(status, str) and status:
        normalized = status.lower()
        if normalized in {"stable", "passed"}:
            return "passed"
        if normalized in {"changed", "uncollected"}:
            return normalized
        if normalized == "failed":
            return "changed"
        if normalized == "unknown":
            return "unknown"
        return "uncollected"
    if "changed" not in entry:
        return "unknown"
    return "changed" if bool(entry.get("changed", False)) else "passed"


def _tail_validation_record_proc_name(record: Mapping[str, object]) -> object:
    proc_name = record.get("proc_name")
    if proc_name:
        return proc_name
    return record.get("function_name")


def _tail_validation_function_accounting(records: Sequence[Mapping[str, object]]) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    status_counts: Counter[str] = Counter()
    for record in records:
        proc_name = _tail_validation_record_proc_name(record)
        stage_statuses = {
            stage: _tail_validation_stage_status(record.get(stage))
            for stage in ("structuring", "postprocess")
        }
        if "changed" in stage_statuses.values():
            status = "changed"
        elif "unknown" in stage_statuses.values():
            status = "unknown"
        elif "uncollected" in stage_statuses.values():
            status = "uncollected"
        else:
            status = "passed"
        status_counts[status] += 1
        rows.append(
            {
                "cod_file": record.get("cod_file"),
                "proc_name": proc_name,
                "proc_kind": record.get("proc_kind"),
                "status": status,
                "stage_statuses": dict(sorted(stage_statuses.items())),
                "exit_kind": record.get("exit_kind"),
                "exit_detail": record.get("exit_detail"),
                "tail_validation_uncollected": bool(record.get("tail_validation_uncollected", False)),
            }
        )
    rows.sort(key=_tail_validation_function_sort_key)
    return {
        "function_status_counts": dict(sorted(status_counts.items())),
        "function_statuses": rows,
        "passed_functions": [row for row in rows if row["status"] == "passed"],
        "changed_functions": [row for row in rows if row["status"] == "changed"],
        "unknown_functions": [row for row in rows if row["status"] == "unknown"],
        "uncollected_functions": [row for row in rows if row["status"] == "uncollected"],
    }


def _tail_validation_stage_summary(records: Sequence[Mapping[str, object]], stage: str) -> dict[str, object]:
    stable_count = 0
    changed_count = 0
    unknown_count = 0
    missing_count = 0
    mode_counter: Counter[str] = Counter()
    verdict_counter: Counter[str] = Counter()
    changed_functions: list[dict[str, object]] = []

    for record in records:
        entry = record.get(stage)
        if not isinstance(entry, Mapping):
            missing_count += 1
            continue
        if "changed" not in entry:
            unknown_count += 1
            continue
        changed = bool(entry.get("changed", False))
        mode = entry.get("mode")
        verdict = entry.get("verdict")
        if isinstance(mode, str) and mode:
            mode_counter[mode] += 1
        if changed:
            changed_count += 1
            if isinstance(verdict, str) and verdict:
                verdict_counter[verdict] += 1
            families = _tail_validation_changed_families(entry)
            changed_functions.append(
                {
                    "cod_file": record.get("cod_file"),
                    "proc_name": _tail_validation_record_proc_name(record),
                    "proc_kind": record.get("proc_kind"),
                    "stage": stage,
                    "verdict": verdict,
                    "families": families,
                }
            )
        else:
            stable_count += 1

    changed_functions.sort(
        key=lambda item: (
            "" if isinstance(item.get("cod_file"), str) else "~",
            item.get("cod_file"),
            item.get("proc_name"),
            item.get("proc_kind"),
        )
    )
    top_verdicts = [
        {"verdict": verdict, "count": count}
        for verdict, count in sorted(verdict_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    return {
        "stable_count": stable_count,
        "changed_count": changed_count,
        "unknown_count": unknown_count,
        "missing_count": missing_count,
        "coverage_count": stable_count + changed_count + unknown_count,
        "mode_counts": dict(sorted(mode_counter.items())),
        "top_verdicts": top_verdicts,
        "changed_functions": changed_functions,
        "changed_families": _tail_validation_changed_family_summary(changed_functions),
    }


def _switch_case_fingerprint(case_value, project) -> str:
    if isinstance(case_value, (tuple, list)):
        return "[" + ",".join(_switch_case_fingerprint(item, project) for item in case_value) + "]"
    return _expr_fingerprint(case_value, project)


def fingerprint_x86_16_tail_validation_boundary(project, codegen, *, mode: str = "live_out") -> str:
    if mode not in _TAIL_VALIDATION_MODES:
        raise ValueError(f"Unsupported x86-16 tail validation mode: {mode}")
    root = _codegen_root(codegen)
    contextual_call_fingerprints = build_x86_16_contextual_call_fingerprints(root, project)
    contextual_call_summaries = _build_contextual_call_summary_map(root, project)
    contextual_condition_fingerprints = build_x86_16_contextual_condition_fingerprints(root, project)
    previous_condition_fingerprints = getattr(
        project,
        "_inertia_tail_validation_contextual_condition_fingerprints",
        None,
    )
    project._inertia_tail_validation_contextual_condition_fingerprints = contextual_condition_fingerprints
    try:
        payload = {
            "arch": getattr(getattr(project, "arch", None), "name", None),
            "mode": mode,
            "fingerprint_version": TAIL_VALIDATION_FINGERPRINT_VERSION,
            "root": _node_boundary_fingerprint(
                root,
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            ),
        }
    finally:
        if previous_condition_fingerprints is None:
            with contextlib.suppress(Exception):
                delattr(project, "_inertia_tail_validation_contextual_condition_fingerprints")
        else:
            project._inertia_tail_validation_contextual_condition_fingerprints = previous_condition_fingerprints
    return build_x86_16_validation_cache_descriptor("tail_validation.boundary", payload).fingerprint


def extract_x86_16_tail_validation_snapshot(function_info: Mapping[str, object] | None) -> dict[str, object]:
    stages: dict[str, object] = {}
    if not isinstance(function_info, Mapping):
        return stages
    validation_info = function_info.get("x86_16_tail_validation")
    if not isinstance(validation_info, Mapping):
        return stages
    for stage in ("structuring", "postprocess"):
        entry = validation_info.get(stage)
        if not isinstance(entry, Mapping):
            continue
        status = entry.get("status")
        if not (isinstance(status, str) and status):
            if "changed" in entry:
                status = "changed" if bool(entry.get("changed", False)) else "stable"
            else:
                # No "changed" field and no explicit status means the entry
                # was persisted without classification metadata and should be
                # treated as unknown rather than silently forcing uncollected.
                status = "unknown"
        changed_value = bool(entry.get("changed", False))
        if not isinstance(entry.get("changed"), bool) and "changed" not in entry:
            changed_value = False
        stages[stage] = {
            "changed": changed_value,
            "status": status,
            "mode": entry.get("mode"),
            "verdict": entry.get("verdict"),
            "summary_text": entry.get("summary_text"),
        }
        delta = entry.get("delta")
        if isinstance(delta, Mapping):
            stages[stage]["delta"] = dict(delta)
    return stages


def x86_16_tail_validation_result_passed(validation: Mapping[str, object] | None) -> bool:
    if not isinstance(validation, Mapping):
        return False
    status = validation.get("status")
    if isinstance(status, str) and status:
        return status.lower() in {"stable", "passed"}
    if "changed" in validation:
        return not bool(validation.get("changed", False))
    return False


def x86_16_tail_validation_snapshot_passed(
    snapshot: Mapping[str, object] | None,
    *,
    expected_stages: Sequence[str] = ("structuring", "postprocess"),
) -> bool:
    if not isinstance(snapshot, Mapping):
        return False
    required_stages = tuple(stage for stage in expected_stages if isinstance(stage, str) and stage)
    if not required_stages:
        return False
    for stage in required_stages:
        entry = snapshot.get(stage)
        if not isinstance(entry, Mapping):
            return False
        status = entry.get("status")
        if isinstance(status, str) and status:
            if status != "stable":
                return False
            continue
        if bool(entry.get("changed", False)):
            return False
    return True


def persist_x86_16_tail_validation_snapshot(
    *,
    function_info: MutableMapping[str, object] | None,
    codegen,
    stage: str,
    validation: Mapping[str, object],
) -> dict[str, object]:
    status = validation.get("status")
    if not isinstance(status, str) or not status:
        status = "changed" if bool(validation.get("changed", False)) else "stable"
    snapshot_entry = {
        "changed": bool(validation.get("changed", False)),
        "status": status,
        "mode": validation.get("mode"),
        "verdict": validation.get("verdict"),
        "summary_text": validation.get("summary_text"),
    }
    delta = validation.get("delta")
    if isinstance(delta, Mapping):
        snapshot_entry["delta"] = dict(delta)
    if isinstance(function_info, MutableMapping):
        validation_info = function_info.setdefault("x86_16_tail_validation", {})
        if isinstance(validation_info, MutableMapping):
            validation_info[stage] = dict(snapshot_entry)
    if codegen is not None:
        snapshot = getattr(codegen, "_inertia_tail_validation_snapshot", None)
        if not isinstance(snapshot, dict):
            snapshot = {}
            codegen._inertia_tail_validation_snapshot = snapshot
        snapshot[stage] = snapshot_entry
    return snapshot_entry


def check_x86_16_tail_validation_surface_consistency(
    summary: Mapping[str, object],
    surface: Mapping[str, object],
    *,
    scanned: int,
) -> tuple[str, ...]:
    issues: list[str] = []
    scanned_count = max(int(scanned or 0), 0)
    structuring = dict(summary.get("structuring", {}) or {})
    postprocess = dict(summary.get("postprocess", {}) or {})
    stage_summaries = {"structuring": structuring, "postprocess": postprocess}
    stage_rows = {
        row.get("stage"): row
        for row in surface.get("stage_rows", ()) or ()
        if isinstance(row, Mapping) and isinstance(row.get("stage"), str)
    }
    expected_changed_total = sum(int(stage.get("changed_count", 0) or 0) for stage in stage_summaries.values())
    expected_missing_total = sum(int(stage.get("missing_count", 0) or 0) for stage in stage_summaries.values())
    expected_unknown_total = sum(int(stage.get("unknown_count", 0) or 0) for stage in stage_summaries.values())
    expected_coverage_total = sum(int(stage.get("coverage_count", 0) or 0) for stage in stage_summaries.values())
    checks = (
        ("changed_stage_total", expected_changed_total),
        ("missing_stage_total", expected_missing_total),
        ("unknown_stage_total", expected_unknown_total),
        ("coverage_count", expected_coverage_total),
        ("changed_function_count", int(summary.get("changed_function_count", 0) or 0)),
        ("passed_function_count", int(summary.get("passed_function_count", 0) or 0)),
        ("unknown_function_count", int(summary.get("unknown_function_count", 0) or 0)),
        ("uncollected_function_count", int(summary.get("uncollected_function_count", 0) or 0)),
    )
    for key, expected in checks:
        actual = int(surface.get(key, 0) or 0)
        if actual != expected:
            issues.append(f"{key}: surface={actual} summary={expected}")
    if dict(surface.get("function_status_counts", {}) or {}) != dict(summary.get("function_status_counts", {}) or {}):
        issues.append("function_status_counts mismatch")
    if len(surface.get("function_statuses", ()) or ()) != scanned_count:
        issues.append(
            f"function_statuses: surface={len(surface.get('function_statuses', ()) or ())} scanned={scanned_count}"
        )
    for stage_name, stage_summary in stage_summaries.items():
        row = stage_rows.get(stage_name)
        if not isinstance(row, Mapping):
            issues.append(f"{stage_name}: missing stage row")
            continue
        for key in ("changed_count", "stable_count", "unknown_count", "missing_count", "coverage_count"):
            actual = int(row.get(key, 0) or 0)
            expected = int(stage_summary.get(key, 0) or 0)
            if actual != expected:
                issues.append(f"{stage_name}.{key}: surface={actual} summary={expected}")
    return tuple(issues)


def build_x86_16_tail_validation_surface(summary: Mapping[str, object], *, scanned: int) -> dict[str, object]:
    scanned_count = max(int(scanned or 0), 0)
    severity = str(summary.get("severity", "uncollected"))
    changed_function_count = int(summary.get("changed_function_count", 0) or 0)
    structuring = dict(summary.get("structuring", {}) or {})
    postprocess = dict(summary.get("postprocess", {}) or {})
    changed_functions = list(summary.get("changed_functions", []) or [])
    function_status_counts = dict(summary.get("function_status_counts", {}) or {})
    function_statuses = list(summary.get("function_statuses", []) or [])
    uncollected_functions = list(summary.get("uncollected_functions", []) or [])
    unknown_functions = list(summary.get("unknown_functions", []) or [])
    stage_rows = []
    total_changed = 0
    total_missing = 0
    total_unknown = 0
    total_coverage = 0

    for stage_name, stage_summary in (("structuring", structuring), ("postprocess", postprocess)):
        changed_count = int(stage_summary.get("changed_count", 0) or 0)
        stable_count = int(stage_summary.get("stable_count", 0) or 0)
        unknown_count = int(stage_summary.get("unknown_count", 0) or 0)
        missing_count = int(stage_summary.get("missing_count", 0) or 0)
        coverage_count = int(stage_summary.get("coverage_count", stable_count + changed_count + unknown_count) or 0)
        total_changed += changed_count
        total_missing += missing_count
        total_unknown += unknown_count
        total_coverage += coverage_count
        stage_rows.append(
            {
                "stage": stage_name,
                "changed_count": changed_count,
                "stable_count": stable_count,
                "unknown_count": unknown_count,
                "missing_count": missing_count,
                "coverage_count": coverage_count,
                "changed_rate": 0.0 if scanned_count == 0 else round(changed_count / scanned_count, 6),
                "coverage_rate": 0.0 if scanned_count == 0 else round(coverage_count / scanned_count, 6),
                "mode_counts": dict(stage_summary.get("mode_counts", {}) or {}),
                "top_verdicts": list(stage_summary.get("top_verdicts", []) or []),
            }
        )

    stage_hotspots = [
        {
            "stage": row["stage"],
            "changed_count": row["changed_count"],
            "changed_rate": row["changed_rate"],
            "top_verdicts": row["top_verdicts"],
        }
        for row in sorted(stage_rows, key=lambda item: (-item["changed_count"], item["stage"]))
        if row["changed_count"] > 0
    ]
    top_changed_verdicts = []
    verdict_counter: Counter[str] = Counter()
    for row in stage_rows:
        for item in row["top_verdicts"]:
            verdict = item.get("verdict")
            count = item.get("count")
            if isinstance(verdict, str) and verdict and isinstance(count, int):
                verdict_counter[verdict] += count
    top_changed_verdicts = [
        {"verdict": verdict, "count": count}
        for verdict, count in sorted(verdict_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    changed_function_rows: dict[tuple[object, object, object], dict[str, object]] = {}
    for item in changed_functions:
        if not isinstance(item, Mapping):
            continue
        key = (
            item.get("cod_file"),
            item.get("proc_name"),
            item.get("proc_kind"),
        )
        row = changed_function_rows.setdefault(
            key,
            {
                "cod_file": item.get("cod_file"),
                "proc_name": item.get("proc_name"),
                "proc_kind": item.get("proc_kind"),
                "stages": [],
                "verdicts": [],
                "changed_stage_count": 0,
            },
        )
        stage = item.get("stage")
        verdict = item.get("verdict")
        if isinstance(stage, str) and stage and stage not in row["stages"]:
            row["stages"].append(stage)
        if isinstance(verdict, str) and verdict and verdict not in row["verdicts"]:
            row["verdicts"].append(verdict)
        row["changed_stage_count"] = len(row["stages"])
    top_changed_functions = sorted(
        (
            {
                **row,
                "stages": tuple(sorted(row["stages"])),
                "verdicts": tuple(row["verdicts"]),
            }
            for row in changed_function_rows.values()
        ),
        key=lambda item: (
            -int(item.get("changed_stage_count", 0) or 0),
            "" if isinstance(item.get("cod_file"), str) else "~",
            item.get("cod_file"),
            item.get("proc_name"),
            item.get("proc_kind"),
        ),
    )
    changed_families = _tail_validation_changed_family_summary(changed_functions)
    top_uncollected_functions = sorted(
        (dict(item) for item in uncollected_functions if isinstance(item, Mapping)),
        key=_tail_validation_function_sort_key,
    )
    top_unknown_functions = sorted(
        (dict(item) for item in unknown_functions if isinstance(item, Mapping)),
        key=_tail_validation_function_sort_key,
    )

    merge_gate = severity == "clean"
    if scanned_count == 0:
        headline = "whole-tail validation: no functions scanned"
    elif severity == "clean":
        headline = f"whole-tail validation clean across {scanned_count} functions"
    elif severity == "uncollected":
        headline = f"whole-tail validation not collected across {scanned_count} functions"
    elif severity == "partial":
        headline = f"whole-tail validation failed across {scanned_count} functions"
    elif severity == "unknown":
        headline = f"whole-tail validation incomplete across {scanned_count} functions"
    else:
        headline = f"whole-tail validation failed across {changed_function_count} functions"

    surface = {
        "headline": headline,
        "severity": severity,
        "merge_gate": merge_gate,
        "changed_function_count": changed_function_count,
        "changed_stage_total": total_changed,
        "coverage_count": total_coverage,
        "missing_stage_total": total_missing,
        "unknown_stage_total": total_unknown,
        "function_status_counts": function_status_counts,
        "function_statuses": function_statuses,
        "passed_function_count": int(summary.get("passed_function_count", 0) or 0),
        "unknown_function_count": int(summary.get("unknown_function_count", 0) or 0),
        "uncollected_function_count": int(summary.get("uncollected_function_count", 0) or 0),
        "top_unknown_functions": top_unknown_functions,
        "top_uncollected_functions": top_uncollected_functions,
        "stage_rows": stage_rows,
        "stage_hotspots": stage_hotspots,
        "top_changed_verdicts": top_changed_verdicts,
        "top_changed_functions": top_changed_functions,
        "changed_families": changed_families,
        "changed_family_routing": build_tail_validation_family_routing(changed_families),
    }
    surface["consistency_issues"] = check_x86_16_tail_validation_surface_consistency(
        summary,
        surface,
        scanned=scanned_count,
    )
    return surface


def _normalized_tail_validation_baseline_entries(
    entries: Sequence[Mapping[str, object]] | None,
) -> list[dict[str, str]]:
    normalized: set[tuple[str, str, str, str, str]] = set()
    for item in entries or ():
        if not isinstance(item, Mapping):
            continue
        cod_file = item.get("cod_file")
        proc_name = item.get("proc_name")
        proc_kind = item.get("proc_kind")
        stage = item.get("stage")
        verdict = item.get("verdict")
        if not all(isinstance(value, str) and value for value in (cod_file, proc_name, proc_kind, stage, verdict)):
            continue
        normalized.add((cod_file, proc_name, proc_kind, stage, verdict))
    return [
        {
            "cod_file": cod_file,
            "proc_name": proc_name,
            "proc_kind": proc_kind,
            "stage": stage,
            "verdict": verdict,
        }
        for cod_file, proc_name, proc_kind, stage, verdict in sorted(normalized)
    ]


def build_x86_16_tail_validation_baseline(summary: Mapping[str, object]) -> dict[str, object]:
    normalized_entries = _normalized_tail_validation_baseline_entries(summary.get("changed_functions"))
    return {
        "version": 1,
        "entries": normalized_entries,
        "entry_count": len(normalized_entries),
    }


def compare_x86_16_tail_validation_baseline(
    summary: Mapping[str, object],
    baseline: Mapping[str, object] | None,
) -> dict[str, object]:
    if not isinstance(baseline, Mapping):
        return {"status": "unavailable", "unexpected": [], "missing": [], "matches": []}

    current_entries = _normalized_tail_validation_baseline_entries(summary.get("changed_functions"))
    baseline_entries = _normalized_tail_validation_baseline_entries(baseline.get("entries"))
    current_set = {
        (
            item["cod_file"],
            item["proc_name"],
            item["proc_kind"],
            item["stage"],
            item["verdict"],
        )
        for item in current_entries
    }
    baseline_set = {
        (
            item["cod_file"],
            item["proc_name"],
            item["proc_kind"],
            item["stage"],
            item["verdict"],
        )
        for item in baseline_entries
    }
    unexpected = [
        {
            "cod_file": cod_file,
            "proc_name": proc_name,
            "proc_kind": proc_kind,
            "stage": stage,
            "verdict": verdict,
        }
        for cod_file, proc_name, proc_kind, stage, verdict in sorted(current_set - baseline_set)
    ]
    missing = [
        {
            "cod_file": cod_file,
            "proc_name": proc_name,
            "proc_kind": proc_kind,
            "stage": stage,
            "verdict": verdict,
        }
        for cod_file, proc_name, proc_kind, stage, verdict in sorted(baseline_set - current_set)
    ]
    matches = [
        {
            "cod_file": cod_file,
            "proc_name": proc_name,
            "proc_kind": proc_kind,
            "stage": stage,
            "verdict": verdict,
        }
        for cod_file, proc_name, proc_kind, stage, verdict in sorted(current_set & baseline_set)
    ]
    if unexpected:
        status = "regressed"
    elif missing:
        status = "improved"
    else:
        status = "matches_baseline"
    return {
        "status": status,
        "unexpected": unexpected,
        "missing": missing,
        "matches": matches,
    }


def annotate_x86_16_tail_validation_surface_with_baseline(
    surface: Mapping[str, object],
    comparison: Mapping[str, object] | None,
) -> dict[str, object]:
    annotated = dict(surface)
    if not isinstance(comparison, Mapping):
        return annotated
    status = comparison.get("status")
    if not isinstance(status, str) or not status:
        return annotated
    unexpected = list(comparison.get("unexpected", []) or [])
    missing = list(comparison.get("missing", []) or [])
    annotated["baseline_status"] = status
    annotated["baseline_unexpected_count"] = len(unexpected)
    annotated["baseline_missing_count"] = len(missing)
    annotated["baseline_unexpected"] = unexpected
    annotated["baseline_missing"] = missing
    return annotated


def build_x86_16_tail_validation_aggregate(
    records: Sequence[Mapping[str, object]],
    *,
    scanned: int,
) -> dict[str, object]:
    normalized_records = _records_with_uncollected_placeholders(records, scanned=scanned)
    descriptor = build_x86_16_validation_cache_descriptor(
        "tail_validation.aggregate",
        {
            "records_fingerprint": _tail_validation_records_fingerprint(records, scanned=scanned),
            "scanned": int(scanned or 0),
        },
    )
    cached = resolve_x86_16_validation_cached_artifact(
        cache=_TAIL_VALIDATION_AGGREGATE_CACHE,
        descriptor=descriptor,
        build=lambda: {
            "summary": summarize_x86_16_tail_validation_records(normalized_records),
            "surface": None,
        },
        clone_on_hit=_clone_tail_validation_aggregate_payload,
        store_value=_clone_tail_validation_aggregate_payload,
    )
    payload = dict(cached["value"])
    if payload.get("surface") is None:
        payload["surface"] = build_x86_16_tail_validation_surface(payload["summary"], scanned=scanned)
        _TAIL_VALIDATION_AGGREGATE_CACHE[descriptor.cache_key] = {
            "summary": dict(payload["summary"]),
            "surface": dict(payload["surface"]),
        }
    return {
        "cache_key": cached["cache_key"],
        "cache_hit": bool(cached["cache_hit"]),
        "summary": payload["summary"],
        "surface": payload["surface"],
    }


def summarize_x86_16_tail_validation_records(records: Sequence[Mapping[str, object]]) -> dict[str, object]:
    structuring = _tail_validation_stage_summary(records, "structuring")
    postprocess = _tail_validation_stage_summary(records, "postprocess")
    function_accounting = _tail_validation_function_accounting(records)
    changed_functions = sorted(
        structuring["changed_functions"] + postprocess["changed_functions"],
        key=lambda item: (
            "" if isinstance(item.get("cod_file"), str) else "~",
            item.get("cod_file"),
            item.get("proc_name"),
            item.get("proc_kind"),
            item.get("verdict"),
        ),
    )
    changed_function_count = len(changed_functions)
    changed_families = _tail_validation_changed_family_summary(changed_functions)
    coverage_count = int(structuring["coverage_count"]) + int(postprocess["coverage_count"])
    missing_count = int(structuring["missing_count"]) + int(postprocess["missing_count"])
    unknown_count = int(structuring["unknown_count"]) + int(postprocess["unknown_count"])
    severity = "clean"
    if changed_function_count > 0:
        severity = "changed"
    elif unknown_count > 0:
        severity = "unknown"
    elif coverage_count == 0 and missing_count > 0:
        severity = "uncollected"
    elif missing_count > 0:
        severity = "partial"
    return {
        "severity": severity,
        "changed_function_count": changed_function_count,
        "coverage_count": coverage_count,
        "missing_count": missing_count,
        "unknown_count": unknown_count,
        "structuring": structuring,
        "postprocess": postprocess,
        "changed_functions": changed_functions,
        "changed_families": changed_families,
        "function_status_counts": function_accounting["function_status_counts"],
        "function_statuses": function_accounting["function_statuses"],
        "passed_functions": function_accounting["passed_functions"],
        "unknown_functions": function_accounting["unknown_functions"],
        "uncollected_functions": function_accounting["uncollected_functions"],
        "passed_function_count": len(function_accounting["passed_functions"]),
        "unknown_function_count": len(function_accounting["unknown_functions"]),
        "uncollected_function_count": len(function_accounting["uncollected_functions"]),
    }


def _record_expr_locations(node, project, observed_locations: set[str]) -> None:
    if node is None:
        return
    if isinstance(node, CVariable):
        observed_locations.add(_location_fingerprint(node, project))
        return
    if isinstance(node, CTypeCast):
        _record_expr_locations(node.expr, project, observed_locations)
        return
    if isinstance(node, CUnaryOp):
        observed_locations.add(_location_fingerprint(node, project))
        _record_expr_locations(node.operand, project, observed_locations)
        return
    if isinstance(node, CBinaryOp):
        _record_expr_locations(node.lhs, project, observed_locations)
        _record_expr_locations(node.rhs, project, observed_locations)
        return
    if isinstance(node, CFunctionCall):
        if _is_runtime_segment_helper_call_8616(node):
            return
        for arg in getattr(node, "args", ()) or ():
            _record_expr_locations(arg, project, observed_locations)
        return


def _is_control_flow_node(node) -> bool:
    return isinstance(node, (CIfElse, CIfBreak, CWhileLoop, CDoWhileLoop, CForLoop, CSwitchCase, CGoto, CBreak, CContinue, CReturn))


def _collect_observed_locations(root, project, mode: str) -> set[str]:
    observed_locations: set[str] = set()
    if mode != "live_out":
        return observed_locations

    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CFunctionCall):
            if _is_runtime_segment_helper_call_8616(node):
                continue
            for arg in getattr(node, "args", ()) or ():
                _record_expr_locations(arg, project, observed_locations)
        if isinstance(node, CReturn):
            _record_expr_locations(getattr(node, "retval", None), project, observed_locations)
    return observed_locations


def _iter_observable_call_nodes_for_validation_8616(node):
    if node is None:
        return
    if isinstance(node, CStatements):
        for stmt in getattr(node, "statements", ()) or ():
            yield from _iter_observable_call_nodes_for_validation_8616(stmt)
        return
    if isinstance(node, CFunctionCall):
        yield node
        return
    if isinstance(node, CAssignment):
        rhs = getattr(node, "rhs", None)
        if isinstance(rhs, CFunctionCall):
            yield rhs
        return
    for attr in ("retval", "condition", "cond", "expr"):
        child = getattr(node, attr, None)
        if isinstance(child, CFunctionCall):
            yield child
        elif child is not None:
            yield from _iter_observable_call_nodes_for_validation_8616(child)
    if hasattr(node, "condition_and_nodes"):
        for cond, body in getattr(node, "condition_and_nodes", ()) or ():
            if isinstance(cond, CFunctionCall):
                yield cond
            elif cond is not None:
                yield from _iter_observable_call_nodes_for_validation_8616(cond)
            yield from _iter_observable_call_nodes_for_validation_8616(body)
    else_node = getattr(node, "else_node", None)
    if else_node is not None:
        yield from _iter_observable_call_nodes_for_validation_8616(else_node)
    for attr in ("body", "initializer", "iterator"):
        child = getattr(node, attr, None)
        if child is not None:
            yield from _iter_observable_call_nodes_for_validation_8616(child)


def _build_contextual_call_summary_map(root, project) -> dict[int, object]:
    if root is None:
        return {}
    summary_map: dict[int, object] = {}
    function = _function_for_call_context_8616(root, project)
    if function is None:
        return {}
    ordered_pairs = _ordered_contextual_call_pairs_8616(root, project)
    for node, callsite_addr in ordered_pairs:
        summary = summarize_x86_16_callsite(function, callsite_addr)
        target_addr = _call_summary_target_addr_8616(project, summary)
        if summary is not None and target_addr is not None:
            if isinstance(summary, Mapping):
                summary_map[id(node)] = {**summary, "target_addr": target_addr}
            else:
                summary_map[id(node)] = {"target_addr": target_addr, "summary": summary}
    if summary_map:
        return summary_map
    call_nodes = list(_iter_observable_call_nodes_for_validation_8616(root))
    if not call_nodes:
        return {}
    direct_targets = _collect_direct_capstone_call_targets_for_function(function)
    for node, target_addr in zip(call_nodes, direct_targets):
        normalized_target = _normalized_call_target_addr_8616(project, target_addr)
        if isinstance(normalized_target, int):
            summary_map[id(node)] = {"target_addr": normalized_target}
    return summary_map


def _call_from_statement_8616(stmt):
    if isinstance(stmt, CFunctionCall):
        return stmt
    expr = getattr(stmt, "expr", None)
    if isinstance(expr, CFunctionCall):
        return expr
    nested_statements = getattr(stmt, "statements", None)
    if isinstance(nested_statements, (list, tuple)) and len(nested_statements) == 1:
        return _call_from_statement_8616(nested_statements[0])
    return None


def _assignment_lhs_rhs_8616(node):
    lhs = getattr(node, "lhs", None)
    rhs = getattr(node, "rhs", None)
    if lhs is None and hasattr(node, "dst"):
        lhs = getattr(node, "dst", None)
        rhs = getattr(node, "src", None)
    return lhs, rhs


def _iter_assignment_nodes_8616(node):
    if isinstance(node, CAssignment) or node.__class__.__name__.endswith("Assignment"):
        yield node
    nested_statements = getattr(node, "statements", None)
    if isinstance(nested_statements, (list, tuple)):
        for nested in nested_statements:
            yield from _iter_assignment_nodes_8616(nested)


def _assignment_lhs_writes_memory_8616(lhs, project) -> bool:
    if lhs is None:
        return False
    location = _location_fingerprint(lhs, project)
    return location.startswith("stack:") or location.startswith("global:") or location.startswith("deref:")


def _contains_call_8616(node) -> bool:
    if isinstance(node, CFunctionCall):
        return True
    expr = getattr(node, "expr", None)
    if isinstance(expr, CFunctionCall):
        return True
    return any(isinstance(child, CFunctionCall) for child in _iter_c_nodes_deep_8616(node))


def _is_stack_carrier_temp_assignment_8616(stmt) -> bool:
    candidates = list(_iter_assignment_nodes_8616(stmt))
    if not candidates:
        return False
    lhs, rhs = _assignment_lhs_rhs_8616(candidates[-1])
    if lhs is None or rhs is None:
        return False
    variable = getattr(lhs, "variable", None)
    name = getattr(variable, "name", None) or getattr(lhs, "name", None)
    if not isinstance(name, str) or not (name.startswith("vvar_") or name.startswith("ir_") or name.startswith("tmp_")):
        return False
    rhs_node = rhs
    while isinstance(rhs_node, CTypeCast):
        rhs_node = rhs_node.expr
    if isinstance(rhs_node, CUnaryOp) and rhs_node.op in {"Reference", "Dereference"}:
        return True
    return isinstance(rhs_node, CBinaryOp) and rhs_node.op in {"Add", "Sub", "Mul", "Shl", "Shr", "And", "Or", "Xor"}


def _is_value_only_assignment_8616(stmt, project) -> bool:
    candidates = list(_iter_assignment_nodes_8616(stmt))
    if not candidates:
        return False
    lhs, _rhs = _assignment_lhs_rhs_8616(candidates[-1])
    return not _assignment_lhs_writes_memory_8616(lhs, project)


def _expr_mentions_temp_carrier_8616(expr) -> bool:
    if expr is None:
        return False
    nodes = (expr, *_iter_c_nodes_deep_8616(expr))
    for node in nodes:
        variable = getattr(node, "variable", None)
        name = getattr(variable, "name", None) or getattr(node, "name", None)
        if isinstance(name, str) and (name.startswith("vvar_") or name.startswith("ir_") or name.startswith("tmp_")):
            return True
        if node.__class__.__name__ == "CDirtyExpression":
            dirty = getattr(node, "dirty", None)
            dirty_name = getattr(dirty, "name", None)
            if isinstance(dirty_name, str) and (
                dirty_name.startswith("vvar_") or dirty_name.startswith("ir_") or dirty_name.startswith("tmp_")
            ):
                return True
    return False


def _looks_like_ss_segment_store_8616(lhs, project) -> bool:
    while isinstance(lhs, CTypeCast):
        lhs = lhs.expr
    if not isinstance(lhs, CUnaryOp) or lhs.op != "Dereference":
        return False
    location = _location_fingerprint(lhs, project)
    if location.startswith("deref:ss:"):
        return True
    return "reg:ss" in _expr_fingerprint(lhs.operand, project)


def _is_dynamic_dirty_ss_location_8616(location: str) -> bool:
    return (
        isinstance(location, str)
        and location.startswith("deref:")
        and "reg:ss" in location
        and ("CDirtyExpression" in location or "CFakeVariable" in location)
    )


def _canonicalize_segmented_write_aliases_8616(segmented_writes: set[str], global_writes: set[str]) -> set[str]:
    if not segmented_writes or not global_writes:
        return segmented_writes
    filtered: set[str] = set()
    for location in segmented_writes:
        match = re.fullmatch(r"deref:ds:0x([0-9a-fA-F]+)", location)
        if match is not None:
            global_location = f"global:{int(match.group(1), 16):#x}"
            if global_location in global_writes:
                continue
        filtered.add(location)
    return filtered


def _prunable_live_out_segment_write_ids_8616(root, project, contextual_call_summaries: Mapping[int, object]) -> set[int]:
    prunable_ids: set[int] = set()

    def _scan_statement_list(statements) -> None:
        stmt_list = list(statements or ())
        for idx, stmt in enumerate(stmt_list):
            call = _call_from_statement_8616(stmt)
            if call is not None:
                summary = contextual_call_summaries.get(id(call))
                if isinstance(summary, Mapping):
                    summary_obj = summary.get("summary", summary)
                else:
                    summary_obj = summary
                expected_arg_count = getattr(summary_obj, "arg_count", None)
                if isinstance(summary_obj, Mapping):
                    expected_arg_count = summary_obj.get("arg_count", expected_arg_count)
                explicit_arg_count = len(tuple(getattr(call, "args", ()) or ()))
                carrier_backed_args = any(
                    _expr_mentions_temp_carrier_8616(arg) for arg in (getattr(call, "args", ()) or ())
                )
                missing_arg_count = expected_arg_count - explicit_arg_count if isinstance(expected_arg_count, int) else 0
                wanted_prunable_count = max(missing_arg_count, 1 if carrier_backed_args else 0)
                if wanted_prunable_count > 0:
                    scan = idx - 1
                    collected = 0
                    while scan >= 0 and collected < wanted_prunable_count:
                        candidate = stmt_list[scan]
                        if _is_stack_carrier_temp_assignment_8616(candidate):
                            scan -= 1
                            continue
                        if _is_value_only_assignment_8616(candidate, project):
                            scan -= 1
                            continue
                        assignments = list(_iter_assignment_nodes_8616(candidate))
                        if len(assignments) == 1 and not _contains_call_8616(candidate):
                            lhs, _rhs = _assignment_lhs_rhs_8616(assignments[0])
                            if _looks_like_ss_segment_store_8616(lhs, project):
                                prunable_ids.add(id(assignments[0]))
                                collected += 1
                                scan -= 1
                                continue
                        break
            nested_statements = getattr(stmt, "statements", None)
            if isinstance(nested_statements, (list, tuple)):
                _scan_statement_list(nested_statements)
            else_node = getattr(stmt, "else_node", None)
            if else_node is not None:
                _scan_statement_list(getattr(else_node, "statements", ()) or ())
            for attr in ("body", "initializer", "iterator"):
                child = getattr(stmt, attr, None)
                if child is not None:
                    _scan_statement_list(getattr(child, "statements", ()) or ())
            if isinstance(stmt, CIfElse):
                for _cond, child in tuple(getattr(stmt, "condition_and_nodes", ()) or ()):
                    _scan_statement_list(getattr(child, "statements", ()) or ())

    if isinstance(root, CStatements):
        _scan_statement_list(getattr(root, "statements", ()) or ())
    else:
        _scan_statement_list((root,))
    return prunable_ids


def _collect_direct_capstone_call_targets_for_function(function) -> tuple[int, ...]:
    project = getattr(function, "project", None)
    if project is None or getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return ()
    main_object = getattr(getattr(project, "loader", None), "main_object", None)
    linked_base = getattr(main_object, "linked_base", None)
    max_addr = getattr(main_object, "max_addr", None)
    image_end = linked_base + max_addr + 1 if isinstance(linked_base, int) and isinstance(max_addr, int) else None
    factory = getattr(project, "factory", None)
    if factory is None:
        return ()
    targets: list[int] = []
    for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
        try:
            block = factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        for insn in getattr(getattr(block, "capstone", None), "insns", ()) or ():
            if str(getattr(insn, "mnemonic", "") or "").lower() != "call":
                continue
            target = _direct_capstone_call_target_8616(insn)
            if not isinstance(target, int):
                continue
            resolved = _normalize_direct_call_target_8616(target, linked_base, image_end)
            if isinstance(resolved, int):
                targets.append(resolved)
    return tuple(targets)


def _direct_capstone_call_target_8616(insn) -> int | None:
    capstone_insn = getattr(insn, "insn", None)
    operands = getattr(capstone_insn, "operands", None)
    if operands:
        operand = operands[0]
        if getattr(operand, "type", None) == 2 and isinstance(getattr(operand, "imm", None), int):
            return int(operand.imm)
    op_str = str(getattr(insn, "op_str", "") or "").strip().lower()
    if not op_str or "[" in op_str or any(ch.isalpha() for ch in op_str if ch not in "xabcdef"):
        return None
    for token in re.split(r"[\s,:]+", op_str):
        if not token:
            continue
        try:
            return int(token, 0)
        except ValueError:
            continue
    return None


def _normalize_direct_call_target_8616(target: int, linked_base: int | None, image_end: int | None) -> int | None:
    if not isinstance(target, int):
        return None
    if isinstance(linked_base, int):
        if target < linked_base:
            linked_target = linked_base + target
            if image_end is None or linked_target < image_end:
                return linked_target
        elif image_end is None or target < image_end:
            return target
        unbased_target = target - linked_base
        if 0 <= unbased_target < 0x10000:
            return unbased_target
        return None
    return target


def collect_x86_16_tail_validation_summary(project, codegen, *, mode: str = "live_out") -> X86_16TailValidationSummary:
    if mode not in _TAIL_VALIDATION_MODES:
        raise ValueError(f"Unsupported x86-16 tail validation mode: {mode}")
    cache = _tail_validation_summary_cache_store(codegen)
    descriptor = build_x86_16_validation_cache_descriptor(
        "tail_validation.summary",
        {
            "mode": mode,
            "boundary_fingerprint": fingerprint_x86_16_tail_validation_boundary(project, codegen, mode=mode),
        },
    )
    entries = cache.get("entries", {})

    root = _codegen_root(codegen)
    helper_calls: set[str] = set()
    register_writes: set[str] = set()
    stack_writes: set[str] = set()
    global_writes: set[str] = set()
    segmented_writes: set[str] = set()
    returns: set[str] = set()
    conditions: set[str] = set()
    control_flow_effects: set[str] = set()

    if root is None:
        return X86_16TailValidationSummary((), (), (), (), (), (), (), ())
    observed_locations = _collect_observed_locations(root, project, mode)
    contextual_call_fingerprints = build_x86_16_contextual_call_fingerprints(root, project)
    contextual_call_summaries = _build_contextual_call_summary_map(root, project)
    contextual_condition_fingerprints = build_x86_16_contextual_condition_fingerprints(root, project)
    prunable_segment_write_ids = (
        _prunable_live_out_segment_write_ids_8616(root, project, contextual_call_summaries)
        if mode == "live_out"
        else set()
    )
    normalized_loop_conditions: dict[int, str] = {}
    suppressed_control_flow_nodes: set[int] = set()
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CWhileLoop):
            continue
        normalized = _extract_loop_break_guard_normalization_8616(node, project, contextual_condition_fingerprints)
        if normalized is None:
            continue
        normalized_loop_conditions[id(node)] = normalized[0]
        suppressed_control_flow_nodes.update(normalized[1])

    for node in _iter_c_nodes_deep_8616(root):
        if id(node) in suppressed_control_flow_nodes:
            continue
        if isinstance(node, CFunctionCall):
            if _is_runtime_segment_helper_call_8616(node):
                continue
            summary = contextual_call_summaries.get(id(node))
            target_addr = _call_summary_target_addr_8616(project, summary)
            call_name = _call_target_name(node, project)
            if isinstance(call_name, str) and call_name:
                call_fingerprint = f"name:{call_name}"
            else:
                call_fingerprint = f"addr:{target_addr:#x}" if isinstance(target_addr, int) else None
                if call_fingerprint is None:
                    call_fingerprint = contextual_call_fingerprints.get(id(node))
            helper_calls.add(call_fingerprint or "<unknown-call>")
        elif isinstance(node, CReturn):
            returns.add(_expr_fingerprint(getattr(node, "retval", None), project))
            control_flow_effects.add("return")
        elif isinstance(node, CAssignment):
            if id(node) in prunable_segment_write_ids:
                continue
            lhs = getattr(node, "lhs", None)
            location = _location_fingerprint(lhs, project, resolve_copy_alias=False)
            if location.startswith("reg:"):
                if mode == "coarse" or location in observed_locations:
                    register_writes.add(location)
            elif location.startswith("stack:"):
                if include_x86_16_tail_validation_stack_write(
                    location,
                    mode=mode,
                    observed_locations=observed_locations,
                ):
                    stack_writes.add(location)
            elif location.startswith("global:"):
                global_writes.add(location)
            elif location.startswith("deref:"):
                if mode == "live_out" and _is_dynamic_dirty_ss_location_8616(location):
                    continue
                segmented_writes.add(location)
        elif isinstance(node, CIfElse):
            pairs = tuple(getattr(node, "condition_and_nodes", ()) or ())
            for idx, (cond, _child) in enumerate(pairs):
                normalized_cond = _normalized_if_chain_condition_8616(pairs, idx, getattr(node, "codegen", None))
                if normalized_cond is not None:
                    cond = normalized_cond
                cond_fingerprint = contextual_condition_fingerprints.get(id(cond), _expr_fingerprint(cond, project))
                control_flow_effects.add(f"if:{cond_fingerprint}")
                if mode == "live_out":
                    conditions.add(cond_fingerprint)
            if getattr(node, "else_node", None) is not None:
                control_flow_effects.add("if:else")
        elif isinstance(node, CIfBreak):
            cond = getattr(node, "condition", None)
            cond_fingerprint = contextual_condition_fingerprints.get(id(cond), _expr_fingerprint(cond, project))
            control_flow_effects.add(f"ifbreak:{cond_fingerprint}")
            if mode == "live_out":
                conditions.add(cond_fingerprint)
        elif isinstance(node, CWhileLoop):
            cond = getattr(node, "condition", None)
            cond_fingerprint = normalized_loop_conditions.get(
                id(node),
                contextual_condition_fingerprints.get(id(cond), _expr_fingerprint(cond, project)),
            )
            control_flow_effects.add(f"while:{cond_fingerprint}")
            if mode == "live_out":
                conditions.add(cond_fingerprint)
        elif isinstance(node, CDoWhileLoop):
            cond = getattr(node, "condition", None)
            cond_fingerprint = contextual_condition_fingerprints.get(id(cond), _expr_fingerprint(cond, project))
            control_flow_effects.add(f"dowhile:{cond_fingerprint}")
            if mode == "live_out":
                conditions.add(cond_fingerprint)
        elif isinstance(node, CForLoop):
            cond = getattr(node, "condition", None)
            cond_fingerprint = contextual_condition_fingerprints.get(id(cond), _expr_fingerprint(cond, project))
            control_flow_effects.add(f"for:{cond_fingerprint}")
            if mode == "live_out":
                conditions.add(cond_fingerprint)
        elif isinstance(node, CSwitchCase):
            switch_fingerprint = _expr_fingerprint(getattr(node, "switch", None), project)
            control_flow_effects.add(f"switch:{switch_fingerprint}")
            if mode == "live_out":
                conditions.add(switch_fingerprint)
            cases = getattr(node, "cases", None)
            if isinstance(cases, dict):
                for case_value in cases:
                    control_flow_effects.add(f"case:{_switch_case_fingerprint(case_value, project)}")
            if getattr(node, "default", None) is not None:
                control_flow_effects.add("case:default")
        elif isinstance(node, CGoto):
            control_flow_effects.add(f"goto:{getattr(node, 'target', None)!r}")
        elif isinstance(node, CBreak):
            control_flow_effects.add("break")
        elif isinstance(node, CContinue):
            control_flow_effects.add("continue")

        if mode == "coarse" and not _is_control_flow_node(node):
            for attr in ("condition", "cond"):
                value = getattr(node, attr, None)
                if value is not None:
                    conditions.add(_expr_fingerprint(value, project))

    def _build_summary() -> X86_16TailValidationSummary:
        canonical_segmented_writes = _canonicalize_segmented_write_aliases_8616(segmented_writes, global_writes)
        return X86_16TailValidationSummary(
            helper_calls=_sorted_unique(helper_calls),
            register_writes=_sorted_unique(register_writes),
            stack_writes=_sorted_unique(stack_writes),
            global_writes=_sorted_unique(global_writes),
            segmented_writes=_sorted_unique(canonical_segmented_writes),
            returns=_sorted_unique(returns),
            conditions=_sorted_unique(conditions),
            control_flow_effects=_sorted_unique(control_flow_effects),
        )

    cached = resolve_x86_16_validation_cached_artifact(
        cache=entries if isinstance(entries, dict) else None,
        descriptor=descriptor,
        build=_build_summary,
    )
    summary = cached["value"]
    if bool(cached["cache_hit"]):
        cache["stats"]["hits"] = int(cache["stats"].get("hits", 0) or 0) + 1
    else:
        cache["stats"]["misses"] = int(cache["stats"].get("misses", 0) or 0) + 1
    codegen._inertia_tail_validation_last_summary_cache_hit = bool(cached["cache_hit"])
    codegen._inertia_tail_validation_last_summary_cache_key = cached["cache_key"]
    return summary


def compare_x86_16_tail_validation_summaries(
    before: X86_16TailValidationSummary,
    after: X86_16TailValidationSummary,
) -> dict[str, object]:
    changed = False
    diff: dict[str, object] = {"changed": False, "before": before.as_dict(), "after": after.as_dict(), "delta": {}}
    for field_name in _TAIL_VALIDATION_OBSERVABLE_FIELDS:
        before_values = _canonicalize_summary_field_values_8616(field_name, set(getattr(before, field_name)))
        after_values = _canonicalize_summary_field_values_8616(field_name, set(getattr(after, field_name)))
        added = tuple(sorted(after_values - before_values))
        removed = tuple(sorted(before_values - after_values))
        if added or removed:
            changed = True
        diff["delta"][field_name] = {"added": added, "removed": removed}
    diff["changed"] = changed
    diff["status"] = "changed" if changed else "stable"
    return diff


def format_x86_16_tail_validation_diff(validation: dict[str, object]) -> str:
    if not validation.get("changed", False):
        return "no observable whole-tail changes"

    delta = validation.get("delta", {})
    parts: list[str] = []
    for field_name in _TAIL_VALIDATION_OBSERVABLE_FIELDS:
        field_delta = delta.get(field_name, {})
        added = field_delta.get("added", ()) or ()
        removed = field_delta.get("removed", ()) or ()
        if not added and not removed:
            continue
        field_parts = [f"+{value}" for value in added] + [f"-{value}" for value in removed]
        parts.append(f"{field_name}: " + ", ".join(field_parts))
    return "; ".join(parts) if parts else "observable whole-tail delta present"


def _format_x86_16_tail_validation_timing_suffix(validation: Mapping[str, object]) -> str:
    timing_debug = os.environ.get("INERTIA_DEBUG_TIMING")
    if timing_debug is None or timing_debug.strip().lower() in {"", "0", "false", "no", "off"}:
        return ""
    timings = validation.get("timings")
    if not isinstance(timings, Mapping):
        return ""

    parts: list[str] = []
    collect_before_ms = timings.get("collect_before_ms")
    collect_after_ms = timings.get("collect_after_ms")
    compare_ms = timings.get("compare_ms")
    total_ms = timings.get("total_ms")

    if isinstance(collect_before_ms, (int, float)) and isinstance(collect_after_ms, (int, float)):
        parts.append(f"collect={collect_before_ms:.1f}+{collect_after_ms:.1f}ms")
    elif isinstance(collect_before_ms, (int, float)):
        parts.append(f"collect={collect_before_ms:.1f}ms")
    elif isinstance(collect_after_ms, (int, float)):
        parts.append(f"collect={collect_after_ms:.1f}ms")

    if isinstance(compare_ms, (int, float)):
        parts.append(f"compare={compare_ms:.1f}ms")
    if isinstance(total_ms, (int, float)):
        parts.append(f"tail_validation={total_ms:.1f}ms")
    if not parts:
        return ""
    return " [" + " ".join(parts) + "]"


def build_x86_16_tail_validation_verdict(stage: str, validation: dict[str, object]) -> str:
    mode = validation.get("mode", "unknown")
    summary_text = validation.get("summary_text")
    if not isinstance(summary_text, str) or not summary_text:
        summary_text = format_x86_16_tail_validation_diff(validation)
    status = validation.get("status")
    if not isinstance(status, str) or not status:
        status = "changed" if validation.get("changed", False) else "stable"
    return f"{stage} whole-tail validation [{mode}] {status}: {summary_text}{_format_x86_16_tail_validation_timing_suffix(validation)}"


def describe_x86_16_tail_validation_scope() -> dict[str, object]:
    return {
        "boundary": "whole-tail validation compares observable structured-codegen effects before and after late x86-16 passes",
        "preferred_mode": "live_out",
        "modes": ("coarse", "live_out"),
        "cache_policy": "reuse summaries and stage comparisons only when structured-codegen boundary fingerprints match exactly",
        "coverage_semantics": {
            "missing": "validation metadata was not collected for that stage on that function",
            "unknown": "validation metadata existed but could not be classified into stable or changed",
        },
        "layers": ("structuring", "postprocess"),
        "observables": _TAIL_VALIDATION_OBSERVABLE_FIELDS,
        "ignored": (
            "temporary names",
            "dead internal rewrites",
            "non-live flag churn",
        ),
    }


def build_x86_16_tail_validation_cached_result(
    *,
    owner,
    stage: str,
    mode: str,
    before_fingerprint: str,
    after_fingerprint: str,
    before_summary: X86_16TailValidationSummary,
    after_summary: X86_16TailValidationSummary,
) -> dict[str, object]:
    cache = _tail_validation_validation_cache_store(owner)
    comparisons = cache.get("comparisons", {})
    descriptor = build_x86_16_validation_cache_descriptor(
        "tail_validation.comparison",
        {
            "stage": stage,
            "mode": mode,
            "before_fingerprint": before_fingerprint,
            "after_fingerprint": after_fingerprint,
        },
    )
    cached = resolve_x86_16_validation_cached_artifact(
        cache=comparisons if isinstance(comparisons, dict) else None,
        descriptor=descriptor,
        build=lambda: {
            **compare_x86_16_tail_validation_summaries(before_summary, after_summary),
            "mode": mode,
        },
        clone_on_hit=dict,
        store_value=dict,
    )
    result = dict(cached["value"])
    if "status" not in result or not isinstance(result.get("status"), str) or not result.get("status"):
        result["status"] = "changed" if bool(result.get("changed", False)) else "stable"
    if "summary_text" not in result:
        result["summary_text"] = format_x86_16_tail_validation_diff(result)
    if "scope" not in result:
        result["scope"] = describe_x86_16_tail_validation_scope()
    if "verdict" not in result:
        result["verdict"] = build_x86_16_tail_validation_verdict(stage, result)
    result["cache_hit"] = bool(cached["cache_hit"])
    result["cache_key"] = cached["cache_key"]
    if isinstance(comparisons, dict) and not cached["cache_hit"]:
        comparisons[cached["cache_key"]] = dict(result)
    return result
