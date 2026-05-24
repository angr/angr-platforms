from __future__ import annotations

import logging
import os
from typing import Iterable

from angr.analyses.decompiler.structured_codegen.c import CForLoop, CIfBreak, CIfElse

from .decompiler_postprocess_utils import _iter_c_nodes_deep_8616
from .ir.condition_ir import ConditionIR
from .structuring.condition_rendering import render_condition_ir_8616, render_condition_ir_native_8616
from .tail_validation_fingerprint import _expr_fingerprint

log = logging.getLogger(__name__)

def _current_original_func_addr_8616(project, codegen) -> int | None:
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
    if not isinstance(func_addr, int):
        return None
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int):
        return func_addr + delta
    return func_addr


def _condition_trace_enabled_8616(project, codegen) -> bool:
    if not os.environ.get("INERTIA_DEBUG_CONDITION_TRACE"):
        return False
    target_text = os.environ.get("INERTIA_DEBUG_CONDITION_TRACE_ADDR")
    target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
    current_addr = _current_original_func_addr_8616(project, codegen)
    return not isinstance(target_addr, int) or current_addr == target_addr


def _condition_trace_store_8616(codegen) -> dict[tuple[int, int], dict[str, object]]:
    store = getattr(codegen, "_inertia_condition_trace", None)
    if not isinstance(store, dict):
        store = {}
        codegen._inertia_condition_trace = store
    return store


def _condition_trace_key_8616(ins_addr: int, block_addr: int) -> tuple[int, int]:
    return (int(ins_addr), int(block_addr))


def _condition_id_for_key_8616(codegen, key: tuple[int, int]) -> int:
    store = _condition_trace_store_8616(codegen)
    if key not in store:
        store[key] = {
            "condition_id": len(store) + 1,
            "origin_insn": key[0],
            "origin_block": key[1],
        }
    return int(store[key]["condition_id"])


def _render_c_expr_8616(expr) -> str | None:
    if expr is None:
        return None
    try:
        return expr.c_repr(indent=0)
    except Exception:  # noqa: BLE001
        return str(expr)


def _node_condition_key_8616(node) -> tuple[int, int] | None:
    tags = getattr(node, "tags", None)
    if not isinstance(tags, dict):
        return None
    ins_addr = tags.get("ins_addr")
    block_addr = tags.get("vex_block_addr")
    if not isinstance(ins_addr, int) or not isinstance(block_addr, int):
        return None
    return _condition_trace_key_8616(ins_addr, block_addr)


def _iter_condition_nodes_8616(codegen) -> Iterable[tuple[tuple[int, int], object, str]]:
    cfunc = getattr(codegen, "cfunc", None)
    root = None
    for attr in ("body", "statements", "stmt"):
        value = getattr(cfunc, attr, None)
        if value is not None:
            root = value
            break
    if root is None:
        root = cfunc
    if root is None:
        return ()
    rows: list[tuple[tuple[int, int], object, str]] = []
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CIfElse):
            for cond, _body in tuple(getattr(node, "condition_and_nodes", ()) or ()):
                key = _node_condition_key_8616(cond)
                if key is not None:
                    rows.append((key, cond, "if"))
        elif isinstance(node, CIfBreak):
            cond = getattr(node, "condition", None)
            key = _node_condition_key_8616(cond)
            if key is not None:
                rows.append((key, cond, "ifbreak"))
        elif isinstance(node, CForLoop):
            cond = getattr(node, "condition", None)
            key = _node_condition_key_8616(cond)
            if key is not None:
                rows.append((key, cond, "for"))
        elif hasattr(node, "condition"):
            cond = getattr(node, "condition", None)
            key = _node_condition_key_8616(cond)
            if key is not None:
                rows.append((key, cond, type(node).__name__))
    return rows


def record_classified_conditions_trace_8616(project, codegen, conditions: list[ConditionIR]) -> None:
    if not _condition_trace_enabled_8616(project, codegen):
        return
    store = _condition_trace_store_8616(codegen)
    if os.environ.get("INERTIA_DEBUG_CONDITION_TRACE"):
        log.warning(
            "[condition-trace] classified-scan func=%#x conditions=%d",
            _current_original_func_addr_8616(project, codegen) or -1,
            len(conditions),
        )
    for cond in conditions:
        if not isinstance(cond.src_insn, int) or not isinstance(cond.block_addr, int):
            continue
        key = _condition_trace_key_8616(cond.src_insn, cond.block_addr)
        _condition_id_for_key_8616(codegen, key)
        entry = store[key]
        entry["classified"] = render_condition_ir_native_8616(cond) or render_condition_ir_8616(cond)
        entry["condition_op"] = cond.op


def record_materialized_condition_trace_8616(project, codegen, key: tuple[int, int], expr) -> None:
    if not _condition_trace_enabled_8616(project, codegen):
        return
    store = _condition_trace_store_8616(codegen)
    _condition_id_for_key_8616(codegen, key)
    entry = store[key]
    entry["materialized"] = _render_c_expr_8616(expr)
    entry["materialized_hash"] = _expr_fingerprint(expr, project)


def record_ast_condition_trace_8616(project, codegen, *, stage: str) -> None:
    if not _condition_trace_enabled_8616(project, codegen):
        return
    store = _condition_trace_store_8616(codegen)
    for key, cond, owner in _iter_condition_nodes_8616(codegen):
        _condition_id_for_key_8616(codegen, key)
        entry = store[key]
        entry[stage] = _render_c_expr_8616(cond)
        entry[f"{stage}_hash"] = _expr_fingerprint(cond, project)
        entry[f"{stage}_owner"] = owner


def record_tail_validation_condition_trace_8616(project, codegen, validation: dict[str, object] | None) -> None:
    if not _condition_trace_enabled_8616(project, codegen):
        return
    if not isinstance(validation, dict):
        return
    store = _condition_trace_store_8616(codegen)
    summary = validation.get("summary_text") or validation.get("verdict") or validation.get("status")
    for entry in store.values():
        entry["validator_seen"] = summary


def materialized_condition_drift_detected_8616(project, codegen) -> bool:
    if not _condition_trace_enabled_8616(project, codegen):
        return False
    store = _condition_trace_store_8616(codegen)
    drifted: list[dict[str, object]] = []
    for entry in store.values():
        materialized = entry.get("materialized_hash")
        emitted = entry.get("emitted_c_hash")
        if isinstance(materialized, str) and isinstance(emitted, str) and materialized != emitted:
            drifted.append(
                {
                    "condition_id": entry.get("condition_id"),
                    "origin_insn": entry.get("origin_insn"),
                    "origin_block": entry.get("origin_block"),
                    "materialized": entry.get("materialized"),
                    "emitted_c": entry.get("emitted_c"),
                }
            )
    codegen._inertia_materialized_condition_drift = bool(drifted)
    codegen._inertia_materialized_condition_drift_details = tuple(drifted)
    return bool(drifted)


def dump_condition_trace_8616(project, codegen, *, label: str) -> None:
    if not _condition_trace_enabled_8616(project, codegen):
        return
    store = _condition_trace_store_8616(codegen)
    if not store:
        log.warning(
            "[condition-trace] %s func=%#x store=empty",
            label,
            _current_original_func_addr_8616(project, codegen) or -1,
        )
        return
    for key in sorted(store):
        entry = store[key]
        log.warning(
            "[condition-trace] %s condition_id=%s origin_block=%#x origin_insn=%#x "
            "classified=%r materialized=%r structured=%r emitted_c=%r validator_seen=%r",
            label,
            entry.get("condition_id"),
            entry.get("origin_block"),
            entry.get("origin_insn"),
            entry.get("classified"),
            entry.get("materialized"),
            entry.get("structured"),
            entry.get("emitted_c"),
            entry.get("validator_seen"),
        )
