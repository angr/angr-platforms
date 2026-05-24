from __future__ import annotations

import enum
import logging
import os

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CFunctionCall, CTypeCast, CUnaryOp
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable

from .decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _match_real_mode_linear_expr_8616,
    _segment_reg_name_8616,
)
from .lowering.stack_probe_return_facts import TypedStackProbeReturnFact8616

__all__ = ["prune_materialized_callsite_segment_metadata_8616"]

logger = logging.getLogger(__name__)


def _is_plain_statement_block_8616(node: object) -> bool:
    return node.__class__.__name__ == "CStatements"


def _call_from_statement_8616(stmt: object) -> CFunctionCall | None:
    if isinstance(stmt, CFunctionCall):
        return stmt
    expr = getattr(stmt, "expr", None)
    if isinstance(expr, CFunctionCall):
        return expr
    return None


def _assignment_lhs_rhs_8616(node: object) -> tuple[object, object]:
    lhs = getattr(node, "lhs", None)
    rhs = getattr(node, "rhs", None)
    if lhs is None and hasattr(node, "dst"):
        lhs = getattr(node, "dst", None)
        rhs = getattr(node, "src", None)
    return lhs, rhs


def _is_assignment_node_8616(node: object) -> bool:
    class_name = node.__class__.__name__
    return class_name == "CAssignment" or class_name.endswith("Assignment") or (
        hasattr(node, "dst") and hasattr(node, "src")
    )


def _assignment_nodes_8616(stmt: object) -> tuple:
    candidates = []
    if _is_assignment_node_8616(stmt):
        candidates.append(stmt)
    for node in _iter_c_nodes_deep_8616(stmt):
        if _is_assignment_node_8616(node):
            candidates.append(node)
    return tuple(candidates)


def _lhs_writes_memory_8616(lhs: object) -> bool:
    if lhs is None:
        return False
    nodes = (lhs, *_iter_c_nodes_deep_8616(lhs))
    for raw_node in nodes:
        node = raw_node
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, CUnaryOp) and node.op == "Dereference":
            return True
        if isinstance(getattr(node, "variable", None), SimMemoryVariable):
            return True
    return False


def _segment_register_value_expr_8616(expr: object, project: object) -> bool:
    node = expr
    while isinstance(node, CTypeCast):
        node = node.expr
    if isinstance(node, CBinaryOp) and node.op in {"Shr", "Shl", "And", "Or"}:
        return _segment_register_value_expr_8616(node.lhs, project)
    variable = getattr(node, "variable", None)
    name = getattr(variable, "name", None) or getattr(node, "name", None)
    if isinstance(name, str) and name.lower() in {"cs", "ds", "es", "ss"}:
        return True
    if project is None:
        return False
    return _segment_reg_name_8616(node, project) in {"cs", "ds", "es", "ss"}


def _lhs_has_ss_address_evidence_8616(lhs: object, project: object) -> bool:
    nodes = (lhs, *_iter_c_nodes_deep_8616(lhs))
    for raw_node in nodes:
        node = raw_node
        while isinstance(node, CTypeCast):
            node = node.expr
        seg_name, _linear = _match_real_mode_linear_expr_8616(node, project)
        if seg_name == "ss":
            return True
    return False


def _segment_metadata_store_8616(stmt: object, project: object, *, allow_carried_high_byte: bool) -> bool:
    assignments = _assignment_nodes_8616(stmt)
    if not assignments:
        return False
    lhs, rhs = _assignment_lhs_rhs_8616(assignments[-1])
    if not _lhs_writes_memory_8616(lhs):
        return False
    if not _segment_register_value_expr_8616(rhs, project):
        return False
    return allow_carried_high_byte or _lhs_has_ss_address_evidence_8616(lhs, project)


CarrierKey8616 = tuple[str, str | int]


class StackCarrierPruneDecision8616(enum.Enum):
    DEFINITELY_DEAD = "definitely_dead"
    LIVE_CALL_ARG_SETUP = "live_call_arg_setup"
    LIVE_MEMORY_WRITE = "live_memory_write"
    LIVE_STACK_CARRIER = "live_stack_carrier"
    LIVE_WIDENING_CARRIER = "live_widening_carrier"
    LIVE_CONDITION_SOURCE = "live_condition_source"
    UNKNOWN_REFUSE = "unknown_refuse"


def _safe_dead_carrier_prune_enabled_8616(codegen: object | None) -> bool:
    # Emergency kill switch.
    flag_disable = os.environ.get("INERTIA_DISABLE_SAFE_DEAD_CARRIER_PRUNE", "").strip().lower()
    if flag_disable in {"1", "true", "yes", "on"}:
        return False
    if codegen is not None:
        attr = getattr(codegen, "_inertia_enable_safe_dead_carrier_prune", None)
        if isinstance(attr, bool):
            return attr
    # Production default.
    return True


def _callsite_materialization_complete_8616(codegen: object | None) -> bool:
    if codegen is None:
        return False
    stats = getattr(codegen, "_inertia_callsite_materialization_stats", None)
    if stats is None:
        return False
    target_fact = int(getattr(stats, "call_target_fact_count", 0) or 0)
    target_mat = int(getattr(stats, "call_target_materialized_count", 0) or 0)
    arg_fact = int(getattr(stats, "call_arg_fact_count", 0) or 0)
    arg_mat = int(getattr(stats, "call_arg_materialized_count", 0) or 0)
    return target_mat >= target_fact and arg_mat >= arg_fact


def _bump_dead_setup_counter_8616(codegen: object | None, name: str, inc: int = 1) -> None:
    if codegen is None:
        return
    setattr(codegen, name, int(getattr(codegen, name, 0)) + int(inc))


def _generic_stack_carrier_name_8616(node: object) -> str | None:
    while isinstance(node, CTypeCast):
        node = node.expr
    variable = getattr(node, "variable", None)
    for name in (getattr(node, "name", None), getattr(variable, "name", None)):
        if isinstance(name, str) and name.startswith(("vvar_", "ir_", "tmp_")):
            return name
    return None


def _stack_carrier_key_8616(node: object) -> CarrierKey8616 | None:
    """Return a stable AST-local key for a stack-address carrier variable."""
    name = _generic_stack_carrier_name_8616(node)
    if name is not None:
        return ("name", name)
    while isinstance(node, CTypeCast):
        node = node.expr
    variable = getattr(node, "variable", None)
    if isinstance(variable, SimRegisterVariable):
        stable_name = getattr(variable, "name", None) or getattr(node, "name", None)
        if isinstance(stable_name, str) and stable_name.lower() in {
            "ax",
            "bx",
            "cx",
            "dx",
            "si",
            "di",
            "bp",
            "sp",
        }:
            return None
        return ("var", id(variable))
    return None


def _generic_stack_carrier_keys_8616(node: object) -> set[CarrierKey8616]:
    names: set[CarrierKey8616] = set()
    for raw_node in (node, *_iter_c_nodes_deep_8616(node)):
        key = _stack_carrier_key_8616(raw_node)
        if key is not None:
            names.add(key)
    return names


def _stmt_has_call_8616(stmt: object) -> bool:
    if stmt is None:
        return False
    if _call_from_statement_8616(stmt) is not None:
        return True
    for node in _iter_c_nodes_deep_8616(stmt):
        if isinstance(node, CFunctionCall):
            return True
    return False


def _stmt_has_memory_write_8616(stmt: object) -> bool:
    for assign in _assignment_nodes_8616(stmt):
        lhs, _rhs = _assignment_lhs_rhs_8616(assign)
        if _lhs_writes_memory_8616(lhs):
            return True
    return False


def _stmt_uses_carrier_key_8616(stmt: object, key: CarrierKey8616) -> bool:
    return key in _generic_stack_carrier_keys_8616(stmt)


def _carrier_key_protected_8616(lhs_key: CarrierKey8616, codegen: object | None) -> bool:
    if codegen is None:
        return False
    for attr in (
        "_inertia_callsite_arg_sources",
        "_inertia_stack_variable_bindings",
        "_inertia_stack_canonicalization_bridges",
        "_inertia_tail_validation_widened_carriers",
        "_inertia_linear_recurrence_state",
    ):
        value = getattr(codegen, attr, None)
        if value is None:
            continue
        text = repr(value)
        if lhs_key[0] == "name" and isinstance(lhs_key[1], str) and lhs_key[1] in text:
            return True
    return False


def _classify_dead_carrier_candidate_8616(
    stmt: object,
    lhs_key: CarrierKey8616,
    rhs: object,
    *,
    live: set[CarrierKey8616],
    known_carriers: set[CarrierKey8616],
    call_indices: set[int],
    stmt_index: int,
    statements: list[object],
    codegen: object | None,
) -> StackCarrierPruneDecision8616:
    if _stmt_has_memory_write_8616(stmt):
        return StackCarrierPruneDecision8616.LIVE_MEMORY_WRITE
    if lhs_key in live:
        return StackCarrierPruneDecision8616.LIVE_STACK_CARRIER
    if _carrier_key_protected_8616(lhs_key, codegen):
        return StackCarrierPruneDecision8616.LIVE_WIDENING_CARRIER
    if _stmt_has_call_8616(stmt):
        return StackCarrierPruneDecision8616.LIVE_CALL_ARG_SETUP
    # Keep setup around call boundaries only when the call actually references
    # this carrier key.
    for near in (stmt_index - 1, stmt_index + 1):
        if near in call_indices and 0 <= near < len(statements) and _stmt_uses_carrier_key_8616(statements[near], lhs_key):
            return StackCarrierPruneDecision8616.LIVE_CALL_ARG_SETUP
    if _generic_stack_carrier_keys_8616(rhs).intersection(known_carriers):
        # If RHS references other carrier keys, preserve unless we can prove the
        # entire chain is dead; conservative by default.
        return StackCarrierPruneDecision8616.UNKNOWN_REFUSE
    return StackCarrierPruneDecision8616.DEFINITELY_DEAD


def _expr_is_pure_stack_address_carrier_8616(
    expr: object,
    known_carriers: set[CarrierKey8616] | None = None,
) -> bool:
    """Return true for side-effect-free stack-address shuttle expressions."""
    node = expr
    while isinstance(node, CTypeCast):
        node = node.expr
    if isinstance(node, CFunctionCall):
        return False
    if isinstance(node, CUnaryOp):
        if node.op == "Dereference":
            return False
        if node.op == "Reference":
            return True
        return _expr_is_pure_stack_address_carrier_8616(getattr(node, "operand", None), known_carriers)
    if isinstance(node, CBinaryOp):
        if node.op not in {"Add", "Sub", "Mul", "Shl", "Shr", "And", "Or", "Xor"}:
            return False
        return _expr_is_pure_stack_address_carrier_8616(
            node.lhs, known_carriers
        ) or _expr_is_pure_stack_address_carrier_8616(node.rhs, known_carriers)
    key = _stack_carrier_key_8616(node)
    return key is not None and (
        _generic_stack_carrier_name_8616(node) is not None or key in (known_carriers or set())
    )


def _dead_stack_carrier_assignment_8616(
    stmt: object,
    known_carriers: set[CarrierKey8616],
) -> tuple[CarrierKey8616, object] | None:
    if not _is_assignment_node_8616(stmt):
        return None
    lhs, rhs = _assignment_lhs_rhs_8616(stmt)
    if _lhs_writes_memory_8616(lhs):
        return None
    lhs_key = _stack_carrier_key_8616(lhs)
    if lhs_key is None or lhs_key not in known_carriers:
        return None
    if not _expr_is_pure_stack_address_carrier_8616(rhs, known_carriers):
        return None
    return lhs_key, rhs


def _collect_stack_carrier_assignments_8616(block: object) -> set[CarrierKey8616]:
    """Collect variables proven to carry stack addresses within this block."""
    known: set[CarrierKey8616] = set()
    if not _is_plain_statement_block_8616(block):
        return known
    statements = getattr(block, "statements", None)
    if not isinstance(statements, (list, tuple)):
        return known
    for stmt in statements:
        if not _is_assignment_node_8616(stmt):
            continue
        lhs, rhs = _assignment_lhs_rhs_8616(stmt)
        if _lhs_writes_memory_8616(lhs):
            continue
        lhs_key = _stack_carrier_key_8616(lhs)
        if lhs_key is not None and _expr_is_pure_stack_address_carrier_8616(rhs, known):
            known.add(lhs_key)
    return known


def _prune_dead_stack_carrier_assignments_8616(block: object, codegen: object | None = None) -> bool:
    """Remove dead generic address carriers left after call arguments are materialized."""
    if not _safe_dead_carrier_prune_enabled_8616(codegen):
        _bump_dead_setup_counter_8616(codegen, "dead_setup_refused")
        _bump_dead_setup_counter_8616(codegen, "dead_setup_unknown_refuse")
        return False
    if not _callsite_materialization_complete_8616(codegen):
        # Evidence gate: do not prune carrier setup until callsite argument facts
        # are fully materialized.
        _bump_dead_setup_counter_8616(codegen, "dead_setup_refused")
        _bump_dead_setup_counter_8616(codegen, "dead_setup_live_call_arg")
        return False
    changed = False
    if not _is_plain_statement_block_8616(block):
        return False
    statements = getattr(block, "statements", None)
    if not isinstance(statements, (list, tuple)):
        return False

    for stmt in list(statements):
        for child in (
            getattr(stmt, "body", None),
            getattr(stmt, "else_node", None),
        ):
            if _is_plain_statement_block_8616(child):
                changed |= _prune_dead_stack_carrier_assignments_8616(child, codegen=codegen)
        if _is_plain_statement_block_8616(stmt):
            changed |= _prune_dead_stack_carrier_assignments_8616(stmt, codegen=codegen)
        for pair in getattr(stmt, "condition_and_nodes", ()) or ():
            if (
                isinstance(pair, tuple)
                and len(pair) == 2
                and _is_plain_statement_block_8616(pair[1])
            ):
                changed |= _prune_dead_stack_carrier_assignments_8616(pair[1], codegen=codegen)

    statement_list = list(getattr(block, "statements", ()) or ())
    known_carriers = _collect_stack_carrier_assignments_8616(block)
    call_indices = {idx for idx, stmt in enumerate(statement_list) if _stmt_has_call_8616(stmt)}
    live: set[CarrierKey8616] = set()
    kept_reversed: list = []
    removed = 0
    reversed_pairs = list(enumerate(statement_list))
    reversed_pairs.reverse()
    for stmt_index, stmt in reversed_pairs:
        carrier = _dead_stack_carrier_assignment_8616(stmt, known_carriers)
        if carrier is not None:
            lhs_key, rhs = carrier
            _bump_dead_setup_counter_8616(codegen, "dead_setup_candidates")
            _bump_dead_setup_counter_8616(codegen, "dead_setup_raw_fact_count")
            _bump_dead_setup_counter_8616(codegen, "dead_setup_normalized_fact_count")
            _bump_dead_setup_counter_8616(codegen, "dead_setup_classified_fact_count")
            decision = _classify_dead_carrier_candidate_8616(
                stmt,
                lhs_key,
                rhs,
                live=live,
                known_carriers=known_carriers,
                call_indices=call_indices,
                stmt_index=stmt_index,
                statements=statement_list,
                codegen=codegen,
            )
            if decision == StackCarrierPruneDecision8616.DEFINITELY_DEAD:
                changed = True
                removed += 1
                _bump_dead_setup_counter_8616(codegen, "dead_setup_pruned")
                _bump_dead_setup_counter_8616(codegen, "dead_setup_materialized_count")
                continue
            if decision == StackCarrierPruneDecision8616.LIVE_CALL_ARG_SETUP:
                _bump_dead_setup_counter_8616(codegen, "dead_setup_live_call_arg")
            elif decision == StackCarrierPruneDecision8616.LIVE_STACK_CARRIER:
                _bump_dead_setup_counter_8616(codegen, "dead_setup_live_stack_carrier")
            elif decision == StackCarrierPruneDecision8616.LIVE_WIDENING_CARRIER:
                _bump_dead_setup_counter_8616(codegen, "dead_setup_live_widening_carrier")
            elif decision == StackCarrierPruneDecision8616.LIVE_CONDITION_SOURCE:
                _bump_dead_setup_counter_8616(codegen, "dead_setup_live_condition_source")
            else:
                _bump_dead_setup_counter_8616(codegen, "dead_setup_unknown_refuse")
            _bump_dead_setup_counter_8616(codegen, "dead_setup_refused")
            live.discard(lhs_key)
            live.update(_generic_stack_carrier_keys_8616(rhs).intersection(known_carriers))
            kept_reversed.append(stmt)
            continue
        live.update(_generic_stack_carrier_keys_8616(stmt).intersection(known_carriers))
        kept_reversed.append(stmt)

    if changed:
        logger.debug(
            "Pruned %d dead stack-address carrier assignment(s) from callsite metadata block with %d carrier key(s)",
            removed,
            len(known_carriers),
        )
        kept_reversed.reverse()
        block.statements = kept_reversed if isinstance(statements, list) else tuple(kept_reversed)
    return changed


def _prune_trailing_segment_metadata_8616(statements: list, project: object) -> bool:
    changed = False
    removed_store = False
    while statements:
        if _segment_metadata_store_8616(statements[-1], project, allow_carried_high_byte=removed_store):
            statements.pop()
            removed_store = True
            changed = True
            continue
        if (
            not removed_store
            and len(statements) >= 2
            and _segment_metadata_store_8616(statements[-1], project, allow_carried_high_byte=True)
            and _segment_metadata_store_8616(statements[-2], project, allow_carried_high_byte=False)
        ):
            statements.pop()
            removed_store = True
            changed = True
            continue
        break
    return changed


def prune_materialized_callsite_segment_metadata_8616(project: object, codegen: object) -> bool:
    """Drop stack-probe segment metadata stores after their call args are materialized."""
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None)
    if not _is_plain_statement_block_8616(root):
        return False

    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        summary_map = {}
    typed_fact_map = getattr(codegen, "_inertia_typed_stack_probe_return_facts", None)
    if not isinstance(typed_fact_map, dict):
        typed_fact_map = {}
    else:
        typed_fact_map = {
            key: value for key, value in typed_fact_map.items() if isinstance(key, int) and isinstance(value, TypedStackProbeReturnFact8616)
        }
    materialized_metadata_ids = getattr(codegen, "_inertia_materialized_callsite_metadata_ids", None)
    if not isinstance(materialized_metadata_ids, dict):
        materialized_metadata_ids = {}
    use_typed_facts = bool(typed_fact_map)

    changed = False

    def rewrite_block(block: object, inherited_stack_probe_address_seen: bool = False) -> bool:
        nonlocal changed
        if not _is_plain_statement_block_8616(block):
            return inherited_stack_probe_address_seen
        statements = getattr(block, "statements", None)
        if not isinstance(statements, (list, tuple)):
            return inherited_stack_probe_address_seen

        stack_probe_address_seen = inherited_stack_probe_address_seen or (
            bool(typed_fact_map)
            if use_typed_facts
            else any(
                bool(getattr(item, "stack_probe_helper", False))
                and getattr(item, "helper_return_state", None) == "stack_address"
                and getattr(item, "helper_return_space", None) in {None, "ss"}
                for item in summary_map.values()
            )
        )
        new_statements = []
        for stmt in list(statements):
            call = _call_from_statement_8616(stmt)
            summary = summary_map.get(id(call)) if call is not None else None
            if call is not None and bool(getattr(summary, "stack_probe_helper", False)):
                if use_typed_facts:
                    stack_probe_address_seen = id(call) in typed_fact_map
                elif getattr(summary, "helper_return_state", None) == "stack_address":
                    stack_probe_address_seen = getattr(summary, "helper_return_space", None) in {None, "ss"}
            # Allow pruning for any call that has recorded segment-metadata store IDs.
            # Far calls (opcode 0x9A / CALL FAR) push CS as part of their call frame;
            # those stores are segment metadata and should be pruned even without a
            # preceding stack-probe helper call.
            has_materialized_metadata = call is not None and bool(materialized_metadata_ids.get(id(call), ()))
            if call is not None and (stack_probe_address_seen or has_materialized_metadata) and not bool(getattr(summary, "stack_probe_helper", False)):
                args = tuple(getattr(call, "args", ()) or ())
                if args and all(not _segment_register_value_expr_8616(arg, project) for arg in args):
                    prunable_ids = {
                        stmt_id for stmt_id in materialized_metadata_ids.get(id(call), ()) if isinstance(stmt_id, int)
                    }
                    if prunable_ids:
                        kept_statements = [old_stmt for old_stmt in new_statements if id(old_stmt) not in prunable_ids]
                        if len(kept_statements) != len(new_statements):
                            new_statements = kept_statements
                            changed = True
            # Ownership boundary:
            # This pass may prune call-frame metadata stores and their dead generic
            # carrier feeders after call arguments / metadata have already been
            # materialized. It must not recover new stack-slot semantics here.
            # If a vvar_/ir_/tmp_ carrier chain still needs to become a stack local,
            # that belongs in stack lowering / AST stack-alias rewrites, not in this
            # cleanup pass.
            #
            # Far calls push CS + IP as a far return frame BEFORE the call.
            # The stores look like: *(vvar_N + 1) = cs >> 8;
            # Detect any preceding memory store whose rhs is a segment register
            # value, then prune it and its carrier-temp feeders.
            # Only prune stores recorded in materialized_metadata_ids for this call.
            _call_args = tuple(getattr(call, "args", ()) or ()) if call is not None else ()
            if call is not None and _call_args and all(not _segment_register_value_expr_8616(arg, project) for arg in _call_args):
                call_metadata_ids = set(materialized_metadata_ids.get(id(call), ())) if call is not None else set()
                if call_metadata_ids:
                    removed = 0
                    scan = len(new_statements) - 1
                    while scan >= 0:
                        candidate = new_statements[scan]
                        if id(candidate) in call_metadata_ids:
                            removed += 1
                            scan -= 1
                            continue
                        assignments = _assignment_nodes_8616(candidate)
                        if not assignments:
                            break
                        lhs, rhs = _assignment_lhs_rhs_8616(assignments[-1])
                        if not _lhs_writes_memory_8616(lhs) or not _segment_register_value_expr_8616(rhs, project):
                            break
                        removed += 1
                        scan -= 1
                    # Also prune carrier-temp assignments (vvar_*) that feed the stores
                    while scan >= 0:
                        candidate = new_statements[scan]
                        lhs, _rhs = _assignment_lhs_rhs_8616(candidate)
                        if _lhs_writes_memory_8616(lhs):
                            break
                        if _generic_stack_carrier_name_8616(lhs if lhs is not None else candidate) is None:
                            break
                        removed += 1
                        scan -= 1
                    if removed > 0:
                        new_statements = new_statements[:-removed]
                        changed = True
            new_statements.append(stmt)

        if new_statements != list(statements):
            block.statements = new_statements if isinstance(statements, list) else tuple(new_statements)

        for stmt in getattr(block, "statements", ()) or ():
            for child in (
                getattr(stmt, "body", None),
                getattr(stmt, "else_node", None),
            ):
                if _is_plain_statement_block_8616(child):
                    rewrite_block(child, stack_probe_address_seen)
            if _is_plain_statement_block_8616(stmt):
                rewrite_block(stmt, stack_probe_address_seen)
            for pair in getattr(stmt, "condition_and_nodes", ()) or ():
                if (
                    isinstance(pair, tuple)
                    and len(pair) == 2
                    and _is_plain_statement_block_8616(pair[1])
                ):
                    rewrite_block(pair[1], stack_probe_address_seen)
        return stack_probe_address_seen

    rewrite_block(root)
    if _prune_dead_stack_carrier_assignments_8616(root, codegen=codegen):
        changed = True
    return changed
