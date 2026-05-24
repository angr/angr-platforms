from __future__ import annotations

# Layer: Lowering
# Responsibility: stack-slot/cvar lowering from typed alias evidence.
# Forbidden: rendered-text parsing and CLI guess-based recovery.

import contextlib
import logging
import os
import re
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypePointer
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable

from ..decompiler_postprocess_utils import _match_bp_stack_dereference_8616

log = logging.getLogger(__name__)


def _canonical_stack_offset_8616(offset):
    if not isinstance(offset, int):
        return offset
    if 0x8000 <= offset <= 0xFFFF:
        return offset - 0x10000
    return offset


def _debug_stack_condition_rebind_8616(codegen, before, after, *, note: str) -> None:
    if not os.environ.get("INERTIA_DEBUG_STACK_CONDITION_CANON"):
        return
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
    delta = getattr(getattr(codegen, "project", None), "_inertia_original_linear_delta", None)
    original = func_addr + delta if isinstance(func_addr, int) and isinstance(delta, int) else func_addr
    target_text = os.environ.get("INERTIA_DEBUG_STACK_CONDITION_CANON_ADDR")
    target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
    if isinstance(target_addr, int) and original != target_addr:
        return
    try:
        before_text = before.c_repr(indent=0)
    except Exception:  # noqa: BLE001
        before_text = str(before)
    try:
        after_text = after.c_repr(indent=0)
    except Exception:  # noqa: BLE001
        after_text = str(after)
    log.warning(
        "[stack-condition-canon] function=%#x note=%s before=%r after=%r",
        original or -1,
        note,
        before_text,
        after_text,
    )


def _is_generic_stack_name_8616(name: object) -> bool:
    return isinstance(name, str) and re.fullmatch(
        r"(?:arg_\d+|local_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)",
        name,
    ) is not None


def _sole_bound_stack_cvar_8616(codegen, resolve_stack_cvar_at_offset):
    bindings = getattr(codegen, "_inertia_stack_variable_bindings", None)
    if not isinstance(bindings, tuple) or len(bindings) != 1:
        return None
    binding = bindings[0]
    offset = _canonical_stack_offset_8616(getattr(binding, "offset", None))
    if not isinstance(offset, int):
        return None
    resolved = resolve_stack_cvar_at_offset(codegen, offset)
    if isinstance(resolved, structured_c.CVariable) and isinstance(
        getattr(resolved, "variable", None), SimStackVariable
    ):
        return resolved
    return None


def _sole_named_stack_cvar_8616(codegen):
    cfunc = getattr(codegen, "cfunc", None)
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return None
    arg_variable_ids = {
        id(getattr(arg, "variable", None))
        for arg in getattr(cfunc, "arg_list", ()) or ()
        if getattr(arg, "variable", None) is not None
    }
    candidates = []
    for variable, cvar in variables_in_use.items():
        if not isinstance(variable, SimStackVariable):
            continue
        if id(variable) in arg_variable_ids:
            continue
        name = getattr(cvar, "name", None) or getattr(variable, "name", None)
        if _is_generic_stack_name_8616(name):
            continue
        candidates.append(cvar)
    return candidates[0] if len(candidates) == 1 else None


def _prefer_bound_stack_cvar_8616(codegen, resolved, resolve_stack_cvar_at_offset):
    if not isinstance(resolved, structured_c.CVariable):
        return resolved
    variable = getattr(resolved, "variable", None)
    if not isinstance(variable, SimStackVariable):
        return resolved
    name = getattr(resolved, "name", None) or getattr(variable, "name", None)
    if not _is_generic_stack_name_8616(name):
        return resolved
    fallback = _sole_bound_stack_cvar_8616(codegen, resolve_stack_cvar_at_offset)
    if fallback is None:
        fallback = _sole_named_stack_cvar_8616(codegen)
    if fallback is None or fallback is resolved:
        return resolved
    fallback_var = getattr(fallback, "variable", None)
    if not isinstance(fallback_var, SimStackVariable):
        return resolved
    fallback_name = getattr(fallback, "name", None) or getattr(fallback_var, "name", None)
    if _is_generic_stack_name_8616(fallback_name):
        return resolved
    return fallback


def _record_stack_canonicalization_bridge_8616(
    codegen,
    *,
    expr,
    resolved_offset: int,
    kind: str,
) -> None:
    def _local_unwrap(node):
        while isinstance(node, structured_c.CTypeCast):
            node = node.expr
        return node

    if codegen is None or not isinstance(resolved_offset, int):
        return
    bridges = getattr(codegen, "_inertia_stack_canonicalization_bridges", None)
    if not isinstance(bridges, dict):
        bridges = {}
        codegen._inertia_stack_canonicalization_bridges = bridges
    expr = _local_unwrap(expr)
    if kind == "indexed_deref":
        if not (
            isinstance(expr, structured_c.CUnaryOp)
            and expr.op == "Dereference"
            and isinstance(_local_unwrap(expr.operand), structured_c.CIndexedVariable)
        ):
            return
        indexed = _local_unwrap(expr.operand)
    elif kind == "indexed_value":
        if not isinstance(expr, structured_c.CIndexedVariable):
            return
        indexed = expr
    else:
        return
    base_ref = _local_unwrap(indexed.variable)
    if not (isinstance(base_ref, structured_c.CUnaryOp) and base_ref.op == "Reference"):
        return
    base_var_expr = _local_unwrap(base_ref.operand)
    base_var = getattr(base_var_expr, "variable", None)
    index_expr = _local_unwrap(indexed.index)
    index_value = getattr(index_expr, "value", None)
    if not isinstance(base_var, SimStackVariable) or not isinstance(index_value, int):
        return
    bridges[(kind, id(base_var), index_value)] = resolved_offset

def _resolve_stack_cvar_at_offset(codegen, offset: int, *, stack_slot_identity_for_variable, preferred_size: int | None = None):
    if getattr(codegen, "cfunc", None) is None:
        return None
    offset = _canonical_stack_offset_8616(offset)
    if not isinstance(offset, int):
        return None

    arg_candidates: list[tuple[object, object]] = []
    arg_variable_ids = {
        id(getattr(arg, "variable", None))
        for arg in getattr(codegen.cfunc, "arg_list", ()) or ()
        if getattr(arg, "variable", None) is not None
    }
    arg_slot_identities = {
        stack_slot_identity_for_variable(getattr(arg, "variable", None))
        for arg in getattr(codegen.cfunc, "arg_list", ()) or ()
        if isinstance(getattr(arg, "variable", None), SimStackVariable)
    }
    arg_slot_identities.discard(None)
    for arg in getattr(codegen.cfunc, "arg_list", ()) or ():
        variable = getattr(arg, "variable", None)
        if isinstance(variable, SimStackVariable):
            arg_candidates.append((variable, arg))

    best_exact = None
    best_exact_score = None
    best_covering = None
    best_covering_score = None

    def _stack_name_is_generic(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(
            r"(?:arg_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)",
            name,
        ) is not None

    def _stack_candidate_score(variable, cvar, *, exact: bool):
        identity = stack_slot_identity_for_variable(variable)
        if identity is None:
            return (-1, -1, -1, -1, -1, -1)
        variable_name = getattr(variable, "name", None)
        cvar_name = getattr(cvar, "name", None)
        unified_name = getattr(getattr(cvar, "unified_variable", None), "name", None)
        preferred_name = next(
            (
                name
                for name in (variable_name, cvar_name, unified_name)
                if isinstance(name, str) and name and not _stack_name_is_generic(name)
            ),
            None,
        )
        is_arg_variable = 1 if id(variable) in arg_variable_ids else 0
        is_arg_slot = 1 if identity in arg_slot_identities else 0
        has_preferred_name = 1 if preferred_name is not None else 0
        size = getattr(variable, "size", None)
        type_size = getattr(getattr(cvar, "variable_type", None), "size", None)
        if isinstance(preferred_size, int) and preferred_size > 0 and isinstance(size, int):
            preferred_bits = preferred_size * 8
            if size == preferred_size:
                size_rank = 3
            elif size > preferred_size:
                size_rank = 2
            else:
                size_rank = 1
            if type_size == preferred_bits:
                type_rank = 3
            elif isinstance(type_size, int) and type_size > preferred_bits:
                type_rank = 2
            else:
                type_rank = 1
            preferred_rank = min(size_rank, type_rank)
            name_rank = has_preferred_name
        else:
            size_rank = -size if isinstance(size, int) else 0
            preferred_rank = has_preferred_name
            name_rank = size_rank
        exact_rank = 1 if exact else 0
        canonical_offset = _canonical_stack_offset_8616(getattr(variable, "offset", 0))
        offset_rank = -canonical_offset if exact else canonical_offset
        return (exact_rank, is_arg_variable, is_arg_slot, preferred_rank, name_rank, offset_rank)

    def _preferred_stack_name(variable, cvar):
        variable_name = getattr(variable, "name", None)
        cvar_name = getattr(cvar, "name", None)
        unified_name = getattr(getattr(cvar, "unified_variable", None), "name", None)
        return next(
            (
                name
                for name in (variable_name, cvar_name, unified_name)
                if isinstance(name, str) and name and not _stack_name_is_generic(name)
            ),
            None,
        )

    def _stack_name_root(name: object) -> str | None:
        if not isinstance(name, str) or not name:
            return None
        match = re.fullmatch(r"(?P<root>.*?)(?:_(?P<suffix>\d+))?", name)
        if match is None:
            return name
        root = match.group("root")
        suffix = match.group("suffix")
        return root if suffix is not None and root else name

    candidates = list(arg_candidates)
    candidates.extend(list(getattr(codegen.cfunc, "variables_in_use", {}).items()))

    for variable, cvar in candidates:
        if not isinstance(variable, SimStackVariable):
            continue
        identity = stack_slot_identity_for_variable(variable)
        if identity is None:
            continue

        base_offset = _canonical_stack_offset_8616(getattr(variable, "offset", None))
        size = getattr(variable, "size", None)
        if not isinstance(base_offset, int) or not isinstance(size, int):
            continue

        if base_offset == offset:
            score = _stack_candidate_score(variable, cvar, exact=True)
            if best_exact_score is None or score > best_exact_score:
                best_exact = (variable, cvar)
                best_exact_score = score
            continue

        if base_offset <= offset < base_offset + size:
            score = _stack_candidate_score(variable, cvar, exact=False)
            if best_covering_score is None or score > best_covering_score:
                best_covering = (variable, cvar)
                best_covering_score = score

    if best_exact is not None and best_covering is not None:
        exact_var, exact_cvar = best_exact
        covering_var, covering_cvar = best_covering
        exact_size = getattr(exact_var, "size", None)
        covering_size = getattr(covering_var, "size", None)
        exact_name = _preferred_stack_name(exact_var, exact_cvar)
        covering_name = _preferred_stack_name(covering_var, covering_cvar)
        exact_offset = _canonical_stack_offset_8616(getattr(exact_var, "offset", None))
        covering_offset = _canonical_stack_offset_8616(getattr(covering_var, "offset", None))
        if (
            isinstance(exact_offset, int)
            and isinstance(covering_offset, int)
            and exact_offset == offset
            and covering_offset < offset
            and isinstance(exact_size, int)
            and isinstance(covering_size, int)
            and exact_size == 1
            and covering_size > exact_size
            and (
                _stack_name_is_generic(getattr(exact_cvar, "name", None) or getattr(exact_var, "name", None))
                or (
                    covering_name is not None
                    and exact_name is not None
                    and _stack_name_root(covering_name) == _stack_name_root(exact_name)
                )
            )
        ):
            return covering_cvar

    if best_exact is not None:
        return best_exact[1]
    return best_covering[1] if best_covering is not None else None


def _materialize_stack_cvar_at_offset(
    codegen,
    offset: int,
    size: int = 2,
    *,
    resolve_stack_cvar_at_offset,
    promote_direct_stack_cvariable,
    stack_type_for_size,
):
    if getattr(codegen, "cfunc", None) is None:
        return None
    offset = _canonical_stack_offset_8616(offset)
    if not isinstance(offset, int):
        return None

    resolved = resolve_stack_cvar_at_offset(codegen, offset, preferred_size=size)
    resolved_variable = getattr(resolved, "variable", None)
    if (
        isinstance(resolved_variable, SimStackVariable)
        and _canonical_stack_offset_8616(getattr(resolved_variable, "offset", None)) == offset
    ):
        target_type = stack_type_for_size(size)
        promote_direct_stack_cvariable(codegen, resolved, size, target_type)
        return resolved

    target_type = stack_type_for_size(size)
    variable = SimStackVariable(
        offset,
        size,
        base="bp",
        name=_stack_object_name(offset, codegen=codegen),
        region=getattr(codegen.cfunc, "addr", None),
    )
    cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        unified_locals[variable] = {(cvar, target_type)}

    stack_local_candidates = getattr(codegen, "_inertia_stack_local_declaration_candidates", None)
    if isinstance(stack_local_candidates, dict):
        stack_local_candidates[id(variable)] = (variable, cvar)

    sort_local_vars = getattr(codegen.cfunc, "sort_local_vars", None)
    if callable(sort_local_vars):
        with contextlib.suppress(Exception):
            sort_local_vars()

    return cvar


def _canonicalize_stack_cvar_expr(
    expr,
    codegen,
    *,
    unwrap_c_casts,
    resolve_stack_cvar_at_offset,
    materialize_stack_cvar_at_offset=None,
    active_expr_ids: set[int] | None = None,
):
    expr = unwrap_c_casts(expr)
    if active_expr_ids is None:
        active_expr_ids = set()
    debug_stats = getattr(codegen, "_inertia_stack_lowering_debug", None)
    if not isinstance(debug_stats, dict):
        debug_stats = {}
        codegen._inertia_stack_lowering_debug = debug_stats
    debug_stats.setdefault("candidate_ast_match_count", 0)
    debug_stats.setdefault("candidate_text_match_count", 0)
    debug_stats.setdefault("lowering_replacements", 0)
    debug_stats.setdefault("lowering_refusals", 0)
    debug_stats.setdefault("stable_ss_lowering_refusal_reasons", {})
    expr_id = id(expr)
    if expr_id in active_expr_ids:
        return expr
    active_expr_ids.add(expr_id)

    synthetic_sp_anchor = None
    synthetic_bp_anchor = None
    inferred_stack_base_alias = ...

    def _iter_statement_nodes(root):
        stack = [root]
        seen_nodes: set[int] = set()
        while stack:
            node = stack.pop()
            if node is None:
                continue
            node_id = id(node)
            if node_id in seen_nodes:
                continue
            seen_nodes.add(node_id)
            yield node
            for attr in ("statements", "condition_and_nodes", "else_node", "lhs", "rhs", "operand", "expr", "init", "condition", "iteration", "body", "args", "operands"):
                if not hasattr(node, attr):
                    continue
                try:
                    value = getattr(node, attr)
                except Exception:
                    continue
                if value is None:
                    continue
                if isinstance(value, list | tuple):
                    for item in reversed(tuple(value)):
                        if isinstance(item, tuple):
                            for nested in reversed(item):
                                stack.append(nested)
                        else:
                            stack.append(item)
                else:
                    stack.append(value)

    def _synthetic_sp_anchor_cvar():
        nonlocal synthetic_sp_anchor
        if synthetic_sp_anchor is not None:
            return synthetic_sp_anchor
        cfunc = getattr(codegen, "cfunc", None)
        region = getattr(cfunc, "addr", None) if cfunc is not None else None
        variable = SimStackVariable(0, 2, base="sp", name="sp_0", region=region)
        synthetic_sp_anchor = structured_c.CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
        variables_in_use = getattr(cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            variables_in_use.setdefault(variable, synthetic_sp_anchor)
        unified_local_vars = getattr(cfunc, "unified_local_vars", None)
        if isinstance(unified_local_vars, dict):
            unified_local_vars.setdefault(variable, {(synthetic_sp_anchor, getattr(synthetic_sp_anchor, "variable_type", None))})
        return synthetic_sp_anchor

    def _synthetic_bp_anchor_cvar():
        nonlocal synthetic_bp_anchor
        if synthetic_bp_anchor is not None:
            return synthetic_bp_anchor
        cfunc = getattr(codegen, "cfunc", None)
        region = getattr(cfunc, "addr", None) if cfunc is not None else None
        variable = SimStackVariable(0, 2, base="bp", name="bp_0", region=region)
        synthetic_bp_anchor = structured_c.CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
        variables_in_use = getattr(cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            variables_in_use.setdefault(variable, synthetic_bp_anchor)
        unified_local_vars = getattr(cfunc, "unified_local_vars", None)
        if isinstance(unified_local_vars, dict):
            unified_local_vars.setdefault(variable, {(synthetic_bp_anchor, getattr(synthetic_bp_anchor, "variable_type", None))})
        return synthetic_bp_anchor

    def _infer_stack_base_alias_from_bp_slots():
        nonlocal inferred_stack_base_alias
        if inferred_stack_base_alias is not ...:
            return inferred_stack_base_alias

        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is None:
            inferred_stack_base_alias = None
            return None

        known_bp_offsets: set[int] = set()
        variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable in variables_in_use:
                if not isinstance(variable, SimStackVariable):
                    continue
                if getattr(variable, "base", None) != "bp":
                    continue
                offset = getattr(variable, "offset", None)
                if isinstance(offset, int) and offset < 0:
                    known_bp_offsets.add(offset)
        if not known_bp_offsets:
            inferred_stack_base_alias = None
            return None

        stack_base_displacements: set[int] = set()

        def _stack_base_displacement(node) -> int | None:
            node = unwrap_c_casts(node)
            if _is_stack_base_fake_variable(node):
                return 0
            if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
                lhs = _stack_base_displacement(node.lhs)
                rhs = _stack_base_displacement(node.rhs)
                lhs_value = getattr(unwrap_c_casts(node.lhs), "value", None)
                rhs_value = getattr(unwrap_c_casts(node.rhs), "value", None)
                if lhs is not None and isinstance(rhs_value, int):
                    return lhs + (rhs_value if node.op == "Add" else -rhs_value)
                if rhs is not None and isinstance(lhs_value, int) and node.op == "Add":
                    return rhs + lhs_value
            return None

        for node in _iter_statement_nodes(root):
            if isinstance(node, structured_c.CIndexedVariable):
                base_disp = _stack_base_displacement(getattr(node, "variable", None))
                index_value = getattr(unwrap_c_casts(getattr(node, "index", None)), "value", None)
                if isinstance(base_disp, int) and isinstance(index_value, int):
                    stack_base_displacements.add(base_disp + index_value)
                continue
            if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
                disp = _stack_base_displacement(getattr(node, "operand", None))
                if isinstance(disp, int):
                    stack_base_displacements.add(disp)

        if len(stack_base_displacements) < 2:
            inferred_stack_base_alias = None
            return None

        bias_scores: dict[int, int] = {}
        for disp in stack_base_displacements:
            for offset in known_bp_offsets:
                bias = offset - disp
                bias_scores[bias] = bias_scores.get(bias, 0) + 1

        best_bias = None
        best_score = 0
        tied = False
        for bias, _ in sorted(bias_scores.items()):
            matched_offsets = {disp + bias for disp in stack_base_displacements if (disp + bias) in known_bp_offsets}
            score = len(matched_offsets)
            if score > best_score:
                best_bias = bias
                best_score = score
                tied = False
            elif score == best_score and score > 0:
                tied = True

        if tied or not isinstance(best_bias, int) or best_score < 2:
            inferred_stack_base_alias = None
            return None

        inferred_stack_base_alias = (_synthetic_bp_anchor_cvar(), best_bias)
        return inferred_stack_base_alias

    def _is_stack_base_fake_variable(node) -> bool:
        return isinstance(node, structured_c.CFakeVariable) and getattr(node, "name", None) == "stack_base"

    def _is_ss_segment_scale_expr(node) -> bool:
        def _expr_is_ss_segment(expr, *, depth: int = 0) -> bool:
            if depth > 4:
                return False
            seg_expr = unwrap_c_casts(expr)
            if isinstance(seg_expr, structured_c.CVariable):
                seg_var = getattr(seg_expr, "variable", None)
                seg_name = getattr(seg_expr, "name", None) or getattr(seg_var, "name", None)
                if seg_name == "ss":
                    return True
                # Accept temporary segment carriers when single-assignment
                # evidence resolves them back to SS.
                if _is_linear_temp_cvar(seg_expr):
                    rhs = _single_assignment_expr_for_cvar(seg_expr)
                    if rhs is not None and _expr_is_ss_segment(rhs, depth=depth + 1):
                        return True
            return False

        node = unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp):
            return False
        if node.op == "Mul":
            pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
            scale = 16
        elif node.op == "Shl":
            pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
            scale = 4
        else:
            return False
        for maybe_seg, maybe_scale in pairs:
            if getattr(unwrap_c_casts(maybe_scale), "value", None) != scale:
                continue
            if _expr_is_ss_segment(maybe_seg):
                return True
        return False

    def _is_sp_virtual_register(variable) -> bool:
        sp_offset = getattr(getattr(getattr(codegen, "project", None), "arch", None), "registers", {}).get("sp", (None, None))[0]
        return isinstance(sp_offset, int) and getattr(variable, "reg", None) == sp_offset

    def _is_linear_temp_cvar(node) -> bool:
        if not isinstance(node, structured_c.CVariable):
            return False
        variable = getattr(node, "variable", None)
        if isinstance(variable, SimStackVariable):
            return False
        name = getattr(node, "name", None) or getattr(variable, "name", None)
        if name is None:
            return True
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+|ir_\d+|tmp_\d+)", name) is not None

    _UNRESOLVED_SINGLE_ASSIGNMENT = object()
    dirty_expr_single_assignment_cache: dict[str, object | None] = {}
    cvar_single_assignment_cache: dict[int, object | None] = {}

    def _alias_keys_for_cvar(node, *, lookup: bool) -> tuple[object, ...]:
        if not isinstance(node, structured_c.CVariable):
            return ()
        variable = getattr(node, "variable", None)
        keys: list[object] = []
        linear_temp = _is_linear_temp_cvar(node)
        if variable is not None:
            keys.append(("var", id(variable)))
            reg = getattr(variable, "reg", None)
            size = getattr(variable, "size", None)
            if lookup and not linear_temp and isinstance(reg, int) and isinstance(size, int):
                keys.append(("reg", reg, size))
        for candidate in (
            getattr(node, "name", None),
            getattr(variable, "name", None),
        ):
            if isinstance(candidate, str) and candidate:
                keys.append(("name", candidate))
        return tuple(dict.fromkeys(keys))

    def _single_assignment_expr_for_cvar(node_cvar):
        cache_key = id(node_cvar)
        if cache_key in cvar_single_assignment_cache:
            return cvar_single_assignment_cache[cache_key]

        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is None or not isinstance(node_cvar, structured_c.CVariable):
            cvar_single_assignment_cache[cache_key] = None
            return None

        node_var = getattr(node_cvar, "variable", None)
        node_name = getattr(node_cvar, "name", None) or getattr(node_var, "name", None)
        node_reg = getattr(node_var, "reg", None)
        node_size = getattr(node_var, "size", None)
        node_linear_temp = _is_linear_temp_cvar(node_cvar)

        def _same_lhs(lhs):
            if not isinstance(lhs, structured_c.CVariable):
                return False
            lhs_var = getattr(lhs, "variable", None)
            if lhs_var is node_var:
                return True
            lhs_name = getattr(lhs, "name", None) or getattr(lhs_var, "name", None)
            if isinstance(node_name, str) and node_name and lhs_name == node_name:
                return True
            lhs_reg = getattr(lhs_var, "reg", None)
            lhs_size = getattr(lhs_var, "size", None)
            lhs_linear_temp = _is_linear_temp_cvar(lhs)
            if node_linear_temp or lhs_linear_temp:
                return False
            return (
                isinstance(node_reg, int)
                and isinstance(node_size, int)
                and isinstance(lhs_reg, int)
                and isinstance(lhs_size, int)
                and lhs_reg == node_reg
                and lhs_size == node_size
            )

        matches = []
        for stmt in _iter_statement_nodes(root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            if not _same_lhs(getattr(stmt, "lhs", None)):
                continue
            matches.append(getattr(stmt, "rhs", None))
            if len(matches) > 1:
                cvar_single_assignment_cache[cache_key] = None
                return None
        resolved = matches[0] if len(matches) == 1 else None
        cvar_single_assignment_cache[cache_key] = resolved
        return resolved

    def _single_assignment_expr_for_virtual_name(name: str):
        cached = dirty_expr_single_assignment_cache.get(name)
        if cached is not None:
            return None if cached is _UNRESOLVED_SINGLE_ASSIGNMENT else cached

        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is None:
            dirty_expr_single_assignment_cache[name] = _UNRESOLVED_SINGLE_ASSIGNMENT
            return None

        target_varid = None
        if name.startswith("vvar_"):
            suffix = name.removeprefix("vvar_")
            if suffix.isdigit():
                target_varid = int(suffix)
        if not isinstance(target_varid, int):
            dirty_expr_single_assignment_cache[name] = _UNRESOLVED_SINGLE_ASSIGNMENT
            return None

        matches = []
        for stmt in _iter_statement_nodes(root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs = getattr(stmt, "lhs", None)
            lhs_name = None
            if isinstance(lhs, structured_c.CVariable):
                lhs_name = getattr(lhs, "name", None) or getattr(getattr(lhs, "variable", None), "name", None)
            lhs_varid = getattr(getattr(lhs, "dirty", None), "varid", None)
            if lhs_name != name and lhs_varid != target_varid:
                continue
            matches.append(getattr(stmt, "rhs", None))
            if len(matches) > 1:
                dirty_expr_single_assignment_cache[name] = _UNRESOLVED_SINGLE_ASSIGNMENT
                return None
        resolved = matches[0] if len(matches) == 1 else None
        dirty_expr_single_assignment_cache[name] = resolved if resolved is not None else _UNRESOLVED_SINGLE_ASSIGNMENT
        return resolved

    def _top_level_statements() -> list[object]:
        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        statements = getattr(root, "statements", None)
        if isinstance(statements, list | tuple):
            return list(statements)
        return []

    def _statement_index_containing(node) -> int | None:
        if node is None:
            return None
        for idx, stmt in enumerate(_top_level_statements()):
            for nested in _iter_statement_nodes(stmt):
                if nested is node:
                    return idx
        return None

    def _nearest_preceding_assignment_expr_for_cvar(node_cvar):
        if not isinstance(node_cvar, structured_c.CVariable):
            return None
        node_var = getattr(node_cvar, "variable", None)
        node_reg = getattr(node_var, "reg", None)
        node_size = getattr(node_var, "size", None)
        if not (isinstance(node_reg, int) and isinstance(node_size, int)):
            return None
        stmt_idx = _statement_index_containing(node_cvar)
        if stmt_idx is None:
            return None

        nearest_rhs = None
        for idx, stmt in enumerate(_top_level_statements()):
            if idx >= stmt_idx or not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs = getattr(stmt, "lhs", None)
            if not isinstance(lhs, structured_c.CVariable):
                continue
            lhs_var = getattr(lhs, "variable", None)
            lhs_reg = getattr(lhs_var, "reg", None)
            lhs_size = getattr(lhs_var, "size", None)
            if lhs_reg == node_reg and lhs_size == node_size:
                nearest_rhs = getattr(stmt, "rhs", None)
        return nearest_rhs

    def _resolve_dirty_virtual_expr(
        node,
        *,
        seen_varids: set[int] | None = None,
    ):
        dirty = getattr(node, "dirty", None)
        if dirty is None:
            return None
        varid = getattr(dirty, "varid", None)
        if not isinstance(varid, int):
            reg = getattr(dirty, "reg", None)
            bits = getattr(dirty, "bits", None)
            if _is_sp_virtual_register(SimpleNamespace(reg=reg, size=(bits // 8) if isinstance(bits, int) else None)):
                return _synthetic_sp_anchor_cvar()
            return None
        if seen_varids is None:
            seen_varids = set()
        if varid in seen_varids:
            return None
        seen_varids.add(varid)
        resolved = _single_assignment_expr_for_virtual_name(f"vvar_{varid}")
        if resolved is not None:
            return resolved
        reg = getattr(dirty, "reg", None)
        bits = getattr(dirty, "bits", None)
        if _is_sp_virtual_register(SimpleNamespace(reg=reg, size=(bits // 8) if isinstance(bits, int) else None)):
            return _synthetic_sp_anchor_cvar()
        return None

    def _canonicalize_dirty_expression(node):
        dirty_expr_cls = getattr(structured_c, "CDirtyExpression", None)
        if dirty_expr_cls is None or not isinstance(node, dirty_expr_cls):
            return node
        resolved = _resolve_dirty_virtual_expr(node)
        if resolved is None:
            return node
        return _canonicalize_stack_cvar_expr(
            resolved,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            materialize_stack_cvar_at_offset=materialize_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )

    dirtyized = _canonicalize_dirty_expression(expr)
    if dirtyized is not expr:
        active_expr_ids.discard(expr_id)
        return dirtyized

    def _is_pointer_capable_stack_variable(var: object, cvar: object | None = None) -> bool:
        if not isinstance(var, SimStackVariable):
            return False
        if getattr(var, "base", None) != "bp":
            return False
        size = getattr(var, "size", None)
        if isinstance(size, int) and size >= 2:
            return True
        var_type = getattr(cvar, "variable_type", None)
        return isinstance(var_type, SimTypePointer)

    def _stack_pointer_aliases():
        cached = getattr(codegen, "_inertia_stack_pointer_aliases_for_cvars", None)
        cache_key = getattr(codegen.cfunc, "statements", None)
        if isinstance(cached, tuple) and len(cached) == 2 and cached[0] is cache_key:
            return cached[1]

        aliases: dict[object, tuple[object, int]] = {}

        def _resolve_stack_pointer_alias(
            node,
            *,
            seen_expr_ids: set[int] | None = None,
            seen_varids: set[int] | None = None,
        ):
            node = unwrap_c_casts(node)
            if node is None:
                return None
            if seen_expr_ids is None:
                seen_expr_ids = set()
            node_id = id(node)
            if node_id in seen_expr_ids:
                return None
            seen_expr_ids.add(node_id)

            if isinstance(node, structured_c.CVariable):
                variable = getattr(node, "variable", None)
                for key in _alias_keys_for_cvar(node, lookup=True):
                    alias = aliases.get(key)
                    if alias is not None:
                        return alias
                if _is_pointer_capable_stack_variable(variable, node):
                    if getattr(variable, "base", None) == "bp":
                        return node, 0
                if _is_sp_virtual_register(variable):
                    return _synthetic_sp_anchor_cvar(), 0
                single_assignment_rhs = _single_assignment_expr_for_cvar(node)
                if single_assignment_rhs is not None:
                    return _resolve_stack_pointer_alias(
                        single_assignment_rhs,
                        seen_expr_ids=seen_expr_ids,
                        seen_varids=seen_varids,
                    )
                nearest_assignment_rhs = _nearest_preceding_assignment_expr_for_cvar(node)
                if nearest_assignment_rhs is not None:
                    return _resolve_stack_pointer_alias(
                        nearest_assignment_rhs,
                        seen_expr_ids=seen_expr_ids,
                        seen_varids=seen_varids,
                    )
                return None
            if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
                operand = unwrap_c_casts(node.operand)
                if isinstance(operand, structured_c.CVariable):
                    variable = getattr(operand, "variable", None)
                    if isinstance(variable, SimStackVariable):
                        if getattr(variable, "base", None) == "bp":
                            return operand, 0
                    for key in _alias_keys_for_cvar(operand, lookup=True):
                        alias = aliases.get(key)
                        if alias is not None:
                            return alias
                return None
            if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
                lhs = _resolve_stack_pointer_alias(
                    node.lhs,
                    seen_expr_ids=seen_expr_ids,
                    seen_varids=seen_varids,
                )
                rhs = _resolve_stack_pointer_alias(
                    node.rhs,
                    seen_expr_ids=seen_expr_ids,
                    seen_varids=seen_varids,
                )
                lhs_value = getattr(unwrap_c_casts(node.lhs), "value", None)
                rhs_value = getattr(unwrap_c_casts(node.rhs), "value", None)
                if lhs is not None and isinstance(rhs_value, int):
                    base, offset = lhs
                    return base, offset + (rhs_value if node.op == "Add" else -rhs_value)
                if rhs is not None and isinstance(lhs_value, int) and node.op == "Add":
                    base, offset = rhs
                    return base, offset + lhs_value
            return None

        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is not None:
            for _ in range(3):
                changed_local = False
                for node in _iter_statement_nodes(root):
                    if not isinstance(node, structured_c.CAssignment):
                        continue
                    lhs = unwrap_c_casts(getattr(node, "lhs", None))
                    if not isinstance(lhs, structured_c.CVariable):
                        continue
                    lhs_var = getattr(lhs, "variable", None)
                    if lhs_var is None:
                        continue
                    keys = _alias_keys_for_cvar(lhs, lookup=False)
                    if not keys:
                        continue
                    resolved = _resolve_stack_pointer_alias(getattr(node, "rhs", None))
                    if resolved is None:
                        continue
                    if isinstance(lhs_var, SimStackVariable):
                        if getattr(lhs_var, "base", None) != "bp":
                            continue
                    if isinstance(lhs_var, SimStackVariable) and not _is_pointer_capable_stack_variable(lhs_var, lhs):
                        # Accept tiny stack temporaries that are proved to carry a stack pointer.
                        # These appear in helper prologue/epilogue carrier patterns.
                        rhs_expr = unwrap_c_casts(getattr(node, "rhs", None))
                        if not (
                            isinstance(rhs_expr, structured_c.CUnaryOp)
                            and rhs_expr.op == "Reference"
                            or isinstance(rhs_expr, structured_c.CBinaryOp)
                        ):
                            continue
                    needs_update = False
                    for key in keys:
                        if aliases.get(key) != resolved:
                            aliases[key] = resolved
                            needs_update = True
                    if needs_update:
                        changed_local = True
                if not changed_local:
                    break

        setattr(codegen, "_inertia_stack_pointer_aliases_for_cvars", (cache_key, aliases))
        return aliases

    def _resolve_stack_pointer_alias_expr(
        base_expr,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ):
        base_ref = unwrap_c_casts(base_expr)
        if base_ref is None:
            return None
        if seen_expr_ids is None:
            seen_expr_ids = set()
        base_ref_id = id(base_ref)
        if base_ref_id in seen_expr_ids:
            return None
        seen_expr_ids.add(base_ref_id)

        resolved_dirty = _resolve_dirty_virtual_expr(base_ref, seen_varids=seen_varids)
        if resolved_dirty is not None:
            return _resolve_stack_pointer_alias_expr(
                resolved_dirty,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        if isinstance(base_ref, structured_c.CUnaryOp) and base_ref.op == "Reference":
            operand = unwrap_c_casts(base_ref.operand)
            if isinstance(operand, structured_c.CVariable):
                base_var = getattr(operand, "variable", None)
                for key in _alias_keys_for_cvar(operand, lookup=True):
                    alias_state = _stack_pointer_aliases().get(key)
                    if alias_state is not None:
                        return alias_state
                if isinstance(base_var, SimStackVariable) and getattr(base_var, "base", None) == "bp":
                    return operand, 0
            return None
        if _is_stack_base_fake_variable(base_ref):
            sp_anchor = _synthetic_sp_anchor_cvar()
            for key in _alias_keys_for_cvar(sp_anchor, lookup=True):
                alias_state = _stack_pointer_aliases().get(key)
                if alias_state is not None:
                    return alias_state
            inferred_alias = _infer_stack_base_alias_from_bp_slots()
            if inferred_alias is not None:
                return inferred_alias
            # `stack_base` is angr's entry-SP placeholder. In a BP-framed
            # 16-bit function, `push bp; mov bp, sp` makes BP two bytes below
            # that value, so stack_base-relative offsets need a +2 BP bias.
            return _synthetic_bp_anchor_cvar(), 2
        if isinstance(base_ref, structured_c.CVariable):
            base_var = getattr(base_ref, "variable", None)
            for key in _alias_keys_for_cvar(base_ref, lookup=True):
                alias_state = _stack_pointer_aliases().get(key)
                if alias_state is not None:
                    return alias_state
            if isinstance(base_var, SimStackVariable) and getattr(base_var, "base", None) == "bp":
                return base_ref, 0
            if _is_sp_virtual_register(base_var):
                return _synthetic_sp_anchor_cvar(), 0
            single_assignment_rhs = _single_assignment_expr_for_cvar(base_ref)
            if single_assignment_rhs is not None:
                return _resolve_stack_pointer_alias_expr(
                    single_assignment_rhs,
                    seen_expr_ids=seen_expr_ids,
                    seen_varids=seen_varids,
                )
            nearest_assignment_rhs = _nearest_preceding_assignment_expr_for_cvar(base_ref)
            if nearest_assignment_rhs is not None:
                return _resolve_stack_pointer_alias_expr(
                    nearest_assignment_rhs,
                    seen_expr_ids=seen_expr_ids,
                    seen_varids=seen_varids,
                )
            return None
        if isinstance(base_ref, structured_c.CBinaryOp) and base_ref.op in {"Add", "Sub"}:
            lhs = _resolve_stack_pointer_alias_expr(
                base_ref.lhs,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
            rhs = _resolve_stack_pointer_alias_expr(
                base_ref.rhs,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
            lhs_value = getattr(unwrap_c_casts(base_ref.lhs), "value", None)
            rhs_value = getattr(unwrap_c_casts(base_ref.rhs), "value", None)
            if base_ref.op == "Add":
                if _is_ss_segment_scale_expr(base_ref.lhs):
                    return rhs
                if _is_ss_segment_scale_expr(base_ref.rhs):
                    return lhs
            if lhs is not None and isinstance(rhs_value, int):
                alias_base_expr, alias_offset = lhs
                return alias_base_expr, alias_offset + (rhs_value if base_ref.op == "Add" else -rhs_value)
            if rhs is not None and isinstance(lhs_value, int) and base_ref.op == "Add":
                alias_base_expr, alias_offset = rhs
                return alias_base_expr, alias_offset + lhs_value
        return None

    def _resolve_base_stack_pointer_alias(base_expr):
        return _resolve_stack_pointer_alias_expr(base_expr)

    def _fact_backed_stack_size_for_offset(offset: int) -> int | None:
        bindings = getattr(codegen, "_inertia_stack_variable_bindings", None)
        if not isinstance(bindings, tuple):
            return None
        for binding in bindings:
            binding_offset = _canonical_stack_offset_8616(getattr(binding, "bp_offset", None))
            if binding_offset is None:
                binding_offset = _canonical_stack_offset_8616(getattr(binding, "offset", None))
            if binding_offset != offset:
                continue
            size = getattr(binding, "size", None)
            if isinstance(size, int) and size > 0:
                return size
        return None

    if isinstance(expr, structured_c.CVariable):
        variable = getattr(expr, "variable", None)
        if isinstance(variable, SimStackVariable):
            offset = getattr(variable, "offset", None)
            if isinstance(offset, int):
                canonical_offset = _canonical_stack_offset_8616(offset)
                preferred_size = (
                    _fact_backed_stack_size_for_offset(canonical_offset)
                    if isinstance(canonical_offset, int)
                    else None
                )
                if preferred_size is None:
                    preferred_size = getattr(variable, "size", None)
                resolved = resolve_stack_cvar_at_offset(
                    codegen,
                    offset,
                    preferred_size=preferred_size if isinstance(preferred_size, int) else None,
                )
                if isinstance(resolved, structured_c.CVariable):
                    active_expr_ids.discard(expr_id)
                    return resolved
                resolved_variable = getattr(resolved, "variable", None)
                if isinstance(resolved_variable, SimStackVariable):
                    variable_type = getattr(resolved, "variable_type", None) or getattr(expr, "variable_type", None)
                    active_expr_ids.discard(expr_id)
                    return structured_c.CVariable(resolved_variable, variable_type=variable_type, codegen=codegen)
        active_expr_ids.discard(expr_id)
        return expr
    if isinstance(expr, structured_c.CIndexedVariable):
        base_expr = _canonicalize_stack_cvar_expr(
            expr.variable,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            materialize_stack_cvar_at_offset=materialize_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        index_expr = _canonicalize_stack_cvar_expr(
            expr.index,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            materialize_stack_cvar_at_offset=materialize_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        alias_state = _resolve_base_stack_pointer_alias(base_expr)
        index_value = getattr(index_expr, "value", None)
        if alias_state is not None and isinstance(index_value, int):
            alias_base_expr, alias_offset = alias_state
            alias_base_var = getattr(alias_base_expr, "variable", None)
            target_offset = getattr(alias_base_var, "offset", None)
            if isinstance(target_offset, int):
                resolved_offset = target_offset + alias_offset + index_value
                resolved = resolve_stack_cvar_at_offset(codegen, resolved_offset, preferred_size=requested_size)
                resolved = _prefer_bound_stack_cvar_8616(codegen, resolved, resolve_stack_cvar_at_offset)
                resolved_var = getattr(resolved, "variable", None)
                if (
                    isinstance(resolved, structured_c.CVariable)
                    and isinstance(resolved_var, SimStackVariable)
                    and getattr(resolved_var, "offset", None) == resolved_offset
                ):
                    _record_stack_canonicalization_bridge_8616(
                        codegen,
                        expr=expr,
                        resolved_offset=resolved_offset,
                        kind="indexed_value",
                    )
                    debug_stats["candidate_ast_match_count"] += 1
                    debug_stats["lowering_replacements"] += 1
                    active_expr_ids.discard(expr_id)
                    return resolved
                arch = getattr(getattr(codegen, "project", None), "arch", None)
                byte_width = getattr(arch, "byte_width", None)
                type_size_bits = getattr(getattr(expr, "type", None), "size", None)
                requested_size = (
                    max(type_size_bits // byte_width, 1)
                    if isinstance(type_size_bits, int) and type_size_bits > 0 and isinstance(byte_width, int) and byte_width > 0
                    else None
                )
                base_size = getattr(alias_base_var, "size", None)
                if (
                    callable(materialize_stack_cvar_at_offset)
                    and isinstance(requested_size, int)
                    and isinstance(base_size, int)
                    and requested_size > base_size
                ):
                    materialized = materialize_stack_cvar_at_offset(codegen, resolved_offset, requested_size)
                    materialized_var = getattr(materialized, "variable", None)
                    if (
                        isinstance(materialized, structured_c.CVariable)
                        and isinstance(materialized_var, SimStackVariable)
                        and getattr(materialized_var, "offset", None) == resolved_offset
                    ):
                        materialized = _prefer_bound_stack_cvar_8616(codegen, materialized, resolve_stack_cvar_at_offset)
                        _record_stack_canonicalization_bridge_8616(
                            codegen,
                            expr=expr,
                            resolved_offset=resolved_offset,
                            kind="indexed_value",
                        )
                        debug_stats["candidate_ast_match_count"] += 1
                        debug_stats["lowering_replacements"] += 1
                        active_expr_ids.discard(expr_id)
                        return materialized
                if callable(materialize_stack_cvar_at_offset):
                    materialized = materialize_stack_cvar_at_offset(
                        codegen,
                        resolved_offset,
                        requested_size if isinstance(requested_size, int) and requested_size > 0 else 1,
                    )
                    materialized_var = getattr(materialized, "variable", None)
                    if (
                        isinstance(materialized, structured_c.CVariable)
                        and isinstance(materialized_var, SimStackVariable)
                        and getattr(materialized_var, "offset", None) == resolved_offset
                    ):
                        materialized = _prefer_bound_stack_cvar_8616(codegen, materialized, resolve_stack_cvar_at_offset)
                        _record_stack_canonicalization_bridge_8616(
                            codegen,
                            expr=expr,
                            resolved_offset=resolved_offset,
                            kind="indexed_value",
                        )
                        debug_stats["candidate_ast_match_count"] += 1
                        debug_stats["lowering_replacements"] += 1
                        active_expr_ids.discard(expr_id)
                        return materialized
        if base_expr is not expr.variable or index_expr is not expr.index:
            active_expr_ids.discard(expr_id)
            return structured_c.CIndexedVariable(base_expr, index_expr, codegen=getattr(expr, "codegen", None))
        active_expr_ids.discard(expr_id)
        return expr
    if isinstance(expr, structured_c.CUnaryOp):
        operand = _canonicalize_stack_cvar_expr(
            expr.operand,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            materialize_stack_cvar_at_offset=materialize_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        deref_operand = unwrap_c_casts(operand)
        if expr.op == "Dereference":
            project = getattr(codegen, "project", None)
            displacement = _match_bp_stack_dereference_8616(
                structured_c.CUnaryOp(expr.op, deref_operand, codegen=getattr(expr, "codegen", None)),
                project,
                codegen,
            )
            if displacement is None:
                alias_state = _resolve_stack_pointer_alias_expr(deref_operand)
                alias_base_expr = alias_state[0] if alias_state is not None else None
                alias_base_var = getattr(alias_base_expr, "variable", None)
                resolved_offset = getattr(alias_base_var, "offset", None)
                if isinstance(resolved_offset, int) and alias_state is not None:
                    displacement = resolved_offset + alias_state[1]
            if isinstance(displacement, int):
                type_bits = getattr(getattr(expr, "type", None), "size", None)
                arch = getattr(getattr(codegen, "project", None), "arch", None)
                byte_width = getattr(arch, "byte_width", None)
                access_size = (
                    max(type_bits // byte_width, 1)
                    if isinstance(type_bits, int) and type_bits > 0 and isinstance(byte_width, int) and byte_width > 0
                    else 2
                )
                resolved = resolve_stack_cvar_at_offset(codegen, displacement, preferred_size=access_size)
                resolved = _prefer_bound_stack_cvar_8616(codegen, resolved, resolve_stack_cvar_at_offset)
                resolved_var = getattr(resolved, "variable", None)
                if (
                    isinstance(resolved, structured_c.CVariable)
                    and isinstance(resolved_var, SimStackVariable)
                    and getattr(resolved_var, "offset", None) == displacement
                ):
                    debug_stats["candidate_ast_match_count"] += 1
                    debug_stats["lowering_replacements"] += 1
                    _debug_stack_condition_rebind_8616(codegen, expr, resolved, note="bp-deref-resolved")
                    active_expr_ids.discard(expr_id)
                    return resolved
                if callable(materialize_stack_cvar_at_offset):
                    materialized = materialize_stack_cvar_at_offset(codegen, displacement, access_size)
                    materialized_var = getattr(materialized, "variable", None)
                    if (
                        isinstance(materialized, structured_c.CVariable)
                        and isinstance(materialized_var, SimStackVariable)
                        and getattr(materialized_var, "offset", None) == displacement
                        ):
                            materialized = _prefer_bound_stack_cvar_8616(codegen, materialized, resolve_stack_cvar_at_offset)
                            debug_stats["candidate_ast_match_count"] += 1
                            debug_stats["lowering_replacements"] += 1
                            _debug_stack_condition_rebind_8616(codegen, expr, materialized, note="bp-deref-materialized")
                            active_expr_ids.discard(expr_id)
                            return materialized
            if isinstance(deref_operand, structured_c.CIndexedVariable):
                base_ref = unwrap_c_casts(deref_operand.variable)
                index_expr = unwrap_c_casts(deref_operand.index)
                base_var_expr = unwrap_c_casts(getattr(base_ref, "operand", None)) if isinstance(base_ref, structured_c.CUnaryOp) and base_ref.op == "Reference" else None
                base_var = getattr(base_var_expr, "variable", None)
                index_value = getattr(index_expr, "value", None)
                if isinstance(base_var_expr, structured_c.CVariable) and isinstance(base_var, SimStackVariable) and isinstance(index_value, int):
                    alias_state = _stack_pointer_aliases().get(id(base_var))
                    if alias_state is not None:
                        alias_base_expr, alias_offset = alias_state
                        alias_base_var = getattr(alias_base_expr, "variable", None)
                        resolved_offset = getattr(alias_base_var, "offset", None)
                        if isinstance(resolved_offset, int):
                            resolved_offset += alias_offset
                    else:
                        resolved_offset = getattr(base_var, "offset", None)
                    if isinstance(resolved_offset, int):
                        resolved_offset += index_value
                        resolved = resolve_stack_cvar_at_offset(codegen, resolved_offset, preferred_size=2)
                        resolved = _prefer_bound_stack_cvar_8616(codegen, resolved, resolve_stack_cvar_at_offset)
                        resolved_var = getattr(resolved, "variable", None)
                        if (
                            isinstance(resolved, structured_c.CVariable)
                            and isinstance(resolved_var, SimStackVariable)
                            and getattr(resolved_var, "offset", None) == resolved_offset
                        ):
                            _record_stack_canonicalization_bridge_8616(
                                codegen,
                                expr=expr,
                                resolved_offset=resolved_offset,
                                kind="indexed_deref",
                            )
                            debug_stats["candidate_ast_match_count"] += 1
                            debug_stats["lowering_replacements"] += 1
                            _debug_stack_condition_rebind_8616(codegen, expr, resolved, note="indexed-deref-resolved")
                            active_expr_ids.discard(expr_id)
                            return resolved
                        if callable(materialize_stack_cvar_at_offset):
                            materialized = materialize_stack_cvar_at_offset(codegen, resolved_offset, 2)
                            materialized_var = getattr(materialized, "variable", None)
                            if (
                                isinstance(materialized, structured_c.CVariable)
                                and isinstance(materialized_var, SimStackVariable)
                                and getattr(materialized_var, "offset", None) == resolved_offset
                            ):
                                materialized = _prefer_bound_stack_cvar_8616(codegen, materialized, resolve_stack_cvar_at_offset)
                                _record_stack_canonicalization_bridge_8616(
                                    codegen,
                                    expr=expr,
                                    resolved_offset=resolved_offset,
                                    kind="indexed_deref",
                                )
                                debug_stats["candidate_ast_match_count"] += 1
                                debug_stats["lowering_replacements"] += 1
                                _debug_stack_condition_rebind_8616(codegen, expr, materialized, note="indexed-deref-materialized")
                                active_expr_ids.discard(expr_id)
                                return materialized
        if (
            expr.op == "Dereference"
            and isinstance(deref_operand, structured_c.CUnaryOp)
            and deref_operand.op == "Reference"
        ):
            referenced = unwrap_c_casts(deref_operand.operand)
            if isinstance(referenced, (structured_c.CVariable, structured_c.CIndexedVariable)):
                _debug_stack_condition_rebind_8616(codegen, expr, referenced, note="deref-reference-collapse")
                active_expr_ids.discard(expr_id)
                return referenced
        if operand is not expr.operand:
            active_expr_ids.discard(expr_id)
            return structured_c.CUnaryOp(expr.op, operand, codegen=getattr(expr, "codegen", None))
        active_expr_ids.discard(expr_id)
        return expr
    if isinstance(expr, structured_c.CBinaryOp):
        lhs = _canonicalize_stack_cvar_expr(
            expr.lhs,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            materialize_stack_cvar_at_offset=materialize_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        rhs = _canonicalize_stack_cvar_expr(
            expr.rhs,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            materialize_stack_cvar_at_offset=materialize_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        if lhs is not expr.lhs or rhs is not expr.rhs:
            active_expr_ids.discard(expr_id)
            return structured_c.CBinaryOp(expr.op, lhs, rhs, codegen=getattr(expr, "codegen", None))
        active_expr_ids.discard(expr_id)
        return expr
    if isinstance(expr, structured_c.CTypeCast):
        inner = _canonicalize_stack_cvar_expr(
            expr.expr,
            codegen,
            unwrap_c_casts=unwrap_c_casts,
            resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
            materialize_stack_cvar_at_offset=materialize_stack_cvar_at_offset,
            active_expr_ids=active_expr_ids,
        )
        if inner is not expr.expr:
            active_expr_ids.discard(expr_id)
            return structured_c.CTypeCast(None, expr.type, inner, codegen=getattr(expr, "codegen", None))
        active_expr_ids.discard(expr_id)
        return expr
    active_expr_ids.discard(expr_id)
    return expr


def _canonicalize_stack_cvars(codegen, *, replace_c_children, canonicalize_stack_cvar_expr) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def _stack_cvar_identity(node) -> tuple[str, int, int | None, int | None, object] | None:
        if not isinstance(node, structured_c.CVariable):
            return None
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        base = getattr(variable, "base", None)
        offset = getattr(variable, "offset", None)
        size = getattr(variable, "size", None)
        region = getattr(variable, "region", None)
        if not isinstance(base, str) or not isinstance(offset, int):
            return None
        type_size = getattr(getattr(node, "variable_type", None), "size", None)
        return base, offset, size if isinstance(size, int) else None, type_size if isinstance(type_size, int) else None, region

    def _same_stack_storage(lhs, rhs) -> bool:
        lhs_identity = _stack_cvar_identity(lhs)
        rhs_identity = _stack_cvar_identity(rhs)
        return lhs_identity is not None and lhs_identity == rhs_identity

    def transform(node):
        nonlocal changed
        canonical = canonicalize_stack_cvar_expr(node, codegen)
        if _same_stack_storage(node, canonical):
            return node
        if canonical is not node:
            changed = True
            return canonical
        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_c_children(root, transform):
        changed = True
    debug_stats = getattr(codegen, "_inertia_stack_lowering_debug", None)
    if isinstance(debug_stats, dict) and changed:
        log.debug(
            "stage=stack_canonicalize function=%#x candidate_ast_match_count=%d lowering_replacements=%d",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            int(debug_stats.get("candidate_ast_match_count", 0) or 0),
            int(debug_stats.get("lowering_replacements", 0) or 0),
        )

    return changed


def _resolve_stack_cvar_from_addr_expr(
    project,
    codegen,
    addr_expr,
    *,
    classify_segmented_addr_expr,
    resolve_stack_cvar_at_offset,
    promote_direct_stack_cvariable,
    materialize_stack_cvar_at_offset,
    stack_type_for_size,
):
    classified = classify_segmented_addr_expr(addr_expr, project)
    if classified is None or classified.kind != "stack" or classified.cvar is None:
        return None

    variable = getattr(classified.cvar, "variable", None)
    if not isinstance(variable, SimStackVariable):
        return None

    target_offset = _canonical_stack_offset_8616(getattr(variable, "offset", None))
    if not isinstance(target_offset, int):
        return None

    resolved_offset = target_offset + classified.extra_offset
    resolved = resolve_stack_cvar_at_offset(codegen, resolved_offset, preferred_size=2)
    resolved_variable = getattr(resolved, "variable", None)
    if (
        isinstance(resolved_variable, SimStackVariable)
        and _canonical_stack_offset_8616(getattr(resolved_variable, "offset", None)) == resolved_offset
    ):
        promote_direct_stack_cvariable(codegen, resolved, 2, stack_type_for_size(2))
        return resolved
    return materialize_stack_cvar_at_offset(codegen, resolved_offset, 2)


def _stack_object_name(offset: int, *, codegen=None) -> str:
    offset = _canonical_stack_offset_8616(offset)
    if not isinstance(offset, int):
        return "arg_0"

    arg_offsets: set[int] = set()
    cfunc = getattr(codegen, "cfunc", None) if codegen is not None else None
    if cfunc is not None:
        for arg in getattr(cfunc, "arg_list", ()) or ():
            arg_var = getattr(arg, "variable", None)
            if isinstance(arg_var, SimStackVariable):
                arg_offset = _canonical_stack_offset_8616(getattr(arg_var, "offset", None))
                if isinstance(arg_offset, int):
                    arg_offsets.add(arg_offset)

    if offset in arg_offsets:
        return f"arg_{offset:x}"

    if offset >= 0:
        return f"local_{offset:x}"
    return f"local_{-offset:x}"
