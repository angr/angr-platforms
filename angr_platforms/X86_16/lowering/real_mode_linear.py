from __future__ import annotations

"""Typed helpers for recognizing real-mode segment:offset linearizations.

The x86-16 lifter represents a real-mode memory address as
``(segment << 4) + offset`` (or equivalently ``segment * 16 + offset``).
This module centralizes that structural recognition so stack lowering can
consume a typed SS address fact instead of re-learning the arithmetic shape in
late cleanup code.
"""

import os
import sys
from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimVariable

from ..alias.alias_model import _stack_storage_facts_for_segmented_address_8616


@dataclass(frozen=True, slots=True)
class RealModeLinearStackAccess8616:
    """Stable SS stack access recovered from real-mode linear address math."""

    displacement: int
    width: int | None


@dataclass(frozen=True, slots=True)
class RealModeLinearGlobalAddress8616:
    """Stable DS/ES address-valued expression recovered from real-mode linear math."""

    segment_name: str
    displacement: int
    residual_terms: tuple[tuple[int, object], ...]
    width: int | None = None


_UNRESOLVED_STACK_OFFSET_8616 = object()


def _type_for_access_width_8616(width: int | None):
    if width == 1:
        return SimTypeChar(False)
    return SimTypeShort(False)


def _strip_casts_8616(node):
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _constant_value_8616(node) -> int | None:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _stack_base_bp_bias_8616(node) -> int | None:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CFakeVariable) and getattr(node, "name", None) == "stack_base":
        # Preserve a neutral anchor for direct stack_base arithmetic. The
        # conversion to BP-relative byte offsets happens in expression-specific
        # handling below.
        return 0
    return None


def _is_stack_base_placeholder_8616(node) -> bool:
    node = _strip_casts_8616(node)
    return isinstance(node, structured_c.CFakeVariable) and getattr(node, "name", None) == "stack_base"


def _segment_base_name_8616(node, project) -> str | None:
    """Return the segment register name for ``seg << 4`` or ``seg * 16``."""

    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None
    expected_scale = 4 if node.op == "Shl" else 16 if node.op == "Mul" else None
    if expected_scale is None:
        return None
    for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if _constant_value_8616(maybe_scale) != expected_scale:
            continue
        maybe_seg = _strip_casts_8616(maybe_seg)
        if not isinstance(maybe_seg, structured_c.CVariable):
            continue
        variable = getattr(maybe_seg, "variable", None)
        if not isinstance(variable, SimRegisterVariable):
            continue
        return getattr(project.arch, "register_names", {}).get(variable.reg)
    return None


def _flatten_signed_terms_8616(
    node,
    sign: int = 1,
) -> tuple[tuple[int, object], ...] | None:
    terms: list[tuple[int, object]] = []
    # We use an explicit stack to avoid recursion depth crashes on very deep trees.
    # active path markers prevent infinite loops from cyclic expressions.
    pending: list[tuple[object, int, bool]] = [(node, sign, False)]
    active: set[int] = set()

    while pending:
        current, current_sign, exiting = pending.pop()
        current = _strip_casts_8616(current)
        if current is None:
            return None
        if exiting:
            if isinstance(current, int):
                active.discard(current)
            continue

        node_id = id(current)
        if node_id in active:
            return None
        if len(active) > 1024:
            return None

        if isinstance(current, structured_c.CBinaryOp) and current.op == "Add":
            active.add(node_id)
            pending.append((node_id, 0, True))
            pending.append((current.rhs, current_sign, False))
            pending.append((current.lhs, current_sign, False))
            continue
        if isinstance(current, structured_c.CBinaryOp) and current.op == "Sub":
            active.add(node_id)
            pending.append((node_id, 0, True))
            pending.append((current.rhs, -current_sign, False))
            pending.append((current.lhs, current_sign, False))
            continue

        terms.append((current_sign, current))
        if len(terms) > 4096:
            return None

    return tuple(terms)


def _decompose_linear_global_terms_8616(node, project) -> tuple[str | None, int, tuple[tuple[int, object], ...]] | None:
    segment_name: str | None = None
    displacement = 0
    residual_terms: list[tuple[int, object]] = []

    terms = _flatten_signed_terms_8616(node)
    if terms is None:
        return None
    for sign, term in terms:
        seg = _segment_base_name_8616(term, project)
        if seg is not None:
            if sign != 1 or segment_name is not None:
                return None
            segment_name = seg
            continue
        const = _constant_value_8616(term)
        if const is not None:
            displacement += sign * const
            continue
        if not _address_projection_term_is_safe_8616(term):
            return None
        residual_terms.append((sign, term))

    return segment_name, displacement, tuple(residual_terms)


def _global_displacement_known_8616(codegen, displacement: int) -> bool:
    variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return False
    addr = displacement & 0xFFFF
    global_name = f"g_{addr:04X}"
    for variable in variables_in_use:
        if isinstance(variable, SimMemoryVariable) and getattr(variable, "addr", None) == addr:
            return True
        if isinstance(variable, SimVariable) and getattr(variable, "name", None) == global_name:
            return True
    return False


def _global_size_from_displacement_8616(codegen, displacement: int) -> int | None:
    variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return None
    addr = displacement & 0xFFFF
    global_name = f"g_{addr:04X}"
    for variable in variables_in_use:
        if isinstance(variable, SimMemoryVariable) and getattr(variable, "addr", None) == addr:
            size = getattr(variable, "size", None)
            if isinstance(size, int) and size > 0:
                return size
        if isinstance(variable, SimVariable) and getattr(variable, "name", None) == global_name:
            cvar = variables_in_use[variable]
            declared = getattr(cvar, "variable", None)
            if isinstance(declared, SimMemoryVariable):
                size = getattr(declared, "size", None)
                if isinstance(size, int) and size > 0:
                    return size
            size = getattr(declared, "size", None) if declared is not None else None
            if isinstance(size, int) and size > 0:
                return size
    return None


def _cvar_has_array_type_8616(cvar) -> bool:
    type_name = type(getattr(cvar, "variable_type", None)).__name__
    return "Array" in type_name


def _iter_statement_nodes_8616(root):
    stack = [root]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if current is None or not type(current).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        yield current
        for attr in ("statements", "body", "else_node", "condition_and_nodes", "condition", "init", "iteration"):
            value = getattr(current, attr, None)
            if value is None:
                continue
            if isinstance(value, list | tuple):
                for item in reversed(tuple(value)):
                    if isinstance(item, tuple):
                        stack.extend(reversed(item))
                    else:
                        stack.append(item)
            else:
                stack.append(value)


def _same_variable_storage_8616(lhs, rhs) -> bool:
    if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
        return False
    lhs_var = getattr(lhs, "variable", None)
    rhs_var = getattr(rhs, "variable", None)
    if lhs_var is rhs_var:
        return True
    lhs_name = getattr(lhs, "name", None) or getattr(lhs_var, "name", None)
    rhs_name = getattr(rhs, "name", None) or getattr(rhs_var, "name", None)
    if isinstance(lhs_name, str) and lhs_name and lhs_name == rhs_name:
        return True
    return (
        isinstance(lhs_var, SimRegisterVariable)
        and isinstance(rhs_var, SimRegisterVariable)
        and getattr(lhs_var, "reg", None) == getattr(rhs_var, "reg", None)
        and getattr(lhs_var, "size", None) == getattr(rhs_var, "size", None)
    )


# ── Precomputed maps (built once per lowering pass) ──

def _build_assignment_maps_8616(codegen):
    """Precompute assignment maps used by lowering and validation fingerprinting."""
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return ({}, {}, {}, set(), set(), set(), {}, {})

    var_id_map: dict[int, object] = {}
    name_map: dict[str, object] = {}
    reg_map: dict[tuple, object] = {}
    multi_var: set[int] = set()
    multi_name: set[str] = set()
    multi_reg: set[tuple] = set()
    first_name_map: dict[str, object] = {}
    first_reg_map: dict[tuple, object] = {}

    for stmt in _iter_statement_nodes_8616(root):
        if not isinstance(stmt, structured_c.CAssignment):
            continue
        lhs = getattr(stmt, "lhs", None)
        rhs = getattr(stmt, "rhs", None)

        if not isinstance(lhs, structured_c.CVariable):
            # CDirtyExpression lhs — record via dirty.name / dirty.varid
            dirty_lhs = getattr(lhs, "dirty", None) if lhs is not None else None
            dirty_name = getattr(dirty_lhs, "name", None)
            dirty_varid = getattr(dirty_lhs, "varid", None)
            if isinstance(dirty_name, str):
                if dirty_name not in first_name_map:
                    first_name_map[dirty_name] = rhs
                if dirty_name in name_map:
                    multi_name.add(dirty_name)
                    name_map[dirty_name] = None
                elif dirty_name not in multi_name:
                    name_map[dirty_name] = rhs
            if isinstance(dirty_varid, int):
                vvar_name = f"vvar_{dirty_varid}"
                if vvar_name not in first_name_map:
                    first_name_map[vvar_name] = rhs
                if vvar_name in name_map:
                    multi_name.add(vvar_name)
                    name_map[vvar_name] = None
                elif vvar_name not in multi_name:
                    name_map[vvar_name] = rhs
            continue

        var = getattr(lhs, "variable", None)

        var_id = id(var) if var is not None else None
        if var_id is not None:
            if var_id in var_id_map:
                multi_var.add(var_id)
                var_id_map[var_id] = None
            elif var_id not in multi_var:
                var_id_map[var_id] = rhs

        name = getattr(lhs, "name", None) or getattr(var, "name", None)
        if isinstance(name, str) and name:
            if name not in first_name_map:
                first_name_map[name] = rhs
            if name in name_map:
                multi_name.add(name)
                name_map[name] = None
            elif name not in multi_name:
                name_map[name] = rhs

        if isinstance(var, SimRegisterVariable):
            reg = getattr(var, "reg", None)
            size = getattr(var, "size", None)
            if isinstance(reg, int) and isinstance(size, int):
                reg_key = (reg, size)
                if reg_key not in first_reg_map:
                    first_reg_map[reg_key] = rhs
                if reg_key in reg_map:
                    multi_reg.add(reg_key)
                    reg_map[reg_key] = None
                elif reg_key not in multi_reg:
                    reg_map[reg_key] = rhs

    return (var_id_map, name_map, reg_map, multi_var, multi_name, multi_reg, first_name_map, first_reg_map)


def _ensure_assignment_maps_8616(codegen) -> tuple:
    """Return cached maps or build and cache them on codegen."""
    cached = getattr(codegen, "_inertia_assignment_maps", None)
    if cached is not None:
        return cached
    maps = _build_assignment_maps_8616(codegen)
    setattr(codegen, "_inertia_assignment_maps", maps)
    return maps


def _build_vvar_carrier_delta_map_8616(codegen) -> dict[int, int]:
    """Precompute vvar_id → carrier_delta in a single pass, caching on codegen."""
    project = getattr(codegen, "project", None)
    sp_reg, _sp_size = getattr(getattr(project, "arch", None), "registers", {}).get("sp", (None, None))
    facts = getattr(codegen, "_inertia_typed_stack_probe_return_facts", {}) or {}
    has_ss_facts = any(
        getattr(fact, "segment_space", None) == "ss" for fact in facts.values()
    )
    deltas: dict[int, int] = {}
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return deltas

    def _seed_from_init(expr, lhs_id):
        if expr is None:
            return None
        rhs_stripped = _strip_casts_8616(expr)
        ref_node: object = None
        const_delta: int = 0
        if isinstance(rhs_stripped, structured_c.CUnaryOp) and rhs_stripped.op == "Reference":
            ref_node = rhs_stripped.operand
        elif isinstance(rhs_stripped, structured_c.CBinaryOp) and rhs_stripped.op in {"Add", "Sub"}:
            if isinstance(_strip_casts_8616(rhs_stripped.lhs), structured_c.CUnaryOp):
                lhs_u = _strip_casts_8616(rhs_stripped.lhs)
                if lhs_u.op == "Reference":
                    ref_node = lhs_u.operand
                    rhs_const = _constant_value_8616(rhs_stripped.rhs)
                    if rhs_const is not None:
                        const_delta = rhs_const if rhs_stripped.op == "Add" else -rhs_const
            if ref_node is None and isinstance(_strip_casts_8616(rhs_stripped.rhs), structured_c.CUnaryOp):
                rhs_u = _strip_casts_8616(rhs_stripped.rhs)
                if rhs_u.op == "Reference" and rhs_stripped.op == "Add":
                    ref_node = rhs_u.operand
                    lhs_const = _constant_value_8616(rhs_stripped.lhs)
                    if lhs_const is not None:
                        const_delta = lhs_const
        if ref_node is not None:
            operand = _strip_casts_8616(ref_node)
            if isinstance(operand, structured_c.CVariable):
                var = getattr(operand, "variable", None)
                if isinstance(var, SimStackVariable):
                    offset = getattr(var, "offset", None)
                    if isinstance(offset, int):
                        deltas[lhs_id] = offset + const_delta
                        return True
        if isinstance(rhs_stripped, structured_c.CVariable):
            var = getattr(rhs_stripped, "variable", None)
            if isinstance(var, SimRegisterVariable) and getattr(var, "reg", None) == sp_reg and has_ss_facts:
                deltas[lhs_id] = 0
                return True
        return None

    for stmt in _iter_statement_nodes_8616(root):
        if not isinstance(stmt, structured_c.CAssignment):
            continue
        lhs_id = _extract_vvar_id_8616(getattr(stmt, "lhs", None))
        if not isinstance(lhs_id, int):
            continue
        _seed_from_init(getattr(stmt, "rhs", None), lhs_id)

    changed = True
    while changed:
        changed = False
        for stmt in _iter_statement_nodes_8616(root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs_id = _extract_vvar_id_8616(getattr(stmt, "lhs", None))
            if not isinstance(lhs_id, int) or lhs_id in deltas:
                continue
            base_ids: list[tuple[int, int]] = []
            const_total = 0
            unknown = False
            terms = _flatten_signed_terms_8616(getattr(stmt, "rhs", None))
            if terms is None:
                continue
            for sign, term in terms:
                base_id = _extract_vvar_id_8616(term)
                if isinstance(base_id, int):
                    base_ids.append((sign, base_id))
                    continue
                const = _constant_value_8616(term)
                if const is not None:
                    const_total += sign * const
                    continue
                unknown = True
            if unknown or len(base_ids) != 1:
                continue
            sign, base_id = base_ids[0]
            if sign != 1 or base_id not in deltas:
                continue
            deltas[lhs_id] = deltas[base_id] + const_total
            changed = True
    return deltas


def _ensure_vvar_carrier_delta_map_8616(codegen) -> dict[int, int]:
    """Return cached vvar_deltas or build and cache them on codegen."""
    cached = getattr(codegen, "_inertia_vvar_carrier_deltas", None)
    if cached is not None:
        return cached
    deltas = _build_vvar_carrier_delta_map_8616(codegen)
    setattr(codegen, "_inertia_vvar_carrier_deltas", deltas)
    return deltas


# ── O(1) lookup wrappers ──

def _single_assignment_rhs_8616(codegen, target):
    if not isinstance(target, structured_c.CVariable):
        return None
    var_id_map, name_map, reg_map, multi_var, multi_name, multi_reg, _first_name_map, _first_reg_map = (
        _ensure_assignment_maps_8616(codegen)
    )
    var = getattr(target, "variable", None)
    var_id = id(var) if var is not None else None
    if var_id is not None and var_id in var_id_map and var_id not in multi_var:
        return var_id_map[var_id]
    name = getattr(target, "name", None) or getattr(var, "name", None)
    if isinstance(name, str) and name in name_map and name not in multi_name:
        return name_map[name]
    if isinstance(var, SimRegisterVariable):
        reg = getattr(var, "reg", None)
        size = getattr(var, "size", None)
        if isinstance(reg, int) and isinstance(size, int):
            reg_key = (reg, size)
            if reg_key in reg_map and reg_key not in multi_reg:
                return reg_map[reg_key]
    return None


def _stack_pointer_carrier_offset_8616(
    node,
    project,
    codegen,
    seen: set[int] | None = None,
) -> int | None:
    """Recover a stack-pointer carrier from existing stack-probe facts."""

    if seen is None:
        seen = set()

    variable = getattr(node, "variable", None) if isinstance(node, structured_c.CVariable) else None
    dirty = getattr(node, "dirty", None)
    if isinstance(variable, SimRegisterVariable):
        reg = getattr(variable, "reg", None)
        size = getattr(variable, "size", None)
    else:
        reg = getattr(dirty, "reg", None)
        bits = getattr(dirty, "bits", None)
        size = (bits // 8) if isinstance(bits, int) else None
        varid = getattr(dirty, "varid", None)
        if not isinstance(reg, int) and isinstance(varid, int):
            target_name = f"vvar_{varid}"
            resolved = _single_assignment_rhs_for_virtual_name_8616(codegen, target_name)
            if resolved is not None:
                return _stack_offset_from_expr_8616(resolved, project, codegen, seen)
            delta = _stack_probe_carrier_delta_8616(node, codegen)
            if delta is not None:
                return delta
    bp_reg, bp_size = getattr(getattr(project, "arch", None), "registers", {}).get("bp", (None, None))
    if isinstance(bp_reg, int) and reg == bp_reg and (size is None or size == bp_size):
        return 0

    sp_reg, sp_size = getattr(getattr(project, "arch", None), "registers", {}).get("sp", (None, None))
    if not (isinstance(sp_reg, int) and reg == sp_reg and (size is None or size == sp_size)):
        return None
    facts = getattr(codegen, "_inertia_typed_stack_probe_return_facts", {}) or {}
    if not facts:
        return None
    for fact in facts.values():
        if getattr(fact, "segment_space", None) != "ss":
            continue
        width = getattr(fact, "width", None)
        if isinstance(width, int) and width > 0:
            return 0
    return None


def _lhs_name_8616(lhs) -> str | None:
    """Extract variable name from CVariable or CDirtyExpression LHS."""
    if isinstance(lhs, structured_c.CVariable):
        return getattr(lhs, "name", None) or getattr(getattr(lhs, "variable", None), "name", None)
    dirty = getattr(lhs, "dirty", None)
    if dirty is not None:
        name = getattr(dirty, "name", None)
        if isinstance(name, str):
            return name
        varid = getattr(dirty, "varid", None)
        if isinstance(varid, int):
            return f"vvar_{varid}"
    return None


def _single_assignment_rhs_for_virtual_name_8616(codegen, target_name: str, *, allow_multi: bool = False):
    _unused_var_id_map, name_map, _unused_reg_map, _unused_multi_var, multi_name, _unused_multi_reg, first_name_map, _first_reg_map = (
        _ensure_assignment_maps_8616(codegen)
    )
    if allow_multi:
        # O(1) lookup from precomputed first-assignment map
        return first_name_map.get(target_name)
    if target_name in name_map and target_name not in multi_name:
        return name_map[target_name]
    return None


def _extract_vvar_id_8616(node) -> int | None:
    dirty = getattr(node, "dirty", None)
    varid = getattr(dirty, "varid", None)
    if isinstance(varid, int):
        return varid
    if isinstance(node, structured_c.CVariable):
        for candidate in (getattr(node, "name", None), getattr(getattr(node, "variable", None), "name", None)):
            if not (isinstance(candidate, str) and candidate.startswith("vvar_")):
                continue
            try:
                return int(candidate.removeprefix("vvar_"), 10)
            except ValueError:
                return None
    return None


def _stack_probe_carrier_delta_8616(node, codegen) -> int | None:
    varid = _extract_vvar_id_8616(node)
    if not isinstance(varid, int):
        return None
    deltas = _ensure_vvar_carrier_delta_map_8616(codegen)
    return deltas.get(varid)


def _stack_offset_from_expr_8616(node, project, codegen, seen: set[int] | None = None) -> int | None:
    if seen is None:
        seen = set()
    node = _strip_casts_8616(node)
    node_id = id(node)
    offset_cache = getattr(codegen, "_inertia_stack_offset_cache", None)
    if not isinstance(offset_cache, dict):
        offset_cache = {}
        setattr(codegen, "_inertia_stack_offset_cache", offset_cache)

    if node_id in offset_cache:
        cached = offset_cache.get(node_id)
        if cached is _UNRESOLVED_STACK_OFFSET_8616:
            return None
        return cached

    if node_id in seen:
        offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
        return None
    if len(seen) > 8192:
        offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
        return None
    seen.add(node_id)

    const = _constant_value_8616(node)
    if const is not None:
        offset_cache[node_id] = const
        return const

    stack_base_bias = _stack_base_bp_bias_8616(node)
    if stack_base_bias is not None:
        offset_cache[node_id] = stack_base_bias
        return stack_base_bias

    if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
        operand = _strip_casts_8616(node.operand)
        variable = getattr(operand, "variable", None) if isinstance(operand, structured_c.CVariable) else None
        if isinstance(variable, SimStackVariable) and isinstance(getattr(variable, "offset", None), int):
            offset_cache[node_id] = variable.offset
            return variable.offset
        offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
        return None

    if isinstance(node, structured_c.CVariable):
        variable = getattr(node, "variable", None)
        if isinstance(variable, SimRegisterVariable):
            carrier_offset = _stack_pointer_carrier_offset_8616(node, project, codegen, seen)
            if carrier_offset is not None:
                offset_cache[node_id] = carrier_offset
                return carrier_offset
        rhs = _single_assignment_rhs_8616(codegen, node)
        if rhs is not None:
            resolved = _stack_offset_from_expr_8616(rhs, project, codegen, seen)
            offset_cache[node_id] = resolved
            return resolved
        # Fallback: try name-based lookup for virtual variables (vvar_*, tmp_*, ir_*)
        node_name = getattr(node, "name", None) or getattr(variable, "name", None)
        if isinstance(node_name, str) and (
            node_name.startswith("vvar_")
            or node_name.startswith("tmp_")
            or node_name.startswith("ir_")
        ):
            rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, node_name)
            if rhs is not None:
                resolved = _stack_offset_from_expr_8616(rhs, project, codegen, seen)
                offset_cache[node_id] = resolved
                return resolved
        # Fallback: try vvar carrier-delta resolution for ss << 4 + vvar patterns
        if isinstance(node_name, str) and node_name.startswith("vvar_"):
            delta = _stack_probe_carrier_delta_8616(node, codegen)
            if delta is not None:
                offset_cache[node_id] = delta
                return delta
        offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
        return None

    # CDirtyExpression: extract varid/name and try vvar resolution
    dirty = getattr(node, "dirty", None)
    if dirty is not None:
        varid = getattr(dirty, "varid", None)
        dirty_name = getattr(dirty, "name", None)
        _diag = {}
        if isinstance(varid, int):
            _diag["varid"] = varid
            target_name = f"vvar_{varid}"
            rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, target_name, allow_multi=True)
            if rhs is not None:
                resolved = _stack_offset_from_expr_8616(rhs, project, codegen, seen)
                if resolved is not None:
                    offset_cache[node_id] = resolved
                    return resolved
                _diag["rhs_found_but_unresolvable"] = True
            else:
                _diag["rhs_not_found"] = True
            delta = _stack_probe_carrier_delta_8616(node, codegen)
            if delta is not None:
                offset_cache[node_id] = delta
                return delta
            _diag["carrier_delta_none"] = True
        elif isinstance(dirty_name, str):
            _diag["dirty_name"] = dirty_name
            if dirty_name.startswith("vvar_") or dirty_name.startswith("tmp_") or dirty_name.startswith("ir_"):
                rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, dirty_name)
                if rhs is not None:
                    resolved = _stack_offset_from_expr_8616(rhs, project, codegen, seen)
                    if resolved is not None:
                        offset_cache[node_id] = resolved
                        return resolved
                    _diag["rhs_found_but_unresolvable"] = True
                else:
                    _diag["rhs_not_found"] = True
        else:
            _diag["no_varid_or_name"] = True
        # Try SP carrier
        carrier_offset = _stack_pointer_carrier_offset_8616(node, project, codegen, seen)
        if carrier_offset is not None:
            offset_cache[node_id] = carrier_offset
            return carrier_offset
        # Try BP base frame — BP is the canonical frame pointer (offset 0).
        dirty_reg = getattr(dirty, "reg", None)
        bp_reg, _bp_size = getattr(getattr(project, "arch", None), "registers", {}).get("bp", (None, None))
        if isinstance(dirty_reg, int) and isinstance(bp_reg, int) and dirty_reg == bp_reg:
            offset_cache[node_id] = 0
            return 0
        _diag["carrier_none"] = True
        _log_refusal_8616(codegen, "cdirty_diag", **_diag)
        offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
        return None

    dirty_carrier_offset = _stack_pointer_carrier_offset_8616(node, project, codegen, seen)
    if dirty_carrier_offset is not None:
        offset_cache[node_id] = dirty_carrier_offset
        return dirty_carrier_offset

    if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
        # In 16-bit AIL, direct stack_base arithmetic frequently carries
        # word-oriented displacements. Normalize them to byte offsets before
        # stack-slot matching so SS:BP materialization can occur early.
        if _is_stack_base_placeholder_8616(node.lhs):
            rhs_const = _constant_value_8616(node.rhs)
            if rhs_const is not None:
                base = _stack_base_bp_bias_8616(node.lhs) or 0
                scaled = int(rhs_const) * 2
                resolved_direct = base + (scaled if node.op == "Add" else -scaled)
                offset_cache[node_id] = resolved_direct
                return resolved_direct
        if node.op == "Add" and _is_stack_base_placeholder_8616(node.rhs):
            lhs_const = _constant_value_8616(node.lhs)
            if lhs_const is not None:
                base = _stack_base_bp_bias_8616(node.rhs) or 0
                resolved_direct = base + int(lhs_const) * 2
                offset_cache[node_id] = resolved_direct
                return resolved_direct
        lhs = _stack_offset_from_expr_8616(node.lhs, project, codegen, seen)
        rhs = _stack_offset_from_expr_8616(node.rhs, project, codegen, seen)
        if lhs is None and _constant_value_8616(node.rhs) is not None:
            offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
            return None
        if rhs is None and _constant_value_8616(node.lhs) is not None and node.op == "Add":
            offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
            return None
        if lhs is None or rhs is None:
            offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
            return None
        resolved = lhs + rhs if node.op == "Add" else lhs - rhs
        offset_cache[node_id] = resolved
        return resolved

    offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
    return None


def _log_refusal_8616(codegen, kind: str, /, **details: object) -> None:
    refusals = getattr(codegen, "_inertia_ss_lowering_refusal_log", None)
    if isinstance(refusals, list):
        refusals.append({"kind": kind, **{k: str(v) for k, v in details.items()}})


def match_stable_ss_linear_stack_access_8616(node, project, codegen) -> RealModeLinearStackAccess8616 | None:
    """Match a dereference of ``(ss << 4) + stack_offset`` with stack proof."""

    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        return None

    segment_name: str | None = None
    offset_total = 0
    offset_terms: list[object] = []
    terms = _flatten_signed_terms_8616(node.operand)
    if terms is None:
        return None
    for sign, term in terms:
        seg = _segment_base_name_8616(term, project)
        if seg is not None:
            if sign != 1 or segment_name is not None:
                return None
            segment_name = seg
            continue
        const = _constant_value_8616(term)
        if const is not None:
            offset_total += sign * const
            continue
        offset_terms.append(term if sign == 1 else structured_c.CBinaryOp("Sub", structured_c.CConstant(0, SimTypeInt(16, signed=False), codegen=codegen), term, codegen=codegen))

    if segment_name != "ss" or len(offset_terms) > 1:
        _log_refusal_8616(codegen, "segment_or_terms", segment=segment_name, terms=len(offset_terms))
        return None
    
    if len(offset_terms) == 0:
        base_offset = 0
    else:
        base_offset = _stack_offset_from_expr_8616(offset_terms[0], project, codegen)
        
    if base_offset is None:
        _log_refusal_8616(codegen, "offset_unresolved", segment=segment_name, offset_expr_type=type(offset_terms[0]).__name__ if offset_terms else "None", const_offset=offset_total)
        return None
    displacement = base_offset + offset_total
    width_bits = getattr(getattr(node, "type", None), "size", None)
    width = max(width_bits // 8, 1) if isinstance(width_bits, int) and width_bits > 0 else None
    region = getattr(getattr(codegen, "cfunc", None), "addr", None)
    facts = _stack_storage_facts_for_segmented_address_8616("ss", displacement, width, region=region)
    if facts is None or facts.identity is None:
        _log_refusal_8616(codegen, "no_stack_facts", displacement=displacement, width=width, region=region)
        return None
    return RealModeLinearStackAccess8616(displacement=displacement, width=width)


def match_stable_ds_es_linear_global_access_8616(node, project, codegen) -> RealModeLinearGlobalAddress8616 | None:
    """Match a dereference of ``(ds << 4) + addr`` or ``(es << 4) + addr``."""

    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        return None

    decomposed = _decompose_linear_global_terms_8616(node.operand, project)
    if decomposed is None:
        return None
    segment_name, displacement, residual_terms = decomposed

    if segment_name in {"ds", "es"}:
        width_bits = getattr(getattr(node, "type", None), "size", None)
        width = max(width_bits // 8, 1) if isinstance(width_bits, int) and width_bits > 0 else None
        if width is None:
            inferred_width = _global_size_from_displacement_8616(codegen, displacement)
            if isinstance(inferred_width, int) and inferred_width > 0:
                width = inferred_width
        return RealModeLinearGlobalAddress8616(
            segment_name=segment_name,
            displacement=displacement,
            residual_terms=tuple(residual_terms),
            width=width,
        )

    if segment_name is not None or not _global_displacement_known_8616(codegen, displacement):
        return None

    width_bits = getattr(getattr(node, "type", None), "size", None)
    width = max(width_bits // 8, 1) if isinstance(width_bits, int) and width_bits > 0 else None
    if width is None:
        inferred_width = _global_size_from_displacement_8616(codegen, displacement)
        if isinstance(inferred_width, int) and inferred_width > 0:
            width = inferred_width
    return RealModeLinearGlobalAddress8616(
        segment_name="segless",
        displacement=displacement,
        residual_terms=tuple(residual_terms),
        width=width,
    )


def _address_projection_term_is_safe_8616(node) -> bool:
    allowed_unary = {"Neg", "BitNot", "Reference"}
    allowed_binary = {"Add", "Sub", "Mul", "Shl", "Shr", "And", "Or", "Xor"}
    pending: list[object] = [_strip_casts_8616(node)]
    seen: set[int] = set()
    while pending:
        expr = _strip_casts_8616(pending.pop())
        if expr is None:
            return False
        expr_id = id(expr)
        if expr_id in seen:
            return False
        seen.add(expr_id)
        if _constant_value_8616(expr) is not None:
            continue
        if isinstance(expr, structured_c.CVariable):
            continue
        if isinstance(expr, structured_c.CUnaryOp) and expr.op in allowed_unary:
            pending.append(expr.operand)
            continue
        if isinstance(expr, structured_c.CBinaryOp) and expr.op in allowed_binary:
            pending.append(expr.rhs)
            pending.append(expr.lhs)
            continue
        return False
    return True


def match_stable_ds_es_linear_global_address_8616(node, project, codegen) -> RealModeLinearGlobalAddress8616 | None:
    """Match an address-valued ``(ds << 4) + base + projection`` expression."""

    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
        return None

    decomposed = _decompose_linear_global_terms_8616(node, project)
    if decomposed is None:
        return None
    segment_name, displacement, residual_terms = decomposed

    if segment_name in {"ds", "es"}:
        return RealModeLinearGlobalAddress8616(
            segment_name=segment_name,
            displacement=displacement,
            residual_terms=tuple(residual_terms),
            width=None,
        )

    if segment_name is not None or not _global_displacement_known_8616(codegen, displacement):
        return None
    return RealModeLinearGlobalAddress8616(
        segment_name="segless",
        displacement=displacement & 0xFFFF,
        residual_terms=tuple(residual_terms),
        width=None,
    )


def lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=None) -> bool:
    """Replace stable DS/ES real-mode linear dereferences with global variable references."""

    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False

    def global_cvar(access: RealModeLinearGlobalAddress8616):
        addr = access.displacement & 0xFFFF
        name = f"g_{addr:04X}"
        scalar_width = min(access.width or 1, 2)
        target_type = _type_for_access_width_8616(scalar_width)
        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable, cvar in tuple(variables_in_use.items()):
                if isinstance(variable, SimMemoryVariable) and getattr(variable, "addr", None) == addr:
                    existing_size = getattr(variable, "size", None)
                    if _cvar_has_array_type_8616(cvar) or (isinstance(existing_size, int) and existing_size > 2):
                        continue
                    if getattr(variable, "size", None) != scalar_width:
                        variable.size = scalar_width
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
                if isinstance(variable, SimVariable) and getattr(variable, "name", None) == name:
                    if _cvar_has_array_type_8616(cvar):
                        continue
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
                if isinstance(variable, SimStackVariable) and getattr(variable, "offset", None) == access.displacement:
                    replacement = SimMemoryVariable(
                        addr,
                        scalar_width,
                        name=name,
                        region=getattr(codegen.cfunc, "addr", None),
                    )
                    replacement_type = getattr(cvar, "variable_type", None) or target_type
                    replacement_cvar = structured_c.CVariable(replacement, variable_type=replacement_type, codegen=codegen)
                    variables_in_use.pop(variable, None)
                    variables_in_use[replacement] = replacement_cvar
                    unified = getattr(codegen.cfunc, "unified_local_vars", None)
                    if isinstance(unified, dict):
                        unified.pop(variable, None)
                        unified[replacement] = {
                            (replacement_cvar, getattr(replacement_cvar, "variable_type", None))
                        }
                    return replacement_cvar
        variable = SimMemoryVariable(addr, scalar_width, name=f"mem_{addr:04X}", region=getattr(codegen.cfunc, "addr", None))
        cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)
        if isinstance(variables_in_use, dict):
            variables_in_use[variable] = cvar
        unified = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
        return cvar

    def global_expr(access: RealModeLinearGlobalAddress8616):
        if not access.residual_terms:
            return global_cvar(access)
        target_type = _type_for_access_width_8616(access.width)
        ptr_type = SimTypePointer(target_type).with_arch(project.arch)
        rebuilt = structured_c.CUnaryOp(
            "Reference",
            global_cvar(access),
            codegen=codegen,
        )
        for sign, term in access.residual_terms:
            rebuilt = structured_c.CBinaryOp(
                "Add" if sign == 1 else "Sub",
                rebuilt,
                term,
                codegen=codegen,
            )
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(ptr_type, ptr_type, rebuilt, codegen=codegen),
            codegen=codegen,
        )

    changed = False

    def transform(node):
        nonlocal changed
        access = match_stable_ds_es_linear_global_access_8616(node, project, codegen)
        if access is not None:
            if access.residual_terms:
                return node
            changed = True
            return global_expr(access)
        return node

    _seen = set()

    def replace_children(root_node) -> bool:
        if root_node is None:
            return False
        node_stack: list[object] = [root_node]
        local_changed = False
        while node_stack:
            node = node_stack.pop()
            if not isinstance(node, object) or node is None:
                continue
            node_id = id(node)
            if node_id in _seen:
                continue
            _seen.add(node_id)

            for attr in ("statements", "lhs", "rhs", "operand", "expr", "init", "condition", "iteration", "body", "else_node"):
                if not hasattr(node, attr):
                    continue
                try:
                    value = getattr(node, attr)
                except Exception:
                    continue

                if isinstance(value, list):
                    for index, item in enumerate(tuple(value)):
                        if not isinstance(item, object):
                            continue
                        replacement = transform(item)
                        if replacement is not item:
                            value[index] = replacement
                            local_changed = True
                        candidate = value[index]
                        if isinstance(candidate, object):
                            node_stack.append(candidate)
                elif value is not None:
                    replacement = transform(value)
                    if replacement is not value:
                        setattr(node, attr, replacement)
                        local_changed = True
                        value = replacement
                    node_stack.append(value)

            condition_and_nodes = getattr(node, "condition_and_nodes", None)
            if condition_and_nodes:
                new_pairs = []
                pair_changed = False
                for cond, body in condition_and_nodes:
                    new_cond = transform(cond) if isinstance(cond, object) else cond
                    new_body = transform(body) if isinstance(body, object) else body
                    if new_cond is not cond:
                        pair_changed = True
                        local_changed = True
                    if new_body is not body:
                        pair_changed = True
                        local_changed = True
                    if isinstance(new_cond, object):
                        node_stack.append(new_cond)
                    if isinstance(new_body, object):
                        node_stack.append(new_body)
                    new_pairs.append((new_cond, new_body))
                if pair_changed:
                    setattr(node, "condition_and_nodes", new_pairs)
        return local_changed

    if replace_children(root):
        changed = True
    return changed


def lower_stable_ds_es_linear_global_addresses_8616(codegen, project=None) -> bool:
    """Replace stable DS/ES address-valued expressions with data-space object references."""

    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False

    def global_address_cvar(displacement: int):
        addr = displacement & 0xFFFF
        name = f"g_{addr:04X}"
        target_type = SimTypeChar(False)
        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable, cvar in tuple(variables_in_use.items()):
                if (
                    isinstance(variable, SimMemoryVariable)
                    and getattr(variable, "addr", None) == addr
                    and getattr(variable, "size", None) == 1
                ):
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
                if (
                    isinstance(variable, SimVariable)
                    and getattr(variable, "name", None) == name
                    and getattr(variable, "size", None) == 1
                ):
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
        variable = SimMemoryVariable(addr, 1, name=name, region=getattr(codegen.cfunc, "addr", None))
        cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)
        if isinstance(variables_in_use, dict):
            variables_in_use[variable] = cvar
        unified = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
        return cvar

    changed = False

    def _reference_expr(displacement: int):
        base_cvar = global_address_cvar(displacement)
        return structured_c.CUnaryOp(
            "Reference",
            base_cvar,
            codegen=codegen,
        )

    def transform(node):
        nonlocal changed
        access = match_stable_ds_es_linear_global_address_8616(node, project, codegen)
        if access is None:
            return node
        if access.residual_terms:
            return node
        base_expr = _reference_expr(access.displacement)
        rebuilt = base_expr
        for sign, term in access.residual_terms:
            rebuilt = structured_c.CBinaryOp(
                "Add" if sign == 1 else "Sub",
                rebuilt,
                term,
                codegen=codegen,
            )
        ptr_type = SimTypePointer(SimTypeChar(False)).with_arch(project.arch)
        changed = True
        return structured_c.CTypeCast(ptr_type, ptr_type, rebuilt, codegen=codegen)

    _seen: set[int] = set()

    def replace_children(root_node) -> bool:
        if root_node is None:
            return False
        node_stack: list[object] = [root_node]
        local_changed = False
        while node_stack:
            node = node_stack.pop()
            if node is None:
                continue
            node_id = id(node)
            if node_id in _seen:
                continue
            _seen.add(node_id)

            for attr in ("statements", "lhs", "rhs", "operand", "expr", "init", "condition", "iteration", "body", "else_node"):
                if not hasattr(node, attr):
                    continue
                try:
                    value = getattr(node, attr)
                except Exception:
                    continue
                if isinstance(value, list):
                    for index, item in enumerate(tuple(value)):
                        replacement = transform(item)
                        if replacement is not item:
                            value[index] = replacement
                            local_changed = True
                        item_candidate = value[index]
                        if item_candidate is not None:
                            node_stack.append(item_candidate)
                elif value is not None:
                    replacement = transform(value)
                    if replacement is not value:
                        setattr(node, attr, replacement)
                        local_changed = True
                        value = replacement
                    node_stack.append(value)

            condition_and_nodes = getattr(node, "condition_and_nodes", None)
            if condition_and_nodes:
                new_pairs = []
                pair_changed = False
                for cond, body in condition_and_nodes:
                    new_cond = transform(cond)
                    if new_cond is not cond:
                        pair_changed = True
                        local_changed = True
                    new_body = transform(body)
                    if new_body is not body:
                        pair_changed = True
                        local_changed = True
                    if new_cond is not None:
                        node_stack.append(new_cond)
                    if new_body is not None:
                        node_stack.append(new_body)
                    new_pairs.append((new_cond, new_body))
                if pair_changed:
                    setattr(node, "condition_and_nodes", new_pairs)
        return local_changed

    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_children(root):
        changed = True
    return changed


def lower_stable_ss_linear_stack_dereferences_8616(codegen, project=None) -> bool:
    """Replace stable SS real-mode linear dereferences with stack variables."""

    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False

    # Invalidate cached maps so they are rebuilt against current codegen state
    setattr(codegen, "_inertia_assignment_maps", None)
    setattr(codegen, "_inertia_vvar_carrier_deltas", None)
    setattr(codegen, "_inertia_stack_offset_cache", None)

    def _canonical_stack_offset_8616(offset):
        if not isinstance(offset, int):
            return offset
        if 0x8000 <= offset <= 0xFFFF:
            return offset - 0x10000
        return offset

    def stack_cvar(access: RealModeLinearStackAccess8616):
        displacement = _canonical_stack_offset_8616(access.displacement)
        target_type = _type_for_access_width_8616(access.width)
        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable, cvar in variables_in_use.items():
                if (
                    isinstance(variable, SimStackVariable)
                    and _canonical_stack_offset_8616(getattr(variable, "offset", None)) == displacement
                ):
                    requested_size = int(access.width or 1)
                    existing_size = getattr(variable, "size", None)
                    if not isinstance(existing_size, int) or existing_size < requested_size:
                        variable.size = requested_size
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
        variable = SimStackVariable(
            displacement,
            access.width or 1,
            base="bp",
            name=f"s_{displacement & 0xffff:x}",
            region=getattr(codegen.cfunc, "addr", None),
        )
        cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)
        if isinstance(variables_in_use, dict):
            variables_in_use[variable] = cvar
        unified = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
        return cvar

    changed = False

    def transform(node):
        nonlocal changed
        node = _strip_casts_8616(node)
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        access = match_stable_ss_linear_stack_access_8616(node, project, codegen)
        if access is not None:
            changed = True
            return stack_cvar(access)
        return node

    _node_count = [0]
    _seen = set()
    def replace_children(node) -> bool:
        if node is None or not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            return False
        _node_count[0] += 1
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE") and _node_count[0] % 500 == 0:
            print(f"[lower_ss_linear] tree walk: {_node_count[0]} nodes", file=sys.stderr, flush=True)
        if id(node) in _seen:
            return False
        _seen.add(id(node))
        local_changed = False
        for attr in ("statements", "lhs", "rhs", "operand", "expr", "init", "condition", "iteration", "body", "else_node"):
            if not hasattr(node, attr):
                continue
            value = getattr(node, attr)
            if isinstance(value, list):
                for index, item in enumerate(tuple(value)):
                    replacement = transform(item)
                    if replacement is not item:
                        value[index] = replacement
                        local_changed = True
                    if replace_children(value[index]):
                        local_changed = True
            elif value is not None:
                replacement = transform(value)
                if replacement is not value:
                    setattr(node, attr, replacement)
                    local_changed = True
                    value = replacement
                if replace_children(value):
                    local_changed = True
        return local_changed

    if replace_children(root):
        changed = True
    return changed


__all__ = (
    "RealModeLinearGlobalAddress8616",
    "RealModeLinearStackAccess8616",
    "lower_stable_ds_es_linear_global_addresses_8616",
    "lower_stable_ss_linear_stack_dereferences_8616",
    "lower_stable_ds_es_linear_global_dereferences_8616",
    "match_stable_ds_es_linear_global_address_8616",
    "match_stable_ss_linear_stack_access_8616",
    "match_stable_ds_es_linear_global_access_8616",
)
