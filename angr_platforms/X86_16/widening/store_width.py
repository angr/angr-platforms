from __future__ import annotations

# Layer: Widening
# Responsibility: typed store-width joins after alias compatibility proof.
# Forbidden: rendered-text adjacency as semantic proof.

import angr
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable


def _global_memory_addr(node) -> int | None:
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = getattr(variable, "addr", None)
    return addr if isinstance(addr, int) else None


def _global_load_addr(node, _project: angr.Project) -> int | None:
    return _global_memory_addr(node)


def _match_scaled_high_byte(node, project: angr.Project, *, c_constant_value, global_load_addr) -> int | None:
    if not isinstance(node, structured_c.CBinaryOp):
        return None

    if node.op == "Mul":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if c_constant_value(maybe_scale) != 0x100:
                continue
            addr = global_load_addr(maybe_load, project)
            if addr is not None:
                return addr

    if node.op == "Shl":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if c_constant_value(maybe_scale) != 8:
                continue
            addr = global_load_addr(maybe_load, project)
            if addr is not None:
                return addr

    return None


def _extract_dereference_addr_expr(node):
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        return None
    operand = node.operand
    if isinstance(operand, structured_c.CTypeCast):
        return operand.expr
    return operand


def _match_byte_load_addr_expr(node, *, unwrap_c_casts):
    addr_expr = _extract_dereference_addr_expr(node)
    if addr_expr is None:
        return None
    type_ = getattr(unwrap_c_casts(node), "type", None)
    bits = getattr(type_, "size", None)
    if bits not in {8, None}:
        return None
    return addr_expr


def _match_byte_store_addr_expr(node):
    addr_expr = _extract_dereference_addr_expr(node)
    if addr_expr is None:
        return None
    type_ = getattr(node, "type", None)
    bits = getattr(type_, "size", None)
    if bits not in {8, 16, None}:
        return None
    return addr_expr


def _match_shifted_high_byte_addr_expr(node, *, unwrap_c_casts, c_constant_value, match_byte_load_addr_expr):
    node = unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None

    if node.op == "Mul":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if c_constant_value(unwrap_c_casts(maybe_scale)) == 0x100:
                return match_byte_load_addr_expr(unwrap_c_casts(maybe_load))

    if node.op == "Shl":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if c_constant_value(unwrap_c_casts(maybe_scale)) == 8:
                return match_byte_load_addr_expr(unwrap_c_casts(maybe_load))

    return None


def _addr_exprs_are_same_or_byte_pair(
    low_addr_expr,
    high_addr_expr,
    project: angr.Project,
    *,
    addr_exprs_are_same,
    addr_exprs_are_byte_pair,
) -> tuple[bool, bool]:
    return (
        addr_exprs_are_same(low_addr_expr, high_addr_expr, project),
        addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project),
    )


def _match_word_pair_low_addr_expr(
    node,
    project: angr.Project,
    *,
    unwrap_c_casts,
    match_byte_load_addr_expr,
    match_shifted_high_byte_addr_expr,
    addr_exprs_are_byte_pair,
):
    node = unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
        return None

    for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        low_addr_expr = match_byte_load_addr_expr(unwrap_c_casts(low_expr))
        high_addr_expr = match_shifted_high_byte_addr_expr(high_expr)
        if low_addr_expr is None or high_addr_expr is None:
            continue
        if addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project):
            return low_addr_expr

    return None


def _make_word_dereference_from_addr_expr(codegen, project: angr.Project, addr_expr):
    word_type = SimTypeShort(False)
    ptr_type = SimTypePointer(word_type).with_arch(project.arch)
    return structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(None, ptr_type, addr_expr, codegen=codegen),
        codegen=codegen,
    )


def _match_word_dereference_addr_expr(node):
    addr_expr = _extract_dereference_addr_expr(node)
    if addr_expr is None:
        return None
    type_ = getattr(node, "type", None)
    bits = getattr(type_, "size", None)
    if bits != 16:
        return None
    return addr_expr


def _high_byte_store_addr(node, project: angr.Project, *, classify_segmented_dereference) -> int | None:
    classified = classify_segmented_dereference(node, project)
    if classified is None or classified.kind != "global":
        return None
    return classified.linear
