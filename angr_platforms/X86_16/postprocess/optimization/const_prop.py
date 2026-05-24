from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CITE,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeInt, SimTypeShort

from ...decompiler_postprocess_utils import _c_constant_value_8616


def _iter_c_statements_safe_8616(node):
    """Yield individual CStatements, descending into CStatements containers."""
    if isinstance(node, CStatements):
        for stmt in node.statements:
            yield from _iter_c_statements_safe_8616(stmt)
        return
    if isinstance(node, CStatements):
        for stmt in node.statements:
            yield stmt
        return
    if isinstance(node, (list, tuple)):
        for item in node:
            yield from _iter_c_statements_safe_8616(item)
        return
    yield node


# Default type for 86_16 constant folding: unsigned 16-bit int
_CONST_DEFAULT_TYPE = SimTypeInt(signed=False)

_CONST_PROP_BINARY_OPS = {
    "Add": lambda a, b: CConstant(a + b, _CONST_DEFAULT_TYPE),
    "Sub": lambda a, b: CConstant(a - b, _CONST_DEFAULT_TYPE),
    "Mul": lambda a, b: CConstant(a * b, _CONST_DEFAULT_TYPE),
    "And": lambda a, b: CConstant(a & b, _CONST_DEFAULT_TYPE),
    "Or": lambda a, b: CConstant(a | b, _CONST_DEFAULT_TYPE),
    "Xor": lambda a, b: CConstant(a ^ b, _CONST_DEFAULT_TYPE),
    "Shl": lambda a, b: CConstant(a << b, _CONST_DEFAULT_TYPE) if 0 <= b < 16 else None,
    "Shr": lambda a, b: CConstant(a >> b, _CONST_DEFAULT_TYPE) if 0 <= b < 16 else None,
    "Div": lambda a, b: CConstant(a // b, _CONST_DEFAULT_TYPE) if b != 0 else None,
}


def _is_const_expr(node) -> bool:
    if isinstance(node, CConstant):
        return True
    if isinstance(node, CBinaryOp):
        return _is_const_expr(node.lhs) and _is_const_expr(node.rhs)
    if isinstance(node, CUnaryOp) and node.op in ("Neg", "Not"):
        return _is_const_expr(node.operand)
    return False


def _eval_const_expr(node) -> int | None:
    if isinstance(node, CConstant):
        return _c_constant_value_8616(node)
    if isinstance(node, CBinaryOp):
        a = _eval_const_expr(node.lhs)
        b = _eval_const_expr(node.rhs)
        if a is None or b is None:
            return None
        fn = _CONST_PROP_BINARY_OPS.get(node.op)
        if fn is None:
            return None
        result = fn(a, b)
        return _c_constant_value_8616(result) if isinstance(result, CConstant) else None
    if isinstance(node, CUnaryOp):
        operand = _eval_const_expr(node.operand)
        if operand is None:
            return None
        if node.op == "Neg":
            return -operand
        if node.op == "Not":
            return int(not operand)
    return None


def _fold_constants_in_node(node) -> bool:
    """Fold constant sub-expressions in-place. Returns True if any folding occurred."""
    changed = False

    if isinstance(node, CBinaryOp):
        a_val = _eval_const_expr(node.lhs)
        b_val = _eval_const_expr(node.rhs)
        if a_val is not None and b_val is not None:
            fn = _CONST_PROP_BINARY_OPS.get(node.op)
            if fn is not None:
                result = fn(a_val, b_val)
                if isinstance(result, CConstant):
                    node.lhs = result
                    node.rhs = CConstant(0, _CONST_DEFAULT_TYPE)
                    node.op = "Add"
                    changed = True
                    return changed

        # Fold: X + 0 → X, X - 0 → X
        if isinstance(node.rhs, CConstant):
            rhs_val = _c_constant_value_8616(node.rhs)
            if rhs_val == 0 and node.op in ("Add", "Sub"):
                changed = True
                return changed

    if isinstance(node, CUnaryOp):
        operand_val = _eval_const_expr(node.operand)
        if operand_val is not None:
            if node.op == "Neg":
                result = CConstant(-operand_val, _CONST_DEFAULT_TYPE)
                node.operand = result
                changed = True
                return changed
            if node.op == "Not":
                result = CConstant(int(not operand_val), _CONST_DEFAULT_TYPE)
                node.operand = result
                changed = True
                return changed

    return changed


def _constant_propagation_8616(stmts, codegen=None):
    """Fold constant sub-expressions in C statements."""
    changed = False
    for stmt in _iter_c_statements_safe_8616(stmts):
        if _fold_constants_in_node(stmt):
            changed = True
    return changed