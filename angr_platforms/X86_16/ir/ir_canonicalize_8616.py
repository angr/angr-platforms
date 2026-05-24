from __future__ import annotations

# Layer: IR
# Responsibility: local algebraic normalization (lossless, preserves semantics).
# Equivalent to LLVM: tiny subset of InstCombine/Reassociate.
# Forbidden: cross-block propagation, variable merging, alias assumptions.

from dataclasses import dataclass
from typing import Any

__all__ = [
    "_ir_canonicalize_expr_8616",
    "canonicalize_expr_8616",
]


@dataclass(frozen=True)
class _ConstReassoc:
    terms: tuple[Any, ...]
    const: int


def canonicalize_expr_8616(expr: Any, *, max_rounds: int = 4) -> Any:
    """Canonicalize a local expression until fixed point."""
    current = expr
    for _ in range(max_rounds):
        new = _ir_canonicalize_expr_once_8616(current)
        if _same_c_expr_8616(new, current):
            return new
        current = new
    return current


def _ir_canonicalize_expr_8616(expr: Any) -> Any:
    """Backward-compatible public entry point."""
    return canonicalize_expr_8616(expr)


def _ir_canonicalize_expr_once_8616(expr: Any) -> Any:
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if not isinstance(expr, structured_c.CBinaryOp):
        return expr

    lhs = canonicalize_expr_8616(expr.lhs)
    rhs = canonicalize_expr_8616(expr.rhs)
    op = getattr(expr, "op", None)

    lhs_val = _c_constant_value(lhs)
    rhs_val = _c_constant_value(rhs)
    folded = _fold_binary_constants_8616(op, lhs_val, rhs_val, expr)
    if folded is not None:
        return folded

    if op in {"Add", "Sub"}:
        out = _canonicalize_add_sub_8616(lhs, rhs, op, expr)
        if out is not None:
            return out

    if op == "Mul":
        out = _canonicalize_mul_8616(lhs, rhs, expr)
        if out is not None:
            return out

    if op == "And":
        out = _canonicalize_bitwise_assoc_8616(lhs, rhs, "And", expr)
        if out is not None:
            return out

    if op == "Or":
        out = _canonicalize_bitwise_assoc_8616(lhs, rhs, "Or", expr)
        if out is not None:
            return out

    if op == "Xor":
        out = _canonicalize_xor_8616(lhs, rhs, expr)
        if out is not None:
            return out

    if op == "Shl" and rhs_val == 0:
        return lhs
    if op in {"Shr", "Sar"} and rhs_val == 0:
        return lhs

    return _rebuild_binary_8616(expr, op, lhs, rhs)


def _canonicalize_add_sub_8616(lhs: Any, rhs: Any, op: str, template: Any) -> Any | None:
    rhs_val = _c_constant_value(rhs)
    lhs_val = _c_constant_value(lhs)

    if op == "Add" and rhs_val == 0:
        return lhs
    if op == "Add" and lhs_val == 0:
        return rhs
    if op == "Sub" and rhs_val == 0:
        return lhs
    if op == "Sub" and _same_c_expr_8616(lhs, rhs):
        return _make_const_8616(0, template)

    flattened = _flatten_add_sub_8616(lhs, rhs, op)
    if flattened is None:
        return None

    terms, const = flattened.terms, flattened.const

    if not terms:
        return _make_const_8616(const, template)

    base = _rebuild_left_assoc_8616(terms, "Add", template)

    if const == 0:
        return base
    if const > 0:
        return _make_binop_8616("Add", base, _make_const_8616(const, template), template)
    return _make_binop_8616("Sub", base, _make_const_8616(-const, template), template)


def _flatten_add_sub_8616(lhs: Any, rhs: Any, op: str) -> _ConstReassoc | None:
    terms: list[Any] = []
    const = 0

    def walk(node: Any, sign: int) -> None:
        nonlocal const
        value = _c_constant_value(node)
        if isinstance(value, int):
            const += sign * value
            return

        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if isinstance(node, structured_c.CBinaryOp):
            node_op = getattr(node, "op", None)
            if node_op == "Add":
                walk(node.lhs, sign)
                walk(node.rhs, sign)
                return
            if node_op == "Sub":
                walk(node.lhs, sign)
                walk(node.rhs, -sign)
                return

        if sign == 1:
            terms.append(node)
        else:
            terms.append(_make_binop_8616("Sub", _make_const_8616(0, node), node, node))

    walk(lhs, 1)
    walk(rhs, 1 if op == "Add" else -1)

    return _ConstReassoc(tuple(terms), const)


def _canonicalize_mul_8616(lhs: Any, rhs: Any, template: Any) -> Any | None:
    lhs_val = _c_constant_value(lhs)
    rhs_val = _c_constant_value(rhs)

    if rhs_val == 1:
        return lhs
    if lhs_val == 1:
        return rhs
    if rhs_val == 0 or lhs_val == 0:
        return _make_const_8616(0, template)

    terms: list[Any] = []
    const = 1

    def walk(node: Any) -> None:
        nonlocal const
        value = _c_constant_value(node)
        if isinstance(value, int):
            const *= value
            return

        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if isinstance(node, structured_c.CBinaryOp) and getattr(node, "op", None) == "Mul":
            walk(node.lhs)
            walk(node.rhs)
            return

        terms.append(node)

    walk(lhs)
    walk(rhs)

    if const == 0:
        return _make_const_8616(0, template)

    if not terms:
        return _make_const_8616(const, template)

    base = _rebuild_left_assoc_8616(tuple(terms), "Mul", template)

    if const == 1:
        return base
    return _make_binop_8616("Mul", base, _make_const_8616(const, template), template)


def _canonicalize_bitwise_assoc_8616(lhs: Any, rhs: Any, op: str, template: Any) -> Any | None:
    lhs_val = _c_constant_value(lhs)
    rhs_val = _c_constant_value(rhs)

    if op == "And":
        if rhs_val in {-1, 0xFFFF, 0xFFFFFFFF}:
            return lhs
        if lhs_val in {-1, 0xFFFF, 0xFFFFFFFF}:
            return rhs
        if rhs_val == 0 or lhs_val == 0:
            return _make_const_8616(0, template)

    if op == "Or":
        if rhs_val == 0:
            return lhs
        if lhs_val == 0:
            return rhs

    terms: list[Any] = []
    const: int | None = None

    def combine(a: int, b: int) -> int:
        if op == "And":
            return a & b
        if op == "Or":
            return a | b
        raise AssertionError(op)

    def walk(node: Any) -> None:
        nonlocal const
        value = _c_constant_value(node)
        if isinstance(value, int):
            const = value if const is None else combine(const, value)
            return

        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if isinstance(node, structured_c.CBinaryOp) and getattr(node, "op", None) == op:
            walk(node.lhs)
            walk(node.rhs)
            return

        terms.append(node)

    walk(lhs)
    walk(rhs)

    if const is None:
        return None

    if op == "And" and const == 0:
        return _make_const_8616(0, template)

    if not terms:
        return _make_const_8616(const, template)

    base = _rebuild_left_assoc_8616(tuple(terms), op, template)

    if op == "Or" and const == 0:
        return base
    if op == "And" and const in {-1, 0xFFFF, 0xFFFFFFFF}:
        return base

    return _make_binop_8616(op, base, _make_const_8616(const, template), template)


def _canonicalize_xor_8616(lhs: Any, rhs: Any, template: Any) -> Any | None:
    lhs_val = _c_constant_value(lhs)
    rhs_val = _c_constant_value(rhs)

    if rhs_val == 0:
        return lhs
    if lhs_val == 0:
        return rhs
    if _same_c_expr_8616(lhs, rhs):
        return _make_const_8616(0, template)

    terms: list[Any] = []
    const = 0

    def walk(node: Any) -> None:
        nonlocal const
        value = _c_constant_value(node)
        if isinstance(value, int):
            const ^= value
            return

        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if isinstance(node, structured_c.CBinaryOp) and getattr(node, "op", None) == "Xor":
            walk(node.lhs)
            walk(node.rhs)
            return

        for idx, existing in enumerate(terms):
            if _same_c_expr_8616(existing, node):
                del terms[idx]
                return
        terms.append(node)

    walk(lhs)
    walk(rhs)

    if not terms:
        return _make_const_8616(const, template)

    base = _rebuild_left_assoc_8616(tuple(terms), "Xor", template)

    if const == 0:
        return base

    return _make_binop_8616("Xor", base, _make_const_8616(const, template), template)


def _fold_binary_constants_8616(op: str, lhs_val: int | None, rhs_val: int | None, template: Any) -> Any | None:
    if not isinstance(lhs_val, int) or not isinstance(rhs_val, int):
        return None

    try:
        if op == "Add":
            value = lhs_val + rhs_val
        elif op == "Sub":
            value = lhs_val - rhs_val
        elif op == "Mul":
            value = lhs_val * rhs_val
        elif op == "And":
            value = lhs_val & rhs_val
        elif op == "Or":
            value = lhs_val | rhs_val
        elif op == "Xor":
            value = lhs_val ^ rhs_val
        elif op == "Shl":
            value = lhs_val << rhs_val
        elif op in {"Shr", "Sar"}:
            if rhs_val < 0:
                return None
            value = lhs_val >> rhs_val
        elif op in {"Div", "Mod"}:
            if rhs_val == 0:
                return None
            value = lhs_val // rhs_val if op == "Div" else lhs_val % rhs_val
        else:
            return None
    except Exception:
        return None

    return _make_const_8616(value, template)


def _rebuild_left_assoc_8616(terms: tuple[Any, ...], op: str, template: Any) -> Any:
    if not terms:
        return _make_const_8616(0, template)

    current = terms[0]
    for term in terms[1:]:
        current = _make_binop_8616(op, current, term, template)
    return current


def _make_binop_8616(op: str, lhs: Any, rhs: Any, template: Any) -> Any:
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    return structured_c.CBinaryOp(
        op,
        lhs,
        rhs,
        codegen=getattr(template, "codegen", None),
    )


def _rebuild_binary_8616(template: Any, op: str, lhs: Any, rhs: Any) -> Any:
    if lhs is getattr(template, "lhs", None) and rhs is getattr(template, "rhs", None):
        return template
    return _make_binop_8616(op, lhs, rhs, template)


def _make_const_8616(value: int, template: Any | None = None) -> Any:
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    from angr.sim_type import SimTypeInt
    type_ = getattr(template, "type", None)
    if type_ is None:
        type_ = SimTypeInt(signed=False, label="int")

    return structured_c.CConstant(
        value,
        type_,
        codegen=getattr(template, "codegen", None),
    )


def _c_constant_value(expr: Any) -> int | None:
    value = getattr(expr, "value", None)
    if isinstance(value, int):
        return value

    value = getattr(expr, "constant", None)
    if isinstance(value, int):
        return value

    return None


def _same_c_expr_8616(lhs: Any, rhs: Any) -> bool:
    if lhs is rhs:
        return True
    if type(lhs) is not type(rhs):
        return False

    if _c_constant_value(lhs) is not None or _c_constant_value(rhs) is not None:
        return _c_constant_value(lhs) == _c_constant_value(rhs)

    return repr(lhs) == repr(rhs)
