from __future__ import annotations

"""Layer: Semantics (condition/flag reasoning).

Condition strengthening: canonicalize comparison expressions.
Extends the canonicalizations from condition_ir.py with loop-specific patterns.

Forbidden: text matching, asm/C regex, postprocess ownership."""

__all__ = [
    "_strengthen_condition_8616",
    "_canonicalize_cmp_sub_8616",
]


def _is_const_expr(expr: object) -> bool:
    """Check if expression is a constant."""
    return hasattr(expr, "value") and isinstance(getattr(expr, "value"), int)


def _get_const_val(expr: object) -> int | None:
    """Extract constant int value or None."""
    if _is_const_expr(expr):
        return int(getattr(expr, "value"))
    return None


def _canonicalize_cmp_sub_8616(cond: object) -> object | None:
    """Canonicalize CMP-SUB patterns to direct comparisons.

    CmpLT(Sub(x, N), 0)  → CmpLT(x, N)
    CmpGE(Sub(x, N), 0)  → CmpGE(x, N)
    CmpGT(Sub(x, N), 0)  → CmpGT(x, N)
    CmpLE(Sub(x, N), 0)  → CmpLE(x, N)
    CmpLT(Sub(x, y), 0)  → CmpLT(x, y)   [reg-to-reg, no constant needed]
    CmpGE(Sub(x, y), 0)  → CmpGE(x, y)

    Returns the strengthened condition node or None.
    """
    if cond is None:
        return None

    op = getattr(cond, "op", None)
    # Get operands via either attribute naming convention
    left = getattr(cond, "left", None) or getattr(cond, "lhs", None)
    right = getattr(cond, "right", None) or getattr(cond, "rhs", None)
    if op is None or left is None or right is None:
        return None

    # Only fire when comparing against zero
    right_val = _get_const_val(right)
    if right_val != 0:
        return None

    op_str = str(op).upper()
    # Only for comparison operators
    if op_str not in ("LT", "LE", "GT", "GE", "EQ", "NE"):
        return None

    # Check if left is Sub(x, N) or Sub(x, y)
    left_op = getattr(left, "op", None)
    if str(left_op) != "Sub":
        return None

    sub_left = getattr(left, "left", None) or getattr(left, "lhs", None)
    sub_right = getattr(left, "right", None) or getattr(left, "rhs", None)
    if sub_left is None or sub_right is None:
        return None

    # Build strengthened comparison: CmpOP(x, N) or CmpOP(x, y)
    cn = type(left) if hasattr(type(left), 'left') else type(cond)

    return type(cond)(
        left=sub_left,
        right=sub_right,
        op=op_str,
    )


def _strengthen_condition_8616(cond: object) -> object | None:
    """Apply all condition strengthening transforms.

    Returns strengthened condition or None if no transform applied.
    """
    # Try CMP-SUB canonicalization first
    result = _canonicalize_cmp_sub_8616(cond)
    if result is not None:
        return result
    return None