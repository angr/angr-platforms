from __future__ import annotations

"""Layer: Structuring
Responsibility: render ConditionIR to C-like strings.

AGENTS rule: No flag-based conditions, no tmp-based conditions.
If signedness cannot be expressed safely in C, use explicit helper form
(e.g. ``s16_lt(lhs, rhs)``, ``u16_lt(lhs, rhs)``).
"""

from ..ir.condition_ir import ConditionIR, ConditionFailure


def render_condition_ir_8616(cond: ConditionIR) -> str | None:
    """Render a ConditionIR to a C-like condition string.

    Returns None if the condition cannot be rendered (unhandled op).
    """
    lhs_str = _format_operand(cond.lhs)
    rhs_str = _format_operand(cond.rhs) if cond.rhs is not None else None

    op = cond.op

    if op == "zero":
        return f"{lhs_str} == 0"
    if op == "nonzero":
        return f"{lhs_str} != 0"

    if op == "eq":
        return f"{lhs_str} == {rhs_str}"
    if op == "ne":
        return f"{lhs_str} != {rhs_str}"

    # Signed comparisons — emit explicit helper if signedness not type-proven
    if op == "slt":
        return f"s16_lt({lhs_str}, {rhs_str})"
    if op == "sle":
        return f"s16_le({lhs_str}, {rhs_str})"
    if op == "sgt":
        return f"s16_gt({lhs_str}, {rhs_str})"
    if op == "sge":
        return f"s16_ge({lhs_str}, {rhs_str})"

    # Unsigned comparisons
    if op == "ult":
        return f"u16_lt({lhs_str}, {rhs_str})"
    if op == "ule":
        return f"u16_le({lhs_str}, {rhs_str})"
    if op == "ugt":
        return f"u16_gt({lhs_str}, {rhs_str})"
    if op == "uge":
        return f"u16_ge({lhs_str}, {rhs_str})"

    return None


def render_condition_ir_native_8616(cond: ConditionIR) -> str | None:
    """Render using native C operators (when unsigned/signed semantics are safe).

    This is for use when type analysis has proven signedness.
    """
    lhs_str = _format_operand(cond.lhs)
    rhs_str = _format_operand(cond.rhs) if cond.rhs is not None else None

    op = cond.op

    if op == "zero":
        return f"{lhs_str} == 0"
    if op == "nonzero":
        return f"{lhs_str} != 0"
    if op == "eq":
        return f"{lhs_str} == {rhs_str}"
    if op == "ne":
        return f"{lhs_str} != {rhs_str}"

    _CMP_SYMBOLS = {
        "eq": "==",
        "ne": "!=",
        "slt": "<",
        "sle": "<=",
        "sgt": ">",
        "sge": ">=",
        "ult": "<",
        "ule": "<=",
        "ugt": ">",
        "uge": ">=",
    }

    sym = _CMP_SYMBOLS.get(op)
    if sym and rhs_str is not None:
        return f"{lhs_str} {sym} {rhs_str}"

    return None


def _format_operand(value) -> str:
    """Format an operand value to a string representation."""
    if value is None:
        return "0"
    if isinstance(value, int):
        if value >= 0:
            return f"0x{value:x}"
        return str(value)
    if hasattr(value, "to_dict"):
        d = value.to_dict()
        if d.get("space") == "reg" and d.get("name"):
            return str(d["name"])
        if d.get("space") == "const" and d.get("const") is not None:
            return str(d["const"])
        return str(d)
    return str(value)