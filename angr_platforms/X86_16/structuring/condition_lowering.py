from __future__ import annotations

# Layer: Structuring
# Responsibility: lower typed IRCondition objects into structured-codegen C condition nodes.
# Forbidden: semantic recovery ownership, text-pattern semantics.

from typing import TYPE_CHECKING

from ..ir.core import IRCondition, IRValue, MemSpace
from ..ir.condition_ir import (
    ConditionOp,
    condition_compare_symbol_8616,
    is_condition_compare_family_8616,
    is_condition_truth_test_8616,
    is_signed_condition_8616,
)

if TYPE_CHECKING:
    from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CUnaryOp, CVariable

__all__ = [
    "lower_typed_condition_to_c_expr_8616",
    "condition_op_to_structured_kind_8616",
]


def _make_c_constant_8616(value: int, codegen, signed: bool = False) -> "CConstant":
    """Create a structured-codegen CConstant node."""
    from angr.analyses.decompiler.structured_codegen.c import CConstant
    from angr.sim_type import SimTypeShort

    return CConstant(int(value), SimTypeShort(signed), codegen=codegen)


def _ir_value_to_cvar_8616(value: IRValue, project, codegen) -> "CVariable":
    """Convert an IRValue to a CVariable node for structured codegen."""
    from angr.analyses.decompiler.structured_codegen.c import CVariable
    from angr.sim_variable import SimRegisterVariable, SimStackVariable

    if value.space == MemSpace.CONST:
        return _make_c_constant_8616(int(value.const or 0), codegen)

    if value.space == MemSpace.REG:
        var = SimRegisterVariable(reg=value.offset, size=value.size or 2)
        return CVariable(variable=var, codegen=codegen)

    if value.space == MemSpace.SS:
        var = SimStackVariable(offset=value.offset, size=value.size or 2, base="bp")
        return CVariable(variable=var, codegen=codegen)

    # Fallback: unnamed register variable
    var = SimRegisterVariable(reg=0, size=value.size or 2)
    return CVariable(variable=var, codegen=codegen)


def lower_typed_condition_to_c_expr_8616(
    recovered: object,  # RecoveredCondition
    project,
    codegen,
) -> object | None:
    """Convert a RecoveredCondition into a structured-codegen C expression node.

    Returns a CBinaryOp (for comparisons) or CUnaryOp (for Not) node, or None.
    """
    from ..semantics.condition_recovery import RecoveredCondition

    if not isinstance(recovered, RecoveredCondition):
        return None

    condition = recovered.condition
    return _lower_condition_ir_to_c_expr_8616(condition, project, codegen)


def _lower_condition_ir_to_c_expr_8616(
    condition: IRCondition,
    project,
    codegen,
) -> object | None:
    """Lower a typed IRCondition to a structured-codegen C expression."""
    from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CUnaryOp

    op = condition.op

    # Zero/nonzero tests
    if op == "zero":
        if not condition.args:
            return None
        lhs = _ir_value_to_cvar_8616(condition.args[0], project, codegen)
        zero = _make_c_constant_8616(0, codegen)
        return CBinaryOp("CmpEQ", lhs, zero, codegen=codegen)

    if op == "nonzero":
        if not condition.args:
            return None
        lhs = _ir_value_to_cvar_8616(condition.args[0], project, codegen)
        zero = _make_c_constant_8616(0, codegen)
        return CBinaryOp("CmpNE", lhs, zero, codegen=codegen)

    # Binary comparisons
    if is_condition_compare_family_8616(op) and len(condition.args) >= 2:
        sym = condition_compare_symbol_8616(op)
        if sym is None:
            return None
        lhs = _ir_value_to_cvar_8616(condition.args[0], project, codegen)
        rhs = _ir_value_to_cvar_8616(condition.args[1], project, codegen)
        # Map to angr structured-codegen CBinaryOp operator names
        angr_op = _condition_ir_op_to_angr_binary_op_8616(sym)
        if angr_op is None:
            return None
        return CBinaryOp(angr_op, lhs, rhs, codegen=codegen)

    # Not
    if op == "not" and len(condition.args) >= 1:
        inner = condition.args[0]
        if isinstance(inner, IRCondition):
            inner_expr = _lower_condition_ir_to_c_expr_8616(inner, project, codegen)
            if inner_expr is not None:
                return CUnaryOp("Not", inner_expr, codegen=codegen)
        return None

    # Compare (generic)
    if op == "compare" and len(condition.args) >= 2:
        lhs = _ir_value_to_cvar_8616(condition.args[0], project, codegen)
        rhs = _ir_value_to_cvar_8616(condition.args[1], project, codegen)
        return CBinaryOp("CmpNE", lhs, rhs, codegen=codegen)

    return None


def condition_op_to_structured_kind_8616(op: str) -> str:
    """Map a ConditionOp to the kind string used in structured-codegen node kinds."""
    if op == "zero":
        return "CmpEQ"
    if op == "nonzero":
        return "CmpNE"
    if op in {"eq", "ne"}:
        return f"Cmp{op.upper()}"
    if op in {"slt", "ult"}:
        return "CmpLT"
    if op in {"sgt", "ugt"}:
        return "CmpGT"
    if op in {"sle", "ule"}:
        return "CmpLE"
    if op in {"sge", "uge"}:
        return "CmpGE"
    return "CmpNE"


_ANGr_BINARY_OP_MAP_8616: dict[str, str] = {
    "==": "CmpEQ",
    "!=": "CmpNE",
    "<": "CmpLT",
    ">": "CmpGT",
    "<=": "CmpLE",
    ">=": "CmpGE",
}


def _condition_ir_op_to_angr_binary_op_8616(symbol: str) -> str | None:
    """Map a condition op symbol ('==', '!=' etc.) to angr CBinaryOp operator name."""
    return _ANGr_BINARY_OP_MAP_8616.get(symbol)