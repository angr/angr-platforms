from __future__ import annotations

# Layer: Semantics
# Responsibility: recover typed IRCondition objects from x86-16 flag/test instruction patterns.
# Forbidden: text-pattern semantics, CLI formatting, postprocess cleanup ownership.

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CVariable, CUnaryOp

from ..ir.core import IRCondition, IRValue, MemSpace
from ..ir.condition_ir import (
    ConditionOp,
    _JCC_COMPARISON_MNEMONICS_8616,
    JCC_EQ_MNEMONICS_8616,
    JCC_NE_MNEMONICS_8616,
    JCC_SGE_MNEMONICS_8616,
    JCC_SGT_MNEMONICS_8616,
    JCC_SLE_MNEMONICS_8616,
    JCC_SLT_MNEMONICS_8616,
    JCC_UGE_MNEMONICS_8616,
    JCC_UGT_MNEMONICS_8616,
    JCC_ULE_MNEMONICS_8616,
    JCC_ULT_MNEMONICS_8616,
    build_condition_ir_8616,
    harmonize_condition_args_8616,
    normalize_condition_op_8616,
)

__all__ = [
    "ConditionConfidence",
    "RecoveredCondition",
    "classify_flag_mask_bit_8616",
    "build_typed_condition_from_flag_mask_8616",
    "build_typed_condition_from_cmp_pair_8616",
    "build_typed_condition_from_test_self_8616",
]

_FLAG_CF = 0x1
_FLAG_ZF = 0x40
_FLAG_SF = 0x80
_FLAG_OF = 0x800


class ConditionConfidence(Enum):
    """How certain we are about a recovered condition."""

    PROVEN = "proven"
    LIKELY = "likely"
    GUESSED = "guessed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class RecoveredCondition:
    """A typed condition recovered from instruction evidence."""

    condition: IRCondition
    confidence: ConditionConfidence = ConditionConfidence.PROVEN
    signed: bool = False
    operand_count: int = 2

    @property
    def is_proven(self) -> bool:
        return self.confidence == ConditionConfidence.PROVEN

    @property
    def is_likely(self) -> bool:
        return self.confidence in {ConditionConfidence.PROVEN, ConditionConfidence.LIKELY}


def _ir_value_from_vex_expr(expr, size_hint: int = 0) -> IRValue:
    """Best-effort conversion of a VEX-style expression operand into IRValue."""
    if expr is None:
        return IRValue(MemSpace.UNKNOWN, size=size_hint or 1)

    # Integer constants
    if isinstance(expr, int):
        return IRValue(MemSpace.CONST, const=expr, size=size_hint or _size_for_int(expr))

    # VEX constant: has .value attribute
    const_value = getattr(expr, "value", None)
    if isinstance(const_value, int):
        return IRValue(MemSpace.CONST, const=const_value, size=size_hint or _size_for_int(const_value))

    # Register operand: has .reg or .reg_name
    reg_offset = getattr(expr, "reg", None)
    reg_name = getattr(expr, "reg_name", None)
    if isinstance(reg_offset, int):
        return IRValue(MemSpace.REG, name=str(reg_name or f"reg_{reg_offset}"), offset=reg_offset, size=size_hint or 2)

    # Generic tmp
    return IRValue(MemSpace.TMP, name=getattr(expr, "__class__", type(expr)).__name__, size=size_hint or 2)


def _size_for_int(value: int) -> int:
    """Determine byte size for a constant integer."""
    abs_val = abs(value)
    if abs_val < 256:
        return 1
    if abs_val < 65536:
        return 2
    return 4


def _c_constant_int_value_8616(node) -> int | None:
    """Extract integer value from a structured-codegen CConstant node."""
    if node is None:
        return None
    cls_name = type(node).__name__
    if cls_name != "CConstant":
        return None
    value = getattr(node, "value", None)
    if isinstance(value, int):
        return value
    return None


def _c_variable_register_name_8616(node) -> str | None:
    """Extract register name from a CVariable or its nested variable attribute."""
    if node is None:
        return None
    cls_name = type(node).__name__
    if cls_name != "CVariable":
        return None
    variable = None
    for attr in ("variable", "unified_variable"):
        candidate = getattr(node, attr, None)
        cls = type(candidate).__name__ if candidate is not None else ""
        if cls == "SimRegisterVariable":
            variable = candidate
            break
    if variable is None:
        return None
    # Try to get register name from project context or from variable reg offset
    reg_offset = getattr(variable, "reg", None)
    if isinstance(reg_offset, int):
        return f"reg_{reg_offset}"
    return getattr(variable, "name", None)


def classify_flag_mask_bit_8616(mask: int) -> tuple[str | None, int | None]:
    """Classify a flag bitmask into (flag_name, bit_value)."""
    if mask & _FLAG_ZF:
        return "ZF", mask
    if mask & _FLAG_CF:
        return "CF", mask
    if mask & _FLAG_SF:
        return "SF", mask
    if mask & _FLAG_OF:
        return "OF", mask
    return None, None


def build_typed_condition_from_flag_mask_8616(
    flag_var,
    mask: int,
    negate: bool,
    *,
    operands: tuple | None = None,
) -> RecoveredCondition | None:
    """Recover a typed condition from a flag mask test like ``(flags & ZF) != 0``.

    Args:
        flag_var: The flag variable node (CVariable or IRValue)
        mask: The flag bitmask value
        negate: Whether the test is negated (result is inverted)
        operands: Optional (lhs, rhs) operands when the condition should be a comparison

    Returns:
        RecoveredCondition or None if recovery fails
    """
    flag_name, _ = classify_flag_mask_bit_8616(mask)
    if flag_name is None:
        return None

    if operands is not None and len(operands) == 2:
        lhs, rhs = operands
        lhs_val = _ir_value_from_vex_expr(lhs) if not isinstance(lhs, IRValue) else lhs
        rhs_val = _ir_value_from_vex_expr(rhs) if not isinstance(rhs, IRValue) else rhs
        lhs_val, rhs_val = harmonize_condition_args_8616(lhs_val, rhs_val)

        if flag_name == "ZF":
            kind: ConditionOp = "ne" if negate else "eq"
            return RecoveredCondition(
                build_condition_ir_8616(kind, lhs_val, rhs_val, expr=("flag_mask", flag_name)),
                confidence=ConditionConfidence.PROVEN,
            )
        if flag_name == "CF":
            kind = "ult" if negate else "uge"
            return RecoveredCondition(
                build_condition_ir_8616(kind, lhs_val, rhs_val, expr=("flag_mask", flag_name)),
                confidence=ConditionConfidence.PROVEN,
            )
        if flag_name == "SF":
            kind = "slt" if negate else "sge"
            return RecoveredCondition(
                build_condition_ir_8616(kind, lhs_val, rhs_val, expr=("flag_mask", flag_name)),
                confidence=ConditionConfidence.PROVEN,
            )
        if flag_name == "OF":
            return RecoveredCondition(
                build_condition_ir_8616("compare", lhs_val, rhs_val, expr=("flag_mask", flag_name)),
                confidence=ConditionConfidence.LIKELY,
            )

    # Single-operand: zero/nonzero test
    if operands is not None and len(operands) == 1:
        (operand,) = operands
        op_val = _ir_value_from_vex_expr(operand) if not isinstance(operand, IRValue) else operand
        if flag_name == "ZF":
            return RecoveredCondition(
                build_condition_ir_8616("nonzero" if negate else "zero", op_val, expr=("flag_mask", flag_name)),
                confidence=ConditionConfidence.PROVEN,
            )
        return RecoveredCondition(
            build_condition_ir_8616("nonzero" if negate else "zero", op_val, expr=("flag_mask", flag_name)),
            confidence=ConditionConfidence.LIKELY,
        )

    return None


def build_typed_condition_from_cmp_pair_8616(
    lhs_node,
    rhs_node,
    *,
    jcc_mnemonic: str | None = None,
) -> RecoveredCondition | None:
    """Recover a typed condition from a CMP-style pair of operands.

    Handles: ``cmp reg, reg``, ``cmp reg, imm``, ``test reg, reg``, ``or reg, reg``.

    If a JCC mnemonic is provided, uses it to resolve signed vs unsigned comparison.
    """
    lhs_val = _ir_value_from_vex_expr(lhs_node)
    rhs_val = _ir_value_from_vex_expr(rhs_node)

    # Detect TEST/OR self pattern: same operand compared to itself
    if _same_operand_test_8616(lhs_node, rhs_node):
        return RecoveredCondition(
            build_condition_ir_8616("nonzero", lhs_val, expr=("test_self",)),
            confidence=ConditionConfidence.PROVEN,
        )

    # Detect zero comparison: cmp reg, 0
    if isinstance(rhs_val.const, int) and rhs_val.const == 0:
        if jcc_mnemonic:
            op = _jcc_to_condition_op_with_zero_8616(jcc_mnemonic, lhs_val, rhs_val)
        else:
            op = _jcc_to_condition_op_8616(jcc_mnemonic, lhs_val, rhs_val)
        return RecoveredCondition(
            build_condition_ir_8616(op, lhs_val, rhs_val, expr=("cmp_zero",)),
            confidence=ConditionConfidence.PROVEN,
        )

    lhs_val, rhs_val = harmonize_condition_args_8616(lhs_val, rhs_val)
    op = _jcc_to_condition_op_8616(jcc_mnemonic, lhs_val, rhs_val)
    return RecoveredCondition(
        build_condition_ir_8616(op, lhs_val, rhs_val, expr=("cmp",)),
        confidence=ConditionConfidence.PROVEN,
    )


def build_typed_condition_from_test_self_8616(operand) -> RecoveredCondition | None:
    """Recover a nonzero test from a TEST/OR self pattern."""
    op_val = _ir_value_from_vex_expr(operand)
    if op_val.space == MemSpace.UNKNOWN:
        return None
    return RecoveredCondition(
        build_condition_ir_8616("nonzero", op_val, expr=("test_self",)),
        confidence=ConditionConfidence.LIKELY,
    )


def _same_operand_test_8616(lhs, rhs) -> bool:
    """Check if two operands represent the same register (test/or self)."""
    lhs_reg = getattr(lhs, "reg", None)
    rhs_reg = getattr(rhs, "reg", None)
    if isinstance(lhs_reg, int) and isinstance(rhs_reg, int):
        return lhs_reg == rhs_reg
    if lhs is rhs:
        return True
    return False


# JCC mnemonic → condition op mapping (unsigned by default)
_JCC_UNSIGNED_OP_8616: dict[str, ConditionOp] = {
    **{mnemonic: "eq" for mnemonic in JCC_EQ_MNEMONICS_8616},
    **{mnemonic: "ne" for mnemonic in JCC_NE_MNEMONICS_8616},
    **{mnemonic: "ult" for mnemonic in JCC_ULT_MNEMONICS_8616},
    **{mnemonic: "uge" for mnemonic in JCC_UGE_MNEMONICS_8616},
    **{mnemonic: "ule" for mnemonic in JCC_ULE_MNEMONICS_8616},
    **{mnemonic: "ugt" for mnemonic in JCC_UGT_MNEMONICS_8616},
}

_JCC_SIGNED_OP_8616: dict[str, ConditionOp] = {
    **{mnemonic: "slt" for mnemonic in JCC_SLT_MNEMONICS_8616},
    **{mnemonic: "sge" for mnemonic in JCC_SGE_MNEMONICS_8616},
    **{mnemonic: "sle" for mnemonic in JCC_SLE_MNEMONICS_8616},
    **{mnemonic: "sgt" for mnemonic in JCC_SGT_MNEMONICS_8616},
}

_JCC_COMPARE_OP_8616: dict[str, ConditionOp] = {
    **{mnemonic: "compare" for mnemonic in _JCC_COMPARISON_MNEMONICS_8616},
}


def _jcc_to_condition_op_8616(mnemonic: str | None, lhs, rhs) -> ConditionOp:
    """Map a JCC mnemonic to a ConditionOp, defaulting to unsigned."""
    if isinstance(mnemonic, str):
        mnemonic = mnemonic.lower().strip()
        unsigned = _JCC_UNSIGNED_OP_8616.get(mnemonic)
        if unsigned is not None:
            return unsigned
        signed = _JCC_SIGNED_OP_8616.get(mnemonic)
        if signed is not None:
            return signed
        compare = _JCC_COMPARE_OP_8616.get(mnemonic)
        if compare is not None:
            return compare
    return "compare"


def _jcc_to_condition_op_with_zero_8616(mnemonic: str | None, lhs, rhs) -> ConditionOp:
    """Map a JCC against zero to the appropriate condition op."""
    if isinstance(mnemonic, str):
        mnemonic = mnemonic.lower().strip()
        if mnemonic in JCC_EQ_MNEMONICS_8616:
            return "eq"
        if mnemonic in JCC_NE_MNEMONICS_8616:
            return "ne"
        if mnemonic in JCC_SGT_MNEMONICS_8616:
            return "sgt"
        if mnemonic in JCC_SGE_MNEMONICS_8616:
            return "sge"
        if mnemonic in JCC_SLT_MNEMONICS_8616:
            return "slt"
        if mnemonic in JCC_SLE_MNEMONICS_8616:
            return "sle"
        if mnemonic in JCC_UGT_MNEMONICS_8616:
            return "ugt"
        if mnemonic in JCC_UGE_MNEMONICS_8616:
            return "uge"
        if mnemonic in JCC_ULT_MNEMONICS_8616:
            return "ult"
        if mnemonic in JCC_ULE_MNEMONICS_8616:
            return "ule"
        if mnemonic in _JCC_COMPARISON_MNEMONICS_8616:
            return "compare"
    return "ne"
