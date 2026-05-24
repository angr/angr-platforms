from __future__ import annotations

import contextlib

from pyvex.lifting.util.vex_helper import Type

from .ir.core import IRCondition, IRValue, MemSpace
from .ir.condition_ir import (
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
)

__all__ = [
    "_condition_value_from_ir_value_8616",
    "_consume_last_condition_branch_8616",
    "_direct_jcc_condition_from_last_condition_8616",
]


def _condition_value_from_ir_value_8616(instruction, value: IRValue):
    if value.space == MemSpace.CONST:
        bits = max(1, int(value.size or 0) * 8 or 16)
        if bits <= 8:
            ty = Type.int_8
        elif bits <= 16:
            ty = Type.int_16
        else:
            ty = Type.int_32
        return instruction.constant(0 if value.const is None else int(value.const), ty)
    if value.space == MemSpace.REG and isinstance(value.name, str) and value.name:
        reg_name = value.name.lower()
        bits = int(value.size or 0) * 8
        if bits <= 8:
            return instruction.get(reg_name, Type.int_8)
        if bits <= 16:
            return instruction.get(reg_name, Type.int_16)
        return instruction.get(reg_name, Type.int_32)
    if value.space == MemSpace.TMP and isinstance(value.name, str) and value.name:
        if value.name == "VexValue":
            return None
        bits = int(value.size or 0) * 8
        if bits <= 8:
            ty = Type.int_8
        elif bits <= 16:
            ty = Type.int_16
        else:
            ty = Type.int_32
        with contextlib.suppress(Exception):
            return instruction.get(value.name, ty)
        return None
    return None


def _direct_jcc_condition_from_last_condition_8616(instruction, kind: str, condition: IRCondition):
    args = tuple(getattr(condition, "args", ()) or ())
    op = str(getattr(condition, "op", ""))
    if op in {"compare", "eq", "ne", "slt", "sle", "sgt", "sge", "ult", "ule", "ugt", "uge", "masked_zero", "zero", "masked_nonzero", "nonzero"}:
        if len(args) not in {1, 2}:
            return None
        if op in {"masked_zero", "zero"}:
            lhs = _condition_value_from_ir_value_8616(instruction, args[0])
            rhs = _condition_value_from_ir_value_8616(instruction, args[1]) if len(args) == 2 else None
            if lhs is None:
                return None
            masked = lhs if rhs is None else lhs & rhs
            if kind in JCC_EQ_MNEMONICS_8616:
                return masked == instruction.constant(0, Type.int_16)
            if kind in JCC_NE_MNEMONICS_8616:
                return masked != instruction.constant(0, Type.int_16)
            return None
        if op in {"masked_nonzero", "nonzero"}:
            lhs = _condition_value_from_ir_value_8616(instruction, args[0])
            rhs = _condition_value_from_ir_value_8616(instruction, args[1]) if len(args) == 2 else None
            if lhs is None:
                return None
            masked = lhs if rhs is None else lhs & rhs
            if kind in JCC_EQ_MNEMONICS_8616:
                return masked == instruction.constant(0, Type.int_16)
            if kind in JCC_NE_MNEMONICS_8616:
                return masked != instruction.constant(0, Type.int_16)
            return None

        lhs = _condition_value_from_ir_value_8616(instruction, args[0])
        rhs = _condition_value_from_ir_value_8616(instruction, args[1])
        if lhs is None or rhs is None:
            return None
        if kind in JCC_EQ_MNEMONICS_8616:
            return lhs == rhs
        if kind in JCC_NE_MNEMONICS_8616:
            return lhs != rhs
        if kind in JCC_SLE_MNEMONICS_8616:
            return lhs.signed <= rhs.signed
        if kind in JCC_SGT_MNEMONICS_8616:
            return lhs.signed > rhs.signed
        if kind in JCC_SLT_MNEMONICS_8616:
            return lhs.signed < rhs.signed
        if kind in JCC_SGE_MNEMONICS_8616:
            return lhs.signed >= rhs.signed
        if kind in JCC_ULT_MNEMONICS_8616:
            return lhs < rhs
        if kind in JCC_UGE_MNEMONICS_8616:
            return lhs >= rhs
        if kind in JCC_ULE_MNEMONICS_8616:
            return lhs <= rhs
        if kind in JCC_UGT_MNEMONICS_8616:
            return lhs > rhs
        if kind in _JCC_COMPARISON_MNEMONICS_8616:
            return None
        return None

    if op in {"zero", "nonzero"} and len(args) == 1:
        value = _condition_value_from_ir_value_8616(instruction, args[0])
        if value is None:
            return None
        zero = instruction.constant(0, Type.int_16)
        if op == "zero":
            return value == zero if kind in JCC_EQ_MNEMONICS_8616 else value != zero if kind in JCC_NE_MNEMONICS_8616 else None
        return value != zero if kind in JCC_EQ_MNEMONICS_8616 else value == zero if kind in JCC_NE_MNEMONICS_8616 else None

    return None


def _consume_last_condition_branch_8616(instruction, emu, kind: str):
    last_condition = getattr(emu, "get_last_condition", lambda: None)()
    if not isinstance(last_condition, IRCondition):
        return None
    branch_cond = _direct_jcc_condition_from_last_condition_8616(instruction, kind, last_condition)
    with contextlib.suppress(Exception):
        emu.clear_last_condition()
    return branch_cond
