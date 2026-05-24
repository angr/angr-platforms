from __future__ import annotations

"""Tests for ir_canonicalize_8616: constant reassociation canonicalizer."""

import pytest
from unittest.mock import MagicMock
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant
from angr.sim_type import SimTypeInt
from angr_platforms.X86_16.ir.ir_canonicalize_8616 import canonicalize_expr_8616

_T = SimTypeInt(signed=False, label="int")


def _make_cg():
    cg = MagicMock()
    cg.next_idx.return_value = 0
    return cg


_cg = _make_cg()


def make_const(value: int):
    return CConstant(value, _T, codegen=_cg)


def make_var(name: str):
    from angr.analyses.decompiler.structured_codegen.c import CVariable
    from angr.sim_variable import SimVariable
    var = SimVariable(2, None, name, None, None)
    return CVariable(var, codegen=_cg)


def _mk_binop(op, lhs, rhs):
    return CBinaryOp(op, lhs, rhs, codegen=_cg)


def _serialize(expr) -> str:
    if isinstance(expr, CConstant):
        return str(expr.value)
    if isinstance(expr, CBinaryOp):
        return f"({_serialize(expr.lhs)} {expr.op} {_serialize(expr.rhs)})"
    return repr(expr)


def _contains_const(expr, val: int) -> bool:
    if isinstance(expr, CConstant) and expr.value == val:
        return True
    if isinstance(expr, CBinaryOp):
        return _contains_const(expr.lhs, val) or _contains_const(expr.rhs, val)
    return False


def _count_binops(expr) -> int:
    if not isinstance(expr, CBinaryOp):
        return 0
    return 1 + _count_binops(expr.lhs) + _count_binops(expr.rhs)


class TestFoldSubSubConstants:
    def test_fold_sub_sub_constants(self):
        x = make_var("x")
        inner = _mk_binop("Sub", x, make_const(2))
        expr = _mk_binop("Sub", inner, make_const(2))
        result = canonicalize_expr_8616(expr)
        s = _serialize(result)
        assert _contains_const(result, 4), f"Expected constant 4 in: {s}"


class TestFoldAddSubConstants:
    def test_fold_add_sub_constants(self):
        x = make_var("x")
        inner = _mk_binop("Add", x, make_const(2))
        expr = _mk_binop("Sub", inner, make_const(1))
        result = canonicalize_expr_8616(expr)
        s = _serialize(result)
        assert _contains_const(result, 1), f"Expected constant 1 in: {s}"


class TestFoldMulConstants:
    def test_fold_mul_constants(self):
        x = make_var("x")
        inner = _mk_binop("Mul", x, make_const(2))
        expr = _mk_binop("Mul", inner, make_const(4))
        result = canonicalize_expr_8616(expr)
        s = _serialize(result)
        assert _contains_const(result, 8), f"Expected constant 8 in: {s}"


class TestFoldAndConstants:
    def test_fold_and_constants(self):
        x = make_var("x")
        inner = _mk_binop("And", x, make_const(0xFF))
        expr = _mk_binop("And", inner, make_const(0x0F))
        result = canonicalize_expr_8616(expr)
        s = _serialize(result)
        assert _contains_const(result, 0x0F), f"Expected constant 0x0F in: {s}"


class TestFoldOrConstants:
    def test_fold_or_constants(self):
        x = make_var("x")
        inner = _mk_binop("Or", x, make_const(1))
        expr = _mk_binop("Or", inner, make_const(2))
        result = canonicalize_expr_8616(expr)
        s = _serialize(result)
        assert _contains_const(result, 3), f"Expected constant 3 in: {s}"


class TestFoldXorDuplicateConstants:
    def test_fold_xor_duplicate_constants(self):
        x = make_var("x")
        inner = _mk_binop("Xor", x, make_const(1))
        expr = _mk_binop("Xor", inner, make_const(1))
        result = canonicalize_expr_8616(expr)
        s = _serialize(result)
        assert not _contains_const(result, 1), f"Should not have constant 1 in: {s}"


class TestShiftZero:
    def test_shift_zero(self):
        x = make_var("x")
        expr = _mk_binop("Shl", x, make_const(0))
        result = canonicalize_expr_8616(expr)
        assert not isinstance(result, CBinaryOp)


class TestIdentity:
    def test_add_zero(self):
        result = canonicalize_expr_8616(_mk_binop("Add", make_const(5), make_const(0)))
        assert isinstance(result, CConstant) and result.value == 5

    def test_sub_zero(self):
        result = canonicalize_expr_8616(_mk_binop("Sub", make_const(5), make_const(0)))
        assert isinstance(result, CConstant) and result.value == 5

    def test_mul_one(self):
        result = canonicalize_expr_8616(_mk_binop("Mul", make_const(5), make_const(1)))
        assert isinstance(result, CConstant) and result.value == 5


class TestConstantFold:
    def test_const_add(self):
        result = canonicalize_expr_8616(_mk_binop("Add", make_const(2), make_const(2)))
        assert result.value == 4

    def test_const_sub(self):
        result = canonicalize_expr_8616(_mk_binop("Sub", make_const(5), make_const(3)))
        assert result.value == 2

    def test_const_mul(self):
        result = canonicalize_expr_8616(_mk_binop("Mul", make_const(3), make_const(4)))
        assert result.value == 12

    def test_const_and(self):
        result = canonicalize_expr_8616(_mk_binop("And", make_const(8), make_const(3)))
        assert result.value == 0

    def test_const_or(self):
        result = canonicalize_expr_8616(_mk_binop("Or", make_const(8), make_const(1)))
        assert result.value == 9

    def test_const_xor(self):
        result = canonicalize_expr_8616(_mk_binop("Xor", make_const(8), make_const(1)))
        assert result.value == 9

    def test_const_shl(self):
        result = canonicalize_expr_8616(_mk_binop("Shl", make_const(1), make_const(3)))
        assert result.value == 8

    def test_const_shr(self):
        result = canonicalize_expr_8616(_mk_binop("Shr", make_const(8), make_const(1)))
        assert result.value == 4
