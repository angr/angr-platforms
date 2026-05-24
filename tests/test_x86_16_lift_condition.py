from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.ir.core import IRCondition, IRValue, MemSpace
from angr_platforms.X86_16.jcc_condition import (
    _consume_last_condition_branch_8616,
    _direct_jcc_condition_from_last_condition_8616,
)


class _SymExpr:
    def __init__(self, text: str):
        self.text = text

    @property
    def signed(self):
        return self

    def __and__(self, other):
        return _SymExpr(f"({self.text} & {other.text})")

    def __eq__(self, other):  # type: ignore[override]
        return _SymExpr(f"({self.text} == {other.text})")

    def __ne__(self, other):  # type: ignore[override]
        return _SymExpr(f"({self.text} != {other.text})")

    def __lt__(self, other):
        return _SymExpr(f"({self.text} < {other.text})")

    def __le__(self, other):
        return _SymExpr(f"({self.text} <= {other.text})")

    def __gt__(self, other):
        return _SymExpr(f"({self.text} > {other.text})")

    def __ge__(self, other):
        return _SymExpr(f"({self.text} >= {other.text})")

    def __repr__(self):
        return self.text


class _FakeInstruction:
    def constant(self, value, _ty):
        return _SymExpr(str(int(value)))

    def get(self, name, _ty):
        return _SymExpr(name)


class _FakeEmu:
    def __init__(self, condition):
        self._last_condition = condition

    def get_last_condition(self):
        return self._last_condition

    def clear_last_condition(self):
        self._last_condition = None


def test_direct_jcc_condition_consumes_compare_artifact():
    condition = IRCondition(
        op="compare",
        args=(
            IRValue(MemSpace.REG, name="ax", size=2),
            IRValue(MemSpace.CONST, const=7, size=2),
        ),
    )

    result = _direct_jcc_condition_from_last_condition_8616(_FakeInstruction(), "jz", condition)

    assert repr(result) == "(ax == 7)"


def test_direct_jcc_condition_consumes_typed_unsigned_compare_artifact():
    condition = IRCondition(
        op="ult",
        args=(
            IRValue(MemSpace.REG, name="ax", size=2),
            IRValue(MemSpace.REG, name="bx", size=2),
        ),
    )

    result = _direct_jcc_condition_from_last_condition_8616(_FakeInstruction(), "jb", condition)

    assert repr(result) == "(ax < bx)"


def test_direct_jcc_condition_consumes_nonzero_test_artifact():
    condition = IRCondition(
        op="nonzero",
        args=(
            IRValue(MemSpace.REG, name="ax", size=2),
            IRValue(MemSpace.CONST, const=0x80, size=2),
        ),
    )

    result = _direct_jcc_condition_from_last_condition_8616(_FakeInstruction(), "jnz", condition)

    assert repr(result) == "((ax & 128) != 0)"


def test_direct_jcc_condition_consumes_zero_test_artifact():
    condition = IRCondition(
        op="zero",
        args=(
            IRValue(MemSpace.REG, name="ax", size=2),
        ),
    )

    result = _direct_jcc_condition_from_last_condition_8616(_FakeInstruction(), "jz", condition)

    assert repr(result) == "(ax == 0)"


def test_direct_jcc_condition_refuses_unsupported_branch_from_nonzero():
    condition = IRCondition(
        op="nonzero",
        args=(
            IRValue(MemSpace.REG, name="ax", size=2),
            IRValue(MemSpace.CONST, const=0x80, size=2),
        ),
    )

    result = _direct_jcc_condition_from_last_condition_8616(_FakeInstruction(), "ja", condition)

    assert result is None


def test_direct_jcc_condition_refuses_vexvalue_named_tmp_operand():
    condition = IRCondition(
        op="compare",
        args=(
            IRValue(MemSpace.TMP, name="VexValue", size=2),
            IRValue(MemSpace.CONST, const=7, size=2),
        ),
    )

    result = _direct_jcc_condition_from_last_condition_8616(_FakeInstruction(), "jz", condition)

    assert result is None


def test_consume_last_condition_branch_clears_consumed_condition():
    condition = IRCondition(
        op="compare",
        args=(
            IRValue(MemSpace.REG, name="ax", size=2),
            IRValue(MemSpace.CONST, const=7, size=2),
        ),
    )
    emu = _FakeEmu(condition)

    result = _consume_last_condition_branch_8616(_FakeInstruction(), emu, "jg")

    assert repr(result) == "(ax > 7)"
    assert emu.get_last_condition() is None
