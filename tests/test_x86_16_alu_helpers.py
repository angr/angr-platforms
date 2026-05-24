from angr_platforms.X86_16.alu_helpers import (
    binary_operation,
    binary_operation_with_carry,
    build_compare_condition_8616,
    compare_operation,
    masked_shift_count,
    rotate_count,
    rotate_left_operation,
    rotate_right_operation,
    shift_left_operation,
    shift_right_arithmetic_operation,
    shift_right_operation,
)
from angr_platforms.X86_16.ir.core import IRCondition, IRValue, MemSpace
from pyvex.lifting.util.vex_helper import Type


class _AluEmu:
    def __init__(self, carry=False):
        self.carry = carry
        self.last_condition = None

    def constant(self, value, _ty):
        return value

    def is_carry(self):
        return self.carry

    def update_eflags_sub(self, lhs, rhs):
        self.last_flags = ("sub", lhs, rhs)

    def update_eflags_and(self, lhs, rhs):
        self.last_flags = ("and", lhs, rhs)

    def update_eflags_or(self, lhs, rhs):
        self.last_flags = ("or", lhs, rhs)

    def update_eflags_xor(self, lhs, rhs):
        self.last_flags = ("xor", lhs, rhs)

    def set_last_condition(self, condition):
        self.last_condition = condition


class _RegOperand:
    def __init__(self, reg: int, size: int = 16):
        self.reg = reg
        self.ty = Type.int_16 if size == 16 else Type.int_8


def test_binary_operation_updates_result_and_flags():
    emu = _AluEmu()
    state = {}

    binary_operation(
        emu,
        lambda: 2,
        lambda: 3,
        lambda value: state.setdefault("result", value),
        lambda lhs, rhs: state.update({"flags": (lhs, rhs)}),
        lambda lhs, rhs: lhs + rhs,
    )

    assert state["result"] == 5
    assert state["flags"] == (2, 3)


def test_binary_operation_with_carry_threads_the_carry_value():
    emu = _AluEmu(carry=True)
    state = {}

    binary_operation_with_carry(
        emu,
        lambda: 2,
        lambda: 3,
        lambda value: state.setdefault("result", value),
        lambda lhs, rhs, carry: state.update({"flags": (lhs, rhs, carry)}),
        lambda lhs, rhs, carry: lhs + rhs + carry,
        width_bits=16,
    )

    assert state["result"] == 6
    assert state["flags"] == (2, 3, True)


def test_binary_operation_with_carry_accepts_plain_booleans():
    emu = _AluEmu(carry=False)
    state = {}

    binary_operation_with_carry(
        emu,
        lambda: 2,
        lambda: 3,
        lambda value: state.setdefault("result", value),
        lambda lhs, rhs, carry: state.update({"flags": (lhs, rhs, carry)}),
        lambda lhs, rhs, carry: lhs + rhs + carry,
        width_bits=16,
    )

    assert state["result"] == 5
    assert state["flags"] == (2, 3, 0)


def test_compare_operation_only_updates_flags():
    state = {}

    compare_operation(lambda: 4, lambda: 2, lambda lhs, rhs: state.update({"flags": (lhs, rhs)}))

    assert state["flags"] == (4, 2)


def test_binary_operation_records_typed_condition_for_subtraction():
    emu = _AluEmu()
    state = {}

    binary_operation(
        emu,
        lambda: 4,
        lambda: 2,
        lambda value: state.setdefault("result", value),
        emu.update_eflags_sub,
        lambda lhs, rhs: lhs - rhs,
    )

    assert state["result"] == 2
    assert emu.last_condition == IRCondition(
        op="compare",
        args=(
            IRValue(MemSpace.CONST, const=4, size=1, expr=("int",)),
            IRValue(MemSpace.CONST, const=2, size=1, expr=("int",)),
        ),
        expr=("update_eflags_sub",),
    )


def test_build_compare_condition_recovers_compare_family():
    condition = build_compare_condition_8616(4, 2, _AluEmu().update_eflags_sub)

    assert condition == IRCondition(
        op="compare",
        args=(
            IRValue(MemSpace.CONST, const=4, size=1, expr=("int",)),
            IRValue(MemSpace.CONST, const=2, size=1, expr=("int",)),
        ),
        expr=("update_eflags_sub",),
    )


def test_build_compare_condition_recovers_equality_for_same_operand_sub():
    condition = build_compare_condition_8616(4, 4, _AluEmu().update_eflags_sub)

    assert condition == IRCondition(
        op="eq",
        args=(
            IRValue(MemSpace.CONST, const=4, size=1, expr=("int",)),
            IRValue(MemSpace.CONST, const=4, size=1, expr=("int",)),
        ),
        expr=("update_eflags_sub", "same_operand"),
    )


def test_compare_operation_sets_last_condition_on_emulator():
    emu = _AluEmu()

    compare_operation(lambda: 4, lambda: 2, emu.update_eflags_sub)

    assert emu.last_flags == ("sub", 4, 2)
    assert emu.last_condition == IRCondition(
        op="compare",
        args=(
            IRValue(MemSpace.CONST, const=4, size=1, expr=("int",)),
            IRValue(MemSpace.CONST, const=2, size=1, expr=("int",)),
        ),
        expr=("update_eflags_sub",),
    )


def test_compare_operation_sets_equality_condition_for_same_operand_sub():
    emu = _AluEmu()

    compare_operation(lambda: 4, lambda: 4, emu.update_eflags_sub)

    assert emu.last_flags == ("sub", 4, 4)
    assert emu.last_condition == IRCondition(
        op="eq",
        args=(
            IRValue(MemSpace.CONST, const=4, size=1, expr=("int",)),
            IRValue(MemSpace.CONST, const=4, size=1, expr=("int",)),
        ),
        expr=("update_eflags_sub", "same_operand"),
    )


def test_compare_operation_captures_nonzero_test_condition():
    emu = _AluEmu()

    compare_operation(lambda: 0x80, lambda: 0x08, emu.update_eflags_and)

    assert emu.last_flags == ("and", 0x80, 0x08)
    assert emu.last_condition == IRCondition(
        op="nonzero",
        args=(
            IRValue(MemSpace.CONST, const=0x80, size=1, expr=("int",)),
            IRValue(MemSpace.CONST, const=0x08, size=1, expr=("int",)),
        ),
        expr=("update_eflags_and",),
    )


def test_compare_operation_captures_unary_nonzero_for_same_operand_test():
    emu = _AluEmu()

    compare_operation(lambda: 0x80, lambda: 0x80, emu.update_eflags_and)

    assert emu.last_flags == ("and", 0x80, 0x80)
    assert emu.last_condition == IRCondition(
        op="nonzero",
        args=(
            IRValue(MemSpace.CONST, const=0x80, size=1, expr=("int",)),
        ),
        expr=("update_eflags_and", "same_operand"),
    )


def test_compare_operation_captures_nonzero_for_or_and_xor():
    emu = _AluEmu()

    compare_operation(lambda: 0x10, lambda: 0x02, emu.update_eflags_or)
    assert emu.last_condition == IRCondition(
        op="nonzero",
        args=(
            IRValue(MemSpace.CONST, const=0x10, size=1, expr=("int",)),
            IRValue(MemSpace.CONST, const=0x02, size=1, expr=("int",)),
        ),
        expr=("update_eflags_or",),
    )

    compare_operation(lambda: 0x10, lambda: 0x02, emu.update_eflags_xor)
    assert emu.last_condition == IRCondition(
        op="nonzero",
        args=(
            IRValue(MemSpace.CONST, const=0x10, size=1, expr=("int",)),
            IRValue(MemSpace.CONST, const=0x02, size=1, expr=("int",)),
        ),
        expr=("update_eflags_xor",),
    )


def test_build_compare_condition_zero_rhs_sub_becomes_unary_nonzero():
    condition = build_compare_condition_8616(4, 0, _AluEmu().update_eflags_sub)

    assert condition == IRCondition(
        op="nonzero",
        args=(
            IRValue(MemSpace.CONST, const=4, size=1, expr=("int",)),
        ),
        expr=("update_eflags_sub", "rhs_zero"),
    )


def test_build_compare_condition_harmonizes_plain_int_width_to_peer_operand():
    lhs = type("_FakeOperand", (), {"width": 16, "value": 4, "ty": Type.int_16})()

    condition = build_compare_condition_8616(lhs, 2, _AluEmu().update_eflags_sub)

    assert condition == IRCondition(
        op="compare",
        args=(
            IRValue(MemSpace.CONST, const=4, size=2, expr=("vex_const",)),
            IRValue(MemSpace.CONST, const=2, size=2, expr=("int",)),
        ),
        expr=("update_eflags_sub",),
    )


def test_build_compare_condition_recovers_register_operand_from_vex_offset():
    condition = build_compare_condition_8616(_RegOperand(0), 7, _AluEmu().update_eflags_sub)

    assert condition == IRCondition(
        op="compare",
        args=(
            IRValue(MemSpace.REG, name="ax", offset=0, size=2, expr=("Ity_I16",)),
            IRValue(MemSpace.CONST, const=7, size=2, expr=("int",)),
        ),
        expr=("update_eflags_sub",),
    )


def test_build_compare_condition_recovers_register_operand_from_reg_name():
    class _RegNameOperand:
        reg_name = "bx"
        ty = Type.int_16

    condition = build_compare_condition_8616(_RegNameOperand(), 1, _AluEmu().update_eflags_sub)

    assert condition == IRCondition(
        op="compare",
        args=(
            IRValue(MemSpace.REG, name="bx", offset=0, size=2, expr=("Ity_I16",)),
            IRValue(MemSpace.CONST, const=1, size=2, expr=("int",)),
        ),
        expr=("update_eflags_sub",),
    )


def test_build_compare_condition_refuses_non_constant_vexvalue_value_property():
    class _BadValue:
        @property
        def value(self):
            raise ValueError("Non-constant VexValue has no value property")

    condition = build_compare_condition_8616(_BadValue(), 2, _AluEmu().update_eflags_sub)

    assert condition == IRCondition(
        op="compare",
        args=(
            IRValue(MemSpace.TMP, name="_BadValue", size=1, expr=("_BadValue",)),
            IRValue(MemSpace.CONST, const=2, size=1, expr=("int",)),
        ),
        expr=("update_eflags_sub",),
    )


def test_shift_helpers_mask_and_rotate_counts():
    emu = _AluEmu()

    assert masked_shift_count(emu, 0x23, 8) == 3
    assert rotate_count(emu, 0x23, 8, 8) == 3


def test_shift_and_rotate_helpers_apply_value_transformations():
    emu = _AluEmu()
    state = {}

    shift_left_operation(emu, lambda: 0x12, lambda value: state.setdefault("shl", value), lambda lhs, rhs: state.update({"shl_flags": (lhs, rhs)}), 1, 8)
    shift_right_operation(emu, lambda: 0x12, lambda value: state.setdefault("shr", value), lambda lhs, rhs: state.update({"shr_flags": (lhs, rhs)}), 1, 8)
    rotate_left_operation(emu, lambda: 0x81, lambda value: state.setdefault("rol", value), lambda lhs, rhs: state.update({"rol_flags": (lhs, rhs)}), 1, 8)
    rotate_right_operation(emu, lambda: 0x81, lambda value: state.setdefault("ror", value), lambda lhs, rhs: state.update({"ror_flags": (lhs, rhs)}), 1, 8)

    assert state["shl"] == 0x24
    assert state["shl_flags"] == (0x12, 1)
    assert state["shr"] == 0x09
    assert state["shr_flags"] == (0x12, 1)
    assert state["rol"] == 0x03
    assert state["rol_flags"] == (0x81, 1)
    assert state["ror"] == 0xC0
    assert state["ror_flags"] == (0x81, 1)


def test_shift_right_arithmetic_helper_uses_sar_on_the_value():
    emu = _AluEmu()

    class _SignedValue(int):
        def sar(self, count):
            return _SignedValue(self >> count)

    state = {}
    shift_right_arithmetic_operation(
        emu,
        lambda: _SignedValue(0xF0),
        lambda value: state.setdefault("result", value),
        lambda lhs, rhs: state.update({"flags": (lhs, rhs)}),
        1,
        8,
    )

    assert state["result"] == 0x78
    assert state["flags"] == (_SignedValue(0xF0), 1)
