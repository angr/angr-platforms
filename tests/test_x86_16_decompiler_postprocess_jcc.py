from __future__ import annotations

from types import SimpleNamespace

import pytest

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CIfElse, CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_jcc import (
    _COND_TO_CMP_OP_8616,
    _DecodedCmpGuard8616,
    _JCC_COMPARE_OPS_8616,
    _rewrite_decoded_jcc_conditions_8616,
    _translate_cmp_jcc_guard_8616,
)
from angr_platforms.X86_16.ir.condition_ir import JCC_TO_COND_8616
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _codegen(statements):
    codegen = _DummyCodegen()
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    return codegen


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen, *, var_name: str | None = None):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=var_name or name), codegen=codegen)


def _stack(offset: int, codegen, name: str):
    return CVariable(SimStackVariable(offset, 2, base="bp", name=name, region=0x4010), codegen=codegen)


def test_rewrite_decoded_jcc_conditions_refuses_self_compare(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    same_expr = CBinaryOp("Add", _reg(project, "ax", codegen), _const(1, codegen), codegen=codegen)

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=same_expr,
            rhs=same_expr,
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond


def test_rewrite_decoded_jcc_conditions_refuses_fingerprint_equal_compare(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    lhs = CBinaryOp("Add", _reg(project, "ax", codegen), _const(1, codegen), codegen=codegen)
    rhs = CBinaryOp("Add", _reg(project, "bx", codegen), _const(2, codegen), codegen=codegen)

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=lhs,
            rhs=rhs,
            op="CmpGT",
        ),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._expr_fingerprint",
        lambda _expr, _project: "same",
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond


def test_rewrite_decoded_jcc_conditions_rewrites_direct_condition_attr(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = cond
    if_stmt.iftrue = CStatements([], codegen=codegen)
    if_stmt.iffalse = None
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition, CBinaryOp)
    assert if_stmt.condition.op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_finds_nested_tags_on_direct_condition(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    inner = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    cond = CBinaryOp("LogicalAnd", CConstant(1, SimTypeShort(False), codegen=codegen), inner, codegen=codegen)
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = cond
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition, CBinaryOp)
    assert if_stmt.condition.op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_rewrites_tuple_condition_pairs(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes, tuple)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_handles_cycle_guard(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    cycle_body = CStatements([if_stmt], codegen=codegen)
    if_stmt.iftrue = cycle_body
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


@pytest.mark.parametrize(
    ("mnemonic", "expected_op"),
    [
        ("jc", "CmpLT"),
        ("jnae", "CmpLT"),
        ("jnb", "CmpGE"),
        ("jnc", "CmpGE"),
        ("jna", "CmpLE"),
        ("jnbe", "CmpGT"),
        ("jnge", "CmpLT"),
        ("jnl", "CmpGE"),
        ("jng", "CmpLE"),
        ("jnle", "CmpGT"),
    ],
)
def test_translate_cmp_jcc_guard_supports_all_alias_mnemonics(monkeypatch, mnemonic, expected_op):
    project = _project()
    codegen = _codegen([])
    bp_arg = _stack(4, codegen, "iMaxLevel")
    local_i = _stack(-4, codegen, "i")
    local_parent = _stack(-2, codegen, "iParent")
    codegen.cfunc.arg_list = (bp_arg,)
    codegen.cfunc.variables_in_use = {
        bp_arg.variable: bp_arg,
        local_i.variable: local_i,
        local_parent.variable: local_parent,
    }
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "bx",
                3: "si",
                4: "al",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, 4), size=2))),
        _Insn(0x4002, "mov", (_Operand(3, mem=_Mem(5, -4), size=2), _Operand(1, reg=1, size=2))),
        _Insn(0x4004, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4006, "shl", (_Operand(1, reg=2, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4008, "mov", (_Operand(1, reg=3, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x400A, "shl", (_Operand(1, reg=3, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x400C, "mov", (_Operand(1, reg=4, size=1), _Operand(3, mem=_Mem(3, 0), size=1))),
        _Insn(0x400E, "cmp", (_Operand(3, mem=_Mem(2, 0), size=1), _Operand(1, reg=4, size=1))),
        _Insn(0x4010, mnemonic, (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns)))

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4010)

    assert decoded is not None
    assert decoded.op == expected_op


@pytest.mark.parametrize(
    ("mnemonic", "expected_op", "expected_mask"),
    [
        ("jo", "CmpNE", 0x800),
        ("jno", "CmpEQ", 0x800),
        ("js", "CmpNE", 0x80),
        ("jns", "CmpEQ", 0x80),
        ("jp", "CmpNE", 0x4),
        ("jpe", "CmpNE", 0x4),
        ("jnp", "CmpEQ", 0x4),
        ("jpo", "CmpEQ", 0x4),
    ],
)
def test_translate_cmp_jcc_guard_supports_flag_variants(monkeypatch, mnemonic, expected_op, expected_mask):
    project = _project()
    codegen = _codegen([])

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, imm=0, size=2):
            self.type = type_
            self.reg = 0
            self.imm = imm
            self.mem = _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

    insns = (
        _Insn(0x4000, "mov", (_Operand(2, imm=0x4000),)),
        _Insn(0x4002, mnemonic, (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns)))

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4002)

    assert decoded is not None
    assert decoded.op == expected_op
    left = getattr(decoded, "lhs", None)
    assert isinstance(left, CBinaryOp)
    assert left.op == "And"
    masked = getattr(left, "rhs", None)
    assert isinstance(masked, CConstant)
    assert masked.value == expected_mask
    assert isinstance(decoded.rhs, CConstant)
    assert decoded.rhs.value == 0


def test_translate_cmp_jcc_guard_uses_existing_bp_slot_variables_for_stack_loads(monkeypatch):
    project = _project()
    codegen = _codegen([])
    bp_arg = _stack(4, codegen, "iMaxLevel")
    local_i = _stack(-4, codegen, "i")
    local_parent = _stack(-2, codegen, "iParent")
    codegen.cfunc.arg_list = (bp_arg,)
    codegen.cfunc.variables_in_use = {
        bp_arg.variable: bp_arg,
        local_i.variable: local_i,
        local_parent.variable: local_parent,
    }
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "bx",
                3: "si",
                4: "al",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, 4), size=2))),
        _Insn(0x4002, "mov", (_Operand(3, mem=_Mem(5, -4), size=2), _Operand(1, reg=1, size=2))),
        _Insn(0x4004, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4006, "shl", (_Operand(1, reg=2, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4008, "mov", (_Operand(1, reg=3, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x400A, "shl", (_Operand(1, reg=3, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x400C, "mov", (_Operand(1, reg=4, size=1), _Operand(3, mem=_Mem(3, 0), size=1))),
        _Insn(0x400E, "cmp", (_Operand(3, mem=_Mem(2, 0), size=1), _Operand(1, reg=4, size=1))),
        _Insn(0x4010, "jg", (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns)))

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4010)

    assert decoded is not None
    assert decoded.op == "CmpGT"


def test_translate_cmp_jcc_guard_keeps_distinct_bp_slot_operands():
    project = _project()
    codegen = _codegen([])
    bp_arg = _stack(4, codegen, "iMaxLevel")
    local_i = _stack(-4, codegen, "i")
    local_parent = _stack(-2, codegen, "iParent")
    codegen.cfunc.arg_list = (bp_arg,)
    codegen.cfunc.variables_in_use = {
        bp_arg.variable: bp_arg,
        local_i.variable: local_i,
        local_parent.variable: local_parent,
    }
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "bx",
                3: "si",
                4: "al",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4002, "shl", (_Operand(1, reg=2, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4004, "mov", (_Operand(1, reg=3, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x4006, "shl", (_Operand(1, reg=3, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4008, "mov", (_Operand(1, reg=4, size=1), _Operand(3, mem=_Mem(3, 0), size=1))),
        _Insn(0x400A, "cmp", (_Operand(3, mem=_Mem(2, 0), size=1), _Operand(1, reg=4, size=1))),
        _Insn(0x400C, "jg", (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns)))

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x400C)

    assert decoded is not None
    assert decoded.op == "CmpGT"
    assert _expr_fingerprint(decoded.lhs, project) != _expr_fingerprint(decoded.rhs, project)


def test_translate_cmp_jcc_guard_synthesizes_distinct_bp_slots_when_locals_missing():
    project = _project()
    codegen = _codegen([])
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {}
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                2: "bx",
                3: "si",
                4: "al",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4002, "shl", (_Operand(1, reg=2, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4004, "mov", (_Operand(1, reg=3, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x4006, "shl", (_Operand(1, reg=3, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4008, "mov", (_Operand(1, reg=4, size=1), _Operand(3, mem=_Mem(3, 0), size=1))),
        _Insn(0x400A, "cmp", (_Operand(3, mem=_Mem(2, 0), size=1), _Operand(1, reg=4, size=1))),
        _Insn(0x400C, "jg", (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns)))

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x400C)

    assert decoded is not None
    assert decoded.op == "CmpGT"
    assert _expr_fingerprint(decoded.lhs, project) != _expr_fingerprint(decoded.rhs, project)


def test_translate_cmp_jcc_guard_supports_cmp_reg_mem_operand_order():
    project = _project()
    codegen = _codegen([])
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {}
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "dx",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x4002, "cmp", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4004, "jle", (_Operand(2, imm=0x4010, size=2),)),
    )
    project.factory = SimpleNamespace(block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns)))

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4004)

    assert decoded is not None
    assert decoded.op == "CmpLE"
    assert decoded.lhs is not None
    assert decoded.rhs is not None


def test_compare_jcc_mapping_stays_in_sync_with_condition_ir_aliases():
    expected = {
        mnemonic: _COND_TO_CMP_OP_8616[cond_op]
        for mnemonic, cond_op in JCC_TO_COND_8616.items()
        if cond_op in _COND_TO_CMP_OP_8616
    }
    assert _JCC_COMPARE_OPS_8616 == expected


def test_translate_cmp_jcc_guard_decodes_32bit_le_chain():
    project = _project()
    codegen = _codegen([])
    hi = _stack(-2, codegen, "goal_hi")
    lo = _stack(-4, codegen, "goal_lo")
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {
        hi.variable: hi,
        lo.variable: lo,
    }
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "dx",
                5: "bp",
            }.get(reg, "")

    block_hi = (
        _Insn(0x5000, "cmp", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x5002, "jle", (_Operand(2, imm=0x5010, size=2),)),
    )
    block_mid = (
        _Insn(0x5010, "jge", (_Operand(2, imm=0x5020, size=2),)),
    )
    block_lo = (
        _Insn(0x5020, "cmp", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x5022, "jbe", (_Operand(2, imm=0x5030, size=2),)),
    )
    blocks = {
        0x5000: block_hi,
        0x5010: block_mid,
        0x5020: block_lo,
    }
    project.factory = SimpleNamespace(
        block=lambda addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=blocks.get(addr, ())))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x5000, 0x5002)

    assert decoded is not None
    assert decoded.expr is not None
    assert isinstance(decoded.expr, CBinaryOp)
