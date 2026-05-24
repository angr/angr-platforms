from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CIfElse, CStatements, CUnaryOp, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_typed_conditions import _apply_typed_conditions_to_codegen_8616
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace


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


def test_apply_typed_conditions_refuses_self_compare_replacement(monkeypatch):
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
    codegen._inertia_typed_conditions = [
        SimpleNamespace(src_insn=0x4020, block_addr=0x4000, op="sgt", lhs="ax", rhs="bx")
    ]

    same_expr = CBinaryOp("Add", _reg(project, "ax", codegen), _const(1, codegen), codegen=codegen)
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions._build_c_condition_expr",
        lambda _project, _cond, _codegen: CBinaryOp("CmpGT", same_expr, same_expr, codegen=_codegen),
    )

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond
    assert getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) == 0


def test_apply_typed_conditions_rewrites_cifelse_condition_and_nodes(monkeypatch):
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
    codegen._inertia_typed_conditions = [
        SimpleNamespace(src_insn=0x4020, block_addr=0x4000, op="sgt", lhs="ax", rhs="bx")
    ]

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions._build_c_condition_expr",
        lambda _project, _cond, _codegen: CBinaryOp(
            "CmpGT",
            _reg(project, "ax", _codegen),
            _reg(project, "bx", _codegen),
            codegen=_codegen,
        ),
    )

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is True
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"
    assert getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) == 1


def test_apply_typed_conditions_rewrites_wrapped_flag_condition(monkeypatch):
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
    cond = CUnaryOp("Not", inner, codegen=codegen)
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        SimpleNamespace(src_insn=0x4020, block_addr=0x4000, op="sgt", lhs="ax", rhs="bx")
    ]

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions._build_c_condition_expr",
        lambda _project, _cond, _codegen: CBinaryOp(
            "CmpGT",
            _reg(project, "ax", _codegen),
            _reg(project, "bx", _codegen),
            codegen=_codegen,
        ),
    )

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is True
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"
    assert getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) == 1


def test_apply_typed_conditions_refuses_fingerprint_equal_replacement(monkeypatch):
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
    codegen._inertia_typed_conditions = [
        SimpleNamespace(src_insn=0x4020, block_addr=0x4000, op="sgt", lhs="ax", rhs="bx")
    ]

    lhs = CBinaryOp("Add", _reg(project, "ax", codegen), _const(1, codegen), codegen=codegen)
    rhs = CBinaryOp("Add", _reg(project, "bx", codegen), _const(2, codegen), codegen=codegen)
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions._build_c_condition_expr",
        lambda _project, _cond, _codegen: CBinaryOp("CmpGT", lhs, rhs, codegen=_codegen),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions._expr_fingerprint",
        lambda _expr, _project: "same",
    )

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond


def test_apply_typed_conditions_materializes_irvalue_operands():
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
    codegen._inertia_typed_conditions = [
        ConditionIR(
            op="ule",
            lhs=IRValue(MemSpace.REG, name="ax", size=2),
            rhs=IRValue(MemSpace.CONST, const=7, size=2),
            src_insn=0x4020,
            block_addr=0x4000,
        )
    ]

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is True
    updated = if_stmt.condition_and_nodes[0][0]
    assert isinstance(updated, CBinaryOp)
    assert updated.op == "CmpLE"
