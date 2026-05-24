from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_globals import (
    WordGlobalStoreCandidate,
    _coalesce_word_global_constant_stores_8616,
    _coalesce_word_global_loads_8616,
    describe_word_global_constant_store_candidates_8616,
)


def _make_codegen(statements):
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=Arch86_16()),
        cfunc=SimpleNamespace(addr=0x1000),
        cstyle_null_cmp=False,
    )
    codegen.cfunc.statements = structured_c.CStatements(statements, codegen=codegen)
    return codegen


def _global_var(addr: int, codegen):
    return structured_c.CVariable(
        SimMemoryVariable(addr, 1, name=f"g_{addr:x}", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _const(value: int, codegen):
    return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(name: str, codegen):
    reg_offset, reg_size = codegen.project.arch.registers[name]
    return structured_c.CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _ds_deref(offset: int, codegen):
    return structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp("Mul", _reg("ds", codegen), _const(16, codegen), codegen=codegen),
            _const(offset, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def test_word_global_store_candidate_extraction_detects_adjacent_constants():
    codegen = _make_codegen([])
    stmt0 = structured_c.CAssignment(
        _global_var(0x2000, codegen),
        structured_c.CConstant(0x12, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    stmt1 = structured_c.CAssignment(
        _global_var(0x2001, codegen),
        structured_c.CConstant(0x34, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([stmt0, stmt1], codegen=codegen)
    project = SimpleNamespace(arch=SimpleNamespace())

    candidates = describe_word_global_constant_store_candidates_8616(project, codegen)

    assert candidates == (WordGlobalStoreCandidate(0x2000, 0x2001, "constant"),)


def test_word_global_store_coalescer_promotes_constant_pairs():
    codegen = _make_codegen([])
    stmt0 = structured_c.CAssignment(
        _global_var(0x2000, codegen),
        structured_c.CConstant(0x12, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    stmt1 = structured_c.CAssignment(
        _global_var(0x2001, codegen),
        structured_c.CConstant(0x34, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([stmt0, stmt1], codegen=codegen)
    project = SimpleNamespace(arch=SimpleNamespace())

    changed = _coalesce_word_global_constant_stores_8616(project, codegen)

    assert 0x2000 in changed
    assert len(codegen.cfunc.statements.statements) == 1


def test_word_global_store_candidate_extraction_ignores_segmented_ds_dereferences():
    codegen = _make_codegen([])
    stmt0 = structured_c.CAssignment(
        _ds_deref(0x2000, codegen),
        _const(0x12, codegen),
        codegen=codegen,
    )
    stmt1 = structured_c.CAssignment(
        _ds_deref(0x2001, codegen),
        _const(0x34, codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([stmt0, stmt1], codegen=codegen)
    project = SimpleNamespace(arch=codegen.project.arch)

    candidates = describe_word_global_constant_store_candidates_8616(project, codegen)
    changed = _coalesce_word_global_constant_stores_8616(project, codegen)

    assert candidates == ()
    assert changed == set()
    assert len(codegen.cfunc.statements.statements) == 2


def test_word_global_load_coalescer_ignores_segmented_ds_dereferences():
    codegen = _make_codegen([])
    expr = structured_c.CBinaryOp(
        "Or",
        _ds_deref(0x2000, codegen),
        structured_c.CBinaryOp("Shl", _ds_deref(0x2001, codegen), _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([structured_c.CReturn(expr, codegen=codegen)], codegen=codegen)
    project = SimpleNamespace(arch=codegen.project.arch)

    changed = _coalesce_word_global_loads_8616(project, codegen)
    returned = codegen.cfunc.statements.statements[0].retval

    assert changed == set()
    assert isinstance(returned, structured_c.CBinaryOp)
