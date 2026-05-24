from __future__ import annotations

from types import SimpleNamespace

import pytest

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CBinaryOp, CConstant, CFunctionCall, CStatements, CUnaryOp, CVariable
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.c_runtime_header import render_c_runtime_header_8616
from angr_platforms.X86_16.lowering.segmented_memory_lowering import (
    apply_runtime_segment_lowering_8616,
    lower_runtime_segment_access_8616,
    lower_runtime_segment_address_8616,
)
from angr_platforms.X86_16.pipeline.architecture_guard import assert_final_c_quality_8616
from inertia_decompiler.cli_arg_parser import _build_cli_argument_parser
from inertia_decompiler.recompile_check import check_c_recompiles_8616


class _DummyCodegen:
    def __init__(self, project):
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _project():
    project = SimpleNamespace(arch=Arch86_16(), _inertia_c_target="portable-flat")
    codegen = _DummyCodegen(project)
    root = CStatements([], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root, variables_in_use={}, unified_local_vars={})
    return project, codegen


def _const(value: int, codegen, sim_type=None):
    return CConstant(value, sim_type or SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _seg_linear(project, seg_name: str, offset_expr, codegen, *, shl: bool = False):
    segment = _reg(project, seg_name, codegen)
    scale = _const(4 if shl else 16, codegen)
    op = "Shl" if shl else "Mul"
    return CBinaryOp("Add", CBinaryOp(op, segment, scale, codegen=codegen), offset_expr, codegen=codegen)


def test_lower_runtime_segment_access_rewrites_ds_word_dereference_to_seg_u16():
    project, codegen = _project()
    operand = _seg_linear(project, "ds", _const(0x0BA2, codegen), codegen)
    operand._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    expr = CUnaryOp("Dereference", operand, codegen=codegen)

    lowered = lower_runtime_segment_access_8616(expr, target="portable-flat")

    assert isinstance(lowered, CFunctionCall)
    assert lowered.callee_target == "SEG_U16"
    assert lowered.args[0].variable.name == "ds"
    assert lowered.args[1].value == 0x0BA2


def test_lower_runtime_segment_access_rewrites_es_byte_runtime_offset_to_seg_u8():
    project, codegen = _project()
    di = _reg(project, "di", codegen)
    offset = CBinaryOp("Add", di, _const(4, codegen), codegen=codegen)
    operand = _seg_linear(project, "es", offset, codegen, shl=True)
    operand._type = SimTypePointer(SimTypeChar(False)).with_arch(project.arch)
    expr = CUnaryOp("Dereference", operand, codegen=codegen)

    lowered = lower_runtime_segment_access_8616(expr, target="msc-dos")

    assert isinstance(lowered, CFunctionCall)
    assert lowered.callee_target == "SEG_U8"
    assert lowered.args[0].variable.name == "es"
    assert isinstance(lowered.args[1], CBinaryOp)
    assert lowered.args[1].op == "Add"


def test_lower_runtime_segment_address_rewrites_to_mk_fp():
    project, codegen = _project()
    bx = _reg(project, "bx", codegen)
    expr = _seg_linear(project, "ds", bx, codegen)

    lowered = lower_runtime_segment_address_8616(expr, target="portable-flat")

    assert isinstance(lowered, CFunctionCall)
    assert lowered.callee_target == "MK_FP"
    assert lowered.args[0].variable.name == "ds"
    assert lowered.args[1] is bx


def test_apply_runtime_segment_lowering_rewrites_nested_ds_accesses():
    project, codegen = _project()
    result_var = CVariable(SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010), codegen=codegen)
    operand = _seg_linear(project, "ds", _const(2978, codegen), codegen)
    operand._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    deref = CUnaryOp("Dereference", operand, codegen=codegen)
    stmt = CAssignment(result_var, CBinaryOp("Sub", deref, _const(1, codegen), codegen=codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements([stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_runtime_segment_lowering_8616(codegen, target="portable-flat")

    assert changed is True
    lowered_rhs = codegen.cfunc.statements.statements[0].rhs.lhs
    assert isinstance(lowered_rhs, CFunctionCall)
    assert lowered_rhs.callee_target == "SEG_U16"


def test_apply_runtime_segment_lowering_preserves_ss_stack_dereferences():
    project, codegen = _project()
    ss = _reg(project, "ss", codegen)
    stack_ref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
            CUnaryOp("Reference", CVariable(SimStackVariable(-2, 2, base="bp", name="local", region=0x4010), codegen=codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    assert lower_runtime_segment_access_8616(stack_ref, target="portable-flat") is None


def test_architecture_guard_rejects_raw_linear_segment_arithmetic():
    with pytest.raises(Exception):
        assert_final_c_quality_8616("x = *((unsigned short *)((ds << 4) + 2978));", function_addr=0x10498)


def test_architecture_guard_accepts_segment_helpers():
    assert_final_c_quality_8616("x = SEG_U16(ds, 2978);\ny = MK_FP(es, di + 4);\n", function_addr=0x10498)


def test_segment_linearization_through_tmp_is_rejected():
    with pytest.raises(Exception):
        assert_final_c_quality_8616(
            "unsigned short tmp;\nunsigned long linear;\n"
            "tmp = ss;\n"
            "linear = tmp << 4;\n",
            function_addr=0x10498,
        )
    with pytest.raises(Exception):
        assert_final_c_quality_8616(
            "unsigned short tmp;\nunsigned long linear;\n"
            "tmp = ds;\n"
            "linear = tmp * 16;\n",
            function_addr=0x10498,
        )
    assert_final_c_quality_8616(
        "p = SEG_PTR(ds, off);\n"
        "x = SEG_U16(ds, off);\n"
        "y = MK_FP(ds, off);\n",
        function_addr=0x10498,
    )


def test_architecture_guard_rejects_heapsort_constant_percolatedown_arg():
    with pytest.raises(Exception):
        assert_final_c_quality_8616(
            "short HeapSort(void)\n{\n    PercolateDown(3);\n}\n",
            function_addr=0x10970,
        )


def test_architecture_guard_rejects_heapsort_reversed_swapbars_args():
    with pytest.raises(Exception):
        assert_final_c_quality_8616(
            "short HeapSort(void)\n{\n    SwapBars(i, 0);\n}\n",
            function_addr=0x10970,
        )


def test_architecture_guard_accepts_heapsort_pointer_and_value_arg_shapes():
    assert_final_c_quality_8616(
        "short HeapSort(void)\n"
        "{\n"
        "    PercolateUp(i);\n"
        "    Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, 2892 + (i << 1)));\n"
        "    SwapBars(0, i);\n"
        "    PercolateDown(i - 1);\n"
        "}\n",
        function_addr=0x10970,
    )


def test_architecture_guard_rejects_heapsort_stack_placeholder_noise():
    with pytest.raises(Exception):
        assert_final_c_quality_8616(
            "short HeapSort(void)\n"
            "{\n"
            "    char s_4;\n"
            "    vvar_23 = &s_4 + 2;\n"
            "    Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, 2892 + (i << 1)));\n"
            "    SwapBars(0, i);\n"
            "    PercolateDown(i - 1);\n"
            "}\n",
            function_addr=0x10970,
        )


def test_render_c_runtime_header_portable_flat_exposes_seg_macros():
    header = render_c_runtime_header_8616("portable-flat")

    assert "extern uint8_t inertia_memory[];" in header
    assert "#define SEG_U16(seg, off)" in header
    assert "#define MK_FP(seg, off)" in header


def test_render_c_runtime_header_msc_dos_uses_far_mk_fp():
    header = render_c_runtime_header_8616("msc-dos")

    assert "#include <dos.h>" in header
    assert "SEG_U16" in header
    assert "far *)MK_FP" in header


def test_cli_arg_parser_accepts_c_target():
    parser = _build_cli_argument_parser()

    args = parser.parse_args(["sample.exe", "--c-target", "msc-dos"])

    assert args.c_target == "msc-dos"


def test_recompile_check_accepts_simple_portable_flat_c():
    result = check_c_recompiles_8616(
        "int demo(unsigned short ds) { return (int)SEG_U16(ds, 0x0BA2); }\n",
        target="portable-flat",
    )

    assert result.passed is True, result.stderr
