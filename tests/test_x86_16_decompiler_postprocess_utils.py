from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CUnaryOp, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_loads import (
    _global_load_addr_8616,
    _match_global_scaled_high_byte_8616,
    _segmented_load_addr_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_utils import (
    _match_real_mode_linear_expr_8616,
)


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _segmented_linear(project, seg_name: str, offset: int, codegen):
    seg = _reg(project, seg_name, codegen)
    return CBinaryOp(
        "Add",
        CBinaryOp("Mul", seg, _const(16, codegen), codegen=codegen),
        _const(offset, codegen),
        codegen=codegen,
    )


def _global_deref(addr: int, codegen):
    return CVariable(
        SimMemoryVariable(addr, 1),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def test_postprocess_utils_do_not_infer_ds_from_bare_constant():
    project = _project()
    codegen = _DummyCodegen()
    deref = CUnaryOp("Dereference", _const(0x234, codegen), codegen=codegen)

    assert _match_real_mode_linear_expr_8616(_const(0x234, codegen), project) == (None, None)
    assert _global_load_addr_8616(deref) is None
    assert _segmented_load_addr_8616(deref, project) == (None, None)


def test_postprocess_utils_match_explicit_segment_times_16_plus_offset():
    project = _project()
    codegen = _DummyCodegen()

    assert _match_real_mode_linear_expr_8616(_segmented_linear(project, "ds", 0x234, codegen), project) == ("ds", 0x234)
    assert _match_real_mode_linear_expr_8616(_segmented_linear(project, "ss", 0x18, codegen), project) == ("ss", 0x18)


def test_postprocess_utils_match_ss_shift_by_four_as_linear_segment_form():
    project = _project()
    codegen = _DummyCodegen()
    ss = _reg(project, "ss", codegen)
    expr = CBinaryOp("Shl", ss, _const(4, codegen), codegen=codegen)

    assert _match_real_mode_linear_expr_8616(expr, project) == ("ss", 0)


def test_postprocess_utils_keep_ds_dereference_loads_explicit():
    project = _project()
    codegen = _DummyCodegen()
    deref = CUnaryOp("Dereference", _segmented_linear(project, "ds", 0x234, codegen), codegen=codegen)

    assert _global_load_addr_8616(deref) is None
    assert _segmented_load_addr_8616(deref, project) == ("ds", 0x234)


def test_postprocess_utils_match_scaled_high_byte_only_for_true_globals():
    codegen = _DummyCodegen()
    global_high = CBinaryOp("Mul", _global_deref(0x235, codegen), _const(0x100, codegen), codegen=codegen)
    ds_deref = CUnaryOp("Dereference", _segmented_linear(_project(), "ds", 0x235, codegen), codegen=codegen)
    ds_high = CBinaryOp("Mul", ds_deref, _const(0x100, codegen), codegen=codegen)

    assert _match_global_scaled_high_byte_8616(global_high) == 0x235
    assert _match_global_scaled_high_byte_8616(ds_high) is None
