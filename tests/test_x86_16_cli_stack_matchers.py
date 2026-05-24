from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import decompile
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16


@dataclass(frozen=True)
class _FakeVirtualVariable:
    varid: int


class _FakeDirtyExpression:
    def __init__(self, dirty, codegen):
        self.dirty = dirty
        self.codegen = codegen
        self.type = SimTypeShort(False).with_arch(codegen.project.arch)


def test_match_stack_cvar_and_offset_resolves_dirty_virtual_assignment_chain():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 0,
    )
    stack_var = SimStackVariable(-10, 1, base="bp", name="s_a", region=0x10010)
    stack_cvar = structured_c.CVariable(stack_var, variable_type=SimTypeShort(False).with_arch(project.arch), codegen=codegen)
    temp_var = SimRegisterVariable(0, 2, name="vvar_20")
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False).with_arch(project.arch), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x10010,
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(
                    temp_cvar,
                    structured_c.CBinaryOp(
                        "Add",
                        structured_c.CUnaryOp("Reference", stack_cvar, codegen=codegen),
                        structured_c.CConstant(2, SimTypeShort(False).with_arch(project.arch), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                )
            ],
            addr=0x10010,
            codegen=codegen,
        ),
    )

    dirty_expr = _FakeDirtyExpression(_FakeVirtualVariable(20), codegen)
    expr = structured_c.CBinaryOp(
        "Sub",
        dirty_expr,
        structured_c.CConstant(2, SimTypeShort(False).with_arch(project.arch), codegen=codegen),
        codegen=codegen,
    )

    matched = decompile._match_stack_cvar_and_offset(expr)

    assert matched is not None
    base, offset = matched
    assert base is stack_cvar
    assert offset == 0


def test_match_stack_cvar_and_offset_resolves_indexed_stack_reference():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 0,
    )
    stack_var = SimStackVariable(-6, 1, base="bp", name="s_6", region=0x10010)
    stack_cvar = structured_c.CVariable(stack_var, variable_type=SimTypeShort(False).with_arch(project.arch), codegen=codegen)

    expr = structured_c.CIndexedVariable(
        structured_c.CUnaryOp("Reference", stack_cvar, codegen=codegen),
        structured_c.CConstant(8, SimTypeShort(False).with_arch(project.arch), codegen=codegen),
        codegen=codegen,
    )

    matched = decompile._match_stack_cvar_and_offset(expr)

    assert matched is not None
    base, offset = matched
    assert base is stack_cvar
    assert offset == 8
