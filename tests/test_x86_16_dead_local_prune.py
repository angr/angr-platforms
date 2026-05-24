from __future__ import annotations

from types import SimpleNamespace

import decompile
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeInt, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16


class _FakeCodegen:
    def __init__(self):
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name):
        self._idx += 1
        return self._idx


def test_prune_dead_local_assignments_keeps_side_effecting_rhs() -> None:
    codegen = _FakeCodegen()
    local_var = SimStackVariable(-2, 2, base="bp", name="local", region=0x1000)
    local_cvar = structured_c.CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    call_expr = structured_c.CFunctionCall(
        "helper",
        SimTypeInt(False),
        args=(),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [structured_c.CAssignment(local_cvar, call_expr, codegen=codegen)],
            codegen=codegen,
        ),
        variables_in_use={local_var: local_cvar},
    )

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 1


def test_prune_dead_local_assignments_drops_duplicate_call_before_return() -> None:
    codegen = _FakeCodegen()
    arg_var = SimRegisterVariable(0, 2, name="arg")
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    call_expr = structured_c.CFunctionCall(
        "helper",
        SimTypeInt(False),
        args=(arg_cvar,),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [
                call_expr,
                structured_c.CReturn(
                    structured_c.CFunctionCall(
                        "helper",
                        SimTypeInt(False),
                        args=(structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen),),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
            ],
            codegen=codegen,
        ),
        variables_in_use={arg_var: arg_cvar},
    )

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    assert isinstance(codegen.cfunc.statements.statements[0], structured_c.CReturn)
