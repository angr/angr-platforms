from __future__ import annotations

from types import SimpleNamespace

import decompile
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
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


def test_prune_unused_local_declarations_keeps_storage_alias_match() -> None:
    codegen = _FakeCodegen()
    live_var = SimStackVariable(-2, 2, base="bp", name="live", region=0x1000)
    alias_var = SimStackVariable(-2, 2, base="bp", name="alias", region=0x1000)
    dead_var = SimStackVariable(-4, 2, base="bp", name="dead", region=0x1000)
    live_cvar = structured_c.CVariable(live_var, variable_type=SimTypeShort(False), codegen=codegen)
    alias_cvar = structured_c.CVariable(alias_var, variable_type=SimTypeShort(False), codegen=codegen)
    dead_cvar = structured_c.CVariable(dead_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [structured_c.CReturn(live_cvar, codegen=codegen)],
            codegen=codegen,
        ),
        variables_in_use={
            live_var: live_cvar,
            alias_var: alias_cvar,
            dead_var: dead_cvar,
        },
        unified_local_vars={
            alias_var: [(alias_cvar, SimTypeShort(False))],
            dead_var: [(dead_cvar, SimTypeShort(False))],
        },
    )

    changed = decompile._prune_unused_local_declarations(codegen)

    assert changed is True
    assert alias_var in codegen.cfunc.variables_in_use
    assert dead_var not in codegen.cfunc.variables_in_use
    assert alias_var in codegen.cfunc.unified_local_vars
    assert dead_var not in codegen.cfunc.unified_local_vars


def test_prune_unused_linear_register_declarations_prunes_only_temp_names() -> None:
    codegen = _FakeCodegen()
    live_var = SimRegisterVariable(0, 2, name="v1")
    dead_temp = SimRegisterVariable(2, 2, name="v2")
    named_reg = SimRegisterVariable(4, 2, name="ax_saved")
    live_cvar = structured_c.CVariable(live_var, variable_type=SimTypeShort(False), codegen=codegen)
    dead_temp_cvar = structured_c.CVariable(dead_temp, variable_type=SimTypeShort(False), codegen=codegen)
    named_reg_cvar = structured_c.CVariable(named_reg, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [structured_c.CReturn(live_cvar, codegen=codegen)],
            codegen=codegen,
        ),
        variables_in_use={
            live_var: live_cvar,
            dead_temp: dead_temp_cvar,
            named_reg: named_reg_cvar,
        },
        unified_local_vars={
            dead_temp: [(dead_temp_cvar, SimTypeShort(False))],
            named_reg: [(named_reg_cvar, SimTypeShort(False))],
        },
    )

    changed = decompile._prune_unused_linear_register_declarations(codegen)

    assert changed is True
    assert dead_temp not in codegen.cfunc.variables_in_use
    assert dead_temp not in codegen.cfunc.unified_local_vars
    assert named_reg in codegen.cfunc.variables_in_use
    assert named_reg in codegen.cfunc.unified_local_vars
