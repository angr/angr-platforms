from __future__ import annotations

from types import SimpleNamespace

import decompile
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar
from angr.sim_variable import SimMemoryVariable, SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16


def test_memory_prune_keeps_observable_global_and_drops_dead_global() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen = SimpleNamespace(
        cfunc=cfunc,
        project=project,
        next_idx=lambda _name: 0,
        cstyle_null_cmp=False,
    )

    used_var = SimMemoryVariable(0x200, 1, name="g_200", region=0x10010)
    dead_var = SimMemoryVariable(0x201, 1, name="g_201", region=0x10010)
    used_cvar = structured_c.CVariable(used_var, codegen=codegen)
    dead_cvar = structured_c.CVariable(dead_var, codegen=codegen)
    cfunc.variables_in_use = {
        used_var: used_cvar,
        dead_var: dead_cvar,
    }
    cfunc.unified_local_vars = {
        used_var: {(used_cvar, SimTypeChar(False))},
        dead_var: {(dead_cvar, SimTypeChar(False))},
    }
    cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                structured_c.CVariable(
                    SimStackVariable(0, 1, base="bp", name="s_0", region=0x10010),
                    codegen=codegen,
                ),
                used_cvar,
                codegen=codegen,
            )
        ],
        addr=0x10010,
        codegen=codegen,
    )

    changed = decompile._prune_unused_unnamed_memory_declarations(codegen)

    assert changed is True
    assert used_var in cfunc.variables_in_use
    assert dead_var not in cfunc.variables_in_use
    assert used_var in cfunc.unified_local_vars
    assert dead_var not in cfunc.unified_local_vars
