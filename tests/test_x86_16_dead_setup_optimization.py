from __future__ import annotations

from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable

from angr_platforms.angr_platforms.X86_16.postprocess.optimization.dead_setup import (
    _count_dead_setup_escaped_8616,
    _prune_dead_setup_carriers_8616,
)


def _mk_codegen_with_statements(statements):
    class _FakeCodegen(SimpleNamespace):
        def __init__(self):
            super().__init__()
            self._next = 0
            self.project = SimpleNamespace(arch=archinfo.ArchX86())
            self.cstyle_null_cmp = False

        def next_idx(self, _kind: str) -> int:
            self._next += 1
            return self._next

    codegen = _FakeCodegen()
    codegen.cfunc = SimpleNamespace()
    codegen.cfunc.statements = structured_c.CStatements(list(statements), codegen=codegen)
    return codegen


def _mk_reg_var(name: str, reg: int):
    return SimRegisterVariable(reg, 2, name=name)


def _mk_cvar(codegen, name: str, reg: int):
    return structured_c.CVariable(
        _mk_reg_var(name, reg),
        codegen=codegen,
    )


def test_dead_setup_prunes_unread_setup_carrier_and_updates_counters():
    codegen = _mk_codegen_with_statements([])
    vvar_1 = _mk_cvar(codegen, "vvar_1", 0)
    base = _mk_cvar(codegen, "local_6", 2)
    rhs = structured_c.CBinaryOp(
        "Add",
        base,
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    setup_assign = structured_c.CAssignment(vvar_1, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([setup_assign], codegen=codegen)

    codegen._inertia_enable_safe_dead_setup_prune = True
    changed = _prune_dead_setup_carriers_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dead_setup_candidates", 0) >= 1
    assert getattr(codegen, "dead_setup_pruned", 0) >= 1
    assert _count_dead_setup_escaped_8616(codegen) == 0


def test_dead_setup_live_carrier_is_not_pruned_or_escaped():
    codegen = _mk_codegen_with_statements([])
    vvar_1 = _mk_cvar(codegen, "vvar_1", 0)
    base = _mk_cvar(codegen, "s_6", 2)
    sink = _mk_cvar(codegen, "s_8", 4)
    rhs = structured_c.CBinaryOp(
        "Add",
        base,
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    setup_assign = structured_c.CAssignment(vvar_1, rhs, codegen=codegen)
    use_assign = structured_c.CAssignment(sink, vvar_1, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([setup_assign, use_assign], codegen=codegen)

    codegen._inertia_enable_safe_dead_setup_prune = True
    changed = _prune_dead_setup_carriers_8616(codegen)

    assert changed is False
    assert len(list(codegen.cfunc.statements.statements)) == 2
    assert getattr(codegen, "dead_setup_refused", 0) >= 1
    # Live setup carriers are not considered escaped dead artifacts.
    assert _count_dead_setup_escaped_8616(codegen) == 0


def test_dead_setup_escape_counter_flags_unpruned_dead_candidate():
    codegen = _mk_codegen_with_statements([])
    vvar_1 = _mk_cvar(codegen, "vvar_1", 0)
    base = _mk_cvar(codegen, "s_6", 2)
    rhs = structured_c.CBinaryOp(
        "Add",
        base,
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    # Deliberately keep an unread setup carrier in final statements to validate
    # that escape counting catches it.
    setup_assign = structured_c.CAssignment(vvar_1, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([setup_assign], codegen=codegen)

    assert _count_dead_setup_escaped_8616(codegen) == 1


def test_dead_setup_prune_is_disabled_by_default():
    codegen = _mk_codegen_with_statements([])
    vvar_1 = _mk_cvar(codegen, "vvar_1", 0)
    base = _mk_cvar(codegen, "local_6", 2)
    rhs = structured_c.CBinaryOp(
        "Add",
        base,
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    setup_assign = structured_c.CAssignment(vvar_1, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([setup_assign], codegen=codegen)

    changed = _prune_dead_setup_carriers_8616(codegen)

    assert changed is True
    assert len(list(codegen.cfunc.statements.statements)) == 0
    assert getattr(codegen, "dead_setup_pruned", 0) >= 1


def test_dead_setup_prune_can_be_forced_disabled_with_env(monkeypatch):
    codegen = _mk_codegen_with_statements([])
    vvar_1 = _mk_cvar(codegen, "vvar_1", 0)
    base = _mk_cvar(codegen, "s_6", 2)
    rhs = structured_c.CBinaryOp(
        "Add",
        base,
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    setup_assign = structured_c.CAssignment(vvar_1, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([setup_assign], codegen=codegen)
    monkeypatch.setenv("INERTIA_DISABLE_DEAD_SETUP_PRUNE", "1")

    changed = _prune_dead_setup_carriers_8616(codegen)

    assert changed is False
    assert len(list(codegen.cfunc.statements.statements)) == 1
    assert getattr(codegen, "dead_setup_prune_disabled", 0) >= 1
