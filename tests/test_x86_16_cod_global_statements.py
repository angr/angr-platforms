from __future__ import annotations

from types import SimpleNamespace

import decompile
import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimMemoryVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16


class _FakeCodegen:
    def __init__(self):
        self._idx = 0
        self.cfunc = SimpleNamespace(addr=0x1000)
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name):
        self._idx += 1
        return self._idx


def _byte_global(addr: int, codegen: _FakeCodegen):
    return structured_c.CVariable(
        SimMemoryVariable(addr, 1, name=f"g_{addr:x}", region=0x1000),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )


def test_coalesce_cod_word_global_statements_merges_adjacent_byte_stores(monkeypatch: pytest.MonkeyPatch) -> None:
    codegen = _FakeCodegen()
    low = _byte_global(0x2000, codegen)
    high = _byte_global(0x2001, codegen)
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(low, structured_c.CConstant(0x34, SimTypeChar(False), codegen=codegen), codegen=codegen),
            structured_c.CAssignment(high, structured_c.CConstant(0x12, SimTypeChar(False), codegen=codegen), codegen=codegen),
        ],
        codegen=codegen,
    )
    monkeypatch.setattr(
        decompile,
        "_high_byte_store_addr",
        lambda node, _project: 0x2001 if node is high else None,
    )

    changed = decompile._coalesce_cod_word_global_statements(
        SimpleNamespace(),
        codegen,
        {0x2000: ("word_global", 2)},
    )

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, structured_c.CAssignment)
    assert getattr(stmt.lhs.variable, "addr", None) == 0x2000
    assert stmt.rhs.value == 0x1234
    assert isinstance(stmt.lhs.variable_type, SimTypeShort)


def test_coalesce_cod_word_global_statements_refuses_non_adjacent_store_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    codegen = _FakeCodegen()
    low = _byte_global(0x2000, codegen)
    high = _byte_global(0x2002, codegen)
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(low, structured_c.CConstant(0x34, SimTypeChar(False), codegen=codegen), codegen=codegen),
            structured_c.CAssignment(high, structured_c.CConstant(0x12, SimTypeChar(False), codegen=codegen), codegen=codegen),
        ],
        codegen=codegen,
    )
    monkeypatch.setattr(
        decompile,
        "_high_byte_store_addr",
        lambda node, _project: 0x2002 if node is high else None,
    )

    changed = decompile._coalesce_cod_word_global_statements(
        SimpleNamespace(),
        codegen,
        {0x2000: ("word_global", 2)},
    )

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 2
