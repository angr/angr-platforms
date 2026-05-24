from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.alias_domains import AX, BX
from angr_platforms.X86_16.alias_state import AliasState
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_simplify import _simplify_structured_expressions_8616


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _codegen(expr):
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=expr, body=expr)
    return codegen


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(name: str, reg: int, codegen):
    return CVariable(SimRegisterVariable(reg, 1, name=name), variable_type=SimTypeShort(False), codegen=codegen)


def _stack(offset: int, codegen):
    return CVariable(
        SimStackVariable(offset, 1, base="bp", name=f"s_{offset & 0xFFFF:x}", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _global(addr: int, codegen):
    return CVariable(SimMemoryVariable(addr, 1, name=f"g_{addr:x}"), variable_type=SimTypeShort(False), codegen=codegen)


def _byte_pair(low, high, codegen):
    return CBinaryOp(
        "Or",
        low,
        CBinaryOp("Shl", high, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )


def test_alias_widening_folds_al_ah_to_ax_only_with_alias_proof():
    codegen = _codegen(None)
    low = _reg("al", 0, codegen)
    high = _reg("ah", 1, codegen)
    expr = _byte_pair(low, high, codegen)
    codegen.cfunc.statements = expr
    codegen.cfunc.body = expr
    codegen._inertia_alias_state = AliasState()
    codegen._inertia_alias_state.bump_domain(AX)

    changed = _simplify_structured_expressions_8616(codegen)

    assert changed is True
    result = codegen.cfunc.statements
    assert isinstance(result, CVariable)
    assert isinstance(result.variable, SimRegisterVariable)
    assert result.variable.name == "ax"
    assert result.variable.size == 2


def test_alias_widening_refuses_register_join_without_matching_alias_version():
    codegen = _codegen(None)
    low = _reg("al", 0, codegen)
    high = _reg("ah", 1, codegen)
    expr = _byte_pair(low, high, codegen)
    codegen.cfunc.statements = expr
    codegen.cfunc.body = expr
    codegen._inertia_alias_state = AliasState()
    codegen._inertia_alias_state.bump_domain(BX)

    changed = _simplify_structured_expressions_8616(codegen)

    assert changed is False
    assert isinstance(codegen.cfunc.statements, CBinaryOp)


def test_alias_widening_folds_adjacent_stack_bytes_only_when_alias_proof_exists():
    codegen = _codegen(None)
    low = _stack(-4, codegen)
    high = _stack(-3, codegen)
    expr = _byte_pair(low, high, codegen)
    codegen.cfunc.statements = expr
    codegen.cfunc.body = expr

    changed = _simplify_structured_expressions_8616(codegen)

    assert changed is True
    result = codegen.cfunc.statements
    assert isinstance(result, CVariable)
    assert isinstance(result.variable, SimStackVariable)
    assert result.variable.offset == -4
    assert result.variable.size == 2


def test_alias_widening_refuses_mixed_domain_byte_pair():
    codegen = _codegen(None)
    low = _stack(-4, codegen)
    high = _global(0x2001, codegen)
    expr = _byte_pair(low, high, codegen)
    codegen.cfunc.statements = expr
    codegen.cfunc.body = expr

    changed = _simplify_structured_expressions_8616(codegen)

    assert changed is False
    assert isinstance(codegen.cfunc.statements, CBinaryOp)
