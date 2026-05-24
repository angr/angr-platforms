from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CBinaryOp, CConstant, CStatements, CUnaryOp, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.address_ir import build_address_ir_8616, resolved_operand_to_address_ir_8616
from angr_platforms.X86_16.addressing_helpers import ResolvedMemoryOperand
from angr_platforms.X86_16.ir.core import MemSpace
from angr_platforms.X86_16.regs import sgreg_t
from angr_platforms.X86_16.segmented_memory_reasoning import apply_x86_16_segmented_memory_reasoning


class _DummyCodegen:
    def __init__(self, project):
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _codegen(*, summary=None):
    project = _project()
    codegen = _DummyCodegen(project)
    root = CStatements([], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root, variables_in_use={}, unified_local_vars={})
    codegen._inertia_vex_ir_artifact = SimpleNamespace(summary=summary or {})
    return project, codegen


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _ss_stack_deref(project, stack_offset: int, addend: int, codegen):
    ss = _reg(project, "ss", codegen)
    return CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
            CBinaryOp(
                "Add",
                CUnaryOp("Reference", CVariable(SimStackVariable(stack_offset, 2, base="bp", name="local", region=0x4010), codegen=codegen), codegen=codegen),
                _const(addend, codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def test_segmented_memory_reasoning_refuses_ss_lowering_without_stable_ss_evidence():
    project, codegen = _codegen(summary={"stable_address_space_counts": {"ds": 1}, "address_space_counts": {"ds": 1}})
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                _ss_stack_deref(project, -2, 2, codegen),
                _const(7, codegen),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_x86_16_segmented_memory_reasoning(codegen)

    assert changed is False
    lhs = codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CUnaryOp)
    assert lhs.op == "Dereference"


def test_segmented_memory_reasoning_allows_ss_lowering_with_stable_ss_evidence():
    project, codegen = _codegen(summary={"stable_address_space_counts": {"ss": 1}, "address_space_counts": {"ss": 1}})
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                _ss_stack_deref(project, -2, 2, codegen),
                _const(7, codegen),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    after_codegen = deepcopy(codegen)

    changed = apply_x86_16_segmented_memory_reasoning(after_codegen)

    assert changed is True
    lhs = after_codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CVariable)
    assert isinstance(lhs.variable, SimStackVariable)


def test_segmented_memory_reasoning_allows_ss_lowering_with_provisional_typed_ss_evidence():
    project, codegen = _codegen(summary={"stable_address_space_counts": {"ds": 1}, "address_space_counts": {"ds": 1, "ss": 1}})
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                _ss_stack_deref(project, -2, 2, codegen),
                _const(7, codegen),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    after_codegen = deepcopy(codegen)

    changed = apply_x86_16_segmented_memory_reasoning(after_codegen)

    assert changed is True
    lhs = after_codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CVariable)
    assert isinstance(lhs.variable, SimStackVariable)


def test_address_ir_facade_preserves_segmented_spaces():
    stack = build_address_ir_8616(
        MemSpace.SS,
        ("bp",),
        offset=-4,
        size=2,
    )
    assert stack.to_ir_address().space.value == "ss"

    resolved = ResolvedMemoryOperand(
        sgreg_t.DS,
        8,
        0x1008,
        16,
        16,
    )
    typed = resolved_operand_to_address_ir_8616(resolved)
    assert typed.space.value == "ds"
