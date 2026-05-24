from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall, CStatements
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeShort

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.decompiler_postprocess_calls import _materialize_callsite_prototypes_8616


class _DummyCodegen:
    def __init__(self, project):
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def test_materialize_callsite_prototypes_seeds_arg_count_and_return_type():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen(project)
    callee = SimpleNamespace(prototype=None, is_prototype_guessed=False)
    call = CFunctionCall(None, callee, [], codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register="ax",
            return_used=True,
        )
    }

    changed = _materialize_callsite_prototypes_8616(project, codegen)

    assert changed is True
    assert len(callee.prototype.args) == 2
    assert all(isinstance(arg, SimTypeShort) for arg in callee.prototype.args)
    assert isinstance(callee.prototype.returnty, SimTypeShort)
    assert tuple(callee.prototype.arg_names) == ("a0", "a1")
    assert callee.is_prototype_guessed is True


def test_materialize_callsite_prototypes_keeps_existing_meaningful_prototype():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen(project)
    existing_proto = SimTypeFunction([SimTypeShort(False)], SimTypeShort(False), arg_names=("value",)).with_arch(project.arch)
    callee = SimpleNamespace(prototype=existing_proto, is_prototype_guessed=False)
    call = CFunctionCall(None, callee, [], codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register="ax",
            return_used=True,
        )
    }

    changed = _materialize_callsite_prototypes_8616(project, codegen)

    assert changed is False
    assert callee.prototype is existing_proto
