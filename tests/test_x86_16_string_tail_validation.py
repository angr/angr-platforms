from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CConstant, CReturn, CStatements
from angr.sim_type import SimTypeShort

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.string_instruction_artifact import StringInstructionArtifact, StringInstructionRecord
from angr_platforms.X86_16.string_instruction_lowering import apply_x86_16_string_instruction_lowering
from angr_platforms.X86_16.tail_validation import collect_x86_16_tail_validation_summary


class _DummyCodegen:
    def __init__(self, arch):
        self._idx = 0
        self.project = SimpleNamespace(arch=arch)
        self.cfunc = None
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def test_string_instruction_lowering_is_tail_validation_neutral():
    arch = Arch86_16()
    codegen = _DummyCodegen(arch)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        body=CStatements(
            [CReturn(CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen)],
            addr=0x4010,
            codegen=codegen,
        ),
    )
    codegen._inertia_string_instruction_artifact = StringInstructionArtifact(
        records=(
            StringInstructionRecord(
                index=0,
                family="movs",
                mnemonic="movs",
                repeat_kind="rep",
                width=1,
                source_segment="ds",
                destination_segment="es",
                direction_mode="forward",
                zero_seeded_accumulator=None,
                zf_sensitive=False,
            ),
        )
    )
    function = SimpleNamespace(addr=0x4010, info={})
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function if addr == 0x4010 else None)),
    )

    before = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")
    changed = apply_x86_16_string_instruction_lowering(project, codegen)
    after = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    assert changed is False
    assert before == after
