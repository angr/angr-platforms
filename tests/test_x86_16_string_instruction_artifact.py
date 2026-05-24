from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.string_instruction_artifact import (
    apply_x86_16_string_instruction_artifact,
    build_x86_16_string_instruction_artifact,
)


class _FakeInsn:
    def __init__(self, mnemonic: str, op_str: str = ""):
        self.mnemonic = mnemonic
        self.op_str = op_str


class _FakeBlock:
    def __init__(self, insns):
        self.capstone = SimpleNamespace(insns=tuple(insns))


class _FakeFactory:
    def __init__(self, blocks):
        self._blocks = blocks

    def block(self, addr, opt_level=0):  # noqa: ARG002
        return self._blocks[addr]


def _project_with_blocks(blocks, function):
    return SimpleNamespace(
        factory=_FakeFactory(blocks),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function if addr == function.addr else None)),
    )


def test_string_instruction_artifact_captures_rep_movsb():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project_with_blocks({0x1000: _FakeBlock((_FakeInsn("cld"), _FakeInsn("rep movsb")))}, function)

    artifact = build_x86_16_string_instruction_artifact(project, function)

    assert tuple(item.family for item in artifact.records) == ("movs",)
    record = artifact.records[0]
    assert record.repeat_kind == "rep"
    assert record.width == 1
    assert record.direction_mode == "forward"
    assert record.source_segment == "ds"
    assert record.destination_segment == "es"
    assert artifact.refusals == ()


def test_string_instruction_artifact_captures_repne_scasb_zero_seed():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project_with_blocks(
        {0x1000: _FakeBlock((_FakeInsn("xor", "al, al"), _FakeInsn("repne scasb")))},
        function,
    )

    artifact = build_x86_16_string_instruction_artifact(project, function)

    assert tuple(item.family for item in artifact.records) == ("scas",)
    record = artifact.records[0]
    assert record.repeat_kind == "repnz"
    assert record.width == 1
    assert record.zero_seeded_accumulator is True
    assert record.zf_sensitive is True


def test_string_instruction_artifact_reports_mixed_direction_signal():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project_with_blocks(
        {
            0x1000: _FakeBlock(
                (
                    _FakeInsn("cld"),
                    _FakeInsn("rep movsb"),
                    _FakeInsn("std"),
                    _FakeInsn("rep movsb"),
                )
            )
        },
        function,
    )

    artifact = build_x86_16_string_instruction_artifact(project, function)

    assert tuple(item.kind for item in artifact.refusals) == ("mixed_direction_signal",)


def test_apply_string_instruction_artifact_attaches_to_codegen_and_function_info():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project_with_blocks({0x1000: _FakeBlock((_FakeInsn("cld"), _FakeInsn("rep movsw")))}, function)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    changed = apply_x86_16_string_instruction_artifact(project, codegen)

    assert changed is False
    assert getattr(codegen, "_inertia_string_instruction_artifact").records[0].width == 2
    assert function.info["x86_16_string_instruction_artifact"]["records"][0]["family"] == "movs"
