from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.ir import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
    build_x86_16_function_ssa,
    build_x86_16_segment_state_artifact,
    build_x86_16_typed_string_effect_artifact,
)
from angr_platforms.X86_16.string_instruction_artifact import StringInstructionArtifact, StringInstructionRecord
from angr_platforms.X86_16.type_array_matching import apply_x86_16_array_expression_matching


def test_segment_state_tracks_explicit_ds_and_es_writes():
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr("MOV", IRValue(MemSpace.REG, name="ds", size=2), (IRValue(MemSpace.REG, name="ax", size=2),)),
                    IRInstr("MOV", IRValue(MemSpace.REG, name="es", size=2), (IRValue(MemSpace.CONST, const=0xB800, size=2),)),
                ),
            ),
        ),
    )

    segment_state = build_x86_16_segment_state_artifact(artifact, function_ssa=build_x86_16_function_ssa(artifact))

    assert segment_state.state_for_register("ds").origin == SegmentOrigin.PROVEN
    assert segment_state.state_for_register("es").origin == SegmentOrigin.PROVEN
    assert segment_state.summary["explicit_write_count"] >= 2


def test_typed_string_effects_become_stable_from_segment_state_and_feed_array_matching():
    segment_ir = IRFunctionArtifact(
        function_addr=0x2000,
        blocks=(
            IRBlock(
                addr=0x2000,
                instrs=(
                    IRInstr("MOV", IRValue(MemSpace.REG, name="ds", size=2), (IRValue(MemSpace.REG, name="ax", size=2),)),
                    IRInstr("MOV", IRValue(MemSpace.REG, name="es", size=2), (IRValue(MemSpace.REG, name="bx", size=2),)),
                ),
            ),
        ),
    )
    segment_state = build_x86_16_segment_state_artifact(segment_ir, function_ssa=build_x86_16_function_ssa(segment_ir))
    string_artifact = build_x86_16_typed_string_effect_artifact(
        StringInstructionArtifact(
            records=(
                StringInstructionRecord(
                    index=0,
                    family="movs",
                    mnemonic="movsw",
                    repeat_kind="rep",
                    width=2,
                    source_segment="ds",
                    destination_segment="es",
                    direction_mode="forward",
                    zero_seeded_accumulator=None,
                    zf_sensitive=False,
                ),
            )
        ),
        segment_state_artifact=segment_state,
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x2000),
        project=None,
        _inertia_string_effect_artifact=string_artifact,
    )

    result = apply_x86_16_array_expression_matching(codegen)

    assert result is False
    assert set(codegen._inertia_array_matching_string_candidates) == {
        ("ds", ("si",), 2),
        ("es", ("di",), 2),
    }
    assert codegen._inertia_array_matching_stats["string_arrays"] == 2


def test_typed_string_effects_without_segment_state_do_not_seed_string_arrays():
    string_artifact = build_x86_16_typed_string_effect_artifact(
        StringInstructionArtifact(
            records=(
                StringInstructionRecord(
                    index=0,
                    family="movs",
                    mnemonic="movsw",
                    repeat_kind="rep",
                    width=2,
                    source_segment="ds",
                    destination_segment="es",
                    direction_mode="forward",
                    zero_seeded_accumulator=None,
                    zf_sensitive=False,
                ),
            )
        )
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x2000),
        project=None,
        _inertia_string_effect_artifact=string_artifact,
    )

    result = apply_x86_16_array_expression_matching(codegen)

    assert result is False
    assert codegen._inertia_array_matching_string_candidates == {}
    assert codegen._inertia_array_matching_stats["string_arrays"] == 0
