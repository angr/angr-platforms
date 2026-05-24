from __future__ import annotations

from angr_platforms.X86_16.ir import (
    AddressStatus,
    IRAddress,
    MemSpace,
    SegmentOrigin,
    build_x86_16_typed_string_effect_artifact,
)
from angr_platforms.X86_16.string_instruction_artifact import (
    StringInstructionArtifact,
    StringInstructionRecord,
    StringInstructionRefusal,
)


def test_typed_string_effect_artifact_maps_movs_to_typed_addresses():
    raw_artifact = StringInstructionArtifact(
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

    artifact = build_x86_16_typed_string_effect_artifact(raw_artifact)

    record = artifact.records[0]
    assert record.source == IRAddress(
        space=MemSpace.DS,
        base=("si",),
        size=2,
        status=AddressStatus.PROVISIONAL,
        segment_origin=SegmentOrigin.PROVEN,
        expr=("movs_source",),
    )
    assert record.destination == IRAddress(
        space=MemSpace.ES,
        base=("di",),
        size=2,
        status=AddressStatus.PROVISIONAL,
        segment_origin=SegmentOrigin.PROVEN,
        expr=("movs_destination",),
    )


def test_typed_string_effect_artifact_preserves_refusal_kinds():
    raw_artifact = StringInstructionArtifact(
        refusals=(
            StringInstructionRefusal("mixed_direction_signal", "mixed"),
            StringInstructionRefusal("other", "detail"),
        )
    )

    artifact = build_x86_16_typed_string_effect_artifact(raw_artifact)

    assert artifact.refusal_kinds == ("mixed_direction_signal", "other")
