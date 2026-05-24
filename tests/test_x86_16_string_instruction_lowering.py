from __future__ import annotations

from angr_platforms.X86_16.string_instruction_artifact import (
    StringInstructionArtifact,
    StringInstructionRecord,
    StringInstructionRefusal,
)
from angr_platforms.X86_16.string_instruction_lowering import (
    build_x86_16_string_intrinsic_artifact,
    render_x86_16_string_intrinsic_c,
)


def _record(
    *,
    index: int,
    family: str,
    repeat_kind: str,
    width: int,
    direction_mode: str = "forward",
    zero_seeded_accumulator: bool | None = None,
) -> StringInstructionRecord:
    return StringInstructionRecord(
        index=index,
        family=family,
        mnemonic=family,
        repeat_kind=repeat_kind,
        width=width,
        source_segment="ds" if family in {"movs", "lods", "cmps"} else None,
        destination_segment="es" if family in {"movs", "stos", "scas", "cmps"} else None,
        direction_mode=direction_mode,
        zero_seeded_accumulator=zero_seeded_accumulator,
        zf_sensitive=family in {"scas", "cmps"},
    )


def test_string_instruction_lowering_accepts_rep_movs_as_memcpy_class():
    artifact = StringInstructionArtifact(records=(_record(index=0, family="movs", repeat_kind="rep", width=1),))

    lowered = build_x86_16_string_intrinsic_artifact(artifact)

    assert tuple(item.family for item in lowered.records) == ("memcpy_class",)


def test_string_instruction_lowering_accepts_repne_scas_zero_seed_as_strlen_class():
    artifact = StringInstructionArtifact(
        records=(_record(index=0, family="scas", repeat_kind="repnz", width=1, zero_seeded_accumulator=True),)
    )

    lowered = build_x86_16_string_intrinsic_artifact(artifact)

    assert tuple(item.family for item in lowered.records) == ("strlen_class",)
    assert "__x86_16_scas_zterm_len" in render_x86_16_string_intrinsic_c("strlen_like", lowered)
    assert "__x86_16_string_state" not in render_x86_16_string_intrinsic_c("strlen_like", lowered)


def test_string_instruction_lowering_combines_strlen_then_movs_into_strlen_copy_class():
    artifact = StringInstructionArtifact(
        records=(
            _record(index=0, family="scas", repeat_kind="repnz", width=1, zero_seeded_accumulator=True),
            _record(index=1, family="movs", repeat_kind="rep", width=1),
        )
    )

    lowered = build_x86_16_string_intrinsic_artifact(artifact)
    rendered = render_x86_16_string_intrinsic_c("strcpy_like", lowered)

    assert tuple(item.family for item in lowered.records) == ("strlen_copy_class",)
    assert "__x86_16_scas_zterm_len" in rendered
    assert "__x86_16_movs(&__x86_16_state, 1);" in rendered


def test_string_instruction_lowering_preserves_explicit_refusal_state():
    artifact = StringInstructionArtifact(
        records=(_record(index=0, family="movs", repeat_kind="rep", width=1),),
        refusals=(StringInstructionRefusal("mixed_direction_signal", "both directions observed"),),
    )

    lowered = build_x86_16_string_intrinsic_artifact(artifact)

    assert lowered.records == ()
    assert tuple(item.kind for item in lowered.refusals) == ("mixed_direction_signal",)


def test_string_instruction_lowering_accepts_mixed_direction_movs_as_overlap_copy_class():
    artifact = StringInstructionArtifact(
        records=(
            _record(index=0, family="movs", repeat_kind="rep", width=1, direction_mode="backward"),
            _record(index=1, family="movs", repeat_kind="none", width=1, direction_mode="forward"),
            _record(index=2, family="movs", repeat_kind="rep", width=2, direction_mode="forward"),
        ),
        refusals=(StringInstructionRefusal("mixed_direction_signal", "both directions observed"),),
    )

    lowered = build_x86_16_string_intrinsic_artifact(artifact)
    rendered = render_x86_16_string_intrinsic_c("memcpy_like", lowered)

    assert tuple(item.family for item in lowered.records) == ("memmove_overlap_class",)
    assert lowered.refusals == ()
    assert "__x86_16_movs_overlap_select();" in rendered
    assert "__x86_16_string_state" not in rendered


def test_string_instruction_lowering_accepts_repnz_scas_plus_tail_as_scan_tail_class():
    artifact = StringInstructionArtifact(
        records=(
            _record(index=0, family="scas", repeat_kind="repnz", width=1, zero_seeded_accumulator=False),
            _record(index=1, family="scas", repeat_kind="none", width=1, zero_seeded_accumulator=False),
        )
    )

    lowered = build_x86_16_string_intrinsic_artifact(artifact)
    rendered = render_x86_16_string_intrinsic_c("scan_like", lowered)

    assert tuple(item.family for item in lowered.records) == ("scan_tail_class",)
    assert "__x86_16_scan_tail(1);" in rendered
    assert "__x86_16_string_state" not in rendered


def test_string_instruction_lowering_renders_compact_memset_intrinsic() -> None:
    artifact = StringInstructionArtifact(records=(_record(index=0, family="stos", repeat_kind="rep", width=1),))

    lowered = build_x86_16_string_intrinsic_artifact(artifact)
    rendered = render_x86_16_string_intrinsic_c("clear_mat", lowered)

    assert tuple(item.family for item in lowered.records) == ("memset_class",)
    assert "void __x86_16_stos(unsigned short width);" in rendered
    assert "__x86_16_stos(1);" in rendered
    assert "__x86_16_string_state" not in rendered
