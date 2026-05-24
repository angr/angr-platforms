from dataclasses import dataclass
from types import SimpleNamespace

from inertia_decompiler.cli_access_object_hints import (
    AccessTraitObjectHint,
    _build_stable_access_object_hints,
)
from inertia_decompiler.cli_access_profiles import build_access_trait_evidence_profiles
from inertia_decompiler.cli_storage_objects import (
    build_storage_object_artifact,
    build_storage_object_records_from_hints,
    storage_object_record_for_key,
)
from angr_platforms.X86_16.type_storage_object_bridge import load_storage_object_bridge


def test_storage_object_records_preserve_member_offsets_deterministically():
    records = build_storage_object_records_from_hints(
        {
            ("mem", 0x40): AccessTraitObjectHint(
                base_key=("mem", 0x40),
                kind="member",
                candidates=((4, 2, 5), (4, 2, 9), (8, 2, 3)),
            )
        }
    )

    record = records[("mem", 0x40)]
    assert record.object_kind == "member"
    assert record.candidate_offsets == (4, 8)
    assert record.primary_member_offset() == 4


def test_storage_object_record_for_key_supports_regioned_stack_fallback():
    records = build_storage_object_records_from_hints(
        {
            ("stack", "bp", -4): AccessTraitObjectHint(
                base_key=("stack", "bp", -4),
                kind="stack",
                candidates=((0, 2, 1),),
            )
        }
    )

    record = storage_object_record_for_key(records, ("stack", "bp", -4, 0x1000))

    assert record is not None
    assert record.object_kind == "stack"
    assert record.should_rename_stack() is True


def test_storage_object_record_helpers_distinguish_member_and_array_shapes():
    member_record = build_storage_object_records_from_hints(
        {
            ("mem", 0x40): AccessTraitObjectHint(
                base_key=("mem", 0x40),
                kind="member",
                candidates=((4, 2, 5),),
            )
        }
    )[("mem", 0x40)]
    array_record = build_storage_object_records_from_hints(
        {
            ("mem", 0x44): AccessTraitObjectHint(
                base_key=("mem", 0x44),
                kind="array",
                candidates=((0, 2, 3),),
            )
        }
    )[("mem", 0x44)]

    assert member_record.is_member_like() is True
    assert member_record.is_array_like() is False
    assert member_record.is_structural() is True
    assert array_record.is_member_like() is False
    assert array_record.is_array_like() is True
    assert array_record.is_structural() is True


def test_storage_object_artifact_records_refusal_for_mixed_evidence():
    traits = {
        "base_const": {
            ("ss", ("stack", "bp", -4), 4, 2, 1): 1,
        },
        "array_evidence": {
            (("stack", "bp", -4), ("reg", 2), 2, 4, 2): 1,
        },
    }

    artifact = build_storage_object_artifact(
        traits,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        build_stable_access_object_hints=lambda raw_traits: _build_stable_access_object_hints(
            raw_traits,
            build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        ),
    )

    assert artifact.records == {}
    assert artifact.refusals[("stack", "bp", -4)].reason == "mixed_or_unstable_evidence"


def test_storage_object_bridge_exposes_member_array_and_refusal_facts():
    project = type("Project", (), {})()
    project._inertia_access_traits = {
        0x4010: {
            "member_evidence": {
                (("mem", 0x20), 0, 2): 3,
                (("mem", 0x60), 0, 2): 1,
            },
            "array_evidence": {
                (("mem", 0x40), ("reg", "bx"), 2, 4, 2): 2,
                (("mem", 0x60), ("reg", "si"), 2, 4, 2): 1,
            },
            "base_const": {},
            "repeated_offsets": {},
            "repeated_offset_widths": {},
            "base_stride": {},
            "base_stride_widths": {},
            "induction_evidence": {},
            "stride_evidence": {},
        }
    }

    bridge = load_storage_object_bridge(project, 0x4010)

    assert bridge is not None
    assert bridge.stats() == {
        "record_count": 2,
        "member_fact_count": 1,
        "array_fact_count": 1,
        "refusal_fact_count": 1,
    }
    assert bridge.member_facts[("mem", 0x20)].object_kind == "member"
    assert bridge.member_facts[("mem", 0x20)].primary_member_offset == 0
    assert bridge.array_facts[("mem", 0x40)].object_kind == "array"
    assert bridge.refusal_facts[("mem", 0x60)].reason == "mixed_or_unstable_evidence"


@dataclass(frozen=True)
class _BridgeProfile:
    has_evidence: bool = True

    def has_any_evidence(self) -> bool:
        return self.has_evidence


def test_storage_object_bridge_carries_segmented_lowering_state():
    stable_key = ("ss", ("stack", "bp", -4))
    refused_key = ("ds", ("mem", 0x60))
    project = SimpleNamespace(_inertia_access_traits={0x4020: {"member_evidence": {}}})
    codegen = SimpleNamespace(
        _inertia_segmented_memory_lowering={
            "SS": {
                "classification": "single",
                "associated_space": "stack",
                "allow_linear_lowering": True,
                "allow_object_lowering": True,
                "reason": "stable stack segment",
            },
            "DS": {
                "classification": "over_associated",
                "associated_space": "data",
                "allow_linear_lowering": False,
                "allow_object_lowering": False,
                "reason": "multiple segment spaces observed",
            },
        }
    )

    bridge = load_storage_object_bridge(
        project,
        0x4020,
        codegen=codegen,
        build_access_trait_evidence_profiles=lambda _traits: {
            stable_key: _BridgeProfile(),
            refused_key: _BridgeProfile(),
        },
        build_stable_access_object_hints=lambda _traits: {
            stable_key: AccessTraitObjectHint(stable_key, "array", ((0, 2, 3),)),
            refused_key: AccessTraitObjectHint(refused_key, "member", ((2, 2, 2),)),
        },
    )

    assert bridge is not None
    assert bridge.allows_object_lowering(stable_key) is True
    assert bridge.facts_by_base[stable_key].segmented_memory.classification == "single"
    assert bridge.facts_by_base[stable_key].segmented_memory.associated_space == "stack"
    assert bridge.allows_object_lowering(refused_key) is False
    assert bridge.lowering_refusal_reason(refused_key) == "multiple segment spaces observed"
