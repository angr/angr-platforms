from angr_platforms.X86_16.recompilable_storage_map import (
    RecompilableStorageMapCandidate,
    build_recompilable_storage_map,
)
from angr_platforms.X86_16.recompilable_storage_alias import (
    AliasBackedStorageSeed,
    export_recompilable_storage_map_from_alias_facts,
)
from angr_platforms.X86_16.recompilable_storage_map_producer import (
    SegmentedStorageSeed,
    export_recompilable_storage_map_from_codegen,
)
from angr_platforms.X86_16.alias_model import (
    AliasStorageFacts,
    _StackSlotIdentity,
    _StorageDomainSignature,
    _StorageView,
)


def test_recompilable_storage_map_preserves_segment_space_order_and_offsets():
    artifact = build_recompilable_storage_map(
        [
            RecompilableStorageMapCandidate(
                segment_reg="SS",
                segment_value=0x3000,
                offset=4,
                width=2,
                identity_kind="stack_slot",
                association_classification="const",
                allow_linear_lowering=True,
                stable_object_kind="stack",
                stable_object_name="frame_4",
            ),
            RecompilableStorageMapCandidate(
                segment_reg="DS",
                segment_value=0x2000,
                offset=4,
                width=2,
                identity_kind="global",
                association_classification="const",
                allow_linear_lowering=True,
                stable_object_kind="global",
                stable_object_name="g_4",
            ),
            RecompilableStorageMapCandidate(
                segment_reg="ES",
                segment_value=0x4000,
                offset=1,
                width=1,
                identity_kind="global",
                association_classification="const",
                allow_linear_lowering=True,
                stable_object_kind="global",
                stable_object_name="es_1",
            ),
        ]
    )

    assert [(row.segment_reg, row.offset) for row in artifact.rows] == [
        ("DS", 4),
        ("ES", 1),
        ("SS", 4),
    ]


def test_recompilable_storage_map_refuses_ambiguous_segment_storage():
    artifact = build_recompilable_storage_map(
        [
            RecompilableStorageMapCandidate(
                segment_reg="DS",
                segment_value=None,
                offset=0x20,
                width=2,
                identity_kind="global",
                association_classification="over_associated",
                allow_linear_lowering=False,
            )
        ]
    )

    assert artifact.rows == ()
    assert len(artifact.refusals) == 1
    refusal = artifact.refusals[0]
    assert refusal.segment_reg == "DS"
    assert refusal.classification == "over_associated"
    assert refusal.reason == "multiple incompatible segment bases"


def test_recompilable_storage_map_keeps_same_offset_in_distinct_segments_distinct():
    artifact = build_recompilable_storage_map(
        [
            RecompilableStorageMapCandidate(
                segment_reg="DS",
                segment_value=0x2000,
                offset=0x10,
                width=2,
                identity_kind="global",
                association_classification="const",
                allow_linear_lowering=True,
                stable_object_kind="global",
                stable_object_name="g_ds_10",
            ),
            RecompilableStorageMapCandidate(
                segment_reg="ES",
                segment_value=0x2100,
                offset=0x10,
                width=2,
                identity_kind="global",
                association_classification="const",
                allow_linear_lowering=True,
                stable_object_kind="global",
                stable_object_name="g_es_10",
            ),
        ]
    )

    assert [(row.segment_reg, row.segment_value, row.offset) for row in artifact.rows] == [
        ("DS", 0x2000, 0x10),
        ("ES", 0x2100, 0x10),
    ]


def test_recompilable_storage_map_producer_uses_codegen_segment_summary_and_lowering():
    class MockCodegen:
        _inertia_segmented_memory_summary = {
            "stable": {
                "DS": {
                    "classification": "const",
                    "known_values": (0x2000,),
                }
            },
            "over_associated": {
                "ES": {
                    "classification": "over_associated",
                    "known_values": (0x2100, 0x2200),
                }
            },
            "unknown": {},
        }
        _inertia_segmented_memory_lowering = {
            "DS": {
                "classification": "const",
                "allow_linear_lowering": True,
            },
            "ES": {
                "classification": "over_associated",
                "allow_linear_lowering": False,
            },
        }

    artifact = export_recompilable_storage_map_from_codegen(
        MockCodegen(),
        (
            SegmentedStorageSeed("DS", 0x10, 2, "global", "global", "g_ds_10"),
            SegmentedStorageSeed("ES", 0x10, 2, "global", "global", "g_es_10"),
        ),
    )

    assert [(row.segment_reg, row.segment_value, row.offset) for row in artifact.rows] == [
        ("DS", 0x2000, 0x10)
    ]
    assert len(artifact.refusals) == 1
    assert artifact.refusals[0].segment_reg == "ES"
    assert artifact.refusals[0].classification == "over_associated"


def test_recompilable_storage_map_producer_refuses_segment_without_lowering_surface():
    class MockCodegen:
        _inertia_segmented_memory_summary = {"stable": {}, "over_associated": {}, "unknown": {}}
        _inertia_segmented_memory_lowering = {}

    artifact = export_recompilable_storage_map_from_codegen(
        MockCodegen(),
        (SegmentedStorageSeed("SS", 4, 2, "stack_slot", "stack", "frame_4"),),
    )

    assert artifact.rows == ()
    assert len(artifact.refusals) == 1
    assert artifact.refusals[0].segment_reg == "SS"
    assert artifact.refusals[0].classification == "unknown"


def test_recompilable_storage_map_alias_export_maps_stack_slot_to_ss():
    class MockCodegen:
        _inertia_segmented_memory_summary = {
            "stable": {"SS": {"classification": "const", "known_values": (0x3000,)}},
            "over_associated": {},
            "unknown": {},
        }
        _inertia_segmented_memory_lowering = {
            "SS": {"classification": "const", "allow_linear_lowering": True}
        }

    stack_facts = AliasStorageFacts(
        domain=_StorageDomainSignature(
            "stack",
            2,
            _StorageView(-32, 16),
            stack_slot=_StackSlotIdentity("bp", -4, 2, region=0x1000),
        ),
        identity=("stack", _StackSlotIdentity("bp", -4, 2, region=0x1000)),
    )

    artifact = export_recompilable_storage_map_from_alias_facts(
        MockCodegen(),
        (
            AliasBackedStorageSeed(
                alias_facts=stack_facts,
                stable_object_kind="stack",
                stable_object_name="frame_4",
            ),
        ),
    )

    assert [(row.segment_reg, row.segment_value, row.offset, row.width) for row in artifact.rows] == [
        ("SS", 0x3000, -4, 2)
    ]
    assert artifact.refusals == ()


def test_recompilable_storage_map_alias_export_requires_explicit_segment_for_memory():
    class MockCodegen:
        _inertia_segmented_memory_summary = {
            "stable": {"DS": {"classification": "const", "known_values": (0x2000,)}},
            "over_associated": {},
            "unknown": {},
        }
        _inertia_segmented_memory_lowering = {
            "DS": {"classification": "const", "allow_linear_lowering": True}
        }

    memory_facts = AliasStorageFacts(
        domain=_StorageDomainSignature("memory", 2, _StorageView(0x40 * 8, 16)),
        identity=("memory", 0x40),
    )

    artifact = export_recompilable_storage_map_from_alias_facts(
        MockCodegen(),
        (AliasBackedStorageSeed(alias_facts=memory_facts),),
    )

    assert artifact.rows == ()
    assert artifact.refusals == ()

    ds_artifact = export_recompilable_storage_map_from_alias_facts(
        MockCodegen(),
        (
            AliasBackedStorageSeed(
                alias_facts=memory_facts,
                segment_reg="DS",
                stable_object_kind="global",
                stable_object_name="g_40",
            ),
        ),
    )

    assert [(row.segment_reg, row.segment_value, row.offset, row.width) for row in ds_artifact.rows] == [
        ("DS", 0x2000, 0x40, 2)
    ]
