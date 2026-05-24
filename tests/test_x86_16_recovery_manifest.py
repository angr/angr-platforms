from angr_platforms.X86_16.recovery_manifest import RECOVERY_LAYERS, describe_x86_16_recovery_layers


def test_x86_16_recovery_layers_cover_current_recovery_boundary():
    assert [layer.name for layer in RECOVERY_LAYERS] == [
        "segmented_memory_association",
        "member_and_array_recovery",
        "stable_stack_object_recovery",
        "stable_global_object_recovery",
        "store_side_widening",
        "segment_aware_object_roots",
        "trait_to_type_handoff",
        "control_flow_structuring",
        "prototype_evidence_layer",
        "far_near_prototype_recovery",
        "wrapper_and_return_recovery",
        "confidence_axis",
        "thin_late_rewrite_boundary",
    ]
    assert describe_x86_16_recovery_layers() == tuple((layer.name, layer.purpose, layer.helpers) for layer in RECOVERY_LAYERS)


def test_x86_16_recovery_layers_pin_existing_helpers():
    stack = RECOVERY_LAYERS[2]
    proto = RECOVERY_LAYERS[8]
    structuring = RECOVERY_LAYERS[7]

    assert "_stack_slot_identity_for_variable" in stack.helpers
    assert "annotate_bp_stack_variable" in stack.helpers
    assert "describe_x86_16_decompiler_structuring_stage" in structuring.helpers
    assert "seed_calling_conventions" in proto.helpers
    assert "apply_x86_16_decompiler_return_compatibility" in proto.helpers


def test_x86_16_segmented_memory_association_helpers_are_explicit():
    seg = RECOVERY_LAYERS[0]

    assert seg.name == "segmented_memory_association"
    assert "_SegmentAssociationState" in seg.helpers
    assert "_classify_segmented_addr_expr" in seg.helpers
