from angr_platforms.X86_16.recovery_artifacts import (
    build_x86_16_corpus_recovery_artifact,
    build_x86_16_function_recovery_artifact,
)


def test_function_recovery_artifact_embeds_effect_helper_and_confidence():
    artifact = build_x86_16_function_recovery_artifact(
        {
            "cod_file": "DOSFUNC.COD",
            "proc_name": "_dos_alloc",
            "proc_kind": "NEAR",
            "ok": True,
            "stage_reached": "decompile",
            "decompiled_count": 1,
            "direct_call_count": 1,
            "register_inputs": ("ax", "ds", "zf"),
            "register_outputs": ("bx", "es", "cf"),
            "return_kind": "scalar",
            "x86_16_vex_ir_summary": {
                "block_count": 1,
                "instruction_count": 4,
                "aliasable_value_count": 2,
                "frame_slot_count": 1,
                "address_status_counts": {"provisional": 1},
                "segment_origin_counts": {"defaulted": 1},
                "condition_counts": {"eq": 1},
                "phi_node_count": 1,
            },
            "runtime_trace": {
                "segment_registers": {"ds": 0x1234},
                "memory_reads": ("ds:0x20",),
                "memory_writes": ("es:0x10",),
            },
            "memory_reads": ("0x40:0x17/1", "ds:0x20"),
            "memory_writes": ("0x402/2", "es:0x10"),
        }
    )

    assert artifact.proc_name == "_dos_alloc"
    assert artifact.ir_summary.block_count == 1
    assert artifact.ir_summary.segment_origin_counts == {"defaulted": 1}
    assert artifact.ir_summary.phi_node_count == 1
    assert artifact.ir_readiness.level == "typed_address_condition_and_ssa"
    assert artifact.to_dict()["ir_summary"]["aliasable_value_count"] == 2
    assert artifact.to_dict()["ir_summary"]["segment_origin_counts"] == {"defaulted": 1}
    assert artifact.to_dict()["ir_readiness"]["condition_count"] == 1
    assert artifact.to_dict()["ir_readiness"]["phi_node_count"] == 1
    assert artifact.effect_summary.direct_call_count == 1
    assert artifact.state_summary.segment_register_inputs == ("ds",)
    assert artifact.state_summary.segment_register_outputs == ("es",)
    assert artifact.state_summary.flag_inputs == ("zf",)
    assert artifact.state_summary.flag_outputs == ("cf",)
    assert [item.label for item in artifact.state_summary.low_memory_reads] == ["bda.keyboard_flags0"]
    assert [item.label for item in artifact.state_summary.low_memory_writes] == ["bda.com2_port"]
    assert artifact.to_dict()["state_summary"]["low_memory_reads"][0]["access_kind"] == "read"
    assert artifact.helper_summary.status == "refused"
    assert artifact.trace_refinement.provenance == "runtime_trace"
    assert artifact.trace_refinement.refined_unknown_segment_count == 0
    assert artifact.confidence.status == "target_recovered_strong"


def test_corpus_recovery_artifact_keeps_helper_family_rows_deterministic():
    artifact = build_x86_16_corpus_recovery_artifact(
        [
            {
                "cod_file": "B.COD",
                "proc_name": "_b",
                "proc_kind": "NEAR",
                "ok": True,
                "stage_reached": "decompile",
                "direct_call_count": 1,
                "memory_reads": ("0xb800:0x12",),
                "return_kind": "scalar",
            },
            {
                "cod_file": "A.COD",
                "proc_name": "_a",
                "proc_kind": "NEAR",
                "ok": True,
                "stage_reached": "decompile",
                "direct_call_count": 2,
                "memory_reads": ("0x40:0x17/1",),
                "memory_writes": ("0x402/2",),
                "return_kind": "scalar",
            },
        ]
    )

    assert [(row.cod_file, row.proc_name) for row in artifact.function_rows] == [
        ("A.COD", "_a"),
        ("B.COD", "_b"),
    ]
    assert artifact.ir_readiness_level_counts == {"missing": 2}
    assert artifact.low_memory_read_region_counts == {"bda": 1, "video_ram": 1}
    assert artifact.low_memory_write_region_counts == {"bda": 1}
    assert artifact.helper_status_counts == {"refused": 2}
    assert artifact.helper_family_rows == (
        {
            "family": "helper_wrapper_nonlocal_memory",
            "count": 2,
            "likely_layer": "alias_model",
            "next_root_cause_file": "angr_platforms/angr_platforms/X86_16/alias_model.py",
            "signal": "nonlocal_memory_effects",
        },
        {
            "family": "helper_wrapper_signature_shape",
            "count": 1,
            "likely_layer": "helper_modeling",
            "next_root_cause_file": "angr_platforms/angr_platforms/X86_16/helper_effect_summary.py",
            "signal": "call_count_not_single",
        },
    )
