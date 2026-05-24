from angr_platforms.X86_16.ir_recovery_summary import summarize_x86_16_ir_recovery


def test_ir_recovery_summary_reads_prebuilt_vex_ir_summary():
    summary = summarize_x86_16_ir_recovery(
        {
            "x86_16_vex_ir_summary": {
                "block_count": 2,
                "instruction_count": 7,
                "refusal_count": 1,
                "aliasable_value_count": 3,
                "ssa_binding_count": 4,
                "phi_node_count": 1,
                "frame_slot_count": 2,
                "frame_refusal_count": 0,
                "space_counts": {"ds": 2, "ss": 1},
                "address_status_counts": {"provisional": 2},
                "segment_origin_counts": {"defaulted": 2, "proven": 1},
                "condition_counts": {"eq": 1},
            }
        }
    )

    assert summary.block_count == 2
    assert summary.aliasable_value_count == 3
    assert summary.phi_node_count == 1
    assert summary.space_counts == {"ds": 2, "ss": 1}
    assert summary.address_status_counts == {"provisional": 2}
    assert summary.segment_origin_counts == {"defaulted": 2, "proven": 1}
    assert summary.condition_counts == {"eq": 1}


def test_ir_recovery_summary_defaults_deterministically_when_missing():
    summary = summarize_x86_16_ir_recovery(
        {
            "cod_file": "DOSFUNC.COD",
            "proc_name": "_dos_alloc",
        }
    )

    assert summary.block_count == 0
    assert summary.instruction_count == 0
    assert summary.space_counts == {}
