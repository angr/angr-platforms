from angr_platforms.X86_16.ir_readiness import summarize_x86_16_ir_readiness


def test_ir_readiness_reports_typed_address_and_condition_level():
    readiness = summarize_x86_16_ir_readiness(
        {
            "x86_16_vex_ir_summary": {
                "block_count": 2,
                "address_status_counts": {"provisional": 3},
                "segment_origin_counts": {"defaulted": 3, "proven": 1},
                "condition_counts": {"eq": 1, "nonzero": 1},
                "phi_node_count": 1,
            }
        }
    )

    assert readiness.level == "typed_address_condition_and_ssa"
    assert readiness.provisional_address_count == 3
    assert readiness.defaulted_segment_count == 3
    assert readiness.proven_segment_count == 1
    assert readiness.condition_count == 2
    assert readiness.phi_node_count == 1


def test_ir_readiness_reports_missing_when_no_blocks_exist():
    readiness = summarize_x86_16_ir_readiness({"x86_16_vex_ir_summary": {"block_count": 0}})

    assert readiness.level == "missing"
    assert "no_ir_blocks" in readiness.reasons


def test_ir_readiness_distinguishes_defaulted_segment_and_missing_ssa():
    readiness = summarize_x86_16_ir_readiness(
        {
            "x86_16_vex_ir_summary": {
                "block_count": 1,
                "address_status_counts": {"provisional": 1},
                "segment_origin_counts": {"defaulted": 1, "unknown": 1},
                "condition_counts": {"masked_nonzero": 1},
                "phi_node_count": 0,
            }
        }
    )

    assert readiness.level == "typed_address_and_condition"
    assert "defaulted_segment_identity_present" in readiness.reasons
    assert "unknown_segment_identity_present" in readiness.reasons
    assert "no_cross_block_ssa" in readiness.reasons
