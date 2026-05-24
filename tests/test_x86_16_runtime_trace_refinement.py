from angr_platforms.X86_16.runtime_trace_refinement import summarize_x86_16_runtime_trace_refinement


def test_runtime_trace_refinement_is_absent_without_trace():
    summary = summarize_x86_16_runtime_trace_refinement(
        {
            "x86_16_vex_ir_summary": {
                "block_count": 1,
                "instruction_count": 1,
                "segment_origin_counts": {"unknown": 2},
            }
        }
    )

    assert summary.provenance == "none"
    assert summary.refined_unknown_segment_count == 0


def test_runtime_trace_refinement_refines_unknown_segments_with_provenance():
    summary = summarize_x86_16_runtime_trace_refinement(
        {
            "x86_16_vex_ir_summary": {
                "block_count": 1,
                "instruction_count": 1,
                "segment_origin_counts": {"unknown": 2},
            },
            "runtime_trace": {
                "segment_registers": {"ds": 0x1234, "es": 0x5678},
                "memory_reads": ("ds:0x20",),
                "memory_writes": ("es:0x10",),
            },
        }
    )

    assert summary.provenance == "runtime_trace"
    assert summary.segment_register_values == {"ds": 0x1234, "es": 0x5678}
    assert summary.refined_unknown_segment_count == 2
    assert summary.remaining_unknown_segment_count == 0
    assert summary.memory_read_count == 1
    assert summary.memory_write_count == 1
