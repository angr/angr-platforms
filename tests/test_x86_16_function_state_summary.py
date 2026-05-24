from angr_platforms.X86_16.function_state_summary import summarize_x86_16_function_state
from angr_platforms.X86_16.recovery_confidence import classify_x86_16_recovery_confidence


def test_function_state_summary_partitions_gp_segment_and_flags():
    summary = summarize_x86_16_function_state(
        {
            "register_inputs": {"ax", "ds", "zf", "es"},
            "register_outputs": ["bx", "cf", "ss"],
            "memory_reads": {"ds:0x20", "0x40:0x17/1", "0x40:0x17/2", "ds:si"},
            "memory_writes": {"es:0x10", "0x402/2"},
            "return_kind": "word",
        }
    )

    assert summary.gp_register_inputs == ("ax",)
    assert summary.segment_register_inputs == ("ds", "es")
    assert summary.flag_inputs == ("zf",)
    assert summary.gp_register_outputs == ("bx",)
    assert summary.segment_register_outputs == ("ss",)
    assert summary.flag_outputs == ("cf",)
    assert summary.touches_segments() is True
    assert summary.touches_flags() is True
    assert summary.memory_reads == ("0x40:0x17/1", "0x40:0x17/2", "ds:0x20", "ds:si")
    assert summary.memory_writes == ("0x402/2", "es:0x10")
    assert [item.access_kind for item in summary.low_memory_reads] == ["read", "read"]
    assert [item.raw_access for item in summary.low_memory_reads] == ["0x40:0x17/1", "0x40:0x17/2"]
    assert [item.label for item in summary.low_memory_reads] == ["bda.keyboard_flags0", "bda+0x17"]
    assert [item.access_kind for item in summary.low_memory_writes] == ["write"]
    assert [item.raw_access for item in summary.low_memory_writes] == ["0x402/2"]
    assert summary.brief().endswith("low_mem_r=2 low_mem_w=1 calls=0 branches=0 return=word")
    assert summary.to_dict()["low_memory_reads"][0]["raw_access"] == "0x40:0x17/1"


def test_recovery_confidence_consumes_function_state_summary():
    summary = classify_x86_16_recovery_confidence(
        {
            "ok": True,
            "decompiled_count": 1,
            "register_inputs": ("ax", "ds", "zf"),
            "register_outputs": ("bx", "es", "cf"),
            "memory_reads": ("ds:0x20", "0x40:0x17/1"),
            "memory_writes": ("es:0x10", "0x402/2"),
            "return_kind": "word",
        }
    )

    evidence_kinds = {item.kind for item in summary.evidence}
    assumption_kinds = {item.kind for item in summary.assumptions}

    assert "function_state_summary" in evidence_kinds
    assert "segment_state_needs_tracking" in assumption_kinds
    assert "live_flags_need_typed_conditions" in assumption_kinds
    assert any(item.startswith("function_state=") for item in summary.diagnostics)
