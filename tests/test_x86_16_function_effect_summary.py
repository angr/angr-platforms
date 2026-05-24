from angr_platforms.X86_16.function_effect_summary import summarize_x86_16_function_effects
from angr_platforms.X86_16.recovery_confidence import classify_x86_16_recovery_confidence


def test_function_effect_summary_is_deterministic_and_sorted():
    summary = summarize_x86_16_function_effects(
        {
            "register_inputs": {"dx", "ax"},
            "register_outputs": ["bx", "ax"],
            "register_clobbers": {"cf", "ds"},
            "frame_stack_reads": {6, 4},
            "frame_stack_writes": [8, 2],
            "memory_reads": {"ds:0x20", "es:0x10"},
            "memory_writes": ["ss:0x4"],
            "direct_call_count": 2,
            "indirect_call_count": 1,
            "direct_branch_count": 3,
            "indirect_branch_count": 0,
            "return_kind": "word",
            "helper_return_state": "stack_address",
            "helper_return_space": "ss",
            "helper_return_width": 2,
            "helper_return_address_kind": "stack",
        }
    )

    assert summary.register_inputs == ("ax", "dx")
    assert summary.register_outputs == ("ax", "bx")
    assert summary.register_clobbers == ("cf", "ds")
    assert summary.frame_stack_reads == (4, 6)
    assert summary.frame_stack_writes == (2, 8)
    assert summary.memory_reads == ("ds:0x20", "es:0x10")
    assert summary.memory_writes == ("ss:0x4",)
    assert summary.helper_return_state == "stack_address"
    assert summary.helper_return_space == "ss"
    assert summary.helper_return_width == 2
    assert summary.helper_return_address_kind == "stack"
    assert summary.has_indirect_control() is True


def test_recovery_confidence_consumes_function_effect_summary():
    summary = classify_x86_16_recovery_confidence(
        {
            "ok": True,
            "decompiled_count": 1,
            "register_inputs": ("ax",),
            "register_clobbers": ("ds",),
            "frame_stack_reads": (4,),
            "direct_call_count": 1,
            "indirect_call_count": 1,
            "return_kind": "word",
        }
    )

    evidence_kinds = {item.kind for item in summary.evidence}
    assumption_kinds = {item.kind for item in summary.assumptions}

    assert "function_effect_summary" in evidence_kinds
    assert "indirect_control_flow" in assumption_kinds
    assert any(item.startswith("function_effects=") for item in summary.diagnostics)
