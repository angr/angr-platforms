from angr_platforms.X86_16.helper_effect_summary import (
    summarize_x86_16_helper_eligibility,
)


def test_helper_effect_summary_accepts_single_direct_call_wrapper_shape():
    summary = summarize_x86_16_helper_eligibility(
        {
            "direct_call_count": 1,
            "return_kind": "scalar",
            "register_inputs": ("ax",),
            "register_outputs": ("ax",),
        }
    )

    assert summary.status == "eligible"
    assert summary.candidate_kind == "single_direct_call_wrapper"
    assert summary.refusals == ()


def test_helper_effect_summary_refuses_indirect_control_and_memory_effects():
    summary = summarize_x86_16_helper_eligibility(
        {
            "direct_call_count": 1,
            "indirect_branch_count": 1,
            "memory_writes": ("ds:0x1234",),
            "return_kind": "scalar",
        }
    )

    assert summary.status == "refused"
    assert summary.candidate_kind == "none"
    assert tuple(item.kind for item in summary.refusals) == (
        "indirect_control",
        "nonlocal_memory_effects",
    )


def test_helper_effect_summary_refuses_stack_probe_helper_when_return_state_is_unknown():
    summary = summarize_x86_16_helper_eligibility(
        {
            "stack_probe_helper": True,
            "direct_call_count": 1,
            "return_kind": "scalar",
            "helper_return_state": "unknown",
        }
    )

    assert summary.status == "refused"
    assert "helper_return_state_unknown" in tuple(item.kind for item in summary.refusals)


def test_helper_effect_summary_refuses_stack_probe_helper_when_return_width_is_unknown():
    summary = summarize_x86_16_helper_eligibility(
        {
            "stack_probe_helper": True,
            "direct_call_count": 1,
            "return_kind": "scalar",
            "helper_return_state": "stack_address",
            "helper_return_space": "ss",
            "helper_return_address_kind": "stack",
        }
    )

    assert summary.status == "refused"
    assert "helper_return_width_unknown" in tuple(item.kind for item in summary.refusals)
