from angr_platforms.X86_16.helper_effect_summary import (
    HelperEligibilityRefusal,
    HelperEligibilitySummary,
)
from angr_platforms.X86_16.helper_family_routing import summarize_x86_16_helper_family_routes


def test_helper_family_routing_builds_deterministic_rows():
    rows = summarize_x86_16_helper_family_routes(
        (
            HelperEligibilitySummary(status="eligible", candidate_kind="single_direct_call_wrapper"),
            HelperEligibilitySummary(
                status="refused",
                refusals=(
                    HelperEligibilityRefusal("indirect_control", "x"),
                    HelperEligibilityRefusal("nonlocal_memory_effects", "y"),
                ),
            ),
            HelperEligibilitySummary(
                status="refused",
                refusals=(HelperEligibilityRefusal("indirect_control", "z"),),
            ),
        )
    )

    assert [item.family for item in rows] == [
        "helper_wrapper_indirect_control",
        "helper_wrapper_candidate",
        "helper_wrapper_nonlocal_memory",
    ]
    assert [item.count for item in rows] == [2, 1, 1]
    assert rows[0].likely_layer == "function_effect_summary"


def test_helper_family_routing_keeps_no_signal_as_explicit_family():
    rows = summarize_x86_16_helper_family_routes((HelperEligibilitySummary(status="no_signal"),))

    assert len(rows) == 1
    assert rows[0].family == "helper_wrapper_no_signal"
    assert rows[0].signal == "no_effect_signal"
