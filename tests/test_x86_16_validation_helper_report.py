from angr_platforms.X86_16.validation_helper_report import (
    build_x86_16_validation_helper_report,
    describe_x86_16_validation_helper_report_surface,
)


def test_validation_helper_report_reuses_recovery_confidence_rows():
    report = build_x86_16_validation_helper_report(
        [
            {
                "ok": True,
                "decompiled_count": 1,
                "direct_call_count": 1,
                "return_kind": "scalar",
            },
            {
                "ok": True,
                "decompiled_count": 1,
                "direct_call_count": 2,
                "return_kind": "scalar",
            },
        ]
    )

    assert report.as_rows() == (
        {
            "family": "helper_wrapper_candidate",
            "count": 1,
            "likely_layer": "helper_modeling",
            "next_root_cause_file": "angr_platforms/angr_platforms/X86_16/helper_effect_summary.py",
            "signal": "eligible",
        },
        {
            "family": "helper_wrapper_signature_shape",
            "count": 1,
            "likely_layer": "helper_modeling",
            "next_root_cause_file": "angr_platforms/angr_platforms/X86_16/helper_effect_summary.py",
            "signal": "call_count_not_single",
        },
    )


def test_validation_helper_report_surface_is_deterministic():
    assert describe_x86_16_validation_helper_report_surface() == {
        "consumer": "validation_helper_report",
        "producer": "summarize_recovery_confidence",
        "surface": "helper_family_rows",
        "typed_rows": (
            "family",
            "count",
            "likely_layer",
            "next_root_cause_file",
            "signal",
        ),
        "purpose": "Route helper/wrapper family evidence into later validation/report consumers.",
    }
