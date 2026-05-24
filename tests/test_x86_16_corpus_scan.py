from pathlib import Path

import pytest

from angr_platforms.X86_16.corpus_scan import (
    FunctionScanResult,
    ScanTimeout,
    StageResult,
    _should_skip_scan_safe_back_edge,
    _should_skip_scan_safe_call_chain,
    _should_skip_scan_safe_call_chain_from_insns,
    _should_skip_scan_safe_cfg,
    _should_skip_scan_safe_decompile,
    _should_skip_scan_safe_decompile_for_cfg_shape,
    _should_skip_scan_safe_tiny_guard_call_helper,
    classify_failure,
    extract_cod_functions,
    scan_function,
    summarize_results,
)


def test_corpus_scan_classifies_core_failure_kinds():
    assert classify_failure("load", ValueError("bad blob"))[0] == "load_failure"
    assert classify_failure("lift", RuntimeError("unsupported opcode 0f ff"))[0] == "unsupported_semantic"
    assert classify_failure("decompile", ScanTimeout("timed out"))[0] == "timeout"
    assert classify_failure("decompile", RuntimeError("maximum recursion depth exceeded"))[0] == "recursion_or_explosion"
    assert classify_failure("cfg", None)[0] == "cfg_failure"
    assert classify_failure("unknown", None)[0] == "analysis_failure"
    assert classify_failure("decompile", None, empty_codegen=True)[0] == "no_code_produced"
    assert classify_failure("decompile", None, empty_codegen=True, rewrite_failed=True)[0] == "rewrite_failure"
    assert classify_failure("decompile", None, empty_codegen=True, regeneration_failed=True)[0] == "regeneration_failure"


def test_corpus_scan_summary_groups_file_health():
    ok_result = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_a",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="decompile",
        function_count=1,
        decompiled_count=1,
        stages=[StageResult("load", True), StageResult("decompile", True)],
    )
    partial_ok = FunctionScanResult(
        cod_file="B.COD",
        proc_name="_b1",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="decompile",
        fallback_kind="cfg_only",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("decompile", True)],
    )
    partial_fail = FunctionScanResult(
        cod_file="B.COD",
        proc_name="_b2",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=False,
        stage_reached="cfg",
        failure_class="cfg_failure",
        reason="cfg broke",
        fallback_kind="block_lift",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("cfg", False, reason="cfg_failure")],
    )
    dead_file = FunctionScanResult(
        cod_file="C.COD",
        proc_name="_c",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=False,
        stage_reached="lift",
        failure_class="lift_failure",
        reason="lift broke",
        fallback_kind="none",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("lift", False, reason="lift_failure")],
    )
    regenerated = FunctionScanResult(
        cod_file="D.COD",
        proc_name="_d",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="decompile",
        fallback_kind="cfg_only",
        function_count=1,
        decompiled_count=0,
        regeneration_failed=True,
        regeneration_failure_pass="_rewrite_callsite_names_8616",
        regeneration_failure_reason="boom",
        stages=[StageResult("load", True), StageResult("decompile", True, detail="boom")],
    )

    summary = summarize_results([ok_result, partial_ok, partial_fail, dead_file, regenerated], "scan-safe")

    assert summary["ok"] == 3
    assert summary["failed"] == 2
    assert summary["failure_counts"] == {"cfg_failure": 1, "lift_failure": 1}
    assert summary["fallback_counts"] == {"block_lift": 1, "cfg_only": 2}
    assert summary["full_decompile_count"] == 1
    assert summary["cfg_only_count"] == 2
    assert summary["lift_only_count"] == 0
    assert summary["block_lift_count"] == 1
    assert summary["rewrite_failure_count"] == 0
    assert summary["structuring_failure_count"] == 0
    assert summary["regeneration_failure_count"] == 1
    assert summary["visibility_debt"] == 2
    assert summary["recovery_debt"] == 2
    assert summary["readability_debt"] == 1
    assert summary["unclassified_failure_count"] == 0
    assert summary["blind_spot_budget"] == {
        "full_decompile_rate": 0.2,
        "cfg_only_rate": 0.4,
        "lift_only_rate": 0.0,
        "block_lift_rate": 0.2,
        "true_failure_rate": 0.4,
    }
    assert summary["debt"] == {"traversal": 2, "recovery": 2, "readability": 1}
    assert summary["files_scan_clean"] == ["A.COD", "D.COD"]
    assert summary["files_partial_success"] == ["B.COD"]
    assert summary["files_zero_success"] == ["C.COD"]
    assert summary["interrupt_api"] == {
        "dos_helpers": 0,
        "bios_helpers": 0,
        "wrapper_calls": 0,
        "unresolved_wrappers": 0,
    }
    assert summary["confidence_status_counts"] == {
        "return_shape_uncertain": 1,
        "partial_recovery": 1,
        "target_recovered_strong": 1,
        "target_unrecovered": 2,
    }
    assert summary["confidence_scan_safe_counts"] == {
        "partial": 1,
        "strong": 1,
        "unresolved": 3,
    }


def test_corpus_scan_summary_accumulates_interrupt_api_counts():
    helper_result = FunctionScanResult(
        cod_file="D.COD",
        proc_name="_d",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="decompile",
        function_count=1,
        decompiled_count=1,
        interrupt_dos_helper_count=2,
        interrupt_bios_helper_count=1,
        interrupt_wrapper_call_count=3,
        interrupt_unresolved_wrapper_count=1,
        semantic_family="interrupt_api",
        stages=[StageResult("load", True), StageResult("decompile", True)],
    )

    summary = summarize_results([helper_result], "scan-safe")

    assert summary["interrupt_api"] == {
        "dos_helpers": 2,
        "bios_helpers": 1,
        "wrapper_calls": 3,
        "unresolved_wrappers": 1,
    }
    assert summary["confidence_status_counts"] == {"helper_guessed_weak": 1}
    assert summary["confidence_assumption_counts"] == {"helper_guessed_from_weak_evidence": 1}
    assert summary["rewrite_failure_count"] == 0
    assert summary["structuring_failure_count"] == 0
    assert summary["regeneration_failure_count"] == 0
    assert summary["family_ownership"] == {
        "top_families": [{"family": "interrupt_api", "count": 1}],
        "top_failures": [],
        "top_fallbacks": [],
        "top_ugly_clusters": [],
    }
    assert summary["readability_clusters"] == []


def test_extract_cod_functions_uses_synthetic_global_offsets(tmp_path: Path):
    cod_path = tmp_path / "DOSFUNC.COD"
    cod_path.write_text(
        "\n".join(
            [
                "_dos_getfree\tPROC NEAR",
                "\t*** 000000\tc6 06 17 00 48 \t\tmov\tBYTE PTR $S424_rin+1,72",
                "\t*** 000005\tc7 06 18 00 ff ff \tmov\tWORD PTR $S424_rin+2,-1",
                "\t*** 00000b\tb8 16 00 \t\tmov\tax,OFFSET DGROUP:$S424_rin",
                "_dos_getfree\tENDP",
            ]
        ),
        encoding="utf-8",
    )

    funcs = extract_cod_functions(cod_path)

    assert funcs == [
        (
            "_dos_getfree",
            "NEAR",
            bytes.fromhex("c6 06 01 70 48 c7 06 02 70 ff ff b8 00 70"),
        )
    ]


def test_corpus_scan_summary_aggregates_tail_validation():
    stable = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_stable",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="decompile",
        function_count=1,
        decompiled_count=1,
        tail_validation={
            "structuring": {
                "changed": False,
                "mode": "live_out",
                "verdict": "structuring whole-tail validation [live_out] stable: no observable whole-tail changes",
            },
            "postprocess": {
                "changed": False,
                "mode": "live_out",
                "verdict": "postprocess whole-tail validation [live_out] stable: no observable whole-tail changes",
            },
        },
        stages=[StageResult("load", True), StageResult("decompile", True)],
    )
    changed = FunctionScanResult(
        cod_file="B.COD",
        proc_name="_changed",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="decompile",
        function_count=1,
        decompiled_count=1,
        tail_validation={
            "postprocess": {
                "changed": True,
                "mode": "live_out",
                "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
            }
        },
        stages=[StageResult("load", True), StageResult("decompile", True)],
    )
    unknown = FunctionScanResult(
        cod_file="C.COD",
        proc_name="_unknown",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=False,
        stage_reached="cfg",
        failure_class="cfg_failure",
        reason="cfg broke",
        fallback_kind="block_lift",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("cfg", False, reason="cfg_failure")],
    )

    summary = summarize_results([stable, changed, unknown], "scan-safe")

    assert summary["tail_validation"]["severity"] == "changed"
    assert summary["tail_validation"]["changed_function_count"] == 1
    assert summary["tail_validation"]["coverage_count"] == 3
    assert summary["tail_validation"]["missing_count"] == 3
    assert summary["tail_validation"]["unknown_count"] == 0
    assert summary["tail_validation"]["structuring"]["stable_count"] == 1
    assert summary["tail_validation"]["structuring"]["unknown_count"] == 0
    assert summary["tail_validation"]["structuring"]["missing_count"] == 2
    assert summary["tail_validation"]["structuring"]["coverage_count"] == 1
    assert summary["tail_validation"]["postprocess"]["stable_count"] == 1
    assert summary["tail_validation"]["postprocess"]["changed_count"] == 1
    assert summary["tail_validation"]["postprocess"]["unknown_count"] == 0
    assert summary["tail_validation"]["postprocess"]["missing_count"] == 1
    assert summary["tail_validation"]["postprocess"]["coverage_count"] == 2
    assert summary["tail_validation"]["postprocess"]["mode_counts"] == {"live_out": 2}
    assert summary["tail_validation"]["postprocess"]["top_verdicts"] == [
        {"verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping", "count": 1}
    ]
    assert summary["tail_validation"]["changed_functions"] == [
        {
            "cod_file": "B.COD",
            "proc_name": "_changed",
            "proc_kind": "NEAR",
            "stage": "postprocess",
            "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
            "families": ("helper call delta",),
        }
    ]
    assert summary["tail_validation_surface"] == {
        "headline": "whole-tail validation failed across 1 functions",
        "severity": "changed",
        "merge_gate": False,
        "changed_function_count": 1,
        "changed_stage_total": 1,
        "coverage_count": 3,
        "missing_stage_total": 3,
        "unknown_stage_total": 0,
        "consistency_issues": (),
        "function_status_counts": {"changed": 1, "passed": 1, "uncollected": 1},
        "function_statuses": [
            {
                "cod_file": "A.COD",
                "proc_name": "_stable",
                "proc_kind": "NEAR",
                "status": "passed",
                "stage_statuses": {"postprocess": "passed", "structuring": "passed"},
                "exit_kind": None,
                "exit_detail": None,
                "tail_validation_uncollected": False,
            },
            {
                "cod_file": "B.COD",
                "proc_name": "_changed",
                "proc_kind": "NEAR",
                "status": "changed",
                "stage_statuses": {"postprocess": "changed", "structuring": "uncollected"},
                "exit_kind": None,
                "exit_detail": None,
                "tail_validation_uncollected": False,
            },
            {
                "cod_file": "C.COD",
                "proc_name": "_unknown",
                "proc_kind": "NEAR",
                "status": "uncollected",
                "stage_statuses": {"postprocess": "uncollected", "structuring": "uncollected"},
                "exit_kind": None,
                "exit_detail": None,
                "tail_validation_uncollected": False,
            },
        ],
        "passed_function_count": 1,
        "unknown_function_count": 0,
        "uncollected_function_count": 1,
        "top_unknown_functions": [],
        "top_uncollected_functions": [
            {
                "cod_file": "C.COD",
                "proc_name": "_unknown",
                "proc_kind": "NEAR",
                "status": "uncollected",
                "stage_statuses": {"postprocess": "uncollected", "structuring": "uncollected"},
                "exit_kind": None,
                "exit_detail": None,
                "tail_validation_uncollected": False,
            }
        ],
        "stage_rows": [
            {
                "stage": "structuring",
                "changed_count": 0,
                "stable_count": 1,
                "unknown_count": 0,
                "missing_count": 2,
                "coverage_count": 1,
                "changed_rate": 0.0,
                "coverage_rate": 0.333333,
                "mode_counts": {"live_out": 1},
                "top_verdicts": [],
            },
            {
                "stage": "postprocess",
                "changed_count": 1,
                "stable_count": 1,
                "unknown_count": 0,
                "missing_count": 1,
                "coverage_count": 2,
                "changed_rate": 0.333333,
                "coverage_rate": 0.666667,
                "mode_counts": {"live_out": 2},
                "top_verdicts": [
                    {"verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping", "count": 1}
                ],
            },
        ],
        "stage_hotspots": [
            {
                "stage": "postprocess",
                "changed_count": 1,
                "changed_rate": 0.333333,
                "top_verdicts": [
                    {"verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping", "count": 1}
                ],
            }
        ],
        "top_changed_verdicts": [
            {"verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping", "count": 1}
        ],
        "top_changed_functions": [
            {
                "cod_file": "B.COD",
                "proc_name": "_changed",
                "proc_kind": "NEAR",
                "stages": ("postprocess",),
                "verdicts": ("postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",),
                "changed_stage_count": 1,
            }
        ],
        "changed_families": [
            {
                "family": "helper call delta",
                "count": 1,
                "function_count": 1,
                "stages": ("postprocess",),
                "examples": ({"cod_file": "B.COD", "proc_name": "_changed", "proc_kind": "NEAR"},),
            }
        ],
        "changed_family_routing": [
            {
                "family": "helper call delta",
                "count": 1,
                "function_count": 1,
                "stages": ("postprocess",),
                "likely_layer": "helpers",
                "next_root_cause_file": "angr_platforms/angr_platforms/X86_16/analysis_helpers.py",
                "signal": "interrupt/dos helper lowering and naming",
            }
        ],
    }
    assert summary["tail_validation_cache"]["cache_hit"] is False
    assert isinstance(summary["tail_validation_cache"]["cache_key"], str)

    cached_summary = summarize_results([stable, changed, unknown], "scan-safe")
    assert cached_summary["tail_validation_cache"]["cache_hit"] is True
    assert cached_summary["tail_validation_cache"]["cache_key"] == summary["tail_validation_cache"]["cache_key"]


def test_corpus_scan_summary_marks_uncollected_tail_validation_when_metadata_is_absent():
    result = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_cfg_only",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="cfg",
        fallback_kind="cfg_only",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("cfg", True)],
    )

    summary = summarize_results([result], "scan-safe")

    assert summary["tail_validation"]["severity"] == "uncollected"
    assert summary["tail_validation"]["coverage_count"] == 0
    assert summary["tail_validation"]["missing_count"] == 2
    assert summary["tail_validation"]["unknown_count"] == 0
    assert summary["tail_validation_surface"]["headline"] == "whole-tail validation not collected across 1 functions"


def test_corpus_scan_summary_ranks_repeat_failures():
    repeated_a = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_a1",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=False,
        stage_reached="decompile",
        failure_class="timeout",
        reason="timed out",
        fallback_kind="block_lift",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("decompile", False, reason="timeout")],
    )
    repeated_b = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_a2",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=False,
        stage_reached="decompile",
        failure_class="timeout",
        reason="timed out",
        fallback_kind="block_lift",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("decompile", False, reason="timeout")],
    )
    other = FunctionScanResult(
        cod_file="B.COD",
        proc_name="_b",
        proc_kind="FAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=False,
        stage_reached="cfg",
        failure_class="cfg_failure",
        reason="cfg broke",
        fallback_kind="block_lift",
        semantic_family="addressing",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("cfg", False, reason="cfg_failure")],
    )

    summary = summarize_results([repeated_a, repeated_b, other], "scan-safe")

    assert summary["top_failure_classes"] == [
        {"failure_class": "timeout", "count": 2},
        {"failure_class": "cfg_failure", "count": 1},
    ]
    assert summary["family_ownership"]["top_families"] == [
        {"family": "stack_control", "count": 2},
        {"family": "addressing", "count": 1},
    ]
    assert summary["family_ownership"]["top_failures"] == [
        {"family": "stack_control", "count": 2},
        {"family": "addressing", "count": 1},
    ]
    assert summary["top_failure_stages"] == [
        {"stage": "decompile", "count": 2},
        {"stage": "cfg", "count": 1},
    ]
    assert summary["timeout_stage_counts"] == {"decompile": 2}
    assert summary["top_failure_files"] == [
        {"cod_file": "A.COD", "count": 2},
        {"cod_file": "B.COD", "count": 1},
    ]
    assert summary["top_failure_functions"][0] == {
        "cod_file": "A.COD",
        "proc_name": "_a1",
        "proc_kind": "NEAR",
        "failure_class": "timeout",
        "count": 1,
    }


def test_corpus_scan_summary_ranks_fallback_hotspots():
    fallback_a = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_a",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="decompile",
        fallback_kind="cfg_only",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("decompile", True)],
    )
    fallback_b = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_b",
        proc_kind="FAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="cfg",
        fallback_kind="lift_only",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("cfg", True)],
    )
    fallback_c = FunctionScanResult(
        cod_file="B.COD",
        proc_name="_c",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=False,
        stage_reached="decompile",
        failure_class="decompiler_crash",
        reason="boom",
        fallback_kind="block_lift",
        semantic_family="addressing",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("decompile", False, reason="decompiler_crash")],
    )

    summary = summarize_results([fallback_a, fallback_b, fallback_c], "scan-safe")

    assert summary["top_fallback_kinds"] == [
        {"fallback_kind": "block_lift", "count": 1},
        {"fallback_kind": "cfg_only", "count": 1},
        {"fallback_kind": "lift_only", "count": 1},
    ]
    assert summary["family_ownership"]["top_fallbacks"] == [
        {"family": "stack_control", "count": 2},
        {"family": "addressing", "count": 1},
    ]


def test_corpus_scan_summary_tracks_readability_clusters():
    readable = FunctionScanResult(
        cod_file="R.COD",
        proc_name="_r",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="decompile",
        function_count=1,
        decompiled_count=1,
        readability_cluster="byte_pair_arithmetic",
        readability_cluster_reason="shift-and-or byte pair detected",
        stages=[StageResult("load", True), StageResult("decompile", True)],
    )
    summary = summarize_results([readable], "scan-safe")

    assert summary["readability_clusters"] == [{"cluster": "byte_pair_arithmetic", "count": 1}]


def test_corpus_scan_summary_ranks_ugly_clusters():
    oversized = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_oversized",
        proc_kind="NEAR",
        byte_len=512,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="cfg",
        fallback_kind="cfg_only",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("decompile", True, detail="skipped decompile for oversized function (512 bytes > 384); cfg ok")],
    )
    complex_cfg = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_complex",
        proc_kind="NEAR",
        byte_len=128,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="cfg",
        fallback_kind="cfg_only",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("decompile", True, detail="skipped decompile for complex CFG (blocks>8 or insns>200); cfg ok")],
    )
    relocation = FunctionScanResult(
        cod_file="B.COD",
        proc_name="_reloc",
        proc_kind="NEAR",
        byte_len=16,
        has_near_call_reloc=True,
        has_far_call_reloc=False,
        ok=False,
        stage_reached="cfg",
        failure_class="skipped_relocation",
        reason="contains unresolved call relocation pattern",
        fallback_kind="block_lift",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("cfg", False, reason="skipped_relocation", detail="contains unresolved call relocation pattern")],
    )

    summary = summarize_results([oversized, complex_cfg, relocation], "scan-safe")

    assert summary["top_ugly_clusters"] == [
        {"cluster": "call_relocation_rescue", "count": 1},
        {"cluster": "control_flow_explosion", "count": 1},
        {"cluster": "oversized_function", "count": 1},
    ]
    assert summary["family_ownership"]["top_ugly_clusters"] == [
        {"family": "stack_control", "cluster": "call_relocation_rescue", "count": 1},
        {"family": "stack_control", "cluster": "control_flow_explosion", "count": 1},
        {"family": "stack_control", "cluster": "oversized_function", "count": 1},
    ]


def test_scan_safe_skips_oversized_decompile_attempts():
    assert _should_skip_scan_safe_decompile(698, "scan-safe", 384) is True
    assert _should_skip_scan_safe_decompile(384, "scan-safe", 384) is False
    assert _should_skip_scan_safe_decompile(698, "lift", 384) is False
    assert _should_skip_scan_safe_decompile(698, "scan-safe", 0) is False


def test_scan_safe_skips_oversized_cfg_attempts():
    assert _should_skip_scan_safe_cfg(2608, "scan-safe", 192) is True
    assert _should_skip_scan_safe_cfg(1589, "scan-safe", 192) is True
    assert _should_skip_scan_safe_cfg(192, "scan-safe", 192) is False
    assert _should_skip_scan_safe_cfg(2608, "lift", 192) is False
    assert _should_skip_scan_safe_cfg(2608, "scan-safe", 0) is False


def test_scan_safe_oversized_functions_use_bounded_probe_before_lift_only(monkeypatch):
    code = b"\x90" * 2608

    class FakeFactory:
        def block(self, addr: int, size: int):  # noqa: ANN001
            raise AssertionError("oversized scan-safe lift_only should not call factory.block before the gate")

    class FakeAnalyses:
        def CFGFast(self, *args, **kwargs):  # noqa: ANN001, ARG002
            raise AssertionError("CFGFast should not run for oversized scan-safe lift_only")

    class FakeProject:
        def __init__(self):
            self.factory = FakeFactory()
            self.analyses = FakeAnalyses()

    monkeypatch.setattr(
        "angr_platforms.X86_16.corpus_scan.project_from_bytes",
        lambda _code: FakeProject(),
    )

    result = scan_function(
        Path("oversized.COD"),
        "_oversized",
        "NEAR",
        code,
        timeout_sec=5,
        mode="scan-safe",
        max_cfg_bytes=192,
    )

    assert result.ok is True
    assert result.fallback_kind == "lift_only"


def test_scan_safe_skips_complex_cfg_shapes():
    class _FakeBlock:
        def __init__(self, insn_count: int):
            self.capstone = type("Capstone", (), {"insns": [object()] * insn_count})()

    class _FakeFunc:
        def __init__(self, blocks):
            self._blocks = blocks

        @property
        def blocks(self):
            return self._blocks

    class _FakeCfg:
        def __init__(self, blocks):
            self.functions = {0x1000: _FakeFunc(blocks)}

    assert _should_skip_scan_safe_decompile_for_cfg_shape(_FakeCfg([_FakeBlock(201)]), "scan-safe", 8, 200) is True
    assert _should_skip_scan_safe_decompile_for_cfg_shape(_FakeCfg([_FakeBlock(1)] * 9), "scan-safe", 8, 200) is True
    assert _should_skip_scan_safe_decompile_for_cfg_shape(_FakeCfg([_FakeBlock(20)]), "lift", 8, 200) is False
    assert _should_skip_scan_safe_decompile_for_cfg_shape(_FakeCfg([_FakeBlock(5)]), "scan-safe", 8, 200) is False


def test_scan_safe_skips_short_loop_heavy_functions():
    class _FakeOp:
        def __init__(self, imm):
            self.imm = imm

    class _FakeInsn:
        def __init__(self, address: int, mnemonic: str, imm: int | None):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = [] if imm is None else [_FakeOp(imm)]

    class _FakeCapstoneBlock:
        def __init__(self, insns):
            self.insns = insns

    assert _should_skip_scan_safe_back_edge(_FakeCapstoneBlock([_FakeInsn(0x1000, "jmp", 0x0FFF)]), "scan-safe", 128) is True
    assert _should_skip_scan_safe_back_edge(_FakeCapstoneBlock([_FakeInsn(0x1000, "jmp", 0x1010)]), "scan-safe", 128) is False
    assert _should_skip_scan_safe_back_edge(_FakeCapstoneBlock([_FakeInsn(0x1000, "mov", None)]), "scan-safe", 128) is False
    assert _should_skip_scan_safe_back_edge(_FakeCapstoneBlock([_FakeInsn(0x1000, "jmp", 0x0FFF)]), "lift", 128) is False


def test_scan_safe_skips_call_heavy_helpers():
    class _FakeInsn:
        def __init__(self, mnemonic: str):
            self.mnemonic = mnemonic

    class _FakeCapstoneBlock:
        def __init__(self, insns):
            self.insns = insns

    assert _should_skip_scan_safe_call_chain(_FakeCapstoneBlock([_FakeInsn("call")] * 3), "scan-safe", 192) is True
    assert _should_skip_scan_safe_call_chain(_FakeCapstoneBlock([_FakeInsn("call")] * 2), "scan-safe", 192) is False
    assert _should_skip_scan_safe_call_chain(_FakeCapstoneBlock([_FakeInsn("call")] * 3), "lift", 192) is False
    assert _should_skip_scan_safe_call_chain(_FakeCapstoneBlock([_FakeInsn("call")] * 3), "scan-safe", 0) is False
    assert _should_skip_scan_safe_call_chain_from_insns([_FakeInsn("call")] * 3, "scan-safe", 192) is True
    assert _should_skip_scan_safe_call_chain_from_insns([_FakeInsn("call")] * 2, "scan-safe", 192) is False
    assert _should_skip_scan_safe_call_chain_from_insns([_FakeInsn("call")] * 3, "lift", 192) is False
    assert _should_skip_scan_safe_call_chain_from_insns([_FakeInsn("call")] * 3, "scan-safe", 0) is False


def test_scan_safe_skips_tiny_guard_call_helpers():
    class _FakeOp:
        def __init__(self, imm):
            self.imm = imm

    class _FakeInsn:
        def __init__(self, address: int, mnemonic: str, op_str: str = "", size: int = 1, imm: int | None = None):
            self.address = address
            self.mnemonic = mnemonic
            self.op_str = op_str
            self.bytes = b"\x90" * size
            self.operands = [] if imm is None else [_FakeOp(imm)]

    insns = [
        _FakeInsn(0x1000, "cmp"),
        _FakeInsn(0x1005, "je", imm=0x1011),
        _FakeInsn(0x1007, "push"),
        _FakeInsn(0x100B, "call"),
        _FakeInsn(0x100E, "add", "sp, 2"),
        _FakeInsn(0x1011, "ret"),
    ]
    assert _should_skip_scan_safe_tiny_guard_call_helper(insns, "scan-safe", 192) is True
    assert _should_skip_scan_safe_tiny_guard_call_helper(insns[:-1], "scan-safe", 192) is False
    assert _should_skip_scan_safe_tiny_guard_call_helper(insns, "lift", 192) is False
    assert _should_skip_scan_safe_tiny_guard_call_helper(insns, "scan-safe", 0) is False


@pytest.mark.parametrize("proc_name", ["_dos_alloc", "_dos_resize", "_dos_mcbInfo"])
def test_scan_safe_keeps_short_dos_memory_helpers_in_bounded_recovery(proc_name: str):
    repo_root = Path(__file__).resolve().parents[2]
    cod_path = repo_root / ".codex_automation" / "evidence_subset" / "cod" / "DOSFUNC.COD"
    funcs = {name: (kind, code) for name, kind, code in extract_cod_functions(cod_path)}
    kind, code = funcs[proc_name]

    result = scan_function(
        cod_path,
        proc_name,
        kind,
        code,
        timeout_sec=5,
        mode="scan-safe",
    )

    assert result.ok is True
    assert result.failure_class is None
    assert result.fallback_kind == "cfg_only"
    assert result.semantic_family == "stack_control"
    assert result.confidence_status == "bounded_recovery"
    assert result.confidence_scan_safe_classification == "strong"


@pytest.mark.parametrize(
    "cod_name, proc_name",
    [
        ("OUTPUT.COD", "_hexdump"),
        ("START1.COD", "_processStoreInput"),
        ("UTIL.COD", "_sizeString"),
        ("START3.COD", "_sub_14BB4"),
    ],
)
def test_scan_safe_keeps_known_hotspots_in_conservative_recovery(cod_name: str, proc_name: str):
    repo_root = Path(__file__).resolve().parents[2]
    cod_path = repo_root / "cod" / cod_name
    funcs = {name: (kind, code) for name, kind, code in extract_cod_functions(cod_path)}
    kind, code = funcs[proc_name]

    result = scan_function(
        cod_path,
        proc_name,
        kind,
        code,
        timeout_sec=5,
        mode="scan-safe",
        max_cfg_bytes=192,
        max_decompile_bytes=384,
    )

    assert result.ok is True
    assert result.failure_class is None
    assert result.fallback_kind in {"cfg_only", "block_lift"}
    assert result.semantic_family == "stack_control"
    assert result.stage_reached == "cleanup"


@pytest.mark.parametrize(
    "proc_name, expected_len",
    [
        ("_DrawMissile", 216),
        ("_DrawCoolF14", 1098),
        ("_DrawTexPlane", 1008),
    ],
)
def test_scan_safe_3dplanes_oversized_functions_stay_in_lift_only_recovery(proc_name: str, expected_len: int):
    repo_root = Path(__file__).resolve().parents[2]
    cod_path = repo_root / ".codex_automation" / "evidence_subset" / "cod" / "f14" / "3DPLANES.COD"
    funcs = {name: (kind, code) for name, kind, code in extract_cod_functions(cod_path)}
    kind, code = funcs[proc_name]

    assert len(code) == expected_len

    result = scan_function(
        cod_path,
        proc_name,
        kind,
        code,
        timeout_sec=5,
        mode="scan-safe",
        max_cfg_bytes=192,
        max_decompile_bytes=384,
    )

    assert result.ok is True
    assert result.failure_class is None
    assert result.fallback_kind == "lift_only"
    assert result.confidence_status == "partial_recovery"
    assert result.stage_reached != "lift"
    assert result.confidence_scan_safe_classification != "none"


@pytest.mark.parametrize("proc_name", ["_DrawRegBoat", "_shape_only_regression"])
def test_scan_safe_call_heavy_helper_classification_is_shape_based(proc_name: str):
    repo_root = Path(__file__).resolve().parents[2]
    cod_path = repo_root / ".codex_automation" / "evidence_subset" / "cod" / "f14" / "3DPLANES.COD"
    funcs = {name: (kind, code) for name, kind, code in extract_cod_functions(cod_path)}
    kind, code = funcs["_DrawRegBoat"]

    assert len(code) == 96

    result = scan_function(
        cod_path,
        proc_name,
        kind,
        code,
        timeout_sec=5,
        mode="scan-safe",
        max_cfg_bytes=192,
        max_decompile_bytes=384,
    )

    assert result.ok is True
    assert result.failure_class is None
    assert result.fallback_kind == "cfg_only"
    assert result.semantic_family == "stack_control"
    assert result.confidence_status == "bounded_recovery"
    assert result.stage_reached == "cleanup"


@pytest.mark.parametrize("proc_name", ["_Release3DMemory", "_shape_only_release"])
def test_scan_safe_tiny_guard_call_helper_bypass_is_shape_based(proc_name: str):
    repo_root = Path(__file__).resolve().parents[2]
    cod_path = repo_root / ".codex_automation" / "evidence_subset" / "cod" / "f14" / "3DLOADER.COD"
    funcs = {name: (kind, code) for name, kind, code in extract_cod_functions(cod_path)}
    kind, code = funcs["_Release3DMemory"]

    assert len(code) == 18

    result = scan_function(
        cod_path,
        proc_name,
        kind,
        code,
        timeout_sec=5,
        mode="scan-safe",
        max_cfg_bytes=192,
        max_decompile_bytes=384,
    )

    assert result.ok is True
    assert result.failure_class is None
    assert result.confidence_status != "target_unrecovered"
    assert result.fallback_kind == "cfg_only"
    assert result.stage_reached == "cleanup"
