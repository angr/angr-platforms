from angr_platforms.X86_16.milestone_report import (
    build_x86_16_milestone_report,
    cache_x86_16_tail_validation_detail_artifact,
    render_x86_16_tail_validation_console_summary,
)
from angr_platforms.X86_16.validation_manifest import describe_x86_16_validation_triage


def test_x86_16_milestone_report_combines_scan_and_quality_context():
    scan_summary = {
        "mode": "scan-safe",
        "scanned": 10,
        "ok": 7,
        "failed": 3,
        "failure_counts": {"cfg_failure": 2, "lift_failure": 1},
        "fallback_counts": {"cfg_only": 2, "block_lift": 1},
        "top_failure_classes": [{"failure_class": "cfg_failure", "count": 2}],
        "top_fallback_kinds": [{"fallback_kind": "cfg_only", "count": 2}],
        "top_failure_stages": [{"stage": "cfg", "count": 2}],
        "top_failure_files": [{"cod_file": "A.COD", "count": 2}],
        "top_failure_functions": [{"cod_file": "A.COD", "proc_name": "_x", "proc_kind": "NEAR", "failure_class": "cfg_failure", "count": 2}],
        "top_fallback_files": [{"cod_file": "A.COD", "count": 2}],
        "top_fallback_functions": [{"cod_file": "A.COD", "proc_name": "_x", "proc_kind": "NEAR", "fallback_kind": "cfg_only", "count": 2}],
        "readability_clusters": [
            {"cluster": "byte_pair_arithmetic", "count": 4},
            {"cluster": "fake_locals_and_stack_noise", "count": 2},
            {"cluster": "boolean_noise", "count": 1},
        ],
        "full_decompile_count": 7,
        "cfg_only_count": 2,
        "lift_only_count": 0,
        "block_lift_count": 1,
        "rewrite_failure_count": 1,
        "structuring_failure_count": 0,
        "regeneration_failure_count": 2,
        "blind_spot_budget": {
            "full_decompile_rate": 0.7,
            "cfg_only_rate": 0.2,
            "lift_only_rate": 0.0,
            "block_lift_rate": 0.1,
            "true_failure_rate": 0.3,
        },
        "debt": {"traversal": 3, "recovery": 2, "readability": 7},
        "interrupt_api": {
            "dos_helpers": 4,
            "bios_helpers": 2,
            "wrapper_calls": 6,
            "unresolved_wrappers": 1,
        },
        "confidence": {
            "status_counts": {"partial_recovery": 1, "target_recovered_strong": 2},
            "scan_safe_counts": {"partial": 1, "strong": 2},
            "assumption_counts": {"far_pointer_unresolved": 1},
            "evidence_counts": {"decompiled_output": 2},
            "diagnostic_counts": {"failure_class=cfg_failure": 1},
        },
        "confidence_status_counts": {"partial_recovery": 1, "target_recovered_strong": 2},
        "confidence_scan_safe_counts": {"partial": 1, "strong": 2},
        "confidence_assumption_counts": {"far_pointer_unresolved": 1},
        "confidence_evidence_counts": {"decompiled_output": 2},
        "confidence_diagnostic_counts": {"failure_class=cfg_failure": 1},
        "tail_validation": {
            "severity": "changed",
            "changed_function_count": 1,
            "coverage_count": 5,
            "missing_count": 3,
            "unknown_count": 0,
            "structuring": {
                "stable_count": 3,
                "changed_count": 0,
                "unknown_count": 0,
                "missing_count": 1,
                "coverage_count": 3,
                "mode_counts": {"live_out": 3},
                "top_verdicts": [],
                "changed_functions": [],
            },
            "postprocess": {
                "stable_count": 2,
                "changed_count": 1,
                "unknown_count": 0,
                "missing_count": 2,
                "coverage_count": 2,
                "mode_counts": {"live_out": 3},
                "top_verdicts": [
                    {
                        "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                        "count": 1,
                    }
                ],
                "changed_functions": [
                    {
                        "cod_file": "cod/f14/OTHER.COD",
                        "proc_name": "_other",
                        "proc_kind": "NEAR",
                        "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                    }
                ],
            },
            "changed_functions": [
                {
                    "cod_file": "cod/f14/OTHER.COD",
                    "proc_name": "_other",
                    "proc_kind": "NEAR",
                    "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                }
            ],
        },
        "tail_validation_surface": {
            "headline": "whole-tail validation failed across 1 functions",
            "severity": "changed",
            "merge_gate": False,
            "changed_function_count": 1,
            "changed_stage_total": 1,
            "coverage_count": 5,
            "missing_stage_total": 3,
            "unknown_stage_total": 0,
            "stage_rows": [
                {
                    "stage": "structuring",
                    "changed_count": 0,
                    "stable_count": 3,
                    "unknown_count": 0,
                    "missing_count": 1,
                    "coverage_count": 3,
                    "changed_rate": 0.0,
                    "coverage_rate": 0.3,
                    "mode_counts": {"live_out": 3},
                    "top_verdicts": [],
                },
                {
                    "stage": "postprocess",
                    "changed_count": 1,
                    "stable_count": 2,
                    "unknown_count": 0,
                    "missing_count": 2,
                    "coverage_count": 2,
                    "changed_rate": 0.1,
                    "coverage_rate": 0.3,
                    "mode_counts": {"live_out": 3},
                    "top_verdicts": [
                        {
                            "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                            "count": 1,
                        }
                    ],
                },
            ],
            "stage_hotspots": [
                {
                    "stage": "postprocess",
                    "changed_count": 1,
                    "changed_rate": 0.1,
                    "top_verdicts": [
                        {
                            "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                            "count": 1,
                        }
                    ],
                }
            ],
            "top_changed_verdicts": [
                {
                    "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                    "count": 1,
                }
            ],
        },
        "results": [
            {
                "cod_file": "cod/f14/MONOPRIN.COD",
                "proc_name": "_mset_pos",
                "proc_kind": "NEAR",
                "ok": True,
                "decompiled_count": 1,
                "fallback_kind": None,
            },
            {
                "cod_file": "cod/f14/OTHER.COD",
                "proc_name": "_other",
                "proc_kind": "NEAR",
                "ok": True,
                "decompiled_count": 1,
                "fallback_kind": None,
            },
            {
                "cod_file": "cod/f14/MAX.COD",
                "proc_name": "_max",
                "proc_kind": "NEAR",
                "ok": True,
                "decompiled_count": 0,
                "fallback_kind": "cfg_only",
            },
            {
                "cod_file": "cod/f14/BROKEN.COD",
                "proc_name": "_broken",
                "proc_kind": "NEAR",
                "ok": False,
                "decompiled_count": 0,
                "fallback_kind": "block_lift",
            },
        ],
        "top_ugly_clusters": [{"cluster": "byte_pair_arithmetic", "count": 4}],
        "timeout_stage_counts": {"decompile": 2},
        "family_ownership": {
            "top_families": [{"family": "stack_control", "count": 2}],
            "top_failures": [{"family": "stack_control", "count": 1}],
            "top_fallbacks": [{"family": "stack_control", "count": 2}],
            "top_ugly_clusters": [{"family": "stack_control", "cluster": "byte_pair_arithmetic", "count": 4}],
        },
    }

    report = build_x86_16_milestone_report(scan_summary, corpus_slice="active-corpus")

    assert report["corpus"] == "x86-16"
    assert report["corpus_slice"] == "active-corpus"
    assert report["scan_summary"]["failed"] == 3
    assert report["corpus_rates"] == {
        "success_rate": 0.7,
        "failure_rate": 0.3,
        "full_decompile_rate": 0.7,
        "cfg_only_rate": 0.2,
        "lift_only_rate": 0.0,
        "block_lift_rate": 0.1,
    }
    assert report["blind_spot_budget"] == scan_summary["blind_spot_budget"]
    assert report["tail_validation"] == scan_summary["tail_validation"]
    assert report["tail_validation_surface"] == scan_summary["tail_validation_surface"]
    assert report["corpus_completion"] == {
        "no_crashes": False,
        "no_blind_spots": True,
        "unclassified_failure_count": 0,
        "scanned": 10,
        "fallback_coverage": {
            "full_decompile_count": 7,
            "cfg_only_count": 2,
            "lift_only_count": 0,
            "block_lift_count": 1,
        },
        "debt": {
            "visibility": 3,
            "recovery": 2,
            "readability": 7,
        },
        "postprocess_failures": {
            "rewrite_failure_count": 1,
            "structuring_failure_count": 0,
            "regeneration_failure_count": 2,
        },
        "confidence": scan_summary["confidence"],
        "confidence_status_counts": scan_summary["confidence_status_counts"],
        "confidence_scan_safe_counts": scan_summary["confidence_scan_safe_counts"],
        "confidence_assumption_counts": scan_summary["confidence_assumption_counts"],
        "confidence_evidence_counts": scan_summary["confidence_evidence_counts"],
        "confidence_diagnostic_counts": scan_summary["confidence_diagnostic_counts"],
        "tail_validation": scan_summary["tail_validation"],
        "tail_validation_surface": scan_summary["tail_validation_surface"],
        "blind_spot_budget": scan_summary["blind_spot_budget"],
        "stable_by_traversal": False,
        "merge_gate": False,
        "readability_tiers": {"R0": 1, "R1": 1, "R2": 1, "R3": 1},
        "timeout_stage_counts": {"decompile": 2},
        "fallback_backlog": {
            "top_fallback_files": [{"cod_file": "A.COD", "count": 2}],
            "top_fallback_functions": [
                {"cod_file": "A.COD", "proc_name": "_x", "proc_kind": "NEAR", "fallback_kind": "cfg_only", "count": 2}
            ],
        },
        "readability_backlog": {
            "top_ugly_clusters": [{"cluster": "byte_pair_arithmetic", "count": 4}],
            "readability_clusters": [
                {"cluster": "byte_pair_arithmetic", "count": 4},
                {"cluster": "fake_locals_and_stack_noise", "count": 2},
                {"cluster": "boolean_noise", "count": 1},
            ],
            "family_ownership": scan_summary["family_ownership"],
        },
        "readability_focus": {
            "goal_queue": [
                {
                    "step": "4.1",
                    "title": "Fix the top ugly clusters, not isolated outputs",
                    "priority": "P1",
                    "deterministic_goal": "Rank repeated ugly forms from scan output, then chip away at the highest-frequency clusters instead of single showcase functions.",
                    "target_clusters": [
                        "byte_pair_arithmetic",
                        "split_segmented_word_accesses",
                        "fake_locals_and_stack_noise",
                        "weak_helper_signatures",
                        "boolean_noise",
                        "unresolved_member_or_array_opportunities",
                    ],
                    "owner_surfaces": [
                        "corpus_scan.top_ugly_clusters",
                        "corpus_scan.family_ownership.top_ugly_clusters",
                        "milestone_report.readability_backlog",
                    ],
                    "completion_signal": "Milestone reports always show stable ranked clusters, and each readability sprint starts from the top cluster counts.",
                    "observed_cluster_count": 7,
                    "observed_family_count": 4,
                    "rank": 1,
                    "is_next_focus": True,
                },
                {
                    "step": "4.2",
                    "title": "Spend the first major readability budget on alias and widening",
                    "priority": "P0",
                    "deterministic_goal": "Move byte-pair, projection, and split-segment cleanup onto alias and widening proof surfaces, then keep late rewrite from re-solving storage identity.",
                    "target_clusters": [
                        "byte_pair_arithmetic",
                        "split_segmented_word_accesses",
                        "fake_locals_and_stack_noise",
                    ],
                    "owner_surfaces": [
                        "alias_api",
                        "widening_pipeline",
                        "projection_cleanup_rules",
                        "source_backed_rewrite_debt",
                    ],
                    "completion_signal": "Several old local coalescers become thin wrappers and the remaining cleanup work consumes shared alias/widening facts.",
                    "observed_cluster_count": 6,
                    "observed_family_count": 4,
                    "rank": 2,
                    "is_next_focus": False,
                },
                {
                    "step": "4.3",
                    "title": "Only then spend on traits, types, and objects",
                    "priority": "P1",
                    "deterministic_goal": "Let trait evidence drive typed object recovery only after alias and widening are stable, so field, array, global, and stack-object wins stay evidence-driven.",
                    "target_clusters": [
                        "fake_locals_and_stack_noise",
                        "weak_helper_signatures",
                        "unresolved_member_or_array_opportunities",
                    ],
                    "owner_surfaces": [
                        "recovery_layers",
                        "validation_families",
                        "readability_set",
                        "readability_tiers",
                    ],
                    "completion_signal": "Object-like output increases without a matching rise in hallucinated structs or arrays.",
                    "observed_cluster_count": 2,
                    "observed_family_count": 0,
                    "rank": 3,
                    "is_next_focus": False,
                },
            ],
            "next_goal": {
                "step": "4.1",
                "title": "Fix the top ugly clusters, not isolated outputs",
                "priority": "P1",
                "deterministic_goal": "Rank repeated ugly forms from scan output, then chip away at the highest-frequency clusters instead of single showcase functions.",
                "target_clusters": [
                    "byte_pair_arithmetic",
                    "split_segmented_word_accesses",
                    "fake_locals_and_stack_noise",
                    "weak_helper_signatures",
                    "boolean_noise",
                    "unresolved_member_or_array_opportunities",
                ],
                "owner_surfaces": [
                    "corpus_scan.top_ugly_clusters",
                    "corpus_scan.family_ownership.top_ugly_clusters",
                    "milestone_report.readability_backlog",
                ],
                "completion_signal": "Milestone reports always show stable ranked clusters, and each readability sprint starts from the top cluster counts.",
                "observed_cluster_count": 7,
                "observed_family_count": 4,
                "rank": 1,
                "is_next_focus": True,
            },
            "top_ugly_clusters": [{"cluster": "byte_pair_arithmetic", "count": 4}],
            "readability_clusters": [
                {"cluster": "byte_pair_arithmetic", "count": 4},
                {"cluster": "fake_locals_and_stack_noise", "count": 2},
                {"cluster": "boolean_noise", "count": 1},
            ],
            "family_ownership": scan_summary["family_ownership"],
        },
    }
    assert report["debt"] == scan_summary["debt"]
    assert report["debt_breakdown"] == {
        "visibility": 3,
        "recovery": 2,
        "readability": 7,
    }
    assert report["postprocess_failures"] == {
        "rewrite_failure_count": 1,
        "structuring_failure_count": 0,
        "regeneration_failure_count": 2,
    }
    assert report["confidence"] == scan_summary["confidence"]
    assert report["confidence_status_counts"] == scan_summary["confidence_status_counts"]
    assert report["confidence_scan_safe_counts"] == scan_summary["confidence_scan_safe_counts"]
    assert report["interrupt_api"] == {
        "dos_helpers": 4,
        "bios_helpers": 2,
        "wrapper_calls": 6,
        "unresolved_wrappers": 1,
    }
    assert report["interrupt_core_surface"] == {
        "vector_base": 0xFF000,
        "vector_count": 256,
        "hook_count": 256,
        "runtime_alias_base": 0x0000,
        "named_vectors": (
            0x10,
            0x11,
            0x12,
            0x13,
            0x14,
            0x15,
            0x16,
            0x17,
            0x1A,
            0x20,
            0x21,
            0x25,
            0x26,
            0x27,
            0x2F,
        ),
        "control_transfer_policy": "int -> synthetic target -> SimOS hook",
        "low_level_helpers": (
            "interrupt_service_addr",
            "ensure_interrupt_service_hook",
            "ensure_dos_service_hook",
            "collect_interrupt_service_calls",
            "patch_interrupt_service_call_sites",
        ),
    }
    assert report["interrupt_lowering_boundary"] == {
        "boundary_rule": "interrupt instruction semantics stay low-level; DOS/BIOS/MS-C lowering stays in analysis and rewrite helpers",
        "core_surface": report["interrupt_core_surface"],
        "api_surface": report["interrupt_api_surface"],
        "validated_by": (
            "tests/test_x86_16_milestone_report.py",
            "tests/test_x86_16_package_exports.py",
            "tests/test_x86_16_helper_modeling.py",
        ),
    }
    assert report["interrupt_lowering_boundary"] == {
        "boundary_rule": "interrupt instruction semantics stay low-level; DOS/BIOS/MS-C lowering stays in analysis and rewrite helpers",
        "core_surface": report["interrupt_core_surface"],
        "api_surface": report["interrupt_api_surface"],
        "validated_by": (
            "tests/test_x86_16_milestone_report.py",
            "tests/test_x86_16_package_exports.py",
            "tests/test_x86_16_helper_modeling.py",
        ),
    }
    assert report["interrupt_api_surface"] == {
        "dos": {
            "service_count": 18,
            "service_names": (
                "print_dos_string",
                "set_current_drive",
                "setvect",
                "get_dos_version",
                "getvect",
                "mkdir",
                "rmdir",
                "chdir",
                "creat",
                "open",
                "close",
                "read",
                "write",
                "unlink",
                "lseek",
                "get_current_directory",
                "resize_dos_memory_block",
                "exit",
            ),
            "helper_names": (
                "_dos_print_dollar_string",
                "_dos_setdrive",
                "_dos_setvect",
                "_dos_get_version",
                "_dos_getvect",
                "_dos_mkdir",
                "_dos_rmdir",
                "_dos_chdir",
                "_dos_creat",
                "_dos_open",
                "_dos_close",
                "_dos_read",
                "_dos_write",
                "_dos_unlink",
                "_dos_seek",
                "_dos_getcwd",
                "_dos_setblock",
                "_dos_exit",
            ),
        },
        "bios": {
            "service_count": 9,
            "service_names": (
                "_bios_int10_video",
                "_bios_equiplist",
                "_bios_memsize",
                "_bios_disk",
                "_bios_serialcom",
                "_bios_int15_system",
                "_bios_keybrd",
                "_bios_printer",
                "_bios_timeofday",
            ),
            "helper_names": (
                "_bios_int10_video",
                "_bios_equiplist",
                "_bios_memsize",
                "_bios_disk",
                "_bios_serialcom",
                "_bios_int15_system",
                "_bios_keybrd",
                "_bios_printer",
                "_bios_timeofday",
            ),
            "vectors": (16, 17, 18, 19, 20, 21, 22, 23, 26),
        },
        "wrappers": {
            "kinds": ("int86", "int86x", "intdos", "intdosx"),
            "input_fields": ("inregs", "outregs", "sregs"),
            "result_paths": (
                "outregs.h.ah",
                "outregs.h.al",
                "outregs.x.ax",
                "outregs.x.bx",
                "outregs.x.cx",
                "outregs.x.dx",
                "sregs.es",
            ),
        },
    }
    assert report["correctness_goal_summary"] == {
        "total": 4,
        "landed": 4,
        "partial": 0,
        "open": 0,
        "strict_percent": 100.0,
        "weighted_percent": 100.0,
        "landed_codes": ("C6.1", "C6.2", "C6.3", "C6.4"),
        "partial_codes": (),
        "open_codes": (),
    }
    assert [item["code"] for item in report["correctness_goals"]] == ["C6.1", "C6.2", "C6.3", "C6.4"]
    assert "tests/test_x86_16_cod_samples.py" in report["correctness_goals"][0]["owner_surfaces"]
    assert report["instruction_metadata_surface"] == {
        "normalized_fields": (
            "width_case",
            "operand_bits",
            "address_bits",
            "displacement_bits",
            "repeat_class",
            "control_flow_class",
        ),
        "repeat_classes": ("none", "repz", "repnz"),
        "control_flow_classes": (
            "none",
            "interrupt",
            "iret",
            "near_ret",
            "far_ret",
            "near_call",
            "far_call",
            "near_jump",
            "far_jump",
            "conditional_jump",
        ),
    }
    assert report["validation_triage"] == describe_x86_16_validation_triage()
    assert report["mixed_width_extension_surface"] == {
        "matrix": (
            {
                "name": "16/16",
                "operand_bits": 16,
                "address_bits": 16,
                "mode32": False,
                "chsz_op": False,
                "chsz_ad": False,
            },
            {
                "name": "32/16",
                "operand_bits": 32,
                "address_bits": 16,
                "mode32": False,
                "chsz_op": True,
                "chsz_ad": False,
            },
            {
                "name": "16/32",
                "operand_bits": 16,
                "address_bits": 32,
                "mode32": False,
                "chsz_op": False,
                "chsz_ad": True,
            },
            {
                "name": "32/32",
                "operand_bits": 32,
                "address_bits": 32,
                "mode32": True,
                "chsz_op": False,
                "chsz_ad": False,
            },
        ),
        "supported_pairs": ((16, 16), (32, 16), (16, 32), (32, 32)),
        "address_widths": (16, 32),
        "operand_widths": (16, 32),
    }
    assert report["mixed_width_instruction_surface"] == {
        "boundary": "mixed-width decode facts feed shared helpers instead of handler-local branches",
        "consumer_paths": (
            "angr_platforms/X86_16/parse.py",
            "angr_platforms/X86_16/exec.py",
            "angr_platforms/X86_16/instruction.py",
            "angr_platforms/X86_16/instr16.py",
            "angr_platforms/X86_16/instr32.py",
        ),
        "validated_by": (
            "tests/test_x86_16_addressing_helpers.py",
            "tests/test_x86_16_decode_metadata.py",
            "tests/test_x86_16_instruction_core_factoring.py",
        ),
        "matrix": report["mixed_width_extension_surface"]["matrix"],
    }
    assert report["mixed_width_instruction_surface"] == {
        "boundary": "mixed-width decode facts feed shared helpers instead of handler-local branches",
        "consumer_paths": (
            "angr_platforms/X86_16/parse.py",
            "angr_platforms/X86_16/exec.py",
            "angr_platforms/X86_16/instruction.py",
            "angr_platforms/X86_16/instr16.py",
            "angr_platforms/X86_16/instr32.py",
        ),
        "validated_by": (
            "tests/test_x86_16_addressing_helpers.py",
            "tests/test_x86_16_decode_metadata.py",
            "tests/test_x86_16_instruction_core_factoring.py",
        ),
        "matrix": report["mixed_width_extension_surface"]["matrix"],
    }
    assert report["readability_tiers"] == {"R0": 1, "R1": 1, "R2": 1, "R3": 1}
    assert [layer["name"] for layer in report["validation_layers"]] == ["unit", "focused_corpus", "whole_program"]
    assert [family["name"] for family in report["validation_families"]] == [
        "addressing",
        "stack_control",
        "string",
        "alu",
        "interrupt_api",
        "correctness",
        "tail_validation_accounting",
        "alias_model",
        "widening",
        "segmented_memory",
        "types_objects",
        "readability_guard",
    ]
    assert report["decode_width_matrix"] == [
        {"name": "16/16", "operand_bits": 16, "address_bits": 16},
        {"name": "32/16", "operand_bits": 32, "address_bits": 16},
        {"name": "16/32", "operand_bits": 16, "address_bits": 32},
        {"name": "32/32", "operand_bits": 32, "address_bits": 32},
    ]
    assert [item["name"] for item in report["alias_api"]] == ["same_domain", "compatible_view", "needs_synthesis", "can_join"]
    assert [item["name"] for item in report["widening_pipeline"]] == [
        "candidate_extraction",
        "compatibility_proof",
        "join_decision",
    ]
    assert [item["name"] for item in report["recovery_layers"]] == [
        "segmented_memory_association",
        "member_and_array_recovery",
        "stable_stack_object_recovery",
        "stable_global_object_recovery",
        "store_side_widening",
        "segment_aware_object_roots",
        "trait_to_type_handoff",
        "control_flow_structuring",
        "prototype_evidence_layer",
        "far_near_prototype_recovery",
        "wrapper_and_return_recovery",
        "confidence_axis",
        "thin_late_rewrite_boundary",
    ]
    assert [item["name"] for item in report["object_recovery_focus"]] == [
        "stable_stack_object_recovery",
        "stable_global_object_recovery",
        "segment_aware_object_roots",
        "trait_to_type_handoff",
        "member_and_array_recovery",
    ]
    assert report["projection_cleanup_rules"] == [
        {
            "name": "concat_fold",
            "purpose": "Fold concatenations of constant halves into one constant and preserve the narrower shift width otherwise.",
        },
        {
            "name": "or_zero_elimination",
            "purpose": "Eliminate redundant zero terms in Or expressions after the low-level expression facts are stable.",
        },
        {
            "name": "and_zero_collapse",
            "purpose": "Collapse And expressions with a zero operand into typed zero constants.",
        },
        {
            "name": "double_not_collapse",
            "purpose": "Remove redundant boolean negation pairs after boolean cite recovery.",
        },
        {
            "name": "zero_compare_projection",
            "purpose": "Convert zero comparisons into the underlying projection or flag source when the evidence is explicit.",
        },
        {
            "name": "sub_self_zero",
            "purpose": "Collapse self-subtractions into typed zero constants once the low-level operands are proven identical.",
        },
    ]
    assert report["source_backed_rewrites"]["count"] == 0
    assert report["source_backed_rewrites"]["status_counts"] == {}
    assert report["source_backed_rewrite_debt"] == {
        "count": 0,
        "active_count": 0,
        "oracle_count": 0,
        "subsumed_count": 0,
        "status_counts": {},
        "active_names": (),
        "oracle_names": (),
        "subsumed_names": (),
    }
    assert report["hotspots"]["fallback_counts"] == {"block_lift": 1, "cfg_only": 2}
    assert report["hotspots"]["top_fallback_kinds"][0]["fallback_kind"] == "cfg_only"
    assert report["hotspots"]["top_ugly_clusters"] == [{"cluster": "byte_pair_arithmetic", "count": 4}]
    assert report["hotspots"]["family_ownership"] == scan_summary["family_ownership"]
    assert report["readability_set_summary"][0] == {
        "source": "cod/f14/MONOPRIN.COD",
        "proc_name": "_mset_pos",
        "anchor_count": 5,
    }
    assert report["readability_goals"] == [
        {
            "step": "4.1",
            "title": "Fix the top ugly clusters, not isolated outputs",
            "deterministic_goal": (
                "Rank repeated ugly forms from scan output, then chip away at the highest-frequency clusters "
                "instead of single showcase functions."
            ),
            "target_clusters": [
                "byte_pair_arithmetic",
                "split_segmented_word_accesses",
                "fake_locals_and_stack_noise",
                "weak_helper_signatures",
                "boolean_noise",
                "unresolved_member_or_array_opportunities",
            ],
            "owner_surfaces": [
                "corpus_scan.top_ugly_clusters",
                "corpus_scan.family_ownership.top_ugly_clusters",
                "milestone_report.readability_backlog",
            ],
            "completion_signal": "Milestone reports always show stable ranked clusters, and each readability sprint starts from the top cluster counts.",
        },
        {
            "step": "4.2",
            "title": "Spend the first major readability budget on alias and widening",
            "deterministic_goal": (
                "Move byte-pair, projection, and split-segment cleanup onto alias and widening proof surfaces, "
                "then keep late rewrite from re-solving storage identity."
            ),
            "target_clusters": [
                "byte_pair_arithmetic",
                "split_segmented_word_accesses",
                "fake_locals_and_stack_noise",
            ],
            "owner_surfaces": [
                "alias_api",
                "widening_pipeline",
                "projection_cleanup_rules",
                "source_backed_rewrite_debt",
            ],
            "completion_signal": "Several old local coalescers become thin wrappers and the remaining cleanup work consumes shared alias/widening facts.",
        },
        {
            "step": "4.3",
            "title": "Only then spend on traits, types, and objects",
            "deterministic_goal": (
                "Let trait evidence drive typed object recovery only after alias and widening are stable, "
                "so field, array, global, and stack-object wins stay evidence-driven."
            ),
            "target_clusters": [
                "fake_locals_and_stack_noise",
                "weak_helper_signatures",
                "unresolved_member_or_array_opportunities",
            ],
            "owner_surfaces": [
                "recovery_layers",
                "validation_families",
                "readability_set",
                "readability_tiers",
            ],
            "completion_signal": "Object-like output increases without a matching rise in hallucinated structs or arrays.",
        },
    ]
    assert report["readability_goal_summary"] == [
        {
            "step": "4.1",
            "title": "Fix the top ugly clusters, not isolated outputs",
            "priority": "P1",
            "deterministic_goal": (
                "Rank repeated ugly forms from scan output, then chip away at the highest-frequency clusters "
                "instead of single showcase functions."
            ),
            "target_clusters": [
                "byte_pair_arithmetic",
                "split_segmented_word_accesses",
                "fake_locals_and_stack_noise",
                "weak_helper_signatures",
                "boolean_noise",
                "unresolved_member_or_array_opportunities",
            ],
            "owner_surfaces": [
                "corpus_scan.top_ugly_clusters",
                "corpus_scan.family_ownership.top_ugly_clusters",
                "milestone_report.readability_backlog",
            ],
            "completion_signal": "Milestone reports always show stable ranked clusters, and each readability sprint starts from the top cluster counts.",
            "observed_cluster_count": 7,
            "observed_family_count": 4,
        },
        {
            "step": "4.2",
            "title": "Spend the first major readability budget on alias and widening",
            "priority": "P0",
            "deterministic_goal": (
                "Move byte-pair, projection, and split-segment cleanup onto alias and widening proof surfaces, "
                "then keep late rewrite from re-solving storage identity."
            ),
            "target_clusters": [
                "byte_pair_arithmetic",
                "split_segmented_word_accesses",
                "fake_locals_and_stack_noise",
            ],
            "owner_surfaces": [
                "alias_api",
                "widening_pipeline",
                "projection_cleanup_rules",
                "source_backed_rewrite_debt",
            ],
            "completion_signal": "Several old local coalescers become thin wrappers and the remaining cleanup work consumes shared alias/widening facts.",
            "observed_cluster_count": 6,
            "observed_family_count": 4,
        },
        {
            "step": "4.3",
            "title": "Only then spend on traits, types, and objects",
            "priority": "P1",
            "deterministic_goal": (
                "Let trait evidence drive typed object recovery only after alias and widening are stable, "
                "so field, array, global, and stack-object wins stay evidence-driven."
            ),
            "target_clusters": [
                "fake_locals_and_stack_noise",
                "weak_helper_signatures",
                "unresolved_member_or_array_opportunities",
            ],
            "owner_surfaces": [
                "recovery_layers",
                "validation_families",
                "readability_set",
                "readability_tiers",
            ],
            "completion_signal": "Object-like output increases without a matching rise in hallucinated structs or arrays.",
            "observed_cluster_count": 2,
            "observed_family_count": 0,
        },
    ]
    assert len(report["readability_set"]) >= 4
    assert report["hotspots"]["top_failure_classes"][0]["failure_class"] == "cfg_failure"


def test_x86_16_tail_validation_console_summary_is_brief_when_clean(tmp_path):
    rendered = render_x86_16_tail_validation_console_summary(
        {
            "headline": "whole-tail validation clean across 12 functions",
            "severity": "clean",
            "merge_gate": True,
            "baseline_status": "matches_baseline",
            "baseline_unexpected_count": 0,
            "baseline_missing_count": 0,
            "stage_hotspots": [],
            "top_changed_verdicts": [],
        },
        cache_path=tmp_path / "tail_validation_console.json",
    )

    assert rendered["cache_hit"] is False
    assert rendered["lines"] == [
        "whole-tail validation clean across 12 functions",
        "baseline=matches_baseline unexpected=0 missing=0",
    ]


def test_x86_16_tail_validation_console_summary_expands_when_changed_and_uses_cache(tmp_path):
    cache_path = tmp_path / "tail_validation_console.json"
    surface = {
        "headline": "whole-tail validation failed across 2 functions",
        "severity": "changed",
        "merge_gate": False,
        "baseline_status": "regressed",
        "baseline_unexpected_count": 2,
        "baseline_missing_count": 0,
        "coverage_count": 0,
        "missing_stage_total": 0,
        "unknown_stage_total": 0,
        "stage_hotspots": [
            {
                "stage": "postprocess",
                "changed_count": 2,
                "changed_rate": 0.25,
                "top_verdicts": [
                    {"verdict": "postprocess whole-tail validation [live_out] changed: helper", "count": 2}
                ],
            },
            {
                "stage": "structuring",
                "changed_count": 1,
                "changed_rate": 0.125,
                "top_verdicts": [
                    {"verdict": "structuring whole-tail validation [live_out] changed: guard", "count": 1}
                ],
            },
        ],
        "top_changed_verdicts": [
            {"verdict": "postprocess whole-tail validation [live_out] changed: helper", "count": 2},
            {"verdict": "structuring whole-tail validation [live_out] changed: guard", "count": 1},
        ],
        "changed_families": [
            {
                "family": "segmented/global write delta",
                "count": 2,
                "function_count": 2,
                "stages": ("postprocess",),
                "examples": (),
            },
            {
                "family": "control-flow/guard delta",
                "count": 1,
                "function_count": 1,
                "stages": ("structuring",),
                "examples": (),
            },
        ],
        "top_changed_functions": [
            {
                "cod_file": "DOSFUNC.COD",
                "proc_name": "_dos_resize",
                "proc_kind": "NEAR",
                "stages": ("postprocess", "structuring"),
                "verdicts": (
                    "structuring whole-tail validation [live_out] changed: guard",
                    "postprocess whole-tail validation [live_out] changed: helper",
                ),
                "changed_stage_count": 2,
            },
            {
                "cod_file": "DOSFUNC.COD",
                "proc_name": "_dos_alloc",
                "proc_kind": "NEAR",
                "stages": ("postprocess",),
                "verdicts": ("postprocess whole-tail validation [live_out] changed: helper",),
                "changed_stage_count": 1,
            },
        ],
    }

    first = render_x86_16_tail_validation_console_summary(surface, cache_path=cache_path)
    second = render_x86_16_tail_validation_console_summary(surface, cache_path=cache_path)

    assert first["cache_hit"] is False
    assert first["lines"] == [
        "whole-tail validation failed across 2 functions",
        "severity=changed merge_gate=hold",
        "baseline=regressed unexpected=2 missing=0",
        "coverage=0 missing=0 unknown=0",
        "stage=postprocess changed=2 rate=0.25",
        "stage=structuring changed=1 rate=0.125",
        "family[2] segmented/global write delta functions=2 stages=postprocess",
        "family[1] control-flow/guard delta functions=1 stages=structuring",
        "verdict[2] postprocess whole-tail validation [live_out] changed: helper",
        "verdict[1] structuring whole-tail validation [live_out] changed: guard",
        "function[postprocess,structuring] DOSFUNC.COD:_dos_resize (NEAR): structuring whole-tail validation [live_out] changed: guard",
        "function[postprocess] DOSFUNC.COD:_dos_alloc (NEAR): postprocess whole-tail validation [live_out] changed: helper",
    ]
    assert second["cache_hit"] is True
    assert second["lines"] == first["lines"]


def test_x86_16_tail_validation_console_summary_calls_out_uncollected_coverage(tmp_path):
    rendered = render_x86_16_tail_validation_console_summary(
        {
            "headline": "whole-tail validation not collected across 8 functions",
            "severity": "uncollected",
            "merge_gate": False,
            "coverage_count": 0,
            "missing_stage_total": 16,
            "unknown_stage_total": 0,
            "stage_hotspots": [],
            "top_changed_verdicts": [],
            "top_uncollected_functions": [
                {
                    "cod_file": "COCKPIT.COD",
                    "proc_name": "_DisplayMaster",
                    "proc_kind": "NEAR",
                    "exit_kind": "timeout",
                }
            ],
        },
        cache_path=tmp_path / "tail_validation_console.json",
    )

    assert rendered["lines"] == [
        "whole-tail validation not collected across 8 functions",
        "severity=uncollected merge_gate=hold",
        "coverage=0 missing=16 unknown=0",
        "uncollected COCKPIT.COD:_DisplayMaster (NEAR): timeout",
    ]


def test_x86_16_tail_validation_detail_artifact_uses_cache(tmp_path):
    cache_path = tmp_path / "tail_validation_surface.json"
    surface = {
        "headline": "whole-tail validation failed across 1 functions",
        "severity": "changed",
        "top_changed_functions": [
            {
                "cod_file": "LIFE.COD",
                "proc_name": "_step",
                "proc_kind": "NEAR",
                "stages": ("postprocess",),
                "verdicts": ("postprocess whole-tail validation [live_out] changed: helper",),
                "changed_stage_count": 1,
            }
        ],
    }

    first = cache_x86_16_tail_validation_detail_artifact(surface, cache_path=cache_path)
    second = cache_x86_16_tail_validation_detail_artifact(surface, cache_path=cache_path)

    assert first["cache_hit"] is False
    assert second["cache_hit"] is True
    assert second["artifact"]["top_changed_functions"][0]["proc_name"] == "_step"
    assert first["path"] != cache_path
    assert first["path"].name.startswith("tail_validation_surface.")
    assert first["path"].suffix == ".json"
    assert second["path"] == first["path"]
    assert second["alias_path"] == cache_path
