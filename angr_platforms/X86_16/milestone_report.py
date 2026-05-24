from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .addressing_helpers import (
    describe_x86_16_decode_width_matrix,
    describe_x86_16_mixed_width_extension_surface,
    describe_x86_16_mixed_width_instruction_surface,
)
from .alias.alias_model import describe_x86_16_alias_recovery_api
from .analysis_helpers import (
    describe_x86_16_interrupt_api_surface,
    describe_x86_16_interrupt_core_surface,
    describe_x86_16_interrupt_lowering_boundary,
)
from .cod_known_objects import describe_x86_16_cod_known_objects
from .cod_source_rewrites import (
    describe_x86_16_source_backed_rewrite_debt,
    describe_x86_16_source_backed_rewrite_status,
)
from .correctness_goals import describe_x86_16_correctness_goals, summarize_x86_16_correctness_goals
from .decompiler_postprocess_simplify import describe_x86_16_projection_cleanup_rules
from .instruction import describe_x86_16_instruction_metadata_surface
from .readability_goals import (
    describe_x86_16_readability_goals,
    summarize_readability_focus,
    summarize_readability_goals,
)
from .readability_set import describe_x86_16_golden_readability_set, summarize_x86_16_golden_readability_set
from .recovery_confidence import describe_x86_16_recovery_confidence_axes
from .recovery_manifest import describe_x86_16_object_recovery_focus, describe_x86_16_recovery_layers
from .tail_validation import build_x86_16_validation_cache_descriptor
from .validation_manifest import (
    describe_x86_16_validation_families,
    describe_x86_16_validation_layers,
    describe_x86_16_validation_triage,
)
from .widening_model import describe_x86_16_widening_pipeline


@dataclass(frozen=True)
class MilestoneReportSection:
    name: str
    summary: Mapping[str, object]


def _tail_validation_cache_key(surface: Mapping[str, object]) -> str:
    return build_x86_16_validation_cache_descriptor("tail_validation.console_summary", surface).cache_key


def _content_addressed_cache_path(path: Path, cache_key: str) -> Path:
    return path.with_name(f"{path.stem}.{cache_key[:12]}{path.suffix}")


def _render_tail_validation_lines(surface: Mapping[str, object]) -> list[str]:
    headline = str(surface.get("headline", "whole-tail validation summary unavailable"))
    severity = str(surface.get("severity", "uncollected"))
    merge_gate = bool(surface.get("merge_gate", False))
    stage_hotspots = list(surface.get("stage_hotspots", []) or [])
    changed_families = list(surface.get("changed_families", []) or [])
    top_changed_verdicts = list(surface.get("top_changed_verdicts", []) or [])
    top_changed_functions = list(surface.get("top_changed_functions", []) or [])
    top_uncollected_functions = list(surface.get("top_uncollected_functions", []) or [])
    top_unknown_functions = list(surface.get("top_unknown_functions", []) or [])
    coverage_count = int(surface.get("coverage_count", 0) or 0)
    missing_stage_total = int(surface.get("missing_stage_total", 0) or 0)
    unknown_stage_total = int(surface.get("unknown_stage_total", 0) or 0)
    baseline_status = surface.get("baseline_status")
    baseline_unexpected_count = int(surface.get("baseline_unexpected_count", 0) or 0)
    baseline_missing_count = int(surface.get("baseline_missing_count", 0) or 0)

    lines = [headline]
    if severity == "clean":
        if isinstance(baseline_status, str) and baseline_status:
            lines.append(
                f"baseline={baseline_status} unexpected={baseline_unexpected_count} missing={baseline_missing_count}"
            )
        return lines

    lines.append(f"severity={severity} merge_gate={'pass' if merge_gate else 'hold'}")
    if isinstance(baseline_status, str) and baseline_status:
        lines.append(f"baseline={baseline_status} unexpected={baseline_unexpected_count} missing={baseline_missing_count}")
    lines.append(
        f"coverage={coverage_count} missing={missing_stage_total} unknown={unknown_stage_total}"
    )
    for item in top_uncollected_functions[:3]:
        proc_name = item.get("proc_name")
        proc_kind = item.get("proc_kind")
        cod_file = item.get("cod_file")
        exit_kind = item.get("exit_kind")
        if not isinstance(proc_name, str) or not proc_name:
            continue
        label = proc_name
        if isinstance(cod_file, str) and cod_file:
            label = f"{cod_file}:{label}"
        if isinstance(proc_kind, str) and proc_kind:
            label = f"{label} ({proc_kind})"
        if isinstance(exit_kind, str) and exit_kind:
            lines.append(f"uncollected {label}: {exit_kind}")
        else:
            lines.append(f"uncollected {label}")
    for item in top_unknown_functions[:3]:
        proc_name = item.get("proc_name")
        proc_kind = item.get("proc_kind")
        cod_file = item.get("cod_file")
        if not isinstance(proc_name, str) or not proc_name:
            continue
        label = proc_name
        if isinstance(cod_file, str) and cod_file:
            label = f"{cod_file}:{label}"
        if isinstance(proc_kind, str) and proc_kind:
            label = f"{label} ({proc_kind})"
        lines.append(f"unknown {label}")
    for hotspot in stage_hotspots[:2]:
        stage = hotspot.get("stage", "unknown")
        changed_count = hotspot.get("changed_count", 0)
        changed_rate = hotspot.get("changed_rate", 0.0)
        lines.append(f"stage={stage} changed={changed_count} rate={changed_rate}")
    for family_row in changed_families[:3]:
        family = family_row.get("family")
        count = family_row.get("count")
        function_count = family_row.get("function_count")
        stages = ",".join(family_row.get("stages", ()) or ())
        if isinstance(family, str) and family:
            lines.append(f"family[{count}] {family} functions={function_count} stages={stages}")
    for item in top_changed_verdicts[:3]:
        verdict = item.get("verdict")
        count = item.get("count")
        if isinstance(verdict, str) and verdict:
            lines.append(f"verdict[{count}] {verdict}")
    for item in top_changed_functions[:3]:
        proc_name = item.get("proc_name")
        proc_kind = item.get("proc_kind")
        cod_file = item.get("cod_file")
        stages = ",".join(item.get("stages", ()) or ())
        verdicts = list(item.get("verdicts", ()) or ())
        if not isinstance(proc_name, str) or not proc_name:
            continue
        label = proc_name
        if isinstance(cod_file, str) and cod_file:
            label = f"{cod_file}:{label}"
        if isinstance(proc_kind, str) and proc_kind:
            label = f"{label} ({proc_kind})"
        if verdicts:
            lines.append(f"function[{stages}] {label}: {verdicts[0]}")
        else:
            lines.append(f"function[{stages}] {label}")
    return lines


def render_x86_16_tail_validation_console_summary(
    surface: Mapping[str, object],
    *,
    cache_path: str | Path | None = None,
) -> dict[str, object]:
    cache_key = _tail_validation_cache_key(surface)
    if cache_path is not None:
        path = Path(cache_path)
        try:
            cached = json.loads(path.read_text())
            if cached.get("cache_key") == cache_key:
                return {
                    "cache_key": cache_key,
                    "cache_hit": True,
                    "lines": list(cached.get("lines", []) or []),
                }
        except Exception:
            pass

    lines = _render_tail_validation_lines(surface)
    rendered = {
        "cache_key": cache_key,
        "cache_hit": False,
        "lines": lines,
    }
    if cache_path is not None:
        path = Path(cache_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"cache_key": cache_key, "lines": lines}, indent=2, sort_keys=True) + "\n")
        except Exception:
            pass
    return rendered


def cache_x86_16_tail_validation_detail_artifact(
    surface: Mapping[str, object],
    *,
    cache_path: str | Path | None,
) -> dict[str, object]:
    artifact = dict(surface)
    cache_key = _tail_validation_cache_key(artifact)
    if cache_path is None:
        return {
            "cache_key": cache_key,
            "cache_hit": False,
            "artifact": artifact,
            "path": None,
        }

    path = Path(cache_path)
    immutable_path = _content_addressed_cache_path(path, cache_key)
    try:
        cached = json.loads(path.read_text())
        if cached.get("cache_key") == cache_key:
            cached_artifact = cached.get("artifact", {})
            return {
                "cache_key": cache_key,
                "cache_hit": True,
                "artifact": dict(cached_artifact) if isinstance(cached_artifact, Mapping) else artifact,
                "path": immutable_path if immutable_path.exists() else path,
                "alias_path": path,
            }
    except Exception:
        pass

    payload = {
        "cache_key": cache_key,
        "artifact": artifact,
    }
    try:
        immutable_path.parent.mkdir(parents=True, exist_ok=True)
        immutable_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    except Exception:
        pass
    return {
        "cache_key": cache_key,
        "cache_hit": False,
        "artifact": artifact,
        "path": immutable_path,
        "alias_path": path,
    }


def _success_rate(summary: Mapping[str, object]) -> float:
    scanned = int(summary.get("scanned", 0) or 0)
    ok = int(summary.get("ok", 0) or 0)
    if scanned <= 0:
        return 0.0
    return round(ok / scanned, 6)


def _readability_tier(result: Mapping[str, object], golden_cases: set[tuple[str, str]]) -> str:
    if not bool(result.get("ok", False)):
        return "R0"
    fallback_kind = result.get("fallback_kind")
    if fallback_kind not in (None, "none"):
        return "R1"
    if int(result.get("decompiled_count", 0) or 0) <= 0:
        return "R1"
    golden_key = (str(result.get("cod_file", "")), str(result.get("proc_name", "")))
    if golden_key in golden_cases:
        return "R3"
    return "R2"


def _build_corpus_completion_surface(
    scan_summary: Mapping[str, object],
    *,
    readability_tiers: Mapping[str, int],
    timeout_stage_counts: Mapping[str, int],
    top_fallback_files: list[dict[str, object]],
    top_fallback_functions: list[dict[str, object]],
    top_ugly_clusters: list[dict[str, object]],
    readability_clusters: list[dict[str, object]],
    family_ownership: Mapping[str, object],
    readability_focus: Mapping[str, object],
) -> dict[str, object]:
    scanned = int(scan_summary.get("scanned", 0) or 0)
    failed = int(scan_summary.get("failed", 0) or 0)
    full_decompile_count = int(scan_summary.get("full_decompile_count", 0) or 0)
    cfg_only_count = int(scan_summary.get("cfg_only_count", 0) or 0)
    lift_only_count = int(scan_summary.get("lift_only_count", 0) or 0)
    block_lift_count = int(scan_summary.get("block_lift_count", 0) or 0)
    debt = dict(scan_summary.get("debt", {}) or {})
    visibility_debt = int(scan_summary.get("visibility_debt", debt.get("traversal", 0)) or 0)
    recovery_debt = int(scan_summary.get("recovery_debt", debt.get("recovery", 0)) or 0)
    readability_debt = int(scan_summary.get("readability_debt", debt.get("readability", 0)) or 0)
    unclassified_failure_count = int(scan_summary.get("unclassified_failure_count", 0) or 0)
    rewrite_failure_count = int(scan_summary.get("rewrite_failure_count", 0) or 0)
    structuring_failure_count = int(scan_summary.get("structuring_failure_count", 0) or 0)
    regeneration_failure_count = int(scan_summary.get("regeneration_failure_count", 0) or 0)
    confidence = dict(scan_summary.get("confidence", {}) or {})
    confidence_status_counts = dict(scan_summary.get("confidence_status_counts", {}) or {})
    confidence_scan_safe_counts = dict(scan_summary.get("confidence_scan_safe_counts", {}) or {})
    confidence_assumption_counts = dict(scan_summary.get("confidence_assumption_counts", {}) or {})
    confidence_evidence_counts = dict(scan_summary.get("confidence_evidence_counts", {}) or {})
    confidence_diagnostic_counts = dict(scan_summary.get("confidence_diagnostic_counts", {}) or {})
    tail_validation = dict(scan_summary.get("tail_validation", {}) or {})
    tail_validation_surface = dict(scan_summary.get("tail_validation_surface", {}) or {})
    blind_spot_budget = dict(scan_summary.get("blind_spot_budget", {}) or {})
    return {
        "no_crashes": failed == 0,
        "no_blind_spots": unclassified_failure_count == 0,
        "unclassified_failure_count": unclassified_failure_count,
        "scanned": scanned,
        "fallback_coverage": {
            "full_decompile_count": full_decompile_count,
            "cfg_only_count": cfg_only_count,
            "lift_only_count": lift_only_count,
            "block_lift_count": block_lift_count,
        },
        "debt": {
            "visibility": visibility_debt,
            "recovery": recovery_debt,
            "readability": readability_debt,
        },
        "postprocess_failures": {
            "rewrite_failure_count": rewrite_failure_count,
            "structuring_failure_count": structuring_failure_count,
            "regeneration_failure_count": regeneration_failure_count,
        },
        "confidence": confidence,
        "confidence_status_counts": confidence_status_counts,
        "confidence_scan_safe_counts": confidence_scan_safe_counts,
        "confidence_assumption_counts": confidence_assumption_counts,
        "confidence_evidence_counts": confidence_evidence_counts,
        "confidence_diagnostic_counts": confidence_diagnostic_counts,
        "tail_validation": tail_validation,
        "tail_validation_surface": tail_validation_surface,
        "blind_spot_budget": blind_spot_budget,
        "stable_by_traversal": failed == 0 and unclassified_failure_count == 0,
        "merge_gate": failed == 0 and unclassified_failure_count == 0,
        "readability_tiers": dict(readability_tiers),
        "timeout_stage_counts": timeout_stage_counts,
        "fallback_backlog": {
            "top_fallback_files": top_fallback_files,
            "top_fallback_functions": top_fallback_functions,
        },
        "readability_backlog": {
            "top_ugly_clusters": top_ugly_clusters,
            "readability_clusters": readability_clusters,
            "family_ownership": family_ownership,
        },
        "readability_focus": {
            "goal_queue": [
                {
                    "step": item["step"],
                    "title": item["title"],
                    "priority": item["priority"],
                    "deterministic_goal": item["deterministic_goal"],
                    "target_clusters": list(item["target_clusters"]),
                    "owner_surfaces": list(item["owner_surfaces"]),
                    "completion_signal": item["completion_signal"],
                    "observed_cluster_count": item["observed_cluster_count"],
                    "observed_family_count": item["observed_family_count"],
                    "rank": item["rank"],
                    "is_next_focus": item["is_next_focus"],
                }
                for item in readability_focus["goal_queue"]
            ],
            "next_goal": None
            if readability_focus.get("next_goal") is None
            else {
                "step": readability_focus["next_goal"]["step"],
                "title": readability_focus["next_goal"]["title"],
                "priority": readability_focus["next_goal"]["priority"],
                "deterministic_goal": readability_focus["next_goal"]["deterministic_goal"],
                "target_clusters": list(readability_focus["next_goal"]["target_clusters"]),
                "owner_surfaces": list(readability_focus["next_goal"]["owner_surfaces"]),
                "completion_signal": readability_focus["next_goal"]["completion_signal"],
                "observed_cluster_count": readability_focus["next_goal"]["observed_cluster_count"],
                "observed_family_count": readability_focus["next_goal"]["observed_family_count"],
                "rank": readability_focus["next_goal"]["rank"],
                "is_next_focus": readability_focus["next_goal"]["is_next_focus"],
            },
            "top_ugly_clusters": top_ugly_clusters,
            "readability_clusters": readability_clusters,
            "family_ownership": family_ownership,
        },
    }


def build_x86_16_milestone_report(
    scan_summary: Mapping[str, object],
    *,
    corpus_name: str = "x86-16",
    corpus_slice: str | None = None,
    blocked_mnemonics: Sequence[str] | None = None,
) -> dict[str, object]:
    validation_layers = describe_x86_16_validation_layers()
    validation_families = describe_x86_16_validation_families()
    validation_triage = describe_x86_16_validation_triage()
    readability_set = describe_x86_16_golden_readability_set()
    correctness_goals = describe_x86_16_correctness_goals()
    alias_api = describe_x86_16_alias_recovery_api()
    widening_pipeline = describe_x86_16_widening_pipeline()
    recovery_layers = describe_x86_16_recovery_layers()
    object_recovery_focus = describe_x86_16_object_recovery_focus()
    recovery_confidence_axes = describe_x86_16_recovery_confidence_axes()
    projection_cleanup_rules = describe_x86_16_projection_cleanup_rules()
    readability_goals = describe_x86_16_readability_goals()
    decode_width_matrix = describe_x86_16_decode_width_matrix()
    mixed_width_extension_surface = describe_x86_16_mixed_width_extension_surface()
    mixed_width_instruction_surface = describe_x86_16_mixed_width_instruction_surface()
    interrupt_api_surface = describe_x86_16_interrupt_api_surface()
    interrupt_core_surface = describe_x86_16_interrupt_core_surface()
    interrupt_lowering_boundary = describe_x86_16_interrupt_lowering_boundary()
    instruction_metadata_surface = describe_x86_16_instruction_metadata_surface()
    failure_counts = dict(scan_summary.get("failure_counts", {}) or {})
    fallback_counts = dict(scan_summary.get("fallback_counts", {}) or {})
    top_failure_classes = list(scan_summary.get("top_failure_classes", []) or [])
    top_fallback_kinds = list(scan_summary.get("top_fallback_kinds", []) or [])
    top_failure_stages = list(scan_summary.get("top_failure_stages", []) or [])
    timeout_stage_counts = dict(scan_summary.get("timeout_stage_counts", {}) or {})
    top_failure_files = list(scan_summary.get("top_failure_files", []) or [])
    top_failure_functions = list(scan_summary.get("top_failure_functions", []) or [])
    top_fallback_files = list(scan_summary.get("top_fallback_files", []) or [])
    top_fallback_functions = list(scan_summary.get("top_fallback_functions", []) or [])
    blind_spot_budget = dict(scan_summary.get("blind_spot_budget", {}) or {})
    debt = dict(scan_summary.get("debt", {}) or {})
    visibility_debt = int(scan_summary.get("visibility_debt", debt.get("traversal", 0)) or 0)
    recovery_debt = int(scan_summary.get("recovery_debt", debt.get("recovery", 0)) or 0)
    readability_debt = int(scan_summary.get("readability_debt", debt.get("readability", 0)) or 0)
    rewrite_failure_count = int(scan_summary.get("rewrite_failure_count", 0) or 0)
    structuring_failure_count = int(scan_summary.get("structuring_failure_count", 0) or 0)
    regeneration_failure_count = int(scan_summary.get("regeneration_failure_count", 0) or 0)
    confidence = dict(scan_summary.get("confidence", {}) or {})
    confidence_status_counts = dict(scan_summary.get("confidence_status_counts", {}) or {})
    confidence_scan_safe_counts = dict(scan_summary.get("confidence_scan_safe_counts", {}) or {})
    confidence_assumption_counts = dict(scan_summary.get("confidence_assumption_counts", {}) or {})
    confidence_evidence_counts = dict(scan_summary.get("confidence_evidence_counts", {}) or {})
    confidence_diagnostic_counts = dict(scan_summary.get("confidence_diagnostic_counts", {}) or {})
    tail_validation = dict(scan_summary.get("tail_validation", {}) or {})
    tail_validation_surface = dict(scan_summary.get("tail_validation_surface", {}) or {})
    top_ugly_clusters = list(scan_summary.get("top_ugly_clusters", []) or [])
    readability_clusters = list(scan_summary.get("readability_clusters", []) or [])
    family_ownership = dict(scan_summary.get("family_ownership", {}) or {})
    interrupt_api = dict(scan_summary.get("interrupt_api", {}) or {})
    scan_results = list(scan_summary.get("results", []) or [])
    golden_cases = {(case.source, case.proc_name) for case in readability_set}
    readability_tier_counts = {"R0": 0, "R1": 0, "R2": 0, "R3": 0}
    for result in scan_results:
        readability_tier_counts[_readability_tier(result, golden_cases)] += 1
    source_backed_rewrites = describe_x86_16_source_backed_rewrite_status()
    source_backed_rewrite_debt = describe_x86_16_source_backed_rewrite_debt()
    cod_known_objects = describe_x86_16_cod_known_objects()
    correctness_goal_summary = summarize_x86_16_correctness_goals()
    readability_focus = summarize_readability_focus(top_ugly_clusters, readability_clusters, family_ownership)
    corpus_completion = _build_corpus_completion_surface(
        scan_summary,
        readability_tiers=readability_tier_counts,
        timeout_stage_counts=timeout_stage_counts,
        top_fallback_files=top_fallback_files,
        top_fallback_functions=top_fallback_functions,
        top_ugly_clusters=top_ugly_clusters,
        readability_clusters=readability_clusters,
        family_ownership=family_ownership,
        readability_focus=readability_focus,
    )
    readability_goal_summary = summarize_readability_goals(top_ugly_clusters, readability_clusters, family_ownership)

    report = {
        "corpus": corpus_name,
        "corpus_slice": corpus_slice or scan_summary.get("slice", "active"),
        "scan_summary": dict(scan_summary),
        "validation_layers": [
            {"name": name, "default_checks": list(checks)} for name, checks in validation_layers
        ],
        "validation_families": [
            {"name": name, "default_checks": list(checks)} for name, checks in validation_families
        ],
        "validation_triage": validation_triage,
        "alias_api": [
            {"name": name, "purpose": purpose, "helpers": list(helpers)}
            for name, purpose, helpers in alias_api
        ],
        "decode_width_matrix": [
            {"name": name, "operand_bits": operand_bits, "address_bits": address_bits}
            for name, operand_bits, address_bits in decode_width_matrix
        ],
        "mixed_width_extension_surface": mixed_width_extension_surface,
        "mixed_width_instruction_surface": mixed_width_instruction_surface,
        "widening_pipeline": [
            {"name": name, "purpose": purpose, "helpers": list(helpers)}
            for name, purpose, helpers in widening_pipeline
        ],
        "recovery_layers": [
            {"name": name, "purpose": purpose, "helpers": list(helpers)}
            for name, purpose, helpers in recovery_layers
        ],
        "recovery_confidence_axes": [
            {"status": status, "meaning": meaning}
            for status, meaning in recovery_confidence_axes
        ],
        "object_recovery_focus": [
            {"name": name, "purpose": purpose, "helpers": list(helpers)}
            for name, purpose, helpers in object_recovery_focus
        ],
        "projection_cleanup_rules": [
            {"name": name, "purpose": purpose}
            for name, purpose in projection_cleanup_rules
        ],
        "readability_goals": [
            {
                "step": step,
                "title": title,
                "deterministic_goal": deterministic_goal,
                "target_clusters": list(target_clusters),
                "owner_surfaces": list(owner_surfaces),
                "completion_signal": completion_signal,
            }
            for step, title, deterministic_goal, target_clusters, owner_surfaces, completion_signal in readability_goals
        ],
        "readability_set_summary": [
            {"source": source, "proc_name": proc_name, "anchor_count": anchor_count}
            for source, proc_name, anchor_count in summarize_x86_16_golden_readability_set()
        ],
        "readability_set": [asdict(case) for case in readability_set],
        "correctness_goals": [
            {
                "code": code,
                "title": title,
                "priority": priority,
                "status": status,
                "owner_surfaces": list(owner_surfaces),
                "completion_signal": completion_signal,
            }
            for code, title, priority, status, owner_surfaces, completion_signal in correctness_goals
        ],
        "correctness_goal_summary": correctness_goal_summary,
        "blocked_mnemonics": list(blocked_mnemonics or ()),
        "corpus_rates": {
            "success_rate": _success_rate(scan_summary),
            "failure_rate": round(1.0 - _success_rate(scan_summary), 6),
            "full_decompile_rate": round(int(scan_summary.get("full_decompile_count", 0) or 0) / max(int(scan_summary.get("scanned", 0) or 0), 1), 6),
            "cfg_only_rate": round(int(scan_summary.get("cfg_only_count", 0) or 0) / max(int(scan_summary.get("scanned", 0) or 0), 1), 6),
            "lift_only_rate": round(int(scan_summary.get("lift_only_count", 0) or 0) / max(int(scan_summary.get("scanned", 0) or 0), 1), 6),
            "block_lift_rate": round(int(scan_summary.get("block_lift_count", 0) or 0) / max(int(scan_summary.get("scanned", 0) or 0), 1), 6),
        },
        "blind_spot_budget": blind_spot_budget,
        "debt": debt,
        "debt_breakdown": {
            "visibility": visibility_debt,
            "recovery": recovery_debt,
            "readability": readability_debt,
        },
        "postprocess_failures": {
            "rewrite_failure_count": rewrite_failure_count,
            "structuring_failure_count": structuring_failure_count,
            "regeneration_failure_count": regeneration_failure_count,
        },
        "confidence": confidence,
        "confidence_status_counts": confidence_status_counts,
        "confidence_scan_safe_counts": confidence_scan_safe_counts,
        "confidence_assumption_counts": confidence_assumption_counts,
        "confidence_evidence_counts": confidence_evidence_counts,
        "confidence_diagnostic_counts": confidence_diagnostic_counts,
        "tail_validation": tail_validation,
        "tail_validation_surface": tail_validation_surface,
        "interrupt_api": {
            "dos_helpers": int(interrupt_api.get("dos_helpers", 0) or 0),
            "bios_helpers": int(interrupt_api.get("bios_helpers", 0) or 0),
            "wrapper_calls": int(interrupt_api.get("wrapper_calls", 0) or 0),
            "unresolved_wrappers": int(interrupt_api.get("unresolved_wrappers", 0) or 0),
        },
        "interrupt_api_surface": interrupt_api_surface,
        "interrupt_core_surface": interrupt_core_surface,
        "interrupt_lowering_boundary": interrupt_lowering_boundary,
        "instruction_metadata_surface": instruction_metadata_surface,
        "readability_tiers": readability_tier_counts,
        "readability_goal_summary": [
            {
                "step": item["step"],
                "title": item["title"],
                "priority": item["priority"],
                "deterministic_goal": item["deterministic_goal"],
                "target_clusters": list(item["target_clusters"]),
                "owner_surfaces": list(item["owner_surfaces"]),
                "completion_signal": item["completion_signal"],
                "observed_cluster_count": item["observed_cluster_count"],
                "observed_family_count": item["observed_family_count"],
            }
            for item in readability_goal_summary
        ],
        "readability_goal_queue": [
            {
                "step": item["step"],
                "title": item["title"],
                "priority": item["priority"],
                "deterministic_goal": item["deterministic_goal"],
                "target_clusters": list(item["target_clusters"]),
                "owner_surfaces": list(item["owner_surfaces"]),
                "completion_signal": item["completion_signal"],
                "observed_cluster_count": item["observed_cluster_count"],
                "observed_family_count": item["observed_family_count"],
                "rank": item["rank"],
                "is_next_focus": item["is_next_focus"],
            }
            for item in readability_focus["goal_queue"]
        ],
        "readability_focus": {
            "next_goal": None
            if readability_focus.get("next_goal") is None
            else {
                "step": readability_focus["next_goal"]["step"],
                "title": readability_focus["next_goal"]["title"],
                "priority": readability_focus["next_goal"]["priority"],
                "deterministic_goal": readability_focus["next_goal"]["deterministic_goal"],
                "target_clusters": list(readability_focus["next_goal"]["target_clusters"]),
                "owner_surfaces": list(readability_focus["next_goal"]["owner_surfaces"]),
                "completion_signal": readability_focus["next_goal"]["completion_signal"],
                "observed_cluster_count": readability_focus["next_goal"]["observed_cluster_count"],
                "observed_family_count": readability_focus["next_goal"]["observed_family_count"],
                "rank": readability_focus["next_goal"]["rank"],
                "is_next_focus": readability_focus["next_goal"]["is_next_focus"],
            },
            "top_ugly_clusters": top_ugly_clusters,
            "readability_clusters": readability_clusters,
            "family_ownership": family_ownership,
        },
        "hotspots": {
            "failure_counts": failure_counts,
            "fallback_counts": fallback_counts,
            "top_failure_classes": top_failure_classes,
            "top_fallback_kinds": top_fallback_kinds,
        "top_failure_stages": top_failure_stages,
        "timeout_stage_counts": timeout_stage_counts,
        "top_failure_files": top_failure_files,
            "top_failure_functions": top_failure_functions,
            "top_fallback_files": top_fallback_files,
            "top_fallback_functions": top_fallback_functions,
            "top_ugly_clusters": top_ugly_clusters,
            "readability_clusters": readability_clusters,
            "family_ownership": family_ownership,
        },
        "source_backed_rewrites": source_backed_rewrites,
        "source_backed_rewrite_debt": source_backed_rewrite_debt,
        "cod_known_objects": cod_known_objects,
        "corpus_completion": corpus_completion,
    }
    return report


def write_x86_16_milestone_report(
    output_path: str | Path,
    scan_summary: Mapping[str, object],
    *,
    corpus_name: str = "x86-16",
    corpus_slice: str | None = None,
    blocked_mnemonics: Sequence[str] | None = None,
) -> Path:
    path = Path(output_path)
    path.write_text(
        json.dumps(
            build_x86_16_milestone_report(
                scan_summary,
                corpus_name=corpus_name,
                corpus_slice=corpus_slice,
                blocked_mnemonics=blocked_mnemonics,
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    return path


__all__ = [
    "MilestoneReportSection",
    "build_x86_16_milestone_report",
    "cache_x86_16_tail_validation_detail_artifact",
    "render_x86_16_tail_validation_console_summary",
    "write_x86_16_milestone_report",
]
