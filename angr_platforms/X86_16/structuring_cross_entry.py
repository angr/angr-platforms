from __future__ import annotations

from typing import Any

from .structuring_grouped_graph_builder import build_grouped_region_graph


def apply_x86_16_cross_entry_grouping(codegen: Any) -> bool:
    grouped_graph = build_grouped_region_graph(codegen)
    artifact = grouped_graph.grouped_units.grouping if grouped_graph.grouped_units is not None else None
    setattr(codegen, "_inertia_cfg_grouping_artifact", artifact)
    setattr(codegen, "_inertia_grouped_region_graph", grouped_graph.graph_result.graph)
    if artifact is None:
        setattr(codegen, "_inertia_grouped_entry_candidate_ids", ())
        setattr(codegen, "_inertia_entry_fragment_ids", ())
        setattr(codegen, "_inertia_cross_entry_grouped_units", grouped_graph.grouped_units)
        setattr(codegen, "_inertia_cross_entry_unit_members", ())
        return False
    grouped_entry_candidate_ids = tuple(artifact.grouped_entry_candidate_ids)
    entry_fragment_ids = tuple(artifact.entry_fragment_ids)
    setattr(codegen, "_inertia_grouped_entry_candidate_ids", grouped_entry_candidate_ids)
    setattr(codegen, "_inertia_entry_fragment_ids", entry_fragment_ids)
    setattr(codegen, "_inertia_cross_entry_grouped_units", grouped_graph.grouped_units)
    member_region_ids = (
        tuple(
            sorted(
                {
                    region_id
                    for unit in grouped_graph.grouped_units.units
                    for region_id in unit.member_region_ids
                }
            )
        )
        if grouped_graph.grouped_units is not None
        else ()
    )
    setattr(codegen, "_inertia_cross_entry_unit_members", member_region_ids)
    return bool(grouped_entry_candidate_ids or entry_fragment_ids or member_region_ids)


def describe_x86_16_cross_entry_grouping_surface() -> dict[str, object]:
    return {
        "producer": "build_cfg_grouping_artifact",
        "artifact_attr": "_inertia_cfg_grouping_artifact",
        "candidate_attr": "_inertia_grouped_entry_candidate_ids",
        "entry_fragment_attr": "_inertia_entry_fragment_ids",
        "grouped_unit_attr": "_inertia_cross_entry_grouped_units",
        "grouped_graph_attr": "_inertia_grouped_region_graph",
        "purpose": "Run CFG grouping export before region structuring/codegen.",
    }


__all__ = [
    "apply_x86_16_cross_entry_grouping",
    "describe_x86_16_cross_entry_grouping_surface",
]
