from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .structuring_cfg_grouping import CFGGroupingArtifact, build_cfg_grouping_artifact


@dataclass(frozen=True, slots=True)
class CrossEntryGroupedUnit:
    anchor_shared_region_id: int
    primary_entry_region_ids: tuple[int, ...]
    entry_fragment_region_ids: tuple[int, ...]
    shared_region_ids: tuple[int, ...]
    member_region_ids: tuple[int, ...]
    refusal_reason: str | None = None


@dataclass(frozen=True, slots=True)
class CrossEntryGroupedUnitRefusal:
    anchor_shared_region_id: int
    shared_region_ids: tuple[int, ...]
    external_predecessor_region_ids: tuple[int, ...]
    ambiguous_predecessor_region_ids: tuple[int, ...]
    refusal_reason: str


@dataclass(frozen=True, slots=True)
class CrossEntryGroupedUnitArtifact:
    grouping: CFGGroupingArtifact
    units: tuple[CrossEntryGroupedUnit, ...]
    refusals: tuple[CrossEntryGroupedUnitRefusal, ...]
    refused_anchor_region_ids: tuple[int, ...]

    def summary_line(self) -> str:
        return f"cross_entry_grouped_units units={len(self.units)} refused={len(self.refused_anchor_region_ids)}"

    def to_dict(self) -> dict[str, object]:
        return {
            "grouping": self.grouping.to_dict(),
            "refused_anchor_region_ids": [hex(region_id) for region_id in self.refused_anchor_region_ids],
            "refusals": [
                {
                    "anchor_shared_region_id": hex(refusal.anchor_shared_region_id),
                    "shared_region_ids": [hex(region_id) for region_id in refusal.shared_region_ids],
                    "external_predecessor_region_ids": [
                        hex(region_id) for region_id in refusal.external_predecessor_region_ids
                    ],
                    "ambiguous_predecessor_region_ids": [
                        hex(region_id) for region_id in refusal.ambiguous_predecessor_region_ids
                    ],
                    "refusal_reason": refusal.refusal_reason,
                }
                for refusal in self.refusals
            ],
            "units": [
                {
                    "anchor_shared_region_id": hex(unit.anchor_shared_region_id),
                    "primary_entry_region_ids": [hex(region_id) for region_id in unit.primary_entry_region_ids],
                    "entry_fragment_region_ids": [hex(region_id) for region_id in unit.entry_fragment_region_ids],
                    "shared_region_ids": [hex(region_id) for region_id in unit.shared_region_ids],
                    "member_region_ids": [hex(region_id) for region_id in unit.member_region_ids],
                    "refusal_reason": unit.refusal_reason,
                }
                for unit in self.units
            ],
        }


def build_x86_16_cross_entry_grouped_units(codegen: Any) -> CrossEntryGroupedUnitArtifact | None:
    grouping = build_cfg_grouping_artifact(codegen)
    if grouping is None:
        return None

    record_by_region_id = {record.region_id: record for record in grouping.records}
    snapshot_nodes = {node.region_id: node for node in grouping.indirect.ownership.snapshot.nodes}
    shared_region_ids = tuple(sorted(grouping.grouped_entry_candidate_ids))
    shared_region_id_set = set(shared_region_ids)
    units: list[CrossEntryGroupedUnit] = []
    refusals: list[CrossEntryGroupedUnitRefusal] = []
    visited_shared_region_ids: set[int] = set()

    for shared_region_id in shared_region_ids:
        if shared_region_id in visited_shared_region_ids:
            continue
        if shared_region_id not in snapshot_nodes:
            refusals.append(
                CrossEntryGroupedUnitRefusal(
                    anchor_shared_region_id=shared_region_id,
                    shared_region_ids=(shared_region_id,),
                    external_predecessor_region_ids=(),
                    ambiguous_predecessor_region_ids=(),
                    refusal_reason="missing_snapshot_node",
                )
            )
            continue
        component_worklist = [shared_region_id]
        component_shared_region_ids: set[int] = set()
        while component_worklist:
            current_region_id = component_worklist.pop()
            if current_region_id in component_shared_region_ids:
                continue
            component_shared_region_ids.add(current_region_id)
            visited_shared_region_ids.add(current_region_id)
            current_node = snapshot_nodes.get(current_region_id)
            if current_node is None:
                continue
            neighbor_ids = set(current_node.predecessor_ids) | set(current_node.successor_ids)
            for neighbor_region_id in neighbor_ids:
                if neighbor_region_id in shared_region_id_set and neighbor_region_id not in component_shared_region_ids:
                    component_worklist.append(neighbor_region_id)

        component_shared_region_ids_tuple = tuple(sorted(component_shared_region_ids))
        anchor_shared_region_id = component_shared_region_ids_tuple[0]
        external_predecessor_ids = sorted(
            {
                predecessor_region_id
                for component_region_id in component_shared_region_ids_tuple
                for predecessor_region_id in snapshot_nodes.get(component_region_id, type("_N", (), {"predecessor_ids": ()})()).predecessor_ids
                if predecessor_region_id not in component_shared_region_ids and predecessor_region_id in record_by_region_id
            }
        )
        primary_entry_region_ids = tuple(
            region_id
            for region_id in external_predecessor_ids
            if record_by_region_id[region_id].grouping_kind == "primary_entry"
        )
        entry_fragment_region_ids = tuple(
            region_id
            for region_id in external_predecessor_ids
            if record_by_region_id[region_id].grouping_kind == "entry_fragment"
        )
        ambiguous_predecessor_ids = tuple(
            region_id
            for region_id in external_predecessor_ids
            if record_by_region_id[region_id].grouping_kind == "grouped_entry_candidate"
        )
        refusal_reason = None
        if ambiguous_predecessor_ids:
            refusal_reason = "shared_predecessor_anchor"
        elif not primary_entry_region_ids and not entry_fragment_region_ids:
            refusal_reason = "no_external_entry_context"
        member_region_ids = tuple(
            sorted(
                set(primary_entry_region_ids)
                | set(entry_fragment_region_ids)
                | set(component_shared_region_ids_tuple)
                | set(ambiguous_predecessor_ids)
            )
        )
        if refusal_reason is not None:
            refusals.append(
                CrossEntryGroupedUnitRefusal(
                    anchor_shared_region_id=anchor_shared_region_id,
                    shared_region_ids=component_shared_region_ids_tuple,
                    external_predecessor_region_ids=tuple(external_predecessor_ids),
                    ambiguous_predecessor_region_ids=ambiguous_predecessor_ids,
                    refusal_reason=refusal_reason,
                )
            )
            continue
        units.append(
            CrossEntryGroupedUnit(
                anchor_shared_region_id=anchor_shared_region_id,
                primary_entry_region_ids=primary_entry_region_ids,
                entry_fragment_region_ids=entry_fragment_region_ids,
                shared_region_ids=component_shared_region_ids_tuple,
                member_region_ids=member_region_ids,
                refusal_reason=None,
            )
        )

    return CrossEntryGroupedUnitArtifact(
        grouping=grouping,
        units=tuple(units),
        refusals=tuple(sorted(refusals, key=lambda item: item.anchor_shared_region_id)),
        refused_anchor_region_ids=tuple(sorted({item.anchor_shared_region_id for item in refusals})),
    )


def apply_x86_16_cross_entry_grouped_units(codegen: Any) -> bool:
    artifact = build_x86_16_cross_entry_grouped_units(codegen)
    setattr(codegen, "_inertia_cross_entry_grouped_units", artifact)
    if artifact is None:
        setattr(codegen, "_inertia_cross_entry_unit_members", ())
        return False
    member_region_ids = tuple(
        sorted(
            {
                region_id
                for unit in artifact.units
                for region_id in unit.member_region_ids
            }
        )
    )
    setattr(codegen, "_inertia_cross_entry_unit_members", member_region_ids)
    return bool(artifact.units)


def describe_x86_16_cross_entry_grouped_unit_surface() -> dict[str, object]:
    return {
        "producer": "build_x86_16_cross_entry_grouped_units",
        "artifact_attr": "_inertia_cross_entry_grouped_units",
        "member_attr": "_inertia_cross_entry_unit_members",
        "purpose": "Materialize grouped multi-entry CFG units before region structuring.",
    }


__all__ = [
    "CrossEntryGroupedUnit",
    "CrossEntryGroupedUnitRefusal",
    "CrossEntryGroupedUnitArtifact",
    "apply_x86_16_cross_entry_grouped_units",
    "build_x86_16_cross_entry_grouped_units",
    "describe_x86_16_cross_entry_grouped_unit_surface",
]
