"""
Abnormal loop-entry and loop-exit normalization for region structuring.

This keeps dedicated abnormal-loop policy out of the main structuring driver.
The goal is not to guess prettier C late. The goal is to make loop-shape
evidence explicit at the CFG layer so later codegen can stay honest.
"""

from __future__ import annotations

from dataclasses import dataclass

from .structuring_analysis import StructureAnalysis
from .structuring_loops import NaturalLoopInfo
from .structuring_region import DominatorInfo, Region, RegionGraph, RegionType


@dataclass(frozen=True)
class LoopEdgeRef:
    source_region_id: int | None
    target_region_id: int | None

    def to_dict(self) -> dict[str, int | None]:
        return {
            "source_region_id": self.source_region_id,
            "target_region_id": self.target_region_id,
        }


@dataclass(frozen=True)
class AbnormalLoopNormalizationPlan:
    header_region_id: int | None
    body_region_ids: tuple[int | None, ...]
    abnormal_entries: tuple[LoopEdgeRef, ...]
    abnormal_exits: tuple[LoopEdgeRef, ...]
    entry_variable_name: str | None
    exit_variable_name: str | None

    @property
    def needs_entry_variable(self) -> bool:
        return bool(self.abnormal_entries)

    @property
    def needs_exit_variable(self) -> bool:
        return bool(self.abnormal_exits)

    @property
    def can_normalize(self) -> bool:
        return bool(self.entry_variable_name or self.exit_variable_name)

    def to_dict(self) -> dict[str, object]:
        return {
            "header_region_id": self.header_region_id,
            "body_region_ids": list(self.body_region_ids),
            "abnormal_entries": [edge.to_dict() for edge in self.abnormal_entries],
            "abnormal_exits": [edge.to_dict() for edge in self.abnormal_exits],
            "entry_variable_name": self.entry_variable_name,
            "exit_variable_name": self.exit_variable_name,
            "can_normalize": self.can_normalize,
        }


def _sorted_regions(regions: set[Region]) -> list[Region]:
    return sorted(
        regions,
        key=lambda region: (
            region.region_id is None,
            region.region_id if region.region_id is not None else -1,
        ),
    )


def build_abnormal_loop_normalization_plan(
    graph: RegionGraph,
    dominators: DominatorInfo | None,
    loop_info: NaturalLoopInfo,
) -> AbnormalLoopNormalizationPlan:
    del dominators

    header = loop_info.header
    body_regions = set(loop_info.body_regions)
    body_regions.add(header)

    external_entry_edges: list[LoopEdgeRef] = []
    for body_region in _sorted_regions(body_regions):
        for pred in graph.predecessors(body_region):
            if pred in body_regions:
                continue
            if body_region == header:
                continue
            external_entry_edges.append(
                LoopEdgeRef(pred.region_id, body_region.region_id)
            )

    exit_targets = {target for _, target in loop_info.exit_edges}
    abnormal_exit_edges: list[LoopEdgeRef] = []
    if len(exit_targets) > 1:
        for source, target in sorted(
            loop_info.exit_edges,
            key=lambda edge: (
                edge[0].region_id is None,
                edge[0].region_id if edge[0].region_id is not None else -1,
                edge[1].region_id is None,
                edge[1].region_id if edge[1].region_id is not None else -1,
            ),
        ):
            abnormal_exit_edges.append(
                LoopEdgeRef(source.region_id, target.region_id)
            )

    header_id = header.region_id
    body_ids = tuple(region.region_id for region in _sorted_regions(body_regions))
    typed_ir_allow = header.metadata.get("typed_ir_allow_abnormal_loop_normalization", True)
    entry_var = (
        f"__loop_entry_sel_{header_id:x}"
        if external_entry_edges and isinstance(header_id, int) and typed_ir_allow
        else None
    )
    exit_var = (
        f"__loop_exit_sel_{header_id:x}"
        if abnormal_exit_edges and isinstance(header_id, int) and typed_ir_allow
        else None
    )

    return AbnormalLoopNormalizationPlan(
        header_region_id=header_id,
        body_region_ids=body_ids,
        abnormal_entries=tuple(external_entry_edges),
        abnormal_exits=tuple(abnormal_exit_edges),
        entry_variable_name=entry_var,
        exit_variable_name=exit_var,
    )


def apply_abnormal_loop_normalization(
    graph: RegionGraph,
    header: Region,
    loop_info: NaturalLoopInfo,
    plan: AbnormalLoopNormalizationPlan,
) -> bool:
    if not plan.can_normalize:
        return False

    body_regions = set(loop_info.body_regions)
    body_regions.add(header)

    for body_region in _sorted_regions(body_regions):
        if body_region == header or body_region not in graph.nodes:
            continue
        graph.merge_regions(body_region, header, transfer_edges="both")

    header.region_type = RegionType.Loop
    header.metadata["loop_info"] = loop_info
    header.metadata["abnormal_loop_plan"] = plan.to_dict()
    if plan.abnormal_entries:
        header.metadata["unstructured_entries"] = [
            (edge.source_region_id, edge.target_region_id) for edge in plan.abnormal_entries
        ]
    if plan.abnormal_exits:
        header.metadata["unstructured_exits"] = [
            (source, target) for source, target in loop_info.exit_edges
        ]
    structuring_variables = [
        name for name in (plan.entry_variable_name, plan.exit_variable_name) if name
    ]
    if structuring_variables:
        header.metadata["structuring_variables"] = structuring_variables
    return True


class AbnormalLoopStructureAnalysis(StructureAnalysis):
    """
    Structuring analysis with explicit abnormal loop normalization.

    This normalizes multi-entry / multi-exit loop shapes as typed metadata
    instead of leaving them as anonymous low-confidence leftovers.
    """

    def _try_natural_loop(self, region: Region) -> bool:
        loop_info = self._detect_natural_loop(region)
        if not loop_info:
            return False

        plan = build_abnormal_loop_normalization_plan(
            self.graph,
            self.dominators,
            loop_info,
        )
        if plan.can_normalize:
            if apply_abnormal_loop_normalization(self.graph, region, loop_info, plan):
                self.stats.regions_reduced += 1
                return True

        return super()._try_natural_loop(region)


__all__ = [
    "LoopEdgeRef",
    "AbnormalLoopNormalizationPlan",
    "build_abnormal_loop_normalization_plan",
    "apply_abnormal_loop_normalization",
    "AbnormalLoopStructureAnalysis",
]
