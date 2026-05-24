"""
Sequence-merge eligibility helpers for region structuring.

This keeps loop-preservation policy outside the main structuring driver.
"""

from __future__ import annotations

from .structuring_region import DominatorInfo, Region, RegionGraph, RegionType


def _can_reach_region(graph: RegionGraph, src: Region, dst: Region) -> bool:
    """Return True when `src` can reach `dst` through successor edges."""

    worklist = [src]
    seen: set[Region] = set()

    while worklist:
        region = worklist.pop()
        if region in seen:
            continue
        seen.add(region)
        for succ in graph.successors(region):
            if succ == dst:
                return True
            if succ not in seen:
                worklist.append(succ)

    return False


def merge_would_hide_cycle(
    graph: RegionGraph,
    dominators: DominatorInfo | None,
    region: Region,
    other: Region,
) -> bool:
    """Return True when merging `other` into `region` would erase a loop edge."""

    if dominators is None:
        return False
    return dominators.dominates(region, other) and _can_reach_region(graph, other, region)


def sequence_merge_is_safe(
    graph: RegionGraph,
    dominators: DominatorInfo | None,
    region: Region,
    succ: Region,
) -> bool:
    """
    Return True when `region -> succ` is safe to collapse as a sequence.

    The key guard is loop preservation: do not consume a successor that feeds a
    back-edge to the region, because that hides a natural loop before cyclic
    analysis can see it.
    """

    if succ.region_type in (RegionType.Loop, RegionType.IncSwitch):
        return False
    if region.region_type == RegionType.Condition:
        return False
    if succ == region:
        return False
    if region.condition_expr is not None:
        return False
    if bool(getattr(region, "metadata", {}).get("typed_ir_has_condition", False)):
        return False
    if bool(getattr(succ, "metadata", {}).get("typed_ir_has_condition", False)):
        return False
    if bool(getattr(succ, "metadata", {}).get("typed_ir_has_phi", False)):
        return False
    if len(graph.predecessors(succ)) != 1:
        return False
    if succ not in region.successors:
        return False
    if merge_would_hide_cycle(graph, dominators, region, succ):
        return False
    return True
