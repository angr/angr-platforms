"""
Natural-loop detection helpers for region-based structuring.

This module isolates loop-specific CFG reasoning from the main
`structuring_analysis` driver so later CFG snapshot work can build on a
smaller, typed surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .structuring_region import DominatorInfo, Region, RegionGraph


@dataclass
class NaturalLoopInfo:
    """Information about one detected natural loop."""

    header: Region
    back_edges: list[Region]
    body_regions: set[Region]
    exit_edges: list[tuple[Region, Region]]
    is_reducible: bool
    confidence: float
    has_single_exit: bool


@dataclass
class LoopExitClassification:
    """Classification of loop exits for later structured rendering."""

    loop_type: str
    break_targets: set[Region]
    continue_target: Optional[Region]
    confidence: str
    fallback_needed: bool


def compute_loop_body(
    graph: RegionGraph,
    dominators: DominatorInfo,
    header: Region,
    back_edges: list[Region],
) -> set[Region]:
    """
    Compute the natural-loop body for `header`.

    The body is the header plus every predecessor chain dominated by the
    header and feeding a back-edge source.
    """

    body = set(back_edges)
    body.add(header)

    changed = True
    while changed:
        changed = False
        for region in list(body):
            for pred in graph.predecessors(region):
                if pred in body:
                    continue
                if not dominators.dominates(header, pred):
                    continue
                body.add(pred)
                changed = True

    return body


def is_well_structured_multi_exit(
    body_regions: set[Region],
    exit_edges: list[tuple[Region, Region]],
) -> bool:
    """
    Heuristic for reducible multi-exit loops.

    If most exits originate from different body regions, treat the loop as a
    structured loop-with-breaks candidate rather than an irreducible branch fan.
    """

    del body_regions
    exit_sources = {src for src, _ in exit_edges}
    unique_ratio = len(exit_sources) / max(len(exit_edges), 1)
    return unique_ratio >= 0.5


def compute_loop_confidence(
    header: Region,
    back_edges: list[Region],
    body_regions: set[Region],
    exit_edges: list[tuple[Region, Region]],
    is_reducible: bool,
) -> float:
    """Score how likely the loop is to be a real natural loop."""

    del header
    score = 0.5

    if len(back_edges) == 1:
        score += 0.3
    elif len(back_edges) <= 3:
        score += 0.15

    exit_targets = {dst for _, dst in exit_edges}
    if len(exit_targets) == 1:
        score += 0.2
    elif len(exit_targets) <= 2:
        score += 0.1

    if is_reducible:
        score += 0.1

    if len(body_regions) > 50:
        score -= 0.2
    elif len(body_regions) > 20:
        score -= 0.1

    return min(1.0, max(0.0, score))


def detect_natural_loop(
    graph: RegionGraph,
    dominators: DominatorInfo,
    region: Region,
) -> Optional[NaturalLoopInfo]:
    """
    Detect a natural loop rooted at `region`.

    Returns a typed summary or `None` if the region is not a loop header.
    """

    if region not in graph.nodes:
        return None

    preds = graph.predecessors(region)
    back_edges = [pred for pred in preds if dominators.strictly_dominates(region, pred)]
    if not back_edges:
        return None

    body_regions = compute_loop_body(graph, dominators, region, back_edges)
    if not body_regions:
        return None

    exit_edges: list[tuple[Region, Region]] = []
    exit_targets: set[Region] = set()
    for body_region in body_regions:
        for succ in graph.successors(body_region):
            if succ in body_regions or succ == region:
                continue
            exit_edges.append((body_region, succ))
            exit_targets.add(succ)

    is_reducible = len(exit_targets) <= 1
    if len(exit_targets) > 1:
        is_reducible = is_well_structured_multi_exit(body_regions, exit_edges)

    confidence = compute_loop_confidence(
        region,
        back_edges,
        body_regions,
        exit_edges,
        is_reducible,
    )
    if confidence < 0.3:
        return None

    return NaturalLoopInfo(
        header=region,
        back_edges=back_edges,
        body_regions=body_regions,
        exit_edges=exit_edges,
        is_reducible=is_reducible,
        confidence=confidence,
        has_single_exit=len(exit_targets) <= 1,
    )
