"""
Deterministic region-graph construction for structuring.

This module isolates the raw CFG-to-region-graph bridge from the structuring
driver so later CFG snapshot logic can reuse the same producer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .structuring_region import Region, RegionGraph, RegionType


@dataclass(frozen=True)
class RegionGraphBuildResult:
    """Typed result of building a region graph from codegen/clinic state."""

    graph: RegionGraph | None
    entry: Region | None


def resolve_clinic_from_codegen(codegen: Any) -> Any | None:
    """Resolve the clinic object from codegen or the backing function."""

    clinic = getattr(codegen, "_clinic", None)
    if clinic is not None:
        return clinic

    project = getattr(codegen, "project", None)
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if project is None or func_addr is None:
        return None

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return None
    return getattr(func, "_clinic", None)


def build_region_graph(codegen: Any) -> RegionGraphBuildResult:
    """Build a deterministic RegionGraph from a clinic AIL graph."""

    graph = RegionGraph()
    regions_by_addr: dict[int, Region] = {}
    clinic = resolve_clinic_from_codegen(codegen)

    if clinic is not None and hasattr(clinic, "graph"):
        ail_graph = clinic.graph
        for node in ail_graph.nodes():
            node_addr = getattr(node, "addr", None)
            if node_addr is None:
                continue
            region = Region(
                block_addr=node_addr,
                region_type=RegionType.Linear,
            )
            graph.add_node(region)
            regions_by_addr[node_addr] = region

        for src, dst in ail_graph.edges():
            src_addr = getattr(src, "addr", None)
            dst_addr = getattr(dst, "addr", None)
            if src_addr in regions_by_addr and dst_addr in regions_by_addr:
                graph.add_edge(regions_by_addr[src_addr], regions_by_addr[dst_addr])

    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if func_addr is not None and func_addr in regions_by_addr:
        graph.entry = regions_by_addr[func_addr]
    elif regions_by_addr:
        graph.entry = next(iter(regions_by_addr.values()))

    if not graph.nodes:
        return RegionGraphBuildResult(graph=None, entry=None)
    return RegionGraphBuildResult(graph=graph, entry=graph.entry)
