"""
Typed CFG snapshot surface for structuring diagnostics.

This sits above the raw region-graph builder and gives later consumers a stable,
deterministic graph summary without scraping rendered code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .structuring_graph_builder import build_region_graph


@dataclass(frozen=True, slots=True)
class CFGSnapshotNode:
    """One region node in the structuring CFG snapshot."""

    region_id: int
    block_addr: int | None
    predecessor_ids: tuple[int, ...]
    successor_ids: tuple[int, ...]
    ownership: str
    reachable_from_entry: bool


@dataclass(frozen=True, slots=True)
class CFGSnapshot:
    """Deterministic snapshot of the region graph seen by structuring."""

    entry_region_id: int | None
    node_count: int
    edge_count: int
    nodes: tuple[CFGSnapshotNode, ...]
    shared_region_ids: tuple[int, ...] = ()
    external_entry_region_ids: tuple[int, ...] = ()
    indirect_site_ids: tuple[int, ...] = ()

    def summary_line(self) -> str:
        """Compact deterministic summary for diagnostics."""

        entry = hex(self.entry_region_id) if self.entry_region_id is not None else "none"
        return (
            f"cfg_snapshot nodes={self.node_count} edges={self.edge_count} "
            f"entry={entry} shared={len(self.shared_region_ids)} indirect={len(self.indirect_site_ids)}"
        )

    def to_dict(self) -> dict[str, object]:
        """Stable serialization for reports and artifacts."""

        return {
            "entry_region_id": hex(self.entry_region_id) if self.entry_region_id is not None else None,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "shared_region_ids": [hex(region_id) for region_id in self.shared_region_ids],
            "external_entry_region_ids": [hex(region_id) for region_id in self.external_entry_region_ids],
            "indirect_site_ids": [hex(region_id) for region_id in self.indirect_site_ids],
            "nodes": [
                {
                    "region_id": hex(node.region_id),
                    "block_addr": hex(node.block_addr) if node.block_addr is not None else None,
                    "predecessor_ids": [hex(region_id) for region_id in node.predecessor_ids],
                    "successor_ids": [hex(region_id) for region_id in node.successor_ids],
                    "ownership": node.ownership,
                    "reachable_from_entry": node.reachable_from_entry,
                }
                for node in self.nodes
            ],
        }


def build_cfg_snapshot(codegen: Any) -> CFGSnapshot | None:
    """Build a deterministic CFG snapshot from codegen."""

    result = build_region_graph(codegen)
    graph = result.graph
    if graph is None:
        return None

    reachable_from_entry: set[int] = set()
    if result.entry is not None:
        worklist = [result.entry]
        seen = set()
        while worklist:
            region = worklist.pop()
            if region in seen:
                continue
            seen.add(region)
            if region.region_id is not None:
                reachable_from_entry.add(region.region_id)
            for succ in graph.successors(region):
                if succ not in seen:
                    worklist.append(succ)

    snapshot_nodes: list[CFGSnapshotNode] = []
    edge_count = 0
    ordered_regions = sorted(
        graph.nodes,
        key=lambda item: ((item.region_id is None), item.region_id if item.region_id is not None else -1),
    )
    for region in ordered_regions:
        predecessor_ids = tuple(
            sorted(pred.region_id for pred in graph.predecessors(region) if pred.region_id is not None)
        )
        successor_ids = tuple(
            sorted(succ.region_id for succ in graph.successors(region) if succ.region_id is not None)
        )
        edge_count += len(successor_ids)
        ownership = "shared" if len(predecessor_ids) > 1 else "single"
        snapshot_nodes.append(
            CFGSnapshotNode(
                region_id=region.region_id if region.region_id is not None else -1,
                block_addr=region.block_addr,
                predecessor_ids=predecessor_ids,
                successor_ids=successor_ids,
                ownership=ownership,
                reachable_from_entry=(region.region_id in reachable_from_entry),
            )
        )

    shared_region_ids = tuple(node.region_id for node in snapshot_nodes if node.ownership == "shared")
    entry_region_id = result.entry.region_id if result.entry is not None else None
    return CFGSnapshot(
        entry_region_id=entry_region_id,
        node_count=len(snapshot_nodes),
        edge_count=edge_count,
        nodes=tuple(snapshot_nodes),
        shared_region_ids=shared_region_ids,
    )
