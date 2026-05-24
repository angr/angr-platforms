"""
Ownership/refusal layer over CFG snapshots.

This module turns raw region connectivity into a typed ownership surface with
explicit refusal reasons for shared or disconnected regions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .structuring_cfg_snapshot import CFGSnapshot, build_cfg_snapshot


@dataclass(frozen=True, slots=True)
class CFGOwnershipRecord:
    """Ownership/refusal state for one CFG region."""

    region_id: int
    ownership_kind: str
    refusal_reason: str | None
    predecessor_count: int
    successor_count: int
    reachable_from_entry: bool


@dataclass(frozen=True, slots=True)
class CFGOwnershipArtifact:
    """Typed ownership surface built from a CFG snapshot."""

    snapshot: CFGSnapshot
    records: tuple[CFGOwnershipRecord, ...]
    shared_region_ids: tuple[int, ...]
    entry_fragment_region_ids: tuple[int, ...]

    def summary_line(self) -> str:
        """Compact deterministic summary for diagnostics."""

        return (
            f"cfg_ownership regions={len(self.records)} shared={len(self.shared_region_ids)} "
            f"entry_fragments={len(self.entry_fragment_region_ids)}"
        )

    def to_dict(self) -> dict[str, object]:
        """Stable serialization for reports and artifacts."""

        return {
            "snapshot": self.snapshot.to_dict(),
            "shared_region_ids": [hex(region_id) for region_id in self.shared_region_ids],
            "entry_fragment_region_ids": [hex(region_id) for region_id in self.entry_fragment_region_ids],
            "records": [
                {
                    "region_id": hex(record.region_id),
                    "ownership_kind": record.ownership_kind,
                    "refusal_reason": record.refusal_reason,
                    "predecessor_count": record.predecessor_count,
                    "successor_count": record.successor_count,
                }
                for record in self.records
            ],
        }


def build_cfg_ownership_artifact(codegen: Any) -> CFGOwnershipArtifact | None:
    """Build the ownership/refusal surface for structuring CFGs."""

    snapshot = build_cfg_snapshot(codegen)
    if snapshot is None:
        return None

    records: list[CFGOwnershipRecord] = []
    shared_region_ids: list[int] = []
    entry_fragment_region_ids: list[int] = []

    for node in snapshot.nodes:
        reachable_by_id = {item.region_id: item.reachable_from_entry for item in snapshot.nodes}
        predecessor_count = len(node.predecessor_ids)
        successor_count = len(node.successor_ids)
        if node.region_id == snapshot.entry_region_id:
            ownership_kind = "entry"
            refusal_reason = None
        elif not node.reachable_from_entry and predecessor_count == 0:
            ownership_kind = "entry_fragment"
            refusal_reason = "disconnected_from_entry"
            entry_fragment_region_ids.append(node.region_id)
        elif not node.reachable_from_entry:
            ownership_kind = "shared_owner"
            refusal_reason = "mixed_reachability_predecessors"
            shared_region_ids.append(node.region_id)
        elif predecessor_count == 0:
            ownership_kind = "entry_fragment"
            refusal_reason = "disconnected_from_entry"
            entry_fragment_region_ids.append(node.region_id)
        elif predecessor_count == 1:
            ownership_kind = "single_owner"
            refusal_reason = None
        else:
            ownership_kind = "shared_owner"
            predecessor_reachability = {reachable_by_id.get(region_id, False) for region_id in node.predecessor_ids}
            if len(predecessor_reachability) > 1:
                refusal_reason = "mixed_reachability_predecessors"
            else:
                refusal_reason = "multiple_predecessors"
            shared_region_ids.append(node.region_id)

        records.append(
            CFGOwnershipRecord(
                region_id=node.region_id,
                ownership_kind=ownership_kind,
                refusal_reason=refusal_reason,
                predecessor_count=predecessor_count,
                successor_count=successor_count,
                reachable_from_entry=node.reachable_from_entry,
            )
        )

    return CFGOwnershipArtifact(
        snapshot=snapshot,
        records=tuple(records),
        shared_region_ids=tuple(shared_region_ids),
        entry_fragment_region_ids=tuple(entry_fragment_region_ids),
    )
