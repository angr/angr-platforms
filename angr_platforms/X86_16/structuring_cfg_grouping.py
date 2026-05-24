"""
Grouped-entry and entry-fragment artifact over CFG ownership surfaces.

This is a deterministic export layer for later cross-entry grouping work. It
does not perform grouping yet; it only emits explicit candidates and refusals.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .structuring_cfg_indirect import CFGIndirectSiteArtifact, build_cfg_indirect_site_artifact


@dataclass(frozen=True, slots=True)
class CFGGroupingRecord:
    """One grouped-entry or entry-fragment export record."""

    region_id: int
    grouping_kind: str
    refusal_reason: str | None


@dataclass(frozen=True, slots=True)
class CFGGroupingArtifact:
    """Deterministic grouping-oriented export surface."""

    indirect: CFGIndirectSiteArtifact
    records: tuple[CFGGroupingRecord, ...]
    grouped_entry_candidate_ids: tuple[int, ...]
    entry_fragment_ids: tuple[int, ...]

    def summary_line(self) -> str:
        """Compact summary for diagnostics."""

        return (
            f"cfg_grouping grouped_candidates={len(self.grouped_entry_candidate_ids)} "
            f"entry_fragments={len(self.entry_fragment_ids)}"
        )

    def to_dict(self) -> dict[str, object]:
        """Stable serialization for reports and artifacts."""

        return {
            "indirect": self.indirect.to_dict(),
            "grouped_entry_candidate_ids": [hex(region_id) for region_id in self.grouped_entry_candidate_ids],
            "entry_fragment_ids": [hex(region_id) for region_id in self.entry_fragment_ids],
            "records": [
                {
                    "region_id": hex(record.region_id),
                    "grouping_kind": record.grouping_kind,
                    "refusal_reason": record.refusal_reason,
                }
                for record in self.records
            ],
        }


def build_cfg_grouping_artifact(codegen: Any) -> CFGGroupingArtifact | None:
    """Build deterministic grouping/export candidates from CFG ownership artifacts."""

    indirect = build_cfg_indirect_site_artifact(codegen)
    if indirect is None:
        return None

    records: list[CFGGroupingRecord] = []
    grouped_entry_candidate_ids: list[int] = []
    entry_fragment_ids: list[int] = []

    for record in indirect.ownership.records:
        if record.ownership_kind == "entry":
            grouping_kind = "primary_entry"
            refusal_reason = None
        elif record.ownership_kind == "entry_fragment":
            grouping_kind = "entry_fragment"
            refusal_reason = record.refusal_reason
            entry_fragment_ids.append(record.region_id)
        elif record.ownership_kind == "shared_owner":
            grouping_kind = "grouped_entry_candidate"
            refusal_reason = record.refusal_reason
            grouped_entry_candidate_ids.append(record.region_id)
        else:
            grouping_kind = "single_cfg_owner"
            refusal_reason = None
        records.append(
            CFGGroupingRecord(
                region_id=record.region_id,
                grouping_kind=grouping_kind,
                refusal_reason=refusal_reason,
            )
        )

    return CFGGroupingArtifact(
        indirect=indirect,
        records=tuple(records),
        grouped_entry_candidate_ids=tuple(grouped_entry_candidate_ids),
        entry_fragment_ids=tuple(entry_fragment_ids),
    )
