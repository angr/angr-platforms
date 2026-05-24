"""
Typed indirect-site placeholder classification over CFG ownership artifacts.

This keeps indirect-site reporting explicit and conservative. It does not infer
dispatch semantics; it only marks graph shapes that deserve later classification.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .structuring_cfg_ownership import CFGOwnershipArtifact, build_cfg_ownership_artifact


@dataclass(frozen=True, slots=True)
class CFGIndirectSiteRecord:
    """One indirect-site candidate or refusal."""

    region_id: int
    classification: str
    refusal_reason: str | None
    successor_count: int


@dataclass(frozen=True, slots=True)
class CFGIndirectSiteArtifact:
    """Deterministic indirect-site placeholder surface."""

    ownership: CFGOwnershipArtifact
    records: tuple[CFGIndirectSiteRecord, ...]
    candidate_region_ids: tuple[int, ...]

    def summary_line(self) -> str:
        """Compact summary for diagnostics."""

        return f"cfg_indirect candidates={len(self.candidate_region_ids)} total={len(self.records)}"

    def to_dict(self) -> dict[str, object]:
        """Stable serialization for reports and artifacts."""

        return {
            "ownership": self.ownership.to_dict(),
            "candidate_region_ids": [hex(region_id) for region_id in self.candidate_region_ids],
            "records": [
                {
                    "region_id": hex(record.region_id),
                    "classification": record.classification,
                    "refusal_reason": record.refusal_reason,
                    "successor_count": record.successor_count,
                }
                for record in self.records
            ],
        }


def build_cfg_indirect_site_artifact(codegen: Any) -> CFGIndirectSiteArtifact | None:
    """Build conservative indirect-site placeholders from CFG shape."""

    ownership = build_cfg_ownership_artifact(codegen)
    if ownership is None:
        return None

    records: list[CFGIndirectSiteRecord] = []
    candidate_region_ids: list[int] = []
    successor_counts = {node.region_id: len(node.successor_ids) for node in ownership.snapshot.nodes}

    for record in ownership.records:
        successor_count = successor_counts.get(record.region_id, 0)
        if successor_count >= 3:
            classification = "fanout_dispatch_candidate"
            refusal_reason = None
            candidate_region_ids.append(record.region_id)
        else:
            classification = "not_indirect_site"
            refusal_reason = "insufficient_fanout"
        records.append(
            CFGIndirectSiteRecord(
                region_id=record.region_id,
                classification=classification,
                refusal_reason=refusal_reason,
                successor_count=successor_count,
            )
        )

    return CFGIndirectSiteArtifact(
        ownership=ownership,
        records=tuple(records),
        candidate_region_ids=tuple(candidate_region_ids),
    )
