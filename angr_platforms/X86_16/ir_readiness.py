from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .ir_recovery_summary import summarize_x86_16_ir_recovery

__all__ = ["IRReadinessSummary", "summarize_x86_16_ir_readiness"]


@dataclass(frozen=True, slots=True)
class IRReadinessSummary:
    level: str
    block_count: int
    provisional_address_count: int
    defaulted_segment_count: int
    proven_segment_count: int
    unknown_segment_count: int
    condition_count: int
    phi_node_count: int
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "level": self.level,
            "block_count": self.block_count,
            "provisional_address_count": self.provisional_address_count,
            "defaulted_segment_count": self.defaulted_segment_count,
            "proven_segment_count": self.proven_segment_count,
            "unknown_segment_count": self.unknown_segment_count,
            "condition_count": self.condition_count,
            "phi_node_count": self.phi_node_count,
            "reasons": list(self.reasons),
        }


def summarize_x86_16_ir_readiness(source: Any) -> IRReadinessSummary:
    summary = summarize_x86_16_ir_recovery(source)
    provisional_address_count = int(summary.address_status_counts.get("provisional", 0) or 0)
    defaulted_segment_count = int(summary.segment_origin_counts.get("defaulted", 0) or 0)
    proven_segment_count = int(summary.segment_origin_counts.get("proven", 0) or 0)
    unknown_segment_count = int(summary.segment_origin_counts.get("unknown", 0) or 0)
    condition_count = int(sum(summary.condition_counts.values()))
    phi_node_count = int(summary.phi_node_count)
    reasons: list[str] = []

    if summary.block_count <= 0:
        reasons.append("no_ir_blocks")
    if provisional_address_count > 0:
        reasons.append("provisional_addresses_present")
    if defaulted_segment_count > 0:
        reasons.append("defaulted_segment_identity_present")
    if unknown_segment_count > 0:
        reasons.append("unknown_segment_identity_present")
    if condition_count <= 0:
        reasons.append("no_typed_conditions")
    if phi_node_count <= 0:
        reasons.append("no_cross_block_ssa")

    if summary.block_count <= 0:
        level = "missing"
    elif condition_count > 0 and (proven_segment_count > 0 or defaulted_segment_count > 0) and phi_node_count > 0:
        level = "typed_address_condition_and_ssa"
    elif condition_count > 0 and (proven_segment_count > 0 or defaulted_segment_count > 0):
        level = "typed_address_and_condition"
    elif condition_count > 0:
        level = "typed_condition_only"
    elif provisional_address_count > 0 or defaulted_segment_count > 0 or proven_segment_count > 0:
        level = "typed_address_only"
    else:
        level = "minimal"

    return IRReadinessSummary(
        level=level,
        block_count=summary.block_count,
        provisional_address_count=provisional_address_count,
        defaulted_segment_count=defaulted_segment_count,
        proven_segment_count=proven_segment_count,
        unknown_segment_count=unknown_segment_count,
        condition_count=condition_count,
        phi_node_count=phi_node_count,
        reasons=tuple(reasons),
    )
