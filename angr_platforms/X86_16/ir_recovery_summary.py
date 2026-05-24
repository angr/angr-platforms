from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["IRRecoverySummary", "summarize_x86_16_ir_recovery"]


def _value(source: Any, name: str, default: Any = None) -> Any:
    if isinstance(source, dict):
        return source.get(name, default)
    return getattr(source, name, default)


@dataclass(frozen=True, slots=True)
class IRRecoverySummary:
    block_count: int
    instruction_count: int
    refusal_count: int
    aliasable_value_count: int
    ssa_binding_count: int
    phi_node_count: int
    frame_slot_count: int
    frame_refusal_count: int
    space_counts: dict[str, int]
    address_status_counts: dict[str, int]
    segment_origin_counts: dict[str, int]
    condition_counts: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "block_count": self.block_count,
            "instruction_count": self.instruction_count,
            "refusal_count": self.refusal_count,
            "aliasable_value_count": self.aliasable_value_count,
            "ssa_binding_count": self.ssa_binding_count,
            "phi_node_count": self.phi_node_count,
            "frame_slot_count": self.frame_slot_count,
            "frame_refusal_count": self.frame_refusal_count,
            "space_counts": dict(self.space_counts),
            "address_status_counts": dict(self.address_status_counts),
            "segment_origin_counts": dict(self.segment_origin_counts),
            "condition_counts": dict(self.condition_counts),
        }


def summarize_x86_16_ir_recovery(source: Any) -> IRRecoverySummary:
    summary = (
        _value(source, "x86_16_vex_ir_summary")
        or _value(source, "_inertia_vex_ir_summary")
        or _value(source, "vex_ir_summary")
        or {}
    )
    if not isinstance(summary, dict):
        summary = {}
    return IRRecoverySummary(
        block_count=int(summary.get("block_count", 0) or 0),
        instruction_count=int(summary.get("instruction_count", 0) or 0),
        refusal_count=int(summary.get("refusal_count", 0) or 0),
        aliasable_value_count=int(summary.get("aliasable_value_count", 0) or 0),
        ssa_binding_count=int(summary.get("ssa_binding_count", 0) or 0),
        phi_node_count=int(summary.get("phi_node_count", 0) or 0),
        frame_slot_count=int(summary.get("frame_slot_count", 0) or 0),
        frame_refusal_count=int(summary.get("frame_refusal_count", 0) or 0),
        space_counts=dict(summary.get("space_counts", {}) or {}),
        address_status_counts=dict(summary.get("address_status_counts", {}) or {}),
        segment_origin_counts=dict(summary.get("segment_origin_counts", {}) or {}),
        condition_counts=dict(summary.get("condition_counts", {}) or {}),
    )
