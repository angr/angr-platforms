from __future__ import annotations

from dataclasses import dataclass

CarrierKey8616 = tuple[str, str | int]

__all__ = [
    "CarrierKey8616",
    "TypedStackProbeReturnFact8616",
    "build_typed_stack_probe_return_facts_8616",
]


@dataclass(frozen=True, slots=True)
class TypedStackProbeReturnFact8616:
    call_node_id: int
    segment_space: str
    width: int
    carrier_keys: tuple[CarrierKey8616, ...] = ()


def build_typed_stack_probe_return_facts_8616(codegen) -> dict[int, TypedStackProbeReturnFact8616]:
    """Build lowering-owned stack-probe facts from typed callsite summaries."""
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    facts: dict[int, TypedStackProbeReturnFact8616] = {}
    if not isinstance(summary_map, dict):
        codegen._inertia_typed_stack_probe_return_facts = facts
        return facts

    for call_node_id, summary in summary_map.items():
        if not isinstance(call_node_id, int):
            continue
        if not bool(getattr(summary, "stack_probe_helper", False)):
            continue
        if getattr(summary, "helper_return_state", None) != "stack_address":
            continue
        address_kind = getattr(summary, "helper_return_address_kind", None)
        if address_kind in {None, "none"}:
            address_kind = "stack"
        if address_kind != "stack":
            continue
        if getattr(summary, "helper_return_space", None) != "ss":
            continue
        width = getattr(summary, "helper_return_width", None)
        if not isinstance(width, int) or width <= 0:
            continue
        facts[call_node_id] = TypedStackProbeReturnFact8616(
            call_node_id=call_node_id,
            segment_space="ss",
            width=width,
            carrier_keys=(),
        )

    codegen._inertia_typed_stack_probe_return_facts = facts
    return facts
