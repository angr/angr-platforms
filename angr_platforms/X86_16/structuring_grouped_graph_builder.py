from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .condition_ir import condition_compare_symbol_8616
from .ir.core import IRAddress, IRCondition, IRValue, MemSpace, AddressStatus, SegmentOrigin
from .structuring_graph_builder import RegionGraphBuildResult, build_region_graph
from .structuring_grouped_units import (
    CrossEntryGroupedUnitArtifact,
    build_x86_16_cross_entry_grouped_units,
)


@dataclass(frozen=True, slots=True)
class GroupedRegionGraphBuildResult:
    graph_result: RegionGraphBuildResult
    grouped_units: CrossEntryGroupedUnitArtifact | None


def _format_ir_value_8616(value: IRValue) -> str | None:
    if value.space == MemSpace.CONST:
        return str(int(value.const)) if isinstance(value.const, int) else None
    if value.space in {MemSpace.REG, MemSpace.TMP} and isinstance(value.name, str) and value.name:
        if int(getattr(value, "offset", 0) or 0) == 0:
            return value.name
        sign = "+" if value.offset > 0 else "-"
        return f"{value.name} {sign} {abs(int(value.offset))}"
    return None


def _format_ir_address_hint_8616(address: IRAddress) -> str | None:
    base = tuple(getattr(address, "base", ()) or ())
    if not base:
        return None
    parts = [str(item) for item in base if isinstance(item, str) and item]
    if not parts:
        return None
    offset = int(getattr(address, "offset", 0) or 0)
    if offset > 0:
        parts.append(str(offset))
    elif offset < 0:
        parts.append(f"- {abs(offset)}")
    base_text = " + ".join(parts)
    if " + - " in base_text:
        base_text = base_text.replace(" + - ", " - ")
    space = getattr(getattr(address, "space", None), "value", "unknown")
    return f"{space}:[{base_text}]"


def _format_ir_condition_hint_8616(condition: IRCondition) -> str | None:
    args = tuple(getattr(condition, "args", ()) or ())
    op = str(getattr(condition, "op", ""))
    if op == "not" and len(args) == 1 and isinstance(args[0], IRCondition):
        inner = _format_ir_condition_hint_8616(args[0])
        if inner is None:
            return None
        return f"!({inner})"
    if op in {"and", "or"} and len(args) == 2 and isinstance(args[0], IRCondition) and isinstance(args[1], IRCondition):
        left = _format_ir_condition_hint_8616(args[0])
        right = _format_ir_condition_hint_8616(args[1])
        if left is None or right is None:
            return None
        join = " && " if op == "and" else " || "
        return f"({left}){join}({right})"
    if op in {"zero", "nonzero"} and len(args) == 1:
        value = _format_ir_value_8616(args[0])
        if value is None:
            return None
        return f"{value} == 0" if op == "zero" else f"{value} != 0"
    if op == "masked_nonzero" and len(args) == 2:
        left = _format_ir_value_8616(args[0])
        right = _format_ir_value_8616(args[1])
        if left is None or right is None:
            return None
        return f"({left} & {right}) != 0"
    cmp_symbol = condition_compare_symbol_8616(op)
    if cmp_symbol is not None and len(args) == 2:
        left = _format_ir_value_8616(args[0])
        right = _format_ir_value_8616(args[1])
        if left is None or right is None:
            return None
        return f"{left} {cmp_symbol} {right}"
    return None


def _typed_ir_support_by_region_id(codegen: Any) -> dict[int, dict[str, object]]:
    artifact = getattr(codegen, "_inertia_vex_ir_artifact", None)
    function_ssa = getattr(codegen, "_inertia_vex_ir_function_ssa", None)
    if artifact is None or not hasattr(artifact, "blocks"):
        return {}

    support: dict[int, dict[str, bool]] = {}
    for block in tuple(getattr(artifact, "blocks", ()) or ()):
        region_id = getattr(block, "addr", None)
        if not isinstance(region_id, int):
            continue
        cjmp_condition_hint = None
        address_spaces: set[str] = set()
        stable_address_spaces: set[str] = set()
        segment_origin_kinds: set[str] = set()
        address_hint = None
        for instr in tuple(getattr(block, "instrs", ()) or ()):
            for arg in tuple(getattr(instr, "args", ()) or ()):
                if not isinstance(arg, IRAddress):
                    continue
                address_spaces.add(getattr(getattr(arg, "space", None), "value", "unknown"))
                if getattr(arg, "status", None) == AddressStatus.STABLE:
                    stable_address_spaces.add(getattr(getattr(arg, "space", None), "value", "unknown"))
                segment_origin_kinds.add(getattr(getattr(arg, "segment_origin", None), "value", "unknown"))
                if address_hint is None and (
                    getattr(arg, "status", None) == AddressStatus.STABLE
                    or getattr(arg, "segment_origin", None) == SegmentOrigin.PROVEN
                ):
                    address_hint = _format_ir_address_hint_8616(arg)
                elif address_hint is None:
                    address_hint = _format_ir_address_hint_8616(arg)
            if getattr(instr, "op", None) != "CJMP":
                continue
            args = tuple(getattr(instr, "args", ()) or ())
            if not args or not isinstance(args[0], IRCondition):
                continue
            cjmp_condition_hint = _format_ir_condition_hint_8616(args[0])
            if cjmp_condition_hint is not None:
                break
        support[region_id] = {
            "has_condition": any(
                any(isinstance(arg, IRCondition) for arg in tuple(getattr(instr, "args", ()) or ()))
                for instr in tuple(getattr(block, "instrs", ()) or ())
            ),
            "condition_kinds": tuple(
                sorted(
                    {
                        str(arg.op)
                        for instr in tuple(getattr(block, "instrs", ()) or ())
                        for arg in tuple(getattr(instr, "args", ()) or ())
                        if isinstance(arg, IRCondition)
                    }
                )
            ),
            "condition_hint": cjmp_condition_hint,
            "has_address": bool(address_spaces),
            "address_spaces": tuple(sorted(address_spaces)),
            "stable_address_spaces": tuple(sorted(stable_address_spaces)),
            "segment_origin_kinds": tuple(sorted(segment_origin_kinds)),
            "address_hint": address_hint,
            "has_phi": False,
        }
    for phi in tuple(getattr(function_ssa, "phi_nodes", ()) or ()):
        region_id = getattr(phi, "block_addr", None)
        if not isinstance(region_id, int):
            continue
        support.setdefault(
            region_id,
            {
                "has_condition": False,
                "condition_kinds": (),
                "condition_hint": None,
                "has_address": False,
                "address_spaces": (),
                "stable_address_spaces": (),
                "segment_origin_kinds": (),
                "address_hint": None,
                "has_phi": False,
            },
        )["has_phi"] = True
    return support


def _annotate_typed_ir_support_on_graph(graph, typed_ir_support: dict[int, dict[str, bool]]) -> None:
    for region in graph.nodes:
        region_id = getattr(region, "region_id", None)
        if not isinstance(region_id, int):
            continue
        ir_support = typed_ir_support.get(region_id)
        if ir_support is None:
            continue
        region.metadata["typed_ir_has_condition"] = ir_support["has_condition"]
        region.metadata["typed_ir_condition_kinds"] = tuple(ir_support.get("condition_kinds", ()) or ())
        region.metadata["typed_ir_condition_hint"] = ir_support.get("condition_hint")
        region.metadata["typed_ir_has_address"] = bool(ir_support.get("has_address", False))
        region.metadata["typed_ir_address_spaces"] = tuple(ir_support.get("address_spaces", ()) or ())
        region.metadata["typed_ir_stable_address_spaces"] = tuple(ir_support.get("stable_address_spaces", ()) or ())
        region.metadata["typed_ir_segment_origin_kinds"] = tuple(ir_support.get("segment_origin_kinds", ()) or ())
        region.metadata["typed_ir_address_hint"] = ir_support.get("address_hint")
        region.metadata["typed_ir_has_phi"] = ir_support["has_phi"]
        region.metadata["typed_ir_allow_abnormal_loop_normalization"] = bool(
            ir_support["has_condition"] or ir_support["has_phi"]
        )


def build_grouped_region_graph(codegen: Any) -> GroupedRegionGraphBuildResult:
    graph_result = build_region_graph(codegen)
    grouped_units = build_x86_16_cross_entry_grouped_units(codegen)
    graph = graph_result.graph
    if graph is None:
        return GroupedRegionGraphBuildResult(graph_result=graph_result, grouped_units=grouped_units)

    typed_ir_support = _typed_ir_support_by_region_id(codegen)
    _annotate_typed_ir_support_on_graph(graph, typed_ir_support)
    if grouped_units is None or not grouped_units.units:
        return GroupedRegionGraphBuildResult(graph_result=graph_result, grouped_units=grouped_units)

    role_by_region_id: dict[int, tuple[str, int]] = {}
    for unit_index, unit in enumerate(grouped_units.units):
        for region_id in unit.primary_entry_region_ids:
            role_by_region_id[region_id] = ("primary_entry", unit_index)
        for region_id in unit.entry_fragment_region_ids:
            role_by_region_id[region_id] = ("entry_fragment", unit_index)
        for region_id in unit.shared_region_ids:
            role_by_region_id[region_id] = ("grouped_entry_candidate", unit_index)

    for region in graph.nodes:
        region_id = getattr(region, "region_id", None)
        if not isinstance(region_id, int):
            continue
        role = role_by_region_id.get(region_id)
        if role is None:
            continue
        grouping_kind, unit_index = role
        region.metadata["cross_entry_grouping_kind"] = grouping_kind
        region.metadata["cross_entry_unit_index"] = unit_index

    return GroupedRegionGraphBuildResult(graph_result=graph_result, grouped_units=grouped_units)


def describe_x86_16_grouped_region_graph_surface() -> dict[str, object]:
    return {
        "producer": "build_grouped_region_graph",
        "graph_surface": "Region.metadata[cross_entry_*, typed_ir_*]",
        "unit_surface": "CrossEntryGroupedUnitArtifact",
        "purpose": "Materialize cross-entry grouping directly onto the region graph before structuring.",
    }


__all__ = [
    "GroupedRegionGraphBuildResult",
    "build_grouped_region_graph",
    "describe_x86_16_grouped_region_graph_surface",
]
