from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

__all__ = [
    "TailValidationFamilyRoute",
    "build_tail_validation_family_routing",
]


@dataclass(frozen=True)
class TailValidationFamilyRoute:
    family: str
    count: int
    function_count: int
    stages: tuple[str, ...]
    likely_layer: str
    next_root_cause_file: str
    signal: str


_DEFAULT_ROUTE = TailValidationFamilyRoute(
    family="unclassified observable delta",
    count=0,
    function_count=0,
    stages=(),
    likely_layer="triage",
    next_root_cause_file="angr_platforms/angr_platforms/X86_16/tail_validation.py",
    signal="needs classification",
)


_FAMILY_ROUTING_TABLE: dict[str, tuple[str, str, str]] = {
    "helper call delta": (
        "helpers",
        "angr_platforms/angr_platforms/X86_16/analysis_helpers.py",
        "interrupt/dos helper lowering and naming",
    ),
    "live-out register delta": (
        "postprocess/flags",
        "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_flags.py",
        "register/flag normalization",
    ),
    "stack write delta": (
        "postprocess/stack",
        "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_simplify.py",
        "stack write normalization",
    ),
    "segmented/global write delta": (
        "segmented-memory",
        "angr_platforms/angr_platforms/X86_16/segmented_memory_reasoning.py",
        "segment association/lowering",
    ),
    "global write delta": (
        "segmented-memory",
        "angr_platforms/angr_platforms/X86_16/segmented_memory_reasoning.py",
        "global vs segmented distinction",
    ),
    "segmented write delta": (
        "segmented-memory",
        "angr_platforms/angr_platforms/X86_16/segmented_memory_reasoning.py",
        "segmented write identity",
    ),
    "return delta": (
        "postprocess/returns",
        "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_stage.py",
        "return lowering/cleanup",
    ),
    "control-flow/guard delta": (
        "structuring",
        "angr_platforms/angr_platforms/X86_16/structuring_sequences.py",
        "guard normalization and structuring order",
    ),
}


def build_tail_validation_family_routing(
    changed_families: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    rows: list[TailValidationFamilyRoute] = []
    for row in changed_families:
        if not isinstance(row, Mapping):
            continue
        family = row.get("family")
        if not isinstance(family, str) or not family:
            continue
        count = int(row.get("count", 0) or 0)
        function_count = int(row.get("function_count", 0) or 0)
        stages_raw = row.get("stages", ()) or ()
        stages = tuple(str(item) for item in stages_raw if isinstance(item, str))
        route = _FAMILY_ROUTING_TABLE.get(family)
        if route is None:
            layer = _DEFAULT_ROUTE.likely_layer
            next_file = _DEFAULT_ROUTE.next_root_cause_file
            signal = _DEFAULT_ROUTE.signal
        else:
            layer, next_file, signal = route
        rows.append(
            TailValidationFamilyRoute(
                family=family,
                count=count,
                function_count=function_count,
                stages=stages,
                likely_layer=layer,
                next_root_cause_file=next_file,
                signal=signal,
            )
        )
    rows.sort(key=lambda item: (-item.count, item.family))
    return [
        {
            "family": item.family,
            "count": item.count,
            "function_count": item.function_count,
            "stages": item.stages,
            "likely_layer": item.likely_layer,
            "next_root_cause_file": item.next_root_cause_file,
            "signal": item.signal,
        }
        for item in rows
    ]
