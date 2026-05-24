from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from .helper_effect_summary import HelperEligibilitySummary

__all__ = [
    "HelperFamilyRoute",
    "summarize_x86_16_helper_family_routes",
]


@dataclass(frozen=True, slots=True)
class HelperFamilyRoute:
    family: str
    count: int
    likely_layer: str
    next_root_cause_file: str
    signal: str

    def to_dict(self) -> dict[str, object]:
        return {
            "family": self.family,
            "count": self.count,
            "likely_layer": self.likely_layer,
            "next_root_cause_file": self.next_root_cause_file,
            "signal": self.signal,
        }


def _route_for_refusal(kind: str) -> tuple[str, str, str]:
    if kind == "indirect_control":
        return (
            "helper_wrapper_indirect_control",
            "function_effect_summary",
            "angr_platforms/angr_platforms/X86_16/function_effect_summary.py",
        )
    if kind == "nonlocal_memory_effects":
        return (
            "helper_wrapper_nonlocal_memory",
            "alias_model",
            "angr_platforms/angr_platforms/X86_16/alias_model.py",
        )
    if kind == "return_kind_unknown":
        return (
            "helper_wrapper_return_shape",
            "return_compatibility",
            "angr_platforms/angr_platforms/X86_16/decompiler_return_compat.py",
        )
    if kind == "direct_branching":
        return (
            "helper_wrapper_branching_shape",
            "helper_modeling",
            "inertia_decompiler/cli_helper_modeling.py",
        )
    return (
        "helper_wrapper_signature_shape",
        "helper_modeling",
        "angr_platforms/angr_platforms/X86_16/helper_effect_summary.py",
    )


def summarize_x86_16_helper_family_routes(
    helper_summaries: Iterable[HelperEligibilitySummary],
) -> tuple[HelperFamilyRoute, ...]:
    refusal_counter: Counter[str] = Counter()
    eligible_counter = 0
    no_signal_counter = 0
    for summary in helper_summaries:
        if summary.status == "eligible":
            eligible_counter += 1
            continue
        if summary.status == "no_signal":
            no_signal_counter += 1
            continue
        for refusal in summary.refusals:
            refusal_counter[refusal.kind] += 1

    routes: list[HelperFamilyRoute] = []
    if eligible_counter:
        routes.append(
            HelperFamilyRoute(
                family="helper_wrapper_candidate",
                count=eligible_counter,
                likely_layer="helper_modeling",
                next_root_cause_file="angr_platforms/angr_platforms/X86_16/helper_effect_summary.py",
                signal="eligible",
            )
        )
    for refusal_kind, count in sorted(refusal_counter.items()):
        family, likely_layer, next_root_cause_file = _route_for_refusal(refusal_kind)
        routes.append(
            HelperFamilyRoute(
                family=family,
                count=count,
                likely_layer=likely_layer,
                next_root_cause_file=next_root_cause_file,
                signal=refusal_kind,
            )
        )
    if no_signal_counter:
        routes.append(
            HelperFamilyRoute(
                family="helper_wrapper_no_signal",
                count=no_signal_counter,
                likely_layer="function_effect_summary",
                next_root_cause_file="angr_platforms/angr_platforms/X86_16/function_effect_summary.py",
                signal="no_effect_signal",
            )
        )
    return tuple(sorted(routes, key=lambda item: (-item.count, item.family, item.signal)))
