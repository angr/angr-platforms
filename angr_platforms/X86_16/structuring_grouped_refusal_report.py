from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .structuring_grouped_units import build_x86_16_cross_entry_grouped_units


@dataclass(frozen=True, slots=True)
class StructuringGroupedRefusalReportRow:
    refusal_reason: str
    count: int
    likely_layer: str
    next_root_cause_file: str


@dataclass(frozen=True, slots=True)
class StructuringGroupedRefusalReport:
    rows: tuple[StructuringGroupedRefusalReportRow, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "rows": [
                {
                    "refusal_reason": row.refusal_reason,
                    "count": row.count,
                    "likely_layer": row.likely_layer,
                    "next_root_cause_file": row.next_root_cause_file,
                }
                for row in self.rows
            ]
        }


def build_x86_16_structuring_grouped_refusal_report(codegen: Any) -> StructuringGroupedRefusalReport | None:
    artifact = build_x86_16_cross_entry_grouped_units(codegen)
    if artifact is None:
        return None
    counts: dict[str, int] = {}
    for refusal in artifact.refusals:
        counts[refusal.refusal_reason] = counts.get(refusal.refusal_reason, 0) + 1
    rows = tuple(
        StructuringGroupedRefusalReportRow(
            refusal_reason=refusal_reason,
            count=counts[refusal_reason],
            likely_layer="cross_entry_grouping",
            next_root_cause_file="angr_platforms/angr_platforms/X86_16/structuring_grouped_units.py",
        )
        for refusal_reason in sorted(counts)
    )
    return StructuringGroupedRefusalReport(rows=rows)


def describe_x86_16_structuring_grouped_refusal_report_surface() -> dict[str, object]:
    return {
        "consumer": "structuring_grouped_refusal_report",
        "producer": "build_x86_16_cross_entry_grouped_units",
        "surface": "cross_entry_grouped_unit_refusals",
        "typed_rows": (
            "refusal_reason",
            "count",
            "likely_layer",
            "next_root_cause_file",
        ),
        "purpose": "Expose explicit multi-entry grouping refusal reasons to validation/reporting consumers.",
    }


__all__ = [
    "StructuringGroupedRefusalReport",
    "StructuringGroupedRefusalReportRow",
    "build_x86_16_structuring_grouped_refusal_report",
    "describe_x86_16_structuring_grouped_refusal_report_surface",
]
