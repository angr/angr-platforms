from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .structuring_cfg_grouping import build_cfg_grouping_artifact


@dataclass(frozen=True, slots=True)
class StructuringGroupingReportRow:
    grouping_kind: str
    count: int
    likely_layer: str
    next_root_cause_file: str


@dataclass(frozen=True, slots=True)
class StructuringGroupingReport:
    rows: tuple[StructuringGroupingReportRow, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "rows": [
                {
                    "grouping_kind": row.grouping_kind,
                    "count": row.count,
                    "likely_layer": row.likely_layer,
                    "next_root_cause_file": row.next_root_cause_file,
                }
                for row in self.rows
            ]
        }


def build_x86_16_structuring_grouping_report(codegen: Any) -> StructuringGroupingReport | None:
    artifact = build_cfg_grouping_artifact(codegen)
    if artifact is None:
        return None
    counts = {
        "primary_entry": 0,
        "entry_fragment": 0,
        "grouped_entry_candidate": 0,
        "single_cfg_owner": 0,
    }
    for record in artifact.records:
        if record.grouping_kind in counts:
            counts[record.grouping_kind] += 1
    rows = tuple(
        StructuringGroupingReportRow(
            grouping_kind=grouping_kind,
            count=count,
            likely_layer="cfg_grouping",
            next_root_cause_file="angr_platforms/angr_platforms/X86_16/structuring_cfg_grouping.py",
        )
        for grouping_kind, count in counts.items()
        if count
    )
    return StructuringGroupingReport(rows=rows)


def describe_x86_16_structuring_grouping_report_surface() -> dict[str, object]:
    return {
        "consumer": "structuring_grouping_report",
        "producer": "build_cfg_grouping_artifact",
        "surface": "cfg_grouping",
        "typed_rows": (
            "grouping_kind",
            "count",
            "likely_layer",
            "next_root_cause_file",
        ),
        "purpose": "Expose grouped-entry and entry-fragment CFG evidence to validation/reporting consumers.",
    }


__all__ = [
    "StructuringGroupingReport",
    "StructuringGroupingReportRow",
    "build_x86_16_structuring_grouping_report",
    "describe_x86_16_structuring_grouping_report_surface",
]
