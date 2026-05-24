from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from .recovery_confidence import summarize_recovery_confidence


@dataclass(frozen=True)
class ValidationHelperFamilyRow:
    family: str
    count: int
    likely_layer: str
    next_root_cause_file: str
    signal: str


@dataclass(frozen=True)
class ValidationHelperReport:
    rows: tuple[ValidationHelperFamilyRow, ...]

    def as_rows(self) -> tuple[dict[str, object], ...]:
        return tuple(
            {
                "family": row.family,
                "count": row.count,
                "likely_layer": row.likely_layer,
                "next_root_cause_file": row.next_root_cause_file,
                "signal": row.signal,
            }
            for row in self.rows
        )


def build_x86_16_validation_helper_report(results: Sequence[Mapping[str, object]]) -> ValidationHelperReport:
    summary = summarize_recovery_confidence(results)
    rows: list[ValidationHelperFamilyRow] = []
    for item in summary.get("helper_family_rows", ()) or ():
        family = item.get("family")
        likely_layer = item.get("likely_layer")
        next_root_cause_file = item.get("next_root_cause_file")
        signal = item.get("signal")
        if not isinstance(family, str) or not family:
            continue
        if not isinstance(likely_layer, str) or not likely_layer:
            continue
        if not isinstance(next_root_cause_file, str) or not next_root_cause_file:
            continue
        if not isinstance(signal, str) or not signal:
            continue
        rows.append(
            ValidationHelperFamilyRow(
                family=family,
                count=int(item.get("count", 0) or 0),
                likely_layer=likely_layer,
                next_root_cause_file=next_root_cause_file,
                signal=signal,
            )
        )
    return ValidationHelperReport(rows=tuple(rows))


def describe_x86_16_validation_helper_report_surface() -> dict[str, object]:
    return {
        "consumer": "validation_helper_report",
        "producer": "summarize_recovery_confidence",
        "surface": "helper_family_rows",
        "typed_rows": (
            "family",
            "count",
            "likely_layer",
            "next_root_cause_file",
            "signal",
        ),
        "purpose": "Route helper/wrapper family evidence into later validation/report consumers.",
    }


__all__ = [
    "ValidationHelperFamilyRow",
    "ValidationHelperReport",
    "build_x86_16_validation_helper_report",
    "describe_x86_16_validation_helper_report_surface",
]
