from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .recompilable_storage_map import (
    RecompilableStorageMapArtifact,
    RecompilableStorageMapCandidate,
    build_recompilable_storage_map,
)

__all__ = [
    "SegmentedStorageSeed",
    "export_recompilable_storage_map_from_codegen",
]


@dataclass(frozen=True)
class SegmentedStorageSeed:
    segment_reg: str
    offset: int
    width: int
    identity_kind: str
    stable_object_kind: str | None = None
    stable_object_name: str | None = None


def _segment_summary_entry(codegen, segment_reg: str) -> dict[str, object]:
    summary = getattr(codegen, "_inertia_segmented_memory_summary", {}) or {}
    normalized = segment_reg.upper()
    for bucket in ("stable", "over_associated", "unknown"):
        entry = ((summary.get(bucket) or {}).get(normalized)) if isinstance(summary, dict) else None
        if isinstance(entry, dict):
            return entry
    return {}


def _segment_lowering_entry(codegen, segment_reg: str) -> dict[str, object]:
    lowering = getattr(codegen, "_inertia_segmented_memory_lowering", {}) or {}
    entry = lowering.get(segment_reg.upper()) if isinstance(lowering, dict) else None
    return entry if isinstance(entry, dict) else {}


def _segment_value_from_summary(entry: dict[str, object], classification: str) -> int | None:
    if classification != "const":
        return None
    known_values = entry.get("known_values")
    if not isinstance(known_values, tuple) or len(known_values) != 1:
        return None
    value = known_values[0]
    return value if isinstance(value, int) else None


def _candidate_from_seed(codegen, seed: SegmentedStorageSeed) -> RecompilableStorageMapCandidate:
    summary_entry = _segment_summary_entry(codegen, seed.segment_reg)
    lowering_entry = _segment_lowering_entry(codegen, seed.segment_reg)
    classification = str(
        lowering_entry.get("classification")
        or summary_entry.get("classification")
        or "unknown"
    )
    allow_linear_lowering = bool(lowering_entry.get("allow_linear_lowering", False))
    return RecompilableStorageMapCandidate(
        segment_reg=seed.segment_reg.upper(),
        segment_value=_segment_value_from_summary(summary_entry, classification),
        offset=seed.offset,
        width=seed.width,
        identity_kind=seed.identity_kind,
        association_classification=classification,
        allow_linear_lowering=allow_linear_lowering,
        stable_object_kind=seed.stable_object_kind,
        stable_object_name=seed.stable_object_name,
    )


def export_recompilable_storage_map_from_codegen(
    codegen,
    seeds: Iterable[SegmentedStorageSeed],
) -> RecompilableStorageMapArtifact:
    candidates = tuple(_candidate_from_seed(codegen, seed) for seed in seeds)
    return build_recompilable_storage_map(candidates)
