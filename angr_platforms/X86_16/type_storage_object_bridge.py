from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from inertia_decompiler.cli_access_object_hints import BaseKey, _build_stable_access_object_hints
from inertia_decompiler.cli_access_profiles import build_access_trait_evidence_profiles
from inertia_decompiler.cli_storage_objects import (
    EvidenceProfiles,
    StableHints,
    StorageObjectArtifact,
    StorageObjectRecord,
    StorageObjectRefusal,
    build_storage_object_artifact,
)

__all__ = [
    "SegmentedStorageFact",
    "StorageObjectBridge",
    "StorageObjectBridgeFact",
    "load_storage_object_bridge",
]


@dataclass(frozen=True, slots=True)
class SegmentedStorageFact:
    segment_register: str | None
    classification: str
    associated_space: str | None
    allow_linear_lowering: bool
    allow_object_lowering: bool
    reason: str

    def refusal_reason(self) -> str | None:
        if self.allow_object_lowering:
            return None
        return self.reason


@dataclass(frozen=True, slots=True)
class StorageObjectBridgeFact:
    base_key: BaseKey
    object_kind: str
    candidate_offsets: tuple[int, ...]
    primary_member_offset: int | None
    segmented_memory: SegmentedStorageFact


@dataclass(frozen=True, slots=True)
class StorageObjectBridge:
    artifact: StorageObjectArtifact
    facts_by_base: dict[BaseKey, StorageObjectBridgeFact]
    member_facts: dict[BaseKey, StorageObjectBridgeFact]
    array_facts: dict[BaseKey, StorageObjectBridgeFact]
    refusal_facts: dict[BaseKey, StorageObjectRefusal]

    def stats(self) -> dict[str, int]:
        return {
            "record_count": len(self.artifact.records),
            "member_fact_count": len(self.member_facts),
            "array_fact_count": len(self.array_facts),
            "refusal_fact_count": len(self.refusal_facts),
        }

    def allows_object_lowering(self, base_key: BaseKey) -> bool:
        fact = self.facts_by_base.get(base_key)
        return bool(fact is not None and fact.segmented_memory.allow_object_lowering)

    def lowering_refusal_reason(self, base_key: BaseKey) -> str | None:
        fact = self.facts_by_base.get(base_key)
        if fact is None:
            refusal = self.refusal_facts.get(base_key)
            return None if refusal is None else refusal.reason
        return fact.segmented_memory.refusal_reason()


def _segment_register_for_base_key(base_key: BaseKey) -> str | None:
    if not base_key:
        return None
    head = base_key[0]
    if isinstance(head, str):
        lowered = head.lower()
        if lowered in {"cs", "ds", "es", "ss"}:
            return lowered.upper()
        if lowered == "stack":
            return "SS"
    return None


def _segmented_fact_for_base_key(
    base_key: BaseKey,
    lowering_by_segment: dict[str, dict[str, object]] | None,
) -> SegmentedStorageFact:
    segment_register = _segment_register_for_base_key(base_key)
    if segment_register is None:
        return SegmentedStorageFact(
            segment_register=None,
            classification="unknown",
            associated_space=None,
            allow_linear_lowering=False,
            allow_object_lowering=False,
            reason="no_segment_context",
        )
    lowering = {} if lowering_by_segment is None else lowering_by_segment.get(segment_register, {})
    if not isinstance(lowering, dict):
        lowering = {}
    classification = lowering.get("classification")
    associated_space = lowering.get("associated_space")
    reason = lowering.get("reason")
    return SegmentedStorageFact(
        segment_register=segment_register,
        classification=classification if isinstance(classification, str) else "unknown",
        associated_space=associated_space if isinstance(associated_space, str) else None,
        allow_linear_lowering=bool(lowering.get("allow_linear_lowering", False)),
        allow_object_lowering=bool(lowering.get("allow_object_lowering", False)),
        reason=reason if isinstance(reason, str) and reason else "missing_segment_summary",
    )


def _fact_from_record(
    record: StorageObjectRecord,
    lowering_by_segment: dict[str, dict[str, object]] | None,
) -> StorageObjectBridgeFact:
    return StorageObjectBridgeFact(
        base_key=record.base_key,
        object_kind=record.object_kind,
        candidate_offsets=record.candidate_offsets,
        primary_member_offset=record.primary_member_offset(),
        segmented_memory=_segmented_fact_for_base_key(record.base_key, lowering_by_segment),
    )


def _artifact_to_bridge(
    artifact: StorageObjectArtifact,
    lowering_by_segment: dict[str, dict[str, object]] | None,
) -> StorageObjectBridge | None:
    facts_by_base = {
        base_key: _fact_from_record(record, lowering_by_segment)
        for base_key, record in artifact.records.items()
    }
    refusal_facts = dict(artifact.refusals)
    if not facts_by_base and not refusal_facts:
        return None
    member_facts = {base_key: fact for base_key, fact in facts_by_base.items() if fact.object_kind == "member"}
    array_facts = {base_key: fact for base_key, fact in facts_by_base.items() if fact.object_kind == "array"}
    return StorageObjectBridge(
        artifact=artifact,
        facts_by_base=facts_by_base,
        member_facts=member_facts,
        array_facts=array_facts,
        refusal_facts=refusal_facts,
    )


def _build_storage_object_hints(
    traits: dict[str, dict[BaseKey, object]],
) -> StableHints:
    return _build_stable_access_object_hints(
        traits,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
    )


def load_storage_object_bridge(
    project: object,
    function_addr: int | None,
    *,
    codegen: object | None = None,
    build_access_trait_evidence_profiles: Callable[[dict[str, dict[BaseKey, object]]], EvidenceProfiles] = build_access_trait_evidence_profiles,
    build_stable_access_object_hints: Callable[[dict[str, dict[BaseKey, object]]], StableHints] = _build_storage_object_hints,
) -> StorageObjectBridge | None:
    if function_addr is None:
        return None
    traits_cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(traits_cache, dict):
        return None
    traits = traits_cache.get(function_addr)
    if not isinstance(traits, dict):
        return None
    artifact = build_storage_object_artifact(
        traits,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        build_stable_access_object_hints=build_stable_access_object_hints,
    )
    lowering_by_segment = None
    if codegen is not None:
        lowering = getattr(codegen, "_inertia_segmented_memory_lowering", None)
        if isinstance(lowering, dict):
            lowering_by_segment = lowering
    return _artifact_to_bridge(artifact, lowering_by_segment)
