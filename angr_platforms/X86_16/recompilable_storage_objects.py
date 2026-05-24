from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from inertia_decompiler.cli_access_object_hints import _build_stable_access_object_hints
from inertia_decompiler.cli_access_profiles import build_access_trait_evidence_profiles
from inertia_decompiler.cli_storage_objects import (
    StorageObjectArtifact,
    build_storage_object_artifact,
)

__all__ = [
    "RecompilableStorageObjectSummary",
    "build_recompilable_storage_object_artifact",
    "summarize_recompilable_storage_object_artifact",
]


@dataclass(frozen=True)
class RecompilableStorageObjectSummary:
    record_count: int
    refusal_count: int
    object_kinds: tuple[str, ...]
    refusal_reasons: tuple[str, ...]


def build_recompilable_storage_object_artifact(
    project: Any,
    function_addr: int | None,
) -> StorageObjectArtifact | None:
    traits_cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(traits_cache, dict):
        return None
    traits = traits_cache.get(function_addr)
    if not isinstance(traits, dict):
        return None
    return build_storage_object_artifact(
        traits,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        build_stable_access_object_hints=lambda current_traits: _build_stable_access_object_hints(
            current_traits,
            build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        ),
    )


def summarize_recompilable_storage_object_artifact(
    artifact: StorageObjectArtifact | None,
) -> RecompilableStorageObjectSummary:
    if artifact is None:
        return RecompilableStorageObjectSummary(
            record_count=0,
            refusal_count=0,
            object_kinds=(),
            refusal_reasons=(),
        )
    return RecompilableStorageObjectSummary(
        record_count=len(artifact.records),
        refusal_count=len(artifact.refusals),
        object_kinds=tuple(
            sorted({record.object_kind for record in artifact.records.values()})
        ),
        refusal_reasons=tuple(
            sorted({refusal.reason for refusal in artifact.refusals.values()})
        ),
    )
