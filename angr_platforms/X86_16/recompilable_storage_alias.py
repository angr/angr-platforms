from __future__ import annotations

from dataclasses import dataclass

from .alias.alias_model import AliasStorageFacts
from .recompilable_storage_map import RecompilableStorageMapArtifact
from .recompilable_storage_map_producer import (
    SegmentedStorageSeed,
    export_recompilable_storage_map_from_codegen,
)

__all__ = [
    "AliasBackedStorageSeed",
    "export_recompilable_storage_map_from_alias_facts",
]


@dataclass(frozen=True)
class AliasBackedStorageSeed:
    alias_facts: AliasStorageFacts
    segment_reg: str | None = None
    stable_object_kind: str | None = None
    stable_object_name: str | None = None


def _segment_seed_from_alias_seed(seed: AliasBackedStorageSeed) -> SegmentedStorageSeed | None:
    facts = seed.alias_facts
    identity = facts.identity
    domain = facts.domain
    width = domain.width or 0

    if facts.needs_synthesis() or identity is None or width <= 0:
        return None

    identity_kind, identity_value = identity

    if identity_kind == "stack":
        return SegmentedStorageSeed(
            segment_reg="SS",
            offset=identity_value.offset,
            width=width,
            identity_kind="stack_slot",
            stable_object_kind=seed.stable_object_kind,
            stable_object_name=seed.stable_object_name,
        )

    if identity_kind == "memory":
        if seed.segment_reg is None:
            return None
        return SegmentedStorageSeed(
            segment_reg=seed.segment_reg,
            offset=int(identity_value),
            width=width,
            identity_kind="global",
            stable_object_kind=seed.stable_object_kind,
            stable_object_name=seed.stable_object_name,
        )

    return None


def export_recompilable_storage_map_from_alias_facts(
    codegen,
    seeds: tuple[AliasBackedStorageSeed, ...],
) -> RecompilableStorageMapArtifact:
    mapped = tuple(
        segment_seed
        for seed in seeds
        for segment_seed in (_segment_seed_from_alias_seed(seed),)
        if segment_seed is not None
    )
    return export_recompilable_storage_map_from_codegen(codegen, mapped)
