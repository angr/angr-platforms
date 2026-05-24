from __future__ import annotations

from dataclasses import dataclass

from .core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from ..string_instruction_artifact import StringInstructionArtifact, StringInstructionRecord

__all__ = [
    "IRStringEffectArtifact",
    "IRStringEffectRecord",
    "apply_x86_16_typed_string_effect_artifact",
    "build_x86_16_typed_string_effect_artifact",
]


@dataclass(frozen=True, slots=True)
class IRStringEffectRecord:
    index: int
    family: str
    repeat_kind: str
    width: int
    direction_mode: str
    source: IRAddress | None
    destination: IRAddress | None
    zf_sensitive: bool
    zero_seeded_accumulator: bool | None

    def to_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "family": self.family,
            "repeat_kind": self.repeat_kind,
            "width": self.width,
            "direction_mode": self.direction_mode,
            "source": None if self.source is None else self.source.to_dict(),
            "destination": None if self.destination is None else self.destination.to_dict(),
            "zf_sensitive": self.zf_sensitive,
            "zero_seeded_accumulator": self.zero_seeded_accumulator,
        }


@dataclass(frozen=True, slots=True)
class IRStringEffectArtifact:
    records: tuple[IRStringEffectRecord, ...] = ()
    refusal_kinds: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "records": [record.to_dict() for record in self.records],
            "refusal_kinds": list(self.refusal_kinds),
        }


def _space_for_segment(segment: str | None) -> MemSpace | None:
    if segment == "ds":
        return MemSpace.DS
    if segment == "es":
        return MemSpace.ES
    if segment == "ss":
        return MemSpace.SS
    return None


def _source_base_for_family(family: str) -> tuple[str, ...]:
    if family in {"movs", "lods", "cmps"}:
        return ("si",)
    return ()


def _destination_base_for_family(family: str) -> tuple[str, ...]:
    if family in {"movs", "stos", "scas", "cmps"}:
        return ("di",)
    return ()


def _segment_state_status(segment: str | None, segment_state_artifact) -> AddressStatus:
    if segment_state_artifact is None:
        return AddressStatus.PROVISIONAL
    if segment is None:
        return AddressStatus.UNKNOWN
    state = segment_state_artifact.state_for_register(segment)
    if state is None:
        return AddressStatus.PROVISIONAL
    if state.origin == SegmentOrigin.PROVEN:
        return AddressStatus.STABLE
    return AddressStatus.PROVISIONAL


def _typed_address(
    segment: str | None,
    base: tuple[str, ...],
    width: int,
    expr: str,
    *,
    segment_state_artifact=None,
) -> IRAddress | None:
    space = _space_for_segment(segment)
    if space is None:
        return None
    return IRAddress(
        space=space,
        base=base,
        offset=0,
        size=width,
        status=_segment_state_status(segment, segment_state_artifact),
        segment_origin=SegmentOrigin.PROVEN,
        expr=(expr,),
    )


def _typed_record(index: int, record: StringInstructionRecord, *, segment_state_artifact=None) -> IRStringEffectRecord:
    return IRStringEffectRecord(
        index=index,
        family=record.family,
        repeat_kind=record.repeat_kind,
        width=record.width,
        direction_mode=record.direction_mode,
        source=_typed_address(
            record.source_segment,
            _source_base_for_family(record.family),
            record.width,
            f"{record.family}_source",
            segment_state_artifact=segment_state_artifact,
        ),
        destination=_typed_address(
            record.destination_segment,
            _destination_base_for_family(record.family),
            record.width,
            f"{record.family}_destination",
            segment_state_artifact=segment_state_artifact,
        ),
        zf_sensitive=record.zf_sensitive,
        zero_seeded_accumulator=record.zero_seeded_accumulator,
    )


def build_x86_16_typed_string_effect_artifact(
    artifact: StringInstructionArtifact,
    *,
    segment_state_artifact=None,
) -> IRStringEffectArtifact:
    return IRStringEffectArtifact(
        records=tuple(
            _typed_record(index, record, segment_state_artifact=segment_state_artifact)
            for index, record in enumerate(artifact.records)
        ),
        refusal_kinds=tuple(item.kind for item in artifact.refusals),
    )


def apply_x86_16_typed_string_effect_artifact(project, codegen) -> bool:  # noqa: ARG001
    raw_artifact = getattr(codegen, "_inertia_string_instruction_artifact", None)
    if raw_artifact is None:
        return False
    artifact = build_x86_16_typed_string_effect_artifact(
        raw_artifact,
        segment_state_artifact=getattr(codegen, "_inertia_segment_state_artifact", None),
    )
    setattr(codegen, "_inertia_string_effect_artifact", artifact)
    return False
