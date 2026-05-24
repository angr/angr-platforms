from __future__ import annotations

from dataclasses import dataclass

from .codegen_metadata import append_codegen_sequence_attr
from .ir_readiness import IRReadinessSummary, summarize_x86_16_ir_readiness

__all__ = ["IRConfidenceMarkerArtifact", "apply_x86_16_ir_confidence_markers"]


@dataclass(frozen=True, slots=True)
class IRConfidenceMarkerArtifact:
    readiness: IRReadinessSummary
    assumptions: tuple[str, ...]
    critical_unknowns: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "readiness": self.readiness.to_dict(),
            "assumptions": list(self.assumptions),
            "critical_unknowns": list(self.critical_unknowns),
        }


def _append_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _build_ir_confidence_marker_artifact(codegen) -> IRConfidenceMarkerArtifact:
    readiness = summarize_x86_16_ir_readiness(codegen)
    assumptions: list[str] = []
    critical_unknowns: list[str] = []

    if readiness.level == "missing":
        assumptions.append("typed IR unavailable")
        return IRConfidenceMarkerArtifact(readiness=readiness, assumptions=tuple(assumptions), critical_unknowns=())

    if readiness.defaulted_segment_count > 0 and readiness.proven_segment_count == 0:
        assumptions.append("typed IR segment identity is only defaulted")
    if readiness.condition_count == 0:
        assumptions.append("typed IR conditions are absent")
    if readiness.block_count > 1 and readiness.phi_node_count == 0:
        assumptions.append("typed IR cross-block SSA is absent")
    if readiness.unknown_segment_count > 0:
        critical_unknowns.append("typed IR still has unknown segment identity")

    return IRConfidenceMarkerArtifact(
        readiness=readiness,
        assumptions=tuple(assumptions),
        critical_unknowns=tuple(critical_unknowns),
    )


def apply_x86_16_ir_confidence_markers(codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    artifact = _build_ir_confidence_marker_artifact(codegen)
    setattr(codegen, "_inertia_ir_confidence_markers", artifact)
    append_codegen_sequence_attr(codegen, cfunc, "_assumptions", artifact.assumptions)
    append_codegen_sequence_attr(codegen, cfunc, "_critical_unknowns", artifact.critical_unknowns)
    return False
