from __future__ import annotations

from dataclasses import dataclass

from .ir_readiness import IRReadinessSummary, summarize_x86_16_ir_readiness

__all__ = ["StructuringIRHintArtifact", "build_structuring_ir_hint_artifact"]


@dataclass(frozen=True, slots=True)
class StructuringIRHintArtifact:
    readiness: IRReadinessSummary
    hints: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "readiness": self.readiness.to_dict(),
            "hints": list(self.hints),
        }


def build_structuring_ir_hint_artifact(codegen, *, succeeded: bool, iterations: int) -> StructuringIRHintArtifact:
    readiness = summarize_x86_16_ir_readiness(codegen)
    hints: list[str] = []

    if readiness.level == "missing":
        hints.append("Typed IR unavailable: structuring guidance is limited to CFG-only diagnostics")
    if not succeeded and readiness.condition_count == 0 and iterations >= 50:
        hints.append("Typed conditions missing: branch intent still depends on lifted flag temporaries")
    if not succeeded and readiness.unknown_segment_count > 0:
        hints.append("Segment identity still unknown: memory-space evidence is missing for some typed addresses")
    elif not succeeded and readiness.defaulted_segment_count > 0:
        hints.append("Segment identity is still defaulted: downstream memory reasoning may remain conservative")
    if not succeeded and readiness.provisional_address_count > 0:
        hints.append("Segmented addresses remain provisional: memory-space evidence may still be too weak for later recovery")
    if not succeeded and readiness.phi_node_count == 0 and iterations >= 25:
        hints.append("Cross-block SSA absent: join-sensitive value history still depends on block-local facts")

    return StructuringIRHintArtifact(readiness=readiness, hints=tuple(hints))
