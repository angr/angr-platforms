from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .recovery_artifact_writer import RecoveryArtifactWriteResult
from .recovery_artifact_cache import describe_x86_16_recovery_artifact_cache_surface

__all__ = [
    "RecoveryArtifactOutputSpec",
    "build_x86_16_recovery_artifact_report",
    "describe_x86_16_recovery_artifact_outputs",
]


@dataclass(frozen=True, slots=True)
class RecoveryArtifactOutputSpec:
    kind: str
    producer: str
    payload: str
    persistence: str

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "producer": self.producer,
            "payload": self.payload,
            "persistence": self.persistence,
        }


_RECOVERY_ARTIFACT_OUTPUTS: tuple[RecoveryArtifactOutputSpec, ...] = (
    RecoveryArtifactOutputSpec(
        kind="function_recovery",
        producer="write_x86_16_function_recovery_artifact",
        payload="FunctionRecoveryArtifact",
        persistence="json",
    ),
    RecoveryArtifactOutputSpec(
        kind="corpus_recovery",
        producer="write_x86_16_corpus_recovery_artifact",
        payload="CorpusRecoveryArtifact",
        persistence="json",
    ),
    RecoveryArtifactOutputSpec(
        kind="targeted_cod_recovery",
        producer="write_x86_16_targeted_cod_recovery_artifact",
        payload="TargetedRecoveryArtifactResult",
        persistence="json",
    ),
    RecoveryArtifactOutputSpec(
        kind="cod_batch_recovery",
        producer="write_x86_16_cod_corpus_recovery_artifact",
        payload="CorpusCodRecoveryArtifactResult",
        persistence="json",
    ),
)


def describe_x86_16_recovery_artifact_outputs() -> tuple[dict[str, str], ...]:
    return tuple(item.to_dict() for item in _RECOVERY_ARTIFACT_OUTPUTS)


def build_x86_16_recovery_artifact_report(
    writes: Iterable[RecoveryArtifactWriteResult],
) -> dict[str, object]:
    write_rows = tuple(
        sorted(
            (item.to_dict() for item in writes),
            key=lambda row: (str(row["artifact_kind"]), str(row["path"])),
        )
    )
    return {
        "outputs": describe_x86_16_recovery_artifact_outputs(),
        "cache_surface": describe_x86_16_recovery_artifact_cache_surface(),
        "writes": write_rows,
    }
