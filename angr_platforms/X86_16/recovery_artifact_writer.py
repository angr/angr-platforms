from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .recovery_artifacts import (
    CorpusRecoveryArtifact,
    FunctionRecoveryArtifact,
    build_x86_16_corpus_recovery_artifact,
    build_x86_16_function_recovery_artifact,
)

__all__ = [
    "RecoveryArtifactWriteResult",
    "write_x86_16_corpus_recovery_artifact",
    "write_x86_16_function_recovery_artifact",
]


@dataclass(frozen=True, slots=True)
class RecoveryArtifactWriteResult:
    path: Path
    artifact_kind: str
    row_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "artifact_kind": self.artifact_kind,
            "row_count": self.row_count,
        }


def _write_payload(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_x86_16_function_recovery_artifact(source: Any, path: str | Path) -> RecoveryArtifactWriteResult:
    artifact: FunctionRecoveryArtifact = build_x86_16_function_recovery_artifact(source)
    output_path = Path(path)
    _write_payload(output_path, artifact.to_dict())
    return RecoveryArtifactWriteResult(
        path=output_path,
        artifact_kind="function_recovery",
        row_count=1,
    )


def write_x86_16_corpus_recovery_artifact(results: list[Any], path: str | Path) -> RecoveryArtifactWriteResult:
    artifact: CorpusRecoveryArtifact = build_x86_16_corpus_recovery_artifact(results)
    output_path = Path(path)
    _write_payload(output_path, artifact.to_dict())
    return RecoveryArtifactWriteResult(
        path=output_path,
        artifact_kind="corpus_recovery",
        row_count=len(artifact.function_rows),
    )
