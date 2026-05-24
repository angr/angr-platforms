from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .corpus_scan import extract_cod_functions, scan_function
from .recovery_artifacts import build_x86_16_corpus_recovery_artifact
from .recovery_artifact_writer import RecoveryArtifactWriteResult, write_x86_16_corpus_recovery_artifact

__all__ = [
    "CorpusCodRecoveryArtifactResult",
    "write_x86_16_cod_corpus_recovery_artifact",
]


@dataclass(frozen=True, slots=True)
class CorpusCodRecoveryArtifactResult:
    cod_path: Path
    proc_count: int
    write_result: RecoveryArtifactWriteResult
    confidence_status_counts: dict[str, int]
    helper_status_counts: dict[str, int]
    low_memory_read_region_counts: dict[str, int]
    low_memory_write_region_counts: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "cod_path": str(self.cod_path),
            "proc_count": self.proc_count,
            "write_result": self.write_result.to_dict(),
            "confidence_status_counts": dict(self.confidence_status_counts),
            "helper_status_counts": dict(self.helper_status_counts),
            "low_memory_read_region_counts": dict(self.low_memory_read_region_counts),
            "low_memory_write_region_counts": dict(self.low_memory_write_region_counts),
        }


def write_x86_16_cod_corpus_recovery_artifact(
    cod_path: str | Path,
    output_path: str | Path,
    *,
    timeout_sec: int = 5,
    mode: str = "scan-safe",
    max_cfg_bytes: int = 192,
    max_cfg_blocks: int = 8,
    max_cfg_insns: int = 200,
    max_decompile_bytes: int = 384,
    max_loop_bytes: int = 128,
    limit: int | None = None,
) -> CorpusCodRecoveryArtifactResult:
    source_path = Path(cod_path)
    entries = extract_cod_functions(source_path)
    if limit is not None and limit >= 0:
        entries = entries[:limit]

    results = [
        scan_function(
            source_path,
            proc_name,
            proc_kind,
            code,
            timeout_sec=timeout_sec,
            mode=mode,
            max_cfg_bytes=max_cfg_bytes,
            max_cfg_blocks=max_cfg_blocks,
            max_cfg_insns=max_cfg_insns,
            max_decompile_bytes=max_decompile_bytes,
            max_loop_bytes=max_loop_bytes,
        )
        for proc_name, proc_kind, code in entries
    ]
    artifact = build_x86_16_corpus_recovery_artifact(results)
    write_result = write_x86_16_corpus_recovery_artifact(results, output_path)
    return CorpusCodRecoveryArtifactResult(
        cod_path=source_path,
        proc_count=len(results),
        write_result=write_result,
        confidence_status_counts=dict(artifact.confidence_status_counts),
        helper_status_counts=dict(artifact.helper_status_counts),
        low_memory_read_region_counts=dict(artifact.low_memory_read_region_counts),
        low_memory_write_region_counts=dict(artifact.low_memory_write_region_counts),
    )
