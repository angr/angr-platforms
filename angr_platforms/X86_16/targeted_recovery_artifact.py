from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .corpus_scan import extract_cod_functions, scan_function
from .recovery_artifact_writer import RecoveryArtifactWriteResult, write_x86_16_function_recovery_artifact

__all__ = [
    "TargetedRecoveryArtifactResult",
    "write_x86_16_targeted_cod_recovery_artifact",
]


@dataclass(frozen=True, slots=True)
class TargetedRecoveryArtifactResult:
    cod_path: Path
    proc_name: str
    proc_kind: str
    write_result: RecoveryArtifactWriteResult
    confidence_status: str | None
    fallback_kind: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "cod_path": str(self.cod_path),
            "proc_name": self.proc_name,
            "proc_kind": self.proc_kind,
            "write_result": self.write_result.to_dict(),
            "confidence_status": self.confidence_status,
            "fallback_kind": self.fallback_kind,
        }


def write_x86_16_targeted_cod_recovery_artifact(
    cod_path: str | Path,
    proc_name: str,
    output_path: str | Path,
    *,
    timeout_sec: int = 5,
    mode: str = "scan-safe",
    max_cfg_bytes: int = 192,
    max_cfg_blocks: int = 8,
    max_cfg_insns: int = 200,
    max_decompile_bytes: int = 384,
    max_loop_bytes: int = 128,
) -> TargetedRecoveryArtifactResult:
    source_path = Path(cod_path)
    entries = {name: (kind, code) for name, kind, code in extract_cod_functions(source_path)}
    if proc_name not in entries:
        raise KeyError(f"{proc_name} not found in {source_path}")
    proc_kind, code = entries[proc_name]
    scan_result = scan_function(
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
    write_result = write_x86_16_function_recovery_artifact(scan_result, output_path)
    return TargetedRecoveryArtifactResult(
        cod_path=source_path,
        proc_name=proc_name,
        proc_kind=proc_kind,
        write_result=write_result,
        confidence_status=scan_result.confidence_status,
        fallback_kind=scan_result.fallback_kind,
    )
