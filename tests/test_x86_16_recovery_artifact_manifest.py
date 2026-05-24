from pathlib import Path

from angr_platforms.X86_16.recovery_artifact_manifest import (
    build_x86_16_recovery_artifact_report,
    describe_x86_16_recovery_artifact_outputs,
)
from angr_platforms.X86_16.recovery_artifact_writer import RecoveryArtifactWriteResult


def test_recovery_artifact_output_descriptor_is_deterministic():
    assert describe_x86_16_recovery_artifact_outputs() == (
        {
            "kind": "function_recovery",
            "producer": "write_x86_16_function_recovery_artifact",
            "payload": "FunctionRecoveryArtifact",
            "persistence": "json",
        },
        {
            "kind": "corpus_recovery",
            "producer": "write_x86_16_corpus_recovery_artifact",
            "payload": "CorpusRecoveryArtifact",
            "persistence": "json",
        },
        {
            "kind": "targeted_cod_recovery",
            "producer": "write_x86_16_targeted_cod_recovery_artifact",
            "payload": "TargetedRecoveryArtifactResult",
            "persistence": "json",
        },
        {
            "kind": "cod_batch_recovery",
            "producer": "write_x86_16_cod_corpus_recovery_artifact",
            "payload": "CorpusCodRecoveryArtifactResult",
            "persistence": "json",
        },
    )


def test_recovery_artifact_report_sorts_write_rows():
    report = build_x86_16_recovery_artifact_report(
        (
            RecoveryArtifactWriteResult(Path("/tmp/z.json"), "function_recovery", 1),
            RecoveryArtifactWriteResult(Path("/tmp/a.json"), "corpus_recovery", 2),
        )
    )

    assert [row["artifact_kind"] for row in report["writes"]] == [
        "corpus_recovery",
        "function_recovery",
    ]
    assert report["cache_surface"]["namespace_family"] == "recovery_artifact.*"
