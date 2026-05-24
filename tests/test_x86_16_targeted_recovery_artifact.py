import json

from angr_platforms.X86_16.targeted_recovery_artifact import write_x86_16_targeted_cod_recovery_artifact


def test_targeted_recovery_artifact_writes_bounded_scan_safe_result(tmp_path):
    cod_path = tmp_path / "HELPER.COD"
    cod_path.write_text(
        "\n".join(
            [
                "_helper\tPROC NEAR",
                "\t*** 000000\te8 00 00 \t\tcall\t$+3",
                "\t*** 000003\te8 00 00 \t\tcall\t$+3",
                "\t*** 000006\te8 00 00 \t\tcall\t$+3",
                "\t*** 000009\tc3 \t\tret",
                "_helper\tENDP",
            ]
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "helper.recovery.json"

    result = write_x86_16_targeted_cod_recovery_artifact(cod_path, "_helper", output_path)

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert result.proc_name == "_helper"
    assert result.fallback_kind == "cfg_only"
    assert result.confidence_status == "bounded_recovery"
    assert payload["proc_name"] == "_helper"
    assert "ir_summary" in payload
    assert payload["confidence"]["status"] == "bounded_recovery"
    assert payload["semantic_family"] == "stack_control"
