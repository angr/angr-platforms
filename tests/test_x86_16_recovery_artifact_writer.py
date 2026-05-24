import json

from angr_platforms.X86_16.recovery_artifact_writer import (
    write_x86_16_corpus_recovery_artifact,
    write_x86_16_function_recovery_artifact,
)


def test_write_function_recovery_artifact_emits_stable_json(tmp_path):
    path = tmp_path / "function.json"
    result = write_x86_16_function_recovery_artifact(
        {
            "cod_file": "DOSFUNC.COD",
            "proc_name": "_dos_alloc",
            "proc_kind": "NEAR",
            "ok": True,
            "stage_reached": "decompile",
            "decompiled_count": 1,
            "direct_call_count": 1,
            "return_kind": "scalar",
            "x86_16_vex_ir_summary": {
                "block_count": 1,
                "instruction_count": 4,
                "aliasable_value_count": 2,
                "frame_slot_count": 1,
            },
            "memory_reads": ("0x40:0x17/1",),
            "memory_writes": ("0x402/2",),
        },
        path,
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert result.artifact_kind == "function_recovery"
    assert result.row_count == 1
    assert payload["proc_name"] == "_dos_alloc"
    assert payload["ir_summary"]["instruction_count"] == 4
    assert payload["state_summary"]["low_memory_reads"][0]["label"] == "bda.keyboard_flags0"
    assert payload["state_summary"]["low_memory_writes"][0]["label"] == "bda.com2_port"
    assert payload["helper_summary"]["status"] == "refused"


def test_write_corpus_recovery_artifact_emits_sorted_rows(tmp_path):
    path = tmp_path / "corpus.json"
    result = write_x86_16_corpus_recovery_artifact(
        [
            {
                "cod_file": "B.COD",
                "proc_name": "_b",
                "proc_kind": "NEAR",
                "ok": True,
                "stage_reached": "decompile",
                "decompiled_count": 1,
                "direct_call_count": 1,
                "memory_reads": ("0xb800:0x12",),
                "return_kind": "scalar",
                "x86_16_vex_ir_summary": {"block_count": 2, "instruction_count": 7},
            },
            {
                "cod_file": "A.COD",
                "proc_name": "_a",
                "proc_kind": "NEAR",
                "ok": True,
                "stage_reached": "decompile",
                "direct_call_count": 2,
                "memory_reads": ("0x40:0x17/1",),
                "memory_writes": ("0x402/2",),
                "return_kind": "scalar",
            },
        ],
        path,
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert result.artifact_kind == "corpus_recovery"
    assert result.row_count == 2
    assert [(row["cod_file"], row["proc_name"]) for row in payload["function_rows"]] == [
        ("A.COD", "_a"),
        ("B.COD", "_b"),
    ]
    assert payload["function_rows"][1]["ir_summary"]["instruction_count"] == 7
    assert payload["low_memory_read_region_counts"] == {"bda": 1, "video_ram": 1}
    assert payload["low_memory_write_region_counts"] == {"bda": 1}
