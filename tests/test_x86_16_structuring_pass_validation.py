from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16 import decompiler_structuring_stage as stage


def test_structuring_stage_records_validation_for_semantic_passes(monkeypatch):
    project = SimpleNamespace(
        _inertia_tail_validation_enabled=True,
        _inertia_decompiler_stage=None,
        kb=SimpleNamespace(functions=None),
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010))

    monkeypatch.setattr(stage, "fingerprint_x86_16_tail_validation_boundary", lambda *_args, **_kwargs: ("fp",))
    monkeypatch.setattr(stage, "collect_x86_16_tail_validation_summary", lambda *_args, **_kwargs: {"conditions": ()})
    monkeypatch.setattr(
        stage,
        "build_x86_16_tail_validation_cached_result",
        lambda **kwargs: {
            "changed": False,
            "cache_hit": False,
            "stage": kwargs["stage"],
            "mode": kwargs["mode"],
        },
    )
    monkeypatch.setattr(stage, "build_x86_16_tail_validation_verdict", lambda pass_name, _validation: f"{pass_name}: stable")
    monkeypatch.setattr(stage, "_decompiler_structuring_passes_for_function", lambda _project, _codegen: (
        stage.DecompilerStructuringPassSpec("_segmented_memory_reasoning_8616", lambda _codegen: False, False),
        stage.DecompilerStructuringPassSpec("_induction_summary_artifact_8616", lambda _codegen: False, False),
    ))

    changed = stage._structuring_codegen_8616(project, codegen)

    assert changed is False
    validation = codegen._inertia_structuring_pass_validation
    assert validation["_segmented_memory_reasoning_8616"]["stage"] == "structuring:_segmented_memory_reasoning_8616"
    assert validation["_segmented_memory_reasoning_8616"]["verdict"] == "structuring:_segmented_memory_reasoning_8616: stable"
    assert "_induction_summary_artifact_8616" not in validation


def test_structuring_stage_rejects_non_stable_validation_status(monkeypatch):
    project = SimpleNamespace(
        _inertia_tail_validation_enabled=True,
        _inertia_decompiler_stage=None,
        kb=SimpleNamespace(functions=None),
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010), order=[])

    def _semantic_pass(_codegen):
        _codegen.order.append("semantic")
        return True

    def _later_pass(_codegen):
        _codegen.order.append("later")
        return True

    monkeypatch.setattr(stage, "fingerprint_x86_16_tail_validation_boundary", lambda *_args, **_kwargs: ("fp",))
    monkeypatch.setattr(stage, "collect_x86_16_tail_validation_summary", lambda *_args, **_kwargs: {"conditions": ()})
    monkeypatch.setattr(
        stage,
        "build_x86_16_tail_validation_cached_result",
        lambda **kwargs: {
            "changed": False,
            "status": "unknown",
            "summary_text": "validation metadata missing",
            "cache_hit": False,
            "stage": kwargs["stage"],
            "mode": kwargs["mode"],
        },
    )
    monkeypatch.setattr(stage, "build_x86_16_tail_validation_verdict", lambda pass_name, _validation: f"{pass_name}: unknown")
    monkeypatch.setattr(
        stage,
        "_decompiler_structuring_passes_for_function",
        lambda _project, _codegen: (
            stage.DecompilerStructuringPassSpec("_segmented_memory_reasoning_8616", _semantic_pass, False),
            stage.DecompilerStructuringPassSpec("_structuring_codegen_8616", _later_pass, False),
        ),
    )

    changed = stage._structuring_codegen_8616(project, codegen)

    assert changed is False
    assert codegen.order == ["semantic"]
    assert codegen._inertia_structuring_validation_failed is True
    assert codegen._inertia_structuring_validation_failure_pass == "_segmented_memory_reasoning_8616"
    assert codegen._inertia_structuring_validation_failure_error == "validation metadata missing"
