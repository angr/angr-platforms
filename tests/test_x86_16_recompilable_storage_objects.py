from types import SimpleNamespace

from angr_platforms.X86_16.recompilable_cli_bridge import _storage_object_meta
from angr_platforms.X86_16.recompilable_storage_fallback import decide_recompilable_storage_fallback
from angr_platforms.X86_16.recompilable_storage_objects import (
    build_recompilable_storage_object_artifact,
    summarize_recompilable_storage_object_artifact,
)


def test_recompilable_storage_object_summary_collects_records_and_refusals():
    project = SimpleNamespace(
        _inertia_access_traits={
            0x4010: {
                "member_evidence": {
                    (("stack", "bp", -4), 0, 2): 3,
                },
                "array_evidence": {},
                "base_stride": {
                    (("reg", "bx"), ("stack", "bp", -4), 4, 0, 2): 2,
                },
            }
        }
    )

    artifact = build_recompilable_storage_object_artifact(project, 0x4010)
    summary = summarize_recompilable_storage_object_artifact(artifact)

    assert artifact is not None
    assert summary.record_count == 0
    assert summary.refusal_count == 1
    assert summary.object_kinds == ()
    assert summary.refusal_reasons == ("mixed_or_unstable_evidence",)


def test_recompilable_storage_fallback_uses_storage_object_backed_source_when_present():
    decision = decide_recompilable_storage_fallback(
        live_shape_ok=False,
        fallback_shape_ok=True,
        shape_ok_evidence_text="shape-ok",
        fallback_evidence_text="fallback",
        storage_object_record_count=2,
        storage_object_refusal_count=0,
    )

    assert decision.use_fallback is True
    assert decision.c_text_source == "storage_object_shape_ok_evidence"
    assert decision.bounded_live_decompile_outcome == "storage_object_shape_ok_evidence_fallback"
    assert decision.selected_text == "shape-ok"


def test_recompilable_storage_fallback_prefers_refusal_outcome_when_only_refusal_signal_exists():
    decision = decide_recompilable_storage_fallback(
        live_shape_ok=False,
        fallback_shape_ok=True,
        shape_ok_evidence_text=None,
        fallback_evidence_text="fallback",
        storage_object_record_count=0,
        storage_object_refusal_count=1,
    )

    assert decision.use_fallback is True
    assert decision.c_text_source == "shape_ok_evidence"
    assert decision.bounded_live_decompile_outcome == "storage_object_refusal_shape_ok_evidence_fallback"
    assert decision.selected_text == "fallback"


def test_recompilable_cli_bridge_storage_meta_defaults_without_traits():
    meta = _storage_object_meta(SimpleNamespace(), 0x4010)

    assert meta == {
        "storage_object_record_count": 0,
        "storage_object_refusal_count": 0,
        "storage_object_kinds": (),
        "storage_object_refusal_reasons": (),
    }
