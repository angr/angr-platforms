from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "RecompilableStorageFallbackDecision",
    "decide_recompilable_storage_fallback",
]


@dataclass(frozen=True)
class RecompilableStorageFallbackDecision:
    use_fallback: bool
    c_text_source: str | None
    bounded_live_decompile_outcome: str | None
    selected_text: str | None


def decide_recompilable_storage_fallback(
    *,
    live_shape_ok: bool,
    fallback_shape_ok: bool,
    shape_ok_evidence_text: str | None,
    fallback_evidence_text: str | None,
    storage_object_record_count: int,
    storage_object_refusal_count: int,
) -> RecompilableStorageFallbackDecision:
    if live_shape_ok or not fallback_shape_ok:
        return RecompilableStorageFallbackDecision(
            use_fallback=False,
            c_text_source=None,
            bounded_live_decompile_outcome=None,
            selected_text=None,
        )

    has_storage_signal = storage_object_record_count > 0 or storage_object_refusal_count > 0
    if has_storage_signal and shape_ok_evidence_text is not None:
        outcome = (
            "storage_object_refusal_shape_ok_evidence_fallback"
            if storage_object_refusal_count > 0
            else "storage_object_shape_ok_evidence_fallback"
        )
        return RecompilableStorageFallbackDecision(
            use_fallback=True,
            c_text_source="storage_object_shape_ok_evidence",
            bounded_live_decompile_outcome=outcome,
            selected_text=shape_ok_evidence_text,
        )

    selected_text = shape_ok_evidence_text or fallback_evidence_text
    if selected_text is None:
        return RecompilableStorageFallbackDecision(
            use_fallback=False,
            c_text_source=None,
            bounded_live_decompile_outcome=None,
            selected_text=None,
        )
    outcome = (
        "storage_object_refusal_shape_ok_evidence_fallback"
        if storage_object_refusal_count > 0
        else "shape_ok_evidence_fallback"
    )
    return RecompilableStorageFallbackDecision(
        use_fallback=True,
        c_text_source="shape_ok_evidence",
        bounded_live_decompile_outcome=outcome,
        selected_text=selected_text,
    )
