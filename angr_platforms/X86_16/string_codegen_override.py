from __future__ import annotations

from .string_instruction_lowering import StringIntrinsicArtifact, render_x86_16_string_intrinsic_c

__all__ = ["apply_x86_16_string_codegen_override"]


def _render_override_text(codegen) -> str | None:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return None
    artifact = getattr(codegen, "_inertia_string_intrinsic_artifact", None)
    if not isinstance(artifact, StringIntrinsicArtifact):
        return None
    if artifact.refusals or not artifact.records:
        return None
    name = getattr(cfunc, "name", None) or f"sub_{getattr(cfunc, 'addr', 0):x}"
    return render_x86_16_string_intrinsic_c(name, artifact)


def apply_x86_16_string_codegen_override(project, codegen) -> bool:  # noqa: ARG001
    rendered = _render_override_text(codegen)
    if rendered is None:
        return False
    if getattr(codegen, "_inertia_string_codegen_override_text", None) == rendered:
        return False
    original = getattr(codegen, "render_text", None)
    if not callable(original):
        return False

    def _render_text_override(_cfunc):  # noqa: ANN001
        return rendered

    setattr(codegen, "_inertia_original_render_text", original)
    setattr(codegen, "_inertia_string_codegen_override_text", rendered)
    setattr(codegen, "render_text", _render_text_override)
    return True
