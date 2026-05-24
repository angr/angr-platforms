from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.string_codegen_override import apply_x86_16_string_codegen_override
from angr_platforms.X86_16.string_instruction_lowering import StringIntrinsicArtifact, StringIntrinsicRecord


def test_string_codegen_override_replaces_render_text_with_normal_path_c():
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, name="memset_like"),
        render_text=lambda _cfunc: "old text",
        _inertia_string_intrinsic_artifact=StringIntrinsicArtifact(
            records=(
                StringIntrinsicRecord(
                    index=0,
                    family="memset_class",
                    record_indexes=(0,),
                    width=2,
                    direction_mode="forward",
                    repeat_kind="rep",
                ),
            )
        ),
    )

    changed = apply_x86_16_string_codegen_override(None, codegen)

    assert changed is True
    rendered = codegen.render_text(codegen.cfunc)
    assert "void memset_like(void)" in rendered
    assert "__x86_16_stos(2);" in rendered
    assert "__x86_16_string_state" not in rendered
