from __future__ import annotations

from inertia_decompiler.decompilation_quality import assess_decompiled_c_text


def test_assess_decompiled_c_text_rejects_raw_ir_shaped_output() -> None:
    assessment = assess_decompiled_c_text(
        "void sub(void) {\n"
        "    STORE(addr=stack_base-2, data=(Reference vvar_4{s0|1b}), size=2, endness=Iend_LE, guard=None)\n"
        "    if (...) { Goto None }\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is True
    assert "store-op" in assessment.markers
    assert "raw-reference" in assessment.markers
    assert "goto-none" in assessment.markers


def test_assess_decompiled_c_text_accepts_normal_c() -> None:
    assessment = assess_decompiled_c_text(
        "int rand(void)\n"
        "{\n"
        "    int value;\n"
        "    value = sub_2cc0();\n"
        "    return value;\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is False
    assert assessment.markers == ()
