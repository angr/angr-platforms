from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.cod_extract import CODProcMetadata
from angr_platforms.X86_16.cod_comment_emitter import format_cod_comment_block
from inertia_decompiler import cli


def test_annotate_cod_proc_output_keeps_names_but_not_source_backed_call_text() -> None:
    metadata = CODProcMetadata(
        stack_aliases={4: "arg0", -2: "local0"},
        call_names=("DosBeep",),
        call_sources=(("DosBeep", "defined( OS2 )"),),
        global_names=("abarWork",),
        source_lines=("return speaker (with bits 0 and 1);",),
        source_line_set=frozenset({"return speaker (with bits 0 and 1);"}),
    )
    c_text = "short Beep(unsigned short a0)\n{\n    CallReturn();\n    DosBeep();\n    return ax;\n}\n"
    rendered = cli._annotate_cod_proc_output(c_text, SimpleNamespace(name="Beep"), metadata)
    assert "defined( OS2 )" not in rendered
    assert "speaker (with bits 0 and 1)" not in rendered
    assert "DosBeep();" in rendered
    assert "[bp+0x4] = arg0" in rendered


def test_format_cod_comment_block_escapes_trailing_macro_backslash_for_c_comments() -> None:
    rendered = format_cod_comment_block(
        func_name="main",
        proc_kind="NEAR",
        cod_path="SORTDEMO.COD",
        source_lines=(
            "#define _outtextxy( ach, x, y )   { _settextposition( y, x ); \\",
            "_outtext( ach ); }",
        ),
    )

    assert "<backslash>" in rendered
