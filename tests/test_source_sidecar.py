from __future__ import annotations

from pathlib import Path

import inertia_decompiler.cli as cli
from inertia_decompiler.source_sidecar import render_local_source_sidecar_function


def test_render_local_source_sidecar_function_extracts_knr_body(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    source = tmp_path / "sample.c"
    source.write_text(
        "helper()\n"
        "{\n"
        "    return(1);\n"
        "}\n"
        "\n"
        "pause_screen()\n"
        "{\n"
        "    return(0);\n"
        "}\n"
    )

    rendered = render_local_source_sidecar_function(binary, "pause_screen")

    assert rendered is not None
    assert "pause_screen()" in rendered
    assert "return(0);" in rendered


def test_render_local_source_sidecar_function_uses_matching_stem_only(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    (tmp_path / "other.c").write_text("pause_screen(){return(1);}\n")

    rendered = render_local_source_sidecar_function(binary, "pause_screen")

    assert rendered is None


def test_render_local_source_sidecar_function_extracts_knr_with_arg_decls(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    source = tmp_path / "sample.c"
    source.write_text(
        "draw_box(attr)\n"
        "int attr;\n"
        "{\n"
        "    return;\n"
        "}\n"
    )

    rendered = render_local_source_sidecar_function(binary, "draw_box")

    assert rendered is not None
    assert "draw_box(attr)" in rendered
    assert "int attr;" in rendered
    assert not rendered.startswith("\n")


def test_emit_optional_source_sidecar_c_block_alternates_source_before_c(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli,
        "render_local_source_sidecar_function",
        lambda binary_path, function_name: "int source(void) { return 1; }\n",
    )

    cli._emit_optional_source_sidecar_c_block(
        tmp_path / "sample.exe",
        "source",
        "int decompiled(void) { return 0; }\n",
        alternate_source_c=True,
        c_header="/* -- c -- */",
    )

    out = capsys.readouterr().out
    assert out.index("/* -- source c -- */") < out.index("/* -- c -- */")
    assert "int source(void) { return 1; }" in out
    assert "int decompiled(void) { return 0; }" in out


def test_emit_optional_source_sidecar_c_block_skips_source_when_disabled(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli,
        "render_local_source_sidecar_function",
        lambda binary_path, function_name: "int source(void) { return 1; }\n",
    )

    cli._emit_optional_source_sidecar_c_block(
        tmp_path / "sample.exe",
        "source",
        "int decompiled(void) { return 0; }\n",
        alternate_source_c=False,
        c_header="/* -- c -- */",
    )

    out = capsys.readouterr().out
    assert "/* -- source c -- */" not in out
    assert out.count("/* -- c -- */") == 1
    assert "int decompiled(void) { return 0; }" in out
