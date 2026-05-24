from __future__ import annotations

from types import SimpleNamespace

from inertia_decompiler.cli_decompilation import _emit_c_stage_trace


def test_emit_c_stage_trace_prints_labeled_snapshot(capsys):
    project = SimpleNamespace(_inertia_trace_c_stages=True)
    function = SimpleNamespace(addr=0x1234, name="demo")

    _emit_c_stage_trace(project, function, "post-helper-call-format", "int demo(void)\n{\n    return 0;\n}\n")

    captured = capsys.readouterr()
    assert "/* -- c trace: 0x1234 demo :: post-helper-call-format -- */" in captured.err
    assert "int demo(void)" not in captured.err


def test_emit_c_stage_trace_stays_silent_when_disabled(capsys):
    project = SimpleNamespace(_inertia_trace_c_stages=False)
    function = SimpleNamespace(addr=0x1234, name="demo")

    _emit_c_stage_trace(project, function, "final-emitted-c", "int demo(void) { return 0; }\n")

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
