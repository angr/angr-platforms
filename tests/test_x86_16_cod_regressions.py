from __future__ import annotations

import re
import subprocess
import sys
import time
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

import decompile
import pytest
from angr.analyses.decompiler.return_maker import ReturnMaker
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.cod_extract import extract_cod_proc_metadata
from angr_platforms.X86_16.cod_known_objects import known_cod_object_spec
from angr_platforms.X86_16.decompiler_return_compat import apply_x86_16_decompiler_return_compatibility

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
COD_DIR = REPO_ROOT / "cod"
RUNNER_PATH = REPO_ROOT / "scripts" / "decompile_cod_dir.py"

_runner_spec = spec_from_file_location("decompile_cod_dir_test_runner", RUNNER_PATH)
assert _runner_spec is not None and _runner_spec.loader is not None
_runner = module_from_spec(_runner_spec)
sys.modules[_runner_spec.name] = _runner
_runner_spec.loader.exec_module(_runner)


def _run_cod_proc(path: Path, proc: str, *, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(path),
            "--proc",
            proc,
            "--timeout",
            str(timeout),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=max(90, timeout * 6),
        check=False,
    )


def _assert_has_all(text: str, anchors: tuple[str, ...]) -> None:
    for anchor in anchors:
        assert anchor in text, anchor


def _assert_has_none(text: str, anchors: tuple[str, ...]) -> None:
    for anchor in anchors:
        assert anchor not in text, anchor


@pytest.mark.parametrize(
    ("cod_name", "proc_name", "timeout"),
    (
        ("BIOSFUNC.COD", "_bios_clearkeyflags", 20),
        ("DOSFUNC.COD", "_dos_getfree", 20),
        ("DOSFUNC.COD", "_dos_loadOverlay", 20),
        ("DOSFUNC.COD", "_dos_getReturnCode", 20),
        ("OVERLAY.COD", "_overlay_load", 20),
        ("EGAME2.COD", "_openFileWrapper", 20),
    ),
)
def test_cod_regression_targets_are_recoverable(cod_name: str, proc_name: str, timeout: int):
    result = _run_cod_proc(COD_DIR / cod_name, proc_name, timeout=timeout)

    assert result.returncode == 0, result.stderr + result.stdout
    assert f"function: 0x1000 {proc_name}" in result.stdout
    assert "Decompilation empty" not in result.stdout


def test_cod_timeout_target_is_classified_deterministically():
    for cod_name, proc_name in (("EGAME11.COD", "_drawCockpit"),):
        start = time.monotonic()
        result = _run_cod_proc(COD_DIR / cod_name, proc_name, timeout=20)
        elapsed = time.monotonic() - start

        assert result.returncode == 3, result.stderr + result.stdout
        _assert_has_all(
            result.stdout,
            (
                "Timed out while recovering a function after 20s",
                "Tip: try a larger --timeout for larger binaries.",
            ),
        )
        assert "during x86-16 function recovery" in result.stdout
        assert elapsed < 60, elapsed


@pytest.mark.parametrize(
    "proc_name",
    ("_dos_alloc", "_dos_resize", "_dos_mcbInfo"),
)
def test_cod_runner_hotspots_fall_back_through_scan_safe_classifier(monkeypatch, tmp_path, proc_name: str):
    item = _runner.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name=proc_name,
        proc_kind="NEAR",
        proc_index=1,
        proc_total=1,
        code=b"\x90",
    )
    scan_result = _runner.FunctionScanResult(
        cod_file="DOSFUNC.COD",
        proc_name=proc_name,
        proc_kind="NEAR",
        byte_len=1,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="decompile",
        fallback_kind="cfg_only",
        semantic_family="stack_control",
        semantic_family_reason="call-heavy helper path",
        function_count=1,
        decompiled_count=0,
        confidence_status="bounded_recovery",
        confidence_scan_safe_classification="strong",
        stages=[],
    )

    def fake_run(*args, **kwargs):  # noqa: ANN001
        stdout_file = kwargs["stdout"]
        stdout_file.write("/* Timed out while recovering a function after 20s. */\n")
        return subprocess.CompletedProcess(args=args[0], returncode=3, stdout="", stderr="")

    monkeypatch.setattr(_runner.subprocess, "run", fake_run)
    monkeypatch.setattr(_runner, "_run_scan_safe_fallback", lambda *_args, **_kwargs: scan_result)

    result = _runner._run_work_item(item, timeout=20, max_memory_mb=1024)
    rendered = _runner._render_result_block(result)

    assert result.exit_kind == "fallback"
    assert result.child_exit_kind == "timeout"
    assert result.scan_safe_result is scan_result
    assert "fallback kind: cfg_only" in rendered
    assert "confidence status: bounded_recovery" in rendered
    assert "confidence scan-safe: strong" in rendered
    assert "child exit kind: timeout" in rendered
    assert "worker process terminated abruptly" not in rendered


def test_cod_biosfunc_clearkeyflags_far_word_store():
    result = _run_cod_proc(COD_DIR / "BIOSFUNC.COD", "_bios_clearkeyflags")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(result.stdout, ("function: 0x1000 _bios_clearkeyflags",))
    _assert_has_all(result.stdout, ("MK_FP(0x40, 0x17)",))
    _assert_has_none(result.stdout, ("*((unsigned short *)1047)", "*((char *)(es * 16 + 1047))", "*((char *)(es * 16 + 1048))"))


def test_cod_dos_getfree_call_and_return_recovered():
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_getfree")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _dos_getfree",
            "unsigned short _dos_getfree(void)",
            "intdos(&rin, &rout)",
            "rin.h.ah",
            "rin.x.bx",
            "rout.x.cflag",
            "return rout.x.bx",
        ),
    )
    _assert_has_none(
        result.stdout,
        (
            "rin = 72;",
            "rin = 65535;",
            "s_2 = &",
            "s_8 = 28675;",
            "err = 28673;",
            "void _dos_getfree(void)",
        ),
    )
    assert "rout" in result.stdout
    assert "rin" in result.stdout
    assert "S425_rout" not in result.stdout


def test_cod_process_id_source_headers_are_captured():
    get_meta = extract_cod_proc_metadata(COD_DIR / "DOSFUNC.COD", "_dos_getProcessId")
    set_meta = extract_cod_proc_metadata(COD_DIR / "DOSFUNC.COD", "_dos_setProcessId")

    assert "uint16 dos_getProcessId(void) {" in get_meta.source_lines
    assert "int dos_setProcessId(const uint16 pid) {" in set_meta.source_lines


@pytest.mark.parametrize(
    ("proc_name", "header_anchor"),
    (
        ("_dos_getProcessId", "unsigned short _dos_getProcessId(void)"),
        ("_dos_setProcessId", "int _dos_setProcessId(const unsigned short pid)"),
    ),
)
def test_cod_process_id_helpers_keep_empty_bodies(proc_name: str, header_anchor: str):
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", proc_name)

    assert result.returncode == 0, result.stderr + result.stdout
    assert header_anchor in result.stdout
    assert "return;" not in result.stdout
    if proc_name == "_dos_setProcessId":
        assert "[bp+0x4] = pid" in result.stdout


def test_cod_extract_canonicalizes_known_object_names():
    get_meta = extract_cod_proc_metadata(COD_DIR / "DOSFUNC.COD", "_dos_getfree")

    assert "rout" in get_meta.global_names
    assert "S425_rout" not in get_meta.global_names


def test_preferred_known_helper_signature_decl_prefers_canonical_prefixed_names():
    assert decompile.preferred_known_helper_signature_decl("intdos") == "int _intdos(union REGS *in, union REGS *out);"
    assert decompile.preferred_known_helper_signature_decl("ERROR") == "int _ERROR(const char *fmt, ...);"


def test_cod_strlen_stack_local_copy_is_declared():
    result = _run_cod_proc(COD_DIR / "default" / "STRLEN.COD", "_strlen")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _strlen",
            "unsigned short _strlen(unsigned short *s)",
            "while (*s++)",
            "n += 1;",
            "return (n);",
        ),
    )
    _assert_has_none(
        result.stdout,
        (
            "if (!(s + 1))",
            "ir_",
            "s_3",
        ),
    )
    assert re.search(r"\bir_\d+\b", result.stdout) is None
    assert "ir_3 = s_3;" not in result.stdout
    assert "ir_4 = s_3;" not in result.stdout
    assert "s_3" not in result.stdout


def test_cod_known_object_catalog_is_exposed():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import angr_platforms.X86_16 as x; "
            "print(x.describe_x86_16_cod_known_objects()['names'])",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "rin",
            "rout",
            "sreg",
            "exeLoadParams",
            "ovlLoadParams",
            "ovlHeader",
            "slotArray",
        ),
    )


def test_cod_overlay_header_known_object_is_pointer_typed():
    spec = known_cod_object_spec("ovlHeader")

    assert spec is not None
    assert spec.type.__class__.__name__ == "SimTypePointer"
    assert getattr(spec.type, "pts_to", None) is not None
    assert getattr(spec.type.pts_to, "name", None) == "struct OvlHeader"


def test_cod_overlay_load_preserves_guarded_free_memory_probe_before_final_return():
    result = _run_cod_proc(COD_DIR / "OVERLAY.COD", "_overlay_load")

    assert result.returncode == 0, result.stderr + result.stdout
    text = result.stdout
    body_match = re.search(
        r"unsigned short _overlay_load\(const char \* filename\)\s*\{(?P<body>.*?)\n\}",
        text,
        re.S,
    )
    assert body_match is not None
    body = body_match.group("body")
    assert not re.search(r"int err;\s*return ovlSegment;", body, re.S)
    ordered = [
        text.index("freeMem = dos_getfree();"),
        text.index("if (freeMem == 0)"),
        text.index("alloc = freeMem - RESERVE_PARA;"),
        text.index("ovlSegment = dos_alloc(alloc);"),
        text.index("return ovlSegment;"),
    ]
    assert ordered == sorted(ordered)
    assert re.search(
        r'if \(freeMem == 0\)\s*\{\s*ERROR\("overlay_load\(\): unable to determine amount of free memory"\);\s*return 0;\s*\}',
        text,
        re.S,
    )


def test_cod_overlay_function_address_keeps_proven_known_object_bindings():
    result = _run_cod_proc(COD_DIR / "OVERLAY.COD", "_overlay_functionAddress")

    assert result.returncode == 0, result.stderr + result.stdout
    text = result.stdout
    assert "struct OvlHeader FAR *ovlHeader = MK_FP(ovlLoadSegment, 0);" in text
    assert "uint16 FAR* slotArray=&(ovlHeader->slot);" in text
    assert "return MK_FP(ovlHeader->code_segment, slotArray[funcNumber]);" in text
    assert re.search(r"(?m)^\s*MK_FP\(ovlHeader->code_segment, slotArray\[funcNumber\]\);\s*$", text) is None


def test_cod_dos_loadoverlay_wrapper_returns_loadprog():
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_loadOverlay")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _dos_loadOverlay",
            "loadprog",
            "file",
            "segment",
        ),
    )
    assert len(re.findall(r"(?m)^\s*return loadprog\(file, segment, DOS_LOAD_OVL, NULL\);\s*$", result.stdout)) == 1
    assert len(re.findall(r"(?m)^\s*loadprog\(file, segment, DOS_LOAD_OVL, NULL\);\s*$", result.stdout)) == 0
    _assert_has_none(
        result.stdout,
        (
            "3823()",
            "v12 << 16",
            "s_4 =",
            "s_6 =",
        ),
    )


def test_cod_dos_runprogram_wrapper_returns_loadprog():
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_runProgram")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _dos_runProgram",
            "loadprog",
            "file",
            "cmdline",
        ),
    )
    assert len(re.findall(r"(?m)^\s*return loadprog\(file, 0, DOS_LOAD_EXEC, cmdline\);\s*$", result.stdout)) == 1
    assert len(re.findall(r"(?m)^\s*loadprog\(file, 0, DOS_LOAD_EXEC, cmdline\);\s*$", result.stdout)) == 0
    _assert_has_none(
        result.stdout,
        (
            "3823()",
            "v12 << 16",
            "s_4 =",
            "s_6 =",
        ),
    )


def test_cod_loadprog_uses_known_helper_signature_and_no_missing_type():
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "loadprog")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 loadprog",
            "int loadprog(const char *file, unsigned short segment, unsigned short mode, const char *cmdline)",
            "int err;",
            "rin.h.al = mode",
            "rin.x.dx = (unsigned int)file",
            "err = intdos(&rin, &rout);",
            "ERROR(\"dos_loadprog: unable to load %s at 0x%x, error 0x%x\", file, segment, err);",
            "return err;",
        ),
    )
    assert len(re.findall(r"(?m)^\s*err = intdos\(&rin, &rout\);\s*$", result.stdout)) == 1
    assert re.search(
        r"rin\.x\.dx = \(unsigned int\)file;\s+switch \(mode\)\s*\{",
        result.stdout,
        re.S,
    ), result.stdout
    assert re.search(
        r"err = intdos\(&rin, &rout\);\s+if \(rout\.x\.cflag != 0\)",
        result.stdout,
        re.S,
    ), result.stdout
    assert not re.search(
        r"rin\.x\.dx = \(unsigned int\)file;\s*if \(rout\.x\.cflag != 0\)",
        result.stdout,
        re.S,
    ), result.stdout
    _assert_has_none(
        result.stdout,
        (
            "<missing-type>",
            "file_2",
            "type_2",
            "unsigned short loadprog(unsigned short file, unsigned short file_2, unsigned short type, unsigned short type_2)",
            "return err_2;",
        ),
    )


def test_cod_openfilewrapper_direct_forwarding():
    result = _run_cod_proc(COD_DIR / "EGAME2.COD", "_openFileWrapper")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(result.stdout, ("function: 0x1000 _openFileWrapper", "openFile(path, mode);"))
    _assert_has_none(
        result.stdout,
        (
            "s_2 = &",
            "s_4 = mode",
            "s_6 = path",
        ),
    )


def test_cod_dos_getreturncode_returns_value():
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_getReturnCode")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _dos_getReturnCode",
            "intdos(&rin, &rout)",
            "return",
        ),
    )


@pytest.mark.parametrize(
    ("cod_name", "proc_name", "anchors"),
    (
        ("DOSFUNC.COD", "_dos_getfree", ("int _intdos(union REGS *in, union REGS *out);", "int _ERROR(const char *fmt, ...);")),
        ("DOSFUNC.COD", "_dos_loadOverlay", ("int loadprog(const char *file, unsigned short segment, unsigned short mode, const char *cmdline);",)),
        ("EGAME2.COD", "_openFileWrapper", ("int _openFile(const char *path, unsigned short mode);",)),
    ),
)
def test_cod_known_helper_signatures_are_declared(cod_name: str, proc_name: str, anchors: tuple[str, ...]):
    result = _run_cod_proc(COD_DIR / cod_name, proc_name)

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(result.stdout, anchors)


def test_regenerate_codegen_text_falls_back_on_failure():
    class DummyCodegen:
        def __init__(self) -> None:
            self.text = "fallback text"
            self.cfunc = object()

        def regenerate_text(self) -> None:
            raise RecursionError("maximum recursion depth exceeded")

        def render_text(self, _cfunc) -> tuple[str, object]:
            return "rendered text", object()

    text, changed = decompile._regenerate_codegen_text_safely(DummyCodegen(), context="dummy")

    assert text == "rendered text"
    assert changed is False


def test_dedupe_duplicate_local_declarations_text_prefers_annotated_slot():
    c_text = (
        "void _dos_free(unsigned short segment)\n"
        "{\n"
        "    char err;  // [bp-0x6]\n"
        "    char err;  // [bp-0x2] err\n"
        "    return;\n"
        "}\n"
    )

    deduped = decompile._dedupe_duplicate_local_declarations_text(c_text)

    assert "char err_2" not in deduped  # non-annotated duplicate removed, not renamed
    assert "char err;  // [bp-0x2] err" in deduped
    assert deduped.count("char err;") == 1


def test_prune_unused_local_declarations_text_keeps_return_statements():
    c_text = (
        "unsigned short _overlay_load(void)\n"
        "{\n"
        "    unsigned short ovlSegment;\n"
        "    dos_getfree();\n"
        "    return ovlSegment;\n"
        "}\n"
    )

    pruned = decompile._prune_unused_local_declarations_text(c_text)

    assert "unsigned short ovlSegment;" in pruned
    assert "return ovlSegment;" in pruned


def test_prune_unused_local_declarations_text_keeps_annotated_declarations():
    c_text = (
        "unsigned short _overlay_load(void)\n"
        "{\n"
        "    unsigned short ovlSegment;  // [bp-0x4] ovlSegment\n"
        "    dos_getfree();\n"
        "}\n"
    )

    pruned = decompile._prune_unused_local_declarations_text(c_text)

    assert "unsigned short ovlSegment;  // [bp-0x4] ovlSegment" in pruned


def test_prune_unused_local_declarations_text_drops_unused_stack_bp_placeholder_declaration():
    c_text = (
        "short PercolateUp(int iMaxLevel)\n"
        "{\n"
        "    int stack_bp_m6_b1;  // [bp-0x6]\n"
        "    char s_fffa;\n"
        "    s_fffa = 1;\n"
        "    return s_fffa;\n"
        "}\n"
    )

    pruned = decompile._prune_unused_local_declarations_text(c_text)

    assert "int stack_bp_m6_b1;  // [bp-0x6]" not in pruned
    assert "char s_fffa;" in pruned


def test_cod_dos_loadprogram_wrapper_keeps_err_guard_and_segment_stores():
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_loadProgram")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "if (err) return err;",
            "*cs = exeLoadParams.cs;",
            "*ss = exeLoadParams.ss;",
        ),
    )
    _assert_has_none(
        result.stdout,
        (
            "MK_FP(ds,",
            "if (err)\n    return err;",
        ),
    )


def test_prune_dead_local_assignments_removes_unused_constant_stores():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    dead_var = SimStackVariable(4, 2, base="bp", name="dead", region=0x1000)
    live_var = SimStackVariable(6, 2, base="bp", name="live", region=0x1000)
    dead_cvar = structured_c.CVariable(dead_var, variable_type=SimTypeShort(False), codegen=codegen)
    live_cvar = structured_c.CVariable(live_var, variable_type=SimTypeShort(False), codegen=codegen)
    statements = structured_c.CStatements(
        [
            structured_c.CAssignment(dead_cvar, structured_c.CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
            structured_c.CAssignment(
                live_cvar,
                structured_c.CBinaryOp(
                    "Add",
                    live_cvar,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=statements,
        variables_in_use={
            dead_var: dead_cvar,
            live_var: live_cvar,
        },
    )

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 1
    assert codegen.cfunc.statements.statements[0].lhs.variable is live_var


def test_prune_dead_local_assignments_removes_overwritten_local_stores():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    local_var = SimStackVariable(-2, 2, base="bp", name="local", region=0x1000)
    local_cvar = structured_c.CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    overwritten = structured_c.CStatements(
        [
            structured_c.CAssignment(
                local_cvar,
                structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                local_cvar,
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CReturn(local_cvar, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=overwritten,
        variables_in_use={local_var: local_cvar},
    )

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    assert codegen.cfunc.statements.statements[0].rhs.value == 2
    assert codegen.cfunc.statements.statements[1].retval.variable is local_var


def test_prune_dead_local_assignments_removes_overwritten_storage_aliases():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    first_var = SimStackVariable(-2, 2, base="bp", name="first", region=0x1000)
    second_var = SimStackVariable(-2, 2, base="bp", name="second", region=0x1000)
    first_cvar = structured_c.CVariable(first_var, variable_type=SimTypeShort(False), codegen=codegen)
    second_cvar = structured_c.CVariable(second_var, variable_type=SimTypeShort(False), codegen=codegen)
    overwritten = structured_c.CStatements(
        [
            structured_c.CAssignment(
                first_cvar,
                structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                second_cvar,
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CReturn(second_cvar, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=overwritten,
        variables_in_use={
            first_var: first_cvar,
            second_var: second_cvar,
        },
    )

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    assert codegen.cfunc.statements.statements[0].rhs.value == 2
    assert codegen.cfunc.statements.statements[1].retval.variable is second_var


def test_prune_dead_local_assignments_removes_redundant_call_before_same_return():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    call = structured_c.CFunctionCall(
        "loadprog",
        SimpleNamespace(name="loadprog"),
        [
            structured_c.CTypeCast(
                SimTypeShort(False),
                SimTypeShort(False),
                structured_c.CVariable(SimStackVariable(-4, 2, base="bp", region=0x1000), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    statements = structured_c.CStatements(
        [
            call,
            structured_c.CReturn(
                structured_c.CFunctionCall(
                    "loadprog",
                    SimpleNamespace(name="loadprog"),
                    [
                        structured_c.CVariable(SimStackVariable(-4, 2, base="bp", region=0x1000), codegen=codegen),
                        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=statements,
        variables_in_use={},
    )

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    assert isinstance(codegen.cfunc.statements.statements[0], structured_c.CReturn)


def test_prune_dead_local_assignments_matches_normalized_call_signature():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    shared_var = SimStackVariable(-4, 2, base="bp", name="arg", region=0x1000)
    call = structured_c.CFunctionCall(
        "loadprog",
        SimpleNamespace(name="loadprog"),
        [
            structured_c.CTypeCast(
                SimTypeShort(False),
                SimTypeShort(False),
                structured_c.CVariable(shared_var, codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    statements = structured_c.CStatements(
        [
            call,
            structured_c.CReturn(
                structured_c.CFunctionCall(
                    "loadprog",
                    SimpleNamespace(name="loadprog"),
                    [
                        structured_c.CVariable(shared_var, codegen=codegen),
                        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=statements, variables_in_use={})

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    assert isinstance(codegen.cfunc.statements.statements[0], structured_c.CReturn)


def test_resolve_stack_cvar_at_offset_prefers_canonical_argument_storage():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False
            self.cfunc = SimpleNamespace(arg_list=[], variables_in_use={})

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    arg_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    alias_var = SimStackVariable(4, 2, base="bp", name="s_3", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    alias_cvar = structured_c.CVariable(alias_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.arg_list = [arg_cvar]
    codegen.cfunc.variables_in_use = {
        arg_var: arg_cvar,
        alias_var: alias_cvar,
    }

    resolved = decompile._resolve_stack_cvar_at_offset(codegen, 4)
    canonical = decompile._canonicalize_stack_cvar_expr(alias_cvar, codegen)

    assert resolved is arg_cvar
    assert canonical is arg_cvar


def test_collapse_annotated_stack_aliases_text_prefers_argument_name():
    c_text = (
        "unsigned short _strlen(unsigned short s)\n"
        "{\n"
        "    unsigned short n;  // [bp-0x2] n\n"
        "    unsigned short s_3; // [bp+0x4] s\n"
        "\n"
        "    n = 0;\n"
        "    while (*s_3++)\n"
        "        n += 1;\n"
        "    return (n);\n"
        "}\n"
    )

    collapsed = decompile._collapse_annotated_stack_aliases_text(c_text)

    assert "unsigned short s_3;" not in collapsed
    assert "while (*s++)" in collapsed
    assert "n += 1;" in collapsed
    assert "if (!(s + 1))" not in collapsed


def test_simplify_x86_16_stack_byte_pointers_rewrites_segment_math():
    c_text = "    *((unsigned short *)(ds * 16 + (unsigned int)cs_2)) = ir_3_2;\n"

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    *((unsigned short far *)MK_FP(ds, (unsigned int)cs_2)) = ir_3_2;\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_bda_linear_constants():
    c_text = "    *((unsigned short *)1047) = es;\n"

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    *((unsigned short far *)MK_FP(0x40, 0x17)) = es;\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_byte_walk_loop():
    c_text = (
        "    while (true)\n"
        "    {\n"
        "        ir_3 = s;\n"
        "        ir_4 = s;\n"
        "        s = (ir_3 | ir_4 * 0x100) + 1 >> 8;\n"
        "        if (!(s + 1))\n"
        "            break;\n"
        "        ir_8 = n;\n"
        "        ir_9 = n;\n"
        "        n = (ir_8 | ir_9 * 0x100) + 1 >> 8;\n"
        "    }\n"
    )

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    while (*s++)\n"
        "    {\n"
        "        n += 1;\n"
        "    }\n\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_ss_stack_alias_chains():
    c_text = (
        "    vvar_20 = (int)&(&s_a)[2];\n"
        "    *((unsigned short *)((ss << 4) + vvar_20 - 2)) = 0;\n"
        "    vvar_24 = vvar_20 - 2 + -2;\n"
        "    *((char *)((ss << 4) + vvar_24)) = cs;\n"
        "    *((char *)(vvar_24 + 1)) = cs >> 8;\n"
    )

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    vvar_20 = (int)&(&s_a)[2];\n"
        "    *((unsigned short *)&s_a) = 0;\n"
        "    vvar_24 = vvar_20 - 2 + -2;\n"
        "    *((char *)(&s_a - 2)) = cs;\n"
        "    *((char *)(&s_a - 1)) = cs >> 8;\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_segmented_byte_pair_loads():
    c_text = (
        "    x = (*((char *)((ds << 4) + 2978)) | *((char *)((ds << 4) + 2978 + 1)) << 8) - 1;\n"
        "    y = (*((char *)((ss << 4) + (unsigned int)&s_4)) | *((char *)((ss << 4) + (unsigned int)&s_4 + 1)) << 8) + 1;\n"
    )

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    x = *((unsigned short far *)MK_FP(ds, 2978)) - 1;\n"
        "    y = *((unsigned short *)&s_4) + 1;\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_direct_ss_local_stores():
    c_text = (
        "    *((char *)((ss << 4) + (unsigned int)&s_4 + 1)) = *((unsigned short *)&s_4) + 1 >> 8;\n"
        "    *((unsigned short *)((ss << 4) + (unsigned int)&s_4 - 2)) = 0;\n"
    )

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    *((char *)(&s_4 + 1)) = *((unsigned short *)&s_4) + 1 >> 8;\n"
        "    *((unsigned short *)(&s_4 - 2)) = 0;\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_direct_ss_local_exprs_inside_for_header():
    c_text = (
        "    for (; ; *((char *)((ss << 4) + (unsigned int)&s_4 + 1)) = *((unsigned short *)&s_4) + 1 >> 8)\n"
        "    {\n"
        "    }\n"
    )

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    for (; ; *((char *)(&s_4 + 1)) = *((unsigned short *)&s_4) + 1 >> 8)\n"
        "    {\n"
        "    }\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_indexed_ss_local_store_shape():
    c_text = (
        "    (&s_8)[16 * ss] = cs;\n"
        "    (&s_7)[16 * ss] = cs >> 8;\n"
    )

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    *((char *)&s_8) = cs;\n"
        "    *((char *)&s_7) = cs >> 8;\n"
    )


def test_decompiler_return_compat_falls_back_when_return_expression_is_unsupported():
    original_handle_return = ReturnMaker._handle_Return
    calls: list[tuple[int, object, object]] = []

    def fake_handle_return(self, stmt_idx, stmt, block):
        calls.append((stmt_idx, stmt, block))
        return "orig"

    try:
        ReturnMaker._handle_Return = fake_handle_return
        apply_x86_16_decompiler_return_compatibility()

        fake_stmt = SimpleNamespace(ret_exprs=[], copy=lambda: SimpleNamespace(ret_exprs=[]), tags={"ins_addr": 0x1000})
        fake_block = SimpleNamespace(statements=[fake_stmt], copy=lambda **kwargs: SimpleNamespace(**kwargs))
        fake_cc = SimpleNamespace(return_val=lambda _returnty: object())
        fake_function = SimpleNamespace(prototype=SimpleNamespace(returnty=SimpleNamespace()), calling_convention=fake_cc)
        fake_self = SimpleNamespace(function=fake_function, arch=SimpleNamespace(byte_width=2), _next_atom=lambda: 1, _new_block=None)

        result = ReturnMaker._handle_Return(fake_self, 0, fake_stmt, fake_block)

        assert result == "orig"
        assert calls
        assert fake_self._new_block is None
    finally:
        ReturnMaker._handle_Return = original_handle_return


def test_duplicate_word_increment_shift_expr_collapses_to_word_increment():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    source_var = SimStackVariable(4, 2, base="bp", name="s_3", region=0x1000)
    low_tmp_var = SimStackVariable(6, 1, base="bp", name="ir_3", region=0x1000)
    high_tmp_var = SimStackVariable(8, 1, base="bp", name="ir_4", region=0x1000)

    source_cvar = structured_c.CVariable(source_var, variable_type=SimTypeShort(False), codegen=codegen)
    low_tmp = structured_c.CVariable(low_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_tmp = structured_c.CVariable(high_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)

    alias_map = {
        id(low_tmp_var): source_cvar,
        id(high_tmp_var): source_cvar,
    }

    def resolve_copy_alias_expr(expr):
        variable = getattr(expr, "variable", None)
        if variable is None:
            return expr
        return alias_map.get(id(variable), expr)

    expr = structured_c.CBinaryOp(
        "Shr",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Or",
                low_tmp,
                structured_c.CBinaryOp(
                    "Mul",
                    high_tmp,
                    structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    matched = decompile._match_duplicate_word_increment_shift_expr(expr, resolve_copy_alias_expr, codegen)

    assert isinstance(matched, structured_c.CBinaryOp)
    assert matched.op == "Add"
    assert matched.lhs.variable is source_var
    assert matched.rhs.value == 1


def test_duplicate_word_increment_shift_expr_rejects_mismatched_storage_aliases():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    left_var = SimStackVariable(4, 2, base="bp", name="left", region=0x1000)
    right_var = SimStackVariable(6, 2, base="bp", name="right", region=0x1000)
    low_tmp_var = SimStackVariable(8, 1, base="bp", name="ir_3", region=0x1000)
    high_tmp_var = SimStackVariable(10, 1, base="bp", name="ir_4", region=0x1000)

    left_cvar = structured_c.CVariable(left_var, variable_type=SimTypeShort(False), codegen=codegen)
    right_cvar = structured_c.CVariable(right_var, variable_type=SimTypeShort(False), codegen=codegen)
    low_tmp = structured_c.CVariable(low_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_tmp = structured_c.CVariable(high_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)

    alias_map = {
        id(low_tmp_var): left_cvar,
        id(high_tmp_var): right_cvar,
    }

    def resolve_copy_alias_expr(expr):
        variable = getattr(expr, "variable", None)
        if variable is None:
            return expr
        return alias_map.get(id(variable), expr)

    expr = structured_c.CBinaryOp(
        "Shr",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Or",
                low_tmp,
                structured_c.CBinaryOp(
                    "Mul",
                    high_tmp,
                    structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    matched = decompile._match_duplicate_word_increment_shift_expr(expr, resolve_copy_alias_expr, codegen)

    assert matched is None


def test_adjacent_byte_pair_alias_seed_widens_into_one_word():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    low_tmp_var = SimStackVariable(6, 1, base="bp", name="ir_3", region=0x1000)
    high_tmp_var = SimStackVariable(8, 1, base="bp", name="ir_4", region=0x1000)
    low_tmp = structured_c.CVariable(low_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_tmp = structured_c.CVariable(high_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)

    low_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            None,
            SimTypeShort(False),
            structured_c.CConstant(0x2000, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    object.__setattr__(low_load, "_type", SimTypeChar())
    high_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            None,
            SimTypeShort(False),
            structured_c.CConstant(0x2001, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    object.__setattr__(high_load, "_type", SimTypeChar())

    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(low_tmp, low_load, codegen=codegen),
                structured_c.CAssignment(high_tmp, high_load, codegen=codegen),
            ],
            codegen=codegen,
        ),
    )

    aliases = decompile._seed_adjacent_byte_pair_aliases(codegen.project, codegen)

    assert id(low_tmp_var) in aliases
    assert id(high_tmp_var) in aliases
    assert decompile._same_c_expression(aliases[id(low_tmp_var)], aliases[id(high_tmp_var)])
    assert isinstance(aliases[id(low_tmp_var)], structured_c.CUnaryOp)
    assert getattr(aliases[id(low_tmp_var)], "op", None) == "Dereference"

    def resolve_copy_alias_expr(expr):
        variable = getattr(expr, "variable", None)
        if variable is None:
            return expr
        return aliases.get(id(variable), expr)

    expr = structured_c.CBinaryOp(
        "Shr",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Or",
                low_tmp,
                structured_c.CBinaryOp(
                    "Mul",
                    high_tmp,
                    structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    matched = decompile._match_duplicate_word_increment_shift_expr(expr, resolve_copy_alias_expr, codegen)

    assert isinstance(matched, structured_c.CBinaryOp)
    assert matched.op == "Add"
    assert isinstance(matched.lhs, structured_c.CUnaryOp)
    assert getattr(matched.lhs, "op", None) == "Dereference"
    assert matched.rhs.value == 1


def test_adjacent_byte_pair_alias_seed_preserves_dereferenced_source_evidence():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    low_tmp_var = SimStackVariable(6, 1, base="bp", name="ir_3", region=0x1000)
    high_tmp_var = SimStackVariable(8, 1, base="bp", name="ir_4", region=0x1000)
    source_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    low_tmp = structured_c.CVariable(low_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_tmp = structured_c.CVariable(high_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)
    source_cvar = structured_c.CVariable(source_var, variable_type=SimTypeShort(False), codegen=codegen)

    low_load = structured_c.CUnaryOp("Dereference", structured_c.CTypeCast(None, SimTypeShort(False), source_cvar, codegen=codegen), codegen=codegen)
    object.__setattr__(low_load, "_type", SimTypeChar())
    high_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            None,
            SimTypeShort(False),
            structured_c.CBinaryOp("Add", source_cvar, structured_c.CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    object.__setattr__(high_load, "_type", SimTypeChar())
    deref_source = structured_c.CUnaryOp("Dereference", source_cvar, codegen=codegen)

    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(low_tmp, low_load, codegen=codegen),
                structured_c.CAssignment(high_tmp, high_load, codegen=codegen),
                structured_c.CAssignment(source_cvar, deref_source, codegen=codegen),
            ],
            codegen=codegen,
        ),
    )

    aliases = decompile._seed_adjacent_byte_pair_aliases(codegen.project, codegen)

    assert not (
        id(low_tmp_var) in aliases
        and id(high_tmp_var) in aliases
        and decompile._same_c_expression(aliases[id(low_tmp_var)], aliases[id(high_tmp_var)])
    )


def test_linear_recurrence_keeps_dereference_based_byte_pair_aliases():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    low_tmp_var = SimRegisterVariable(10, 1, name="ir_3")
    high_tmp_var = SimRegisterVariable(12, 1, name="ir_4")
    recur_var = SimRegisterVariable(14, 2, name="ir_5")
    source_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)

    low_tmp = structured_c.CVariable(low_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_tmp = structured_c.CVariable(high_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)
    recur_cvar = structured_c.CVariable(recur_var, variable_type=SimTypeShort(False), codegen=codegen)
    source_cvar = structured_c.CVariable(source_var, variable_type=SimTypeShort(False), codegen=codegen)

    low_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(None, SimTypeShort(False), source_cvar, codegen=codegen),
        codegen=codegen,
    )
    object.__setattr__(low_load, "_type", SimTypeChar())
    high_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            None,
            SimTypeShort(False),
            structured_c.CBinaryOp(
                "Add",
                source_cvar,
                structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    object.__setattr__(high_load, "_type", SimTypeChar())

    widened = structured_c.CBinaryOp(
        "Shr",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Or",
                low_tmp,
                structured_c.CBinaryOp(
                    "Mul",
                    high_tmp,
                    structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(low_tmp, low_load, codegen=codegen),
                structured_c.CAssignment(high_tmp, high_load, codegen=codegen),
                structured_c.CAssignment(recur_cvar, widened, codegen=codegen),
                structured_c.CIfElse(
                    [
                        (
                            structured_c.CUnaryOp("Not", recur_cvar, codegen=codegen),
                            structured_c.CStatements([], addr=0x1000, codegen=codegen),
                        )
                    ],
                    codegen=codegen,
                ),
            ],
            addr=0x1000,
            codegen=codegen,
        ),
    )

    decompile._coalesce_linear_recurrence_statements(codegen.project, codegen)

    recur_stmt = codegen.cfunc.statements.statements[2]
    assert isinstance(recur_stmt, structured_c.CAssignment)
    assert isinstance(recur_stmt.rhs, structured_c.CBinaryOp)
    assert recur_stmt.rhs.op == "Add"
    assert isinstance(recur_stmt.rhs.lhs, structured_c.CUnaryOp)
    assert getattr(recur_stmt.rhs.lhs, "op", None) == "Dereference"
    rewritten_if = codegen.cfunc.statements.statements[3]
    assert isinstance(rewritten_if, structured_c.CIfElse)
    rewritten_cond = rewritten_if.condition_and_nodes[0][0]
    assert isinstance(rewritten_cond, structured_c.CUnaryOp)
    assert rewritten_cond.op == "Not"
    # operand may be CBinaryOp (pre-lowering) or CVariable (post-lowering via
    # stack alias resolution). Both shapes preserve the recurrence evidence.
    assert isinstance(rewritten_cond.operand, (structured_c.CBinaryOp, structured_c.CVariable))


def test_linear_recurrence_preserves_stack_byte_pair_evidence_for_assignments_and_conditions():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    base_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    temp_var = SimRegisterVariable(10, 2, name="ir_3")
    base_cvar = structured_c.CVariable(base_var, variable_type=SimTypeShort(False), codegen=codegen)
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False), codegen=codegen)
    widened_word = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Or",
            base_cvar,
            structured_c.CBinaryOp(
                "Mul",
                base_cvar,
                structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    condition = structured_c.CUnaryOp("Not", widened_word, codegen=codegen)
    body = structured_c.CStatements([], addr=0x1000, codegen=codegen)
    if_stmt = structured_c.CIfElse([(condition, body)], codegen=codegen)

    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(temp_cvar, widened_word, codegen=codegen),
                if_stmt,
            ],
            addr=0x1000,
            codegen=codegen,
        ),
    )

    changed = decompile._coalesce_linear_recurrence_statements(codegen.project, codegen)

    assert not changed
    first_stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(first_stmt, structured_c.CAssignment)
    assert isinstance(first_stmt.rhs, structured_c.CBinaryOp)
    assert first_stmt.rhs.op == "Add"
    assert isinstance(first_stmt.rhs.lhs, structured_c.CBinaryOp)
    assert first_stmt.rhs.lhs.op == "Or"
    assert first_stmt.rhs.rhs.value == 1
    rewritten_if = codegen.cfunc.statements.statements[1]
    assert isinstance(rewritten_if, structured_c.CIfElse)
    rewritten_cond = rewritten_if.condition_and_nodes[0][0]
    assert isinstance(rewritten_cond, structured_c.CUnaryOp)
    assert rewritten_cond.op == "Not"
    assert isinstance(rewritten_cond.operand, structured_c.CBinaryOp)
    assert rewritten_cond.operand.op == "Add"
    assert isinstance(rewritten_cond.operand.lhs, structured_c.CBinaryOp)
    assert rewritten_cond.operand.lhs.op == "Or"
    assert rewritten_cond.operand.rhs.value == 1


def test_linear_recurrence_refuses_to_linearize_loaded_byte_value_back_into_ds_address():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    ds_offset, ds_size = codegen.project.arch.registers["ds"]
    ds_var = SimRegisterVariable(ds_offset, ds_size, name="ds")
    temp_var = SimRegisterVariable(14, 2, name="vvar_173")

    ds_cvar = structured_c.CVariable(ds_var, variable_type=SimTypeShort(False), codegen=codegen)
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False), codegen=codegen)
    addr_expr = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Shl",
            ds_cvar,
            structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CConstant(2987, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    byte_deref = structured_c.CUnaryOp("Dereference", addr_expr, codegen=codegen)
    object.__setattr__(byte_deref, "_type", SimTypeChar())

    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(
                    temp_cvar,
                    structured_c.CBinaryOp(
                        "Add",
                        byte_deref,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CAssignment(
                    byte_deref,
                    structured_c.CBinaryOp(
                        "Sub",
                        temp_cvar,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
            ],
            addr=0x1000,
            codegen=codegen,
        ),
    )

    changed = decompile._coalesce_linear_recurrence_statements(codegen.project, codegen)

    assert changed is False
    store_stmt = codegen.cfunc.statements.statements[1]
    assert isinstance(store_stmt, structured_c.CAssignment)
    assert isinstance(store_stmt.rhs, structured_c.CBinaryOp)
    assert store_stmt.rhs.op == "Sub"
    assert isinstance(store_stmt.rhs.lhs, structured_c.CVariable)
    assert getattr(store_stmt.rhs.lhs, "variable", None) is temp_var


def test_structured_simplifier_preserves_adjacent_ds_byte_loads_and_word_increment_value():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False
            self.stmt_comments = {}
            self.expr_comments = {}
            self.display_vvar_ids = False
            self.cfunc = SimpleNamespace(
                addr=0x10CE0,
                arg_list=(),
                sort_local_vars=lambda: None,
                unified_local_vars={},
                variables_in_use={},
            )

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    ds_offset, ds_size = codegen.project.arch.registers["ds"]
    ds_var = SimRegisterVariable(ds_offset, ds_size, name="ds")
    low_temp_var = SimRegisterVariable(1, 1, name="ir_10")
    high_temp_var = SimRegisterVariable(2, 1, name="ir_11")

    def ds_linear_expr():
        return structured_c.CBinaryOp(
            "Shl",
            structured_c.CVariable(ds_var, variable_type=SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def ds_addr(offset: int):
        return structured_c.CBinaryOp(
            "Add",
            ds_linear_expr(),
            structured_c.CConstant(offset, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def deref(addr_expr, type_):
        node = structured_c.CUnaryOp("Dereference", addr_expr, codegen=codegen)
        object.__setattr__(node, "_type", type_)
        return node

    low_load = structured_c.CAssignment(
        structured_c.CVariable(low_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
        deref(ds_addr(2986), SimTypeChar(False)),
        codegen=codegen,
    )
    high_load = structured_c.CAssignment(
        structured_c.CVariable(high_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
        deref(ds_addr(2987), SimTypeChar(False)),
        codegen=codegen,
    )
    widened_increment = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Or",
            structured_c.CVariable(low_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
            structured_c.CBinaryOp(
                "Shl",
                structured_c.CVariable(high_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
                structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    word_store = structured_c.CAssignment(
        deref(ds_addr(2986), SimTypeShort(False)),
        widened_increment,
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [low_load, high_load, word_store],
        addr=0x10CE0,
        codegen=codegen,
    )

    changed = decompile._simplify_structured_c_expressions(codegen)

    assert changed is True

    rewritten_low_load = codegen.cfunc.statements.statements[0]
    rewritten_high_load = codegen.cfunc.statements.statements[1]
    rewritten_store = codegen.cfunc.statements.statements[2]

    assert isinstance(rewritten_low_load.rhs, structured_c.CUnaryOp)
    assert isinstance(rewritten_high_load.rhs, structured_c.CUnaryOp)
    assert rewritten_low_load.rhs.operand.rhs.value == 2986
    assert rewritten_high_load.rhs.operand.rhs.value == 2987

    assert isinstance(rewritten_store.rhs, structured_c.CBinaryOp)
    assert rewritten_store.rhs.op == "Add"
    assert isinstance(rewritten_store.rhs.lhs, structured_c.CBinaryOp)
    assert rewritten_store.rhs.lhs.op == "Or"
    assert rewritten_store.rhs.rhs.value == 1


def test_structured_simplifier_refuses_bare_word_global_promotion_for_adjacent_memory_bytes():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False
            self.stmt_comments = {}
            self.expr_comments = {}
            self.display_vvar_ids = False
            self.cfunc = SimpleNamespace(
                addr=0x10808,
                arg_list=(),
                sort_local_vars=lambda: None,
                unified_local_vars={},
                variables_in_use={},
            )

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    low_global = structured_c.CVariable(
        SimMemoryVariable(0x0BA4, 1, name="g_0BA4", region=0x10808),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    high_global = structured_c.CVariable(
        SimMemoryVariable(0x0BA5, 1, name="g_0BA5", region=0x10808),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )

    expr = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Or",
            low_global,
            structured_c.CBinaryOp(
                "Shl",
                high_global,
                structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = expr

    changed = decompile._simplify_structured_c_expressions(codegen)

    assert changed is True
    result = codegen.cfunc.statements
    assert isinstance(result, structured_c.CBinaryOp)
    assert result.op == "Add"
    assert isinstance(result.lhs, structured_c.CBinaryOp)
    assert result.lhs.op == "Or"
    assert isinstance(result.lhs.lhs, structured_c.CVariable)
    assert isinstance(result.lhs.lhs.variable, SimMemoryVariable)
    assert result.lhs.lhs.variable.size == 1


def test_structured_simplifier_keeps_dereference_backed_temp_widening_honest():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False
            self.stmt_comments = {}
            self.expr_comments = {}
            self.display_vvar_ids = False
            self.cfunc = SimpleNamespace(
                addr=0x10808,
                arg_list=(),
                sort_local_vars=lambda: None,
                unified_local_vars={},
                variables_in_use={},
            )

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    ds_offset, ds_size = codegen.project.arch.registers["ds"]
    ds_var = SimRegisterVariable(ds_offset, ds_size, name="ds")
    low_temp_var = SimRegisterVariable(101, 1, name="ir_8")
    high_temp_var = SimRegisterVariable(102, 1, name="ir_9")

    def ds_linear_expr():
        return structured_c.CBinaryOp(
            "Shl",
            structured_c.CVariable(ds_var, variable_type=SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def ds_addr(offset: int):
        return structured_c.CBinaryOp(
            "Add",
            ds_linear_expr(),
            structured_c.CConstant(offset, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def ds_addr_plus_one(offset: int):
        return structured_c.CBinaryOp(
            "Add",
            ds_addr(offset),
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def deref(addr_expr, type_):
        node = structured_c.CUnaryOp("Dereference", addr_expr, codegen=codegen)
        object.__setattr__(node, "_type", type_)
        return node

    low_load = structured_c.CAssignment(
        structured_c.CVariable(low_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
        deref(ds_addr(2980), SimTypeChar(False)),
        codegen=codegen,
    )
    high_load = structured_c.CAssignment(
        structured_c.CVariable(high_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
        deref(ds_addr_plus_one(2980), SimTypeChar(False)),
        codegen=codegen,
    )
    widened_increment = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Or",
            structured_c.CVariable(low_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
            structured_c.CBinaryOp(
                "Shl",
                structured_c.CVariable(high_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
                structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    word_store = structured_c.CAssignment(
        deref(ds_addr(2980), SimTypeShort(False)),
        widened_increment,
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [low_load, high_load, word_store],
        addr=0x10808,
        codegen=codegen,
    )

    changed = decompile._simplify_structured_c_expressions(codegen)

    assert changed is True
    rewritten_store = codegen.cfunc.statements.statements[2]
    assert isinstance(rewritten_store.rhs, structured_c.CBinaryOp)
    assert rewritten_store.rhs.op == "Add"
    assert isinstance(rewritten_store.rhs.lhs, structured_c.CBinaryOp)
    assert rewritten_store.rhs.lhs.op == "Or"
    assert isinstance(rewritten_store.rhs.lhs.lhs, structured_c.CVariable)
    assert rewritten_store.rhs.lhs.lhs.variable is low_temp_var
    assert rewritten_store.rhs.rhs.value == 1


def test_structured_simplifier_does_not_rewrite_inside_dereference_address_subtrees():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False
            self.stmt_comments = {}
            self.expr_comments = {}
            self.display_vvar_ids = False
            self.cfunc = SimpleNamespace(
                addr=0x10808,
                arg_list=(),
                sort_local_vars=lambda: None,
                unified_local_vars={},
                variables_in_use={},
            )

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    ds_offset, ds_size = codegen.project.arch.registers["ds"]
    ds_var = SimRegisterVariable(ds_offset, ds_size, name="ds")
    row_var = SimStackVariable(2, 2, base="bp", name="s_2", region=0x10808)
    ax_var = SimRegisterVariable(120, 2, name="ax_3")
    bx_var = SimRegisterVariable(122, 2, name="bx")

    def cvar(var, type_=None):
        return structured_c.CVariable(var, variable_type=type_, codegen=codegen)

    def const(value):
        return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)

    def ds_linear():
        return structured_c.CBinaryOp("Shl", cvar(ds_var, SimTypeShort(False)), const(4), codegen=codegen)

    def row_index():
        return structured_c.CBinaryOp("Shl", cvar(row_var, SimTypeShort(False)), const(1), codegen=codegen)

    def ds_indexed(offset: int):
        return structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp("Add", ds_linear(), const(offset), codegen=codegen),
            row_index(),
            codegen=codegen,
        )

    def deref(addr_expr, type_):
        node = structured_c.CUnaryOp("Dereference", addr_expr, codegen=codegen)
        object.__setattr__(node, "_type", type_)
        return node

    ax_load = structured_c.CAssignment(
        cvar(ax_var, SimTypeShort(False)),
        structured_c.CBinaryOp(
            "Or",
            deref(ds_indexed(2890), SimTypeChar(False)),
            structured_c.CBinaryOp(
                "Shl",
                deref(
                    structured_c.CBinaryOp("Add", ds_indexed(2890), const(1), codegen=codegen),
                    SimTypeChar(False),
                ),
                const(8),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    bx_assign = structured_c.CAssignment(cvar(bx_var, SimTypeShort(False)), row_index(), codegen=codegen)
    word_store = structured_c.CAssignment(
        deref(
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp("Add", ds_linear(), const(2892), codegen=codegen),
                cvar(bx_var, SimTypeShort(False)),
                codegen=codegen,
            ),
            SimTypeShort(False),
        ),
        structured_c.CBinaryOp(
            "Or",
            deref(ds_indexed(2890), SimTypeChar(False)),
            structured_c.CBinaryOp(
                "Shl",
                deref(
                    structured_c.CBinaryOp("Add", ds_indexed(2890), const(1), codegen=codegen),
                    SimTypeChar(False),
                ),
                const(8),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([ax_load, bx_assign, word_store], addr=0x10808, codegen=codegen)

    changed = decompile._simplify_structured_c_expressions(codegen)

    assert changed is True
    rewritten_load = codegen.cfunc.statements.statements[0]
    rewritten_store = codegen.cfunc.statements.statements[2]

    assert rewritten_load.rhs.lhs.operand.rhs.value == 2890
    assert rewritten_load.rhs.rhs.lhs.operand.lhs.rhs.value == 2890
    assert rewritten_store.lhs.operand.lhs.rhs.value == 2892
    assert rewritten_store.rhs.lhs.operand.rhs.value == 2890
    assert rewritten_store.rhs.rhs.lhs.operand.lhs.rhs.value == 2890


def test_linear_recurrence_assignment_rewrite_refuses_non_dereference_algebraic_shape():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    base_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    temp_var = SimRegisterVariable(10, 2, name="ir_9")
    base_cvar = structured_c.CVariable(base_var, variable_type=SimTypeShort(False), codegen=codegen)
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False), codegen=codegen)
    widened_word = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Or",
            base_cvar,
            structured_c.CBinaryOp(
                "Mul",
                base_cvar,
                structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements(
            [structured_c.CAssignment(temp_cvar, widened_word, codegen=codegen)],
            addr=0x1000,
            codegen=codegen,
        ),
    )

    changed = decompile._coalesce_linear_recurrence_statements(codegen.project, codegen)

    assert changed is False
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, structured_c.CAssignment)
    assert isinstance(stmt.rhs, structured_c.CBinaryOp)
    assert stmt.rhs.op == "Add"
    assert isinstance(stmt.rhs.lhs, structured_c.CBinaryOp)
    assert stmt.rhs.lhs.op == "Or"
    assert stmt.rhs.rhs.value == 1


def test_linear_recurrence_condition_rewrite_refuses_non_dereference_algebraic_shape():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    base_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    base_cvar = structured_c.CVariable(base_var, variable_type=SimTypeShort(False), codegen=codegen)
    widened_word = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Or",
            base_cvar,
            structured_c.CBinaryOp(
                "Mul",
                base_cvar,
                structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    while_stmt = structured_c.CWhileLoop(
        structured_c.CUnaryOp("Not", widened_word, codegen=codegen),
        structured_c.CStatements([], addr=0x1000, codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements([while_stmt], addr=0x1000, codegen=codegen),
    )

    changed = decompile._coalesce_linear_recurrence_statements(codegen.project, codegen)

    assert changed is False
    rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten, structured_c.CWhileLoop)
    assert isinstance(rewritten.condition, structured_c.CUnaryOp)
    assert rewritten.condition.op == "Not"
    assert isinstance(rewritten.condition.operand, structured_c.CBinaryOp)
    assert rewritten.condition.operand.op == "Add"
    assert isinstance(rewritten.condition.operand.lhs, structured_c.CBinaryOp)
    assert rewritten.condition.operand.lhs.op == "Or"
    assert rewritten.condition.operand.rhs.value == 1


def test_linear_recurrence_tolerates_self_referential_condition_nodes():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    temp_var = SimRegisterVariable(10, 2, name="ir_7")
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False), codegen=codegen)
    cyclic_cond = structured_c.CUnaryOp("Not", temp_cvar, codegen=codegen)
    cyclic_cond.operand = cyclic_cond

    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements(
            [
                structured_c.CIfElse(
                    [(cyclic_cond, structured_c.CStatements([], addr=0x1000, codegen=codegen))],
                    codegen=codegen,
                )
            ],
            addr=0x1000,
            codegen=codegen,
        ),
    )

    decompile._coalesce_linear_recurrence_statements(codegen.project, codegen)
    rewritten_if = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten_if, structured_c.CIfElse)
    assert rewritten_if.condition_and_nodes[0][0] is cyclic_cond


def test_canonicalize_stack_cvar_expr_prefers_annotated_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    arg_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    alias_var = SimStackVariable(4, 2, base="bp", name="s_3", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    alias_cvar = structured_c.CVariable(alias_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[arg_cvar],
        variables_in_use={
            arg_var: arg_cvar,
            alias_var: alias_cvar,
        },
    )

    expr = structured_c.CBinaryOp(
        "Add",
        alias_cvar,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert isinstance(canonical, structured_c.CBinaryOp)
    assert canonical.lhs.variable is arg_var
    assert canonical.rhs.value == 1
    assert decompile._canonicalize_stack_cvar_expr(alias_cvar, codegen).variable is arg_var


def test_canonicalize_stack_cvar_expr_rewrites_indexed_stack_reference_to_exact_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    base_var = SimStackVariable(-6, 1, base="bp", name="s_6", region=0x1000)
    target_var = SimStackVariable(2, 2, base="bp", name="wait_hi", region=0x1000)
    base_cvar = structured_c.CVariable(base_var, variable_type=SimTypeChar(False), codegen=codegen)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={
            base_var: base_cvar,
            target_var: target_cvar,
        },
    )

    expr = structured_c.CUnaryOp(
        "Reference",
        structured_c.CIndexedVariable(
            structured_c.CUnaryOp("Reference", base_cvar, codegen=codegen),
            structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert isinstance(canonical, structured_c.CUnaryOp)
    assert canonical.op == "Reference"
    assert isinstance(canonical.operand, structured_c.CVariable)
    assert canonical.operand.variable is target_var


def test_canonicalize_stack_cvar_expr_collapses_deref_of_reference_to_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    slot_var = SimStackVariable(0, 2, base="bp", name="goal", region=0x1000)
    slot_cvar = structured_c.CVariable(slot_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(arg_list=[], variables_in_use={slot_var: slot_cvar})

    expr = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CUnaryOp("Reference", slot_cvar, codegen=codegen),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert canonical is slot_cvar


def test_canonicalize_stack_cvar_expr_uses_stack_local_pointer_alias_for_indexed_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    alias_var = SimStackVariable(-2, 2, base="bp", name="s_2", region=0x1000)
    target_var = SimStackVariable(4, 2, base="bp", name="iRow1", region=0x1000)
    alias_cvar = structured_c.CVariable(alias_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[target_cvar],
        variables_in_use={
            alias_var: alias_cvar,
            target_var: target_cvar,
        },
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                alias_cvar,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CUnaryOp("Reference", alias_cvar, codegen=codegen),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        ],
        addr=0x1000,
        codegen=codegen,
    )

    expr = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CUnaryOp(
            "Reference",
            structured_c.CIndexedVariable(
                structured_c.CUnaryOp("Reference", alias_cvar, codegen=codegen),
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert canonical is target_cvar


def test_canonicalize_stack_cvar_expr_uses_vvar_pointer_alias_for_direct_indexed_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    base_var = SimStackVariable(-8, 1, base="bp", name="s_8", region=0x1000)
    target_var = SimStackVariable(-11, 1, base="bp", name="local_b", region=0x1000)
    carrier_var = SimRegisterVariable(8, 2, name="vvar_24")
    base_cvar = structured_c.CVariable(base_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeChar(False), codegen=codegen)
    carrier_cvar = structured_c.CVariable(carrier_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={
            base_var: base_cvar,
            target_var: target_cvar,
            carrier_var: carrier_cvar,
        },
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                carrier_cvar,
                structured_c.CBinaryOp(
                    "Sub",
                    structured_c.CUnaryOp("Reference", base_cvar, codegen=codegen),
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        ],
        addr=0x1000,
        codegen=codegen,
    )

    expr = structured_c.CIndexedVariable(
        carrier_cvar,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert canonical is target_cvar


def test_canonicalize_stack_cvar_expr_rewrites_ss_linear_deref_from_vvar_carrier():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    ss_off, ss_size = codegen.project.arch.registers["ss"]
    ss_var = SimRegisterVariable(ss_off, ss_size, name="ss")
    ss_cvar = structured_c.CVariable(ss_var, variable_type=SimTypeShort(False), codegen=codegen)
    carrier_var = SimRegisterVariable(0x20, 2, name="vvar_20")
    carrier_cvar = structured_c.CVariable(carrier_var, variable_type=SimTypeShort(False), codegen=codegen)
    base_var = SimStackVariable(-8, 2, base="bp", name="s_8", region=0x1000)
    base_cvar = structured_c.CVariable(base_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_var = SimStackVariable(-10, 2, base="bp", name="local_a", region=0x1000)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)

    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={
            ss_var: ss_cvar,
            carrier_var: carrier_cvar,
            base_var: base_cvar,
            target_var: target_cvar,
        },
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                carrier_cvar,
                structured_c.CUnaryOp("Reference", base_cvar, codegen=codegen),
                codegen=codegen,
            )
        ],
        addr=0x1000,
        codegen=codegen,
    )

    expr = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                ss_cvar,
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Sub",
                carrier_cvar,
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert isinstance(canonical, structured_c.CVariable)
    assert canonical.variable is target_var


def test_canonicalize_stack_cvar_expr_rewrites_plain_deref_from_vvar_carrier():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    carrier_var = SimRegisterVariable(0x20, 2, name="vvar_11")
    carrier_cvar = structured_c.CVariable(carrier_var, variable_type=SimTypeShort(False), codegen=codegen)
    base_var = SimStackVariable(-8, 2, base="bp", name="s_8", region=0x1000)
    base_cvar = structured_c.CVariable(base_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_var = SimStackVariable(-10, 2, base="bp", name="local_a", region=0x1000)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)

    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={
            carrier_var: carrier_cvar,
            base_var: base_cvar,
            target_var: target_cvar,
        },
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                carrier_cvar,
                structured_c.CUnaryOp("Reference", base_cvar, codegen=codegen),
                codegen=codegen,
            )
        ],
        addr=0x1000,
        codegen=codegen,
    )

    expr = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Sub",
            carrier_cvar,
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert isinstance(canonical, structured_c.CVariable)
    assert canonical.variable is target_var


def test_canonicalize_stack_cvar_expr_rewrites_indexed_stack_base_fake_variable_to_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    target_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x1000)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={target_var: target_cvar},
        unified_local_vars={},
    )
    codegen.cfunc.statements = structured_c.CStatements([], addr=0x1000, codegen=codegen)

    expr = structured_c.CIndexedVariable(
        structured_c.CBinaryOp(
            "Add",
            structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
            structured_c.CConstant(-6, SimTypeShort(True), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert canonical is target_cvar


def test_canonicalize_stack_cvar_expr_infers_bare_stack_base_bias_from_bp_slots():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    i_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x1000)
    i_parent_var = SimStackVariable(-2, 2, base="bp", name="iParent", region=0x1000)
    i_cvar = structured_c.CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    i_parent_cvar = structured_c.CVariable(i_parent_var, variable_type=SimTypeShort(False), codegen=codegen)
    expr_i = structured_c.CIndexedVariable(
        structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    expr_i_parent = structured_c.CIndexedVariable(
        structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
        structured_c.CConstant(6, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={
            i_var: i_cvar,
            i_parent_var: i_parent_cvar,
        },
        unified_local_vars={},
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(i_cvar, expr_i, codegen=codegen),
                structured_c.CAssignment(i_parent_cvar, expr_i_parent, codegen=codegen),
            ],
            addr=0x1000,
            codegen=codegen,
        ),
    )

    canonical_i = decompile._canonicalize_stack_cvar_expr(expr_i, codegen)
    canonical_i_parent = decompile._canonicalize_stack_cvar_expr(expr_i_parent, codegen)

    assert canonical_i is i_cvar
    assert canonical_i_parent is i_parent_cvar


def test_canonicalize_stack_cvar_expr_rewrites_deref_from_stack_base_fake_variable_to_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    target_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x1000)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={target_var: target_cvar},
        unified_local_vars={},
    )
    codegen.cfunc.statements = structured_c.CStatements([], addr=0x1000, codegen=codegen)

    expr = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
            structured_c.CConstant(-2, SimTypeShort(True), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert canonical is target_cvar


def test_canonicalize_stack_cvar_expr_rewrites_ss_linear_deref_from_stack_base_fake_variable_to_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    ss_off, ss_size = codegen.project.arch.registers["ss"]
    ss_var = SimRegisterVariable(ss_off, ss_size, name="ss")
    ss_cvar = structured_c.CVariable(ss_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x1000)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={ss_var: ss_cvar, target_var: target_cvar},
        unified_local_vars={},
    )
    codegen.cfunc.statements = structured_c.CStatements([], addr=0x1000, codegen=codegen)

    expr = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                ss_cvar,
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
                structured_c.CConstant(-2, SimTypeShort(True), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert canonical is target_cvar


def test_canonicalize_stack_cvar_expr_rewrites_ss_linear_deref_from_dirty_vvar_stack_alias():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    ss_off, ss_size = codegen.project.arch.registers["ss"]
    ss_var = SimRegisterVariable(ss_off, ss_size, name="ss")
    ss_cvar = structured_c.CVariable(ss_var, variable_type=SimTypeShort(False), codegen=codegen)
    carrier_var = SimRegisterVariable(8, 2, name="vvar_24")
    carrier_cvar = structured_c.CVariable(carrier_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x1000)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={ss_var: ss_cvar, carrier_var: carrier_cvar, target_var: target_cvar},
        unified_local_vars={},
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                carrier_cvar,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
                    structured_c.CConstant(-2, SimTypeShort(True), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        ],
        addr=0x1000,
        codegen=codegen,
    )

    expr = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                ss_cvar,
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CDirtyExpression(SimpleNamespace(varid=24, name="vvar_24"), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert canonical is target_cvar


def test_canonicalize_stack_cvar_expr_rewrites_arithmetic_from_dirty_vvar_stack_alias():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    ss_off, ss_size = codegen.project.arch.registers["ss"]
    ss_var = SimRegisterVariable(ss_off, ss_size, name="ss")
    ss_cvar = structured_c.CVariable(ss_var, variable_type=SimTypeShort(False), codegen=codegen)
    carrier_var = SimRegisterVariable(8, 2, name="vvar_24")
    carrier_cvar = structured_c.CVariable(carrier_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x1000)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={
            ss_var: ss_cvar,
            carrier_var: carrier_cvar,
            target_var: target_cvar,
        },
        unified_local_vars={},
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                carrier_cvar,
                target_cvar,
                codegen=codegen,
            )
        ],
        addr=0x1000,
        codegen=codegen,
    )

    expr = structured_c.CBinaryOp(
        "Sub",
        structured_c.CDirtyExpression(SimpleNamespace(varid=24, name="vvar_24"), codegen=codegen),
        structured_c.CConstant(4, SimTypeShort(True), codegen=codegen),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert isinstance(canonical, structured_c.CBinaryOp)
    assert isinstance(canonical.lhs, structured_c.CVariable)
    assert getattr(canonical.lhs, "name", None) == "i"


def test_materialize_missing_stack_local_declarations_adds_live_stack_slots():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    arg_var = SimStackVariable(2, 2, base="bp", name="arg", region=0x1000)
    local_var = SimStackVariable(4, 2, base="bp", name="local", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    local_cvar = structured_c.CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[SimpleNamespace(variable=arg_var)],
        statements=structured_c.CStatements([], codegen=codegen),
        unified_local_vars={},
        variables_in_use={
            arg_var: arg_cvar,
            local_var: local_cvar,
        },
        sort_local_vars=lambda: None,
    )

    changed = decompile._materialize_missing_stack_local_declarations(codegen)

    assert changed is True
    assert local_var in codegen.cfunc.unified_local_vars
    assert codegen.cfunc.unified_local_vars[local_var] == {(local_cvar, local_cvar.variable_type)}
    assert arg_var not in codegen.cfunc.unified_local_vars


def test_materialize_missing_stack_local_declarations_skips_arg_slot_aliases():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    arg_var = SimStackVariable(2, 2, base="bp", name="arg", region=0x1000)
    alias_var = SimStackVariable(2, 2, base="bp", name="s_3", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    alias_cvar = structured_c.CVariable(alias_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[SimpleNamespace(variable=arg_var)],
        statements=structured_c.CStatements([], codegen=codegen),
        unified_local_vars={},
        variables_in_use={
            arg_var: arg_cvar,
            alias_var: alias_cvar,
        },
        sort_local_vars=lambda: None,
    )

    changed = decompile._materialize_missing_stack_local_declarations(codegen)

    assert changed is False
    assert alias_var not in codegen.cfunc.unified_local_vars
    assert arg_var not in codegen.cfunc.unified_local_vars


def test_materialize_missing_stack_local_declarations_converts_stack_bp_placeholder_variable():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    placeholder_var = SimRegisterVariable(0, 2, name="<0x1000[is_1]|Stack bp-0x6, 1 B>")
    placeholder_cvar = structured_c.CVariable(placeholder_var, variable_type=SimTypeShort(False), codegen=codegen)
    stmt = structured_c.CAssignment(
        placeholder_cvar,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[],
        statements=structured_c.CStatements([stmt], codegen=codegen),
        body=None,
        unified_local_vars={},
        variables_in_use={
            placeholder_var: placeholder_cvar,
        },
        sort_local_vars=lambda: None,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_stack_local_declaration_candidates = {
        id(placeholder_var): (placeholder_var, placeholder_cvar),
    }

    changed = decompile._materialize_missing_stack_local_declarations(codegen)

    assert changed is True
    lhs = codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs.variable, SimStackVariable)
    assert lhs.variable.offset == -6
    assert lhs.variable.base == "bp"
    assert lhs.variable.size == 1
    assert lhs.variable in codegen.cfunc.variables_in_use
    assert lhs.variable in codegen.cfunc.unified_local_vars
    assert placeholder_var not in codegen.cfunc.variables_in_use


def test_binary_specific_annotations_apply_generic_metadata(monkeypatch):
    calls: list[dict[str, object]] = []

    def fake_apply(project, **kwargs):
        calls.append(kwargs)
        return True

    monkeypatch.setattr(decompile, "apply_x86_16_metadata_annotations", fake_apply)
    project = SimpleNamespace()
    lst_metadata = SimpleNamespace()
    cod_metadata = SimpleNamespace()
    synthetic_globals = {0x10: ("foo", 1)}

    changed = decompile._apply_binary_specific_annotations(
        project,
        Path("sample.cod"),
        lst_metadata,
        func_addr=0x1000,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
    )

    assert changed is True
    assert calls == [
        {
            "func_addr": 0x1000,
            "cod_metadata": cod_metadata,
            "lst_metadata": lst_metadata,
            "synthetic_globals": synthetic_globals,
        }
    ]


def test_tiny_wrapper_staging_locals_are_pruned_structurally():
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=None, variables_in_use={}, unified_local_vars={}),
        project=SimpleNamespace(arch=decompile.Arch86_16()),
        next_idx=lambda _name: 1,
    )

    source_value = decompile.structured_c.CVariable(
        decompile.SimStackVariable(4, 2, base="bp", name="path", region=0),
        variable_type=decompile.SimTypeShort(False),
        codegen=codegen,
    )
    staging_value = decompile.structured_c.CVariable(
        decompile.SimStackVariable(0, 2, base="bp", name="s_2", region=0),
        variable_type=decompile.SimTypeShort(False),
        codegen=codegen,
    )
    staging_mode = decompile.structured_c.CVariable(
        decompile.SimStackVariable(2, 2, base="bp", name="s_4", region=0),
        variable_type=decompile.SimTypeShort(False),
        codegen=codegen,
    )

    call = decompile.structured_c.CExpressionStatement(
        decompile.structured_c.CFunctionCall(
            "openFile",
            SimpleNamespace(name="openFile"),
            [staging_value, staging_mode],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = decompile.structured_c.CStatements(
        [
            decompile.structured_c.CAssignment(
                staging_value,
                decompile.structured_c.CConstant(0x1234, decompile.SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            decompile.structured_c.CAssignment(
                staging_mode,
                decompile.structured_c.CConstant(3, decompile.SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            decompile.structured_c.CAssignment(
                source_value,
                decompile.structured_c.CConstant(0x5678, decompile.SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            call,
        ],
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {
        staging_value.variable: SimpleNamespace(),
        staging_mode.variable: SimpleNamespace(),
        source_value.variable: SimpleNamespace(),
    }

    changed = decompile._prune_tiny_wrapper_staging_locals(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    assert isinstance(codegen.cfunc.statements.statements[0], decompile.structured_c.CAssignment)
    assert isinstance(codegen.cfunc.statements.statements[1], decompile.structured_c.CExpressionStatement)
    assert codegen.cfunc.statements.statements[1].expr.args[0].value == 0x1234
    assert codegen.cfunc.statements.statements[1].expr.args[1].value == 3
    assert staging_value.variable not in codegen.cfunc.variables_in_use
    assert staging_mode.variable not in codegen.cfunc.variables_in_use
