from pathlib import Path

from angr_platforms.X86_16.recompilable_cases import get_x86_16_recompilable_subset_cases
from angr_platforms.X86_16.recompilable_checks import check_recompilable_c_text_shape, compile_recompilable_c_text
from angr_platforms.X86_16.recompilable_source_evidence import (
    build_recompilable_source_evidence_text,
    load_or_build_recompilable_source_evidence,
)


def _case_by_name(name: str):
    return next(case for case in get_x86_16_recompilable_subset_cases() if case.name == name)


def test_build_recompilable_source_evidence_text_for_loadprog_is_shape_ok_and_compilable():
    case = _case_by_name("loadprog_real")

    c_text = build_recompilable_source_evidence_text(case)

    assert c_text is not None
    shape = check_recompilable_c_text_shape(c_text, case)
    assert shape["shape_ok"] is True
    compile_proc = compile_recompilable_c_text(c_text)
    assert compile_proc.returncode == 0


def test_build_recompilable_source_evidence_text_for_dos_load_program_keeps_key_source_lines_and_compiles():
    case = _case_by_name("dos_loadProgram_real")

    c_text = build_recompilable_source_evidence_text(case)

    assert c_text is not None
    assert "unsigned short _dos_loadProgram(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)" in c_text
    assert "if (err) return err;" in c_text
    assert "*cs = exeLoadParams.cs;" in c_text
    assert "*ss = exeLoadParams.ss;" in c_text
    compile_proc = compile_recompilable_c_text(c_text)
    assert compile_proc.returncode == 0


def test_build_recompilable_source_evidence_text_for_strlen_is_shape_ok_and_compilable():
    case = _case_by_name("strlen_real")

    c_text = build_recompilable_source_evidence_text(case)

    assert c_text is not None
    assert "unsigned short _strlen(unsigned short *s)" in c_text
    shape = check_recompilable_c_text_shape(c_text, case)
    assert shape["shape_ok"] is True
    compile_proc = compile_recompilable_c_text(c_text)
    assert compile_proc.returncode == 0


def test_build_recompilable_source_evidence_text_for_bios_clearkeyflags_is_shape_ok_and_compilable():
    case = _case_by_name("bios_clearkeyflags_real")

    c_text = build_recompilable_source_evidence_text(case)

    assert c_text is not None
    assert "void _bios_clearkeyflags(void)" in c_text
    assert "unsigned short *bios_keyflags = MK_FP(0x40, 0x17);" in c_text
    shape = check_recompilable_c_text_shape(c_text, case)
    assert shape["shape_ok"] is True
    compile_proc = compile_recompilable_c_text(c_text)
    assert compile_proc.returncode == 0


def test_load_or_build_recompilable_source_evidence_persists_expected_path():
    case = _case_by_name("loadprog_real")

    c_text, evidence_path = load_or_build_recompilable_source_evidence(case)

    assert c_text is not None
    assert evidence_path == Path(".codex_automation/evidence_subset/cod/DOSFUNC.dec").resolve()
    assert evidence_path.exists()


def test_load_or_build_recompilable_source_evidence_persists_strlen_and_bios_paths():
    strlen_case = _case_by_name("strlen_real")
    bios_case = _case_by_name("bios_clearkeyflags_real")

    _, strlen_path = load_or_build_recompilable_source_evidence(strlen_case)
    _, bios_path = load_or_build_recompilable_source_evidence(bios_case)

    assert strlen_path == Path(".codex_automation/evidence_subset/cod/default/STRLEN.dec").resolve()
    assert bios_path == Path(".codex_automation/evidence_subset/cod/BIOSFUNC.dec").resolve()
    assert strlen_path.exists()
    assert bios_path.exists()
