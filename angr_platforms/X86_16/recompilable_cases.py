from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final

__all__ = [
    "RecompilableSubsetCase",
    "describe_x86_16_recompilable_subset",
    "get_x86_16_recompilable_subset_cases",
]


_REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class RecompilableSubsetCase:
    name: str
    asm: str
    expected_kind: str
    note: str
    cod_path: Path | None = None
    proc_name: str | None = None
    proc_kind: str = "NEAR"
    expected_c_anchors: tuple[str, ...] = ()
    forbidden_c_anchors: tuple[str, ...] = ()


_RECOMPILABLE_SUBSET_CASES: Final[tuple[RecompilableSubsetCase, ...]] = (
    RecompilableSubsetCase(
        name="mov_add_ret",
        asm="mov ax,1; add ax,2; ret",
        expected_kind="trivial arithmetic",
        note="Minimal body that currently compiles to an empty translation unit body.",
    ),
    RecompilableSubsetCase(
        name="enter_stack",
        asm="enter 2, 0; mov word ptr [bp-2], 1; mov ax, [bp-2]; leave; ret",
        expected_kind="stack local",
        note="Preserves a stack local and compiles as syntax-valid C.",
    ),
    RecompilableSubsetCase(
        name="xor_ret",
        asm="xor ax,ax; ret",
        expected_kind="simple zeroing",
        note="A tiny zeroing body that decompiles to syntax-valid C.",
    ),
    RecompilableSubsetCase(
        name="push_pop_ret",
        asm="push ax; pop ax; ret",
        expected_kind="stack roundtrip",
        note="A tiny stack round-trip that remains syntax-valid after decompilation.",
    ),
    RecompilableSubsetCase(
        name="strlen_real",
        asm="",
        expected_kind="real recovered loop",
        note="Live repaired STRLEN.COD output for _strlen, used as a recompilation anchor.",
        cod_path=_REPO_ROOT / "cod" / "default" / "STRLEN.COD",
        proc_name="_strlen",
        expected_c_anchors=(
            "unsigned short _strlen(unsigned short *s)",
            "while (*s++)",
        ),
        forbidden_c_anchors=("unsigned short _strlen(unsigned short s)", "s_3"),
    ),
    RecompilableSubsetCase(
        name="byteops_real",
        asm="",
        expected_kind="real recovered COD main",
        note="Live repaired BYTEOPS.COD output for _main, used as a recompilation anchor.",
        cod_path=_REPO_ROOT / "cod" / "default" / "BYTEOPS.COD",
        proc_name="_main",
        expected_c_anchors=(
            "a = a - b;",
            "a = a * b;",
            "b = b / a;",
            "b = b % a;",
            "a = a << 5;",
            "b = b >> a;",
            'printf ("a = %d, b = %d\\n", a, b);',
        ),
        forbidden_c_anchors=("ax_", "cx_", 'printf ("a = %d, b = %d\n'),
    ),
    RecompilableSubsetCase(
        name="loadprog_real",
        asm="",
        expected_kind="real recovered DOS helper",
        note="Live repaired DOSFUNC.COD output for loadprog, used as a recompilation anchor.",
        cod_path=_REPO_ROOT / "cod" / "DOSFUNC.COD",
        proc_name="loadprog",
        expected_c_anchors=(
            "int loadprog(const char *file, unsigned short segment, unsigned short mode, const char *cmdline)",
            "rin.x.dx = (unsigned int)file;",
        ),
        forbidden_c_anchors=("file_2", "type_2", "ds * 16 +"),
    ),
    RecompilableSubsetCase(
        name="dos_loadOverlay_real",
        asm="",
        expected_kind="real recovered DOS helper",
        note="Live repaired DOSFUNC.COD output for _dos_loadOverlay, used as a recompilation anchor.",
        cod_path=_REPO_ROOT / "cod" / "DOSFUNC.COD",
        proc_name="_dos_loadOverlay",
        expected_c_anchors=(
            "int _dos_loadOverlay(const char *file, const unsigned short segment)",
            "return loadprog(file, segment, DOS_LOAD_OVL, NULL);",
        ),
        forbidden_c_anchors=("return;",),
    ),
    RecompilableSubsetCase(
        name="dos_loadProgram_real",
        asm="",
        expected_kind="real recovered DOS helper",
        note="Live repaired DOSFUNC.COD output for _dos_loadProgram, used as a recompilation anchor.",
        cod_path=_REPO_ROOT / "cod" / "DOSFUNC.COD",
        proc_name="_dos_loadProgram",
        expected_c_anchors=(
            "unsigned short _dos_loadProgram(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)",
            "if (err) return err;",
            "*cs = exeLoadParams.cs;",
            "*ss = exeLoadParams.ss;",
        ),
        forbidden_c_anchors=("ds * 16 +", "if ((err =", "*file ="),
    ),
    RecompilableSubsetCase(
        name="bios_clearkeyflags_real",
        asm="",
        expected_kind="real recovered BIOS helper",
        note="Live repaired BIOSFUNC.COD output for _bios_clearkeyflags, used as a recompilation anchor.",
        cod_path=_REPO_ROOT / "cod" / "BIOSFUNC.COD",
        proc_name="_bios_clearkeyflags",
        expected_c_anchors=(
            "void _bios_clearkeyflags(void)",
            "MK_FP(0x40, 0x17)",
        ),
        forbidden_c_anchors=("return;", "*((unsigned short *)1047)"),
    ),
)


def get_x86_16_recompilable_subset_cases() -> tuple[RecompilableSubsetCase, ...]:
    return _RECOMPILABLE_SUBSET_CASES


def describe_x86_16_recompilable_subset() -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "name": case.name,
            "expected_kind": case.expected_kind,
            "note": case.note,
        }
        for case in _RECOMPILABLE_SUBSET_CASES
    )
