from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from .recompilable_cases import RecompilableSubsetCase

__all__ = [
    "check_recompilable_c_text_shape",
    "compile_recompilable_c_text",
    "syntax_check_recompilable_c_text",
]


def _compat_syntax_prelude() -> str:
    return """#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef union REGS {
    struct {
        unsigned char al;
        unsigned char ah;
        unsigned char bl;
        unsigned char bh;
        unsigned char cl;
        unsigned char ch;
        unsigned char dl;
        unsigned char dh;
    } h;
    struct {
        unsigned short ax;
        unsigned short bx;
        unsigned short cx;
        unsigned short dx;
        unsigned short cflag;
        unsigned short si;
        unsigned short di;
        unsigned short flags;
        unsigned short es;
        unsigned short ds;
    } x;
} REGS;

typedef struct ExeLoadParams {
    unsigned short envSegment;
    unsigned short cmdlineOffset;
    unsigned short cmdlineSegment;
    unsigned short fcb1Offset;
    unsigned short fcb1Segment;
    unsigned short fcb2Offset;
    unsigned short fcb2Segment;
    unsigned short ss;
    unsigned short sp;
    unsigned short cs;
    unsigned short ip;
} ExeLoadParams;

typedef struct OvlLoadParams {
    unsigned short segment;
    unsigned short reloc;
} OvlLoadParams;

static inline uintptr_t MK_FP(unsigned short seg, unsigned short off) {
    return ((uintptr_t)seg << 4) + off;
}

static inline unsigned short FP_OFF(const void *ptr) {
    return (unsigned short)((uintptr_t)ptr & 0xffffU);
}

static inline unsigned short FP_SEG(const void *ptr) {
    return (unsigned short)(((uintptr_t)ptr >> 4) & 0xffffU);
}

static inline int intdos(union REGS *in, union REGS *out) {
    (void)in;
    (void)out;
    return 0;
}

static const unsigned short _psp = 0;

#define DOSF_ALLOCMEM 0
#define DOSF_LOADPROG 0x4b
#define DOS_LOAD_EXEC 0
#define DOS_LOAD_NOEXEC 1
#define DOS_LOAD_OVL 3
#define DOSERR_INVFUNC 1
#define DEBUG(...) do { } while (0)
#define INFO(...) do { } while (0)
#define ERROR(...) do { } while (0)
"""


def _write_c_text_tempfile(c_text: str) -> Path:
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as tmp:
        path = Path(tmp.name)
        tmp.write(_compat_syntax_prelude())
        tmp.write("\n")
        tmp.write(c_text)
    return path


def syntax_check_recompilable_c_text(c_text: str) -> subprocess.CompletedProcess[str]:
    path = _write_c_text_tempfile(c_text)
    try:
        return subprocess.run(
            ["gcc", "-std=c11", "-fsyntax-only", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        path.unlink(missing_ok=True)


def compile_recompilable_c_text(c_text: str) -> subprocess.CompletedProcess[str]:
    path = _write_c_text_tempfile(c_text)
    obj_path = path.with_suffix(".o")
    try:
        return subprocess.run(
            ["gcc", "-std=c11", "-c", "-o", str(obj_path), str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        path.unlink(missing_ok=True)
        obj_path.unlink(missing_ok=True)


def check_recompilable_c_text_shape(
    c_text: str, case: RecompilableSubsetCase
) -> dict[str, object]:
    missing = tuple(anchor for anchor in case.expected_c_anchors if anchor not in c_text)
    forbidden = tuple(anchor for anchor in case.forbidden_c_anchors if anchor in c_text)
    return {
        "shape_ok": not missing and not forbidden,
        "shape_missing": missing,
        "shape_forbidden": forbidden,
    }
