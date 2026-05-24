import io
import re
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import angr
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import decompile

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.cod_extract import (
    extract_cod_proc_metadata,
    join_cod_entries_with_synthetic_globals,
)
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401

_ROOT = Path(__file__).resolve().parents[2]
_COD_DIR = _ROOT / "cod"
_F14_COD_DIR = _COD_DIR / "f14"
_X16_SAMPLES_DIR = Path(__file__).resolve().parents[1] / "x16_samples"
_OPTIONAL_COMPILER_COD = _COD_DIR / "output_Od_Gs.COD"


@dataclass(frozen=True)
class DecompCase:
    name: str
    cod_name: str
    proc_name: str
    original_c: str
    expected_tokens: tuple[str, ...]
    cod_dir: Path | None = None
    proc_kind: str = "NEAR"


@dataclass(frozen=True)
class BlockLiftCase:
    name: str
    cod_name: str
    proc_name: str
    block_addr: int
    original_c: str
    expected_tokens: tuple[str, ...]
    cod_dir: Path | None = None
    proc_kind: str = "NEAR"
    start_offset: int | None = None
    end_offset: int | None = None
    expected_token_counts: tuple[tuple[str, int], ...] = ()


DECOMP_CASES = (
    DecompCase(
        name="isod_fold_values",
        cod_name="ISOD.COD",
        proc_name="fold_values",
        cod_dir=_X16_SAMPLES_DIR,
        original_c="return value + 123;",
        expected_tokens=("123", "return"),
    ),
    DecompCase(
        name="imod_fold_values",
        cod_name="IMOD.COD",
        proc_name="fold_values",
        cod_dir=_X16_SAMPLES_DIR,
        proc_kind="FAR",
        original_c="return value + 123;",
        expected_tokens=("123", "return"),
    ),
    DecompCase(
        name="f14_mset_pos",
        cod_name="MONOPRIN.COD",
        proc_name="_mset_pos",
        cod_dir=_F14_COD_DIR,
        original_c="_mono_x = x % 80; _mono_y = y % 25; return 0;",
        expected_tokens=("% 80", "% 25", "return"),
    ),
    DecompCase(
        name="f14_change_weather",
        cod_name="NHORZ.COD",
        proc_name="_ChangeWeather",
        cod_dir=_F14_COD_DIR,
        original_c=(
            "if (BadWeather) { CLOUDHEIGHT=8150; CLOUDTHICK=500; } "
            "else { CLOUDHEIGHT=125; CLOUDTHICK=1000; }"
        ),
        expected_tokens=("8150", "500", "125", "1000"),
    ),
    DecompCase(
        name="f14_ready5",
        cod_name="PLANES3.COD",
        proc_name="_Ready5",
        cod_dir=_F14_COD_DIR,
        original_c="bv[planecnt].basespeed = 0; /* struct stride 46, field offset 18 */ return 0;",
        expected_tokens=("46", "18", "return"),
    ),
    DecompCase(
        name="f14_lookdown",
        cod_name="COCKPIT.COD",
        proc_name="_LookDown",
        cod_dir=_F14_COD_DIR,
        original_c="Rp3D->Length1 = 50; RpCRT1->YBgn = 27; RpCRT2->YBgn = 25; RpCRT4->YBgn = 39;",
        expected_tokens=("50", "27", "25", "39"),
    ),
    DecompCase(
        name="f14_lookup",
        cod_name="COCKPIT.COD",
        proc_name="_LookUp",
        cod_dir=_F14_COD_DIR,
        original_c=(
            "Rp3D->Length1 = 150; RpCRT1->YBgn = 138; RpCRT2->YBgn = 136; "
            "RpCRT4->YBgn = 150; else Rp3D->Length1 = 139;"
        ),
        expected_tokens=("150", "138", "136", "139"),
    ),
    DecompCase(
        name="f14_mousepos",
        cod_name="BILLASM.COD",
        proc_name="_MousePOS",
        cod_dir=_F14_COD_DIR,
        original_c="if (!MOUSE) return 0; MouseX = x << 1; MouseY = y; int 33h;",
        expected_tokens=("* 2", "return"),
    ),
)


BLOCK_LIFT_CASES = (
    BlockLiftCase(
        name="isod_query_interrupts_setup",
        cod_name="ISOD.COD",
        proc_name="query_interrupts",
        cod_dir=_X16_SAMPLES_DIR,
        block_addr=0x1000,
        original_c="inregs.h.ah = 0x30; int86(0x21, &inregs, &outregs);",
        expected_tokens=("STle(", "0x30", "PUT(ax) = 0x0021", "PUT(ip) = 0x1019"),
        start_offset=0x35,
        end_offset=0x4E,
    ),
    BlockLiftCase(
        name="default_max_compare_body",
        cod_name="MAX.COD",
        proc_name="_max",
        cod_dir=_COD_DIR / "default",
        block_addr=0x1000,
        original_c="if (x > y) return x; return y;",
        expected_tokens=("CmpLE16S", "PUT(ip) = 0x1008", "PUT(ip) = 0x100e", "LDle:I16"),
        start_offset=0x4E,
    ),
    BlockLiftCase(
        name="f14_get_cat_heading_segmented_add",
        cod_name="CARR.COD",
        proc_name="_GetCatHeading",
        cod_dir=_F14_COD_DIR,
        block_addr=0x1000,
        original_c="return carrier.catpult[cat].heading + carrier.heading;",
        expected_tokens=("Shl16", "LDle:I16", "Add16", "PUT(ax)"),
    ),
    BlockLiftCase(
        name="f14_overlay_loader_block",
        cod_name="OVL.COD",
        proc_name="_dig_load_overlay",
        cod_dir=_F14_COD_DIR,
        block_addr=0x1030,
        original_c="ax = 0; adc ax, 0; err = ax; if (err == 0) goto success;",
        expected_tokens=("PUT(ax) = 0x0000", "PUT(flags)", "PUT(ip) = 0x1043"),
    ),
    BlockLiftCase(
        name="f14_config_crts_loop",
        cod_name="COCKPIT.COD",
        proc_name="_ConfigCrts",
        cod_dir=_F14_COD_DIR,
        block_addr=0x100B,
        original_c="for (i = 0; i < 8; i++) { CrtDisplays[i] = CrtConfig[i]; }",
        expected_tokens=("Shl16", "0x0222", "LDle:I16", "STle", "0x0008"),
    ),
    BlockLiftCase(
        name="f14_inbox_bounds_check",
        cod_name="CARR.COD",
        proc_name="_InBox",
        cod_dir=_F14_COD_DIR,
        block_addr=0x1000,
        original_c="if ((x < xl) || (x > xh) || (z < zl) || (z > zh)) return 0; else return 1;",
        expected_tokens=("CmpGT16S", "PUT(ip) = 0x100b", "PUT(ip) = 0x101d", "Ijk_Boring"),
    ),
    BlockLiftCase(
        name="f14_inboxlng_long_bounds_check",
        cod_name="CARR.COD",
        proc_name="_InBoxLng",
        cod_dir=_F14_COD_DIR,
        block_addr=0x1000,
        original_c="if ((x < xl) || (x > xh) || (z < zl) || (z > zh)) return 0; else return 1;",
        expected_tokens=("CmpGT16S", "PUT(ip) = 0x100e", "PUT(ip) = 0x1045", "LDle:I16"),
    ),
)


@dataclass(frozen=True)
class MatrixBlockLiftCase:
    name: str
    cod_name: str
    proc_name: str
    proc_kind: str
    start_offset: int
    end_offset: int
    original_c: str
    expected_tokens: tuple[str, ...]
    expected_token_counts: tuple[tuple[str, int], ...] = ()


QUERY_INTERRUPT_MATRIX_CASES = (
    MatrixBlockLiftCase(
        name="isod_query_interrupts_prefix",
        cod_name="ISOD.COD",
        proc_name="query_interrupts",
        proc_kind="NEAR",
        start_offset=0x35,
        end_offset=0x4E,
        original_c="inregs.h.ah = 0x30; int86(0x21, &inregs, &outregs);",
        expected_tokens=("0x30", "PUT(ax) = 0x0021", "STle("),
    ),
    MatrixBlockLiftCase(
        name="isot_query_interrupts_prefix",
        cod_name="ISOT.COD",
        proc_name="query_interrupts",
        proc_kind="NEAR",
        start_offset=0x28,
        end_offset=0x3E,
        original_c="inregs.h.ah = 0x30; int86(0x21, &inregs, &outregs);",
        expected_tokens=("0x30", "PUT(ax) = 0x0021", "STle("),
    ),
    MatrixBlockLiftCase(
        name="isox_query_interrupts_prefix",
        cod_name="ISOX.COD",
        proc_name="query_interrupts",
        proc_kind="NEAR",
        start_offset=0x28,
        end_offset=0x3E,
        original_c="inregs.h.ah = 0x30; int86(0x21, &inregs, &outregs);",
        expected_tokens=("0x30", "PUT(ax) = 0x0021", "STle("),
    ),
    MatrixBlockLiftCase(
        name="imod_query_interrupts_prefix",
        cod_name="IMOD.COD",
        proc_name="query_interrupts",
        proc_kind="FAR",
        start_offset=0x35,
        end_offset=0x4E,
        original_c="inregs.h.ah = 0x30; int86(0x21, &inregs, &outregs);",
        expected_tokens=("0x30", "PUT(ax) = 0x0021", "STle("),
    ),
    MatrixBlockLiftCase(
        name="imot_query_interrupts_prefix",
        cod_name="IMOT.COD",
        proc_name="query_interrupts",
        proc_kind="FAR",
        start_offset=0x28,
        end_offset=0x3E,
        original_c="inregs.h.ah = 0x30; int86(0x21, &inregs, &outregs);",
        expected_tokens=("0x30", "PUT(ax) = 0x0021", "STle("),
    ),
    MatrixBlockLiftCase(
        name="imox_query_interrupts_prefix",
        cod_name="IMOX.COD",
        proc_name="query_interrupts",
        proc_kind="FAR",
        start_offset=0x28,
        end_offset=0x3E,
        original_c="inregs.h.ah = 0x30; int86(0x21, &inregs, &outregs);",
        expected_tokens=("0x30", "PUT(ax) = 0x0021", "STle("),
    ),
    MatrixBlockLiftCase(
        name="ihod_query_interrupts_prefix",
        cod_name="IHOD.COD",
        proc_name="query_interrupts",
        proc_kind="FAR",
        start_offset=0x35,
        end_offset=0x50,
        original_c="inregs.h.ah = 0x30; int86(0x21, &inregs, &outregs);",
        expected_tokens=("0x30", "PUT(ax) = 0x0021", "STle(", "GET:I16(ss)"),
    ),
    MatrixBlockLiftCase(
        name="ihot_query_interrupts_prefix",
        cod_name="IHOT.COD",
        proc_name="query_interrupts",
        proc_kind="FAR",
        start_offset=0x28,
        end_offset=0x40,
        original_c="inregs.h.ah = 0x30; int86(0x21, &inregs, &outregs);",
        expected_tokens=("0x30", "PUT(ax) = 0x0021", "STle(", "GET:I16(ss)"),
    ),
    MatrixBlockLiftCase(
        name="ilod_query_interrupts_prefix",
        cod_name="ILOD.COD",
        proc_name="query_interrupts",
        proc_kind="FAR",
        start_offset=0x35,
        end_offset=0x50,
        original_c="inregs.h.ah = 0x30; int86(0x21, &inregs, &outregs);",
        expected_tokens=("0x30", "PUT(ax) = 0x0021", "STle(", "GET:I16(ss)"),
    ),
    MatrixBlockLiftCase(
        name="ilot_query_interrupts_prefix",
        cod_name="ILOT.COD",
        proc_name="query_interrupts",
        proc_kind="FAR",
        start_offset=0x28,
        end_offset=0x40,
        original_c="inregs.h.ah = 0x30; int86(0x21, &inregs, &outregs);",
        expected_tokens=("0x30", "PUT(ax) = 0x0021", "STle(", "GET:I16(ss)"),
    ),
)


QUERY_INTERRUPT_INT21_VECTOR_MATRIX_CASES = (
    MatrixBlockLiftCase(
        name="isod_query_interrupts_int21_vector",
        cod_name="ISOD.COD",
        proc_name="query_interrupts",
        proc_kind="NEAR",
        start_offset=0xD7,
        end_offset=0xE3,
        original_c="g_info.int21_segment = sregs.es; g_info.int21_offset = outregs.x.bx;",
        expected_tokens=("0x00000008", "0x0000000a", "STle(", "LDle:I16"),
    ),
    MatrixBlockLiftCase(
        name="isot_query_interrupts_int21_vector",
        cod_name="ISOT.COD",
        proc_name="query_interrupts",
        proc_kind="NEAR",
        start_offset=0xC7,
        end_offset=0xD3,
        original_c="g_info.int21_segment = sregs.es; g_info.int21_offset = outregs.x.bx;",
        expected_tokens=("0x00000008", "0x0000000a", "STle(", "LDle:I16"),
    ),
    MatrixBlockLiftCase(
        name="isox_query_interrupts_int21_vector",
        cod_name="ISOX.COD",
        proc_name="query_interrupts",
        proc_kind="NEAR",
        start_offset=0xC7,
        end_offset=0xD3,
        original_c="g_info.int21_segment = sregs.es; g_info.int21_offset = outregs.x.bx;",
        expected_tokens=("0x00000008", "0x0000000a", "STle(", "LDle:I16"),
    ),
    MatrixBlockLiftCase(
        name="imod_query_interrupts_int21_vector",
        cod_name="IMOD.COD",
        proc_name="query_interrupts",
        proc_kind="FAR",
        start_offset=0xE1,
        end_offset=0xED,
        original_c="g_info.int21_segment = sregs.es; g_info.int21_offset = outregs.x.bx;",
        expected_tokens=("0x00000008", "0x0000000a", "STle(", "LDle:I16"),
    ),
    MatrixBlockLiftCase(
        name="imot_query_interrupts_int21_vector",
        cod_name="IMOT.COD",
        proc_name="query_interrupts",
        proc_kind="FAR",
        start_offset=0xD1,
        end_offset=0xDD,
        original_c="g_info.int21_segment = sregs.es; g_info.int21_offset = outregs.x.bx;",
        expected_tokens=("0x00000008", "0x0000000a", "STle(", "LDle:I16"),
    ),
    MatrixBlockLiftCase(
        name="imox_query_interrupts_int21_vector",
        cod_name="IMOX.COD",
        proc_name="query_interrupts",
        proc_kind="FAR",
        start_offset=0xD1,
        end_offset=0xDD,
        original_c="g_info.int21_segment = sregs.es; g_info.int21_offset = outregs.x.bx;",
        expected_tokens=("0x00000008", "0x0000000a", "STle(", "LDle:I16"),
    ),
    MatrixBlockLiftCase(
        name="ihod_query_interrupts_int21_vector",
        cod_name="IHOD.COD",
        proc_name="query_interrupts",
        proc_kind="FAR",
        start_offset=0xEC,
        end_offset=0xF8,
        original_c="g_info.int21_segment = sregs.es; g_info.int21_offset = outregs.x.bx;",
        expected_tokens=("0x00000008", "0x0000000a", "STle(", "LDle:I16"),
    ),
    MatrixBlockLiftCase(
        name="ihot_query_interrupts_int21_vector",
        cod_name="IHOT.COD",
        proc_name="query_interrupts",
        proc_kind="FAR",
        start_offset=0xDC,
        end_offset=0xE8,
        original_c="g_info.int21_segment = sregs.es; g_info.int21_offset = outregs.x.bx;",
        expected_tokens=("0x00000008", "0x0000000a", "STle(", "LDle:I16"),
    ),
    MatrixBlockLiftCase(
        name="ilod_query_interrupts_int21_vector",
        cod_name="ILOD.COD",
        proc_name="query_interrupts",
        proc_kind="FAR",
        start_offset=0xEC,
        end_offset=0xF8,
        original_c="g_info.int21_segment = sregs.es; g_info.int21_offset = outregs.x.bx;",
        expected_tokens=("0x00000008", "0x0000000a", "STle(", "LDle:I16"),
    ),
    MatrixBlockLiftCase(
        name="ilot_query_interrupts_int21_vector",
        cod_name="ILOT.COD",
        proc_name="query_interrupts",
        proc_kind="FAR",
        start_offset=0xDC,
        end_offset=0xE8,
        original_c="g_info.int21_segment = sregs.es; g_info.int21_offset = outregs.x.bx;",
        expected_tokens=("0x00000008", "0x0000000a", "STle(", "LDle:I16"),
    ),
)


SHOW_SUMMARY_MATRIX_CASES = (
    MatrixBlockLiftCase(
        name="isod_show_summary_prefix",
        cod_name="ISOD.COD",
        proc_name="show_summary",
        proc_kind="NEAR",
        start_offset=0xF2,
        end_offset=0x102,
        original_c='cprintf("dos=%u bios=%u mode=%u\\r\\n", g_info.dos_version, g_info.bios_kb, g_info.video_mode);',
        expected_tokens=("0x0004", "0x0002", "0x0000", "STle(", "PUT(ax) = 0x0000"),
    ),
    MatrixBlockLiftCase(
        name="isot_show_summary_prefix",
        cod_name="ISOT.COD",
        proc_name="show_summary",
        proc_kind="NEAR",
        start_offset=0xD8,
        end_offset=0xE8,
        original_c='cprintf("dos=%u bios=%u mode=%u\\r\\n", g_info.dos_version, g_info.bios_kb, g_info.video_mode);',
        expected_tokens=("0x0004", "0x0002", "0x0000", "STle(", "PUT(ax) = 0x0000"),
    ),
    MatrixBlockLiftCase(
        name="isox_show_summary_prefix",
        cod_name="ISOX.COD",
        proc_name="show_summary",
        proc_kind="NEAR",
        start_offset=0xD8,
        end_offset=0xE8,
        original_c='cprintf("dos=%u bios=%u mode=%u\\r\\n", g_info.dos_version, g_info.bios_kb, g_info.video_mode);',
        expected_tokens=("0x0004", "0x0002", "0x0000", "STle(", "PUT(ax) = 0x0000"),
    ),
    MatrixBlockLiftCase(
        name="imod_show_summary_prefix",
        cod_name="IMOD.COD",
        proc_name="show_summary",
        proc_kind="FAR",
        start_offset=0xFC,
        end_offset=0x10C,
        original_c='cprintf("dos=%u bios=%u mode=%u\\r\\n", g_info.dos_version, g_info.bios_kb, g_info.video_mode);',
        expected_tokens=("0x0004", "0x0002", "0x0000", "STle(", "PUT(ax) = 0x0000"),
    ),
    MatrixBlockLiftCase(
        name="imot_show_summary_prefix",
        cod_name="IMOT.COD",
        proc_name="show_summary",
        proc_kind="FAR",
        start_offset=0xE2,
        end_offset=0xF2,
        original_c='cprintf("dos=%u bios=%u mode=%u\\r\\n", g_info.dos_version, g_info.bios_kb, g_info.video_mode);',
        expected_tokens=("0x0004", "0x0002", "0x0000", "STle(", "PUT(ax) = 0x0000"),
    ),
    MatrixBlockLiftCase(
        name="imox_show_summary_prefix",
        cod_name="IMOX.COD",
        proc_name="show_summary",
        proc_kind="FAR",
        start_offset=0xE2,
        end_offset=0xF2,
        original_c='cprintf("dos=%u bios=%u mode=%u\\r\\n", g_info.dos_version, g_info.bios_kb, g_info.video_mode);',
        expected_tokens=("0x0004", "0x0002", "0x0000", "STle(", "PUT(ax) = 0x0000"),
    ),
    MatrixBlockLiftCase(
        name="ihod_show_summary_prefix",
        cod_name="IHOD.COD",
        proc_name="show_summary",
        proc_kind="FAR",
        start_offset=0x107,
        end_offset=0x118,
        original_c='cprintf("dos=%u bios=%u mode=%u\\r\\n", g_info.dos_version, g_info.bios_kb, g_info.video_mode);',
        expected_tokens=("0x0004", "0x0002", "0x0000", "STle(", "GET:I16(ds)"),
    ),
    MatrixBlockLiftCase(
        name="ihot_show_summary_prefix",
        cod_name="IHOT.COD",
        proc_name="show_summary",
        proc_kind="FAR",
        start_offset=0xEC,
        end_offset=0xFD,
        original_c='cprintf("dos=%u bios=%u mode=%u\\r\\n", g_info.dos_version, g_info.bios_kb, g_info.video_mode);',
        expected_tokens=("0x0004", "0x0002", "0x0000", "STle(", "GET:I16(ds)"),
    ),
    MatrixBlockLiftCase(
        name="ilod_show_summary_prefix",
        cod_name="ILOD.COD",
        proc_name="show_summary",
        proc_kind="FAR",
        start_offset=0x107,
        end_offset=0x118,
        original_c='cprintf("dos=%u bios=%u mode=%u\\r\\n", g_info.dos_version, g_info.bios_kb, g_info.video_mode);',
        expected_tokens=("0x0004", "0x0002", "0x0000", "STle(", "GET:I16(ds)"),
    ),
    MatrixBlockLiftCase(
        name="ilot_show_summary_prefix",
        cod_name="ILOT.COD",
        proc_name="show_summary",
        proc_kind="FAR",
        start_offset=0xEC,
        end_offset=0xFD,
        original_c='cprintf("dos=%u bios=%u mode=%u\\r\\n", g_info.dos_version, g_info.bios_kb, g_info.video_mode);',
        expected_tokens=("0x0004", "0x0002", "0x0000", "STle(", "GET:I16(ds)"),
    ),
)


MAIN_FOLD_VALUES_ARG_MATRIX_CASES = (
    MatrixBlockLiftCase(
        name="isod_main_fold_values_args",
        cod_name="ISOD.COD",
        proc_name="_main",
        proc_kind="NEAR",
        start_offset=0x11D,
        end_offset=0x127,
        original_c="return fold_values(g_info.video_mode, g_info.bios_kb & 0xFF);",
        expected_tokens=("And16(t5,0xff00)", "Add16(0x0000,0x0004)", "PUT(sp) =", "Shr16(t95,0x08)"),
        expected_token_counts=(("STle(", 3),),
    ),
    MatrixBlockLiftCase(
        name="isot_main_fold_values_args",
        cod_name="ISOT.COD",
        proc_name="_main",
        proc_kind="NEAR",
        start_offset=0xF6,
        end_offset=0x100,
        original_c="return fold_values(g_info.video_mode, g_info.bios_kb & 0xFF);",
        expected_tokens=("And16(t5,0xff00)", "Add16(0x0000,0x0004)", "PUT(sp) =", "Shr16(t95,0x08)"),
        expected_token_counts=(("STle(", 3),),
    ),
    MatrixBlockLiftCase(
        name="isox_main_fold_values_args",
        cod_name="ISOX.COD",
        proc_name="_main",
        proc_kind="NEAR",
        start_offset=0xF6,
        end_offset=0x100,
        original_c="return fold_values(g_info.video_mode, g_info.bios_kb & 0xFF);",
        expected_tokens=("And16(t5,0xff00)", "Add16(0x0000,0x0004)", "PUT(sp) =", "Shr16(t95,0x08)"),
        expected_token_counts=(("STle(", 3),),
    ),
    MatrixBlockLiftCase(
        name="imod_main_fold_values_args",
        cod_name="IMOD.COD",
        proc_name="_main",
        proc_kind="FAR",
        start_offset=0x12D,
        end_offset=0x137,
        original_c="return fold_values(g_info.video_mode, g_info.bios_kb & 0xFF);",
        expected_tokens=("And16(t5,0xff00)", "Add16(0x0000,0x0004)", "PUT(sp) =", "Shr16(t95,0x08)"),
        expected_token_counts=(("STle(", 3),),
    ),
    MatrixBlockLiftCase(
        name="imot_main_fold_values_args",
        cod_name="IMOT.COD",
        proc_name="_main",
        proc_kind="FAR",
        start_offset=0x104,
        end_offset=0x10E,
        original_c="return fold_values(g_info.video_mode, g_info.bios_kb & 0xFF);",
        expected_tokens=("And16(t5,0xff00)", "Add16(0x0000,0x0004)", "PUT(sp) =", "Shr16(t95,0x08)"),
        expected_token_counts=(("STle(", 3),),
    ),
    MatrixBlockLiftCase(
        name="imox_main_fold_values_args",
        cod_name="IMOX.COD",
        proc_name="_main",
        proc_kind="FAR",
        start_offset=0x104,
        end_offset=0x10E,
        original_c="return fold_values(g_info.video_mode, g_info.bios_kb & 0xFF);",
        expected_tokens=("And16(t5,0xff00)", "Add16(0x0000,0x0004)", "PUT(sp) =", "Shr16(t95,0x08)"),
        expected_token_counts=(("STle(", 3),),
    ),
    MatrixBlockLiftCase(
        name="ihod_main_fold_values_args",
        cod_name="IHOD.COD",
        proc_name="_main",
        proc_kind="FAR",
        start_offset=0x139,
        end_offset=0x143,
        original_c="return fold_values(g_info.video_mode, g_info.bios_kb & 0xFF);",
        expected_tokens=("And16(t5,0xff00)", "Add16(0x0000,0x0004)", "PUT(sp) =", "Shr16(t95,0x08)"),
        expected_token_counts=(("STle(", 3),),
    ),
    MatrixBlockLiftCase(
        name="ihot_main_fold_values_args",
        cod_name="IHOT.COD",
        proc_name="_main",
        proc_kind="FAR",
        start_offset=0x10E,
        end_offset=0x118,
        original_c="return fold_values(g_info.video_mode, g_info.bios_kb & 0xFF);",
        expected_tokens=("And16(t5,0xff00)", "Add16(0x0000,0x0004)", "PUT(sp) =", "Shr16(t95,0x08)"),
        expected_token_counts=(("STle(", 3),),
    ),
    MatrixBlockLiftCase(
        name="ilod_main_fold_values_args",
        cod_name="ILOD.COD",
        proc_name="_main",
        proc_kind="FAR",
        start_offset=0x139,
        end_offset=0x143,
        original_c="return fold_values(g_info.video_mode, g_info.bios_kb & 0xFF);",
        expected_tokens=("And16(t5,0xff00)", "Add16(0x0000,0x0004)", "PUT(sp) =", "Shr16(t95,0x08)"),
        expected_token_counts=(("STle(", 3),),
    ),
    MatrixBlockLiftCase(
        name="ilot_main_fold_values_args",
        cod_name="ILOT.COD",
        proc_name="_main",
        proc_kind="FAR",
        start_offset=0x10E,
        end_offset=0x118,
        original_c="return fold_values(g_info.video_mode, g_info.bios_kb & 0xFF);",
        expected_tokens=("And16(t5,0xff00)", "Add16(0x0000,0x0004)", "PUT(sp) =", "Shr16(t95,0x08)"),
        expected_token_counts=(("STle(", 3),),
    ),
)


MAIN_CALL_PREFIX_MATRIX_CASES = (
    MatrixBlockLiftCase(
        name="isod_main_call_prefix",
        cod_name="ISOD.COD",
        proc_name="_main",
        proc_kind="NEAR",
        start_offset=0x10E,
        end_offset=0x11D,
        original_c="query_interrupts(); show_summary();",
        expected_tokens=("GET:I16(bp)", "GET:I16(di)", "GET:I16(si)", "0x100c", "Ijk_Call"),
    ),
    MatrixBlockLiftCase(
        name="isot_main_call_prefix",
        cod_name="ISOT.COD",
        proc_name="_main",
        proc_kind="NEAR",
        start_offset=0xF0,
        end_offset=0xF6,
        original_c="query_interrupts(); show_summary();",
        expected_tokens=("GET:I16(sp)", "STle(", "0x1003", "NEXT: PUT(ip) = 0x0f38; Ijk_Call"),
    ),
    MatrixBlockLiftCase(
        name="isox_main_call_prefix",
        cod_name="ISOX.COD",
        proc_name="_main",
        proc_kind="NEAR",
        start_offset=0xF0,
        end_offset=0xF6,
        original_c="query_interrupts(); show_summary();",
        expected_tokens=("GET:I16(sp)", "STle(", "0x1003", "NEXT: PUT(ip) = 0x0f38; Ijk_Call"),
    ),
    MatrixBlockLiftCase(
        name="imod_main_call_prefix",
        cod_name="IMOD.COD",
        proc_name="_main",
        proc_kind="FAR",
        start_offset=0x11A,
        end_offset=0x12D,
        original_c="query_interrupts(); show_summary();",
        expected_tokens=("GET:I16(bp)", "GET:I16(di)", "GET:I16(si)", "PUT(cs) = 0x0000", "Ijk_Call"),
    ),
    MatrixBlockLiftCase(
        name="imot_main_call_prefix",
        cod_name="IMOT.COD",
        proc_name="_main",
        proc_kind="FAR",
        start_offset=0xFC,
        end_offset=0x104,
        original_c="query_interrupts(); show_summary();",
        expected_tokens=("GET:I16(cs)", "STle(", "0x1004", "NEXT: PUT(ip) = 0x1004; Ijk_Call"),
    ),
    MatrixBlockLiftCase(
        name="imox_main_call_prefix",
        cod_name="IMOX.COD",
        proc_name="_main",
        proc_kind="FAR",
        start_offset=0xFC,
        end_offset=0x104,
        original_c="query_interrupts(); show_summary();",
        expected_tokens=("GET:I16(cs)", "STle(", "0x1004", "NEXT: PUT(ip) = 0x1004; Ijk_Call"),
    ),
    MatrixBlockLiftCase(
        name="ihod_main_call_prefix",
        cod_name="IHOD.COD",
        proc_name="_main",
        proc_kind="FAR",
        start_offset=0x126,
        end_offset=0x139,
        original_c="query_interrupts(); show_summary();",
        expected_tokens=("GET:I16(bp)", "GET:I16(di)", "GET:I16(si)", "PUT(cs) = 0x0000", "Ijk_Call"),
    ),
    MatrixBlockLiftCase(
        name="ihot_main_call_prefix",
        cod_name="IHOT.COD",
        proc_name="_main",
        proc_kind="FAR",
        start_offset=0x106,
        end_offset=0x10E,
        original_c="query_interrupts(); show_summary();",
        expected_tokens=("GET:I16(cs)", "STle(", "0x1004", "NEXT: PUT(ip) = 0x1004; Ijk_Call"),
    ),
    MatrixBlockLiftCase(
        name="ilod_main_call_prefix",
        cod_name="ILOD.COD",
        proc_name="_main",
        proc_kind="FAR",
        start_offset=0x126,
        end_offset=0x139,
        original_c="query_interrupts(); show_summary();",
        expected_tokens=("GET:I16(bp)", "GET:I16(di)", "GET:I16(si)", "PUT(cs) = 0x0000", "Ijk_Call"),
    ),
    MatrixBlockLiftCase(
        name="ilot_main_call_prefix",
        cod_name="ILOT.COD",
        proc_name="_main",
        proc_kind="FAR",
        start_offset=0x106,
        end_offset=0x10E,
        original_c="query_interrupts(); show_summary();",
        expected_tokens=("GET:I16(cs)", "STle(", "0x1004", "NEXT: PUT(ip) = 0x1004; Ijk_Call"),
    ),
)


FOLD_VALUES_BLOCK_MATRIX_CASES = (
    MatrixBlockLiftCase(
        name="isod_fold_values_block",
        cod_name="ISOD.COD",
        proc_name="fold_values",
        proc_kind="NEAR",
        start_offset=0x0,
        end_offset=0x1B,
        original_c="return (mode << 5) + bios_kb + 123 <= 1000;",
        expected_tokens=("Sub16(t9,0x0002)", "Add16(0x0000,0x0006)", "CmpGT16U", "PUT(ip) = 0x101b"),
    ),
    MatrixBlockLiftCase(
        name="isot_fold_values_block",
        cod_name="ISOT.COD",
        proc_name="fold_values",
        proc_kind="NEAR",
        start_offset=0x0,
        end_offset=0x16,
        original_c="return (mode << 5) + bios_kb + 123 <= 1000;",
        expected_tokens=("8Sto16(0x02)", "Add16(0x0000,0x0006)", "CmpLE16U", "PUT(ip) = 0x1016"),
    ),
    MatrixBlockLiftCase(
        name="isox_fold_values_block",
        cod_name="ISOX.COD",
        proc_name="fold_values",
        proc_kind="NEAR",
        start_offset=0x0,
        end_offset=0x16,
        original_c="return (mode << 5) + bios_kb + 123 <= 1000;",
        expected_tokens=("8Sto16(0x02)", "Add16(0x0000,0x0006)", "CmpLE16U", "PUT(ip) = 0x1016"),
    ),
    MatrixBlockLiftCase(
        name="imod_fold_values_block",
        cod_name="IMOD.COD",
        proc_name="fold_values",
        proc_kind="FAR",
        start_offset=0x0,
        end_offset=0x1B,
        original_c="return (mode << 5) + bios_kb + 123 <= 1000;",
        expected_tokens=("Sub16(t9,0x0002)", "Add16(0x0000,0x0008)", "CmpGT16U", "PUT(ip) = 0x101b"),
    ),
    MatrixBlockLiftCase(
        name="imot_fold_values_block",
        cod_name="IMOT.COD",
        proc_name="fold_values",
        proc_kind="FAR",
        start_offset=0x0,
        end_offset=0x16,
        original_c="return (mode << 5) + bios_kb + 123 <= 1000;",
        expected_tokens=("8Sto16(0x02)", "Add16(0x0000,0x0008)", "CmpLE16U", "PUT(ip) = 0x1016"),
    ),
    MatrixBlockLiftCase(
        name="imox_fold_values_block",
        cod_name="IMOX.COD",
        proc_name="fold_values",
        proc_kind="FAR",
        start_offset=0x0,
        end_offset=0x16,
        original_c="return (mode << 5) + bios_kb + 123 <= 1000;",
        expected_tokens=("8Sto16(0x02)", "Add16(0x0000,0x0008)", "CmpLE16U", "PUT(ip) = 0x1016"),
    ),
    MatrixBlockLiftCase(
        name="ihod_fold_values_block",
        cod_name="IHOD.COD",
        proc_name="fold_values",
        proc_kind="FAR",
        start_offset=0x0,
        end_offset=0x1B,
        original_c="return (mode << 5) + bios_kb + 123 <= 1000;",
        expected_tokens=("Sub16(t9,0x0002)", "Add16(0x0000,0x0008)", "CmpGT16U", "PUT(ip) = 0x101b"),
    ),
    MatrixBlockLiftCase(
        name="ihot_fold_values_block",
        cod_name="IHOT.COD",
        proc_name="fold_values",
        proc_kind="FAR",
        start_offset=0x0,
        end_offset=0x16,
        original_c="return (mode << 5) + bios_kb + 123 <= 1000;",
        expected_tokens=("8Sto16(0x02)", "Add16(0x0000,0x0008)", "CmpLE16U", "PUT(ip) = 0x1016"),
    ),
    MatrixBlockLiftCase(
        name="ilod_fold_values_block",
        cod_name="ILOD.COD",
        proc_name="fold_values",
        proc_kind="FAR",
        start_offset=0x0,
        end_offset=0x1B,
        original_c="return (mode << 5) + bios_kb + 123 <= 1000;",
        expected_tokens=("Sub16(t9,0x0002)", "Add16(0x0000,0x0008)", "CmpGT16U", "PUT(ip) = 0x101b"),
    ),
    MatrixBlockLiftCase(
        name="ilot_fold_values_block",
        cod_name="ILOT.COD",
        proc_name="fold_values",
        proc_kind="FAR",
        start_offset=0x0,
        end_offset=0x16,
        original_c="return (mode << 5) + bios_kb + 123 <= 1000;",
        expected_tokens=("8Sto16(0x02)", "Add16(0x0000,0x0008)", "CmpLE16U", "PUT(ip) = 0x1016"),
    ),
)


def _project_from_bytes(code: bytes):
    return angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )


def _decompile_blob(code: bytes):
    project = _project_from_bytes(code)
    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    assert dec.codegen is not None
    return dec.codegen.text


def _assert_text_contains(text: str, expected_tokens: tuple[str, ...], original_c: str):
    missing = [token for token in expected_tokens if token not in text]
    assert not missing, (
        "Recovered C no longer reflects the original source intent.\n"
        f"Original C fragment:\n{original_c}\n\n"
        f"Missing expected tokens: {missing}\n\n"
        f"Recovered C:\n{text}"
    )


def _assert_irsb_contains(
    irsb_text: str,
    expected_tokens: tuple[str, ...],
    original_c: str,
    expected_token_counts: tuple[tuple[str, int], ...] = (),
):
    missing = [token for token in expected_tokens if token not in irsb_text]
    count_failures = [
        f"{token!r} expected at least {minimum} times, got {irsb_text.count(token)}"
        for token, minimum in expected_token_counts
        if irsb_text.count(token) < minimum
    ]
    assert not missing and not count_failures, (
        "Lifted VEX no longer reflects the intended source-level operation.\n"
        f"Original C fragment:\n{original_c}\n\n"
        f"Missing expected IR anchors: {missing}\n"
        f"Count mismatches: {count_failures}\n\n"
        f"Recovered IRSB:\n{irsb_text}"
    )


def _extract_cod_function(cod_name: str, proc_name: str, cod_dir: Path | None = None, proc_kind: str = "NEAR"):
    base_dir = _COD_DIR if cod_dir is None else cod_dir
    lines = (base_dir / cod_name).read_text(errors="ignore").splitlines()
    start_marker = f"{proc_name}\tPROC {proc_kind}"
    end_marker = f"{proc_name}\tENDP"

    collect = False
    entries = []
    for line in lines:
        if start_marker in line:
            collect = True
            continue
        if collect and end_marker in line:
            break
        if not collect:
            continue

        match = re.search(r"\*\*\*\s+([0-9A-Fa-f]+)\s+((?:[0-9A-Fa-f]{2}\s+)+)(.*)$", line)
        if not match:
            continue

        entries.append(
            {
                "offset": int(match.group(1), 16),
                "bytes": bytes.fromhex("".join(match.group(2).split())),
                "text": match.group(3).strip(),
            }
        )

    assert entries, f"did not find {proc_name} in {cod_name}"
    return entries


def _join_entries(entries, start_offset=None, end_offset=None):
    return b"".join(
        entry["bytes"]
        for entry in entries
        if (start_offset is None or start_offset <= entry["offset"])
        and (end_offset is None or entry["offset"] < end_offset)
    )


class _TimeoutExpired(Exception):
    pass


def _raise_timeout(_signum, _frame):
    raise _TimeoutExpired("timed out while analyzing BIOS .COD sample")


def test_cod_extractor_identifies_relocation_free_and_relocated_samples():
    if not _OPTIONAL_COMPILER_COD.exists():
        pytest.skip("optional compiler corpus sample output_Od_Gs.COD is not present in this workspace")

    bios_entries = _extract_cod_function("BIOSFUNC.COD", "_bios_clearkeyflags")
    bios_bytes = _join_entries(bios_entries)

    compiler_entries = _extract_cod_function("output_Od_Gs.COD", "_compiler_idiom_test_suite")
    compiler_bytes = _join_entries(compiler_entries)

    assert bios_bytes.hex() == "558bec83ec04c746fc1704c746fe00002bdb8ec3bb1704268c078be55dc3"
    assert b"\xe8\x00\x00" not in bios_bytes
    assert compiler_bytes.find(b"\xe8\x00\x00") == 0x160


def test_cod_offset_globals_are_synthesized_from_offset_immediates():
    strlen_entries = _extract_cod_function("STRLEN.COD", "_main", cod_dir=_COD_DIR / "default")
    _, strlen_globals = join_cod_entries_with_synthetic_globals(strlen_entries)
    assert any(name == "SG103" for name, _width in strlen_globals.values())

    overlay_entries = _extract_cod_function("OVERLAY.COD", "_overlay_load")
    _, overlay_globals = join_cod_entries_with_synthetic_globals(overlay_entries)
    overlay_metadata = extract_cod_proc_metadata(_COD_DIR / "OVERLAY.COD", "_overlay_load")

    assert any(name == "SG284" for name, _width in overlay_globals.values())
    assert "es" not in overlay_metadata.global_names


def test_cod_synthetic_globals_preserve_symbol_displacements():
    entries = [
        {
            "offset": 0,
            "bytes": bytes.fromhex("c6 06 17 00 48"),
            "text": "mov BYTE PTR $S424_rin+1,72",
        },
        {
            "offset": 5,
            "bytes": bytes.fromhex("c7 06 18 00 ff ff"),
            "text": "mov WORD PTR $S424_rin+2,-1",
        },
        {
            "offset": 11,
            "bytes": bytes.fromhex("b8 16 00"),
            "text": "mov ax,OFFSET DGROUP:$S424_rin",
        },
    ]

    proc_code, synthetic_globals = join_cod_entries_with_synthetic_globals(entries)

    assert proc_code.hex(" ") == "c6 06 01 70 48 c7 06 02 70 ff ff b8 00 70"
    assert synthetic_globals == {0x7000: ("rin", 4)}


def test_cod_unused_local_declarations_are_pruned():
    strlen_entries = _extract_cod_function("STRLEN.COD", "_main", cod_dir=_COD_DIR / "default")
    text = _decompile_blob(_join_entries(strlen_entries))

    assert "unsigned short s_2;" not in text
    assert "unsigned short ss;" not in text


def test_byteops_cod_main_renders_named_byte_locals_without_generic_staging_names():
    proc_path = _COD_DIR / "default" / "BYTEOPS.COD"
    entries = decompile.extract_cod_function_entries(proc_path, "_main", "NEAR")
    proc_code, synthetic_globals = decompile.join_cod_entries_with_synthetic_globals(entries)

    project = decompile._build_project_from_bytes(proc_code, base_addr=0x1000, entry_point=0x1000)
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[project.entry],
        regions=[(project.entry, project.entry + len(proc_code))],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[project.entry]
    cod_metadata = decompile.extract_cod_proc_metadata(proc_path, "_main", "NEAR")

    status, text = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=10,
        api_style="modern",
        binary_path=proc_path,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
    )

    assert status == "ok"
    assert "/* COD annotations:" in text
    assert "[bp-0x4] = b" in text
    assert "[bp-0x2] = a" in text
    assert "char b;  // [bp-0x4] b" in text
    assert "char a;  // [bp-0x2] a" in text
    assert "printf (" in text
    assert "a = %d, b = %d" in text
    assert "ir_" not in text
    assert "s_" not in text
    assert "a_2" not in text
    expected_body = [
        "a = 255;",
        "b = 143;",
        "b = a + b;",
        "a = a - b;",
        "a = a * b;",
        "b = b / a;",
        "b = b % a;",
        "a = a << 5;",
        "b = b >> a;",
        'printf ("a = %d, b = %d\\n", a, b);',
    ]
    positions = [text.index(stmt) for stmt in expected_body]
    assert positions == sorted(positions)
    assert "ax_" not in text
    assert re.search(r"\bcx_\w*\b", text) is None


def test_strlen_cod_sample_resolves_direct_stack_loads_to_annotated_slots():
    result = subprocess.run(
        [
            sys.executable,
            str(_ROOT / "decompile.py"),
            "cod/default/STRLEN.COD",
            "--proc",
            "_strlen",
            "--timeout",
            "20",
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    text = result.stdout

    assert "ir_3 = s_3;" not in text
    assert "ir_4 = s_3;" not in text
    assert "s_3 = (ir_3 | ir_4 * 0x100) + 1;" not in text
    assert "s_3 = ir_3 + 1 >> 8;" not in text
    assert "s_3 += 1;" not in text
    assert "while (*s++)" in text
    assert "if (!(s + 1))" not in text
    assert "n += 1;" in text
    assert "n = 0;" in text
    assert "return (n);" in text
    assert "unsigned short _strlen(unsigned short *s)" in text
    assert "unsigned short s_3;" not in text
    assert "s_3" not in text
    assert "char s_0;" not in text
    assert "unsigned short s_2;" not in text
    assert "&v1 + 4" not in text
    assert "&s_0 - 2" not in text


def test_overlay_cod_sample_rewrites_far_pointer_stack_pair_to_mk_fp():
    result = subprocess.run(
        [
            sys.executable,
            str(_ROOT / "decompile.py"),
            "cod/OVERLAY.COD",
            "--proc",
            "_overlay_functionAddress",
            "--timeout",
            "20",
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    text = result.stdout

    assert re.search(
        r"long _overlay_functionAddress\(const uint16 ovlLoadSegment, const uint16 funcNumber\)",
        text,
    )
    assert "struct OvlHeader FAR *ovlHeader = MK_FP(ovlLoadSegment, 0);" in text
    assert "uint16 FAR* slotArray=&(ovlHeader->slot);" in text
    assert "return MK_FP(ovlHeader->code_segment, slotArray[funcNumber]);" in text
    assert "[bp-0x8] = ovlHeader" in text
    assert "[bp-0x4] = slotArray" in text
    assert re.search(r"\bs_[0-9a-fA-F]+\b", text) is None
    assert "return *((unsigned short *)(&s_2 - 4));" not in text
    assert "return *((unsigned short *)(&s_0 - 4));" not in text


def test_overlay_cod_sample_wrapper_returns_overlay_segment():
    result = subprocess.run(
        [
            sys.executable,
            str(_ROOT / "decompile.py"),
            "cod/OVERLAY.COD",
            "--proc",
            "_overlay_load",
            "--timeout",
            "20",
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    text = result.stdout

    assert re.search(r"unsigned short _overlay_load\(const char \*\s*filename\)", text)
    assert "int err;" in text
    assert "unsigned short freeMem;" in text
    assert "unsigned short alloc;" in text
    assert "unsigned short ovlSegment;" in text
    assert "unsigned short ovlSize;" in text
    assert re.search(r"struct OvlHeader \*ovlHeader(?: = NULL)?;", text)
    assert "MK_FP(ds," not in text
    assert "file_2" not in text
    assert "dos_getfree();" in text
    assert "return ovlSegment;" in text
    assert "return;" not in text
    assert re.search(r"\bs_[0-9a-fA-F]+\b", text) is None
    assert re.search(r"\bvvar_\d+\b", text) is None
    assert re.search(r"\bax_\d+\b", text) is None
    body_match = re.search(
        r"unsigned short _overlay_load\(const char \* filename\)\s*\{(?P<body>.*?)\n\}",
        text,
        re.S,
    )
    assert body_match is not None
    body = body_match.group("body")
    assert not re.search(r"int err;\s*return ovlSegment;", body, re.S)
    assert re.search(r"int err;\s*freeMem = dos_getfree\(\);", body, re.S)
    assert re.search(
        r"if \(freeMem == 0\)\s*\{\s*ERROR\(\"overlay_load\(\): unable to determine amount of free memory\"\);\s*return 0;\s*\}",
        body,
        re.S,
    )
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


def test_dosfunc_cod_sample_deduplicates_stack_local_names():
    result = subprocess.run(
        [
            sys.executable,
            str(_ROOT / "decompile.py"),
            "cod/DOSFUNC.COD",
            "--proc",
            "_dos_free",
            "--timeout",
            "20",
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    text = result.stdout

    assert text.count("return err;") == 1
    assert "ERROR(\"dos_free: error freeing segment 0x%x: error 0x%x\", segment, (int)err);" in text
    assert "err_2" not in text


@pytest.mark.parametrize(
    ("proc_name", "header_anchor"),
    (
        ("_dos_getProcessId", "unsigned short _dos_getProcessId(void)"),
        ("_dos_setProcessId", "int _dos_setProcessId(const unsigned short pid)"),
    ),
)
def test_dosfunc_cod_sample_process_helpers_stay_empty(proc_name: str, header_anchor: str):
    result = subprocess.run(
        [
            sys.executable,
            str(_ROOT / "decompile.py"),
            "cod/DOSFUNC.COD",
            "--proc",
            proc_name,
            "--timeout",
            "20",
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    text = result.stdout

    assert header_anchor in text
    assert "return;" not in text
    if proc_name == "_dos_setProcessId":
        assert "[bp+0x4] = pid" in text


def test_bios_cod_sample_decompilation():
    bios_entries = _extract_cod_function("BIOSFUNC.COD", "_bios_clearkeyflags")
    project = _project_from_bytes(_join_entries(bios_entries))

    old_handler = signal.signal(signal.SIGALRM, _raise_timeout)
    signal.alarm(5)
    try:
        cfg = project.analyses.CFGFast(normalize=True)
        dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    _assert_text_contains(
        dec.codegen.text,
        ("MK_FP(0x40, 0x17)", "return"),
        "MK_FP(0x40, 0x17)",
    )
    assert "1047" not in dec.codegen.text


def test_compiler_idiom_prefix_lifts_from_cod_bytes():
    if not _OPTIONAL_COMPILER_COD.exists():
        pytest.skip("optional compiler corpus sample output_Od_Gs.COD is not present in this workspace")

    compiler_entries = _extract_cod_function("output_Od_Gs.COD", "_compiler_idiom_test_suite")
    # This relocation-free prefix covers `result = param_int * 2; temp_val = 10;`.
    prefix = _join_entries(compiler_entries, start_offset=0x9, end_offset=0x16)
    project = _project_from_bytes(prefix)

    irsb = project.factory.block(0x1000, len(prefix)).vex

    assert "Shl16" in irsb._pp_str()


@pytest.mark.parametrize("case", DECOMP_CASES, ids=lambda case: case.name)
def test_cod_decompilation_cases(case: DecompCase):
    entries = _extract_cod_function(case.cod_name, case.proc_name, cod_dir=case.cod_dir, proc_kind=case.proc_kind)
    text = _decompile_blob(_join_entries(entries))
    _assert_text_contains(text, case.expected_tokens, case.original_c)


@pytest.mark.parametrize("case", BLOCK_LIFT_CASES, ids=lambda case: case.name)
def test_cod_block_lift_cases(case: BlockLiftCase):
    entries = _extract_cod_function(case.cod_name, case.proc_name, cod_dir=case.cod_dir, proc_kind=case.proc_kind)
    code = _join_entries(entries, start_offset=case.start_offset, end_offset=case.end_offset)
    project = _project_from_bytes(code)
    block = project.factory.block(case.block_addr)
    irsb_text = block.vex._pp_str()

    expected_jumpkind = "Ijk_Ret" if case.name == "f14_get_cat_heading_segmented_add" else "Ijk_Boring"
    assert block.vex.jumpkind == expected_jumpkind
    _assert_irsb_contains(irsb_text, case.expected_tokens, case.original_c)


@pytest.mark.parametrize("case", QUERY_INTERRUPT_MATRIX_CASES, ids=lambda case: case.name)
def test_query_interrupt_block_lift_matrix(case: MatrixBlockLiftCase):
    entries = _extract_cod_function(case.cod_name, case.proc_name, cod_dir=_X16_SAMPLES_DIR, proc_kind=case.proc_kind)
    code = _join_entries(entries, start_offset=case.start_offset, end_offset=case.end_offset)
    project = _project_from_bytes(code)
    block = project.factory.block(0x1000)
    irsb_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Boring"
    _assert_irsb_contains(irsb_text, case.expected_tokens, case.original_c)


@pytest.mark.parametrize("case", QUERY_INTERRUPT_INT21_VECTOR_MATRIX_CASES, ids=lambda case: case.name)
def test_query_interrupt_int21_vector_block_lift_matrix(case: MatrixBlockLiftCase):
    entries = _extract_cod_function(case.cod_name, case.proc_name, cod_dir=_X16_SAMPLES_DIR, proc_kind=case.proc_kind)
    code = _join_entries(entries, start_offset=case.start_offset, end_offset=case.end_offset)
    project = _project_from_bytes(code)
    block = project.factory.block(0x1000)
    irsb_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Boring"
    _assert_irsb_contains(irsb_text, case.expected_tokens, case.original_c)


@pytest.mark.parametrize("case", SHOW_SUMMARY_MATRIX_CASES, ids=lambda case: case.name)
def test_show_summary_block_lift_matrix(case: MatrixBlockLiftCase):
    entries = _extract_cod_function(case.cod_name, case.proc_name, cod_dir=_X16_SAMPLES_DIR, proc_kind=case.proc_kind)
    code = _join_entries(entries, start_offset=case.start_offset, end_offset=case.end_offset)
    project = _project_from_bytes(code)
    block = project.factory.block(0x1000)
    irsb_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Boring"
    _assert_irsb_contains(irsb_text, case.expected_tokens, case.original_c)


@pytest.mark.parametrize("case", MAIN_FOLD_VALUES_ARG_MATRIX_CASES, ids=lambda case: case.name)
def test_main_fold_values_arg_block_lift_matrix(case: MatrixBlockLiftCase):
    entries = _extract_cod_function(case.cod_name, case.proc_name, cod_dir=_X16_SAMPLES_DIR, proc_kind=case.proc_kind)
    code = _join_entries(entries, start_offset=case.start_offset, end_offset=case.end_offset)
    project = _project_from_bytes(code)
    block = project.factory.block(0x1000)
    irsb_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Boring"
    _assert_irsb_contains(irsb_text, case.expected_tokens, case.original_c, case.expected_token_counts)


@pytest.mark.parametrize("case", MAIN_CALL_PREFIX_MATRIX_CASES, ids=lambda case: case.name)
def test_main_call_prefix_block_lift_matrix(case: MatrixBlockLiftCase):
    entries = _extract_cod_function(case.cod_name, case.proc_name, cod_dir=_X16_SAMPLES_DIR, proc_kind=case.proc_kind)
    code = _join_entries(entries, start_offset=case.start_offset, end_offset=case.end_offset)
    project = _project_from_bytes(code)
    block = project.factory.block(0x1000)
    irsb_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Call"
    _assert_irsb_contains(irsb_text, case.expected_tokens, case.original_c)


@pytest.mark.parametrize("case", FOLD_VALUES_BLOCK_MATRIX_CASES, ids=lambda case: case.name)
def test_fold_values_block_lift_matrix(case: MatrixBlockLiftCase):
    entries = _extract_cod_function(case.cod_name, case.proc_name, cod_dir=_X16_SAMPLES_DIR, proc_kind=case.proc_kind)
    code = _join_entries(entries, start_offset=case.start_offset, end_offset=case.end_offset)
    project = _project_from_bytes(code)
    block = project.factory.block(0x1000)
    irsb_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Boring"
    _assert_irsb_contains(irsb_text, case.expected_tokens, case.original_c)
