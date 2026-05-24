from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import angr
import pytest

from angr_platforms.X86_16.analysis_helpers import (
    collect_direct_far_call_targets,
    collect_dos_int21_calls,
    extend_cfg_for_far_calls,
    infer_com_region,
    patch_dos_int21_call_sites,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.load_dos_mz import DOSMZ  # noqa: F401

MATRIX_DIR = Path(__file__).resolve().parents[1] / "x16_samples"
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import decompile

MANIFEST_PATH = MATRIX_DIR / "matrix_manifest.json"
EXPECTED_EXE_VARIANTS = {
    ("ISOD", "small", "/Od"),
    ("ISOT", "small", "/Ot"),
    ("ISOX", "small", "/Ox"),
    ("IMOD", "medium", "/Od"),
    ("IMOT", "medium", "/Ot"),
    ("IMOX", "medium", "/Ox"),
    ("ILOD", "large", "/Od"),
    ("ILOT", "large", "/Ot"),
    ("IHOD", "huge", "/Od"),
    ("IHOT", "huge", "/Ot"),
}
EXPECTED_COM_VARIANTS = {
    ("ICOMDO", "tiny", "n/a"),
    ("ICOMBI", "tiny", "n/a"),
}


def _load_manifest():
    return json.loads(MANIFEST_PATH.read_text())


def _decompile_entry_function(binary_name: str, window: int = 0x200, api_style: str | None = None):
    path = MATRIX_DIR / binary_name
    if binary_name.lower().endswith(".com"):
        project = angr.Project(
            path,
            main_opts={
                "backend": "blob",
                "arch": Arch86_16(),
                "base_addr": 0x1000,
                "entry_point": 0x1000,
            },
            simos="DOS",
        )
        regions = [infer_com_region(path, base_addr=0x1000, window=window, arch=project.arch)]
    else:
        project = angr.Project(path)
        regions = [(project.entry, project.entry + window)]

    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[project.entry],
        regions=regions,
        normalize=True,
        force_complete_scan=False,
    )
    if project.arch.name == "86_16":
        extended_cfg = extend_cfg_for_far_calls(project, cfg.functions[project.entry], entry_window=window)
        if extended_cfg is not None and project.entry in extended_cfg.functions:
            cfg = extended_cfg

    function = cfg.functions[project.entry]
    dec = project.analyses.Decompiler(function, cfg=cfg)
    if dec.codegen is None:
        return None
    patch_dos_int21_call_sites(function, path)
    if api_style is not None and decompile._attach_dos_pseudo_callees(project, function, dec.codegen, api_style):
        dec.codegen.regenerate_text()
    text = dec.codegen.text
    if api_style is not None:
        text = decompile._format_known_helper_calls(project, function, text, api_style, path)
    return text


@pytest.mark.skipif(not MANIFEST_PATH.exists(), reason="sample matrix manifest is not available")
def test_sample_matrix_manifest_has_expected_variant_mix():
    entries = _load_manifest()
    exe_entries = [entry for entry in entries if entry["format"] == "exe"]
    com_entries = [entry for entry in entries if entry["format"] == "com"]
    exe_variants = {(entry["id"], entry["memory_model"], entry["optimization"]) for entry in exe_entries}
    com_variants = {(entry["id"], entry["memory_model"], entry["optimization"]) for entry in com_entries}

    assert len(exe_entries) == 10
    assert len(com_entries) == 2
    assert exe_variants == EXPECTED_EXE_VARIANTS
    assert com_variants == EXPECTED_COM_VARIANTS

    for entry in exe_entries:
        assert (MATRIX_DIR / entry["binary"]).exists()
        assert (MATRIX_DIR / entry["object"]).exists()
        assert (MATRIX_DIR / entry["cod"]).exists()
        assert (MATRIX_DIR / entry["map"]).exists()
        assert entry["source"] == "IDEMO.C"
        assert entry["compiler"] == "msc510"

    for entry in com_entries:
        assert (MATRIX_DIR / entry["binary"]).exists()
        assert (MATRIX_DIR / entry["listing"]).exists()
        assert entry["compiler"] == "uasm"


@pytest.mark.skipif(not MANIFEST_PATH.exists(), reason="sample matrix manifest is not available")
def test_msc_exe_variants_load_with_dos_mz_backend():
    entries = _load_manifest()

    for entry in entries:
        if entry["format"] != "exe":
            continue

        project = angr.Project(MATRIX_DIR / entry["binary"])
        cod_text = (MATRIX_DIR / entry["cod"]).read_text(errors="ignore")
        block = project.factory.block(project.entry, size=16)
        asm = "\n".join(f"{insn.mnemonic} {insn.op_str}".strip() for insn in block.capstone.insns).lower()

        assert isinstance(project.loader.main_object, DOSMZ)
        assert project.arch.name == "86_16"
        assert "_main" in cod_text.lower()
        assert "idemo.c" in cod_text.lower()
        assert any(name in cod_text.lower() for name in ("_int86", "_int86x", "int86", "int86x"))
        assert "int 0x21" in asm


@pytest.mark.skipif(not MANIFEST_PATH.exists(), reason="sample matrix manifest is not available")
def test_com_variants_disassemble_as_real_mode_blobs():
    entries = _load_manifest()

    for entry in entries:
        if entry["format"] != "com":
            continue

        project = angr.Project(
            MATRIX_DIR / entry["binary"],
            main_opts={
                "backend": "blob",
                "arch": Arch86_16(),
                "base_addr": 0x1000,
                "entry_point": 0x1000,
            },
            simos="DOS",
        )
        block = project.factory.block(0x1000, size=16)
        asm = "\n".join(f"{insn.mnemonic} {insn.op_str}".strip() for insn in block.capstone.insns).lower()

        assert project.arch.name == "86_16"
        assert "int " in asm


def test_small_model_rep_cmps_block_lifts():
    project = angr.Project(MATRIX_DIR / "ISOD.EXE")

    block = project.factory.block(0x1267, size=8, opt_level=0)
    asm = "\n".join(f"{insn.mnemonic} {insn.op_str}".strip() for insn in block.capstone.insns).lower()

    assert "cmpsb" in asm
    assert block.vex.jumpkind == "Ijk_Boring"


def test_medium_model_global_add_block_lifts():
    project = angr.Project(MATRIX_DIR / "IMOD.EXE")

    block = project.factory.block(0x1682, size=4, opt_level=0)
    vex_text = block.vex._pp_str()

    assert "add word ptr [0x62], dx" in "\n".join(
        f"{insn.mnemonic} {insn.op_str}".strip().lower() for insn in block.capstone.insns
    )
    assert "Add16" in vex_text
    assert block.vex.jumpkind == "Ijk_Boring"


def test_medium_model_entry_far_call_targets_are_discoverable():
    project = angr.Project(MATRIX_DIR / "IMOD.EXE")
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[project.entry],
        regions=[(project.entry, project.entry + 0x200)],
        normalize=True,
        force_complete_scan=False,
    )

    far_targets = collect_direct_far_call_targets(cfg.functions[project.entry])

    assert len(far_targets) >= 12
    assert {target.target_addr for target in far_targets} >= {0x111A, 0x121E, 0x12E2, 0x1380, 0x13F4, 0x1586, 0x161F}


def test_medium_model_entry_far_call_sites_are_patched():
    project = angr.Project(MATRIX_DIR / "IMOD.EXE")
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[project.entry],
        regions=[(project.entry, project.entry + 0x200)],
        normalize=True,
        force_complete_scan=False,
    )
    extended_cfg = extend_cfg_for_far_calls(project, cfg.functions[project.entry], entry_window=0x200)

    assert extended_cfg is not None
    function = extended_cfg.functions[project.entry]
    assert function.get_call_target(0x117E) == 0x1380


def test_cod_access_traits_are_collected_for_segmented_proc():
    proc_path = REPO_ROOT / "cod" / "f14" / "COCKPIT.COD"
    entries = decompile.extract_cod_function_entries(proc_path, "_TIDShowRange", "NEAR")
    cod_metadata = decompile.extract_cod_proc_metadata(proc_path, "_TIDShowRange", "NEAR")
    selected_entries = decompile.extract_small_two_arg_cod_logic_entries(entries)
    if selected_entries is None:
        selected_entries = decompile.extract_simple_cod_logic_entries(entries)
    if selected_entries is None:
        proc_code, synthetic_globals = decompile.join_cod_entries_with_synthetic_globals(
            entries,
            start_offset=decompile.infer_cod_logic_start(entries),
        )
    else:
        proc_code, synthetic_globals = decompile.join_cod_entries_with_synthetic_globals(selected_entries)

    project = decompile._build_project_from_bytes(proc_code, base_addr=0x1000, entry_point=0x1000)
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[project.entry],
        regions=[(project.entry, project.entry + len(proc_code))],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[project.entry]

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=10,
        api_style="modern",
        binary_path=proc_path,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
    )

    assert status == "ok", payload
    traits = getattr(project, "_inertia_access_traits", {})
    function_traits = traits.get(function.addr)
    assert function_traits is not None
    assert function_traits["base_stride"]
    assert any(key[0] == "ss" and key[2] == 16 and key[3] == 0 and key[4] == 2 for key in function_traits["base_stride"])
    assert function_traits["induction_evidence"]
    assert any(
        evidence.index_key == ("reg", 30)
        and evidence.stride == 16
        and evidence.offset == 0
        and evidence.width == 2
        and evidence.count >= 1
        for evidence in function_traits["induction_evidence"].values()
    )
    assert function_traits["member_evidence"]
    assert any(
        key[0] == ("reg", 6) and key[1] in {782, 783} and key[2] in {1, 2}
        for key in function_traits["member_evidence"]
    )


def test_small_model_entry_function_decompiles_in_bounded_window():
    recovered_c = _decompile_entry_function("ISOD.EXE")

    assert recovered_c is not None
    assert "520" in recovered_c


def test_small_model_entry_function_formats_pseudo_dos_helpers():
    recovered_c = _decompile_entry_function("ISOD.EXE", api_style="pseudo")

    assert recovered_c is not None
    assert "int dos_get_version(void);" in recovered_c
    assert "int dos_setblock(void);" in recovered_c
    assert "void dos_exit(int status);" in recovered_c
    assert "dos_get_version()" in recovered_c
    assert "dos_exit(255)" in recovered_c
    assert "dos_setblock()" in recovered_c


def test_com_entry_function_attaches_pseudo_callees_before_final_rendering():
    path = MATRIX_DIR / "ICOMDO.COM"
    project = angr.Project(
        path,
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        simos="DOS",
    )
    regions = [infer_com_region(path, base_addr=0x1000, window=0x80, arch=project.arch)]
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[project.entry],
        regions=regions,
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[project.entry]
    patch_dos_int21_call_sites(function, path)
    dec = project.analyses.Decompiler(function, cfg=cfg)

    assert dec.codegen is not None
    assert "1044513();" in dec.codegen.text
    assert decompile._attach_dos_pseudo_callees(project, function, dec.codegen, "pseudo") is True

    dec.codegen.regenerate_text()

    assert "dos_get_version();" in dec.codegen.text
    assert "dos_print_dollar_string();" in dec.codegen.text
    assert "dos_exit();" in dec.codegen.text


def test_small_model_entry_dos_int21_calls_are_recoverable():
    project = angr.Project(MATRIX_DIR / "ISOD.EXE")
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[0x1146],
        regions=[(0x1146, 0x1146 + 0x200)],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[0x1146]

    calls = collect_dos_int21_calls(function, MATRIX_DIR / "ISOD.EXE")

    assert [call.insn_addr for call in calls] == [0x1148, 0x117A, 0x11A2]
    assert [call.ah for call in calls] == [0x30, 0x4C, 0x4A]


def test_small_model_entry_dos_int21_calls_map_to_named_helpers():
    project = angr.Project(MATRIX_DIR / "ISOD.EXE")
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[0x1146],
        regions=[(0x1146, 0x1146 + 0x200)],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[0x1146]

    replacements = decompile._int21_call_replacements(project, function, "modern", MATRIX_DIR / "ISOD.EXE")

    assert replacements == ["get_dos_version()", "exit(255)", "resize_dos_memory_block()"]


def test_medium_model_entry_function_decompiles_in_bounded_window():
    recovered_c = _decompile_entry_function("IMOD.EXE")

    assert recovered_c is not None
    assert "526" in recovered_c
    assert "sub_1380()" in recovered_c
    assert "sub_161f()" in recovered_c


def test_com_entry_function_decompiles_without_trailing_data_junk():
    recovered_c = _decompile_entry_function("ICOMDO.COM", window=0x80)

    assert recovered_c is not None
    assert "field_61" not in recovered_c
    assert "insw" not in recovered_c


def test_medium_model_far_call_sites_stop_logging_unknown_cc(caplog):
    project = angr.Project(MATRIX_DIR / "IMOD.EXE")
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[project.entry],
        regions=[(project.entry, project.entry + 0x200)],
        normalize=True,
        force_complete_scan=False,
    )
    extended_cfg = extend_cfg_for_far_calls(project, cfg.functions[project.entry], entry_window=0x200)
    assert extended_cfg is not None

    with caplog.at_level(logging.WARNING):
        function = extended_cfg.functions[project.entry]
        project.analyses.Decompiler(function, cfg=extended_cfg)

    warning_text = "\n".join(record.getMessage() for record in caplog.records)
    assert "Call site 0x117e" not in warning_text
    assert "Call site 0x1185" not in warning_text
    assert "Call site 0x11ce" not in warning_text
    assert "Call site 0x11d5" not in warning_text
    assert "Call site 0x11dc" not in warning_text
    assert "Call site 0x11e1" not in warning_text
    assert "Call site 0x11f4" not in warning_text
    assert "Call site 0x11fa" not in warning_text
    assert "Call site 0x1209" not in warning_text
    assert "Call site 0x1214" not in warning_text


def test_synthetic_com_dos_file_services_map_to_named_helpers(tmp_path):
    code = bytearray(
        [
            0xB4,
            0x3D,  # mov ah, 3Dh
            0xB0,
            0x01,  # mov al, 1
            0xBA,
            0x30,
            0x01,  # mov dx, 130h
            0xCD,
            0x21,  # int 21h
            0xB4,
            0x3C,  # mov ah, 3Ch
            0xB9,
            0x20,
            0x00,  # mov cx, 20h
            0xBA,
            0x40,
            0x01,  # mov dx, 140h
            0xCD,
            0x21,  # int 21h
            0xB4,
            0x3E,  # mov ah, 3Eh
            0xBB,
            0x42,
            0x00,  # mov bx, 42h
            0xCD,
            0x21,  # int 21h
            0xB8,
            0x00,
            0x4C,  # mov ax, 4C00h
            0xCD,
            0x21,  # int 21h
        ]
    )
    while len(code) < 0x30:
        code.append(0)
    code.extend(b"INPUT.TXT\x00")
    while len(code) < 0x40:
        code.append(0)
    code.extend(b"OUTPUT.BIN\x00")

    binary_path = tmp_path / "dos_file_calls.com"
    binary_path.write_bytes(bytes(code))

    project = angr.Project(
        binary_path,
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        simos="DOS",
    )
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[0x1000],
        regions=[(0x1000, 0x1020)],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[0x1000]

    calls = collect_dos_int21_calls(function, binary_path)
    modern = decompile._int21_call_replacements(project, function, "modern", binary_path)
    dos = decompile._int21_call_replacements(project, function, "dos", binary_path)
    modern_decls = decompile._dos_helper_declarations(function, "modern", binary_path)
    dos_decls = decompile._dos_helper_declarations(function, "dos", binary_path)

    assert [call.ah for call in calls] == [0x3D, 0x3C, 0x3E, 0x4C]
    assert modern == [
        'open("INPUT.TXT", 1)',
        'creat("OUTPUT.BIN", 0x20)',
        "close(0x42)",
        "exit(0)",
    ]
    assert dos == [
        '_dos_open("INPUT.TXT", 1)',
        '_dos_creat("OUTPUT.BIN", 0x20)',
        "_dos_close(0x42)",
        "_dos_exit(0)",
    ]
    assert "int open(const char *path, int oflag);" in modern_decls
    assert "int creat(const char *path, int attrs);" in modern_decls
    assert "int close(int fd);" in modern_decls
    assert "int _dos_open(const char far *path, unsigned char mode);" in dos_decls
    assert "int _dos_creat(const char far *path, unsigned short attrs);" in dos_decls
    assert "int _dos_close(unsigned short handle);" in dos_decls


def test_synthetic_bp_based_dos_open_call_recovers_argument_shapes(tmp_path):
    code = bytes(
        [
            0x55,  # push bp
            0x89,
            0xE5,  # mov bp, sp
            0xB4,
            0x3D,  # mov ah, 3Dh
            0x8A,
            0x46,
            0x06,  # mov al, [bp+6]
            0x8B,
            0x56,
            0x04,  # mov dx, [bp+4]
            0xCD,
            0x21,  # int 21h
            0xC3,  # ret
        ]
    )
    binary_path = tmp_path / "bp_open.bin"
    binary_path.write_bytes(code)

    project = angr.Project(
        binary_path,
        auto_load_libs=False,
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[0x1000],
        regions=[(0x1000, 0x1010)],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[0x1000]

    calls = collect_dos_int21_calls(function)
    modern = decompile._int21_call_replacements(project, function, "modern", None)
    dos = decompile._int21_call_replacements(project, function, "dos", None)

    assert len(calls) == 1
    assert calls[0].ah == 0x3D
    assert calls[0].al_expr == "[bp+6]"
    assert calls[0].dx_expr == "[bp+4]"
    assert modern == ["open((const char *)[bp+4], [bp+6])"]
    assert dos == ["_dos_open((const char far *)[bp+4], [bp+6])"]


def test_synthetic_dos_read_write_seek_helpers_map_to_named_calls(tmp_path):
    code = bytes(
        [
            0xB4,
            0x3F,  # mov ah, 3Fh
            0xBB,
            0x03,
            0x00,  # mov bx, 3
            0xB9,
            0x10,
            0x00,  # mov cx, 10h
            0xBA,
            0x30,
            0x01,  # mov dx, 130h
            0xCD,
            0x21,  # int 21h
            0xB4,
            0x40,  # mov ah, 40h
            0xBB,
            0x04,
            0x00,  # mov bx, 4
            0xB9,
            0x20,
            0x00,  # mov cx, 20h
            0xBA,
            0x40,
            0x01,  # mov dx, 140h
            0xCD,
            0x21,  # int 21h
            0xB4,
            0x42,  # mov ah, 42h
            0xB0,
            0x02,  # mov al, 2
            0xBB,
            0x04,
            0x00,  # mov bx, 4
            0xB9,
            0x34,
            0x12,  # mov cx, 1234h
            0xBA,
            0x78,
            0x56,  # mov dx, 5678h
            0xCD,
            0x21,  # int 21h
            0xC3,
        ]
    )
    binary_path = tmp_path / "dos_io_family.bin"
    binary_path.write_bytes(code)

    project = angr.Project(
        binary_path,
        auto_load_libs=False,
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[0x1000],
        regions=[(0x1000, 0x1030)],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[0x1000]

    calls = collect_dos_int21_calls(function)
    modern = decompile._int21_call_replacements(project, function, "modern", None)
    dos = decompile._int21_call_replacements(project, function, "dos", None)
    modern_decls = decompile._dos_helper_declarations(function, "modern", None)
    dos_decls = decompile._dos_helper_declarations(function, "dos", None)

    assert [call.ah for call in calls] == [0x3F, 0x40, 0x42]
    assert modern == [
        "read(3, (void *)0x130, 0x10)",
        "write(4, (const void *)0x140, 0x20)",
        "lseek(4, 0x12345678, 2)",
    ]
    assert dos == [
        "_dos_read(3, (void far *)0x130, 0x10)",
        "_dos_write(4, (const void far *)0x140, 0x20)",
        "_dos_seek(4, 0x12345678, 2)",
    ]
    assert "int read(int fd, void *buf, unsigned int count);" in modern_decls
    assert "int write(int fd, const void *buf, unsigned int count);" in modern_decls
    assert "long lseek(int fd, long offset, int whence);" in modern_decls
    assert "int _dos_read(unsigned short handle, void far *buffer, unsigned short count);" in dos_decls
    assert "int _dos_write(unsigned short handle, const void far *buffer, unsigned short count);" in dos_decls
    assert "long _dos_seek(unsigned short handle, long offset, unsigned char origin);" in dos_decls


def test_synthetic_bp_based_dos_seek_call_recovers_argument_shapes(tmp_path):
    code = bytes(
        [
            0x55,  # push bp
            0x89,
            0xE5,  # mov bp, sp
            0xB4,
            0x42,  # mov ah, 42h
            0x8A,
            0x46,
            0x0A,  # mov al, [bp+0Ah]
            0x8B,
            0x5E,
            0x04,  # mov bx, [bp+4]
            0x8B,
            0x4E,
            0x06,  # mov cx, [bp+6]
            0x8B,
            0x56,
            0x08,  # mov dx, [bp+8]
            0xCD,
            0x21,  # int 21h
            0xC3,
        ]
    )
    binary_path = tmp_path / "bp_seek.bin"
    binary_path.write_bytes(code)

    project = angr.Project(
        binary_path,
        auto_load_libs=False,
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[0x1000],
        regions=[(0x1000, 0x1020)],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[0x1000]

    calls = collect_dos_int21_calls(function)
    modern = decompile._int21_call_replacements(project, function, "modern", None)
    dos = decompile._int21_call_replacements(project, function, "dos", None)

    assert len(calls) == 1
    assert calls[0].ah == 0x42
    assert calls[0].al_expr == "[bp+0xa]"
    assert calls[0].bx_expr == "[bp+4]"
    assert calls[0].cx_expr == "[bp+6]"
    assert calls[0].dx_expr == "[bp+8]"
    assert modern == ["lseek([bp+4], MK_LONG([bp+8], [bp+6]), [bp+0xa])"]
    assert dos == ["_dos_seek([bp+4], MK_LONG([bp+8], [bp+6]), [bp+0xa])"]


def test_synthetic_dos_filesystem_helpers_map_to_named_calls(tmp_path):
    code = bytearray(
        [
            0xB4,
            0x39,  # mov ah, 39h
            0xBA,
            0x30,
            0x01,  # mov dx, 130h
            0xCD,
            0x21,  # int 21h
            0xB4,
            0x3A,  # mov ah, 3Ah
            0xBA,
            0x40,
            0x01,  # mov dx, 140h
            0xCD,
            0x21,  # int 21h
            0xB4,
            0x3B,  # mov ah, 3Bh
            0xBA,
            0x50,
            0x01,  # mov dx, 150h
            0xCD,
            0x21,  # int 21h
            0xB4,
            0x41,  # mov ah, 41h
            0xBA,
            0x60,
            0x01,  # mov dx, 160h
            0xCD,
            0x21,  # int 21h
            0xC3,
        ]
    )
    while len(code) < 0x30:
        code.append(0)
    code.extend(b"DIR1\x00")
    while len(code) < 0x40:
        code.append(0)
    code.extend(b"DIR2\x00")
    while len(code) < 0x50:
        code.append(0)
    code.extend(b"DIR3\x00")
    while len(code) < 0x60:
        code.append(0)
    code.extend(b"OLD.DAT\x00")

    binary_path = tmp_path / "dos_fs_helpers.com"
    binary_path.write_bytes(bytes(code))

    project = angr.Project(
        binary_path,
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        simos="DOS",
    )
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[0x1000],
        regions=[(0x1000, 0x1020)],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[0x1000]

    calls = collect_dos_int21_calls(function, binary_path)
    modern = decompile._int21_call_replacements(project, function, "modern", binary_path)
    dos = decompile._int21_call_replacements(project, function, "dos", binary_path)
    modern_decls = decompile._dos_helper_declarations(function, "modern", binary_path)
    dos_decls = decompile._dos_helper_declarations(function, "dos", binary_path)

    assert [call.ah for call in calls] == [0x39, 0x3A, 0x3B, 0x41]
    assert modern == ['mkdir("DIR1")', 'rmdir("DIR2")', 'chdir("DIR3")', 'unlink("OLD.DAT")']
    assert dos == ['_dos_mkdir("DIR1")', '_dos_rmdir("DIR2")', '_dos_chdir("DIR3")', '_dos_unlink("OLD.DAT")']
    assert "int mkdir(const char *path);" in modern_decls
    assert "int rmdir(const char *path);" in modern_decls
    assert "int chdir(const char *path);" in modern_decls
    assert "int unlink(const char *path);" in modern_decls
    assert "int _dos_mkdir(const char far *path);" in dos_decls
    assert "int _dos_rmdir(const char far *path);" in dos_decls
    assert "int _dos_chdir(const char far *path);" in dos_decls
    assert "int _dos_unlink(const char far *path);" in dos_decls


def test_synthetic_bp_based_dos_unlink_call_recovers_argument_shape(tmp_path):
    code = bytes(
        [
            0x55,  # push bp
            0x89,
            0xE5,  # mov bp, sp
            0xB4,
            0x41,  # mov ah, 41h
            0x8B,
            0x56,
            0x04,  # mov dx, [bp+4]
            0xCD,
            0x21,  # int 21h
            0xC3,
        ]
    )
    binary_path = tmp_path / "bp_unlink.bin"
    binary_path.write_bytes(code)

    project = angr.Project(
        binary_path,
        auto_load_libs=False,
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[0x1000],
        regions=[(0x1000, 0x1010)],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[0x1000]

    calls = collect_dos_int21_calls(function)
    modern = decompile._int21_call_replacements(project, function, "modern", None)
    dos = decompile._int21_call_replacements(project, function, "dos", None)

    assert len(calls) == 1
    assert calls[0].ah == 0x41
    assert calls[0].dx_expr == "[bp+4]"
    assert modern == ["unlink((const char *)[bp+4])"]
    assert dos == ["_dos_unlink((const char far *)[bp+4])"]


def test_synthetic_dos_drive_and_cwd_helpers_map_to_named_calls(tmp_path):
    code = bytes(
        [
            0xB4,
            0x0E,  # mov ah, 0Eh
            0xB2,
            0x02,  # mov dl, 2
            0xCD,
            0x21,  # int 21h
            0xB4,
            0x47,  # mov ah, 47h
            0xB2,
            0x01,  # mov dl, 1
            0xBE,
            0x80,
            0x01,  # mov si, 180h
            0xCD,
            0x21,  # int 21h
            0xC3,
        ]
    )
    binary_path = tmp_path / "dos_drive_cwd.bin"
    binary_path.write_bytes(code)

    project = angr.Project(
        binary_path,
        auto_load_libs=False,
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[0x1000],
        regions=[(0x1000, 0x1020)],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[0x1000]

    calls = collect_dos_int21_calls(function)
    modern = decompile._int21_call_replacements(project, function, "modern", None)
    dos = decompile._int21_call_replacements(project, function, "dos", None)
    pseudo = decompile._int21_call_replacements(project, function, "pseudo", None)

    assert [call.ah for call in calls] == [0x0E, 0x47]
    assert modern == ["set_current_drive(2)", "get_current_directory(1, (char *)0x180)"]
    assert dos == ["_dos_setdrive(2)", "_dos_getcwd(1, (char far *)0x180)"]
    assert pseudo == ["dos_set_current_drive(2)", "dos_get_current_directory(1, (char *)0x180)"]


def test_synthetic_bp_based_dos_getcwd_call_recovers_argument_shapes(tmp_path):
    code = bytes(
        [
            0x55,  # push bp
            0x89,
            0xE5,  # mov bp, sp
            0xB4,
            0x47,  # mov ah, 47h
            0x8A,
            0x56,
            0x04,  # mov dl, [bp+4]
            0x8B,
            0x76,
            0x06,  # mov si, [bp+6]
            0xCD,
            0x21,  # int 21h
            0xC3,
        ]
    )
    binary_path = tmp_path / "bp_getcwd.bin"
    binary_path.write_bytes(code)

    project = angr.Project(
        binary_path,
        auto_load_libs=False,
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[0x1000],
        regions=[(0x1000, 0x1010)],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[0x1000]

    calls = collect_dos_int21_calls(function)
    modern = decompile._int21_call_replacements(project, function, "modern", None)
    dos = decompile._int21_call_replacements(project, function, "dos", None)

    assert len(calls) == 1
    assert calls[0].ah == 0x47
    assert calls[0].dl_expr == "[bp+4]"
    assert calls[0].si_expr == "[bp+6]"
    assert modern == ["get_current_directory([bp+4], (char *)[bp+6])"]
    assert dos == ["_dos_getcwd([bp+4], (char far *)[bp+6])"]
