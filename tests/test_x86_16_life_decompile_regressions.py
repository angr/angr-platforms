from __future__ import annotations

from pathlib import Path

import inertia_decompiler.cli as decompile
import inertia_decompiler.sidecar_metadata as sidecar_metadata
from inertia_decompiler.source_sidecar import render_local_source_sidecar_function


REPO_ROOT = Path(__file__).resolve().parents[2]
LIFE_EXE = REPO_ROOT / "LIFE.EXE"


def test_life_rand_never_reports_ir_shaped_output_as_success() -> None:
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, project, allow_peer_exe=False)
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True,
        force_segment=True,
        resolve_indirect_jumps=False,
        show_progressbar=False,
        regions=[(0x11732, 0x1175E)],
    )
    function = cfg.kb.functions.floor_func(0x11732)

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=8,
        api_style="c",
        binary_path=LIFE_EXE,
        lst_metadata=metadata,
    )

    if status == "ok":
        assert "STORE(addr=" not in payload
        assert "Goto None" not in payload
    else:
        assert "unresolved IR-shaped C" in payload


def test_life_main_does_not_use_verbatim_source_sidecar() -> None:
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, project, allow_peer_exe=False)
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True,
        force_segment=True,
        resolve_indirect_jumps=False,
        show_progressbar=False,
        regions=[(0x10010, 0x10040)],
    )
    function = cfg.kb.functions.floor_func(0x10010)

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=8,
        api_style="c",
        binary_path=LIFE_EXE,
        lst_metadata=metadata,
    )

    source_text = render_local_source_sidecar_function(LIFE_EXE, "main")

    assert status in {"ok", "empty", "error", "timeout"}
    assert source_text is not None
    assert payload != source_text


def test_life_exit_refuses_ir_shaped_codegen_as_success() -> None:
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, project, allow_peer_exe=False)
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True,
        force_segment=True,
        resolve_indirect_jumps=False,
        show_progressbar=False,
        regions=[(0x1157C, 0x115A0)],
    )
    function = cfg.kb.functions.floor_func(0x1157C)

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=8,
        api_style="c",
        binary_path=LIFE_EXE,
        lst_metadata=metadata,
    )

    assert status != "ok"
    assert "unresolved IR-shaped C" in payload


def test_life_exit_nonoptimized_fallback_refuses_ir_shaped_output() -> None:
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, project, allow_peer_exe=False)

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1157C,
        "exit",
        timeout=8,
        api_style="c",
        binary_path=LIFE_EXE,
        lst_metadata=metadata,
    )

    assert outcome.status != "ok"
    assert outcome.rendered is None
    assert "unresolved" in outcome.payload.lower()


def test_life_pause_screen_does_not_use_verbatim_source_sidecar() -> None:
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, project, allow_peer_exe=False)
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True,
        force_segment=True,
        resolve_indirect_jumps=False,
        show_progressbar=False,
        regions=[(0x107E3, 0x1092B)],
    )
    function = cfg.kb.functions.floor_func(0x107E3)

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=8,
        api_style="c",
        binary_path=LIFE_EXE,
        lst_metadata=metadata,
    )

    source_text = render_local_source_sidecar_function(LIFE_EXE, "pause_screen")

    assert source_text is not None
    assert payload != source_text


def test_life_timer_does_not_use_verbatim_source_sidecar() -> None:
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, project, allow_peer_exe=False)
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True,
        force_segment=True,
        resolve_indirect_jumps=False,
        show_progressbar=False,
        regions=[(0x10467, 0x104B3)],
    )
    function = cfg.kb.functions.floor_func(0x10467)

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=8,
        api_style="c",
        binary_path=LIFE_EXE,
        lst_metadata=metadata,
    )

    source_text = render_local_source_sidecar_function(LIFE_EXE, "timer")

    assert source_text is not None
    assert payload != source_text


def test_life_rand_dist_does_not_use_verbatim_source_sidecar() -> None:
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, project, allow_peer_exe=False)
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True,
        force_segment=True,
        resolve_indirect_jumps=False,
        show_progressbar=False,
        regions=[(0x103AB, 0x103F3)],
    )
    function = cfg.kb.functions.floor_func(0x103AB)

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=8,
        api_style="c",
        binary_path=LIFE_EXE,
        lst_metadata=metadata,
    )

    source_text = render_local_source_sidecar_function(LIFE_EXE, "rand_dist")

    assert source_text is not None
    assert payload != source_text


def test_life_clear_mat_uses_compact_string_intrinsic_rendering() -> None:
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    payload = decompile._try_emit_string_intrinsic_c(project, start=0x10AB1, end=0x10AC5, name="clear_mat")

    assert payload is not None
    assert "void __x86_16_stos(unsigned short width);" in payload
    assert "__x86_16_stos(1);" in payload
    assert "__x86_16_string_state" not in payload
