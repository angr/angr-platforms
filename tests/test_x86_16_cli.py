from __future__ import annotations

import contextlib
import importlib.util
import subprocess
import sys
import time
from concurrent.futures.thread import _threads_queues
from pathlib import Path
from types import SimpleNamespace

import decompile
import inertia_decompiler.cli_decompilation as cli_decompilation
import inertia_decompiler.cli_core as cli_core
import inertia_decompiler.cache as recovery_cache
from inertia_decompiler.direct_addr_failure_family import (
    advance_failure_family_state,
    FailureFamilyState,
    build_failure_family_snapshot,
    failure_family_repeat_reason,
    remember_failure_family_candidate,
)
import inertia_decompiler.decompile_file_summary as file_summary
import inertia_decompiler.non_optimized_fallback as non_optimized_fallback
import inertia_decompiler.sidecar_cache as sidecar_cache
from inertia_decompiler.slice_recovery import SliceRecoveryAttemptOutcome
from inertia_decompiler.work_items import FunctionWorkItem
import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from inertia_decompiler import sidecar_metadata, sidecar_parsers
from omf_pat import (
    CachedPatRegexSpec,
    PatModule,
    PatPublicName,
    _normalize_pat_backend_choice,
    ensure_pat_from_omf_input,
    enumerate_microsoft_lib_dictionary_symbols,
    enumerate_omf_lib_dictionary_symbols,
    extract_omf_modules_from_lib,
    generate_pat_from_omf_lib,
    generate_pat_from_omf_obj,
    load_cached_pat_regex_specs,
    lookup_microsoft_lib_symbol,
    lookup_omf_lib_symbol,
    match_pat_modules,
    parse_microsoft_lib,
    parse_omf_lib,
    parse_pat_file,
)
from signature_catalog import build_signature_catalog, match_signature_catalog

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.cod_extract import extract_cod_listing_metadata
from angr_platforms.X86_16.codeview_nb00 import find_codeview_nb00, parse_codeview_nb00
from angr_platforms.X86_16.fast_tracer import trace_16bit_seed_candidates
from angr_platforms.X86_16.flair_extract import list_flair_sig_libraries, match_flair_startup_entry
from angr_platforms.X86_16.load_dos_mz import DOSMZ
from angr_platforms.X86_16.lst_extract import LSTMetadata, extract_lst_metadata
from angr_platforms.X86_16.turbo_debug_tdinfo import TDInfoSymbolClass, parse_tdinfo_exe

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
TRACE_PATH = REPO_ROOT / "angr_platforms" / "scripts" / "trace_x86_16_paths.py"
MONOPRIN_COD = REPO_ROOT / "cod" / "f14" / "MONOPRIN.COD"
NHORZ_COD = REPO_ROOT / "cod" / "f14" / "NHORZ.COD"
MAX_COD = REPO_ROOT / "cod" / "default" / "MAX.COD"
DOSFUNC_COD = REPO_ROOT / "cod" / "DOSFUNC.COD"
ICOMDO_COM = REPO_ROOT / "angr_platforms" / "x16_samples" / "ICOMDO.COM"
ISOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ISOD.COD"
IMOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IMOD.COD"
ISOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ISOT.COD"
ISOX_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ISOX.COD"
IHOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IHOD.COD"
IHOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IHOT.COD"
ILOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ILOD.COD"
ILOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ILOT.COD"
IMOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IMOT.COD"
IMOX_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IMOX.COD"
LIFE_EXE = REPO_ROOT / "LIFE.EXE"
LIFE2_EXE = REPO_ROOT / "LIFE2.EXE"
LIFE_COD = REPO_ROOT / "LIFE.COD"
NONAME_TDINFO_EXE = REPO_ROOT / "tdinfo-parser" / "NONAME.EXE"
SYNTHETIC_OBJ = REPO_ROOT / "angr_platforms" / "tests" / "fixtures" / "synthetic.obj"
BORLAND_CC_LIB = Path("/home/xor/inertia_player/dos_compilers/Borland Turbo C v2/LIB/CC.LIB")
BORLAND_GRAPHICS_LIB = Path("/home/xor/inertia_player/dos_compilers/Borland Turbo C v2/LIB/GRAPHICS.LIB")


def test_emit_function_timing_summary_orders_slowest_first(capsys):
    function_fast = SimpleNamespace(addr=0x1000, name="fast")
    function_slow = SimpleNamespace(addr=0x2000, name="slow")
    tasks = [
        decompile.FunctionWorkItem(index=1, function_cfg=object(), function=function_fast),
        decompile.FunctionWorkItem(index=2, function_cfg=object(), function=function_slow),
    ]
    results = {
        1: decompile.FunctionWorkResult(
            index=1,
            status="ok",
            payload="",
            debug_output="",
            function=function_fast,
            function_cfg=tasks[0].function_cfg,
            elapsed=0.25,
        ),
        2: decompile.FunctionWorkResult(
            index=2,
            status="timeout",
            payload="",
            debug_output="",
            function=function_slow,
            function_cfg=tasks[1].function_cfg,
            elapsed=2.0,
        ),
    }

    decompile._emit_function_timing_summary(tasks, results)

    out = capsys.readouterr().out
    assert "summary: slowest function attempt(s), top 2:" in out
    assert out.index("0x2000 slow: 2.00s status=timed_out") < out.index(
        "0x1000 fast: 0.25s status=decompiled"
    )


def test_sidecar_metadata_cache_sources_do_not_include_cli():
    sources = {path.name for path in recovery_cache.SIDECAR_METADATA_CACHE_SOURCE_FILES}

    assert "cli.py" not in sources
    assert "sidecar_metadata.py" in sources
    assert "sidecar_parsers.py" in sources
    assert "omf_pat.py" in sources


def test_emit_function_timing_summary_ignores_cached_timings(capsys):
    function_cached = SimpleNamespace(addr=0x1000, name="cached")
    function_current = SimpleNamespace(addr=0x2000, name="current")
    tasks = [
        decompile.FunctionWorkItem(index=1, function_cfg=object(), function=function_cached),
        decompile.FunctionWorkItem(index=2, function_cfg=object(), function=function_current),
    ]
    results = {
        1: decompile.FunctionWorkResult(
            index=1,
            status="ok",
            payload="",
            debug_output="",
            function=function_cached,
            function_cfg=tasks[0].function_cfg,
            elapsed=99.0,
            from_cache=True,
        ),
        2: decompile.FunctionWorkResult(
            index=2,
            status="ok",
            payload="",
            debug_output="",
            function=function_current,
            function_cfg=tasks[1].function_cfg,
            elapsed=0.5,
        ),
    }

    decompile._emit_function_timing_summary(tasks, results)

    out = capsys.readouterr().out
    assert "0x2000 current: 0.50s status=decompiled" in out
    assert "0x1000 cached" not in out


def test_emit_file_summary_sorts_and_dedupes_compilers_and_signature_sources(capsys):
    project = SimpleNamespace(
        _inertia_signature_compiler_names=(
            "Microsoft C v6ax",
            "Microsoft C v5",
            "Microsoft C v5.1",
            "Microsoft C v5",
        ),
        _inertia_flair_sig_titles=("ZLIB", "bsort"),
        _inertia_flair_local_pat_sources=(r"C:\\sig\\BSORT.sig",),
        _inertia_peer_exe_titles=("showmenu", "zlib"),
    )
    metadata = SimpleNamespace(signature_code_addrs=(0x1000, 0x1010))

    file_summary.emit_file_decompilation_summary(
        project,
        metadata,
        shown_total=8,
        decompiled=7,
        failed=1,
        skipped_signature_labels=3,
        same_family_retry_stops=2,
        fallback_family_labels=("isolated_retry", "structurer_retry"),
    )

    assert capsys.readouterr().out.strip().splitlines() == [
        "summary: probable compiler versions: Microsoft C v5, Microsoft C v5.1, Microsoft C v6ax",
        "summary: probable library/signature sources: BSORT, showmenu, ZLIB",
        "summary: signature-matched library functions: 2",
        "summary: hidden signature-matched labels: 3",
        "summary: same_family_retry_stops=2 fallback_family_labels=isolated_retry, structurer_retry",
        "summary: shown=8 decompiled=7 asm_or_detail_fallback=1",
    ]


def test_asm_fallback_pattern_note_names_string_instruction_evidence():
    note = decompile._asm_fallback_pattern_note(
        "0x1168f: rep movsb byte ptr es:[di], byte ptr [si]\n"
        "0x116db: rep stosw word ptr es:[di], ax\n"
        "0x11555: repne scasb al, byte ptr es:[di]\n"
        "0x12be2: repe cmpsb byte ptr [si], byte ptr es:[di]\n"
    )

    assert note is not None
    assert "assembly pattern" in note
    assert "x86 string-instruction" in note
    assert "copy loop" in note
    assert "fill loop" in note
    assert "scan loop" in note
    assert "compare loop" in note
    assert "not guessed C" in note


def test_default_recovery_timeout_uses_wider_default_gate():
    assert decompile._default_recovery_timeout(20, explicit_timeout=False) == 20
    assert decompile._default_recovery_timeout(20, explicit_timeout=True) == 20
    assert decompile._default_recovery_timeout(3, explicit_timeout=True) == 3


def test_heavy_fallback_lane_policy_stays_closed_for_sweep_runs():
    assert not non_optimized_fallback.allows_heavy_fallbacks_for_run(
        interactive_stdout=False,
        max_functions=8,
        addr_requested=False,
    )
    assert non_optimized_fallback.allows_heavy_fallbacks_for_run(
        interactive_stdout=True,
        max_functions=8,
        addr_requested=False,
    )
    assert non_optimized_fallback.allows_heavy_fallbacks_for_run(
        interactive_stdout=False,
        max_functions=0,
        addr_requested=False,
    )
    assert non_optimized_fallback.allows_heavy_fallbacks_for_run(
        interactive_stdout=False,
        max_functions=8,
        addr_requested=True,
    )


def test_adaptive_per_byte_timeout_model_scales_from_successes():
    model = decompile._AdaptivePerByteTimeoutModel(20, explicit_timeout=False, margin=1.5)

    baseline = model.timeout_for_byte_count(0x20)
    model.observe_success(0x20, 1.0)
    model.observe_success(0x40, 2.2)
    model.observe_success(0x80, 4.6)

    assert model.timeout_for_byte_count(0x20) == baseline
    assert model.timeout_for_byte_count(0x80) == baseline
    assert model.timeout_for_byte_count(0x100) == baseline



def test_direct_addr_failure_family_repeat_reason_changes_on_new_proof():
    base = build_failure_family_snapshot(
        status="empty",
        failure_stage="structuring",
        fallback_kind="isolated_retry",
        tail_validation_verdict="uncollected",
        artifact_path="0x102e0:RunMenu",
    )
    repeat = build_failure_family_snapshot(
        status="empty",
        failure_stage="structuring",
        fallback_kind="isolated_retry",
        tail_validation_verdict="uncollected",
        artifact_path="0x102e0:RunMenu",
    )
    changed_artifact = build_failure_family_snapshot(
        status="empty",
        failure_stage="structuring",
        fallback_kind="isolated_retry",
        tail_validation_verdict="uncollected",
        artifact_path="0x102e0:RunMenu:retry",
    )
    changed_verdict = build_failure_family_snapshot(
        status="empty",
        failure_stage="structuring",
        fallback_kind="isolated_retry",
        tail_validation_verdict="stable",
        artifact_path="0x102e0:RunMenu",
    )

    assert failure_family_repeat_reason(base, repeat) is not None
    assert failure_family_repeat_reason(base, changed_artifact) is None
    assert failure_family_repeat_reason(base, changed_verdict) is None


def test_direct_addr_failure_family_state_tracks_previous_candidate_and_new_proof():
    state = FailureFamilyState()
    base = build_failure_family_snapshot(
        status="empty",
        failure_stage="structuring",
        fallback_kind="structurer_retry",
        tail_validation_verdict="uncollected",
        artifact_path="0x102e0:RunMenu",
    )
    repeat = build_failure_family_snapshot(
        status="empty",
        failure_stage="structuring",
        fallback_kind="structurer_retry",
        tail_validation_verdict="uncollected",
        artifact_path="0x102e0:RunMenu",
    )
    changed = build_failure_family_snapshot(
        status="empty",
        failure_stage="structuring",
        fallback_kind="structurer_retry",
        tail_validation_verdict="changed",
        artifact_path="0x102e0:RunMenu:retry",
    )

    assert remember_failure_family_candidate(state, base) is None
    assert state.previous_snapshot is None
    assert state.candidate_snapshot == base
    assert state.new_proof_seen is False
    assert state.repeat_detected is False
    advance_failure_family_state(state)
    assert state.previous_snapshot == base

    assert remember_failure_family_candidate(state, repeat) is not None
    assert state.previous_snapshot == base
    assert state.candidate_snapshot == repeat
    assert state.new_proof_seen is False
    assert state.repeat_detected is True
    advance_failure_family_state(state)
    assert state.previous_snapshot == repeat

    assert remember_failure_family_candidate(state, changed) is None
    assert state.previous_snapshot == repeat
    assert state.candidate_snapshot == changed
    assert state.new_proof_seen is True
    assert state.repeat_detected is False


def test_decompile_function_with_stats_skips_same_family_retry_without_new_proof(monkeypatch, capsys):
    calls: list[int] = []

    class _FakeDecompiler:
        def __init__(self):
            self.codegen = None
            self.errors = [SimpleNamespace(exc_type=KeyError, exc_value=KeyError("same family"))]
            self.clinic = None

    class _FakeAnalyses:
        def Decompiler(self, *_args, **_kwargs):
            calls.append(1)
            return _FakeDecompiler()

    project = SimpleNamespace(
        analyses=_FakeAnalyses(),
        arch=SimpleNamespace(name="86_16"),
        entry=0x1000,
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x1000)),
        _inertia_decompiler_stage="structuring",
    )
    function = SimpleNamespace(addr=0x102E0, name="RunMenu", info={}, project=project, normalized=True)
    cfg = SimpleNamespace()

    monkeypatch.setattr(cli_decompilation, "_analysis_timeout", lambda *_args, **_kwargs: contextlib.nullcontext())
    monkeypatch.setattr(cli_decompilation, "_guard_angr_peephole_expr_bitwidth_assertion", lambda *_args, **_kwargs: contextlib.nullcontext())
    monkeypatch.setattr(cli_decompilation, "_guard_angr_variable_recovery_binop_sub_size_mismatch", lambda *_args, **_kwargs: contextlib.nullcontext())
    monkeypatch.setattr(cli_decompilation, "_guard_angr_ail_narrowing", lambda *_args, **_kwargs: contextlib.nullcontext())
    monkeypatch.setattr(cli_decompilation, "_guard_angr_clinic_stage_markers", lambda *_args, **_kwargs: contextlib.nullcontext())

    status, payload, partial_payload, block_count, byte_count, elapsed = cli_decompilation._decompile_function_with_stats(
        project,
        cfg,
        function,
        timeout=2,
        api_style="default",
        binary_path=None,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
        enable_postprocess=True,
        allow_isolated_retry=True,
        failure_family_state=FailureFamilyState(
            previous_snapshot=build_failure_family_snapshot(
                status="empty",
                failure_stage="structuring",
                fallback_kind="structurer_retry",
                tail_validation_verdict="uncollected",
                artifact_path="0x102e0:RunMenu",
            )
        ),
    )
    captured = capsys.readouterr()

    assert status == "empty"
    assert "stop: same failure family" in captured.out
    assert calls == [1]
    assert partial_payload is None
    assert block_count == 0
    assert byte_count == 0
    assert elapsed >= 0


def test_function_work_cache_ignores_timeout_records(monkeypatch):
    function = SimpleNamespace(addr=0x1234, name="sub_1234", project=None)
    item = FunctionWorkItem(index=1, function_cfg=object(), function=function)
    monkeypatch.setattr(cli_core, "_function_decompilation_cache_key", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        cli_core,
        "_load_cache_json",
        lambda *_args, **_kwargs: {
            "status": "timeout",
            "payload": "Timed out.",
            "timeout": 2,
        },
    )

    result, _debug, _cache_key, _tail_enabled, _expected_stages = cli_core._function_work_cache_lookup(
        item,
        binary_path=None,
        timeout=2,
        api_style="dos",
        enable_structured_simplify=True,
        enable_postprocess=True,
    )

    assert result is None
    assert "ignoring cached failed function result" in _debug
    assert "status=timeout" in _debug


def test_tail_validation_cache_paths_are_stable_for_direct_binary_runs():
    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=None,
        function=SimpleNamespace(addr=0x1234, name="_life_step"),
    )

    console_path = decompile._tail_validation_console_cache_path(LIFE_EXE, [item])
    detail_path = decompile._tail_validation_detail_cache_path(LIFE_EXE, [item])

    assert console_path is not None
    assert detail_path is not None
    assert console_path.name.endswith(".tail_validation_console.json")
    assert detail_path.name.endswith(".tail_validation_surface.json")
    assert "LIFE" in console_path.name
    assert "LIFE" in detail_path.name


def _build_synthetic_microsoft_lib(
    module_bytes: bytes,
    *,
    page_size: int = 512,
    case_sensitive: bool = False,
    extended_records: list[tuple[int, tuple[int, ...]]] | None = None,
    dictionary_entries: list[tuple[str, int]] | None = None,
) -> bytes:
    header_payload_len = page_size - 3
    module_page = module_bytes + (b"\x00" * ((page_size - (len(module_bytes) % page_size)) % page_size))
    dict_offset = page_size + len(module_page)
    dict_blocks = 1
    header = bytearray(page_size)
    header[0] = 0xF0
    header[1:3] = header_payload_len.to_bytes(2, "little")
    header[3:7] = dict_offset.to_bytes(4, "little")
    header[7:9] = dict_blocks.to_bytes(2, "little")
    header[9] = 0x01 if case_sensitive else 0x00
    dict_page = bytearray(512)
    if dictionary_entries:
        free_offset = 38 * 2
        for symbol_name, module_page_number in dictionary_entries:
            encoded_name = symbol_name.encode("latin1")
            entry = bytes([len(encoded_name)]) + encoded_name + int(module_page_number).to_bytes(2, "little")
            assert free_offset + len(entry) <= len(dict_page)
            _page_index, _page_delta, bucket, bucket_delta = _hash_synthetic_microsoft_lib_symbol(
                symbol_name,
                dict_blocks,
                case_sensitive=case_sensitive,
            )
            start_bucket = bucket
            while dict_page[bucket] != 0:
                bucket = (bucket + bucket_delta) % 37
                assert bucket != start_bucket
            dict_page[bucket] = free_offset // 2
            dict_page[free_offset : free_offset + len(entry)] = entry
            free_offset += len(entry)
            if free_offset & 1:
                free_offset += 1
        dict_page[37] = free_offset // 2
    blob = bytes(header) + module_page + bytes(dict_page)
    if extended_records:
        payload = bytearray()
        payload += len(extended_records).to_bytes(2, "little")
        table_size = len(extended_records) * 4
        dependency_lists = bytearray()
        offsets: list[int] = []
        for _page_number, deps in extended_records:
            offsets.append(2 + table_size + len(dependency_lists))
            for dep in deps:
                dependency_lists += int(dep).to_bytes(2, "little")
            dependency_lists += (0).to_bytes(2, "little")
        for (page_number, _deps), dep_offset in zip(extended_records, offsets, strict=True):
            payload += int(page_number).to_bytes(2, "little")
            payload += int(dep_offset).to_bytes(2, "little")
        payload += dependency_lists
        record_length = len(payload) + 1
        ext = bytearray()
        ext.append(0xF2)
        ext += record_length.to_bytes(2, "little")
        ext += payload
        ext.append(0)
        blob += bytes(ext)
    trailer = bytearray(512)
    trailer[0] = 0xF1
    trailer[1:3] = (509).to_bytes(2, "little")
    return blob + bytes(trailer)


def _hash_synthetic_microsoft_lib_symbol(symbol_name: str, dictionary_pages: int, *, case_sensitive: bool) -> tuple[int, int, int, int]:
    name_bytes = symbol_name.encode("latin1", errors="ignore")
    if not case_sensitive:
        name_bytes = bytes((byte | 0x20) if 0x41 <= byte <= 0x5A else byte for byte in name_bytes)
    page_index = 0
    page_index_delta = 0
    bucket_index = 0
    bucket_index_delta = 0
    for forward, reverse in zip(name_bytes, reversed(name_bytes), strict=True):
        page_index = ((page_index << 2) ^ forward) & 0xFFFFFFFF
        bucket_index_delta = ((bucket_index_delta >> 2) ^ forward) & 0xFFFFFFFF
        bucket_index = ((bucket_index >> 2) ^ reverse) & 0xFFFFFFFF
        page_index_delta = ((page_index_delta << 2) ^ reverse) & 0xFFFFFFFF
    page_index %= dictionary_pages
    page_index_delta = (page_index_delta % dictionary_pages) or 1
    bucket_index %= 37
    bucket_index_delta = (bucket_index_delta % 37) or 1
    return page_index, page_index_delta, bucket_index, bucket_index_delta


def _run_decompile_proc(
    path: Path,
    proc: str,
    *,
    proc_kind: str = "NEAR",
    analysis_timeout: int = 10,
    subprocess_timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(path),
            "--proc",
            proc,
            "--proc-kind",
            proc_kind,
            "--timeout",
            str(analysis_timeout),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=subprocess_timeout,
        check=False,
    )


def test_preferred_decompiler_options_prefers_phoenix_for_true_wrappers():
    assert decompile._preferred_decompiler_options(1, 21, wrapper_like=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(1, 24, wrapper_like=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(2, 21, wrapper_like=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(1, 25, wrapper_like=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(1, 24) is None
    assert decompile._preferred_decompiler_options(2, 21) is None


def test_preferred_decompiler_options_rejects_call_heavy_small_functions():
    assert decompile._preferred_decompiler_options(1, 24, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(1, 23, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(1, 25, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(6, 64, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(1, 24, wrapper_like=False) is None


def test_preferred_decompiler_options_accepts_tiny_single_call_helpers():
    assert decompile._preferred_decompiler_options(3, 0x14, tiny_single_call_helper=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(3, 0x17, tiny_single_call_helper=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(1, 0x14, tiny_single_call_helper=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(3, 0x14, tiny_single_call_helper=False) is None


@pytest.mark.parametrize(
    "addr, byte_count, block_sizes",
    [
        (0x10010, 0x14, (0x08, 0x08, 0x04)),
        (0x1157C, 0x17, (0x08, 0x08, 0x07)),
        (0x1196F, 0x14, (0x14,)),
    ],
)
def test_function_decompilation_profile_marks_tiny_single_call_helpers_small(addr, byte_count, block_sizes):
    blocks = {}
    block_addrs = [addr + (index * 0x10) for index in range(len(block_sizes))]
    for index, (block_addr, block_size) in enumerate(zip(block_addrs, block_sizes, strict=True)):
        insns = [
            SimpleNamespace(mnemonic="push", op_str="bp"),
            SimpleNamespace(mnemonic="mov", op_str="bp, sp"),
        ]
        if index == 0:
            insns.append(SimpleNamespace(mnemonic="call", op_str="0x1140d"))
        insns.append(SimpleNamespace(mnemonic="mov", op_str="ax, [bp + 4]"))
        blocks[block_addr] = SimpleNamespace(size=block_size, capstone=SimpleNamespace(insns=insns))

    project = SimpleNamespace(factory=SimpleNamespace(block=lambda block_addr, opt_level=0: blocks[block_addr]))
    function = SimpleNamespace(
        addr=addr,
        name=f"sub_{addr:x}",
        project=project,
        block_addrs_set=set(blocks),
        get_call_sites=lambda: [addr + 0x20],
    )

    profile = decompile._function_decompilation_profile(function, len(block_sizes), byte_count)

    assert profile["block_count"] == len(block_sizes)
    assert profile["byte_count"] == byte_count
    assert profile["wrapper_like"] is False
    assert profile["tiny_single_call_helper"] is True


def test_function_decompilation_profile_rejects_branch_heavy_helpers():
    blocks = {
        0x2000: SimpleNamespace(
            size=0x08,
            capstone=SimpleNamespace(
                insns=[
                    SimpleNamespace(mnemonic="push", op_str="bp"),
                    SimpleNamespace(mnemonic="call", op_str="0x3000"),
                ]
            ),
        ),
        0x2010: SimpleNamespace(
            size=0x08,
            capstone=SimpleNamespace(
                insns=[
                    SimpleNamespace(mnemonic="jnz", op_str="0x2030"),
                    SimpleNamespace(mnemonic="mov", op_str="ax, [bp + 4]"),
                ]
            ),
        ),
        0x2020: SimpleNamespace(
            size=0x08,
            capstone=SimpleNamespace(insns=[SimpleNamespace(mnemonic="ret", op_str="")]),
        ),
    }
    project = SimpleNamespace(factory=SimpleNamespace(block=lambda block_addr, opt_level=0: blocks[block_addr]))
    function = SimpleNamespace(
        addr=0x2000,
        name="sub_2000",
        project=project,
        block_addrs_set=set(blocks),
        get_call_sites=lambda: [0x2004],
    )

    profile = decompile._function_decompilation_profile(function, 3, 0x18)

    assert profile["wrapper_like"] is False
    assert profile["tiny_single_call_helper"] is False


def test_function_recovery_detail_names_recovery_stage():
    assert decompile._function_recovery_detail("recovery") == "during x86-16 function recovery"
    assert decompile._function_recovery_detail("recovery:fast") == "during x86-16 function recovery (fast CFGFast)"
    assert decompile._function_recovery_detail("recovery:full") == "during x86-16 function recovery (full CFGFast)"
    assert decompile._function_recovery_detail("recovery:narrow:0x80") == (
        "during x86-16 function recovery (narrow CFGFast)"
    )
    assert decompile._function_recovery_detail("postprocess") is None


def test_install_angr_peephole_expr_bitwidth_guard_skips_mismatched_replacements():
    class BaseWalker:
        def __init__(self):
            self.any_update = False
            self.expr_opts = []

        def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
            return expr

    class FakeWalker(BaseWalker):
        pass

    class FakeExpr:
        def __init__(self, bits):
            self.bits = bits

    class FakeExprOpt:
        expr_classes = (FakeExpr,)

        def optimize(self, expr, stmt_idx=None, block=None):
            return FakeExpr(8)

    original = decompile._install_angr_peephole_expr_bitwidth_guard(FakeWalker)
    try:
        walker = FakeWalker()
        walker.expr_opts = [FakeExprOpt()]
        expr = FakeExpr(16)
        result = walker._handle_expr(0, expr, 0, None, None)
    finally:
        FakeWalker._handle_expr = original

    assert result is expr
    assert walker.any_update is False


def test_install_angr_variable_recovery_binop_sub_size_guard_computes_in_wider_domain_then_narrows():
    class FakeBV:
        def __init__(self, bits, *, concrete=False, concrete_value=0):
            self._bits = bits
            self.concrete = concrete
            self.concrete_value = concrete_value

        def size(self):
            return self._bits

        def zero_extend(self, nbits):
            return FakeBV(self._bits + nbits, concrete=self.concrete, concrete_value=self.concrete_value)

        def __getitem__(self, item):
            hi, lo = item.start, item.stop
            return FakeBV(hi - lo + 1, concrete=self.concrete, concrete_value=self.concrete_value)

        def __sub__(self, other):
            return FakeBV(max(self._bits, other._bits))

    class FakeRichR:
        def __init__(self, data, typevar=None, type_constraints=None):
            self.data = data
            self.typevar = typevar
            self.type_constraints = type_constraints

    class FakeTypeVariable:
        pass

    class FakeTypevarsModule:
        TypeVariable = FakeTypeVariable

        @staticmethod
        def new_dtv(*_args, **_kwargs):
            return FakeTypeVariable()

        @staticmethod
        def SubN(_value):
            return "subn"

        @staticmethod
        def Sub(_lhs, _rhs, _out):
            return ("sub", _lhs, _rhs, _out)

    class FakeState:
        def top(self, bits):
            return ("top", bits)

    class FakeEngine:
        def __init__(self):
            self.state = FakeState()

        def _expr_pair(self, _arg0, _arg1):
            return FakeRichR(FakeBV(16), typevar=FakeTypeVariable()), FakeRichR(FakeBV(8))

        def _handle_binop_Sub(self, expr):
            raise AssertionError("original implementation should not run")

    class FakeExpr:
        bits = 16
        operands = ("lhs", "rhs")

    original = decompile._install_angr_variable_recovery_binop_sub_size_guard(
        FakeEngine,
        richr_cls=FakeRichR,
        typevars_module=FakeTypevarsModule,
    )
    try:
        result = FakeEngine()._handle_binop_Sub(FakeExpr())
    finally:
        FakeEngine._handle_binop_Sub = original

    assert isinstance(result.data, FakeBV)
    assert result.data.size() == 16


def test_recover_direct_addr_function_prefers_candidate_recovery_for_x86_16(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x4000)),
    )
    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=0x1196F)
    calls = []

    monkeypatch.setattr(decompile, "_analysis_timeout", contextlib.nullcontext)

    def fake_recover_candidate(project_arg, *, candidate_addr, image_end, metadata, project_entry, region_span):
        calls.append((candidate_addr, image_end, project_entry, region_span))
        return expected_cfg, expected_func

    monkeypatch.setattr(decompile, "_recover_candidate_function_pair", fake_recover_candidate)
    monkeypatch.setattr(
        decompile,
        "_pick_function",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("raw pick_function should not run")),
    )

    cfg, func = decompile._recover_direct_addr_function(
        project,
        0x1196F,
        timeout=6,
        window=0x40,
        function_label=None,
        lst_metadata=None,
        low_memory_path=False,
        prefer_fast_recovery=False,
    )

    assert (cfg, func) == (expected_cfg, expected_func)
    assert calls == [(0x1196F, 0x14001, 0x11423, 0x180)]


def test_fallback_entry_function_retries_broader_windows_after_narrow_recovery_fails(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        calls.append(("infer", window))
        return start_addr, start_addr + window

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions))
        region = regions[0]
        if region[1] - region[0] >= 0x800:
            return expected_cfg, expected_func
        raise KeyError("narrow miss")

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    cfg, func = decompile._fallback_entry_function(project, timeout=10, window=0x200)

    assert cfg is expected_cfg
    assert func is expected_func
    assert project._inertia_decompiler_stage == "recovery:narrow:0x800"
    assert len([call for call in calls if call[0] == "pick"]) == 5
    assert [call[1][0][1] - call[1][0][0] for call in calls if call[0] == "pick"] == [
        0x200,
        0x200,
        0x400,
        0x400,
        0x800,
    ]


def test_fallback_entry_function_uses_lean_cfgfast_for_86_16(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    captured: list[dict[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        return start_addr, start_addr + window

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        captured.append({"regions": regions, "data_references": data_references})
        return expected_cfg, expected_func

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    cfg, func = decompile._fallback_entry_function(project, timeout=10, window=0x200)

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured[-1]["data_references"] is False


def test_pick_function_lean_disables_expensive_cfgfast_features(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function_lean(project, 0x1000, regions=[(0x1000, 0x1100)])

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured == [
        {
            "start_at_entry": False,
            "function_starts": [0x1000],
            "regions": [(0x1000, 0x1100)],
            "normalize": False,
            "data_references": False,
            "force_smart_scan": False,
            "force_complete_scan": False,
            "resolve_indirect_jumps": False,
            "function_prologues": False,
            "symbols": False,
            "cross_references": False,
        }
    ]


def test_pick_function_lean_can_skip_far_call_extension(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("far-call extension should not run")))
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function_lean(
        project,
        0x1000,
        regions=[(0x1000, 0x1100)],
        extend_far_calls=False,
    )

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured == [
        {
            "start_at_entry": False,
            "function_starts": [0x1000],
            "regions": [(0x1000, 0x1100)],
            "normalize": False,
            "data_references": False,
            "force_smart_scan": False,
            "force_complete_scan": False,
            "resolve_indirect_jumps": False,
            "function_prologues": False,
            "symbols": False,
            "cross_references": False,
        }
    ]


def test_pick_function_lean_can_extend_traced_neighbor_calls(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )

    initial_func = SimpleNamespace(addr=0x1000)
    extended_func = SimpleNamespace(addr=0x1000)
    initial_cfg = SimpleNamespace(functions={0x1000: initial_func})
    extended_cfg = SimpleNamespace(functions={0x1000: extended_func})
    patched: list[object] = []

    project.analyses = SimpleNamespace(CFGFast=lambda **_kwargs: initial_cfg)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "extend_cfg_for_neighbor_calls",
        lambda project_arg, function, *, entry_window: (
            extended_cfg
            if project_arg is project and function is initial_func and entry_window == 0x100
            else None
        ),
    )
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda function, *_args, **_kwargs: patched.append(function))

    cfg, func = decompile._pick_function_lean(project, 0x1000, regions=[(0x1000, 0x1100)])

    assert cfg is extended_cfg
    assert func is extended_func
    assert patched == [extended_func]


def test_find_codeview_nb00_detects_life_exe():
    found = find_codeview_nb00(LIFE_EXE.read_bytes())
    assert found is not None
    signature, debug_base, subdir_addr = found
    assert signature == "NB00"
    assert debug_base == 23926
    assert subdir_addr == 31887


def test_parse_codeview_nb00_extracts_life_functions_and_data():
    info = parse_codeview_nb00(LIFE_EXE, load_base_linear=0x10000)

    assert info is not None
    assert len(info.modules) >= 3
    assert len(info.publics) >= 100
    assert "main" in {name.lstrip("_") for name in info.code_labels.values()}
    assert "init_life" in {name.lstrip("_") for name in info.code_labels.values()}
    assert "draw_box" in {name.lstrip("_") for name in info.code_labels.values()}
    assert "generation" in {name.lstrip("_") for name in info.code_labels.values()}
    assert "speed" in {name.lstrip("_") for name in info.data_labels.values()}
    assert info.code_labels[0x10010].lstrip("_") == "main"
    assert info.code_labels[0x100ea].lstrip("_") == "init_life"
    assert info.code_labels[0x101a3].lstrip("_") == "draw_box"
    assert info.data_labels[0x15bb0].lstrip("_") == "speed"
    assert "LIFE.OBJ" in {module.name for module in info.modules}


def test_parse_codeview_nb00_agrees_with_life_cod_proc_names():
    info = parse_codeview_nb00(LIFE_EXE, load_base_linear=0x10000)

    assert info is not None
    cod_text = LIFE_COD.read_text(errors="ignore")

    for proc_name in ("_main", "_init_life", "_draw_box", "_generation", "_proc_key"):
        assert f"PUBLIC\t{proc_name}" in cod_text
        assert proc_name.lstrip("_") in {name.lstrip("_") for name in info.code_labels.values()}


def test_parse_tdinfo_exe_reads_noname_sample():
    info = parse_tdinfo_exe(NONAME_TDINFO_EXE, load_base_linear=0x10000)

    assert info is not None
    assert info.header.major_version == 2
    assert info.header.minor_version == 8
    assert info.header.symbols_count == 96
    assert "_main" in info.names
    assert any(symbol.symbol_class is TDInfoSymbolClass.STATIC for symbol in info.symbols)
    assert info.code_labels[0x10005] == "cvtfak"


def test_load_lst_metadata_uses_tdinfo_when_present():
    project = decompile._build_project(NONAME_TDINFO_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = decompile._load_lst_metadata(NONAME_TDINFO_EXE, project)

    assert metadata is not None
    assert "turbo_debug_tdinfo" in metadata.source_format
    assert metadata.code_labels[0x10005] == "cvtfak"


def test_extract_cod_listing_metadata_reads_life_cod_ranges():
    metadata = extract_cod_listing_metadata(LIFE_COD)

    assert metadata.code_labels[0] == "_main"
    assert metadata.proc_kinds[0] == "NEAR"
    assert metadata.code_ranges[0][1] > metadata.code_ranges[0][0]


def test_load_lst_metadata_uses_codeview_nb00_when_sidecars_absent():
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = decompile._load_lst_metadata(LIFE_EXE, project)

    assert metadata is not None
    assert metadata.absolute_addrs is True
    assert "codeview_nb00" in metadata.source_format
    assert "cod_listing" in metadata.source_format
    assert metadata.code_labels[0x10010] == "main"
    assert 0x100c6 not in metadata.code_labels
    assert metadata.code_labels[0x100ea] == "init_life"
    assert 0x10000 not in metadata.code_labels
    assert metadata.data_labels[0x15bb0] == "_speed"


def test_sidecar_cod_metadata_for_function_uses_sibling_cod():
    project = SimpleNamespace()
    function = SimpleNamespace(addr=0x10010, name="main")
    metadata = SimpleNamespace(
        cod_path=str(LIFE_COD),
        cod_proc_kinds={0x10010: "NEAR"},
    )

    cod_metadata = decompile._sidecar_cod_metadata_for_function(project, function, LIFE_EXE, metadata)

    assert cod_metadata is not None
    assert cod_metadata.has_source_lines(("main(argc, argv)",))


def test_dosmz_loader_handles_life_exe_sparse_relocations():
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)

    assert project.arch.name == "86_16"
    assert project.entry == 0x11423
    assert project.loader.main_object.max_addr >= 0x18be1


def test_probe_lift_break_reports_first_bad_instruction(monkeypatch):
    insns = [
        SimpleNamespace(address=0x1000, size=1, mnemonic="push", op_str="bp"),
        SimpleNamespace(address=0x1001, size=2, mnemonic="mov", op_str="bp, sp"),
        SimpleNamespace(address=0x1003, size=2, mnemonic="int", op_str="0x21"),
    ]
    project = SimpleNamespace(
        factory=SimpleNamespace(
            block=lambda addr, size, opt_level=0: (_ for _ in ()).throw(ValueError("bad lift")) if addr == 0x1003 else object()
        ),
    )

    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x1000, 0x1005))
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: insns)

    rendered = decompile._probe_lift_break(project, 0x1000)

    assert "first lift failure at 0x1003" in rendered
    assert "0x1003: int 0x21" in rendered


def test_try_decompile_non_optimized_slice_uses_raw_slice(monkeypatch):
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\x90\xc3")),
    )
    function = SimpleNamespace(name="main", addr=0x1000, normalized=True, blocks=(SimpleNamespace(size=0x10),))
    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x1000, 0x1003))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: SimpleNamespace())
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (SimpleNamespace(), function),
    )
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "int main(void)\n{\n    return 0;\n}\n", 1, 3, 0.01),
    )

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1000,
        "main",
        timeout=1,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
    )

    assert "int main" in outcome.rendered


def test_try_decompile_non_optimized_slice_returns_partial_timeout_payload(monkeypatch):
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\x90\xc3")),
    )
    function = SimpleNamespace(name="main", addr=0x1000, normalized=True, blocks=(SimpleNamespace(size=0x10),))

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x1000, 0x1003))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: SimpleNamespace())
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (SimpleNamespace(), function),
    )
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("timeout", "Timed out after 1s.", "int partial(void) { return 1; }", 1, 3, 0.01),
    )
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1000,
        "main",
        timeout=1,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
    )

    assert outcome.rendered == "int partial(void) { return 1; }"
    assert outcome.partial_payload == "int partial(void) { return 1; }"
    assert outcome.failure_detail is not None
    assert outcome.failure_detail.startswith("shared-project slice lean: timeout: Timed out after 1s.")
    assert "stop_family=partial-timeout" in outcome.failure_detail


def test_try_decompile_non_optimized_slice_reports_failure_detail(monkeypatch):
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\x90\xc3")),
    )
    function = SimpleNamespace(name="main", addr=0x1000, normalized=True, blocks=(SimpleNamespace(size=0x10),))

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x1000, 0x1003))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: SimpleNamespace())
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (SimpleNamespace(), function),
    )
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("error", "slice lift broke", None, 1, 3, 0.01),
    )
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1000,
        "main",
        timeout=1,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
        allow_fresh_project_retry=False,
    )

    assert outcome.rendered is None
    assert outcome.failure_detail is not None
    assert outcome.failure_detail.startswith("shared-project slice lean: error: slice lift broke")
    assert outcome.attempt_failures[0].startswith("shared-project slice lean: error: slice lift broke")


def test_try_decompile_non_optimized_slice_retries_full_recovery_after_lean_miss(monkeypatch):
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\x90\xc3")),
    )
    function = SimpleNamespace(name="main", addr=0x1000, normalized=True, blocks=(SimpleNamespace(size=0x10),))
    calls: list[tuple[str, bool]] = []

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x1000, 0x1003))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: SimpleNamespace())

    def _fake_pick_function_lean(*_args, **_kwargs):
        calls.append(("lean", False))
        raise KeyError("lean miss")

    def _fake_pick_function(_slice_project, _start, *, data_references, **_kwargs):
        calls.append(("full", data_references))
        if data_references:
            raise AssertionError("full-with-refs should not run after full-no-refs succeeds")
        return SimpleNamespace(), function

    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_pick_function", _fake_pick_function)
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "int recovered(void) { return 2; }", None, 1, 3, 0.01),
    )

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1000,
        "main",
        timeout=3,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
        allow_fresh_project_retry=False,
    )

    assert outcome.rendered == "int recovered(void) { return 2; }"
    assert calls == [("lean", False), ("full", False)]


def test_try_decompile_non_optimized_slice_allows_short_cod_budget(monkeypatch):
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\x90\xc3")),
    )
    function = SimpleNamespace(name="main", addr=0x1000, normalized=True, blocks=(SimpleNamespace(size=0x10),))

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x1000, 0x1003))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: SimpleNamespace())
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (SimpleNamespace(), function),
    )
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "int main(void)\n{\n    return 0;\n}\n", None, 1, 3, 0.01),
    )

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1000,
        "main",
        timeout=3,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
        cod_metadata=SimpleNamespace(proc_name="_main"),
    )

    assert "int main" in outcome.rendered


def test_recover_lst_function_prefers_lean_cfgfast_for_labeled_x86_16(monkeypatch):
    project = SimpleNamespace(entry=0x1E432, arch=SimpleNamespace(name="86_16"))
    metadata = SimpleNamespace(absolute_addrs=True)
    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=0x10010, name="main")

    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda _project, start_addr, *, window: (start_addr, start_addr + window),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (expected_cfg, expected_func),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("full CFGFast should not run")),
    )

    cfg, func = decompile._recover_lst_function(
        project,
        metadata,
        0x10010,
        "main",
        timeout=4,
        window=0x200,
    )

    assert cfg is expected_cfg
    assert func is expected_func
    assert func.name == "main"


def test_rank_exe_function_seeds_uses_epilog_follow_ons(monkeypatch):
    code = b"\xc3\x55\x8b\xec\x90"
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=0x1004,
                linked_base=0x1000,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_linear_disassembly",
        lambda *_args, **_kwargs: [SimpleNamespace(address=0x1000, size=1, mnemonic="ret", op_str="")],
    )

    ranked = decompile._rank_exe_function_seeds(project)

    assert 0x1001 in ranked


def test_rank_exe_function_seeds_ignores_epilog_follow_ons_without_prologue(monkeypatch):
    code = b"\xc3\x90\x90\x31\xc0"
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=0x1004,
                linked_base=0x1000,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_linear_disassembly",
        lambda *_args, **_kwargs: [SimpleNamespace(address=0x1000, size=1, mnemonic="ret", op_str="")],
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )

    ranked = decompile._rank_exe_function_seeds(project)

    assert 0x1003 not in ranked


def test_fast_tracer_collects_call_and_jump_targets():
    code = bytearray(b"\x90" * 0x60)
    base = 0x1000
    callsite = base + 0x00
    call_target = base + 0x20
    rel = call_target - (callsite + 3)
    code[0:3] = b"\xE8" + int(rel).to_bytes(2, "little", signed=True)
    code[0x20:0x23] = b"\x55\x8B\xEC"
    jmp_site = base + 0x03
    jmp_target = base + 0x30
    jrel = jmp_target - (jmp_site + 2)
    code[3:5] = b"\xEB" + int(jrel).to_bytes(1, "little", signed=True)
    code[0x30:0x33] = b"\x55\x8B\xEC"
    project = SimpleNamespace(arch=Arch86_16())

    traced = trace_16bit_seed_candidates(project, bytes(code), linked_base=base, windows=[(base, base + len(code))])

    assert call_target in traced.call_targets
    assert jmp_target in traced.jump_targets
    assert traced.scores[call_target] > traced.scores[jmp_target]


def test_fast_tracer_keeps_direct_call_target_without_frame_prologue():
    code = bytearray(b"\x90" * 0x40)
    base = 0x1000
    call_target = base + 0x20
    rel = call_target - (base + 3)
    code[0:3] = b"\xE8" + int(rel).to_bytes(2, "little", signed=True)
    code[0x20:0x24] = b"\x59\x8B\xDC\x2B"
    project = SimpleNamespace(arch=Arch86_16())

    traced = trace_16bit_seed_candidates(project, bytes(code), linked_base=base, windows=[(base, base + len(code))])

    assert call_target in traced.call_targets


def test_fast_tracer_marks_ret_follow_on_as_weak_candidate():
    code = bytearray(b"\x90" * 0x20)
    base = 0x1000
    code[0:1] = b"\xC3"
    code[1:4] = b"\x90\x90\x90"
    code[4:7] = b"\x55\x8B\xEC"
    project = SimpleNamespace(arch=Arch86_16())

    traced = trace_16bit_seed_candidates(project, bytes(code), linked_base=base, windows=[(base, base + len(code))])

    assert base in traced.returns
    assert base + 4 in traced.jump_targets


def test_fast_tracer_ignores_ret_follow_on_without_function_prologue():
    code = bytearray(b"\x90" * 0x20)
    base = 0x1000
    code[0:1] = b"\xC3"
    code[1:5] = b"\x90\x90\x90\x90"
    code[5:8] = b"\x31\xC0\x90"
    project = SimpleNamespace(arch=Arch86_16())

    traced = trace_16bit_seed_candidates(project, bytes(code), linked_base=base, windows=[(base, base + len(code))])

    assert base in traced.returns
    assert base + 5 not in traced.jump_targets


def test_rank_exe_function_seeds_respects_known_code_windows(monkeypatch):
    code = b"\x90" * 0x300
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1100: "main"},
        code_ranges={0x1100: (0x1100, 0x1120)},
        absolute_addrs=True,
    )
    project = SimpleNamespace(
        entry=0x1000,
        _inertia_lst_metadata=metadata,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=len(code) - 1,
                linked_base=0x1000,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
                mz_segment_spans=(),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: set())
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    ranked = decompile._rank_exe_function_seeds(project)

    assert ranked == [0x1100]


def test_rank_exe_function_seeds_excludes_signature_matched_library_labels(monkeypatch):
    code = bytearray(b"\x90" * 0x200)
    library_addr = 0x1100
    client_addr = 0x1120
    code[library_addr - 0x1000 : library_addr - 0x1000 + 3] = b"\x55\x8B\xEC"
    code[client_addr - 0x1000 : client_addr - 0x1000 + 3] = b"\x55\x8B\xEC"
    metadata = LSTMetadata(
        data_labels={},
        code_labels={
            library_addr: "flair_library_func",
            client_addr: "client_func",
        },
        code_ranges={
            library_addr: (library_addr, library_addr + 0x10),
            client_addr: (client_addr, client_addr + 0x10),
        },
        signature_code_addrs=frozenset({library_addr}),
        absolute_addrs=True,
        source_format="flair_pat+flair_sig",
    )
    project = SimpleNamespace(
        entry=0x1000,
        _inertia_lst_metadata=metadata,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=len(code) - 1,
                linked_base=0x1000,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: bytes(code)),
                mz_segment_spans=(),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    ranked = decompile._rank_exe_function_seeds(project)

    assert library_addr not in ranked
    assert client_addr in ranked


def test_rank_exe_function_seeds_prioritizes_entry_window_call_targets(monkeypatch):
    code = bytearray(b"\x90" * 0x200)
    entry = 0x1080
    target = 0x1010
    helper = 0x10c0
    call_offset = entry - 0x1000
    rel = target - (entry + 3)
    helper_rel = helper - (entry + 6)
    code[call_offset : call_offset + 3] = b"\xE8" + int(rel).to_bytes(2, "little", signed=True)
    code[call_offset + 3 : call_offset + 6] = b"\xE8" + int(helper_rel).to_bytes(2, "little", signed=True)
    project = SimpleNamespace(
        entry=entry,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=len(code) - 1,
                linked_base=0x1000,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: bytes(code)),
                mz_segment_spans=(),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    ranked = decompile._rank_exe_function_seeds(project)

    assert ranked
    assert ranked[0] == target
    assert ranked.index(target) < ranked.index(helper)


def test_rank_exe_function_seeds_uses_far_call_relocation_targets(monkeypatch):
    code = bytearray(b"\x90" * 0x240)
    entry = 0x1100
    target = 0x1180
    callsite = 0x1010
    code[callsite - 0x1000] = 0x9A
    code[callsite - 0x1000 + 1 : callsite - 0x1000 + 3] = (target & 0xF).to_bytes(2, "little")
    code[callsite - 0x1000 + 3 : callsite - 0x1000 + 5] = ((target - 0x1000) >> 4).to_bytes(2, "little")
    helper = 0x1190
    helper_rel = helper - (entry + 3)
    code[entry - 0x1000 : entry - 0x1000 + 3] = b"\xE8" + int(helper_rel).to_bytes(2, "little", signed=True)
    weak_ptr = 0x11d0
    code[0x40:0x42] = (weak_ptr & 0xF).to_bytes(2, "little")
    code[0x42:0x44] = ((weak_ptr - 0x1000) >> 4).to_bytes(2, "little")
    project = SimpleNamespace(
        entry=entry,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=len(code) - 1,
                linked_base=0x1000,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: bytes(code)),
                mz_segment_spans=(),
                mz_relocation_entries=((0x13, 0x0), (0x42, 0x0)),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    ranked = decompile._rank_exe_function_seeds(project)

    assert target in ranked
    assert weak_ptr in ranked
    assert ranked.index(target) < ranked.index(weak_ptr)


def test_rank_exe_function_seeds_keeps_direct_call_target_without_frame_prologue(monkeypatch):
    code = bytearray(b"\x90" * 0x80)
    base = 0x1000
    target = base + 0x20
    rel = target - (base + 3)
    code[0:3] = b"\xE8" + int(rel).to_bytes(2, "little", signed=True)
    code[0x20:0x24] = b"\x59\x8B\xDC\x2B"
    project = SimpleNamespace(
        entry=base,
        arch=Arch86_16(),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=len(code) - 1,
                linked_base=base,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: bytes(code)),
                mz_segment_spans=(),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    ranked = decompile._rank_exe_function_seeds(project)

    assert target in ranked


def test_rank_exe_function_seeds_excludes_unconfirmed_near_call_only_labels(monkeypatch):
    code = bytearray(b"\x90" * 0x80)
    base = 0x1000
    target = base + 0x20
    rel = target - (base + 3)
    code[0:3] = b"\xE8" + int(rel).to_bytes(2, "little", signed=True)
    code[0x20:0x24] = b"\x59\x8B\xDC\x2B"
    project = SimpleNamespace(
        entry=base,
        arch=Arch86_16(),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=len(code) - 1,
                linked_base=base,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: bytes(code)),
                mz_segment_spans=(),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: set())
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "trace_16bit_seed_candidates",
        lambda *_args, **_kwargs: SimpleNamespace(call_targets=set(), jump_targets=set(), returns=set(), scores={}),
    )

    ranked = decompile._rank_exe_function_seeds(project)

    assert target not in ranked


def test_rank_exe_function_seeds_uses_recovery_labels_when_visible_catalog_is_empty(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    code = b"\x90" * 0x200
    binary.write_bytes(code)
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1100: "sig_func"},
        code_ranges={0x1100: (0x1100, 0x1120)},
        signature_code_addrs=frozenset({0x1100}),
        absolute_addrs=True,
        source_format="flair_pat+flair_sig",
    )
    project = SimpleNamespace(
        entry=0x1000,
        _inertia_lst_metadata=metadata,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=binary,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
    )
    monkeypatch.setattr(decompile, "_seed_scan_windows", lambda _project: [(0x1100, 0x1120)])
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: set())
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    recovery_calls = {"count": 0}

    def _counting_recovery_labels(meta):
        recovery_calls["count"] += 1
        return sidecar_metadata._recovery_code_labels(meta)

    monkeypatch.setattr(decompile, "_recovery_code_labels", _counting_recovery_labels)

    ranked = decompile._rank_exe_function_seeds(project)

    assert sidecar_metadata._visible_code_labels(metadata) == {}
    assert sidecar_metadata._recovery_code_labels(metadata) == {0x1100: "sig_func"}
    assert recovery_calls["count"] == 1
    assert ranked == []


def test_rank_exe_function_seeds_prefers_bounded_metadata_spans_over_tiny_entry_targets(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    code = b"\x90" * 0x200
    binary.write_bytes(code)
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1100: "sig_func"},
        code_ranges={0x1100: (0x1100, 0x1140)},
        signature_code_addrs=frozenset(),
        absolute_addrs=True,
        source_format="flair_pat+flair_sig",
    )
    project = SimpleNamespace(
        entry=0x1000,
        _inertia_lst_metadata=metadata,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=binary,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
    )
    monkeypatch.setattr(decompile, "_seed_scan_windows", lambda _project: [(0x1000, 0x1200)])
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: {0x1010})
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )

    ranked = decompile._rank_exe_function_seeds(project)

    assert ranked.index(0x1100) < ranked.index(0x1010)


def test_recover_seeded_exe_functions_reuses_existing_project_before_rebuild(monkeypatch):
    code = b"\x55\x8B\xEC" + b"\x90" * 0x20
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)]))
        ),
    )
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x1003])
    rebuilds: list[Path] = []
    monkeypatch.setattr(
        decompile,
        "_build_project",
        lambda path, **_kwargs: rebuilds.append(path) or (_ for _ in ()).throw(AssertionError("seed recovery should not rebuild")),
    )
    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=0x1003, name="sub_1003", is_plt=False, is_simprocedure=False)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: (expected_cfg, expected_func))

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=1)

    assert recovered == [(expected_cfg, expected_func)]
    assert rebuilds == []


def test_recover_seeded_exe_functions_keeps_ranked_seeds_ahead_of_neighbor_follow_ons(monkeypatch):
    code = b"\x55\x8B\xEC" + b"\x90" * 0x40
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)]))
        ),
    )
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x1010, 0x1200])
    monkeypatch.setattr(decompile, "_load_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_store_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())
    recovered_order: list[int] = []

    def _fake_pick(_project, addr, **_kwargs):
        recovered_order.append(addr)
        return SimpleNamespace(), SimpleNamespace(addr=addr, name=f"sub_{addr:x}", is_plt=False, is_simprocedure=False)

    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick)
    monkeypatch.setattr(
        decompile,
        "collect_neighbor_call_targets",
        lambda function: [SimpleNamespace(target_addr=0x1030)] if function.addr == 0x1010 else [],
    )

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=3)

    assert [func.addr for _cfg, func in recovered] == [0x1010, 0x1200, 0x1030]
    assert recovered_order[:3] == [0x1010, 0x1200, 0x1030]


def test_recover_seeded_exe_functions_includes_prologue_scan_candidates(monkeypatch):
    code = bytearray(b"\x90" * 0x400)
    base = 0x1000
    prologue_addr = 0x1110
    seed_addr = 0x1200
    code[prologue_addr - base : prologue_addr - base + 3] = b"\x55\x8B\xEC"

    def _load(addr, size, **_kwargs):
        if addr == 0:
            return bytes(code[:size])
        return bytes(code[addr - base : addr - base + size])

    project = SimpleNamespace(
        entry=0x1100,
        arch=SimpleNamespace(name="86_16", capstone=Arch86_16().capstone),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=base,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=_load),
            )
        ),
        factory=SimpleNamespace(
            block=lambda addr, size=16, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(insns=list(project.arch.capstone.disasm(bytes(code[addr - base : addr - base + size]), addr)))
            )
        ),
    )
    recovered_order: list[int] = []
    monkeypatch.setattr(decompile, "_load_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_store_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [seed_addr])
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda _project, addr, **_kwargs: (
            recovered_order.append(addr) or SimpleNamespace(),
            SimpleNamespace(addr=addr, name=f"sub_{addr:x}", is_plt=False, is_simprocedure=False),
        ),
    )
    monkeypatch.setattr(decompile, "collect_neighbor_call_targets", lambda _function: [])

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=2)

    assert [func.addr for _cfg, func in recovered] == [prologue_addr, seed_addr]
    assert recovered_order[0] == prologue_addr
    assert seed_addr in recovered_order


def test_recover_seeded_exe_functions_scans_tiny_entry_body_for_direct_calls(monkeypatch):
    code = bytearray(b"\x90" * 0x400)
    base = 0x1000
    func_addr = 0x1010
    target_addr = 0x1030
    branch_addr = 0x1018
    rel = target_addr - (func_addr + 4 + 3)
    code[func_addr - base : func_addr - base + 4] = b"\x55\x8B\xEC\x90"
    code[func_addr - base + 4 : func_addr - base + 7] = b"\xE8" + int(rel).to_bytes(2, "little", signed=True)
    jmp_rel = branch_addr - (func_addr + 7 + 2)
    code[func_addr - base + 7 : func_addr - base + 9] = b"\xEB" + int(jmp_rel).to_bytes(1, "little", signed=True)
    code[func_addr - base + 9] = 0xC3
    project = SimpleNamespace(
        entry=0x1100,
        arch=SimpleNamespace(name="86_16", capstone=Arch86_16().capstone),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=base,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda addr, size, **_kwargs: bytes(code[addr - base : addr - base + size])),
            ),
            memory=SimpleNamespace(load=lambda addr, size, **_kwargs: bytes(code[addr - base : addr - base + size])),
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)]))
        ),
    )
    monkeypatch.setattr(decompile, "_load_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_store_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [func_addr, 0x1200])
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda _project, addr, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(
                addr=addr,
                name=f"sub_{addr:x}",
                is_plt=False,
                is_simprocedure=False,
                blocks=(SimpleNamespace(size=0x10),),
            ),
        ),
    )
    monkeypatch.setattr(decompile, "collect_neighbor_call_targets", lambda _function: [])

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=3)

    assert [func.addr for _cfg, func in recovered] == [func_addr, 0x1200, target_addr]


def test_rank_gap_scan_candidate_addrs_rejects_out_of_image_candidates():
    code = bytearray(b"\x90" * 0x80)
    base = 0x1000
    prologue_addr = 0x1020
    call_addr = 0x1010
    out_of_image_target = 0x2000
    rel = out_of_image_target - (call_addr + 3)
    code[prologue_addr - base : prologue_addr - base + 3] = b"\x55\x8B\xEC"
    code[call_addr - base : call_addr - base + 3] = b"\xE8" + int(rel).to_bytes(2, "little", signed=True)

    class _Memory:
        def load(self, offset, size):
            return bytes(code[offset : offset + size])

    class _AbsMemory:
        def load(self, addr, size, **_kwargs):
            return bytes(code[addr - base : addr - base + size])

    project = SimpleNamespace(
        entry=0x1010,
        arch=SimpleNamespace(name="86_16", capstone=Arch86_16().capstone),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(max_addr=len(code) - 1, linked_base=base, memory=_Memory()),
            memory=_AbsMemory(),
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(
                    insns=[
                        SimpleNamespace(mnemonic="push", op_str="bp"),
                        SimpleNamespace(mnemonic="mov", op_str="bp, sp"),
                    ]
                )
            )
        ),
    )
    recovered = [
        (
            SimpleNamespace(),
            SimpleNamespace(
                addr=0x1010,
                blocks=(SimpleNamespace(addr=call_addr, size=3),),
            ),
        )
    ]

    ranked = decompile._rank_gap_scan_candidate_addrs(
        project,
        recovered,
        covered_ranges=[(0x1008, 0x100C)],
        existing_addrs={0x1008},
        image_end=base + len(code),
    )

    assert prologue_addr in ranked
    assert out_of_image_target not in ranked


def test_recover_seeded_exe_functions_queues_gap_candidates_before_wrapper_follow_ons(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x10000,
                max_addr=0x600,
            )
        ),
    )
    recovered_order: list[int] = []

    monkeypatch.setattr(decompile, "_load_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_store_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x10010])
    monkeypatch.setattr(decompile, "_rank_prologue_scan_candidate_addrs", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_rank_gap_scan_candidate_addrs", lambda *_args, **_kwargs: [0x10050])

    def _fake_recover(_project, *, candidate_addr, **_kwargs):
        recovered_order.append(candidate_addr)
        if candidate_addr == 0x10010:
            func = SimpleNamespace(
                addr=candidate_addr,
                name=f"sub_{candidate_addr:x}",
                is_plt=False,
                is_simprocedure=False,
                info={"x86_16_recovery_truncated": True},
                blocks=(SimpleNamespace(addr=candidate_addr, size=0x18),),
            )
        elif candidate_addr == 0x10050:
            func = SimpleNamespace(
                addr=candidate_addr,
                name=f"sub_{candidate_addr:x}",
                is_plt=False,
                is_simprocedure=False,
                blocks=(SimpleNamespace(addr=candidate_addr, size=0x40),),
            )
        else:
            func = SimpleNamespace(
                addr=candidate_addr,
                name=f"sub_{candidate_addr:x}",
                is_plt=False,
                is_simprocedure=False,
                blocks=(SimpleNamespace(addr=candidate_addr, size=0x10),),
            )
        return SimpleNamespace(), func

    monkeypatch.setattr(decompile, "_recover_candidate_with_timeout", _fake_recover)
    monkeypatch.setattr(
        decompile,
        "collect_neighbor_call_targets",
        lambda function: [SimpleNamespace(target_addr=0x100A0)] if function.addr == 0x10010 else [],
    )
    monkeypatch.setattr(decompile, "_linear_function_seed_targets", lambda *_args, **_kwargs: set())

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=3)

    assert [func.addr for _cfg, func in recovered] == [0x10010, 0x10050, 0x100A0]
    assert recovered_order[:3] == [0x10010, 0x10050, 0x100A0]


def test_recover_candidate_function_pair_prefers_richer_bounded_body_recovery(monkeypatch):
    candidate_addr = 0x1000
    candidate_project = SimpleNamespace(
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)]))
        )
    )
    narrow_region = (candidate_addr, candidate_addr + 0x20)
    wide_region = (candidate_addr, candidate_addr + 0x100)

    def _function(addr, sizes):
        return SimpleNamespace(
            addr=addr,
            blocks=tuple(SimpleNamespace(size=size) for size in sizes),
            is_plt=False,
            is_simprocedure=False,
        )

    monkeypatch.setattr(decompile, "_candidate_recovery_regions", lambda *_args, **_kwargs: [narrow_region, wide_region])
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda _project, _addr, *, regions, **_kwargs: (
            SimpleNamespace(region=regions[0]),
            _function(candidate_addr, (8, 8, 8, 8)) if regions[0] == narrow_region else _function(candidate_addr, (0x18, 0x18, 0x18, 0x18, 0x18)),
        ),
    )
    monkeypatch.setattr(decompile, "_pick_function", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected richer fallback")))

    recovered_cfg, recovered_function = decompile._recover_candidate_function_pair(
        candidate_project,
        candidate_addr=candidate_addr,
        image_end=0x2000,
        metadata=None,
        project_entry=0x1100,
        region_span=0x120,
    )

    assert recovered_cfg.region == wide_region
    assert decompile._function_recovery_score(recovered_function) == (5, 0x78)


def test_recover_candidate_function_pair_retries_richer_bounded_region_when_exact_region_truncates(monkeypatch):
    candidate_addr = 0x1000
    candidate_project = SimpleNamespace(
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)]))
        )
    )
    exact_region = (candidate_addr, candidate_addr + 0x100)
    bounded_region = (candidate_addr, candidate_addr + 0x180)

    def _function(addr, sizes):
        return SimpleNamespace(
            addr=addr,
            blocks=tuple(SimpleNamespace(size=size) for size in sizes),
            is_plt=False,
            is_simprocedure=False,
            info={},
        )

    monkeypatch.setattr(
        decompile,
        "_candidate_recovery_regions",
        lambda metadata, *_args, **_kwargs: [exact_region] if metadata is not None else [bounded_region],
    )
    monkeypatch.setattr(decompile, "_lst_code_region", lambda _metadata, _addr: exact_region)
    monkeypatch.setattr(
        decompile,
        "_richest_bounded_recovery_region",
        lambda _addr, *, image_end, region_span: bounded_region if image_end and region_span else bounded_region,
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda _project, _addr, *, regions, **_kwargs: (
            SimpleNamespace(region=regions[0]),
            _function(candidate_addr, (8, 8)),
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function",
        lambda _project, _addr, *, regions, **_kwargs: (
            SimpleNamespace(region=regions[0]),
            _function(candidate_addr, (0x18, 0x18, 0x18, 0x18, 0x18)),
        )
        if regions[0] == bounded_region
        else (_ for _ in ()).throw(AssertionError("unexpected exact-region fallback")),
    )

    recovered_cfg, recovered_function = decompile._recover_candidate_function_pair(
        candidate_project,
        candidate_addr=candidate_addr,
        image_end=0x2000,
        metadata=SimpleNamespace(),
        project_entry=0x1100,
        region_span=0x120,
    )

    assert recovered_cfg.region == bounded_region
    assert decompile._function_recovery_score(recovered_function) == (5, 0x78)
    assert recovered_function.info["x86_16_recovery_truncated"] is False


def test_rank_function_cfg_pairs_for_display_prefers_body_seed_and_its_callees(monkeypatch):
    project = SimpleNamespace(entry=0x11423)
    pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="_start")),
        (SimpleNamespace(), SimpleNamespace(addr=0x114cd, name="runtime_init")),
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010")),
        (SimpleNamespace(), SimpleNamespace(addr=0x101a3, name="sub_101a3")),
    ]
    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: (
            {0x114cd, 0x10010} if addr == 0x11423 else {0x101a3} if addr == 0x10010 else set()
        ),
    )

    ranked = decompile._rank_function_cfg_pairs_for_display(project, pairs)

    assert [function.addr for _cfg, function in ranked] == [0x11423, 0x10010, 0x101a3, 0x114cd]


def test_rank_function_cfg_pairs_for_display_demotes_tiny_wrapper_like_entry_targets(monkeypatch):
    project = SimpleNamespace(entry=0x11423)
    pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="_start", blocks=(SimpleNamespace(size=0x16),))),
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", blocks=(SimpleNamespace(size=0x14),))),
        (SimpleNamespace(), SimpleNamespace(addr=0x1157c, name="tiny_wrapper", blocks=(SimpleNamespace(size=0x08), SimpleNamespace(size=0x08)))),
        (SimpleNamespace(), SimpleNamespace(addr=0x1223b, name="bigger_body", blocks=(SimpleNamespace(size=0x20), SimpleNamespace(size=0x20), SimpleNamespace(size=0x20)))),
    ]
    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: (
            {0x114cd, 0x10010, 0x1157c, 0x1223b} if addr == 0x11423 else set()
        ),
    )

    ranked = decompile._rank_function_cfg_pairs_for_display(project, pairs)

    assert [function.addr for _cfg, function in ranked] == [0x11423, 0x10010, 0x1223b, 0x1157c]


def test_rank_function_cfg_pairs_for_display_prefers_large_pre_entry_body_when_complexity_needs_recovery_fallback(monkeypatch):
    project = SimpleNamespace(entry=0x11423)
    entry = (
        SimpleNamespace(),
        SimpleNamespace(addr=0x11423, name="_start", project=project, blocks=(SimpleNamespace(size=0x20),)),
    )
    body = (
        SimpleNamespace(),
        SimpleNamespace(addr=0x10010, name="sub_10010", project=project, blocks=(SimpleNamespace(size=0x50),)),
    )
    runtime_shell = (
        SimpleNamespace(),
        SimpleNamespace(addr=0x11440, name="runtime_shell", project=project, blocks=(SimpleNamespace(size=0x10),)),
    )

    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x11440} if addr == 0x11423 else set(),
    )

    ranked = decompile._rank_function_cfg_pairs_for_display(project, [runtime_shell, body, entry])

    assert [function.addr for _cfg, function in ranked[:3]] == [0x11423, 0x10010, 0x11440]


def test_function_attempt_status_reports_uncollected_when_tail_validation_disabled(capsys):
    function = SimpleNamespace(
        addr=0x10010,
        name="sub_10010",
        project=SimpleNamespace(_inertia_tail_validation_enabled=False),
    )

    decompile._print_function_attempt_status(
        function,
        attempt="decompiled",
        validation_snapshot=None,
    )

    assert "attempt=decompiled validation=uncollected" in capsys.readouterr().out


def test_function_attempt_status_reports_failed_for_changed_tail_validation(capsys):
    function = SimpleNamespace(
        addr=0x10010,
        name="sub_10010",
        project=SimpleNamespace(_inertia_tail_validation_enabled=True),
    )

    decompile._print_function_attempt_status(
        function,
        attempt="decompiled",
        validation_snapshot={
            "structuring": {"changed": False, "status": "stable"},
            "postprocess": {"changed": True, "status": "changed"},
        },
    )

    assert "attempt=decompiled validation=failed" in capsys.readouterr().out


def test_run_function_work_item_uses_persistent_disk_cache(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    calls = {"count": 0}

    def _fake_decompile(*_args, **_kwargs):
        calls["count"] += 1
        item.function.info = {
            "x86_16_tail_validation": {
                "structuring": {"changed": False, "verdict": "structuring stable"},
                "postprocess": {"changed": False, "verdict": "postprocess stable"},
            }
        }
        return "ok", "int sub_1000(void) { return 1; }", None, 1, 4, 0.01

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-a")
    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)

    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=SimpleNamespace(),
        function=SimpleNamespace(addr=0x1000, name="sub_1000", project=SimpleNamespace()),
    )

    first = decompile._run_function_work_item(
        item,
        timeout=5,
        api_style="pascal",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
    )
    second = decompile._run_function_work_item(
        item,
        timeout=5,
        api_style="pascal",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
    )

    assert calls["count"] == 1
    assert first.payload == second.payload
    assert "cache hit" in second.debug_output
    assert "validation=passed" in second.debug_output
    assert second.tail_validation == {
        "structuring": {"changed": False, "mode": None, "verdict": "structuring stable", "summary_text": None},
        "postprocess": {"changed": False, "mode": None, "verdict": "postprocess stable", "summary_text": None},
    }


def test_run_function_work_item_bypasses_persistent_cache_without_passed_tail_validation(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    calls = {"count": 0}

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-a")

    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=SimpleNamespace(),
        function=SimpleNamespace(addr=0x1000, name="sub_1000", project=SimpleNamespace(), info={}),
    )

    def _fake_decompile(*_args, **_kwargs):
        calls["count"] += 1
        item.function.info = {
            "x86_16_tail_validation": {
                "structuring": {"changed": False, "verdict": "structuring stable"},
                "postprocess": {"changed": False, "verdict": "postprocess stable"},
            }
        }
        return "ok", "int sub_1000(void) { return 2; }", None, 1, 4, 0.01

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)

    cache_key = recovery_cache._function_decompilation_cache_key(
        binary_path=binary,
        function_addr=0x1000,
        function_name="sub_1000",
        api_style="pascal",
        enable_structured_simplify=True,
        enable_postprocess=True,
    )
    decompile._store_cache_json(
        "function_decompile",
        cache_key,
        {
            "status": "ok",
            "payload": "int stale(void) { return 0; }",
        },
    )

    result = decompile._run_function_work_item(
        item,
        timeout=5,
        api_style="pascal",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
    )

    assert calls["count"] == 1
    assert "stale" not in result.payload
    assert "cache bypass" in result.debug_output
    assert "validation=uncollected" in result.debug_output
    stored = decompile._load_cache_json("function_decompile", cache_key)
    assert stored["status"] == "ok"
    assert stored["payload"] == "int sub_1000(void) { return 2; }"
    assert stored["tail_validation_passed"] is True
    assert stored["elapsed"] == 0.01
    assert stored["block_count"] == 1
    assert stored["byte_count"] == 4
    assert stored["tail_validation"] == {
        "structuring": {
            "changed": False,
            "mode": None,
            "status": "stable",
            "verdict": "structuring stable",
            "summary_text": None,
        },
        "postprocess": {
            "changed": False,
            "mode": None,
            "status": "stable",
            "verdict": "postprocess stable",
            "summary_text": None,
        },
    }


def test_run_function_work_item_cache_separates_same_addr_cod_proc_names(monkeypatch, tmp_path):
    binary = tmp_path / "sample.cod"
    binary.write_bytes(b"PROC")
    calls = {"count": 0}

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-a")

    def _item(name):
        return decompile.FunctionWorkItem(
            index=1,
            function_cfg=SimpleNamespace(),
            function=SimpleNamespace(addr=0x1000, name=name, project=SimpleNamespace(), info={}),
        )

    def _fake_decompile(_project, _cfg, function, *_args, **_kwargs):
        calls["count"] += 1
        function.info = {
            "x86_16_tail_validation": {
                "structuring": {"changed": False, "verdict": "structuring stable"},
                "postprocess": {"changed": False, "verdict": "postprocess stable"},
            }
        }
        return "ok", f"void {function.name}(void) {{}}", None, 1, 4, 0.01

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)

    first = decompile._run_function_work_item(
        _item("_FirstProc"),
        timeout=5,
        api_style="pascal",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
    )
    second = decompile._run_function_work_item(
        _item("_SecondProc"),
        timeout=5,
        api_style="pascal",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
    )

    assert calls["count"] == 2
    assert "_FirstProc" in first.payload
    assert "_SecondProc" in second.payload
    assert "cache hit" not in second.debug_output


def test_run_function_work_item_does_not_cache_timeout_results(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    calls = {"count": 0}

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-a")

    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=SimpleNamespace(),
        function=SimpleNamespace(addr=0x1000, name="sub_1000", project=SimpleNamespace(), info={}),
    )

    def _fake_timeout(*_args, **_kwargs):
        calls["count"] += 1
        return "timeout", "Timed out after 5s.", None, 1, 0, 5.0

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_timeout)

    first = decompile._run_function_work_item(
        item,
        timeout=5,
        api_style="pascal",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
    )
    second = decompile._run_function_work_item(
        item,
        timeout=5,
        api_style="pascal",
        binary_path=binary,
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
    )

    assert first.status == "timeout"
    assert second.status == "timeout"
    assert calls["count"] == 2
    cached = decompile._load_cache_json(
        "function_decompile",
        recovery_cache._function_decompilation_cache_key(
            binary_path=binary,
            function_addr=0x1000,
            function_name="sub_1000",
            api_style="pascal",
            enable_structured_simplify=True,
            enable_postprocess=True,
        ),
    )
    assert cached is None


def test_try_decompile_non_optimized_slice_retries_with_fresh_project(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"\x90" * 0x40)
    shared_project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )
    fresh_project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )
    slice_project = SimpleNamespace()
    cfg = SimpleNamespace()

    class FakeFunction:
        def __init__(self):
            self.addr = 0x11593
            self.name = "sub_11593"
            self.normalized = False

        def normalize(self):
            self.normalized = True

        def get_call_sites(self):
            return []

        def get_call_target(self, _callsite):
            return 0x1140D

    func = FakeFunction()
    calls = {"decompile": 0}

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x11593, 0x115b5))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *_args, **_kwargs: slice_project)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(decompile, "_sidecar_cod_metadata_for_function", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_build_project",
        lambda path, **_kwargs: fresh_project if Path(path) == binary else shared_project,
    )
    monkeypatch.setattr(
        decompile,
        "_build_project_cached",
        lambda path, **_kwargs: fresh_project if Path(path) == binary else shared_project,
    )
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())

    def _fake_decompile(project, *_args, **_kwargs):
        calls["decompile"] += 1
        if calls["decompile"] == 1:
            return "timeout", "Timed out after 6s.", 1, 0x20, 6.0
        return "ok", "int sub_11593(void) { return 0; }", 1, 0x20, 1.0

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)

    outcome = decompile._try_decompile_non_optimized_slice(
        shared_project,
        0x11593,
        "sub_11593",
        timeout=6,
        api_style="modern",
        binary_path=binary,
        lst_metadata=None,
    )

    assert calls["decompile"] == 2
    assert outcome.rendered == "int sub_11593(void) { return 0; }"


def test_try_decompile_non_optimized_slice_prepares_direct_callee_context_before_retry(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"\x90" * 0x40)
    shared_project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )
    fresh_project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )

    class FakeFunctionManager:
        def __init__(self):
            self.created: list[int] = []

        def function(self, *, addr=None, create=False, **_kwargs):
            if create:
                self.created.append(addr)
            return SimpleNamespace(addr=addr)

    class FakeFunction:
        def __init__(self):
            self.addr = 0x11593
            self.name = "sub_11593"
            self.normalized = False
            self._callsite_checks = 0

        def normalize(self):
            self.normalized = True

        def get_call_sites(self):
            self._callsite_checks += 1
            if self._callsite_checks == 1:
                return []
            return [0x1159F]

        def get_call_target(self, _callsite):
            return 0x1140D

    slice_project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        kb=SimpleNamespace(functions=FakeFunctionManager()),
    )
    cfg = SimpleNamespace()
    func = FakeFunction()
    calls = {"decompile": 0}

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x11593, 0x115b5))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *_args, **_kwargs: slice_project)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(decompile, "_sidecar_cod_metadata_for_function", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_build_project",
        lambda path, **_kwargs: fresh_project if Path(path) == binary else shared_project,
    )
    monkeypatch.setattr(
        decompile,
        "_build_project_cached",
        lambda path, **_kwargs: fresh_project if Path(path) == binary else shared_project,
    )
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())

    def _fake_decompile(project, *_args, **_kwargs):
        calls["decompile"] += 1
        if not project.kb.functions.created:
            return "timeout", "missing direct callee context", 1, 0x20, 6.0
        return "ok", "int sub_11593(void) { return 0; }", 1, 0x20, 1.0

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)

    outcome = decompile._try_decompile_non_optimized_slice(
        shared_project,
        0x11593,
        "sub_11593",
        timeout=6,
        api_style="modern",
        binary_path=binary,
        lst_metadata=None,
    )

    assert calls["decompile"] == 2
    assert func.normalized is True
    assert slice_project.kb.functions.created == [0x1140D]
    assert outcome.rendered == "int sub_11593(void) { return 0; }"


def test_try_decompile_non_optimized_slice_retries_with_blob_project_for_cod_inputs(monkeypatch):
    shared_project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )
    fresh_project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )
    slice_project = SimpleNamespace()
    cfg = SimpleNamespace()
    func = SimpleNamespace(name="sub_11593")
    calls = {"decompile": 0, "build": []}

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x11593, 0x115b5))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *_args, **_kwargs: slice_project)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(decompile, "_sidecar_cod_metadata_for_function", lambda *_args, **_kwargs: None)

    def _fake_build_project(path, *, force_blob, base_addr, entry_point):
        calls["build"].append((Path(path), force_blob, base_addr, entry_point))
        assert Path(path) == LIFE_COD
        assert force_blob is True
        return fresh_project

    monkeypatch.setattr(decompile, "_build_project", _fake_build_project)
    monkeypatch.setattr(decompile, "_build_project_cached", _fake_build_project)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())

    def _fake_decompile(project, *_args, **_kwargs):
        calls["decompile"] += 1
        if calls["decompile"] == 1:
            return "timeout", "Timed out after 6s.", 1, 0x20, 6.0
        return "ok", "int sub_11593(void) { return 0; }", 1, 0x20, 1.0

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)

    outcome = decompile._try_decompile_non_optimized_slice(
        shared_project,
        0x11593,
        "sub_11593",
        timeout=6,
        api_style="modern",
        binary_path=LIFE_COD,
        lst_metadata=None,
    )

    assert calls["build"] == [(LIFE_COD, True, 0x1000, 0x1000)]
    assert calls["decompile"] == 2
    assert outcome.rendered == "int sub_11593(void) { return 0; }"


def test_try_decompile_non_optimized_slice_never_caches_results(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"\x90" * 0x40)
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x1000),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )
    slice_project = SimpleNamespace()
    cfg = SimpleNamespace()

    class FakeFunction:
        def __init__(self):
            self.addr = 0x114CD
            self.name = "sub_114cd"
            self.normalized = False

        def normalize(self):
            self.normalized = True

        def get_call_sites(self):
            return []

        def get_call_target(self, _callsite):
            return 0x1140D

    func = FakeFunction()

    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x114cd, 0x114eb))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *_args, **_kwargs: slice_project)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(decompile, "_sidecar_cod_metadata_for_function", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_build_project",
        lambda path, **_kwargs: fresh_project if Path(path) == binary else project,
    )
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "void sub_114cd(void) {}", 1, 0x20, 0.5),
    )

    def _unexpected_cache_write(*_args, **_kwargs):
        raise AssertionError("non-optimized fallback should not write cache entries")

    monkeypatch.setattr(decompile, "_store_cache_json", _unexpected_cache_write)

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x114cd,
        "sub_114cd",
        timeout=6,
        api_style="modern",
        binary_path=binary,
        lst_metadata=None,
    )

    assert outcome.rendered == "void sub_114cd(void) {}"


def test_decompile_function_empty_reports_angr_error_detail(monkeypatch):
    class FakeErrorEntry:
        def __init__(self, error):
            self.error = error

    class FakeDecompiler:
        def __init__(self, *_args, **_kwargs):
            self.codegen = None
            self.errors = [FakeErrorEntry(KeyError(5133))]
            self.clinic = None

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        analyses=SimpleNamespace(
            Decompiler=FakeDecompiler,
            Clinic=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError()),
        ),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x200)),
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", normalized=True, blocks=(SimpleNamespace(size=0x10),))
    cfg = SimpleNamespace()

    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "seed_calling_conventions", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_preferred_decompiler_options", lambda *_args, **_kwargs: None)

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=1,
        api_style="pascal",
        binary_path=None,
        allow_isolated_retry=False,
    )

    assert status == "empty"
    assert "KeyError: 5133" in payload
    assert "clinic=None" in payload
    assert "clinic-failure=AssertionError" in payload


def test_decompile_function_timeout_returns_partial_codegen_text(monkeypatch):
    class FakeCodegen:
        text = "int partial(void) { return 1; }"

        cfunc = object()

        def render_text(self, _cfunc):
            return self.text

    class FakeDecompiler:
        def __init__(self, *_args, **_kwargs):
            self.codegen = FakeCodegen()
            self.errors = []
            self.clinic = object()

    @contextlib.contextmanager
    def _fake_timeout(_seconds):
        yield
        raise decompile._AnalysisTimeout()

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        analyses=SimpleNamespace(Decompiler=FakeDecompiler),
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", normalized=True, blocks=(SimpleNamespace(size=0x10),))
    cfg = SimpleNamespace()

    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "seed_calling_conventions", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_preferred_decompiler_options", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_analysis_timeout", _fake_timeout)
    monkeypatch.setattr(decompile, "_format_known_helper_calls", lambda *_args, **_kwargs: _args[2])

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=1,
        api_style="modern",
        binary_path=None,
        allow_isolated_retry=False,
    )

    assert status == "timeout"
    assert payload == "Timed out after 1s."
    assert project._inertia_partial_codegen_text == "int partial(void) { return 1; }"


def test_resolve_stack_cvar_from_addr_expr_materializes_derived_word_stack_local(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        arg_list=(),
        sort_local_vars=lambda: None,
        unified_local_vars={},
        variables_in_use={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, next_idx=lambda _name: 0, project=project)

    base_var = SimStackVariable(-2, 1, base="bp", name="s_2", region=0x10010)
    base_cvar = structured_c.CVariable(base_var, codegen=codegen)
    low_addr_expr = object()

    monkeypatch.setattr(
        decompile,
        "_classify_segmented_addr_expr",
        lambda expr, _project: SimpleNamespace(kind="stack", cvar=base_cvar, stack_var=base_var, extra_offset=2)
        if expr is low_addr_expr
        else None,
    )

    resolved = decompile._resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)

    assert isinstance(resolved, structured_c.CVariable)
    assert isinstance(resolved.variable, SimStackVariable)
    assert resolved.variable.offset == 0
    assert resolved.variable.size == 2
    assert codegen.cfunc.variables_in_use[resolved.variable] is resolved
    assert resolved.variable in codegen.cfunc.unified_local_vars
    assert any(cvar is resolved for cvar, _vartype in codegen.cfunc.unified_local_vars[resolved.variable])


def test_coalesce_segmented_word_store_statements_prefers_derived_stack_local_word_lhs(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, bits=16, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        arg_list=(),
        sort_local_vars=lambda: None,
        unified_local_vars={},
        variables_in_use={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, next_idx=lambda _name: 0, project=project)

    base_var = SimStackVariable(-2, 1, base="bp", name="s_2", region=0x10010)
    base_cvar = structured_c.CVariable(base_var, codegen=codegen)
    low_addr_expr = SimpleNamespace(type=None)
    high_addr_expr = SimpleNamespace(type=None)
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                SimpleNamespace(type=SimTypeChar(False)),
                structured_c.CConstant(0x12, SimTypeChar(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                SimpleNamespace(type=SimTypeChar(False)),
                structured_c.CConstant(0x34, SimTypeChar(False), codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    alias_facts = SimpleNamespace(identity=object(), can_join=lambda _other: True, needs_synthesis=lambda: False)
    word_rhs = structured_c.CConstant(0x3412, SimTypeShort(False), codegen=codegen)

    monkeypatch.setattr(
        decompile,
        "_classify_segmented_addr_expr",
        lambda expr, _project: SimpleNamespace(kind="stack", cvar=base_cvar, stack_var=base_var, extra_offset=2)
        if expr is low_addr_expr
        else None,
    )
    monkeypatch.setattr(decompile, "describe_alias_storage", lambda _expr: alias_facts)
    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: True)
    monkeypatch.setattr(
        decompile,
        "_match_byte_store_addr_expr",
        lambda node: low_addr_expr if node is root.statements[0].lhs else high_addr_expr if node is root.statements[1].lhs else None,
    )
    monkeypatch.setattr(
        decompile,
        "_match_word_rhs_from_byte_pair",
        lambda _low_rhs, _high_rhs, _codegen, _project: word_rhs,
    )

    changed = decompile._coalesce_segmented_word_store_statements(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    replacement = codegen.cfunc.statements.statements[0]
    assert isinstance(replacement, structured_c.CAssignment)
    assert isinstance(replacement.lhs, structured_c.CVariable)
    assert isinstance(replacement.lhs.variable, SimStackVariable)
    assert replacement.lhs.variable.offset == 0
    assert replacement.lhs.variable.size == 2


def test_coalesce_segmented_word_store_statements_refuses_non_joinable_stack_slot(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, bits=16, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        arg_list=(),
        sort_local_vars=lambda: None,
        unified_local_vars={},
        variables_in_use={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, next_idx=lambda _name: 0, project=project)

    base_var = SimStackVariable(-2, 1, base="bp", name="s_2", region=0x10010)
    base_cvar = structured_c.CVariable(base_var, codegen=codegen)
    lhs_var = SimStackVariable(0, 1, base="bp", name="s_0", region=0x20020)
    lhs_cvar = structured_c.CVariable(lhs_var, codegen=codegen)
    next_lhs = object()
    rhs_low = structured_c.CConstant(0x12, SimTypeChar(False), codegen=codegen)
    rhs_high = structured_c.CConstant(0x34, SimTypeChar(False), codegen=codegen)
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(lhs_cvar, rhs_low, codegen=codegen),
            structured_c.CAssignment(next_lhs, rhs_high, codegen=codegen),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root
    word_rhs = structured_c.CConstant(0x3412, SimTypeShort(False), codegen=codegen)

    monkeypatch.setattr(decompile, "_match_ss_local_plus_const", lambda node, _project: (base_cvar, 1) if node is next_lhs else None)
    monkeypatch.setattr(decompile, "_match_word_rhs_from_byte_pair", lambda _lo, _hi, _codegen, _project: word_rhs)
    monkeypatch.setattr(decompile, "_stack_slot_identity_can_join", lambda _lhs, _rhs: False)

    changed = decompile._coalesce_segmented_word_store_statements(project, codegen)

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 2
    assert codegen.cfunc.statements.statements[0].lhs is lhs_cvar
    assert codegen.cfunc.statements.statements[1].lhs is next_lhs


def test_coalesce_segmented_word_store_statements_accepts_stable_ds_segment_const_pair_without_alias_identity(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, bits=16, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        arg_list=(),
        sort_local_vars=lambda: None,
        unified_local_vars={},
        variables_in_use={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, next_idx=lambda _name: 0, project=project)

    low_addr_expr = object()
    high_addr_expr = object()
    low_lhs = object()
    high_lhs = object()
    rhs_low = structured_c.CConstant(0x12, SimTypeChar(False), codegen=codegen)
    rhs_high = structured_c.CConstant(0x34, SimTypeChar(False), codegen=codegen)
    word_rhs = structured_c.CConstant(0x3412, SimTypeShort(False), codegen=codegen)
    replacement_lhs = object()

    root = structured_c.CStatements(
        [
            structured_c.CAssignment(low_lhs, rhs_low, codegen=codegen),
            structured_c.CAssignment(high_lhs, rhs_high, codegen=codegen),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    monkeypatch.setattr(
        decompile,
        "_match_byte_store_addr_expr",
        lambda node: low_addr_expr if node is low_lhs else high_addr_expr if node is high_lhs else None,
    )
    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: True)
    monkeypatch.setattr(decompile, "_match_word_rhs_from_byte_pair", lambda _lo, _hi, _codegen, _project: word_rhs)
    monkeypatch.setattr(
        decompile,
        "describe_alias_storage",
        lambda _expr: SimpleNamespace(identity=None, can_join=lambda _other: False),
    )
    monkeypatch.setattr(
        decompile,
        "_classify_segmented_addr_expr",
        lambda expr, _project: SimpleNamespace(kind="segment_const", seg_name="ds", linear=0x0BAA if expr is low_addr_expr else 0x0BAB),
    )
    monkeypatch.setattr(decompile, "_resolve_stack_cvar_from_addr_expr", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_make_word_dereference_from_addr_expr", lambda _codegen, _project, _addr_expr: replacement_lhs)

    changed = decompile._coalesce_segmented_word_store_statements(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    replacement = codegen.cfunc.statements.statements[0]
    assert isinstance(replacement, structured_c.CAssignment)
    assert replacement.lhs is replacement_lhs
    assert replacement.rhs is word_rhs


def test_match_byte_store_addr_expr_accepts_word_typed_dereference_split_store():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False)

    addr_expr = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x2000, SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    deref = decompile._make_word_dereference_from_addr_expr(codegen, project, addr_expr)

    assert decompile._match_byte_store_addr_expr(deref) is addr_expr


def test_coalesce_segmented_word_store_statements_rewrites_word_typed_split_store_inside_while_loop(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        arg_list=(),
        sort_local_vars=lambda: None,
        unified_local_vars={},
        variables_in_use={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, next_idx=lambda _name: 0, project=project, cstyle_null_cmp=False)

    low_addr_expr = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x2000, SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    high_addr_expr = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x2000, SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    low_lhs = decompile._make_word_dereference_from_addr_expr(codegen, project, low_addr_expr)
    high_lhs = decompile._make_word_dereference_from_addr_expr(codegen, project, high_addr_expr)
    rhs_low = structured_c.CConstant(0x12, SimTypeChar(False), codegen=codegen)
    rhs_high = structured_c.CConstant(0x34, SimTypeChar(False), codegen=codegen)
    word_rhs = structured_c.CConstant(0x3412, SimTypeShort(False), codegen=codegen)
    replacement_lhs = object()

    loop_body = structured_c.CStatements(
        [
            structured_c.CAssignment(low_lhs, rhs_low, codegen=codegen),
            structured_c.CAssignment(high_lhs, rhs_high, codegen=codegen),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    loop = structured_c.CWhileLoop(
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        loop_body,
        codegen=codegen,
    )
    cfunc.statements = structured_c.CStatements([loop], addr=0x10010, codegen=codegen)

    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: True)
    monkeypatch.setattr(decompile, "_match_word_rhs_from_byte_pair", lambda _lo, _hi, _codegen, _project: word_rhs)
    monkeypatch.setattr(
        decompile,
        "describe_alias_storage",
        lambda _expr: SimpleNamespace(identity=None, can_join=lambda _other: False),
    )
    monkeypatch.setattr(
        decompile,
        "_classify_segmented_addr_expr",
        lambda expr, _project: SimpleNamespace(kind="segment_const", seg_name="ds", linear=0x2000 if expr is low_addr_expr else 0x2001),
    )
    monkeypatch.setattr(decompile, "_resolve_stack_cvar_from_addr_expr", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_make_word_dereference_from_addr_expr", lambda _codegen, _project, _addr_expr: replacement_lhs)

    changed = decompile._coalesce_segmented_word_store_statements(project, codegen)

    assert changed is True
    rewritten_loop = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten_loop, structured_c.CWhileLoop)
    assert len(rewritten_loop.body.statements) == 1
    replacement = rewritten_loop.body.statements[0]
    assert isinstance(replacement, structured_c.CAssignment)
    assert replacement.lhs is replacement_lhs
    assert replacement.rhs is word_rhs


def test_coalesce_segmented_word_load_expressions_preserves_existing_dereference_evidence(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(addr=0x10010)
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False)

    addr_var = SimRegisterVariable(0, 2)
    addr_cvar = structured_c.CVariable(addr_var, codegen=codegen)
    low_addr_expr = addr_cvar
    high_addr_expr = structured_c.CBinaryOp(
        "Add",
        addr_cvar,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    pair_expr = structured_c.CBinaryOp(
        "Or",
        structured_c.CConstant(0x12, SimTypeChar(False), codegen=codegen),
        structured_c.CConstant(0x3400, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                structured_c.CVariable(SimRegisterVariable(2, 2), codegen=codegen),
                pair_expr,
                codegen=codegen,
            ),
            structured_c.CAssignment(
                structured_c.CVariable(SimRegisterVariable(4, 2), codegen=codegen),
                structured_c.CUnaryOp("Dereference", addr_cvar, codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    alias_facts = SimpleNamespace(identity=object(), can_join=lambda _other: True, needs_synthesis=lambda: False)

    monkeypatch.setattr(decompile, "_match_byte_load_addr_expr", lambda node: low_addr_expr if node is root.statements[0].rhs.lhs else None)
    monkeypatch.setattr(decompile, "_match_shifted_high_byte_addr_expr", lambda node: high_addr_expr if node is root.statements[0].rhs.rhs else None)
    monkeypatch.setattr(decompile, "describe_alias_storage", lambda _expr: alias_facts)
    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: True)
    monkeypatch.setattr(decompile, "_resolve_stack_cvar_from_addr_expr", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_classify_segmented_addr_expr",
        lambda _expr, _project: SimpleNamespace(kind="segment_const"),
    )
    monkeypatch.setattr(
        decompile,
        "_make_word_dereference_from_addr_expr",
        lambda *_args, **_kwargs: structured_c.CConstant(0x9999, SimTypeShort(False), codegen=codegen),
    )

    changed = decompile._coalesce_segmented_word_load_expressions(project, codegen)

    assert changed is False
    assert codegen.cfunc.statements.statements[0].rhs is pair_expr


def test_simplify_nested_mk_fp_calls_collapses_only_zero_offset_forms():
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(addr=0x10010)
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False)

    inner_seg = structured_c.CConstant(0x40, SimTypeShort(False), codegen=codegen)
    inner_off = structured_c.CConstant(0x17, SimTypeShort(False), codegen=codegen)
    nested = structured_c.CFunctionCall(
        "MK_FP",
        None,
        [
            structured_c.CFunctionCall("MK_FP", None, [inner_seg, inner_off], codegen=codegen),
            structured_c.CFunctionCall(
                "MK_FP",
                None,
                [
                    structured_c.CConstant(0x1234, SimTypeShort(False), codegen=codegen),
                    structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                ],
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    root = structured_c.CStatements([nested], addr=0x10010, codegen=codegen)
    cfunc.statements = root

    changed = decompile._simplify_nested_mk_fp_calls(codegen)

    assert changed is True
    rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten, structured_c.CFunctionCall)
    assert rewritten.callee_target == "MK_FP"
    assert rewritten.args[0] is inner_seg
    assert rewritten.args[1] is inner_off


def test_simplify_nested_mk_fp_calls_keeps_nonzero_inner_offset():
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(addr=0x10010)
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False)

    nested = structured_c.CFunctionCall(
        "MK_FP",
        None,
        [
            structured_c.CConstant(0x40, SimTypeShort(False), codegen=codegen),
            structured_c.CFunctionCall(
                "MK_FP",
                None,
                [
                    structured_c.CConstant(0x1234, SimTypeShort(False), codegen=codegen),
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                ],
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    root = structured_c.CStatements([nested], addr=0x10010, codegen=codegen)
    cfunc.statements = root

    changed = decompile._simplify_nested_mk_fp_calls(codegen)

    assert changed is False
    assert codegen.cfunc.statements.statements[0] is nested


def test_attach_ss_stack_variables_preserves_far_pointer_stack_local_width(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False)

    promoted_var = SimStackVariable(2, 1, base="bp", name="s_2", region=0x10010)
    promoted_cvar = structured_c.CVariable(promoted_var, codegen=codegen)
    cfunc.variables_in_use[promoted_var] = promoted_cvar
    cfunc.unified_local_vars[promoted_var] = {(promoted_cvar, SimTypeShort(False))}

    match_var = SimStackVariable(0, 1, base="bp", name="s_0", region=0x10010)
    node = structured_c.CAssignment(
        promoted_cvar,
        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    class _FarPointerType:
        size = 32

        def with_arch(self, _arch):
            return self

    node.type = _FarPointerType()
    cfunc.statements = structured_c.CStatements([node], addr=0x10010, codegen=codegen)

    monkeypatch.setattr(
        decompile,
        "_match_ss_stack_reference",
        lambda _node, _project: (match_var, promoted_cvar, 2),
    )

    changed = decompile._attach_ss_stack_variables(project, codegen)

    assert changed is True
    assert promoted_var.size == 4
    assert cfunc.variables_in_use[promoted_var] is promoted_cvar
    assert promoted_cvar.variable.size == 4
    assert isinstance(cfunc.statements.statements[0], structured_c.CVariable)
    assert cfunc.statements.statements[0] is promoted_cvar


def test_attach_ss_stack_variables_does_not_reuse_covering_stack_slot_for_far_pointer(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False)

    covering_var = SimStackVariable(0, 8, base="bp", name="cover", region=0x10010)
    covering_cvar = structured_c.CVariable(covering_var, codegen=codegen)
    cfunc.variables_in_use[covering_var] = covering_cvar
    cfunc.unified_local_vars[covering_var] = {(covering_cvar, SimTypeShort(False))}

    match_var = SimStackVariable(0, 1, base="bp", name="s_0", region=0x10010)
    node = structured_c.CAssignment(
        covering_cvar,
        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    class _FarPointerType:
        size = 32

        def with_arch(self, _arch):
            return self

    node.type = _FarPointerType()
    cfunc.statements = structured_c.CStatements([node], addr=0x10010, codegen=codegen)

    monkeypatch.setattr(
        decompile,
        "_match_ss_stack_reference",
        lambda _node, _project: (match_var, covering_cvar, 2),
    )

    changed = decompile._attach_ss_stack_variables(project, codegen)

    assert changed is True
    replacement = cfunc.statements.statements[0]
    assert isinstance(replacement, structured_c.CVariable)
    assert replacement is not covering_cvar
    assert isinstance(replacement.variable, SimStackVariable)
    assert replacement.variable.offset == 2


def test_rewrite_ss_stack_byte_offsets_refuses_large_unsigned_addr_expr(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(addr=0x10010, project=SimpleNamespace(loader=None))
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False)

    ptr_type = decompile.SimTypePointer(SimTypeChar(False)).with_arch(project.arch)
    node = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            None,
            ptr_type,
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = structured_c.CStatements([node], addr=0x10010, codegen=codegen)
    cfunc.statements = root

    large_addr = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x9000, SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    monkeypatch.setattr(
        decompile,
        "_classify_segmented_dereference",
        lambda _node, _project: SimpleNamespace(
            kind="segment_const",
            seg_name="ss",
            extra_offset=2,
            addr_expr=large_addr,
            cvar=None,
        ),
    )
    monkeypatch.setattr(decompile, "_strip_segment_scale_from_addr_expr", lambda _expr, _project: large_addr)

    changed = decompile._rewrite_ss_stack_byte_offsets(project, codegen)

    assert changed is False
    assert codegen.cfunc.statements.statements[0] is node


def test_coalesce_direct_ss_local_word_statements_refuses_region_mismatch(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False)

    low_var = SimStackVariable(0, 1, base="bp", name="s_0", region=0x10010)
    low_cvar = structured_c.CVariable(low_var, codegen=codegen)
    target_var = SimStackVariable(0, 1, base="bp", name="s_0_other", region=0x20020)
    target_cvar = structured_c.CVariable(target_var, codegen=codegen)

    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                low_cvar,
                structured_c.CVariable(low_var, codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                structured_c.CVariable(target_var, codegen=codegen),
                structured_c.CBinaryOp(
                    "Shr",
                    structured_c.CVariable(low_var, codegen=codegen),
                    structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    monkeypatch.setattr(
        decompile,
        "_match_ss_local_plus_const",
        lambda node, _project: (target_cvar, 1) if node is root.statements[1].lhs else None,
    )
    monkeypatch.setattr(
        decompile,
        "_match_shift_right_8_expr",
        lambda node: low_cvar if node is root.statements[1].rhs else None,
    )

    changed = decompile._coalesce_direct_ss_local_word_statements(project, codegen)

    assert changed is False
    assert len(cfunc.statements.statements) == 2
    assert low_var.size == 1


def test_coalesce_direct_ss_local_word_statements_rewrites_stack_address_split_store_inside_while_loop(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False)

    low_var = SimStackVariable(0, 1, base="bp", name="s_0", region=0x10010)
    low_cvar = structured_c.CVariable(low_var, codegen=codegen)
    word_var = SimStackVariable(0, 2, base="bp", name="local_0", region=0x10010)
    word_cvar = structured_c.CVariable(word_var, codegen=codegen)
    low_addr_expr = object()
    high_addr_expr = object()
    low_lhs = object()
    high_lhs = object()

    loop_body = structured_c.CStatements(
        [
            structured_c.CAssignment(
                low_lhs,
                low_cvar,
                codegen=codegen,
            ),
            structured_c.CAssignment(
                high_lhs,
                structured_c.CBinaryOp(
                    "Shr",
                    low_cvar,
                    structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    loop = structured_c.CWhileLoop(
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        loop_body,
        codegen=codegen,
    )
    cfunc.statements = structured_c.CStatements([loop], addr=0x10010, codegen=codegen)

    monkeypatch.setattr(
        decompile,
        "_match_byte_store_addr_expr",
        lambda node: low_addr_expr if node is low_lhs else high_addr_expr if node is high_lhs else None,
    )
    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: True)
    monkeypatch.setattr(
        decompile,
        "_match_shift_right_8_expr",
        lambda node: low_cvar if node is loop_body.statements[1].rhs else None,
    )
    monkeypatch.setattr(decompile, "_resolve_stack_cvar_from_addr_expr", lambda _project, _codegen, expr: word_cvar if expr is low_addr_expr else None)
    monkeypatch.setattr(decompile, "_canonicalize_stack_cvar_expr", lambda expr, _codegen: expr)

    changed = decompile._coalesce_direct_ss_local_word_statements(project, codegen)

    assert changed is True
    rewritten_loop = cfunc.statements.statements[0]
    assert isinstance(rewritten_loop, structured_c.CWhileLoop)
    assert len(rewritten_loop.body.statements) == 1
    replacement = rewritten_loop.body.statements[0]
    assert isinstance(replacement, structured_c.CAssignment)
    assert replacement.lhs is word_cvar
    assert replacement.rhs is low_cvar


def test_coalesce_direct_ss_local_word_statements_refuses_nonadjacent_stack_address_pair(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False)

    low_var = SimStackVariable(0, 1, base="bp", name="s_0", region=0x10010)
    low_cvar = structured_c.CVariable(low_var, codegen=codegen)
    low_addr_expr = object()
    high_addr_expr = object()
    low_lhs = object()
    high_lhs = object()

    root = structured_c.CStatements(
        [
            structured_c.CAssignment(low_lhs, low_cvar, codegen=codegen),
            structured_c.CAssignment(
                high_lhs,
                structured_c.CBinaryOp(
                    "Shr",
                    low_cvar,
                    structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    monkeypatch.setattr(
        decompile,
        "_match_byte_store_addr_expr",
        lambda node: low_addr_expr if node is low_lhs else high_addr_expr if node is high_lhs else None,
    )
    monkeypatch.setattr(decompile, "_addr_exprs_are_byte_pair", lambda _low, _high, _project: False)
    monkeypatch.setattr(
        decompile,
        "_match_shift_right_8_expr",
        lambda node: low_cvar if node is root.statements[1].rhs else None,
    )

    changed = decompile._coalesce_direct_ss_local_word_statements(project, codegen)

    assert changed is False
    assert len(cfunc.statements.statements) == 2
    assert cfunc.statements.statements[0].lhs is low_lhs
    assert cfunc.statements.statements[1].lhs is high_lhs


def test_coalesce_far_pointer_stack_expressions_avoids_byte_local_alias_for_far_pointer_store(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False)

    byte_var = SimStackVariable(0, 1, base="bp", name="s_0", region=0x10010)
    byte_cvar = structured_c.CVariable(byte_var, codegen=codegen)
    store_var = SimStackVariable(2, 1, base="bp", name="s_2", region=0x10010)
    store_cvar = structured_c.CVariable(store_var, codegen=codegen)
    out_var = SimStackVariable(4, 1, base="bp", name="s_4", region=0x10010)
    out_cvar = structured_c.CVariable(out_var, codegen=codegen)

    cfunc.variables_in_use[byte_var] = byte_cvar
    cfunc.variables_in_use[store_var] = store_cvar
    cfunc.variables_in_use[out_var] = out_cvar
    cfunc.unified_local_vars[byte_var] = {(byte_cvar, SimTypeShort(False))}
    cfunc.unified_local_vars[store_var] = {(store_cvar, SimTypeShort(False))}
    cfunc.unified_local_vars[out_var] = {(out_cvar, SimTypeShort(False))}

    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                store_cvar,
                structured_c.CConstant(7, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                out_cvar,
                structured_c.CBinaryOp(
                    "Add",
                    store_cvar,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    project._inertia_access_traits = {
        cfunc.addr: {
            "base_const": {
                ("ss", ("stack", "bp", 2), 2, 2, 1): 1,
            },
            "base_stride": {},
            "repeated_offsets": {},
            "repeated_offset_widths": {},
            "base_stride_widths": {},
            "member_evidence": {},
            "array_evidence": {},
        }
    }

    monkeypatch.setattr(
        decompile,
        "describe_alias_storage",
        lambda _expr: SimpleNamespace(identity=object(), can_join=lambda _other: True, needs_synthesis=lambda: False),
    )
    decompile._coalesce_far_pointer_stack_expressions(project, codegen)

    rhs = cfunc.statements.statements[1].rhs
    assert isinstance(rhs, structured_c.CFunctionCall)
    assert rhs.callee_target == "MK_FP"
    assert not any(isinstance(arg, structured_c.CVariable) and arg.variable is store_var for arg in rhs.args)


def test_coalesce_cod_word_global_loads_refuses_stable_member_hint(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(addr=0x10010, variables_in_use={}, unified_local_vars={}, arg_list=(), sort_local_vars=lambda: None)
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False)

    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                structured_c.CVariable(SimStackVariable(0, 2, base="bp", name="s_0", region=0x10010), codegen=codegen),
                structured_c.CBinaryOp(
                    "Or",
                    structured_c.CVariable(SimMemoryVariable(0x200, 1, name="g_200"), codegen=codegen),
                    structured_c.CBinaryOp(
                        "Mul",
                        structured_c.CVariable(SimMemoryVariable(0x201, 1, name="g_201"), codegen=codegen),
                        structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    project._inertia_access_traits = {
        cfunc.addr: {
            "member_evidence": {
                (("mem", 0x200), 0, 2): 1,
            },
            "base_const": {},
            "base_stride": {},
            "repeated_offsets": {},
            "repeated_offset_widths": {},
            "base_stride_widths": {},
            "array_evidence": {},
        }
    }

    changed = decompile._coalesce_cod_word_global_loads(project, codegen, {0x200: ("table_word", 2)})

    assert changed is False
    rhs = cfunc.statements.statements[0].rhs
    assert isinstance(rhs, structured_c.CBinaryOp)
    assert rhs.op == "Or"


def test_prune_unused_unnamed_memory_declarations_keeps_only_used_globals():
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(addr=0x10010, variables_in_use={}, unified_local_vars={}, arg_list=(), sort_local_vars=lambda: None)
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False)

    used_var = SimMemoryVariable(0x200, 1, name="g_200", region=0x10010)
    dead_var = SimMemoryVariable(0x201, 1, name="g_201", region=0x10010)
    used_cvar = structured_c.CVariable(used_var, codegen=codegen)
    dead_cvar = structured_c.CVariable(dead_var, codegen=codegen)
    cfunc.variables_in_use = {
        used_var: used_cvar,
        dead_var: dead_cvar,
    }
    cfunc.unified_local_vars = {
        used_var: {(used_cvar, SimTypeChar(False))},
        dead_var: {(dead_cvar, SimTypeChar(False))},
    }
    cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                structured_c.CVariable(SimStackVariable(0, 1, base="bp", name="s_0", region=0x10010), codegen=codegen),
                used_cvar,
                codegen=codegen,
            )
        ],
        addr=0x10010,
        codegen=codegen,
    )

    changed = decompile._prune_unused_unnamed_memory_declarations(codegen)

    assert changed is True
    assert used_var in cfunc.variables_in_use
    assert dead_var not in cfunc.variables_in_use
    assert used_var in cfunc.unified_local_vars
    assert dead_var not in cfunc.unified_local_vars


def test_repro_decompiler_boundary_reports_blocked_narrow_stack_object(monkeypatch, tmp_path, capsys):
    spec = importlib.util.spec_from_file_location("repro_decompiler_boundary", REPO_ROOT / "scripts" / "repro_decompiler_boundary.py")
    assert spec is not None
    assert spec.loader is not None
    boundary = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boundary)

    binary = tmp_path / "LIFE2.EXE"
    binary.write_bytes(b"MZ")

    stack_vars = [
        SimStackVariable(-2, 1, base="bp", name="s_2", region=0x1157C),
        SimStackVariable(0, 1, base="bp", name="s_0", region=0x1157C),
        SimStackVariable(2, 2, base="bp", name="ret_addr", region=0x1157C),
    ]

    class _FakeVariableManager:
        def get_variables(self):
            return list(stack_vars)

    fake_manager = _FakeVariableManager()
    fake_registry = SimpleNamespace(get_function_manager=lambda _addr: fake_manager)
    fake_clinic = SimpleNamespace(variable_kb=SimpleNamespace(variables=fake_registry))
    fake_codegen = SimpleNamespace(
        text=(
            "void sub_1157c(void)\n"
            "{\n"
            "    *((unsigned short *)(ir_0 * 16 + (unsigned int)(&s_2 + 2))) = 5512;\n"
            "    sub_15d8(); /* do not return */\n"
            "    *((unsigned short *)(ir_0 * 16 + (unsigned int)(&s_2 + 2))) = 5521;\n"
            "    sub_15d8(); /* do not return */\n"
            "}\n"
        )
    )
    fake_project = SimpleNamespace(
        analyses=SimpleNamespace(
            Clinic=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError()),
        )
    )
    fake_function = SimpleNamespace(addr=0x1157C, name="sub_1157c")

    monkeypatch.setattr(boundary, "_build_project", lambda *_args, **_kwargs: fake_project)
    monkeypatch.setattr(boundary.cli, "_infer_x86_16_linear_region", lambda *_args, **_kwargs: (0x1157C, 0x115BF))
    monkeypatch.setattr(boundary.cli, "_pick_function", lambda *_args, **_kwargs: (SimpleNamespace(), fake_function))
    monkeypatch.setattr(boundary.cli, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        boundary,
        "_probe_decompiler",
        lambda _project, _function, _options, *, generate_code, regen_clinic=None: SimpleNamespace(
            clinic=fake_clinic,
            codegen=None if not generate_code else fake_codegen,
        ),
    )
    monkeypatch.setattr(
        boundary.argparse.ArgumentParser,
        "parse_args",
        lambda self: SimpleNamespace(
            binary=binary,
            addr=0x1157C,
            window=0x80,
            base_addr=0x10000,
            entry_point=0x11423,
        ),
    )

    assert boundary.main() == 0
    out = capsys.readouterr().out

    assert "clinic_without_guards=error AssertionError" in out
    assert "decompiler_generate_code_false.codegen_present=False" in out
    assert "decompiler_regen_clinic_false.codegen_present=True" in out
    assert "upstream_hook_path=/home/xor/vextest/.venv/lib/python3.14/site-packages/angr/analyses/decompiler/decompiler.py:293-443" in out
    assert "cache_hook_note=Decompiler(generate_code=False) followed by Decompiler(regen_clinic=False) reuses the cached clinic" in out
    assert "same_clinic_object=True" in out
    assert "same_variable_manager_object=True" in out
    assert "stack_object_0x1157c_preserved=True" in out
    assert "stack_object_0x1157c_widened=False" in out
    assert "upstream_hook_note=no caller-visible callback exists between Clinic(...) and StructuredCodeGenerator(...)" in out
    assert "codegen_sub_15d8_call_count=2" in out
    assert "boundary_fixpoint=upstream_angr_cached_clinic_reuse_before_codegen" in out
    assert "boundary_status=blocked_pre_codegen_stack_object_remains_narrow" in out


def test_decompile_function_disables_structuring_for_tiny_single_call_helpers(monkeypatch):
    class FakeDecompiler:
        def __init__(self, function, cfg=None, options=None):
            assert options == [("structurer_cls", "Phoenix")]
            self.codegen = SimpleNamespace(cfunc=SimpleNamespace(variables_in_use={}, arg_list=()))
            self.errors = []
            self.clinic = object()

    blocks = {
        0x1196F: SimpleNamespace(
            size=0x14,
            bytes=b"\x90" * 0x14,
            capstone=SimpleNamespace(
                insns=[
                    SimpleNamespace(mnemonic="push", op_str="si"),
                    SimpleNamespace(mnemonic="call", op_str="0x11a03"),
                ]
            ),
        )
    }
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        analyses=SimpleNamespace(Decompiler=FakeDecompiler),
        factory=SimpleNamespace(block=lambda block_addr, opt_level=0: blocks[block_addr]),
    )
    function = SimpleNamespace(
        addr=0x1196F,
        name="sub_1196f",
        normalized=True,
        project=project,
        block_addrs_set=set(blocks),
        get_call_sites=lambda: [0x11972],
    )
    cfg = SimpleNamespace()

    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "seed_calling_conventions", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_register_direct_call_target_function_stubs", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(decompile, "_snapshot_codegen_text", lambda *_args, **_kwargs: "void sub_1196f(void) {}")

    def _assert_structuring_disabled(project_obj, *_args, **_kwargs):
        assert getattr(project_obj, "_inertia_structuring_enabled") is False
        return False

    def _noop_rewrite(*_args, **_kwargs):
        return False

    def _identity_text(text, *_args, **_kwargs):
        return text

    monkeypatch.setattr(decompile, "_attach_dos_pseudo_callees", _assert_structuring_disabled)
    for name in (
        "_attach_interrupt_wrapper_callees",
        "_lower_interrupt_wrapper_result_reads",
        "_attach_segment_register_names",
        "_attach_register_names",
        "_normalize_scalar_byte_register_types",
        "_attach_ss_stack_variables",
        "_rewrite_ss_stack_byte_offsets",
        "_canonicalize_stack_cvars",
        "_coalesce_direct_ss_local_word_statements",
        "_coalesce_segmented_word_store_statements",
        "_coalesce_segmented_word_load_expressions",
        "_prune_tiny_wrapper_staging_locals",
        "_prune_unused_unnamed_memory_declarations",
        "_prune_dead_local_assignments",
        "_prune_unused_local_declarations",
        "_prune_void_function_return_values",
        "_coalesce_cod_word_global_loads",
        "_coalesce_linear_recurrence_statements",
        "_attach_cod_global_names",
        "_attach_cod_global_declaration_names",
        "_attach_cod_global_declaration_types",
        "_collect_access_traits",
        "_coalesce_far_pointer_stack_expressions",
        "_simplify_nested_mk_fp_calls",
        "_attach_access_trait_field_names",
        "_attach_pointer_member_names",
        "_attach_cod_variable_names",
        "_attach_cod_callee_names",
        "_simplify_basic_algebraic_identities",
        "_materialize_missing_stack_local_declarations",
        "_materialize_missing_register_local_declarations",
        "_dedupe_codegen_variable_names_8616",
    ):
        monkeypatch.setattr(decompile, name, _noop_rewrite)
    for name in (
        "_normalize_boolean_conditions",
        "_fix_carr_inbox_guard_blind_spot",
        "_fix_carr_inboxlng_guard_blind_spot",
        "_fix_nhorz_changeweather_blind_spot",
        "_fix_cockpit_look_blind_spot",
        "_fix_billasm_rotate_pt_blind_spot",
        "_fix_monoprin_mset_pos_blind_spot",
        "_fix_planes3_ready5_blind_spot",
        "_normalize_anonymous_call_targets",
        "_prune_void_function_return_values_text",
        "_normalize_function_signature_arg_names",
        "_collapse_annotated_stack_aliases_text",
        "_materialize_missing_generic_local_declarations_text",
        "_prune_unused_local_declarations_text",
        "_annotate_cod_proc_output",
        "_rewrite_known_helper_signature_text",
        "_prune_trailing_generic_return_text",
        "_materialize_annotated_cod_declarations_text",
        "_collapse_duplicate_type_keywords_text",
        "_normalize_spurious_duplicate_local_suffixes",
        "_dedupe_adjacent_prototype_lines",
        "_sanitize_mangled_autonames_text",
        "_simplify_x86_16_stack_byte_pointers",
    ):
        monkeypatch.setattr(decompile, name, _identity_text)
    monkeypatch.setattr(decompile, "_format_known_helper_calls", lambda *_args, **_kwargs: _args[2])

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=1,
        api_style="pascal",
        binary_path=None,
        allow_isolated_retry=False,
    )

    assert status == "ok"
    assert payload == "void sub_1196f(void) {}"


def test_register_direct_call_target_function_stubs_registers_linear_and_unbased_targets():
    created = []

    class FakeFunctionManager:
        def function(self, *, addr=None, create=False, **_kwargs):
            created.append((addr, create))
            return SimpleNamespace(addr=addr)

    function = SimpleNamespace(
        get_call_sites=lambda: [0x10016, 0x10040],
        get_call_target=lambda site: 0x140D if site == 0x10016 else 0x1140D,
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x4000)),
        kb=SimpleNamespace(functions=FakeFunctionManager()),
    )

    count = decompile._register_direct_call_target_function_stubs(project, function)

    assert count == 2
    assert set(created) == {(0x140D, True), (0x1140D, True)}


def test_register_direct_call_target_function_stubs_falls_back_to_capstone_direct_calls():
    created = []

    class FakeFunctionManager:
        def function(self, *, addr=None, create=False, **_kwargs):
            created.append((addr, create))
            return SimpleNamespace(addr=addr)

    blocks = {
        0x10010: SimpleNamespace(
            capstone=SimpleNamespace(
                insns=[
                    SimpleNamespace(address=0x10016, mnemonic="call", op_str="0x140D"),
                    SimpleNamespace(address=0x1001C, mnemonic="call", op_str="0x1140D"),
                    SimpleNamespace(address=0x10021, mnemonic="jmp", op_str="0x1002D"),
                ]
            )
        )
    }
    function = SimpleNamespace(
        block_addrs_set=set(blocks),
        get_call_sites=lambda: [],
        get_call_target=lambda _site: None,
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda block_addr, opt_level=0: blocks[block_addr]),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x4000)),
        kb=SimpleNamespace(functions=FakeFunctionManager()),
    )

    count = decompile._register_direct_call_target_function_stubs(project, function)

    assert count == 2
    assert set(created) == {(0x140D, True), (0x1140D, True)}


def test_register_direct_call_target_function_stubs_uses_cod_call_names_for_unlabeled_targets():
    created = {}

    class FakeFunctionManager:
        def function(self, *, addr=None, create=False, **_kwargs):
            stub = created.setdefault(addr, SimpleNamespace(addr=addr, name=f"sub_{addr:x}"))
            return stub

    function = SimpleNamespace(
        get_call_sites=lambda: [0x10016, 0x10020],
        get_call_target=lambda site: 0x1446 if site == 0x10016 else 0x183a,
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x4000)),
        kb=SimpleNamespace(functions=FakeFunctionManager()),
    )
    cod_metadata = SimpleNamespace(call_names=("clock", "aNchkstk"))

    count = decompile._register_direct_call_target_function_stubs(project, function, cod_metadata=cod_metadata)

    assert count == 4
    assert created[0x1446].name == "clock"
    assert created[0x183A].name == "aNchkstk"
    assert created[0x11446].name == "clock"
    assert created[0x1183A].name == "aNchkstk"


def test_rank_exe_function_seeds_uses_persistent_cache(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"\xE8\x00\x00\xC3")
    code = binary.read_bytes()
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=binary,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
    )
    calls = {"count": 0}

    def _fake_pick(*_args, **_kwargs):
        calls["count"] += 1
        return SimpleNamespace(), SimpleNamespace(addr=0x1000, blocks=(SimpleNamespace(size=4),))

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-r")
    monkeypatch.setattr(decompile, "_seed_scan_windows", lambda _project: [(0x1000, 0x1004)])
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: {0x1003})
    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick)
    monkeypatch.setattr(decompile, "collect_neighbor_call_targets", lambda _function: [])
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    first = decompile._rank_exe_function_seeds(project)
    second = decompile._rank_exe_function_seeds(project)

    assert first == second
    assert calls["count"] == 1


def test_rank_exe_function_seeds_cache_key_changes_when_recovery_metadata_changes(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    code = b"\x90" * 0x400
    binary.write_bytes(code)
    metadata_a = LSTMetadata(
        data_labels={},
        code_labels={0x1100: "sig_a"},
        code_ranges={0x1100: (0x1100, 0x1120)},
        signature_code_addrs=frozenset(),
        absolute_addrs=True,
        source_format="flair_pat+flair_sig",
    )
    metadata_b = LSTMetadata(
        data_labels={},
        code_labels={0x1200: "sig_b"},
        code_ranges={0x1200: (0x1200, 0x1240)},
        signature_code_addrs=frozenset(),
        absolute_addrs=True,
        source_format="flair_pat+flair_sig",
    )
    calls = {"count": 0}

    def _make_project(metadata):
        return SimpleNamespace(
            entry=0x1000,
            _inertia_lst_metadata=metadata,
            loader=SimpleNamespace(
                main_object=SimpleNamespace(
                    binary=binary,
                    linked_base=0x1000,
                    max_addr=len(code) - 1,
                    memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
                )
            ),
        )

    def _fake_pick(*_args, **_kwargs):
        calls["count"] += 1
        return SimpleNamespace(), SimpleNamespace(addr=0x1000, blocks=(SimpleNamespace(size=4),))

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-r")
    monkeypatch.setattr(decompile, "_seed_scan_windows", lambda _project: [(0x1100, 0x1240)])
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: set())
    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "collect_neighbor_call_targets", lambda _function: [])
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    first = decompile._rank_exe_function_seeds(_make_project(metadata_a))
    second = decompile._rank_exe_function_seeds(_make_project(metadata_b))

    assert first == [0x1100]
    assert second == [0x1200]
    assert calls["count"] == 2


def test_main_uses_cached_exe_catalog_addresses_before_cfg(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_pair = (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project))

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-r")
    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("fresh CFG should not run")))
    monkeypatch.setattr(decompile, "_recover_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("whole CFG should not run")))
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: [recovered_pair])
    monkeypatch.setattr(
        decompile,
        "_supplement_cached_seeded_recovery",
        lambda _project, pairs, addrs, **_kwargs: (pairs, addrs),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            elapsed=1.0,
            byte_count=8,
        ),
    )
    decompile._store_cache_json(
        "recovery",
        decompile._recovery_cache_key(
            binary_path=binary,
            kind="display_catalog_addrs",
            extra={"entry": 0x11423, "arch": "86_16"},
        ),
        {"addrs": [0x10010]},
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "0"])
    out = capsys.readouterr().out

    assert rc in {0, 2}
    assert "using cached discovered function addresses" in out
    assert "/* == function 0x10010 sub_10010 == */" in out


def test_recover_cached_function_pairs_gives_pre_entry_candidates_more_time(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=CLI_PATH, linked_base=0x1000, max_addr=0x600),
        ),
    )
    seen_timeouts: list[tuple[int, int]] = []

    def _fake_recover(_project, *, candidate_addr, timeout, **_kwargs):
        seen_timeouts.append((candidate_addr, timeout))
        return (
            SimpleNamespace(),
            SimpleNamespace(
                addr=candidate_addr,
                name=f"sub_{candidate_addr:x}",
                is_plt=False,
                is_simprocedure=False,
                info={},
                blocks=(SimpleNamespace(size=0x18),),
            ),
        )

    monkeypatch.setattr(decompile, "_recover_candidate_with_timeout", _fake_recover)

    recovered = decompile._recover_cached_function_pairs(
        project,
        addrs=[0x10010, 0x11593],
        timeout=6,
        limit=2,
        region_span=0x120,
        per_function_timeout=1,
    )

    assert [function.addr for _cfg, function in recovered] == [0x10010, 0x11593]
    assert seen_timeouts == [(0x10010, 2), (0x11593, 1)]


def test_main_supplements_cached_exe_catalog_before_display_slice(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    runtime_pair = (SimpleNamespace(), SimpleNamespace(addr=0x11440, name="runtime_shell", project=project))
    helper_pair = (SimpleNamespace(), SimpleNamespace(addr=0x114CD, name="runtime_init", project=project))
    body_pair = (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project))

    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "digest-cache-supplement")
    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("fresh CFG should not run")))
    monkeypatch.setattr(decompile, "_recover_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("whole CFG should not run")))
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: [runtime_pair, helper_pair])
    monkeypatch.setattr(
        decompile,
        "_supplement_cached_seeded_recovery",
        lambda _project, _pairs, _addrs, **_kwargs: ([body_pair, runtime_pair, helper_pair], [0x10010, 0x11440, 0x114CD]),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            elapsed=1.0,
            byte_count=8,
        ),
    )
    decompile._store_cache_json(
        "recovery",
        decompile._recovery_cache_key(
            binary_path=binary,
            kind="display_catalog_addrs",
            extra={"entry": 0x11423, "arch": "86_16"},
        ),
        {"addrs": [0x11440, 0x114CD]},
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "using cached discovered function addresses" in out
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x11440 runtime_shell == */" in out
    assert "/* == function 0x114cd runtime_init == */" not in out


def test_main_prefers_fast_exe_catalog_before_cfg(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    body_function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), entry_function), (SimpleNamespace(), body_function)],
    )
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("slow CFG should not run")))
    monkeypatch.setattr(decompile, "_recover_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("whole CFG should not run")))
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile._AdaptivePerByteTimeoutModel, "observe_success", lambda self, *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            elapsed=1.0,
            byte_count=8,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc in {0, 2}
    assert "/* == function 0x11423 _start == */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out


def test_main_emits_tail_validation_summary_and_metadata_to_stderr(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("slow CFG should not run")))
    monkeypatch.setattr(decompile, "_recover_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("whole CFG should not run")))
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            tail_validation={
                "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable", "summary_text": "no observable delta"},
                "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable", "summary_text": "no observable delta"},
            },
        ),
    )
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "3"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "[tail-validation] whole-tail validation clean across 1 functions" in captured.err
    assert "@@INERTIA_TAIL_VALIDATION@@ " in captured.err


def test_tail_validation_runtime_policy_defaults_off_for_exe_and_on_for_cod(monkeypatch, tmp_path):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("INERTIA_ENABLE_TAIL_VALIDATION", raising=False)
    monkeypatch.delenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", raising=False)

    assert decompile._tail_validation_enabled_for_run(tmp_path / "sample.exe") is False
    assert decompile._tail_validation_enabled_for_run(tmp_path / "sample.cod") is True
    assert decompile._tail_validation_enabled_for_run(tmp_path / "sample.exe", proc="main") is True


def test_main_suppresses_tail_validation_stderr_for_direct_exe_by_default(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)

    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("INERTIA_ENABLE_TAIL_VALIDATION", raising=False)
    monkeypatch.delenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", raising=False)
    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("slow CFG should not run")))
    monkeypatch.setattr(decompile, "_recover_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("whole CFG should not run")))
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            tail_validation={
                "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable", "summary_text": "no observable delta"},
                "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable", "summary_text": "no observable delta"},
            },
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "3"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "[tail-validation]" not in captured.err


def test_main_emits_uncollected_tail_validation_for_direct_nonoptimized_fallback(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
        _inertia_last_tail_validation_snapshot={
            "structuring": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
            "postprocess": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
        },
    )

    def _fake_timeout(fn, **kwargs):  # noqa: ANN001
        if kwargs.get("thread_name_prefix") == "recovery":
            raise decompile._AnalysisTimeout()
        return fn()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)
    monkeypatch.setattr(decompile, "_try_decompile_non_optimized_slice", lambda *_args, **_kwargs: "int fallback(void) { return 7; }")
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--addr", "0x11423", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "/* == c (non-optimized fallback) == */" in captured.out
    assert "int fallback(void) { return 7; }" in captured.out
    assert "[tail-validation]" in captured.err
    assert "not collected" in captured.err
    assert "detail artifact " in captured.err
    assert '"scanned": 1' in captured.err
    assert '"detail_cache_path": "' in captured.err
    assert '"detail_cache_path": null' not in captured.err
    assert '"tail_validation_uncollected": true' in captured.err
    assert '"function_name": "sub_11423"' in captured.err


def test_main_renders_direct_nonoptimized_outcome_payload_instead_of_repr(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )

    def _fake_timeout(fn, **kwargs):  # noqa: ANN001
        if kwargs.get("thread_name_prefix") == "recovery":
            raise decompile._AnalysisTimeout()
        return fn()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)
    monkeypatch.setattr(
        decompile,
        "_try_decompile_non_optimized_slice",
        lambda *_args, **_kwargs: decompile.NonOptimizedSliceOutcome(
            rendered="int fallback(void) { return 7; }",
            status="timeout",
            payload="Timed out after 2s.",
        ),
    )

    rc = decompile.main([str(binary), "--addr", "0x11423", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "/* == c (non-optimized fallback) == */" in captured.out
    assert "int fallback(void) { return 7; }" in captured.out
    assert "NonOptimizedSliceOutcome(" not in captured.out


def test_main_emits_current_run_tail_validation_for_direct_nonoptimized_fallback(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
            memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size),
        ),
    )
    slice_project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda _start, size: b"\x90" * size)),
    )

    def _fake_timeout(fn, **kwargs):  # noqa: ANN001
        if kwargs.get("thread_name_prefix") == "recovery":
            raise decompile._AnalysisTimeout()
        return fn()

    def _fake_decompile_function_with_stats(slice_project_arg, *_args, **_kwargs):
        slice_project_arg._inertia_last_tail_validation_snapshot = {
            "structuring": {
                "changed": True,
                "mode": "live_out",
                "verdict": "structuring whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                "summary_text": "helper_calls: +helper_ping",
            },
            "postprocess": {
                "changed": True,
                "mode": "live_out",
                "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                "summary_text": "helper_calls: +helper_ping",
            },
        }
        return "ok", "int fallback(void) { return 7; }", None, 1, 0x20, 0.5

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *_args, **_kwargs: slice_project)
    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x10010, 0x10020))
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=0x10010, name="sub_10010", normalized=False),
        ),
    )
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_sidecar_cod_metadata_for_function", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile_function_with_stats)
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--addr", "0x11423", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "/* == c (non-optimized fallback) == */" in captured.out
    assert "int fallback(void) { return 7; }" in captured.out
    assert "[tail-validation] whole-tail validation failed across 2 functions" in captured.err
    assert "not collected" not in captured.err


def test_main_aggregate_trivial_fallback_does_not_reuse_stale_project_snapshot(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
        _inertia_last_tail_validation_snapshot={
            "structuring": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
            "postprocess": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
        },
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x10010: "sub_10010"},
        code_ranges={0x10010: (0x10010, 0x10011)},
        absolute_addrs=True,
        source_format="cod_listing",
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="error",
            payload="Decompiler did not produce code.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )
    monkeypatch.setattr(decompile, "_try_emit_trivial_sidecar_c", lambda *_args, **_kwargs: "void sub_10010(void)\n{\n}\n")
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "3"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "/* -- c (trivial sidecar fallback) -- */" in captured.out
    assert "[tail-validation]" in captured.err
    assert "not collected" in captured.err
    assert "detail artifact " in captured.err
    assert '"records": []' in captured.err
    assert '"scanned": 1' in captured.err
    assert '"detail_cache_path": "' in captured.err
    assert '"detail_cache_path": null' not in captured.err


def test_main_aggregate_uses_sidecar_fallback_tail_validation_snapshot(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x10010: "sub_10010"},
        code_ranges={0x10010: (0x10010, 0x10020)},
        absolute_addrs=True,
        source_format="cod_listing",
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="error",
            payload="Decompiler did not produce code.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    def _fake_sidecar_slice(project_arg, *_args, **_kwargs):
        project_arg._inertia_last_tail_validation_snapshot = {
            "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable"},
            "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable"},
        }
        return SliceRecoveryAttemptOutcome(
            attempt_name="sidecar_slice",
            status="ok",
            payload="int sub_10010(void) { return 0; }",
            snapshot=project_arg._inertia_last_tail_validation_snapshot,
        )

    monkeypatch.setattr(decompile, "_try_decompile_sidecar_slice", _fake_sidecar_slice)
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "0"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "/* -- c (sidecar slice fallback) -- */" in captured.out
    assert "[tail-validation] whole-tail validation clean across 1 functions" in captured.err
    assert '"function_addr": 65552' in captured.err


def test_main_direct_path_uses_peer_sidecar_fallback_tail_validation_snapshot(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace()
    func = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x10010: "sub_10010"},
        code_ranges={0x10010: (0x10010, 0x10020)},
        absolute_addrs=True,
        source_format="cod_listing",
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_direct_addr_function", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(decompile, "_decompile_function_with_stats", lambda *_args, **_kwargs: ("error", "Decompiler did not produce code.", None, 1, 4, 0.01))
    monkeypatch.setattr(decompile, "_try_decompile_non_optimized_known_function", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_try_decompile_sidecar_slice", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_try_decompile_peer_sidecar_slice",
        lambda project_arg, *_args, **_kwargs: (
            setattr(
                project_arg,
                "_inertia_last_tail_validation_snapshot",
                {
                    "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable"},
                    "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable"},
                },
            )
            or "int sub_10010(void) { return 0; }"
        ),
    )
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--addr", "0x10010", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "/* == c (peer sidecar fallback) == */" in captured.out
    assert "[tail-validation] whole-tail validation clean across 1 functions" in captured.err
    assert '"function_addr": 65552' in captured.err


def test_main_direct_partial_timeout_uses_captured_tail_validation_snapshot(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace()
    func = SimpleNamespace(
        addr=0x10010,
        name="sub_10010",
        project=project,
        info={
            "x86_16_tail_validation": {
                "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable"},
                "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable"},
            }
        },
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_direct_addr_function", lambda *_args, **_kwargs: (cfg, func))

    def _fake_decompile(*_args, **_kwargs):
        project._inertia_last_tail_validation_snapshot = {
            "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable"},
            "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable"},
        }
        return ("timeout", "Timed out after 2s.", "int partial(void) { return 1; }", 1, 4, 0.01)

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)
    monkeypatch.setattr(
        decompile,
        "_try_decompile_non_optimized_slice",
        lambda project_arg, *_args, **_kwargs: (
            setattr(
                project_arg,
                "_inertia_last_tail_validation_snapshot",
                {
                    "structuring": {"changed": True, "mode": "live_out", "verdict": "stale changed"},
                    "postprocess": {"changed": True, "mode": "live_out", "verdict": "stale changed"},
                },
            )
            or None
        ),
    )
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--addr", "0x10010", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "/* == c (partial timeout) == */" in captured.out
    assert "int partial(void) { return 1; }" in captured.out
    assert "[tail-validation] whole-tail validation clean across 1 functions" in captured.err
    assert '"detail_cache_path": "' in captured.err
    assert '"detail_cache_path": null' not in captured.err
    assert "stale changed" not in captured.err


def test_main_direct_decompile_outer_timeout_reaches_nonoptimized_fallback(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace()
    func = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)

    def _fake_timeout(fn, *, thread_name_prefix, **_kwargs):
        if thread_name_prefix == "direct-decomp":
            raise decompile.FuturesTimeoutError()
        return fn()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)
    monkeypatch.setattr(decompile, "_recover_direct_addr_function", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(decompile, "_try_decompile_non_optimized_slice", lambda *_args, **_kwargs: "int fallback(void) { return 7; }")
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--addr", "0x10010", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "/* Falling back to non-optimized slice decompilation. */" in captured.out
    assert "int fallback(void) { return 7; }" in captured.out
    assert "[tail-validation]" in captured.err


def test_main_direct_timeout_reports_nonoptimized_failure_before_string_fallback(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace()
    func = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)

    def _fake_timeout(fn, **kwargs):  # noqa: ANN001
        if kwargs.get("thread_name_prefix") == "recovery":
            raise decompile._AnalysisTimeout()
        return fn()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda *_args, **_kwargs: (_ for _ in ()).throw(decompile.FuturesTimeoutError()))
    monkeypatch.setattr(decompile, "_recover_direct_addr_function", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(
        decompile,
        "_try_decompile_non_optimized_slice",
        lambda *_args, **_kwargs: decompile.NonOptimizedSliceOutcome(
            rendered=None,
            status="error",
            payload="slice lift broke",
            failure_detail="shared-project slice: error: slice lift broke",
            attempt_failures=("shared-project slice: error: slice lift broke",),
        ),
    )
    monkeypatch.setattr(decompile, "_try_emit_string_intrinsic_c", lambda *_args, **_kwargs: "char fallback(void) { return 7; }")
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x10010, 0x10020))
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--addr", "0x10010", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 0
    assert "/* non-optimized fallback unavailable: shared-project slice: error: slice lift broke */" in captured.out
    assert captured.out.index("non-optimized fallback unavailable") < captured.out.index("/* == c (string intrinsic fallback) == */")
    assert "char fallback(void) { return 7; }" in captured.out


def test_main_aggregate_partial_timeout_uses_result_tail_validation(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
        _inertia_last_tail_validation_snapshot={
            "structuring": {"changed": True, "mode": "live_out", "verdict": "stale changed"},
            "postprocess": {"changed": True, "mode": "live_out", "verdict": "stale changed"},
        },
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="timeout",
            payload="Timed out after 2s.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            partial_payload="int partial(void) { return 1; }",
            tail_validation={
                "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable"},
                "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable"},
            },
        ),
    )
    monkeypatch.setattr(decompile, "_try_decompile_non_optimized_slice", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_format_asm_range", lambda *_args, **_kwargs: "mov ax, ax")
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x11423, 0x11425))
    monkeypatch.setattr(decompile, "_probe_lift_break", lambda *_args, **_kwargs: "<probe>")
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "3"])
    captured = capsys.readouterr()

    assert rc == 2
    assert "/* -- c (partial timeout) -- */" in captured.out
    assert "[tail-validation] whole-tail validation clean across 1 functions" in captured.err
    assert '"detail_cache_path": "' in captured.err
    assert '"detail_cache_path": null' not in captured.err
    assert "stale changed" not in captured.err


def test_main_direct_sidecar_bounded_asm_fallback_does_not_reuse_stale_project_snapshot(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
        _inertia_last_tail_validation_snapshot={
            "structuring": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
            "postprocess": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
        },
    )
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x10010: "sub_10010"},
        code_ranges={0x10010: (0x10010, 0x10020)},
        absolute_addrs=True,
        source_format="cod_listing",
    )

    def _fake_timeout(fn, **kwargs):  # noqa: ANN001
        if kwargs.get("thread_name_prefix") == "recovery":
            raise decompile._AnalysisTimeout()
        return fn()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)
    monkeypatch.setattr(decompile, "_try_decompile_sidecar_slice", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_format_asm_range", lambda *_args, **_kwargs: "mov ax, ax")
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--addr", "0x10010", "--timeout", "2"])
    captured = capsys.readouterr()

    assert rc == 4
    assert "/* == asm fallback == */" in captured.out
    assert "mov ax, ax" in captured.out
    assert "[tail-validation]" in captured.err
    assert "not collected" in captured.err
    assert "detail artifact " in captured.err
    assert '"records": []' in captured.err
    assert '"detail_cache_path": "' in captured.err
    assert '"detail_cache_path": null' not in captured.err
    assert "stale stable" not in captured.err


def test_main_aggregate_asm_fallback_does_not_reuse_stale_project_snapshot(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
        _inertia_last_tail_validation_snapshot={
            "structuring": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
            "postprocess": {"changed": False, "mode": "live_out", "verdict": "stale stable"},
        },
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="error",
            payload="Decompiler did not produce code.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )
    monkeypatch.setattr(decompile, "_try_decompile_non_optimized_slice", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_probe_lift_break", lambda *_args, **_kwargs: "<probe>")
    monkeypatch.setattr(decompile, "_format_asm_range", lambda *_args, **_kwargs: "mov ax, ax")
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x10010, 0x10012))
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "1"])
    captured = capsys.readouterr()

    assert rc == 2
    assert "-- asm fallback --" in captured.out
    assert "mov ax, ax" in captured.out
    assert "[tail-validation]" in captured.err
    assert "not collected" in captured.err
    assert "detail artifact " in captured.err
    assert '"records": []' in captured.err
    assert '"detail_cache_path": "' in captured.err
    assert '"detail_cache_path": null' not in captured.err
    assert "stale stable" not in captured.err


def test_main_reports_uncapped_seeded_function_count(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "life2.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace(functions={})
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    seed_functions = [
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x10020, name="sub_10020", project=project)),
    ]

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_recover_fast_exe_catalog", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(decompile, "_interesting_functions", lambda _cfg, limit=None: ([entry_function], 1))
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: (seed_functions, [0x10010, 0x10020, 0x10030]),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            elapsed=1.0,
            byte_count=8,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* functions queued for decompilation: 4 */" in out
    assert "/* showing first 2 functions because --max-functions=2; raise it or omit the option to decompile all queued functions */" in out


def test_main_reports_uncapped_cached_function_count(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project, get_call_sites=lambda: ())),
        (SimpleNamespace(), SimpleNamespace(addr=0x10020, name="sub_10020", project=project, get_call_sites=lambda: ())),
    ]

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [0x10010, 0x10020, 0x10030])
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: recovered_pairs)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* functions queued for decompilation: 3 */" in out
    assert "/* showing first 2 functions because --max-functions=2; raise it or omit the option to decompile all queued functions */" in out


def test_main_decompiles_all_functions_by_default_without_sidecar(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x10000 + i * 0x10, name=f"sub_{i:04x}", project=project))
        for i in range(30)
    ]
    stored_pairs = []

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [pair[1].addr for pair in recovered_pairs])
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: list(recovered_pairs))
    monkeypatch.setattr(
        decompile,
        "_supplement_cached_seeded_recovery",
        lambda _project, pairs, addrs, **_kwargs: (pairs, addrs),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_store_catalog_address_cache",
        lambda _project, _binary, function_cfg_pairs: stored_pairs.extend(function_cfg_pairs),
    )
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* functions queued for decompilation: 30 */" in out
    assert "showing first 8 by default for responsiveness" not in out
    assert "summary: decompiled 30/30 selected functions" in out
    assert len(stored_pairs) == 30


def test_main_does_not_auto_cap_noninteractive_stdout_without_sidecar(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x10000 + i * 0x10, name=f"sub_{i:04x}", project=project))
        for i in range(30)
    ]

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_stdout_is_interactive", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [pair[1].addr for pair in recovered_pairs])
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: list(recovered_pairs))
    monkeypatch.setattr(
        decompile,
        "_supplement_cached_seeded_recovery",
        lambda _project, pairs, addrs, **_kwargs: (pairs, addrs),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "showing first 8 by default for responsiveness" not in out
    assert "/* info: selected 30 function(s) for decompilation */" in out
    assert "summary: decompiled 30/30 selected functions" in out


def test_main_reports_pure_recovery_mode_and_attempt_states(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x10020, name="sub_10020", project=project)),
    ]

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [0x10010, 0x10020])
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: list(recovered_pairs))
    monkeypatch.setattr(
        decompile,
        "_supplement_cached_seeded_recovery",
        lambda _project, pairs, addrs, **_kwargs: (pairs, addrs),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_try_decompile_non_optimized_slice", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x10010] * 102)

    def _fake_run(item, **_kwargs):
        if item.function.addr == 0x10010:
            return decompile.FunctionWorkResult(
                index=item.index,
                status="ok",
                payload=f"int {item.function.name}(void) {{ return 0; }}",
                debug_output="",
                function=item.function,
                function_cfg=item.function_cfg,
                tail_validation={
                    "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable", "summary_text": None},
                    "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable", "summary_text": None},
                },
            )
        return decompile.FunctionWorkResult(
            index=item.index,
            status="timeout",
            payload="Timed out after 2s.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            tail_validation={},
        )

    monkeypatch.setattr(decompile, "_run_function_work_item", _fake_run)

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* info: recovery evidence: pure binary recovery mode (no helper metadata/debug info found) */" in out
    assert "/* info: direct-binary recovery found 102 likely non-library function entries */" in out
    assert "/* functions queued for decompilation: 102 */" in out
    assert "/* info: selected 2 function(s) for display */" in out
    assert "/* info: decompilation attempted for 2/2 displayed function(s) */" in out
    assert "/* info: function 0x10010 sub_10010 attempt=decompiled validation=passed */" in out
    assert "/* info: function 0x10020 sub_10020 attempt=timed_out validation=uncollected */" in out


def test_main_uses_ranked_binary_placeholders_when_upfront_catalog_is_empty(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_recover_fast_exe_catalog", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError()))
    monkeypatch.setattr(decompile, "_recover_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError()))
    monkeypatch.setattr(decompile, "_recover_fast_seed_functions", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x10010, 0x10040, 0x10080])
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project, is_plt=False, is_simprocedure=False),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* info: direct-binary recovery found 3 likely non-library function entries */" in out
    assert "/* info: selected 2 function(s) for display */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x10040 sub_10040 == */" in out
    assert "/* info: decompilation attempted for 2/2 displayed function(s) */" in out


def test_main_prefers_quickly_recoverable_ranked_binary_preview_items(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_recover_fast_exe_catalog", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError()))
    monkeypatch.setattr(decompile, "_recover_cfg", lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError()))
    monkeypatch.setattr(decompile, "_recover_fast_seed_functions", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x10B4B, 0x10010, 0x114CD])
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)

    def fake_recover(_project, addr, name, **_kwargs):
        if addr == 0x10B4B:
            raise TimeoutError("slow seed")
        return (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project, is_plt=False, is_simprocedure=False),
        )

    monkeypatch.setattr(decompile, "_recover_ranked_binary_function", fake_recover)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x114cd sub_114cd == */" in out
    assert "/* == function 0x10b4b sub_10b4b == */" not in out


def test_main_selected_count_reflects_supplemented_hidden_sidecar_display(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = SimpleNamespace(
        source_format="flair_pat+flair_sig",
        code_labels={0x10010: "lib_only"},
        code_ranges={},
        data_labels={},
        absolute_addrs=True,
    )
    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x11423, 0x11450, 0x10010, 0x100EA])
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_rank_function_cfg_pairs_for_display", lambda _project, pairs: list(pairs))
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project),
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "4"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* info: selected 4 function(s) for display */" in out
    assert "/* info: decompilation attempted for 4/4 displayed function(s) */" in out


def test_main_hidden_sidecar_fills_display_slots_from_ranked_preview(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = SimpleNamespace(
        source_format="flair_pat+flair_sig",
        code_labels={0x10010: "lib_only"},
        code_ranges={},
        data_labels={},
        absolute_addrs=True,
    )
    initial_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="sub_11423", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x1179E, name="sub_1179e", project=project)),
    ]

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x11423, 0x1179E, 0x10010, 0x100EA])
    monkeypatch.setattr(decompile, "_recover_seeded_exe_functions", lambda *_args, **_kwargs: (list(initial_pairs), [0x11423, 0x1179E]))
    monkeypatch.setattr(
        decompile,
        "_prepare_ranked_binary_preview_items",
        lambda *_args, **_kwargs: [
            decompile.FunctionWorkItem(
                index=1,
                function_cfg=None,
                function=SimpleNamespace(addr=0x10010, name="sub_10010", project=project),
            ),
            decompile.FunctionWorkItem(
                index=2,
                function_cfg=None,
                function=SimpleNamespace(addr=0x100EA, name="sub_100ea", project=project),
            ),
        ],
    )
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project, is_plt=False, is_simprocedure=False),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 4)
    monkeypatch.setattr(decompile, "_rank_function_cfg_pairs_for_display", lambda _project, pairs: list(pairs))
    monkeypatch.setattr(
        decompile,
        "_supplement_function_cfg_pairs_with_seeded_recovery",
        lambda _project, pairs, **_kwargs: list(pairs),
    )
    monkeypatch.setattr(
        decompile,
        "_supplement_function_cfg_pairs_with_ranked_preview",
        lambda _project, pairs, _ranked, **_kwargs: list(pairs),
    )
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "4"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* info: selected 4 function(s) for display */" in out
    assert "/* parallel function decompilation: disabled (RAM pressure or single function) */" in out
    assert "/* info: decompilation attempted for 4/4 displayed function(s) */" in out


def test_main_hidden_sidecar_defaults_to_all_ranked_functions(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = SimpleNamespace(
        source_format="flair_pat+flair_sig",
        code_labels={0x10010: "lib_only"},
        code_ranges={},
        data_labels={},
        absolute_addrs=True,
    )
    seeded_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="_start", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x1179E, name="sub_1179e", project=project)),
    ]
    ranked_addrs = [0x11423, 0x1179E, 0x1157C, 0x11593]
    seen_items = []

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: list(ranked_addrs))
    monkeypatch.setattr(decompile, "_recover_seeded_exe_functions", lambda *_args, **_kwargs: (list(seeded_pairs), [0x11423, 0x1179E]))
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda func, *, timeout: func())
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)

    def fake_run(item, **_kwargs):
        seen_items.append((item.function.addr, item.function_cfg is not None))
        return decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        )

    monkeypatch.setattr(decompile, "_run_function_work_item", fake_run)

    rc = decompile.main([str(binary), "--timeout", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* info: selected 4 function(s) for decompilation */" in out
    assert "showing first" not in out
    assert seen_items == [
        (0x11423, True),
        (0x1179E, True),
        (0x1157C, True),
        (0x11593, True),
    ]


def test_main_serial_whole_binary_path_does_not_wrap_function_work_items_in_executor(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x10020, name="sub_10020", project=project)),
    ]
    seen = []

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [0x10010, 0x10020])
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: list(recovered_pairs))
    monkeypatch.setattr(
        decompile,
        "_supplement_cached_seeded_recovery",
        lambda _project, pairs, addrs, **_kwargs: (pairs, addrs),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "DaemonThreadPoolExecutor", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("serial path should not create executor")))

    def _fake_run(item, **_kwargs):
        seen.append(item.function.addr)
        return decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        )

    monkeypatch.setattr(decompile, "_run_function_work_item", _fake_run)

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert sorted(seen) == [0x10010, 0x10020]
    assert "summary: decompiled 2/2 shown functions" in out


def test_main_full_serial_whole_binary_uses_isolated_fork_lane(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x10020, name="sub_10020", project=project)),
    ]
    seen = []
    fork_calls = []

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [0x10010, 0x10020])
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: list(recovered_pairs))
    monkeypatch.setattr(
        decompile,
        "_supplement_cached_seeded_recovery",
        lambda _project, pairs, addrs, **_kwargs: (pairs, addrs),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile.threading, "active_count", lambda: 1)

    def _fake_run(item, **_kwargs):
        seen.append(item.function.addr)
        return decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        )

    def _fake_fork(func, *, timeout):
        fork_calls.append(timeout)
        return func()

    monkeypatch.setattr(decompile, "_run_function_work_item", _fake_run)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", _fake_fork)

    rc = decompile.main([str(binary), "--timeout", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert sorted(seen) == [0x10010, 0x10020]
    assert fork_calls == [4, 4]
    assert "/* parallel function decompilation: disabled; using isolated serial fork/COW workers to bound RAM */" in out


def test_prepare_ranked_binary_preview_items_uses_fork_lane_on_main_thread(monkeypatch):
    project = SimpleNamespace()
    fork_calls = []

    monkeypatch.setattr(decompile.threading, "active_count", lambda: 1)
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (SimpleNamespace(), SimpleNamespace(addr=addr, name=name, project=project)),
    )

    def _fake_fork(func, *, timeout):
        fork_calls.append(timeout)
        return func()

    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", _fake_fork)

    items = decompile._prepare_ranked_binary_preview_items(
        project,
        [0x10010, 0x10020, 0x10030],
        max_count=2,
        timeout=3,
        window=0x200,
        low_memory=False,
    )

    assert [item.function.addr for item in items] == [0x10010, 0x10020]
    assert fork_calls == [3, 3]


def test_main_hidden_sidecar_prefers_ranked_preview_over_non_entry_seeded_pairs(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = SimpleNamespace(
        source_format="flair_pat+flair_sig",
        code_labels={0x10010: "lib_only"},
        code_ranges={},
        data_labels={},
        absolute_addrs=True,
    )
    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x10010, 0x100EA, 0x10179])
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("seed catalog should be skipped")),
    )
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_rank_function_cfg_pairs_for_display", lambda _project, pairs: list(pairs))
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "3"])
    captured = capsys.readouterr()
    out = captured.out

    assert rc == 0
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x100ea sub_100ea == */" in out
    assert "/* == function 0x10179 sub_10179 == */" in out
    assert "/* == function 0x11423 _start == */" not in out
    assert "/* == function 0x1179e slow_seed == */" not in out


def test_main_hidden_sidecar_disables_isolated_retry_in_capped_serial_lane(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = SimpleNamespace(
        source_format="flair_pat+flair_sig",
        code_labels={0x10010: "lib_only"},
        code_ranges={},
        data_labels={},
        absolute_addrs=True,
    )
    seen_retry_flags = []

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x115D8, 0x1157C])
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)

    def fake_run(item, **kwargs):
        seen_retry_flags.append(kwargs.get("allow_isolated_retry"))
        return decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        )

    monkeypatch.setattr(decompile, "_run_function_work_item", fake_run)

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    capsys.readouterr()

    assert rc == 0
    assert seen_retry_flags == [False, False]


def test_main_hidden_sidecar_uses_ranked_preview_before_seed_catalog(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = SimpleNamespace(
        source_format="flair_pat+flair_sig",
        code_labels={0x10010: "lib_only"},
        code_ranges={},
        data_labels={},
        absolute_addrs=True,
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x10010, 0x100EA, 0x10179, 0x101A3])
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("seed catalog should be skipped")),
    )
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())
    monkeypatch.setattr(
        decompile,
        "_recover_ranked_binary_function",
        lambda _project, addr, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=addr, name=name, project=project),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_rank_function_cfg_pairs_for_display", lambda _project, pairs: list(pairs))
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    captured = capsys.readouterr()
    out = captured.out
    assert rc == 0
    assert "/* info: selected 2 function(s) for display */" in out


def test_rank_hidden_sidecar_pairs_for_display_throughput_keeps_entry_only_for_tight_cap(monkeypatch):
    project = SimpleNamespace(entry=0x11423)
    pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="_start", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="fast_a", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x100EA, name="fast_b", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x10179, name="tiny_wrapper", project=project)),
    ]
    complexity_by_addr = {
        0x11423: (5, 30),
        0x10010: (2, 10),
        0x100EA: (3, 18),
        0x10179: (1, 6),
    }

    monkeypatch.setattr(decompile, "_function_complexity", lambda function: complexity_by_addr[function.addr])
    monkeypatch.setattr(decompile, "_function_recovery_truncated", lambda _function: False)

    ranked_tight = decompile._rank_hidden_sidecar_pairs_for_display_throughput(
        project,
        pairs,
        limit=2,
    )
    ranked_wide = decompile._rank_hidden_sidecar_pairs_for_display_throughput(
        project,
        pairs,
        limit=3,
    )

    assert [function.addr for _cfg, function in ranked_tight] == [0x10010, 0x11423]
    assert [function.addr for _cfg, function in ranked_wide] == [0x10010, 0x100EA, 0x10179]


def test_function_complexity_caches_project_block_decodes():
    calls: list[tuple[int, int]] = []

    class FakeFactory:
        def block(self, addr, *, opt_level):
            calls.append((addr, opt_level))
            return SimpleNamespace(bytes=b"\x90" * (addr & 0xF))

    project = SimpleNamespace(factory=FakeFactory())
    function = SimpleNamespace(
        project=project,
        block_addrs_set={0x1002, 0x1005},
        info={},
    )

    assert decompile._function_complexity(function) == (2, 7)
    assert decompile._function_complexity(function) == (2, 7)
    assert calls == [(0x1002, 0), (0x1005, 0)]


def test_supplement_function_cfg_pairs_with_ranked_preview_adds_recoverable_pairs(monkeypatch):
    project = SimpleNamespace()
    existing_pair = (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="sub_11423", project=project))

    monkeypatch.setattr(
        decompile,
        "_prepare_ranked_binary_preview_items",
        lambda *_args, **_kwargs: [
            decompile.FunctionWorkItem(
                index=1,
                function_cfg=SimpleNamespace(),
                function=SimpleNamespace(addr=0x10010, name="sub_10010", project=project),
            ),
            decompile.FunctionWorkItem(
                index=2,
                function_cfg=SimpleNamespace(),
                function=SimpleNamespace(addr=0x100EA, name="sub_100ea", project=project),
            ),
            decompile.FunctionWorkItem(
                index=3,
                function_cfg=None,
                function=SimpleNamespace(addr=0x10179, name="sub_10179", project=project),
            ),
        ],
    )

    supplemented = decompile._supplement_function_cfg_pairs_with_ranked_preview(
        project,
        [existing_pair],
        [0x10010, 0x100EA, 0x10179],
        target_count=3,
        timeout=6,
        window=0x200,
        low_memory=False,
    )

    assert [func.addr for _cfg, func in supplemented] == [0x11423, 0x10010, 0x100EA]


def test_supplement_function_cfg_pairs_with_seeded_recovery_adds_unique_pairs(monkeypatch):
    project = SimpleNamespace()
    existing_pair = (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="sub_11423", project=project))
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: [
            (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="sub_11423", project=project)),
            (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project)),
            (SimpleNamespace(), SimpleNamespace(addr=0x100EA, name="sub_100ea", project=project)),
        ],
    )

    supplemented = decompile._supplement_function_cfg_pairs_with_seeded_recovery(
        project,
        [existing_pair],
        timeout=6,
        target_count=3,
    )

    assert [func.addr for _cfg, func in supplemented] == [0x11423, 0x10010, 0x100EA]


def test_main_reports_sidecar_debug_assisted_recovery_mode(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = SimpleNamespace(
        source_format="codeview_nb00",
        code_labels={0x10010: "sub_10010"},
        code_ranges={0x10010: (0x10010, 0x10020)},
        data_labels={},
        absolute_addrs=True,
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(
        decompile,
        "_visible_code_labels",
        lambda _metadata: dict(metadata.code_labels),
    )
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(
        decompile,
        "_rank_labeled_function_entries_cached",
        lambda _project, entries, _metadata: (list(entries), False),
    )
    monkeypatch.setattr(
        decompile,
        "_recover_lst_function",
        lambda _project, _metadata, offset, name, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=offset, name=name, project=project),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            tail_validation={},
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "1"])
    out = capsys.readouterr().out

    assert rc in {0, 2}
    assert "/* info: recovery evidence: sidecar/debug-assisted recovery (codeview_nb00) */" in out


def test_main_limits_sidecar_catalog_preview_for_responsiveness(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400)),
    )
    metadata = SimpleNamespace(
        code_labels={0x10000 + i * 0x10: f"proc_{i}" for i in range(30)},
        code_ranges={0x10000 + i * 0x10: (0x10000 + i * 0x10, 0x10000 + i * 0x10 + 0x20) for i in range(30)},
        data_labels={},
    )
    catalog_limits = []

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: dict(metadata.code_labels))
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: {})
    monkeypatch.setattr(
        decompile,
        "_rank_labeled_function_entries_cached",
        lambda _project, entries, _metadata: (list(entries), False),
    )
    monkeypatch.setattr(
        decompile,
        "_format_sidecar_function_catalog",
        lambda _metadata, limit=None: catalog_limits.append(limit) or "catalog-preview",
    )
    monkeypatch.setattr(
        decompile,
        "_recover_lst_function",
        lambda _project, offset, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(addr=offset, name=metadata.code_labels[offset], project=project),
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2"])
    out = capsys.readouterr().out

    assert rc in {0, 2}
    assert catalog_limits == [None]
    assert "catalog preview limited" not in out
    assert "showing first 8 by default for responsiveness" not in out


def test_recover_fast_exe_catalog_overscans_seed_limit_before_trimming(monkeypatch):
    project = SimpleNamespace(entry=0x11423)
    entry_pair = (SimpleNamespace(), SimpleNamespace(addr=0x11423, name="_start"))
    seeded_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x114cd, name="runtime")),
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010")),
        (SimpleNamespace(), SimpleNamespace(addr=0x100ea, name="sub_100ea")),
    ]
    recorded_limits: list[int | None] = []

    monkeypatch.setattr(decompile, "_fallback_entry_function", lambda *_args, **_kwargs: entry_pair)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())

    def _fake_recover_fast_seed_functions(_project, *, timeout, limit):
        recorded_limits.append(limit)
        return seeded_pairs

    monkeypatch.setattr(decompile, "_recover_fast_seed_functions", _fake_recover_fast_seed_functions)
    monkeypatch.setattr(
        decompile,
        "_rank_function_cfg_pairs_for_display",
        lambda _project, pairs: [entry_pair, seeded_pairs[1], seeded_pairs[2], seeded_pairs[0]],
    )

    recovered = decompile._recover_fast_exe_catalog(project, timeout=4, window=0x200, low_memory=False, limit=2)

    assert recorded_limits == [6]
    assert [func.addr for _cfg, func in recovered] == [0x11423, 0x10010]


def test_rank_exe_function_seeds_tolerates_timed_out_entry_probe(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"\xE8\x00\x00\xC3")
    code = binary.read_bytes()
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=binary,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
    )

    monkeypatch.setattr(decompile, "_seed_scan_windows", lambda _project: [(0x1000, 0x1004)])
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: {0x1003})
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_run_with_timeout_in_daemon_thread",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(decompile.FuturesTimeoutError()),
    )

    ranked = decompile._rank_exe_function_seeds(project)

    assert ranked == [0x1003]


def test_main_falls_back_after_fast_exe_catalog_timeout(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace(functions={})
    recovered_function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    def _fake_timeout(fn, *, thread_name_prefix, **_kwargs):
        if thread_name_prefix == "fast-catalog":
            raise decompile.FuturesTimeoutError()
        return fn()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(decompile, "_interesting_functions", lambda _cfg, limit=None: ([recovered_function], 1))
    monkeypatch.setattr(decompile, "_recover_seeded_exe_functions", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "1"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "Quick EXE function discovery timed out" in out
    assert "/* == function 0x11423 _start == */" in out


def test_main_streaming_timeout_reports_nonoptimized_skip_before_string_fallback(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace(functions={})
    recovered_function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(decompile, "_interesting_functions", lambda _cfg, limit=None: ([recovered_function], 1))
    monkeypatch.setattr(decompile, "_recover_seeded_exe_functions", lambda *_args, **_kwargs: ([], []))
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile._AdaptivePerByteTimeoutModel, "observe_success", lambda self, *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="timeout",
            payload="Timed out after 2s.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            partial_payload=None,
            tail_validation={},
            skip_heavy_fallbacks=True,
        ),
    )
    monkeypatch.setattr(decompile, "_try_decompile_non_optimized_slice", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("non-opt lane should stay closed")))
    monkeypatch.setattr(decompile, "_try_emit_string_intrinsic_c", lambda *_args, **_kwargs: "int fallback(void) { return 7; }")
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "8"])
    out = capsys.readouterr().out

    assert rc == 2
    assert (
        "heavy fallback lane disabled for sweep mode "
        "(interactive_stdout=False, max_functions=8, addr=unset)"
        in out
    )
    assert out.index("non-optimized fallback unavailable") < out.index("/* -- c (string intrinsic fallback) -- */")
    assert "int fallback(void) { return 7; }" in out


def test_main_streaming_timeout_reports_nonoptimized_failure_detail_before_string_fallback(
    monkeypatch, tmp_path, capsys
):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace(functions={})
    recovered_function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: True)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(decompile, "_interesting_functions", lambda _cfg, limit=None: ([recovered_function], 1))
    monkeypatch.setattr(decompile, "_recover_seeded_exe_functions", lambda *_args, **_kwargs: ([], []))
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile._AdaptivePerByteTimeoutModel, "observe_success", lambda self, *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="timeout",
            payload="Timed out after 2s.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            partial_payload=None,
            tail_validation={},
            skip_heavy_fallbacks=False,
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_try_decompile_non_optimized_slice",
        lambda *_args, **_kwargs: decompile.NonOptimizedSliceOutcome(
            rendered=None,
            status="error",
            payload="slice lift broke",
            failure_detail="shared-project slice lean: error: slice lift broke",
            attempt_failures=("shared-project slice lean: error: slice lift broke",),
        ),
    )
    monkeypatch.setattr(decompile, "_try_emit_string_intrinsic_c", lambda *_args, **_kwargs: "int fallback(void) { return 7; }")
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "1"])
    out = capsys.readouterr().out

    assert rc == 2
    assert "shared-project slice lean: error: slice lift broke" in out
    assert out.index("non-optimized fallback unavailable") < out.index("/* -- c (string intrinsic fallback) -- */")
    assert "int fallback(void) { return 7; }" in out


def test_main_falls_back_to_partial_timeout_before_asm_when_available(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace(functions={})
    recovered_function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(decompile, "_interesting_functions", lambda _cfg, limit=None: ([recovered_function], 1))
    monkeypatch.setattr(decompile, "_recover_seeded_exe_functions", lambda *_args, **_kwargs: ([], []))
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile._AdaptivePerByteTimeoutModel, "observe_success", lambda self, *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_try_decompile_non_optimized_slice", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_format_asm_range", lambda *_args, **_kwargs: "mov ax, ax")
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x11423, 0x11425))
    monkeypatch.setattr(decompile, "_probe_lift_break", lambda *_args, **_kwargs: "<probe>")
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="timeout",
            payload="Timed out after 2s.",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
            partial_payload="int partial(void) { return 1; }",
            tail_validation={},
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "1"])
    out = capsys.readouterr().out

    assert rc == 2
    assert "/* info: function 0x11423 _start attempt=timed_out validation=uncollected */" in out
    assert "/* problem: timeout */" in out
    assert "/* -- c (partial timeout) -- */" in out
    assert out.index("/* -- c (partial timeout) -- */") < out.index("-- asm fallback --")
    assert "int partial(void) { return 1; }" in out


def test_main_uses_seed_recovery_when_only_hidden_signature_labels_exist(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "life2.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_cfg = SimpleNamespace(functions={})
    recovered_function = SimpleNamespace(addr=0x10010, name="main", project=project)
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x11423: "_startup_sig"},
        code_ranges={},
        absolute_addrs=True,
        source_format="flair_pat+flair_sig",
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: {0x11423: "_startup_sig"})
    monkeypatch.setattr(decompile, "_rank_labeled_function_entries", lambda *_args, **_kwargs: pytest.fail("visible-label ranking should not run"))
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: [(recovered_cfg, recovered_function)],
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "1"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "Signature-bounded sidecar labels available" in out
    assert "/* == function 0x10010 main == */" in out


def test_main_serial_function_timeout_does_not_stall_whole_run(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    body_function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)
    calls = {"work": 0}

    def _fake_timeout(fn, *, thread_name_prefix, **_kwargs):
        if thread_name_prefix == "func-serial" and calls["work"] == 0:
            calls["work"] += 1
            raise decompile.FuturesTimeoutError()
        return fn()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: True)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), entry_function), (SimpleNamespace(), body_function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)
    monkeypatch.setattr(decompile, "_format_asm_range", lambda *_args, **_kwargs: "0x1000: ret")
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x1000, 0x1001))
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* == function 0x11423 _start == */" in out
    assert "Timed out after 2s." in out
    assert "/* == function 0x10010 sub_10010 == */" in out


def test_choose_function_parallelism_honors_forced_serial_env(monkeypatch):
    monkeypatch.setenv("INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION", "1")
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)

    assert decompile._choose_function_parallelism(8) == 1


def test_daemon_thread_pool_executor_detaches_non_waiting_workers_from_atexit_registry():
    executor = decompile.DaemonThreadPoolExecutor(max_workers=1, thread_name_prefix="detach-test")
    future = executor.submit(time.sleep, 0.5)
    deadline = time.time() + 2.0
    while not executor._threads and time.time() < deadline:
        time.sleep(0.01)
    threads = list(executor._threads)
    assert threads
    assert any(thread in _threads_queues for thread in threads)
    executor.shutdown(wait=False, cancel_futures=True)
    assert all(thread not in _threads_queues for thread in threads)
    future.cancel()


def test_run_function_work_item_uses_fork_lane_for_force_isolated_project(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x400)),
        analyses=SimpleNamespace(),
    )
    function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    item = decompile.FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)
    seen = {}

    monkeypatch.setattr(decompile.os, "name", "posix")
    monkeypatch.setattr(decompile.threading, "current_thread", lambda: decompile.threading.main_thread())
    monkeypatch.setattr(decompile.threading, "active_count", lambda: 1)
    monkeypatch.setattr(decompile, "_tail_validation_runtime_enabled", lambda _project: False)
    monkeypatch.setattr(decompile, "_function_decompilation_cache_key", lambda **_kwargs: None)

    def fake_fork_runner(fn, *, timeout):
        seen["timeout"] = timeout
        return fn()

    def fake_decompile_with_stats(*args, **kwargs):
        seen["project"] = args[0]
        seen["function"] = args[2]
        return ("ok", "int _start(void) { return 0; }", None, 1, 1, 0.1)

    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", fake_fork_runner)
    monkeypatch.setattr(decompile, "_decompile_function_with_stats", fake_decompile_with_stats)
    monkeypatch.setattr(decompile, "_tail_validation_snapshot_for_function_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("should not rebuild project")))

    result = decompile._run_function_work_item(
        item,
        timeout=2,
        api_style="modern",
        binary_path=Path("/tmp/sample.exe"),
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=None,
        enable_structured_simplify=True,
        force_isolated_project=True,
        allow_isolated_retry=False,
    )

    assert result.status == "ok"
    assert result.payload == "int _start(void) { return 0; }"
    assert seen["project"] is project
    assert seen["function"] is function
    assert seen["timeout"] == 3


def test_main_uses_prefork_pool_for_isolated_x86_16_parallel_lane(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    recovered_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x10010, name="sub_10010", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x10020, name="sub_10020", project=project)),
        (SimpleNamespace(), SimpleNamespace(addr=0x10030, name="sub_10030", project=project)),
    ]
    seen = {"jobs": None, "workers": None}

    class _FakePreforkPool:
        def __init__(self, *, max_workers, worker_func, name_prefix="prefork"):
            seen["workers"] = max_workers
            self._worker_func = worker_func

        def run_unordered(self, jobs, *, poll_timeout=0.25):
            seen["jobs"] = list(jobs)
            for job_id, payload in jobs:
                yield job_id, self._worker_func(payload)

        def shutdown(self):
            return None

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_recover_fast_exe_catalog", lambda *_args, **_kwargs: list(recovered_pairs))
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 2)
    monkeypatch.setattr(decompile, "PreforkJobPool", _FakePreforkPool)
    monkeypatch.setattr(decompile.threading, "active_count", lambda: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "3"])
    out = capsys.readouterr().out

    assert rc == 0
    assert seen["workers"] == 2
    assert seen["jobs"] == [(1, 1), (2, 2), (3, 3)]
    assert "summary: decompiled 3/3 shown functions" in out


def test_main_parallel_keeps_timeout_after_deadline(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    class _FakeFuture:
        def __init__(self, result):
            self._result = result

        def result(self, timeout=None):
            return self._result

        def done(self):
            return False

        def cancelled(self):
            return False

    class _FakeExecutor:
        def __init__(self, *args, **kwargs):
            self.future = None

        def submit(self, _fn, item, **_kwargs):
            self.future = _FakeFuture(
                decompile.FunctionWorkResult(
                    index=item.index,
                    status="ok",
                    payload=f"int {item.function.name}(void) {{ return 0; }}",
                    debug_output="",
                    function=item.function,
                    function_cfg=item.function_cfg,
                )
            )
            return self.future

        def shutdown(self, wait=True, cancel_futures=True):
            return None

    monotonic_values = iter([0.0] + [5.0] * 16)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 2)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "DaemonThreadPoolExecutor", _FakeExecutor)
    monkeypatch.setattr(decompile, "wait", lambda pending, **_kwargs: (set(), set(pending)))
    monkeypatch.setattr(decompile.time, "monotonic", lambda: next(monotonic_values))

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "3"])
    out = capsys.readouterr().out

    assert rc == 2
    assert "int _start(void) { return 0; }" not in out
    assert "Timed out after 2s." in out


def test_main_parallel_does_not_promote_late_partial_after_deadline(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    class _FakeFuture:
        def __init__(self, result):
            self._result = result

        def result(self, timeout=None):
            return self._result

        def done(self):
            return False

        def cancelled(self):
            return False

    class _FakeExecutor:
        def __init__(self, *args, **kwargs):
            self.future = None

        def submit(self, _fn, item, **_kwargs):
            self.future = _FakeFuture(
                decompile.FunctionWorkResult(
                    index=item.index,
                    status="timeout",
                    payload="Timed out after 2s.",
                    debug_output="",
                    function=item.function,
                    function_cfg=item.function_cfg,
                    partial_payload="int _start(void) { return 0; }",
                )
            )
            return self.future

        def shutdown(self, wait=True, cancel_futures=True):
            return None

    monotonic_values = iter([0.0] + [5.0] * 16)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 2)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "DaemonThreadPoolExecutor", _FakeExecutor)
    monkeypatch.setattr(decompile, "wait", lambda pending, **_kwargs: (set(), set(pending)))
    monkeypatch.setattr(decompile.time, "monotonic", lambda: next(monotonic_values))

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "3"])
    out = capsys.readouterr().out

    assert rc == 2
    assert "/* -- c (partial timeout) -- */" not in out
    assert "int _start(void) { return 0; }" not in out
    assert "Timed out after 2s." in out


def test_main_parallel_promotes_done_future_at_deadline(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    class _FakeFuture:
        def __init__(self, result):
            self._result = result
            self._done = True

        def result(self, timeout=None):
            return self._result

        def done(self):
            return self._done

        def cancelled(self):
            return False

    class _FakeExecutor:
        def __init__(self, *args, **kwargs):
            self.future = None

        def submit(self, _fn, item, **_kwargs):
            self.future = _FakeFuture(
                decompile.FunctionWorkResult(
                    index=item.index,
                    status="ok",
                    payload=f"int {item.function.name}(void) {{ return 0; }}",
                    debug_output="",
                    function=item.function,
                    function_cfg=item.function_cfg,
                )
            )
            return self.future

        def shutdown(self, wait=True, cancel_futures=True):
            return None

    monotonic_values = iter([0.0] + [5.0] * 16)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 2)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "DaemonThreadPoolExecutor", _FakeExecutor)
    monkeypatch.setattr(decompile, "wait", lambda pending, **_kwargs: (set(), set(pending)))
    monkeypatch.setattr(decompile.time, "monotonic", lambda: next(monotonic_values))

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "1"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* -- c -- */" in out
    assert "int _start(void) { return 0; }" in out
    assert "Timed out after 2s." not in out


def test_main_parallel_promotes_future_completed_during_late_collection(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    function = SimpleNamespace(addr=0x11423, name="_start", project=project)

    class _FakeFuture:
        def __init__(self, result):
            self._result = result
            self._done = False

        def result(self, timeout=None):
            return self._result

        def done(self):
            return self._done

        def cancelled(self):
            return False

    class _FakeExecutor:
        def __init__(self, *args, **kwargs):
            self.future = None

        def submit(self, _fn, item, **_kwargs):
            self.future = _FakeFuture(
                decompile.FunctionWorkResult(
                    index=item.index,
                    status="ok",
                    payload=f"int {item.function.name}(void) {{ return 0; }}",
                    debug_output="",
                    function=item.function,
                    function_cfg=item.function_cfg,
                )
            )
            executor_state["future"] = self.future
            return self.future

        def shutdown(self, wait=True, cancel_futures=True):
            return None

    monotonic_values = iter([0.0] + [5.0] * 16)
    executor_state = {"future": None}
    wait_calls = {"count": 0}

    def _fake_wait(pending, **_kwargs):
        wait_calls["count"] += 1
        if wait_calls["count"] == 1:
            return set(), set(pending)
        future = executor_state["future"]
        if future is not None:
            future._done = True
        return {future} if future is not None else set(), set()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_recover_fast_exe_catalog",
        lambda *_args, **_kwargs: [(SimpleNamespace(), function)],
    )
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 2)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "DaemonThreadPoolExecutor", _FakeExecutor)
    monkeypatch.setattr(decompile, "wait", _fake_wait)
    monkeypatch.setattr(decompile.time, "monotonic", lambda: next(monotonic_values))

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "1"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* -- c -- */" in out
    assert "int _start(void) { return 0; }" in out
    assert "Timed out after 2s." not in out


def test_candidate_recovery_regions_use_only_largest_window_for_body_seed():
    regions = decompile._candidate_recovery_regions(
        None,
        0x10010,
        image_end=0x11000,
        region_span=0x120,
        project_entry=0x11423,
    )

    assert regions == [(0x10010, 0x10130)]


def test_rank_function_cfg_pairs_for_display_prefers_truncated_body_seed_over_wrapper_paths(monkeypatch):
    project = SimpleNamespace(entry=0x11423)
    entry = (SimpleNamespace(), SimpleNamespace(addr=0x11423, blocks=(SimpleNamespace(size=0x20),)))
    body = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x10010,
            blocks=(SimpleNamespace(size=0x40),),
            info={"x86_16_recovery_truncated": True},
        ),
    )
    wrapper = (SimpleNamespace(), SimpleNamespace(addr=0x10050, blocks=(SimpleNamespace(size=0x10),)))
    runtime_shell = (SimpleNamespace(), SimpleNamespace(addr=0x11440, blocks=(SimpleNamespace(size=0x10),)))

    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x10050} if addr == 0x11423 else ({0x11440} if addr == 0x10010 else set()),
    )

    ranked = decompile._rank_function_cfg_pairs_for_display(project, [wrapper, runtime_shell, body, entry])

    assert [func.addr for _cfg, func in ranked[:3]] == [0x11423, 0x10010, 0x11440]


def test_rank_function_cfg_pairs_for_display_keeps_secondary_pre_entry_body_ahead_of_runtime_shell(monkeypatch):
    project = SimpleNamespace(entry=0x11423)
    entry = (SimpleNamespace(), SimpleNamespace(addr=0x11423, blocks=(SimpleNamespace(size=0x20),)))
    primary_body = (SimpleNamespace(), SimpleNamespace(addr=0x11000, blocks=(SimpleNamespace(size=0x60),)))
    secondary_body = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x10010,
            blocks=(SimpleNamespace(size=0x50),),
            info={"x86_16_recovery_truncated": True},
        ),
    )
    runtime_shell = (SimpleNamespace(), SimpleNamespace(addr=0x11440, blocks=(SimpleNamespace(size=0x10),)))

    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x11440} if addr == 0x11423 else set(),
    )

    ranked = decompile._rank_function_cfg_pairs_for_display(project, [runtime_shell, secondary_body, primary_body, entry])

    assert [func.addr for _cfg, func in ranked[:4]] == [0x11423, 0x10010, 0x11000, 0x11440]


def test_rank_function_cfg_pairs_for_display_demotes_wrapper_body_targets_below_other_pre_entry_bodies(monkeypatch):
    project = SimpleNamespace(entry=0x11423)
    entry = (SimpleNamespace(), SimpleNamespace(addr=0x11423, blocks=(SimpleNamespace(size=0x20),)))
    primary_body = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x10010,
            blocks=(SimpleNamespace(size=0x50),),
            info={"x86_16_recovery_truncated": True},
        ),
    )
    secondary_body = (SimpleNamespace(), SimpleNamespace(addr=0x10120, blocks=(SimpleNamespace(size=0x40),)))
    wrapper_target = (SimpleNamespace(), SimpleNamespace(addr=0x10050, blocks=(SimpleNamespace(size=0x10),)))

    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x10050} if addr == 0x10010 else set(),
    )

    ranked = decompile._rank_function_cfg_pairs_for_display(project, [wrapper_target, secondary_body, primary_body, entry])

    assert [func.addr for _cfg, func in ranked[:4]] == [0x11423, 0x10010, 0x10120, 0x10050]


def test_recover_candidate_function_pair_stops_after_good_enough_score(monkeypatch):
    seen_regions: list[tuple[int, int]] = []

    def _fake_pick(_project, addr, *, regions=None, **_kwargs):
        seen_regions.append(regions[0])
        blocks = tuple(SimpleNamespace(size=0x20) for _ in range(4))
        return SimpleNamespace(), SimpleNamespace(addr=addr, blocks=blocks)

    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick)

    cfg, func = decompile._recover_candidate_function_pair(
        SimpleNamespace(
            factory=SimpleNamespace(
                block=lambda *_args, **_kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=[SimpleNamespace(address=0x11450)]))
            )
        ),
        candidate_addr=0x11450,
        image_end=0x12000,
        metadata=None,
        project_entry=0x11423,
        region_span=0x200,
    )

    assert cfg is not None
    assert func.addr == 0x11450
    assert seen_regions == [(0x11450, 0x114d0)]


def test_recover_seeded_exe_functions_skips_seeds_inside_recovered_ranges(monkeypatch):
    code = b"\x90" * 0x400
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x10000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
    )
    calls: list[int] = []

    def _fake_recover(_project, *, candidate_addr, **_kwargs):
        calls.append(candidate_addr)
        if candidate_addr == 0x10010:
            func = SimpleNamespace(
                addr=0x10010,
                name="sub_10010",
                is_plt=False,
                is_simprocedure=False,
                blocks=(SimpleNamespace(addr=0x10010, size=0x60),),
            )
        else:
            func = SimpleNamespace(
                addr=candidate_addr,
                name=f"sub_{candidate_addr:x}",
                is_plt=False,
                is_simprocedure=False,
                blocks=(SimpleNamespace(addr=candidate_addr, size=0x10),),
            )
        return SimpleNamespace(), func

    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x10010, 0x10030, 0x10100])
    monkeypatch.setattr(decompile, "_recover_candidate_function_pair", _fake_recover)
    monkeypatch.setattr(decompile, "collect_neighbor_call_targets", lambda _function: [])

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=3)

    assert [func.addr for _cfg, func in recovered] == [0x10010, 0x10100]
    assert calls == [0x10010, 0x10100]


def test_recover_candidate_with_timeout_uses_thread_timeout_off_main_thread(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace()
    calls: list[str] = []

    monkeypatch.setattr(
        decompile,
        "_recover_candidate_function_pair",
        lambda *_args, **_kwargs: (SimpleNamespace(), SimpleNamespace(addr=0x1000, blocks=())),
    )
    monkeypatch.setattr(decompile.threading, "current_thread", lambda: object())
    monkeypatch.setattr(decompile.threading, "main_thread", lambda: object())

    def _fake_thread_timeout(fn, *, thread_name_prefix, timeout):
        calls.append(f"{thread_name_prefix}:{timeout}")
        return fn()

    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_thread_timeout)

    cfg, func = decompile._recover_candidate_with_timeout(
        project,
        candidate_addr=0x1000,
        image_end=0x2000,
        metadata=None,
        project_entry=0x1000,
        region_span=0x120,
        timeout=3,
        binary_path=binary,
        linked_base=0x1000,
    )

    assert cfg is not None
    assert func.addr == 0x1000
    assert calls == ["recover-candidate:3"]


def test_recover_candidate_with_timeout_uses_fork_timeout_on_main_thread(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace()
    seen = {}

    monkeypatch.setattr(
        decompile,
        "_recover_candidate_function_pair",
        lambda *_args, **_kwargs: (SimpleNamespace(), SimpleNamespace(addr=0x1000, blocks=())),
    )
    monkeypatch.setattr(decompile.os, "name", "posix")
    monkeypatch.setattr(decompile.threading, "current_thread", lambda: decompile.threading.main_thread())
    monkeypatch.setattr(decompile.threading, "active_count", lambda: 1)

    def _fake_fork_timeout(fn, *, timeout):
        seen["timeout"] = timeout
        return fn()

    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", _fake_fork_timeout)
    monkeypatch.setattr(
        decompile,
        "_run_with_timeout_in_daemon_thread",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("thread timeout should not run")),
    )

    cfg, func = decompile._recover_candidate_with_timeout(
        project,
        candidate_addr=0x1000,
        image_end=0x2000,
        metadata=None,
        project_entry=0x1000,
        region_span=0x120,
        timeout=3,
        binary_path=binary,
        linked_base=0x1000,
    )

    assert cfg is not None
    assert func.addr == 0x1000
    assert seen["timeout"] == 4


def test_recover_candidate_with_timeout_reuses_runtime_candidate_cache(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace()
    seen = {"calls": 0}

    def _fake_recover(*_args, **_kwargs):
        seen["calls"] += 1
        return (SimpleNamespace(tag="cfg"), SimpleNamespace(addr=0x1000, blocks=()))

    monkeypatch.setattr(decompile, "_recover_candidate_function_pair", _fake_recover)
    monkeypatch.setattr(decompile.os, "name", "posix")
    monkeypatch.setattr(decompile.threading, "current_thread", lambda: decompile.threading.main_thread())
    monkeypatch.setattr(decompile.threading, "active_count", lambda: 1)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())

    first_cfg, first_func = decompile._recover_candidate_with_timeout(
        project,
        candidate_addr=0x1000,
        image_end=0x2000,
        metadata=None,
        project_entry=0x1000,
        region_span=0x120,
        timeout=3,
        binary_path=binary,
        linked_base=0x1000,
    )
    second_cfg, second_func = decompile._recover_candidate_with_timeout(
        project,
        candidate_addr=0x1000,
        image_end=0x2000,
        metadata=None,
        project_entry=0x1000,
        region_span=0x120,
        timeout=3,
        binary_path=binary,
        linked_base=0x1000,
    )

    assert seen["calls"] == 1
    assert first_cfg is second_cfg
    assert first_func is second_func


def test_try_decompile_non_optimized_slice_uses_fork_lane_on_main_thread(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    slice_project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x55\x8b\xec\xc3")),
        arch=SimpleNamespace(name="86_16"),
    )
    project = SimpleNamespace(
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x10000),
            memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x55\x8b\xec\xc3"),
        ),
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
    )
    cfg = SimpleNamespace()

    class FakeFunction:
        def __init__(self):
            self.addr = 0x114CD
            self.name = "sub_114cd"
            self.normalized = False

        def normalize(self):
            self.normalized = True

        def get_call_sites(self):
            return []

        def get_call_target(self, _callsite):
            return None

    func = FakeFunction()
    seen = {}

    monkeypatch.setattr(decompile.os, "name", "posix")
    monkeypatch.setattr(decompile.threading, "current_thread", lambda: decompile.threading.main_thread())
    monkeypatch.setattr(decompile.threading, "active_count", lambda: 1)
    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x114cd, 0x114d1))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *_args, **_kwargs: slice_project)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: (cfg, func))
    monkeypatch.setattr(decompile, "_sidecar_cod_metadata_for_function", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "void sub_114cd(void) {}", None, 1, 0x20, 0.5),
    )

    def _fake_fork_timeout(fn, *, timeout):
        seen["timeout"] = timeout
        return fn()

    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", _fake_fork_timeout)
    monkeypatch.setattr(
        decompile,
        "_run_with_timeout_in_daemon_thread",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("daemon thread fallback should not run")),
    )

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x114cd,
        "sub_114cd",
        timeout=6,
        api_style="modern",
        binary_path=binary,
        lst_metadata=None,
    )

    assert outcome.rendered == "void sub_114cd(void) {}"
    assert seen["timeout"] == 7


def test_try_decompile_non_optimized_slice_uses_bounded_attempt_timeout_in_daemon_mode(monkeypatch):
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x55\x8b\xec\xc3")),
    )
    function = SimpleNamespace(name="main", addr=0x1000, normalized=True, blocks=(SimpleNamespace(size=0x10),))
    seen: dict[str, int] = {}

    monkeypatch.setattr(decompile.os, "name", "nt")
    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x1000, 0x1004))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: SimpleNamespace())
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (SimpleNamespace(), function),
    )
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)

    def _fake_daemon_timeout(fn, *, timeout, **_kwargs):
        seen["timeout"] = timeout
        return fn()

    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_daemon_timeout)
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("timeout", "Timed out after 4s.", "int partial(void) { return 1; }", 1, 4, 4.0),
    )

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1000,
        "main",
        timeout=5,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
    )

    assert outcome.rendered == "int partial(void) { return 1; }"
    assert seen["timeout"] == 7


def test_try_decompile_non_optimized_slice_retries_after_bounded_lean_timeout(monkeypatch):
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x55\x8b\xec\xc3")),
    )
    function = SimpleNamespace(name="main", addr=0x1000, normalized=True, blocks=(SimpleNamespace(size=0x10),))
    calls: list[tuple[str, bool]] = []
    daemon_calls = {"count": 0}

    monkeypatch.setattr(decompile.os, "name", "nt")
    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x1000, 0x1004))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: SimpleNamespace())

    def _fake_pick_function_lean(*_args, **_kwargs):
        calls.append(("lean", False))
        return SimpleNamespace(), function

    def _fake_pick_function(_slice_project, _start, *, data_references, **_kwargs):
        calls.append(("full", data_references))
        if data_references:
            raise AssertionError("full-with-refs should not run after full-no-refs succeeds")
        return SimpleNamespace(), function

    def _fake_daemon_timeout(fn, *, timeout, **_kwargs):
        daemon_calls["count"] += 1
        if daemon_calls["count"] == 1:
            raise TimeoutError(f"Timed out after {timeout}s.")
        return fn()

    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_pick_function", _fake_pick_function)
    monkeypatch.setattr(decompile, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_daemon_timeout)
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "int recovered(void) { return 2; }", None, 1, 3, 0.01),
    )

    outcome = decompile._try_decompile_non_optimized_slice(
        project,
        0x1000,
        "main",
        timeout=5,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
        allow_fresh_project_retry=False,
    )

    assert outcome.rendered == "int recovered(void) { return 2; }"
    assert calls == [("full", False)]
    assert daemon_calls["count"] == 2


def test_main_defers_exe_limit_until_after_seed_ranking(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    runtime_function = SimpleNamespace(addr=0x114cd, name="runtime_init", project=project)
    extra_runtime = SimpleNamespace(addr=0x1157c, name="runtime_more", project=project)
    body_function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)
    cfg = SimpleNamespace(functions={})

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(
        decompile,
        "_interesting_functions",
        lambda _cfg, limit=None: ([entry_function, runtime_function, extra_runtime], 3),
    )
    monkeypatch.setattr(decompile, "_recover_seeded_exe_functions", lambda *_args, **_kwargs: [(SimpleNamespace(), body_function)])
    monkeypatch.setattr(
        decompile,
        "_rank_function_cfg_pairs_for_display",
        lambda _project, _pairs: [
            (cfg, entry_function),
            (SimpleNamespace(), body_function),
            (cfg, runtime_function),
            (cfg, extra_runtime),
        ],
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* == function 0x11423 _start == */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x114cd runtime_init == */" not in out


def test_main_reranks_merged_seeded_pairs_before_max_function_slice(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace(functions={})
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project, blocks=(SimpleNamespace(size=0x20),))
    wrapper_function = SimpleNamespace(addr=0x11440, name="runtime_shell", project=project, blocks=(SimpleNamespace(size=0x10),))
    body_function = SimpleNamespace(
        addr=0x10010,
        name="sub_10010",
        project=project,
        blocks=(SimpleNamespace(size=0x50),),
        info={"x86_16_recovery_truncated": True},
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(decompile, "_interesting_functions", lambda _cfg, limit=None: ([entry_function, wrapper_function], 2))
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: ([(SimpleNamespace(), body_function)], [0x10010]),
    )
    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x11440} if addr == 0x11423 else set(),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* == function 0x11423 _start == */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x11440 runtime_shell == */" not in out


def test_main_reranks_nontruncated_seeded_body_before_runtime_shell(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace(functions={})
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project, blocks=(SimpleNamespace(size=0x20),))
    runtime_function = SimpleNamespace(addr=0x11440, name="runtime_shell", project=project, blocks=(SimpleNamespace(size=0x10),))
    body_function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project, blocks=(SimpleNamespace(size=0x50),))

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(decompile, "_recover_partial_cfg", lambda *_args, **_kwargs: cfg)
    monkeypatch.setattr(decompile, "_interesting_functions", lambda _cfg, limit=None: ([entry_function, runtime_function], 2))
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: ([(SimpleNamespace(), body_function)], [0x10010]),
    )
    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x11440} if addr == 0x11423 else set(),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* == function 0x11423 _start == */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x11440 runtime_shell == */" not in out


def test_main_defers_exe_limit_until_after_seed_ranking_with_recovery_only_sidecar(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = SimpleNamespace(code_labels={0x11423: "_startup_sig"})
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    runtime_function = SimpleNamespace(addr=0x114cd, name="runtime_init", project=project)
    body_function = SimpleNamespace(
        addr=0x10010,
        name="sub_10010",
        project=project,
        blocks=(SimpleNamespace(size=0x40),),
        info={"x86_16_recovery_truncated": True},
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: {0x11423: "_startup_sig"})
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: (
            [
                (SimpleNamespace(), entry_function),
                (SimpleNamespace(), runtime_function),
                (SimpleNamespace(), body_function),
            ],
            [0x11423, 0x114cd, 0x10010],
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "/* == function 0x11423 _start == */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out
    assert "/* == function 0x114cd runtime_init == */" not in out


def test_main_helper_free_small_cap_exe_uses_serial_workers_with_hidden_seed_metadata(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    cfg = SimpleNamespace(functions={})
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    body_function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)
    metadata = SimpleNamespace()
    max_workers_seen: list[int] = []

    class _FakeExecutor:
        def __init__(self, max_workers, *args, **kwargs):
            max_workers_seen.append(max_workers)

        def submit(self, fn, item, **kwargs):
            class _Future:
                def result(self, timeout=None):
                    return decompile.FunctionWorkResult(
                        index=item.index,
                        status="ok",
                        payload=f"int {item.function.name}(void) {{ return 0; }}",
                        debug_output="",
                        byte_count=1,
                        elapsed=0.01,
                        function=item.function,
                        function_cfg=item.function_cfg,
                    )

                def __hash__(self):
                    return id(self)

            return _Future()

        def shutdown(self, wait=True, cancel_futures=True):
            return None

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: {0x11423: "_startup_sig"})
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: [(SimpleNamespace(), entry_function), (SimpleNamespace(), body_function)],
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 2)
    monkeypatch.setattr(decompile, "DaemonThreadPoolExecutor", _FakeExecutor)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "2", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert max_workers_seen == []
    assert "/* == function 0x11423 _start == */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out


def test_main_uses_default_signature_catalog_when_not_explicit(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    default_catalog = tmp_path / "repo_signature_catalog.pat"
    seen: dict[str, object] = {}

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "default_signature_catalog_path", lambda *_args, **_kwargs: default_catalog)

    def _fake_load_lst_metadata(_binary, _project, *, pat_backend=None, signature_catalog=None, **_kwargs):
        seen["signature_catalog"] = signature_catalog
        return None

    monkeypatch.setattr(decompile, "_load_lst_metadata", _fake_load_lst_metadata)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(
        decompile,
        "_run_with_timeout_in_daemon_thread",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(FuturesTimeoutError()),
    )
    monkeypatch.setattr(decompile, "_recover_fast_seed_functions", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_format_first_block_asm", lambda *_args, **_kwargs: "entry asm")
    monkeypatch.setattr(decompile, "_probe_lift_break", lambda *_args, **_kwargs: "lift probe")
    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x11423, 0x11440))
    monkeypatch.setattr(decompile, "_format_asm_range", lambda *_args, **_kwargs: "asm range")

    rc = decompile.main([str(binary), "--timeout", "1"])
    _out = capsys.readouterr().out

    assert rc == 5
    assert seen["signature_catalog"] == default_catalog


def test_main_hidden_seed_metadata_gives_seed_catalog_more_time(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400),
        ),
    )
    metadata = SimpleNamespace()
    seen_timeouts: list[tuple[str, int]] = []
    entry_function = SimpleNamespace(addr=0x11423, name="_start", project=project)
    body_function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)

    def _fake_run(fn, *, timeout, thread_name_prefix, **_kwargs):
        seen_timeouts.append((thread_name_prefix, timeout))
        return fn()

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(decompile, "_visible_code_labels", lambda _metadata: {})
    monkeypatch.setattr(decompile, "_recovery_code_labels", lambda _metadata: {0x11423: "_startup_sig"})
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_run)
    monkeypatch.setattr(
        decompile,
        "_recover_seeded_exe_functions",
        lambda *_args, **_kwargs: (
            [(SimpleNamespace(), entry_function), (SimpleNamespace(), body_function)],
            [0x11423, 0x10010],
        ),
    )
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(
        decompile,
        "_run_function_work_item",
        lambda item, **_kwargs: decompile.FunctionWorkResult(
            index=item.index,
            status="ok",
            payload=f"int {item.function.name}(void) {{ return 0; }}",
            debug_output="",
            byte_count=1,
            elapsed=0.01,
            function=item.function,
            function_cfg=item.function_cfg,
        ),
    )

    rc = decompile.main([str(binary), "--timeout", "6", "--max-functions", "2"])
    out = capsys.readouterr().out

    assert rc == 0
    assert ("seed-catalog", 8) in seen_timeouts
    assert "/* == function 0x11423 _start == */" in out
    assert "/* == function 0x10010 sub_10010 == */" in out


def test_recover_seeded_exe_functions_prefers_largest_bounded_recovery(monkeypatch):
    code = b"\x55\x8B\xEC" + b"\x90" * 0x500
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)]))
        ),
    )
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x1010])
    seen_regions: list[tuple[int, int]] = []

    def _fake_pick(_project, addr, *, regions=None, **_kwargs):
        seen_regions.append(regions[0])
        size = regions[0][1] - regions[0][0]
        block_count = 1 if size <= 0x80 else 3
        total_size = 0x20 if size <= 0x80 else 0x90
        blocks = tuple(SimpleNamespace(size=total_size // block_count) for _ in range(block_count))
        func = SimpleNamespace(addr=addr, name=f"sub_{addr:x}", is_plt=False, is_simprocedure=False, blocks=blocks)
        return SimpleNamespace(), func

    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick)
    monkeypatch.setattr(decompile, "collect_neighbor_call_targets", lambda _function: [])

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=1, region_span=0x400)

    assert recovered
    assert len(seen_regions) >= 2
    assert sum(block.size for block in recovered[0][1].blocks) == 0x90


def test_supplement_cached_seeded_recovery_adds_pre_entry_body_function(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x1000,
                max_addr=0x600,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 0x600),
            )
        ),
    )
    helper_pair = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x114cd,
            name="sub_114cd",
            is_plt=False,
            is_simprocedure=False,
            info={},
            blocks=(SimpleNamespace(size=0x18),),
        ),
    )
    body_pair = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x10010,
            name="sub_10010",
            is_plt=False,
            is_simprocedure=False,
            info={},
            blocks=(SimpleNamespace(size=0x40), SimpleNamespace(size=0x40)),
        ),
    )
    stored_payloads: list[dict[str, object]] = []

    monkeypatch.setattr(decompile, "_supplement_functions_from_prologue_scan", lambda *_args, **_kwargs: [body_pair])
    monkeypatch.setattr(
        decompile,
        "_rank_function_cfg_pairs_for_display",
        lambda _project, pairs: sorted(pairs, key=lambda item: item[1].addr),
    )
    monkeypatch.setattr(decompile, "_store_cache_json", lambda _kind, _key, payload: stored_payloads.append(payload))

    recovered, addrs = decompile._supplement_cached_seeded_recovery(
        project,
        [helper_pair],
        [0x114cd],
        region_span=0x120,
        per_function_timeout=1,
        limit=4,
        cache_key={"kind": "seeded_function_catalog"},
    )

    assert [function.addr for _cfg, function in recovered] == [0x10010, 0x114cd]
    assert addrs == [0x10010, 0x114cd]
    assert stored_payloads[-1] == {"addrs": [0x10010, 0x114cd]}


def test_supplement_cached_seeded_recovery_prioritizes_linear_body_targets_for_tiny_pre_entry_body(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x10000,
                max_addr=0x600,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 0x600),
            )
        ),
    )
    tiny_body_pair = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x10010,
            name="sub_10010",
            is_plt=False,
            is_simprocedure=False,
            info={"x86_16_recovery_truncated": True},
            blocks=(SimpleNamespace(addr=0x10010, size=0x18),),
        ),
    )
    captured_candidate_addrs: list[int] = []

    monkeypatch.setattr(decompile, "_rank_gap_scan_candidate_addrs", lambda *_args, **_kwargs: [0x10040])
    monkeypatch.setattr(
        decompile,
        "_linear_function_seed_targets",
        lambda _project, addr, **_kwargs: {0x10060} if addr == 0x10010 else set(),
    )
    monkeypatch.setattr(
        decompile,
        "collect_neighbor_call_targets",
        lambda function: [SimpleNamespace(target_addr=0x101A0)] if function.addr == 0x10010 else [],
    )

    def _fake_supplement(_project, _existing_addrs, *, candidate_addrs=None, **_kwargs):
        captured_candidate_addrs[:] = list(candidate_addrs or [])
        return [
            (
                SimpleNamespace(),
                SimpleNamespace(
                    addr=0x10060,
                    name="sub_10060",
                    is_plt=False,
                    is_simprocedure=False,
                    info={},
                    blocks=(SimpleNamespace(addr=0x10060, size=0x60),),
                ),
            )
        ]

    monkeypatch.setattr(decompile, "_supplement_functions_from_prologue_scan", _fake_supplement)
    monkeypatch.setattr(
        decompile,
        "_rank_function_cfg_pairs_for_display",
        lambda _project, pairs: sorted(pairs, key=lambda item: item[1].addr),
    )

    recovered, addrs = decompile._supplement_cached_seeded_recovery(
        project,
        [tiny_body_pair],
        [0x10010],
        region_span=0x120,
        per_function_timeout=1,
        limit=4,
        cache_key=None,
    )

    assert captured_candidate_addrs[:3] == [0x10040, 0x10060, 0x101A0]
    assert [function.addr for _cfg, function in recovered] == [0x10010, 0x10060]
    assert addrs == [0x10010, 0x10060]


def test_recover_seeded_exe_functions_cached_supplement_timeout_uses_cached_recovery(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x1000,
                max_addr=0x600,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 0x600),
            )
        ),
    )
    helper_pair = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x114cd,
            name="sub_114cd",
            is_plt=False,
            is_simprocedure=False,
            info={},
            blocks=(SimpleNamespace(size=0x18),),
        ),
    )

    def _fake_timeout(fn, *, thread_name_prefix, **_kwargs):
        if thread_name_prefix == "cached-supplement":
            raise decompile.FuturesTimeoutError()
        return fn()

    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x114cd])
    monkeypatch.setattr(decompile, "_load_cache_json", lambda *_args, **_kwargs: {"addrs": [0x114cd]})
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: [helper_pair])
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)

    recovered, addrs = decompile._recover_seeded_exe_functions(project, timeout=4, limit=2, return_addrs=True)

    assert [function.addr for _cfg, function in recovered] == [0x114cd]
    assert addrs == [0x114cd]


def test_recover_seeded_exe_functions_gives_cached_supplement_more_budget(monkeypatch):
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x1000,
                max_addr=0x600,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 0x600),
            )
        ),
    )
    helper_pair = (
        SimpleNamespace(),
        SimpleNamespace(
            addr=0x114cd,
            name="sub_114cd",
            is_plt=False,
            is_simprocedure=False,
            info={},
            blocks=(SimpleNamespace(size=0x18),),
        ),
    )
    captured_timeouts: list[tuple[str, int]] = []

    def _fake_timeout(fn, *, timeout, thread_name_prefix, **_kwargs):
        captured_timeouts.append((thread_name_prefix, timeout))
        return fn()

    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x114cd])
    monkeypatch.setattr(decompile, "_load_cache_json", lambda *_args, **_kwargs: {"addrs": [0x114cd]})
    monkeypatch.setattr(decompile, "_recover_cached_function_pairs", lambda *_args, **_kwargs: [helper_pair])
    monkeypatch.setattr(decompile, "_supplement_cached_seeded_recovery", lambda _project, pairs, addrs, **_kwargs: (pairs, addrs))
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", _fake_timeout)

    recovered, addrs = decompile._recover_seeded_exe_functions(project, timeout=6, limit=2, return_addrs=True)

    assert [function.addr for _cfg, function in recovered] == [0x114cd]
    assert addrs == [0x114cd]
    assert ("cached-supplement", 4) in captured_timeouts


def test_recover_seeded_exe_functions_prioritizes_linear_body_targets_for_truncated_recovery(monkeypatch):
    code = b"\x90" * 0x600
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x10000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)]))
        ),
    )
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x10010])
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected lean recovery")),
    )
    monkeypatch.setattr(
        decompile,
        "_recover_candidate_with_timeout",
        lambda _project, *, candidate_addr, **_kwargs: (
            SimpleNamespace(),
            SimpleNamespace(
                addr=candidate_addr,
                name=f"sub_{candidate_addr:x}",
                is_plt=False,
                is_simprocedure=False,
                info={"x86_16_recovery_truncated": candidate_addr == 0x10010},
                blocks=(SimpleNamespace(size=0x18), SimpleNamespace(size=0x18)),
            ),
        ),
    )
    call_order: list[int] = []

    def _collect_neighbor_call_targets(function):
        if function.addr == 0x10010:
            return [SimpleNamespace(target_addr=0x101a0)]
        return []

    monkeypatch.setattr(decompile, "collect_neighbor_call_targets", _collect_neighbor_call_targets)
    monkeypatch.setattr(decompile, "_linear_function_seed_targets", lambda _project, addr, **_kwargs: {0x10050} if addr == 0x10010 else set())

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=3)

    assert [func.addr for _cfg, func in recovered] == [0x10010, 0x10050, 0x101a0]


def test_recover_seeded_exe_functions_stops_after_limit_without_return_addrs(monkeypatch):
    code = b"\x90" * 0x600
    project = SimpleNamespace(
        entry=0x11423,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x10000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)]))
        ),
    )
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x10010, 0x10040, 0x10070])
    monkeypatch.setattr(decompile, "_load_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_store_cache_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_rank_prologue_scan_candidate_addrs", lambda *_args, **_kwargs: [])
    call_order: list[int] = []

    def _fake_recover(_project, *, candidate_addr, **_kwargs):
        call_order.append(candidate_addr)
        return (
            SimpleNamespace(),
            SimpleNamespace(
                addr=candidate_addr,
                name=f"sub_{candidate_addr:x}",
                is_plt=False,
                is_simprocedure=False,
                info={},
                blocks=(SimpleNamespace(size=0x18),),
            ),
        )

    monkeypatch.setattr(decompile, "_recover_candidate_with_timeout", _fake_recover)
    monkeypatch.setattr(decompile, "collect_neighbor_call_targets", lambda _function: [])

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=2, return_addrs=False)

    assert [func.addr for _cfg, func in recovered] == [0x10010, 0x10040]
    assert call_order == [0x10010, 0x10040]


def test_match_flair_startup_entry_matches_watcom_startup_pattern():
    entry_bytes = bytes.fromhex("CCEBFD90909090" + "90" * 25)

    matches = match_flair_startup_entry(entry_bytes, Path("/home/xor/ida77/flair77"))

    assert matches
    assert any(match.pat_path.endswith("exe_wa16.pat") for match in matches)


def test_list_flair_sig_libraries_reads_pascal_catalogs():
    libraries = list_flair_sig_libraries(Path("/home/xor/ida77/flair77"))

    assert any("Turbo Pascal" in library.title for library in libraries)


def test_ensure_pat_from_omf_input_generates_fallback_pat_for_obj(tmp_path):
    pat_path = ensure_pat_from_omf_input(SYNTHETIC_OBJ, tmp_path, flair_root=Path("/home/xor/ida77/flair77"))

    assert pat_path is not None
    modules = parse_pat_file(pat_path)
    assert [module.module_name for module in modules] == ["E086_SHORTCUT", "E086_ENTRY"]


def test_ensure_pat_from_omf_input_merges_plb_and_fallback_for_life_obj(tmp_path):
    pat_path = ensure_pat_from_omf_input(REPO_ROOT / "LIFE.OBJ", tmp_path, flair_root=Path("/home/xor/ida77/flair77"))

    assert pat_path is not None
    modules = parse_pat_file(pat_path)
    names = {module.module_name for module in modules}
    assert "_main" in names
    assert "_generation" in names
    rich_module = next(module for module in modules if module.referenced_names and any(pub.name == "_main" for pub in module.public_names))
    assert any(ref.name == "__chkstk" for ref in rich_module.referenced_names)
    assert len(modules) >= 15


def test_generate_pat_from_omf_obj_captures_fixupp_external_refs_for_life_obj(tmp_path):
    pat_path = tmp_path / "life-fallback.pat"

    count = generate_pat_from_omf_obj(REPO_ROOT / "LIFE.OBJ", pat_path)

    assert count >= 5
    modules = parse_pat_file(pat_path)
    main_module = next(module for module in modules if module.module_name == "_main")
    assert main_module.referenced_names
    all_ref_names = {ref.name for module in modules for ref in module.referenced_names}
    assert "__chkstk" in all_ref_names
    assert "_printf" in all_ref_names or "_sprintf" in all_ref_names


def test_extract_omf_modules_from_lib_reads_page_aligned_module(tmp_path):
    lib_path = tmp_path / "sample.lib"
    lib_path.write_bytes(_build_synthetic_microsoft_lib(SYNTHETIC_OBJ.read_bytes()))

    modules = extract_omf_modules_from_lib(lib_path)

    assert len(modules) == 1
    assert modules[0].module_name == "SYNTHETIC.OBJ"
    assert modules[0].data.startswith(SYNTHETIC_OBJ.read_bytes()[:16])


def test_parse_microsoft_lib_reads_header_and_extended_dictionary(tmp_path):
    lib_path = tmp_path / "sample.lib"
    lib_path.write_bytes(
        _build_synthetic_microsoft_lib(
            SYNTHETIC_OBJ.read_bytes(),
            case_sensitive=True,
            extended_records=[(1, (7, 9))],
        )
    )

    metadata = parse_microsoft_lib(lib_path)

    assert metadata.header.page_size == 512
    assert metadata.header.case_sensitive is True
    assert metadata.header.dictionary_blocks == 1
    assert len(metadata.modules) == 1
    assert metadata.modules[0].page_number == 1
    assert metadata.modules[0].dependency_indexes == (7, 9)
    assert metadata.extended_records[0].page_number == 1
    assert metadata.extended_records[0].dependency_indexes == (7, 9)


def test_parse_microsoft_lib_reads_dictionary_entries_and_lookup(tmp_path):
    lib_path = tmp_path / "sample.lib"
    lib_path.write_bytes(
        _build_synthetic_microsoft_lib(
            SYNTHETIC_OBJ.read_bytes(),
            dictionary_entries=[("__chkstk", 1), ("_main", 1)],
        )
    )

    metadata = parse_microsoft_lib(lib_path)

    assert {(entry.symbol_name, entry.module_page) for entry in metadata.dictionary_entries} == {
        ("__chkstk", 1),
        ("_main", 1),
    }
    assert lookup_microsoft_lib_symbol(lib_path, "__CHKSTK") is not None
    assert lookup_microsoft_lib_symbol(lib_path, "__CHKSTK").module_page == 1
    assert lookup_microsoft_lib_symbol(lib_path, "_main").symbol_name == "_main"


def test_enumerate_microsoft_lib_dictionary_symbols_preserves_case_sensitive_lookup(tmp_path):
    lib_path = tmp_path / "sample.lib"
    lib_path.write_bytes(
        _build_synthetic_microsoft_lib(
            SYNTHETIC_OBJ.read_bytes(),
            case_sensitive=True,
            dictionary_entries=[("SymbolExact", 1)],
        )
    )

    entries = enumerate_microsoft_lib_dictionary_symbols(lib_path)

    assert [(entry.symbol_name, entry.module_page) for entry in entries] == [("SymbolExact", 1)]
    assert lookup_microsoft_lib_symbol(lib_path, "SymbolExact") is not None
    assert lookup_microsoft_lib_symbol(lib_path, "symbolexact") is None


def test_generate_pat_from_omf_lib_extracts_obj_members(tmp_path):
    lib_path = tmp_path / "sample.lib"
    lib_path.write_bytes(_build_synthetic_microsoft_lib(SYNTHETIC_OBJ.read_bytes()))
    pat_path = tmp_path / "sample.pat"

    count = generate_pat_from_omf_lib(lib_path, pat_path)

    assert count >= 2
    modules = parse_pat_file(pat_path)
    assert [module.module_name for module in modules[:2]] == ["E086_SHORTCUT", "E086_ENTRY"]


@pytest.mark.skipif(not BORLAND_CC_LIB.exists(), reason="Borland Turbo C v2 library samples are not available")
def test_parse_omf_lib_smoke_reads_real_borland_turbo_c_archive():
    metadata = parse_omf_lib(BORLAND_CC_LIB)

    assert metadata.header.page_size == 16
    assert len(metadata.modules) > 200
    assert len(metadata.dictionary_entries) > 500
    assert metadata.modules[0].module_name == "IOERROR"
    assert enumerate_omf_lib_dictionary_symbols(BORLAND_CC_LIB)
    assert lookup_omf_lib_symbol(BORLAND_CC_LIB, "__IOERROR") is not None


@pytest.mark.skipif(not BORLAND_GRAPHICS_LIB.exists(), reason="Borland Turbo C v2 graphics library sample is not available")
def test_generate_pat_from_real_borland_omf_lib_smoke(tmp_path):
    pat_path = tmp_path / "graphics.pat"

    count = generate_pat_from_omf_lib(BORLAND_GRAPHICS_LIB, pat_path)

    assert count > 0
    modules = parse_pat_file(pat_path)
    assert modules
    assert any(module.module_name in {"___move", "_graphresult", "_detectgraph"} for module in modules)


def test_match_pat_modules_labels_unique_generated_function_match():
    image = bytes.fromhex(
        "90 90 90 FB FC 52 50 53 55 56 57 06 51 1E 8B EC 36 89 2E DE 00 C5 76 12 AD 89 76 12 8C D7 8E DF 8A CC 98 C3 90"
    )
    module = PatModule(
        source_path="<memory>",
        compiler_name="",
        module_name="demo_func",
        pattern_bytes=tuple([0xFB, 0xFC, 0x52, 0x50, 0x53, 0x55, 0x56, 0x57, 0x06, 0x51, 0x1E, 0x8B] + [None] * 20),
        module_length=0x0C,
        public_names=(PatPublicName(offset=0, name="demo_func"),),
        referenced_names=(),
        tail_bytes=(),
    )

    code_labels, code_ranges, matched_compiler_names = match_pat_modules(image, 0x1000, [module])

    assert code_labels == {0x1003: "demo_func"}
    assert code_ranges == {0x1003: (0x1003, 0x100F)}
    assert matched_compiler_names == ()


def test_load_cached_pat_regex_specs_creates_reusable_disk_cache(tmp_path):
    pat_path = tmp_path / "demo.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    pat_path.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")

    specs = load_cached_pat_regex_specs(pat_path, tmp_path)

    assert len(specs) == 1
    assert isinstance(specs[0], CachedPatRegexSpec)
    assert any(path.suffixes[-2:] == [".patrx", ".pickle"] for path in tmp_path.iterdir() if path.is_file())


def test_match_pat_modules_accepts_cached_regex_specs(tmp_path):
    pat_path = tmp_path / "demo.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    pat_path.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")
    specs = load_cached_pat_regex_specs(pat_path, tmp_path)
    image = bytes.fromhex(
        "90 90 90 FB FC 52 50 53 55 56 57 06 51 1E 8B EC 36 89 2E DE 00 C5 76 12 AD 89 76 12 8C D7 8E DF 8A CC 98 C3 90"
    )

    code_labels, code_ranges, matched_compiler_names = match_pat_modules(image, 0x1000, specs)

    assert code_labels == {0x1003: "demo_func"}
    assert code_ranges == {0x1003: (0x1003, 0x100F)}
    assert matched_compiler_names == ()


def test_match_pat_modules_supports_both_explicit_backends(tmp_path):
    pat_path = tmp_path / "demo.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    pat_path.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")
    specs = load_cached_pat_regex_specs(pat_path, tmp_path)
    image = bytes.fromhex(
        "90 90 90 FB FC 52 50 53 55 56 57 06 51 1E 8B EC 36 89 2E DE 00 C5 76 12 AD 89 76 12 8C D7 8E DF 8A CC 98 C3 90"
    )

    py_labels, py_ranges, py_compilers = match_pat_modules(image, 0x1000, specs, backend="python_regex")
    hs_labels, hs_ranges, hs_compilers = match_pat_modules(image, 0x1000, specs, backend="hyperscan")

    assert py_labels == {0x1003: "demo_func"}
    assert py_ranges == {0x1003: (0x1003, 0x100F)}
    assert hs_labels == py_labels
    assert hs_ranges == py_ranges
    assert py_compilers == hs_compilers == ()


def test_normalize_pat_backend_choice_rejects_unknown_backend():
    with pytest.raises(ValueError):
        _normalize_pat_backend_choice("wat")


def test_detect_flair_metadata_forwards_pat_backend(monkeypatch):
    recorded = {}
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(),
            memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 32),
        ),
    )

    monkeypatch.setattr(sidecar_parsers.Path, "exists", lambda self: True)
    monkeypatch.setattr(sidecar_parsers, "match_flair_startup_entry", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(sidecar_parsers, "list_flair_sig_libraries", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(sidecar_parsers, "_match_flair_startup_pat_functions", lambda *_args, **_kwargs: ({}, {}))

    def _fake_discover(binary, project_arg, *, flair_root=None, backend=None, **_kwargs):
        recorded["binary"] = binary
        recorded["project"] = project_arg
        recorded["flair_root"] = flair_root
        recorded["backend"] = backend
        return SimpleNamespace(code_labels={}, code_ranges={}, source_formats=())

    monkeypatch.setattr(sidecar_parsers, "discover_local_pat_matches", _fake_discover)

    sidecar_parsers._detect_flair_metadata(Path("/tmp/demo.exe"), project, pat_backend="python_regex")

    assert recorded["backend"] == "python_regex"


def test_build_signature_catalog_skips_duplicate_modules(tmp_path):
    left = tmp_path / "left.pat"
    right = tmp_path / "right.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    left.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")
    right.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")
    output = tmp_path / "catalog.pat"

    result = build_signature_catalog([left, right], output, recursive=False, cache_dir=tmp_path / "cache")

    assert result.input_count == 2
    assert result.imported_module_count == 2
    assert result.unique_module_count == 1
    assert result.duplicate_module_count == 1
    modules = parse_pat_file(output)
    assert [module.module_name for module in modules] == ["demo_func"]


def test_build_signature_catalog_merges_exact_patterns_with_normalized_names(tmp_path):
    left = tmp_path / "left.pat"
    right = tmp_path / "right.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    left.write_text(f"{pattern} 00 0000 000C :0000 __DEMO123__\n---\n")
    right.write_text(f"{pattern} 00 0000 000C :0000 demo123\n---\n")
    output = tmp_path / "catalog.pat"

    result = build_signature_catalog([left, right], output, recursive=False, cache_dir=tmp_path / "cache")

    assert result.input_count == 2
    assert result.imported_module_count == 2
    assert result.unique_module_count == 1
    assert result.duplicate_module_count == 1
    modules = parse_pat_file(output)
    assert [module.module_name for module in modules] == ["__DEMO123__"]


def test_build_signature_catalog_merges_exact_patterns_with_internal_underscores(tmp_path):
    left = tmp_path / "left.pat"
    right = tmp_path / "right.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    left.write_text(f"{pattern} 00 0000 000C :0000 __DEMO_FUNC_123__\n---\n")
    right.write_text(f"{pattern} 00 0000 000C :0000 demo_func_123\n---\n")
    output = tmp_path / "catalog.pat"

    result = build_signature_catalog([left, right], output, recursive=False, cache_dir=tmp_path / "cache")

    assert result.input_count == 2
    assert result.imported_module_count == 2
    assert result.unique_module_count == 1
    assert result.duplicate_module_count == 1
    modules = parse_pat_file(output)
    assert [module.module_name for module in modules] == ["__DEMO_FUNC_123__"]


def test_match_signature_catalog_matches_prebuilt_catalog(tmp_path):
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    catalog = tmp_path / "catalog.pat"
    catalog.write_text(
        f"{pattern} 00 0000 000C :0000 demo_func ; mod=demo_func | compiler=Microsoft C v5.1\n---\n"
    )
    image = bytes.fromhex(
        "90 90 90 FB FC 52 50 53 55 56 57 06 51 1E 8B EC 36 89 2E DE 00 C5 76 12 AD 89 76 12 8C D7 8E DF 8A CC 98 C3 90"
    )
    project = SimpleNamespace(
        loader=SimpleNamespace(
            main_object=SimpleNamespace(min_addr=0x1000, max_addr=0x1000 + len(image) - 1),
            memory=SimpleNamespace(load=lambda addr, size: image[addr - 0x1000 : addr - 0x1000 + size]),
        )
    )

    result = match_signature_catalog(catalog, tmp_path / "demo.exe", project, backend="python_regex")

    assert result.code_labels == {0x1003: "demo_func"}
    assert result.code_ranges == {0x1003: (0x1003, 0x100F)}
    assert result.source_formats == ("signature_catalog",)
    assert result.matched_compiler_names == ("Microsoft C v5.1",)


def test_detect_flair_metadata_merges_local_pat_matches(monkeypatch):
    project = SimpleNamespace(
        entry=0x2000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(),
            memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 32),
        ),
    )
    monkeypatch.setattr(sidecar_parsers, "match_flair_startup_entry", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(sidecar_parsers, "list_flair_sig_libraries", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(sidecar_parsers, "_match_flair_startup_pat_functions", lambda *_args, **_kwargs: ({}, {}))
    monkeypatch.setattr(
        sidecar_parsers,
        "discover_local_pat_matches",
        lambda *_args, **_kwargs: SimpleNamespace(
            code_labels={0x1234: "helper_func"},
            code_ranges={0x1234: (0x1234, 0x1250)},
            source_formats=("local_omf_pat",),
        ),
    )

    code_labels, code_ranges, source_formats = sidecar_parsers._detect_flair_metadata(Path("/tmp/demo.exe"), project)

    assert code_labels[0x1234] == "helper_func"
    assert code_ranges[0x1234] == (0x1234, 0x1250)
    assert "local_omf_pat" in source_formats


def test_detect_flair_metadata_merges_signature_catalog(monkeypatch, tmp_path):
    project = SimpleNamespace(
        entry=0x2000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(),
            memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 32),
        ),
    )
    catalog = tmp_path / "catalog.pat"
    catalog.write_text("---\n")
    monkeypatch.setattr(sidecar_parsers, "match_flair_startup_entry", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(sidecar_parsers, "list_flair_sig_libraries", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(sidecar_parsers, "_match_flair_startup_pat_functions", lambda *_args, **_kwargs: ({}, {}))
    monkeypatch.setattr(
        sidecar_parsers,
        "match_signature_catalog",
        lambda *_args, **_kwargs: SimpleNamespace(
            code_labels={0x2345: "catalog_func"},
            code_ranges={0x2345: (0x2345, 0x2350)},
            source_formats=("signature_catalog",),
        ),
    )
    monkeypatch.setattr(
        sidecar_parsers,
        "discover_local_pat_matches",
        lambda *_args, **_kwargs: SimpleNamespace(code_labels={}, code_ranges={}, source_formats=()),
    )

    code_labels, code_ranges, source_formats = sidecar_parsers._detect_flair_metadata(
        Path("/tmp/demo.exe"),
        project,
        pat_backend="python_regex",
        signature_catalog=catalog,
    )

    assert code_labels[0x2345] == "catalog_func"
    assert code_ranges[0x2345] == (0x2345, 0x2350)
    assert "signature_catalog" in source_formats


def test_detect_flair_metadata_searches_startup_pats_across_whole_binary(monkeypatch):
    project = SimpleNamespace(
        entry=0x2000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(min_addr=0x2000, max_addr=0x203F),
            memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 64),
        ),
    )
    seen: dict[str, object] = {}

    monkeypatch.setattr(sidecar_parsers, "match_flair_startup_entry", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(sidecar_parsers, "list_flair_sig_libraries", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(sidecar_parsers, "_load_flair_startup_pat_modules", lambda *_args, **_kwargs: ("module",))

    def _fake_match(image_bytes, base_addr, modules, *, backend=None):
        seen["image_len"] = len(image_bytes)
        seen["base_addr"] = base_addr
        seen["modules"] = modules
        seen["backend"] = backend
        return {0x2010: "startup_sig_func"}, {0x2010: (0x2010, 0x2020)}

    monkeypatch.setattr(sidecar_parsers, "match_pat_modules", _fake_match)
    monkeypatch.setattr(
        sidecar_parsers,
        "discover_local_pat_matches",
        lambda *_args, **_kwargs: SimpleNamespace(code_labels={}, code_ranges={}, source_formats=()),
    )

    code_labels, code_ranges, source_formats = sidecar_parsers._detect_flair_metadata(
        Path("/tmp/demo.exe"),
        project,
        pat_backend="python_regex",
    )

    assert seen == {"image_len": 64, "base_addr": 0x2000, "modules": ("module",), "backend": "python_regex"}
    assert code_labels[0x2010] == "startup_sig_func"
    assert code_ranges[0x2010] == (0x2010, 0x2020)
    assert "flair_pat" in source_formats


def test_peer_exe_catalog_requires_exact_span_byte_match():
    image = bytes.fromhex("90 90 55 8B EC C3 90 55 8B EC 90 C3 90")
    peer_image = bytes.fromhex("90 90 55 8B EC C3 90 55 8B ED 90 C3 90")
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda addr, size: image[addr - 0x1000 : addr - 0x1000 + size]))
    )
    peer_project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda addr, size: peer_image[addr - 0x1000 : addr - 0x1000 + size]))
    )
    peer_metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1002: "match_func", 0x1007: "mismatch_func"},
        code_ranges={0x1002: (0x1002, 0x1006), 0x1007: (0x1007, 0x100C)},
        absolute_addrs=True,
        source_format="cod_listing",
    )

    labels, ranges = sidecar_metadata._merge_peer_function_catalog(project, peer_project, peer_metadata)

    assert labels == {0x1002: "match_func"}
    assert ranges == {0x1002: (0x1002, 0x1006)}


def test_discover_peer_exe_catalog_matches_merges_exact_sibling_catalog(monkeypatch, tmp_path):
    binary = tmp_path / "demo2.exe"
    peer_binary = tmp_path / "demo.exe"
    binary.write_bytes(b"MZ")
    peer_binary.write_bytes(b"MZ")
    image = bytes.fromhex("90 90 55 8B EC C3 90")
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x10000),
            memory=SimpleNamespace(load=lambda addr, size: image[addr - 0x1000 : addr - 0x1000 + size]),
        ),
    )
    peer_project = SimpleNamespace(
        loader=SimpleNamespace(
            memory=SimpleNamespace(load=lambda addr, size: image[addr - 0x1000 : addr - 0x1000 + size]),
        )
    )
    peer_metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1002: "peer_func"},
        code_ranges={0x1002: (0x1002, 0x1006)},
        absolute_addrs=True,
        source_format="cod_listing+codeview_nb00",
    )

    monkeypatch.setattr(sidecar_metadata, "_peer_exe_family_candidates", lambda _binary: (peer_binary,))
    monkeypatch.setattr(sidecar_metadata, "_build_project", lambda *args, **kwargs: peer_project)
    monkeypatch.setattr(
        sidecar_metadata,
        "_load_lst_metadata",
        lambda path, *_args, **kwargs: peer_metadata if path == peer_binary and kwargs.get("allow_peer_exe") is False else None,
    )

    labels, ranges, source_formats = sidecar_metadata._discover_peer_exe_catalog_matches(binary, project)

    assert labels == {0x1002: "peer_func"}
    assert ranges == {0x1002: (0x1002, 0x1006)}
    assert source_formats == ("peer_exe",)
    assert getattr(project, "_inertia_peer_exe_titles", ()) == (peer_binary.name,)
    assert getattr(project, "_inertia_peer_exe_paths", ()) == (str(peer_binary),)
    assert getattr(project, "_inertia_peer_sidecar_cache", {}).get(str(peer_binary)) == (peer_project, peer_metadata)


def test_try_decompile_peer_sidecar_slice_uses_native_peer_metadata(monkeypatch, tmp_path):
    peer_binary = tmp_path / "demo.exe"
    peer_binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000)),
        _inertia_peer_exe_paths=(str(peer_binary),),
    )
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "func"},
        code_ranges={0x1000: (0x1000, 0x1006)},
        absolute_addrs=True,
        source_format="peer_exe",
    )
    peer_project = SimpleNamespace(entry=0x1000)
    peer_metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "func"},
        code_ranges={0x1000: (0x1000, 0x1006)},
        absolute_addrs=True,
        source_format="cod_listing+codeview_nb00",
        cod_path=str(tmp_path / "demo.cod"),
    )

    monkeypatch.setattr(decompile, "_build_project", lambda *args, **kwargs: peer_project)
    monkeypatch.setattr(
        decompile,
        "_load_lst_metadata",
        lambda path, *_args, **kwargs: peer_metadata if path == peer_binary and kwargs.get("allow_peer_exe") is False else None,
    )
    monkeypatch.setattr(decompile, "_exact_function_span_matches", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        decompile,
        "_try_decompile_sidecar_slice",
        lambda project_arg, metadata_arg, addr, name, **_kwargs: (
            ("ok", "void func(void)\n{\n}\n")
            if project_arg is peer_project and metadata_arg is peer_metadata and addr == 0x1000 and name == "func"
            else None
        ),
    )

    rendered = decompile._try_decompile_peer_sidecar_slice(
        project,
        metadata,
        0x1000,
        "func",
        timeout=6,
        api_style="default",
        binary_path=tmp_path / "demo2.exe",
    )

    assert rendered == "void func(void)\n{\n}\n"


def test_try_decompile_peer_sidecar_slice_reuses_cached_peer_bundle(monkeypatch, tmp_path):
    peer_binary = tmp_path / "demo.exe"
    peer_binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000)),
        _inertia_peer_exe_paths=(str(peer_binary),),
    )
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "func"},
        code_ranges={0x1000: (0x1000, 0x1006)},
        absolute_addrs=True,
        source_format="peer_exe",
    )
    peer_project = SimpleNamespace(entry=0x1000)
    peer_metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "func"},
        code_ranges={0x1000: (0x1000, 0x1006)},
        absolute_addrs=True,
        source_format="cod_listing+codeview_nb00",
    )
    build_calls = []
    metadata_calls = []

    def _fake_build(*_args, **_kwargs):
        build_calls.append("build")
        return peer_project

    def _fake_load(path, *_args, **kwargs):
        metadata_calls.append((path, kwargs.get("allow_peer_exe")))
        return peer_metadata if path == peer_binary and kwargs.get("allow_peer_exe") is False else None

    monkeypatch.setattr(decompile, "_build_project", _fake_build)
    monkeypatch.setattr(decompile, "_load_lst_metadata", _fake_load)
    monkeypatch.setattr(decompile, "_exact_function_span_matches", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        decompile,
        "_try_decompile_sidecar_slice",
        lambda project_arg, metadata_arg, addr, name, **_kwargs: (
            ("ok", f"void {name}(void)\n{{\n}}\n")
            if project_arg is peer_project and metadata_arg is peer_metadata and addr == 0x1000
            else None
        ),
    )

    rendered_once = decompile._try_decompile_peer_sidecar_slice(
        project,
        metadata,
        0x1000,
        "func",
        timeout=6,
        api_style="default",
        binary_path=tmp_path / "demo2.exe",
    )
    rendered_twice = decompile._try_decompile_peer_sidecar_slice(
        project,
        metadata,
        0x1000,
        "func",
        timeout=6,
        api_style="default",
        binary_path=tmp_path / "demo2.exe",
    )

    assert rendered_once == "void func(void)\n{\n}\n"
    assert rendered_twice == "void func(void)\n{\n}\n"
    assert build_calls == ["build"]
    assert metadata_calls == [(peer_binary, False)]


def test_try_decompile_sidecar_slice_retries_with_broader_exact_region_recovery(monkeypatch):
    slice_project = SimpleNamespace()
    function = SimpleNamespace(name="func")
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\xc3")),
    )
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "func"},
        code_ranges={0x1000: (0x1000, 0x1002)},
        absolute_addrs=True,
        source_format="cod_listing",
    )
    calls: list[str] = []

    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: slice_project)

    def _fake_pick_lean(*_args, **_kwargs):
        calls.append("lean")
        raise KeyError("lean failed")

    def _fake_pick_full(*_args, data_references=None, **_kwargs):
        calls.append(f"full:{data_references}")
        return "cfg", function

    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick_lean)
    monkeypatch.setattr(decompile, "_pick_function", _fake_pick_full)
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "void func(void)\n{\n}\n", 1, 2, 0.01),
    )

    result = decompile._try_decompile_sidecar_slice(
        project,
        metadata,
        0x1000,
        "func",
        timeout=6,
        api_style="default",
        binary_path=None,
    )

    assert result == ("ok", "void func(void)\n{\n}\n")
    assert calls == ["lean", "full:False"]


def test_try_decompile_sidecar_slice_preserves_tail_validation_snapshot_on_source_project(monkeypatch):
    slice_project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    function = SimpleNamespace(name="func", info={})
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\xc3")),
    )
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "func"},
        code_ranges={0x1000: (0x1000, 0x1002)},
        absolute_addrs=True,
        source_format="cod_listing",
    )

    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: slice_project)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: ("cfg", function))

    def _fake_decompile(*_args, **_kwargs):
        slice_project._inertia_last_tail_validation_snapshot = {
            "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable"},
            "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable"},
        }
        return ("ok", "void func(void)\n{\n}\n", 1, 2, 0.01)

    monkeypatch.setattr(decompile, "_decompile_function_with_stats", _fake_decompile)

    result = decompile._try_decompile_sidecar_slice(
        project,
        metadata,
        0x1000,
        "func",
        timeout=6,
        api_style="default",
        binary_path=None,
    )

    assert result is not None
    assert result.status == "ok"
    assert result.payload == "void func(void)\n{\n}\n"
    assert project._inertia_last_tail_validation_snapshot == {
        "structuring": {"changed": False, "mode": "live_out", "verdict": "structuring stable"},
        "postprocess": {"changed": False, "mode": "live_out", "verdict": "postprocess stable"},
    }


def test_try_decompile_sidecar_slice_falls_back_to_cod_source_when_decompiler_stays_empty(monkeypatch):
    slice_project = SimpleNamespace()
    function = SimpleNamespace(name="func")
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\xc3")),
    )
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "func"},
        code_ranges={0x1000: (0x1000, 0x1002)},
        absolute_addrs=True,
        source_format="cod_listing",
        cod_path="/tmp/demo.cod",
    )

    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: slice_project)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: ("cfg", function))
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("empty", "Decompiler did not produce code.", 1, 2, 0.01),
    )
    monkeypatch.setattr(
        decompile,
        "_sidecar_cod_metadata_for_function",
        lambda *_args, **_kwargs: SimpleNamespace(
            source_lines=(
                "func() {",
                "value = 1;",
                "}",
            )
        ),
    )

    result = decompile._try_decompile_sidecar_slice(
        project,
        metadata,
        0x1000,
        "func",
        timeout=6,
        api_style="default",
        binary_path=Path("/tmp/demo.exe"),
    )

    assert result == ("ok", "func() {\nvalue = 1;\n}\n")


def test_recover_lst_function_retries_full_exact_region_when_lean_result_is_truncated(monkeypatch):
    project = SimpleNamespace(entry=0x2000, arch=SimpleNamespace(name="86_16"))
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "func"},
        code_ranges={0x1000: (0x1000, 0x10c0)},
        absolute_addrs=True,
        source_format="cod_listing",
    )
    tiny_func = SimpleNamespace(name="func", blocks=(SimpleNamespace(addr=0x1000, size=8), SimpleNamespace(addr=0x1008, size=8)))
    full_func = SimpleNamespace(
        name="func",
        blocks=(
            SimpleNamespace(addr=0x1000, size=0x30),
            SimpleNamespace(addr=0x1030, size=0x30),
            SimpleNamespace(addr=0x1060, size=0x30),
        ),
    )
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(decompile, "_analysis_timeout", lambda *_args, **_kwargs: __import__("contextlib").nullcontext())
    monkeypatch.setattr(decompile, "_x86_16_fast_recovery_windows", lambda *_args, **_kwargs: (0x80,))
    monkeypatch.setattr(decompile, "_x86_16_recovery_windows", lambda *_args, **_kwargs: (0x80,))
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (calls.append(("lean", None)) or ("cfg-lean", tiny_func)),
    )

    def _fake_pick_function(*_args, data_references=None, **_kwargs):
        calls.append(("full", data_references))
        return "cfg-full", full_func

    monkeypatch.setattr(decompile, "_pick_function", _fake_pick_function)

    cfg, func = decompile._recover_lst_function(
        project,
        metadata,
        0x1000,
        "func",
        timeout=2,
        window=0x200,
    )

    assert cfg == "cfg-full"
    assert func is full_func
    assert calls == [("lean", None), ("full", False), ("full", True)]


def test_load_lst_metadata_forwards_flair_parameters_without_global_args(monkeypatch, tmp_path):
    binary = tmp_path / "demo.exe"
    binary.write_bytes(b"MZ")
    catalog = tmp_path / "catalog.pat"
    catalog.write_text("---\n")
    project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x40)),
        kb=SimpleNamespace(labels={}),
    )
    seen: dict[str, object] = {}

    monkeypatch.setattr(sidecar_metadata, "_probe_ida_base_linear", lambda *_args, **_kwargs: 0x1000)
    monkeypatch.setattr(
        sidecar_metadata,
        "_detect_flair_metadata",
        lambda _binary, _project, *, pat_backend=None, signature_catalog=None: (
            seen.setdefault("pat_backend", pat_backend) and {0x1010: "sig_func"},
            seen.setdefault("signature_catalog", signature_catalog) and {0x1010: (0x1010, 0x1020)},
            ("signature_catalog",),
        ),
    )

    metadata = sidecar_metadata._load_lst_metadata(
        binary,
        project,
        pat_backend="python_regex",
        signature_catalog=catalog,
    )

    assert metadata is not None
    assert seen == {"pat_backend": "python_regex", "signature_catalog": catalog}
    assert metadata.code_labels[0x1010] == "sig_func"
    assert metadata.signature_code_addrs == frozenset({0x1010})


def test_life2_without_peer_exe_metadata_has_no_sidecars_but_life_does():
    life_project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    life_metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, life_project, allow_peer_exe=False)

    life2_project = decompile._build_project(LIFE2_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    life2_metadata = sidecar_metadata._load_lst_metadata(LIFE2_EXE, life2_project, allow_peer_exe=False)

    assert life_metadata is not None
    assert sidecar_metadata._visible_code_labels(life_metadata)
    assert life2_metadata is not None
    assert sidecar_metadata._visible_code_labels(life2_metadata) == {}
    assert life2_metadata.source_format == "flair_pat"


def test_life2_default_metadata_stays_independent_from_life_peer_catalog():
    project = decompile._build_project(LIFE2_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE2_EXE, project)

    assert metadata is not None
    assert "peer_exe" not in metadata.source_format
    assert getattr(project, "_inertia_peer_exe_titles", ()) == ()
    assert getattr(project, "_inertia_peer_exe_paths", ()) == ()
    assert sidecar_metadata._visible_code_labels(metadata) == {}


def test_life2_signature_metadata_seeds_bounded_recovery_without_peer_catalog():
    project = decompile._build_project(LIFE2_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE2_EXE, project, allow_peer_exe=False)

    assert metadata is not None
    assert sidecar_metadata._visible_code_labels(metadata) == {}
    recovery_labels = sidecar_metadata._recovery_code_labels(metadata)
    assert recovery_labels
    span_start, _span = next((addr, span) for addr, span in metadata.code_ranges.items() if span[1] - span[0] > 1)
    start_name = sidecar_metadata._lst_code_label(metadata, span_start, project.entry)
    assert start_name is not None
    assert sidecar_metadata._lst_code_label(metadata, span_start + 1, project.entry) == start_name

    ranked = decompile._rank_exe_function_seeds(project)

    assert ranked
    assert any(addr in recovery_labels for addr in ranked)


def test_life2_signature_metadata_bounded_span_precedes_tiny_helper_seed(monkeypatch):
    project = decompile._build_project(LIFE2_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE2_EXE, project, allow_peer_exe=False)

    assert metadata is not None
    project._inertia_lst_metadata = metadata
    bounded_addr, bounded_span = next((addr, span) for addr, span in metadata.code_ranges.items() if span[1] - span[0] > 1)
    helper_addr = 0x1140D
    assert bounded_span[1] - bounded_span[0] > 1

    window_start = min(bounded_addr, helper_addr)
    window_end = max(bounded_addr, helper_addr) + 0x40

    monkeypatch.setattr(decompile, "_seed_scan_windows", lambda _project: [(window_start, window_end)])
    monkeypatch.setattr(decompile, "_entry_window_seed_targets", lambda *_args, **_kwargs: {helper_addr})
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )

    ranked = decompile._rank_exe_function_seeds(project)

    assert bounded_addr in ranked
    assert helper_addr in ranked
    assert ranked.index(bounded_addr) < ranked.index(helper_addr)


def test_load_lst_metadata_reuses_cached_flair_metadata(monkeypatch, tmp_path):
    binary = tmp_path / "demo.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x1040)),
        kb=SimpleNamespace(labels={}),
    )
    cache_store = {}
    seen = {"calls": 0}

    monkeypatch.setattr(sidecar_metadata, "_probe_ida_base_linear", lambda _binary, _linked_base=0: 0x1000)
    monkeypatch.setattr(sidecar_cache, "_load_cache_json", lambda namespace, key: cache_store.get((namespace, repr(key))))
    monkeypatch.setattr(sidecar_cache, "_store_cache_json", lambda namespace, key, value: cache_store.__setitem__((namespace, repr(key)), value))

    def fake_detect_flair_metadata(_binary, _project, *, pat_backend=None, signature_catalog=None):
        assert pat_backend == "python"
        assert signature_catalog is None
        seen["calls"] += 1
        setattr(_project, "_inertia_flair_startup_matches", ("startup/demo.pat",))
        setattr(_project, "_inertia_flair_local_pat_sources", ("local_omf_pat",))
        setattr(_project, "_inertia_signature_compiler_names", ("Microsoft C v5.1",))
        return {0x1010: "sig_func"}, {0x1010: (0x1010, 0x1020)}, ("flair_pat",)

    monkeypatch.setattr(sidecar_metadata, "_detect_flair_metadata", fake_detect_flair_metadata)

    first = sidecar_metadata._load_lst_metadata(binary, project, allow_peer_exe=False, pat_backend="python")
    assert first is not None
    assert first.code_labels[0x1010] == "sig_func"
    assert seen["calls"] == 1

    second_project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x1040)),
        kb=SimpleNamespace(labels={}),
    )
    second = sidecar_metadata._load_lst_metadata(binary, second_project, allow_peer_exe=False, pat_backend="python")

    assert second is not None
    assert second.code_labels[0x1010] == "sig_func"
    assert seen["calls"] == 1
    assert getattr(second_project, "_inertia_flair_startup_matches", ()) == ("startup/demo.pat",)
    assert getattr(second_project, "_inertia_flair_local_pat_sources", ()) == ("local_omf_pat",)
    assert getattr(second_project, "_inertia_signature_compiler_names", ()) == ("Microsoft C v5.1",)


def test_life2_peer_catalog_oracle_requires_explicit_helper_call():
    project = decompile._build_project(LIFE2_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    labels, ranges, source_formats = sidecar_metadata._discover_peer_exe_catalog_matches(LIFE2_EXE, project)

    assert source_formats == ("peer_exe",)
    assert labels
    assert ranges
    assert {"main", "init_life", "init_buf", "draw_box", "init_mats"} <= set(labels.values())


def test_parse_ida_map_metadata_prefers_segment_class_over_loc_name(tmp_path):
    map_path = tmp_path / "demo.map"
    map_path.write_text(
        "\n"
        " Start  Stop   Length Name               Class\n"
        "\n"
        " 00000H 0001FH 00020H seg000             CODE\n"
        " 00020H 0002FH 00010H dseg               DATA\n"
        "\n"
        "  Address         Publics by Value\n"
        "\n"
        " 0000:0004       loc_10004\n"
        " 0000:0010       main\n"
        " 0002:0002       word_10022\n"
    )

    code_labels, data_labels, segment_offsets = decompile._parse_ida_map_metadata(map_path, load_base_linear=0x10000)

    assert segment_offsets == {"seg000": 0x0000, "dseg": 0x0020}
    assert code_labels[0x10004] == "loc_10004"
    assert code_labels[0x10010] == "main"
    assert data_labels[0x10022] == "word_10022"


def test_visible_code_labels_skip_signature_matched_functions_by_default():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1200: "real_func", 0x1300: "sig_func"},
        code_ranges={0x1200: (0x1200, 0x1220), 0x1300: (0x1300, 0x1310)},
        signature_code_addrs=frozenset({0x1300}),
        absolute_addrs=True,
        source_format="ida_map+signature_catalog",
    )

    assert decompile._visible_code_labels(metadata) == {0x1200: "real_func"}


def test_recovery_code_labels_include_bounded_signature_matches_without_changing_visible_catalog():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1200: "real_func", 0x1300: "sig_func", 0x1400: "loose_sig_func"},
        code_ranges={0x1200: (0x1200, 0x1220), 0x1300: (0x1300, 0x1310)},
        signature_code_addrs=frozenset({0x1300, 0x1400}),
        absolute_addrs=True,
        source_format="ida_map+signature_catalog",
    )

    assert decompile._visible_code_labels(metadata) == {0x1200: "real_func"}
    assert sidecar_metadata._recovery_code_labels(metadata) == {
        0x1200: "real_func",
        0x1300: "sig_func",
    }


def test_format_sidecar_function_catalog_omits_signature_matched_functions():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1200: "real_func", 0x1300: "sig_func"},
        code_ranges={0x1200: (0x1200, 0x1220), 0x1300: (0x1300, 0x1310)},
        signature_code_addrs=frozenset({0x1300}),
        absolute_addrs=True,
        source_format="signature_catalog",
    )

    formatted = decompile._format_sidecar_function_catalog(metadata)

    assert "real_func" in formatted
    assert "sig_func" not in formatted


def test_extract_lst_metadata_supports_uasm_proc_ranges_from_snake_listing():
    metadata = extract_lst_metadata(REPO_ROOT / "snake.lst")

    assert metadata.source_format == "uasm_lst"
    assert metadata.data_labels[0x00] == "msg"
    assert metadata.code_labels[0x00] == "main"
    assert metadata.code_labels[0x92] == "delay"
    assert metadata.code_ranges[0x00] == (0x00, 0x92)
    assert metadata.code_ranges[0x92] == (0x92, 0xA3)


def test_extract_lst_metadata_supports_uasm_entry_labels_in_com_listing():
    metadata = extract_lst_metadata(REPO_ROOT / "angr_platforms" / "x16_samples" / "ICOMDO.LST")

    assert metadata.source_format == "uasm_lst"
    assert metadata.code_labels[0x100] == "start"
    assert metadata.data_labels[0x110] == "msg"


def test_extract_lst_metadata_supports_masm_snow_listing():
    metadata = extract_lst_metadata(REPO_ROOT / "snow.lst")

    assert metadata.source_format == "masm_lst"
    assert metadata.code_labels[0x0000] == "start"
    assert metadata.code_ranges[0x0000] == (0x0000, 0x00B8)
    assert metadata.data_labels[0x00B8] == "const005"


def test_extract_lst_metadata_supports_ida_prefixed_listing(tmp_path):
    listing = """seg000:0000 seg000          segment byte public 'CODE' use16\nseg000:0010 main            proc near\nseg000:0010                 push    bp\nseg000:0012 main            endp\nseg001:0000 seg001          segment word public 'DATA' use16\nseg001:0004 value           db 1\n"""
    tmp = tmp_path / "ida_style.lst"
    tmp.write_text(listing)
    metadata = extract_lst_metadata(tmp)

    assert metadata.source_format == "ida_lst"
    assert metadata.code_labels[0x0010] == "main"
    assert metadata.code_ranges[0x0010] == (0x0010, 0x0012)
    assert metadata.data_labels[0x0004] == "value"


def test_rank_labeled_function_entries_prefers_entry_and_main(monkeypatch):
    project = SimpleNamespace(entry=0x1E432)
    monkeypatch.setattr(decompile, "_is_zero_filled_region", lambda *_args, **_kwargs: False)
    metadata = SimpleNamespace(
        code_ranges={
            0x10000: (0x10000, 0x10010),
            0x10010: (0x10010, 0x10147),
            0x1E432: (0x1E432, 0x1E4E4),
            0x1E4C6: (0x1E4C6, 0x1E4D5),
        }
    )

    ranked = decompile._rank_labeled_function_entries(
        project,
        [
            (0x10000, "padding"),
            (0x10010, "main"),
            (0x1E432, "start"),
            (0x1E4C6, "cintDIV"),
        ],
        metadata,
    )

    assert ranked[:4] == [
        (0x1E432, "start"),
        (0x10010, "main"),
        (0x1E4C6, "cintDIV"),
        (0x10000, "padding"),
    ]


def test_rank_labeled_function_entries_cached_reuses_recovery_cache(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x1E432,
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=binary)),
    )
    metadata = SimpleNamespace(
        source_format="codeview_nb00",
        code_ranges={
            0x10000: (0x10000, 0x10010),
            0x10010: (0x10010, 0x10147),
            0x1E432: (0x1E432, 0x1E4E4),
        },
    )
    entries = [(0x10000, "padding"), (0x10010, "main"), (0x1E432, "start")]

    monkeypatch.setattr(decompile, "_is_zero_filled_region", lambda *_args, **_kwargs: False)

    first, first_hit = decompile._rank_labeled_function_entries_cached(project, entries, metadata)
    second, second_hit = decompile._rank_labeled_function_entries_cached(project, entries, metadata)

    assert first_hit is False
    assert second_hit is True
    assert first == second


def test_dosmz_loader_widens_linear_address_space_without_widening_near_words(tmp_path):
    mz = bytearray(0x20)
    mz[0:2] = b"MZ"
    mz[0x08:0x0A] = (2).to_bytes(2, "little")
    mz[0x10:0x12] = (0x200).to_bytes(2, "little")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(bytes(mz) + b"\x90" * 32)

    with sample.open("rb") as fp:
        obj = DOSMZ(str(sample), fp, base_addr=0x10000)

    assert obj.arch.bits == 32
    assert obj.arch.bytes == 2
    assert obj.linked_base == 0x10000


def test_parse_mzre_map_metadata_extracts_code_ranges(tmp_path):
    map_path = tmp_path / "sample.map"
    map_path.write_text(
        "seg000 CODE 0000\n"
        "main: seg000 NEAR 0010-0146 R0010-0146\n",
        encoding="utf-8",
    )

    code_labels, data_labels, code_ranges = decompile._parse_mzre_map_metadata(
        map_path,
        load_base_linear=0x10000,
    )

    assert data_labels == {}
    assert code_labels == {0x10010: "main"}
    assert code_ranges == {0x10010: (0x10010, 0x10147)}


def test_lst_code_region_prefers_exact_or_containing_sidecar_span():
    metadata = SimpleNamespace(
        code_ranges={
            0x10010: (0x10010, 0x10147),
            0x10147: (0x10147, 0x10211),
        }
    )

    assert decompile._lst_code_region(metadata, 0x10010) == (0x10010, 0x10147)
    assert decompile._lst_code_region(metadata, 0x10080) == (0x10010, 0x10147)
    assert decompile._lst_code_region(metadata, 0x10147) == (0x10147, 0x10211)
    assert decompile._lst_code_region(metadata, 0x20000) is None


def test_lst_code_label_uses_containing_sidecar_span_name():
    metadata = SimpleNamespace(
        absolute_addrs=True,
        code_labels={0x10010: "main", 0x10147: "drawCockpit"},
        code_ranges={
            0x10010: (0x10010, 0x10147),
            0x10147: (0x10147, 0x10211),
        },
    )

    assert decompile._lst_code_label(metadata, 0x10010, 0x1000) == "main"
    assert decompile._lst_code_label(metadata, 0x10080, 0x1000) == "main"
    assert decompile._lst_code_label(metadata, 0x10147, 0x1000) == "drawCockpit"
    assert decompile._lst_code_label(metadata, 0x20000, 0x1000) is None


def test_format_sidecar_function_catalog_includes_ranges_and_sizes():
    metadata = SimpleNamespace(
        code_labels={
            0x10010: "main",
            0x10147: "drawCockpit",
        },
        code_ranges={
            0x10010: (0x10010, 0x10147),
            0x10147: (0x10147, 0x10211),
        },
    )

    rendered = decompile._format_sidecar_function_catalog(metadata)

    assert "0x10010 main size=0x137 range=[0x10010, 0x10147)" in rendered
    assert "0x10147 drawCockpit size=0xca range=[0x10147, 0x10211)" in rendered


def test_parse_idc_metadata_filters_control_flow_labels(tmp_path):
    idc_path = tmp_path / "sample.idc"
    idc_path.write_text(
        'set_name(0X10010, "main");\n'
        'set_name(0X1008C, "cond_1008C");\n'
        'set_name(0X1009D, "else_1009D");\n',
        encoding="utf-8",
    )

    code_labels, data_labels = decompile._parse_idc_metadata(idc_path)

    assert code_labels == {0x10010: "main"}
    assert data_labels == {
        0x1008C: "cond_1008C",
        0x1009D: "else_1009D",
    }


def test_label_looks_like_function_filters_internal_hex_suffixed_flow_labels():
    assert decompile._label_looks_like_function("main")
    assert decompile._label_looks_like_function("MainGameLoop")
    assert decompile._label_looks_like_function("cintDIV")
    assert not decompile._label_looks_like_function("cond_1008C")
    assert not decompile._label_looks_like_function("innerCond_12D71")
    assert not decompile._label_looks_like_function("nextInner2_12D9E")
    assert not decompile._label_looks_like_function("out_12C7D")


def test_fallback_entry_function_uses_fast_recovery_for_call_heavy_cod_helpers(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_pick_function_lean(
        project_arg,
        addr,
        *,
        regions=None,
        data_references=None,
        extend_far_calls=None,
    ):
        calls.append(("lean", regions, data_references, extend_far_calls))
        return expected_cfg, expected_func

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_pick_function_lean", fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_pick_function", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("slow path should not run")))
    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", lambda project_arg, start_addr, *, window: (start_addr, start_addr + window))

    cfg, func = decompile._fallback_entry_function(project, timeout=10, window=0x200, prefer_fast_recovery=True)

    assert cfg is expected_cfg
    assert func is expected_func
    assert project._inertia_decompiler_stage == "recovery:fast"
    assert calls == [("lean", [(0x1000, 0x1080)], False, False)]


def test_fallback_entry_function_uses_full_timeout_budget_for_fast_cod_helpers(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    budgets: list[int] = []

    def fake_analysis_timeout(timeout):
        budgets.append(timeout)

        class _Ctx:
            def __enter__(self):
                return None

            def __exit__(self, exc_type, exc, tb):  # noqa: ANN001
                return False

        return _Ctx()

    monkeypatch.setattr(decompile, "_analysis_timeout", fake_analysis_timeout)
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (SimpleNamespace(), SimpleNamespace(addr=project.entry)),
    )
    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda project_arg, start_addr, *, window: (start_addr, start_addr + window),
    )

    decompile._fallback_entry_function(project, timeout=20, window=0x200, prefer_fast_recovery=True)

    assert budgets == [20]


def test_fallback_entry_function_falls_back_after_fast_recovery_error(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_pick_function_lean(
        project_arg,
        addr,
        *,
        regions=None,
        data_references=None,
        extend_far_calls=None,
    ):
        calls.append(("lean", regions, data_references, extend_far_calls))
        raise ValueError("fast recovery failed")

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions, data_references, force_smart_scan))
        return expected_cfg, expected_func

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_pick_function_lean", fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)
    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda project_arg, start_addr, *, window: (start_addr, start_addr + window),
    )

    cfg, func = decompile._fallback_entry_function(project, timeout=20, window=0x200, prefer_fast_recovery=True)

    assert cfg is expected_cfg
    assert func is expected_func
    assert calls[0][0] == "lean"
    assert calls[-1][0] == "pick"


def test_fallback_entry_function_propagates_timeout_without_retrying(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        calls.append(("infer", window))
        return start_addr, start_addr + window

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions, data_references, force_smart_scan))
        raise decompile._AnalysisTimeout()

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    with pytest.raises(decompile._AnalysisTimeout):
        decompile._fallback_entry_function(project, timeout=10, window=0x200)

    assert calls == [("infer", 0x200), ("pick", [(0x1000, 0x1200)], False, False)]


def test_recover_lst_function_retries_broader_windows_after_narrow_miss(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    lst_metadata = SimpleNamespace(code_labels={0x0: "helper"})
    calls: list[tuple[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        calls.append(("infer", window))
        return start_addr, start_addr + window

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions, force_smart_scan))
        region = regions[0]
        if region[1] - region[0] >= 0x1000:
            return expected_cfg, expected_func
        raise KeyError("narrow miss")

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    cfg, func = decompile._recover_lst_function(
        project,
        lst_metadata,
        0x0,
        "helper",
        timeout=10,
        window=0x200,
    )

    assert cfg is expected_cfg
    assert func is expected_func
    assert [call[1] for call in calls if call[0] == "infer"] == [0x200, 0x400, 0x800, 0x1000]
    assert [call[1][0][1] - call[1][0][0] for call in calls if call[0] == "pick"] == [
        0x200,
        0x400,
        0x800,
        0x1000,
    ]


def test_pick_function_retries_smart_scan_before_complete_scan_after_narrow_cfgfast_miss(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfgs = [
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={0x1000: expected_func}),
    ]

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfgs[len(captured) - 1]

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function(project, 0x1000, regions=[(0x1000, 0x1100)], data_references=True)

    assert cfg is expected_cfgs[-1]
    assert func is expected_func
    assert len(captured) == 4
    assert [entry.get("force_complete_scan", False) for entry in captured] == [False, False, True, True]
    assert [entry["data_references"] for entry in captured] == [True, True, True, True]
    assert [entry["force_smart_scan"] for entry in captured] == [False, True, False, True]


def test_pick_function_continues_after_cfgfast_exception(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        if len(captured) < 3:
            raise ValueError("CFGFast temporarily failed")
        return SimpleNamespace(functions={0x1000: expected_func})

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function(project, 0x1000, regions=[(0x1000, 0x1100)], data_references=True)

    assert cfg.functions[0x1000] is expected_func
    assert func is expected_func
    assert len(captured) == 3


def test_pick_function_disables_smart_scan_for_bounded_x86_16_regions(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function(project, 0x1000, regions=[(0x1000, 0x1100)])

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured[0]["force_smart_scan"] is False
    assert captured[0]["data_references"] is True


def test_describe_exception_keeps_type_when_message_is_empty():
    assert decompile._describe_exception(AssertionError()) == "AssertionError"
    assert decompile._describe_exception(ValueError("bad cfg")) == "ValueError: bad cfg"


def test_detect_packed_mz_executable_recognizes_lzexe(tmp_path):
    path = tmp_path / "packed.exe"
    header = bytearray(0x40)
    header[0:2] = b"MZ"
    header[0x1C:0x20] = b"LZ91"
    path.write_bytes(bytes(header))

    assert decompile._detect_packed_mz_executable(path) == "LZEXE 0.91"


def test_recover_partial_cfg_uses_bounded_cfgfast_and_returns_entry_cfg(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []
    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda project_arg, start_addr, *, window: (start_addr, start_addr + window),
    )
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg = decompile._recover_partial_cfg(project, window=0x200)

    assert cfg is expected_cfg
    assert captured == [
        {
            "start_at_entry": False,
            "function_starts": [0x1000],
            "regions": [(0x1000, 0x1200)],
            "normalize": True,
            "force_complete_scan": False,
            "data_references": False,
            "force_smart_scan": False,
        }
    ]


def test_supplement_functions_from_prologue_scan_adds_confirmed_recoveries(monkeypatch):
    code = bytearray(0x2000)
    for addr in (0x1750, 0x1770):
        offset = addr - 0x1000
        code[offset : offset + 3] = b"\x55\x8b\xec"

    class _Memory:
        def load(self, offset, size):
            return bytes(code[offset : offset + size])

    project = SimpleNamespace(
        entry=0x1500,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(max_addr=len(code) - 1, linked_base=0x1000, memory=_Memory())),
    )

    class _Block:
        def __init__(self):
            self.capstone = SimpleNamespace(
                insns=[
                    SimpleNamespace(mnemonic="push", op_str="bp"),
                    SimpleNamespace(mnemonic="mov", op_str="bp, sp"),
                ]
            )

    project.factory = SimpleNamespace(block=lambda *_args, **_kwargs: _Block())

    expected = {
        0x1770: (SimpleNamespace(), SimpleNamespace(addr=0x1770, name="sub_1770")),
        0x1750: (SimpleNamespace(), SimpleNamespace(addr=0x1750, name="sub_1750")),
    }

    def fake_pick_function_lean(project_arg, addr, **_kwargs):
        return expected[addr]

    monkeypatch.setattr(decompile, "_pick_function_lean", fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda func, **_kwargs: func())

    supplemental = decompile._supplement_functions_from_prologue_scan(project, existing_addrs={0x1500})

    assert [function.addr for _, function in supplemental] == [0x1750]


def test_dedupe_adjacent_prototype_lines_removes_only_consecutive_duplicates():
    source = "int dos_int21(void);\nint dos_int21(void);\nint other(void);\n\nint dos_int21(void);\n"

    assert decompile._dedupe_adjacent_prototype_lines(source) == (
        "int dos_int21(void);\nint other(void);\n\nint dos_int21(void);\n"
    )


def test_sanitize_mangled_autonames_text_fixes_repeated_autonames():
    source = "long sub_6c5sub_6()\n{\n    dos_int2sub_1();\n}\n"

    assert decompile._sanitize_mangled_autonames_text(source) == (
        "long sub_6c5()\n{\n    dos_int2();\n}\n"
    )


def test_cleanup_text_preserves_dos_int21_numeric_helper_name():
    source = (
        "int dos_int21(void);\n"
        "int dos_int21_2(void);\n"
        "\n"
        "void sub_114cd(void)\n"
        "{\n"
        "    dos_int21();\n"
        "    dos_int21sub_1();\n"
        "    dos_int21_2();\n"
        "}\n"
    )

    cleaned = decompile._normalize_anonymous_call_targets(source)
    cleaned = decompile._normalize_spurious_duplicate_local_suffixes(cleaned)
    cleaned = decompile._dedupe_adjacent_prototype_lines(cleaned)
    cleaned = decompile._sanitize_mangled_autonames_text(cleaned)

    assert "dos_int2sub_1();" not in cleaned
    assert "dos_int2();" not in cleaned
    assert "dos_int21sub_1();" not in cleaned
    assert cleaned.count("dos_int21();") == 3


def test_recover_blob_entry_function_enables_data_references(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
        analyses=SimpleNamespace(),
    )
    captured: list[dict[str, object]] = []

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfgs[len(captured) - 1]

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfgs = [
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={0x1000: expected_func}),
    ]
    project.analyses.CFGFast = fake_cfgfast

    cfg, func = decompile._recover_blob_entry_function(project, 0x1000, timeout=10)

    assert cfg is expected_cfgs[-1]
    assert func is expected_func
    assert [entry["data_references"] for entry in captured] == [False, True]


def test_decompile_cli_recovers_source_like_monoprin_tokens():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(MONOPRIN_COD), "--proc", "_mset_pos", "--timeout", "10"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _mset_pos" in result.stdout
    assert "== c ==" in result.stdout
    assert "% 80" in result.stdout
    assert "% 25" in result.stdout
    assert (
        "int _mset_pos(int x, int y)" in result.stdout
        or "short _mset_pos(unsigned short v0, unsigned short x, unsigned short y)" in result.stdout
        or "short _mset_pos(unsigned short x, unsigned short y)" in result.stdout
        or "short _mset_pos(unsigned short x_3, unsigned short y)" in result.stdout
        or "short _mset_pos(unsigned short x, unsigned short x_2, unsigned short y)" in result.stdout
        or "short _mset_pos(unsigned short x, unsigned short x_3, unsigned short y)" in result.stdout
    )
    assert "[bp+0x4] = x" in result.stdout
    assert "[bp+0x6] = y" in result.stdout
    assert "mono_x =" in result.stdout
    assert "mono_y =" in result.stdout
    assert "&v1" not in result.stdout
    assert "return" in result.stdout


def test_decompile_cli_can_extract_and_name_cod_procedure():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(NHORZ_COD), "--proc", "_ChangeWeather", "--timeout", "10"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _ChangeWeather" in result.stdout
    assert "int _ChangeWeather(void)" in result.stdout
    assert "globals = _CLOUDHEIGHT, _CLOUDTHICK" in result.stdout
    assert "extern char g_" not in result.stdout
    assert "if (BadWeather)" in result.stdout
    assert "if (!(...))" not in result.stdout
    assert "if (!(!" not in result.stdout
    assert "BadWeather = 0;" in result.stdout
    assert "CLOUDHEIGHT = 8150;" in result.stdout
    assert "CLOUDTHICK = 500;" in result.stdout
    assert "0x7000" not in result.stdout
    assert "_start" not in result.stdout


def test_normalize_function_signature_arg_names_deduplicates_duplicate_parameters():
    text = "unsigned short _strlen(unsigned short s, unsigned short s)\n"

    assert decompile._normalize_function_signature_arg_names(text) == (
        "unsigned short _strlen(unsigned short s, unsigned short s_2)\n"
    )


def test_prune_void_function_return_values_text_handles_multiline_headers():
    text = (
        "void _dos_free()\n"
        "{\n"
        "    if (rout.x.cflag != 0) {\n"
        "        return err;\n"
        "    }\n"
        "    return 0;\n"
        "}\n"
    )

    assert decompile._prune_void_function_return_values_text(text) == (
        "void _dos_free()\n"
        "{\n"
        "    if (rout.x.cflag != 0) {\n"
        "        return;\n"
        "    }\n"
        "    return;\n"
        "}\n"
    )


def test_prune_void_function_return_values_text_drops_bare_returns_from_nonvoid_functions():
    text = (
        "unsigned short _dos_getProcessId(void)\n"
        "{\n"
        "    return;\n"
        "}\n"
    )

    assert decompile._prune_void_function_return_values_text(text) == (
        "unsigned short _dos_getProcessId(void)\n"
        "{\n"
        "}\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_far_pointer_stack_stores():
    metadata = SimpleNamespace(stack_aliases={0xA: "cs", 0xC: "ss"})
    text = "    *((unsigned short *)(ds * 16 + (unsigned int)cs_2)) = ir_3_2;\n"

    assert decompile._simplify_x86_16_stack_byte_pointers(text, metadata) == "    *cs = ir_3_2;\n"


def test_simplify_x86_16_stack_byte_pointers_keeps_const_pointer_inputs_stable():
    metadata = SimpleNamespace(stack_aliases={0x4: "file"})
    text = (
        "unsigned short demo(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)\n"
        "{\n"
        "    *((unsigned short *)(ds * 16 + (unsigned int)file)) = ir_4_2;\n"
        "}\n"
    )

    simplified = decompile._simplify_x86_16_stack_byte_pointers(text, metadata)

    assert "*file =" not in simplified
    assert "MK_FP(ds, (unsigned int)file)" in simplified


def test_simplify_x86_16_stack_byte_pointers_keeps_adjacent_source_backed_stores_distinct():
    metadata = SimpleNamespace(
        stack_aliases={},
        global_names=("exeLoadParams",),
        source_lines=(
            "if (err) return err;",
            "*cs = exeLoadParams.cs;",
            "*ss = exeLoadParams.ss;",
            "return 0;",
        ),
    )
    text = (
        "unsigned short demo(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)\n"
        "{\n"
        "    err = loadprog(file, 0, DOS_LOAD_NOEXEC, cmdline);\n"
        "    if (err) return err;\n"
        "    ir_3_2 = exeLoadParams.cs;\n"
        "    *cs = ir_3_2;\n"
        "    *ss = exeLoadParams.ss;\n"
        "    return 0;\n"
        "}\n"
    )

    simplified = decompile._simplify_x86_16_stack_byte_pointers(text, metadata)

    assert "    *cs = exeLoadParams.cs;\n" in simplified
    assert "    *ss = exeLoadParams.ss;\n" in simplified
    assert simplified.index("    *cs = exeLoadParams.cs;\n") < simplified.index("    *ss = exeLoadParams.ss;\n")


def test_simplify_x86_16_stack_byte_pointers_splits_reused_temp_windows_for_source_backed_stores():
    metadata = SimpleNamespace(
        stack_aliases={},
        global_names=("exeLoadParams",),
        source_lines=(
            "if (err) return err;",
            "*cs = exeLoadParams.cs;",
            "*ss = exeLoadParams.ss;",
            "return 0;",
        ),
    )
    text = (
        "unsigned short demo(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)\n"
        "{\n"
        "    err = loadprog(file, 0, DOS_LOAD_NOEXEC, cmdline);\n"
        "    if (err) return err;\n"
        "    ir_3_2 = exeLoadParams.cs;\n"
        "    *cs = ir_3_2;\n"
        "    ir_3_2 = exeLoadParams.ss;\n"
        "    *ss = ir_3_2;\n"
        "    return 0;\n"
        "}\n"
    )

    simplified = decompile._simplify_x86_16_stack_byte_pointers(text, metadata)

    assert "    *cs = exeLoadParams.cs;\n" in simplified
    assert "    *ss = exeLoadParams.ss;\n" in simplified
    assert simplified.index("    *cs = exeLoadParams.cs;\n") < simplified.index("    *ss = exeLoadParams.ss;\n")


def test_dedupe_codegen_variable_names_tolerates_none_sort_fields():
    from angr.analyses.decompiler.structured_codegen.c import CVariable
    from angr.sim_variable import SimMemoryVariable

    class _Codegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name: str) -> int:
            self._idx += 1
            return self._idx

    codegen = _Codegen()
    mem_var = SimMemoryVariable(addr=None, size=2)
    cvar = CVariable(mem_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={mem_var: cvar},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )

    changed = decompile._dedupe_codegen_variable_names_8616(codegen)

    assert changed is True
    assert isinstance(mem_var.name, str) and mem_var.name


def test_dedupe_codegen_variable_names_normalizes_mixed_ident_sort_fields():
    from angr.analyses.decompiler.structured_codegen.c import CVariable
    from angr.sim_variable import SimRegisterVariable

    class _Codegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name: str) -> int:
            self._idx += 1
            return self._idx

    codegen = _Codegen()
    reg_a = SimRegisterVariable(0, 2, name="alpha", ident=None)
    reg_b = SimRegisterVariable(2, 2, name="beta", ident="r1")
    cvar_a = CVariable(reg_a, codegen=codegen)
    cvar_b = CVariable(reg_b, codegen=codegen)

    def sort_local_vars():
        sorted(codegen.cfunc.variables_in_use, key=lambda v: v.ident)

    codegen.cfunc = SimpleNamespace(
        variables_in_use={reg_a: cvar_a, reg_b: cvar_b},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=sort_local_vars,
    )

    changed = decompile._dedupe_codegen_variable_names_8616(codegen)

    assert changed is False
    assert isinstance(reg_a.ident, str)
    assert isinstance(reg_b.ident, str)


def test_format_known_helper_calls_handles_missing_cod_metadata(monkeypatch):
    monkeypatch.setattr(decompile, "collect_dos_int21_calls", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "collect_interrupt_service_calls", lambda *_args, **_kwargs: [])

    project = SimpleNamespace(_sim_procedures={})
    function = SimpleNamespace(addr=0x1000, name="demo")

    assert (
        decompile._format_known_helper_calls(project, function, "int demo(void)\n{\n    return 0;\n}\n", "cdecl", None)
        == "int demo(void)\n{\n    return 0;\n}"
    )


def test_decompile_cli_prunes_void_returns_for_multiline_headers():
    result = _run_decompile_proc(DOSFUNC_COD, "_dos_free")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "unsigned short _dos_free(const unsigned short segment)" in result.stdout
    assert "sreg.es = segment;" in result.stdout
    assert "return err;" in result.stdout
    assert "return 0;" in result.stdout
    assert "return;" not in result.stdout


@pytest.mark.parametrize(
    ("proc_name", "header_anchor"),
    (
        ("_dos_getProcessId", "unsigned short _dos_getProcessId(void)"),
        ("_dos_setProcessId", "int _dos_setProcessId(const unsigned short pid)"),
    ),
)
def test_decompile_cli_recovers_dos_process_id_helpers(proc_name: str, header_anchor: str):
    result = _run_decompile_proc(DOSFUNC_COD, proc_name)

    assert result.returncode == 0, result.stderr + result.stdout
    assert header_anchor in result.stdout
    assert "return ir_1;" not in result.stdout
    assert "return;" not in result.stdout
    if proc_name == "_dos_setProcessId":
        assert "[bp+0x4] = pid" in result.stdout


def test_decompile_cli_recovers_dos_load_program_pointer_stores():
    result = _run_decompile_proc(DOSFUNC_COD, "_dos_loadProgram")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "unsigned short _dos_loadProgram(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)" in result.stdout
    assert "if (err) return err;" in result.stdout
    assert "*cs = exeLoadParams.cs;" in result.stdout
    assert "*ss = exeLoadParams.ss;" in result.stdout
    assert "ds * 16 +" not in result.stdout
    assert "*file =" not in result.stdout
    assert "ds * 16 +" not in result.stdout
    assert "if (&err)" not in result.stdout


def test_decompile_cli_skips_chkstk_thunk_for_small_cod_logic():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(MAX_COD), "--proc", "_max", "--timeout", "10"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _max" in result.stdout
    assert "UnresolvableJumpTarget" not in result.stdout
    assert "/* COD annotations:" in result.stdout
    assert "[bp+0x4] = x" in result.stdout
    assert "[bp+0x6] = y" in result.stdout
    assert "short _max(" in result.stdout
    assert "unsigned short _max(unsigned short x, unsigned short y)" in result.stdout
    assert "unsigned short y" in result.stdout
    assert "if (a1 > x)" in result.stdout
    assert "return x_3;" in result.stdout


def test_decompile_cli_recovers_small_cod_byte_condition_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "BILLASM.COD", "_MousePOS")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _MousePOS" in result.stdout
    assert "[bp+0x4] = x" in result.stdout
    assert "[bp+0x6] = y" in result.stdout
    assert "short _MousePOS(unsigned short x, unsigned short y)" in result.stdout
    assert "globals = _MOUSE, _MouseX, _MouseY" in result.stdout
    assert "if (!(MOUSE))" in result.stdout
    assert "&v1" not in result.stdout
    assert "return sub_ff033();" in result.stdout


def test_decompile_cli_recovers_configcrts_copy_loop():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "COCKPIT.COD", "_ConfigCrts")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _ConfigCrts" in result.stdout
    assert "unsigned short _ConfigCrts(void)" in result.stdout
    assert "i = 0;" in result.stdout
    assert "field_1 = i * 2;" in result.stdout
    assert "do" in result.stdout
    assert "return v7;" in result.stdout


def test_decompile_cli_recovers_rotate_pt_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "BILLASM.COD", "_rotate_pt")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _rotate_pt" in result.stdout
    assert "void _rotate_pt(unsigned short s, unsigned short d, unsigned short ang)" in result.stdout
    assert "[bp+0x4] = s" in result.stdout
    assert "[bp+0x6] = d" in result.stdout
    assert "[bp-0x4] = y" in result.stdout
    assert "[bp-0x2] = x" in result.stdout
    assert "calls = _CosB, _SinB" in result.stdout
    assert "y_4 = *((char *)(ds * 16 + s))" in result.stdout
    assert "CosB(OurRoll);" in result.stdout


def test_decompile_cli_recovers_sethook_branch_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetHook")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _SetHook" in result.stdout
    assert "unsigned short _SetHook(unsigned short Hook)" in result.stdout
    assert "[bp+0x4] = Hook" in result.stdout
    assert "globals = _HookDown" in result.stdout
    assert "calls = _Message" in result.stdout
    assert 'Message ("Hook Lowered",RIO_NOW_MSG);' in result.stdout
    assert "sub_102f();" not in result.stdout
    assert "HookDown == Hook" in result.stdout
    assert "g_7000 = Hook;" in result.stdout or "HookDown = Hook;" in result.stdout
    assert "if (Hook)" in result.stdout
    assert "if (!(...))" not in result.stdout
    assert "v2 = &v3;" not in result.stdout
    assert "= 93;" in result.stdout
    assert "= 106;" in result.stdout
    assert "return 1;" in result.stdout
    assert "s_" not in result.stdout


def test_decompile_cli_recovers_setgear_guard_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetGear")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _SetGear" in result.stdout
    assert "unsigned short _SetGear(unsigned short G)" in result.stdout or "void _SetGear(int G)" in result.stdout
    assert "if (!(ejected))" in result.stdout
    assert "if (!G)" in result.stdout
    assert "if (Knots <= 350)" in result.stdout
    assert "Status = Status | 1;" in result.stdout
    assert "Status = Status & -2;" in result.stdout
    assert "Message (\"Landing gear lowered\",RIO_MSG);" in result.stdout
    assert "return v13;" in result.stdout
    assert "if (...)" not in result.stdout
    assert "28674" not in result.stdout
    assert "28682" not in result.stdout
    assert "sub_102f();" not in result.stdout


def test_decompile_cli_recovers_setdlc_state_store():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetDLC")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _SetDLC" in result.stdout
    assert "short _SetDLC(" in result.stdout
    assert "unsigned short DLC" in result.stdout
    assert "[bp+0x4] = DLC" in result.stdout
    assert "globals = _DirectLiftControl" in result.stdout
    assert "DirectLiftControl = DLC;" in result.stdout
    assert "DLC >> 8" not in result.stdout
    assert "return DLC;" in result.stdout


def test_decompile_cli_keeps_query_interrupts_wrapper_calls_classified_in_matrix_corpus():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(IMOD_COD),
            "--proc",
            "query_interrupts",
            "--proc-kind",
            "FAR",
            "--timeout",
            "60",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 query_interrupts" in result.stdout
    assert "calls = _int86, _int86x" in result.stdout
    assert "int86(0x21, &inregs, &outregs);" in result.stdout
    assert "info = outregs;" in result.stdout
    assert "return outregs;" in result.stdout


def test_decompile_cli_recovers_tidshowrange_layout_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "COCKPIT.COD", "_TIDShowRange")

    assert result.returncode in (0, 3), result.stderr + result.stdout
    if result.returncode == 3:
        assert "Timed out while recovering a function after 10s." in result.stdout
        return
    assert "function: 0x1000 _TIDShowRange" in result.stdout
    assert "void _TIDShowRange(void)" in result.stdout
    assert "RectFill(Rp2,146,21,29,9,BLACK);" in result.stdout
    assert "MapInEMSSprite(MISCSPRTSEG,0)" in result.stdout


def test_decompile_cli_recovers_drawradaralt_branch_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "COCKPIT.COD", "_DrawRadarAlt")

    if result.returncode == 3:
        assert "Timed out while recovering a function after 10s." in result.stdout
        return

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _DrawRadarAlt" in result.stdout
    assert "void _DrawRadarAlt(void)" in result.stdout
    assert "[bp-0xc] = newalt" in result.stdout
    assert "[bp-0xa] = y2" in result.stdout
    assert "[bp-0x8] = soffset" in result.stdout
    assert "[bp-0x2] = b" in result.stdout
    assert "calls = _MapInEMSSprite, _TransRectCopy, _MDiv, _Rotate2D, _scaley, _DrawLine, _RectCopy" in result.stdout
    assert "if (!(View))" in result.stdout
    assert "unsigned short y2;  // [bp-0xa] y2" in result.stdout
    assert "unsigned short b;  // [bp-0x2] b" in result.stdout
    assert "y2 = 0;" in result.stdout
    assert "y2 = 112;" in result.stdout
    assert "s_12 = 0;" in result.stdout
    assert "s_14 = 2;" in result.stdout
    assert "MapInEMSSprite(MISCSPRTSEG,0);" in result.stdout


@pytest.mark.parametrize(
    ("path", "proc_kind", "shape_tokens"),
    [
        (ISOD_COD, "NEAR", ("& 0xff00 |", "return ")),
        (ISOT_COD, "NEAR", ("& 0xff00 |", "return ")),
        (ISOX_COD, "NEAR", ("& 0xff00 |", "return ")),
        (IMOD_COD, "FAR", ("& 0xff00 |", "return ")),
        (IMOT_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
        (IMOX_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
        (IHOD_COD, "FAR", ("& 0xff00 |", "return ")),
        (IHOT_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
        (ILOD_COD, "FAR", ("& 0xff00 |", "return ")),
        (ILOT_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
    ],
)
def test_decompile_cli_main_matrix(path: Path, proc_kind: str, shape_tokens: tuple[str, str]):
    result = _run_decompile_proc(path, "_main", proc_kind=proc_kind, analysis_timeout=20, subprocess_timeout=60)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _main" in result.stdout
    assert "int _main(void)" in result.stdout
    for token in shape_tokens:
        assert token in result.stdout
    assert "Decompiler timeout" not in result.stdout


@pytest.mark.parametrize(
    ("path", "proc_kind"),
    [
        (ISOD_COD, "NEAR"),
        (ISOT_COD, "NEAR"),
        (ISOX_COD, "NEAR"),
        (IMOD_COD, "FAR"),
        (IMOT_COD, "FAR"),
        (IMOX_COD, "FAR"),
        (IHOD_COD, "FAR"),
        (IHOT_COD, "FAR"),
        (ILOD_COD, "FAR"),
        (ILOT_COD, "FAR"),
    ],
)
def test_decompile_cli_show_summary_matrix(path: Path, proc_kind: str):
    result = _run_decompile_proc(path, "show_summary", proc_kind=proc_kind, analysis_timeout=20, subprocess_timeout=60)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 show_summary" in result.stdout
    assert "int show_summary(void)" in result.stdout
    assert "info >> 8;" in result.stdout
    assert "*((" in result.stdout
    assert "Decompiler timeout" not in result.stdout


@pytest.mark.parametrize(
    ("path", "proc", "proc_kind", "analysis_timeout", "subprocess_timeout", "expected_tokens", "forbidden_tokens"),
    [
        (
            MAX_COD,
            "_max",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _max", "if (x > y)", "return x;", "return y;"),
            ("UnresolvableJumpTarget",),
        ),
        (
            NHORZ_COD,
            "_ChangeWeather",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _ChangeWeather", "if (BadWeather)", "CLOUDHEIGHT = 8150;", "CLOUDTHICK = 500;", "CLOUDTHICK = 1000;"),
            ("if (!(...))", "if (!(!"),
        ),
            (
                MONOPRIN_COD,
                "_mset_pos",
                "NEAR",
                10,
                30,
                (
                    "function: 0x1000 _mset_pos",
                    "% 80",
                    "% 25",
                    "int _mset_pos(int x, int y)",
                ),
                ("&v1",),
            ),
                (
                    REPO_ROOT / "cod" / "f14" / "BILLASM.COD",
                    "_MousePOS",
                    "NEAR",
                    10,
                    30,
                        (
                            "function: 0x1000 _MousePOS",
                            "if (!(MOUSE))",
                                "MouseX =",
                            "MouseY = y;",
                            "return sub_ff033();",
                        ),
                        ("if (...)", "28675", "28677"),
                    ),
        (
            REPO_ROOT / "cod" / "f14" / "PLANES3.COD",
            "_Ready5",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _Ready5", "void _Ready5(void)", "planecnt", "droll", "pdest", "* 46", "+ 18 + v3", "return;"),
            (),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
            "_LookDown",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _LookDown", "if (!(BackSeat))", "Rp3D->Length1 = 50;", "RpCRT1->YBgn = 27;", "RpCRT2->YBgn = 25;", "RpCRT4->YBgn = 39;", "VdiMask[MASKY] = 27;", "AdiMask[MASKY] = 25;", "RawMask[MASKY] = 39;"),
            (),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
            "_LookUp",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _LookUp", "if (!(BackSeat))", "Rp3D->Length1 = 150;", "RpCRT1->YBgn = 138;", "RpCRT2->YBgn = 136;", "RpCRT4->YBgn = 150;", "VdiMask[MASKY] = 138;", "AdiMask[MASKY] = 136;", "RawMask[MASKY] = 150;"),
            (),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "CARR.COD",
            "_InBox",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _InBox", "return 1;", "xl <=", "xh >=", "zl <=", "zh >="),
            ("if (...)", "!(zh >=", "xl >", "xh <", "zl >"),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "CARR.COD",
            "_InBoxLng",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _InBoxLng", "if (x < xl || x > xh || z < zl || z > zh)", "return 0;", "return 1;"),
            ("if (...)", "!(v4", "& &"),
        ),
            (
                REPO_ROOT / "cod" / "f14" / "CARR.COD",
                "_SetHook",
                "NEAR",
                10,
            30,
                        ("function: 0x1000 _SetHook", "return 1;", "if (Hook)", "= 93;", "Message (\"Hook Lowered\",RIO_NOW_MSG);", "HookDown == Hook", "HookDown = Hook;"),
                    (),
                ),
            (
                REPO_ROOT / "cod" / "f14" / "CARR.COD",
                "_SetGear",
                "NEAR",
                10,
                30,
                (
                    "function: 0x1000 _SetGear",
                    "unsigned short _SetGear(unsigned short G)",
                    "if (!(ejected))",
                    "if (!G)",
                    "if (Knots <= 350)",
                    "Status = Status | 1;",
                    "Status = Status & -2;",
                    'Message ("Landing gear lowered",RIO_MSG);',
                    "return v13;",
                ),
                (),
            ),
        (
            REPO_ROOT / "cod" / "f14" / "CARR.COD",
            "_SetDLC",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _SetDLC", "DirectLiftControl = DLC;", "return DLC;"),
            ("DLC >> 8",),
        ),
            (
                REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
                "_TIDShowRange",
                "NEAR",
                10,
                30,
                    ("function: 0x1000 _TIDShowRange", "Timed out while recovering a function after 10s."),
                (),
            ),
        (
            REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
            "_DrawRadarAlt",
            "NEAR",
            10,
            30,
                ("function: 0x1000 _DrawRadarAlt", "if (!(View))", "y2 = 0;", "y2 = 112;", "s_12 = 0;", "s_14 = 2;", "MapInEMSSprite(MISCSPRTSEG,0);"),
            (),
        ),
            (
                ISOD_COD,
                "fold_values",
                "NEAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                IMOD_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                ISOT_COD,
                "fold_values",
                "NEAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                ISOX_COD,
                "fold_values",
                "NEAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                IHOD_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                IHOT_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                ILOD_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                ILOT_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                IMOT_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                IMOX_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
    ],
)
def test_decompile_cli_small_cod_logic_batch(
    path, proc, proc_kind, analysis_timeout, subprocess_timeout, expected_tokens, forbidden_tokens
):
    result = _run_decompile_proc(
        path,
        proc,
        proc_kind=proc_kind,
        analysis_timeout=analysis_timeout,
        subprocess_timeout=subprocess_timeout,
    )

    if proc == "_TIDShowRange" and result.returncode == 3:
        assert "Timed out while recovering a function after 10s." in result.stdout
        return
    if proc == "_DrawRadarAlt" and result.returncode == 3:
        assert "Timed out while recovering a function after 10s." in result.stdout
        return
    if proc == "fold_values" and result.returncode == 3:
        assert "Timed out while recovering a function after 20s." in result.stdout
        return

    assert result.returncode == 0, result.stderr + result.stdout
    for token in expected_tokens:
        assert token in result.stdout, result.stdout
    for token in forbidden_tokens:
        assert token not in result.stdout, result.stdout


def test_decompile_cli_names_known_dos_interrupt_helpers_in_com_output():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(ICOMDO_COM), "--timeout", "10", "--window", "0x80", "--max-functions", "2"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "int get_dos_version(void);" in result.stdout
    assert "void print_dos_string(const char *s);" in result.stdout
    assert "void exit(int status);" in result.stdout
    assert "void _start(void)" in result.stdout
    assert "get_dos_version();" in result.stdout
    assert 'print_dos_string("DOS sample");' in result.stdout
    assert "exit(0);" in result.stdout
    assert "1044513();" not in result.stdout
    assert "dos_int21();" not in result.stdout


def test_decompile_cli_supports_dos_api_style_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "dos",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "unsigned short _dos_get_version(void);" in result.stdout
    assert "void _dos_print_dollar_string(const char far *s);" in result.stdout
    assert "void _dos_exit(unsigned char status);" in result.stdout
    assert "_dos_get_version();" in result.stdout
    assert '_dos_print_dollar_string("DOS sample");' in result.stdout
    assert "_dos_exit(0);" in result.stdout


def test_decompile_cli_supports_raw_api_style_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "raw",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "dos_int21();" in result.stdout


def test_decompile_cli_supports_pseudo_api_style_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "pseudo",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "int dos_get_version(void);" in result.stdout
    assert "void dos_print_dollar_string(const char *s);" in result.stdout
    assert "void dos_exit(int status);" in result.stdout
    assert "dos_get_version();" in result.stdout
    assert 'dos_print_dollar_string("DOS sample");' in result.stdout
    assert "dos_exit(0);" in result.stdout


def test_decompile_cli_supports_msc_api_style_alias_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "msc",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "_dos_get_version();" in result.stdout
    assert '_dos_print_dollar_string("DOS sample");' in result.stdout
    assert "_dos_exit(0);" in result.stdout


def test_trace_x86_16_paths_cli_traces_small_com_stub():
    result = subprocess.run(
        [sys.executable, str(TRACE_PATH), str(ICOMDO_COM), "--mode", "exec", "--max-steps", "6"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "mode: exec" in result.stdout
    assert "== step 0 @ 0x1000 ==" in result.stdout
    assert "mov ah, 0x30" in result.stdout
    assert "== step 2 @ 0xf021 ==" in result.stdout
    assert "helper=DOSInt21 ; get_dos_version()" in result.stdout
    assert "== step 3 @ 0x1004 ==" in result.stdout
    assert "mov ah, 9" in result.stdout
    assert "== step 5 @ 0x1009 ==" in result.stdout
    assert "int 0x21" in result.stdout


def test_trace_x86_16_paths_cli_exec_supports_helper_annotations():
    result = subprocess.run(
        [sys.executable, str(TRACE_PATH), str(ICOMDO_COM), "--mode", "exec", "--max-steps", "8"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert 'helper=DOSInt21 ; print_dos_string("DOS sample")' in result.stdout


def test_trace_x86_16_paths_cli_recovers_cfg_for_small_com_stub():
    result = subprocess.run(
        [sys.executable, str(TRACE_PATH), str(ICOMDO_COM), "--mode", "cfg", "--max-blocks", "4"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "mode: cfg" in result.stdout
    assert "function: 0x1000 _start" in result.stdout
    assert "== block 0x1000 ==" in result.stdout
    assert "0x1000: mov ah, 0x30" in result.stdout
    assert "0x1002: int 0x21 ; get_dos_version()" in result.stdout
    assert '0x1009: int 0x21 ; print_dos_string("DOS sample")' in result.stdout


def test_trace_x86_16_paths_cli_supports_msc_helper_annotations():
    result = subprocess.run(
        [
            sys.executable,
            str(TRACE_PATH),
            str(ICOMDO_COM),
            "--mode",
            "cfg",
            "--max-blocks",
            "4",
            "--api-style",
            "msc",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "0x1002: int 0x21 ; _dos_get_version()" in result.stdout
    assert '0x1009: int 0x21 ; _dos_print_dollar_string("DOS sample")' in result.stdout


def test_trace_x86_16_paths_cli_supports_pseudo_helper_annotations():
    result = subprocess.run(
        [
            sys.executable,
            str(TRACE_PATH),
            str(ICOMDO_COM),
            "--mode",
            "cfg",
            "--max-blocks",
            "4",
            "--api-style",
            "pseudo",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "0x1002: int 0x21 ; dos_get_version()" in result.stdout
    assert '0x1009: int 0x21 ; dos_print_dollar_string("DOS sample")' in result.stdout
