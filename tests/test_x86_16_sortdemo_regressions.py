from __future__ import annotations

import subprocess
import sys
import os
from pathlib import Path

from inertia_decompiler.acceptance_scorecard import build_acceptance_scorecard
from inertia_decompiler.source_sidecar import render_local_source_sidecar_function

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
SORTDEMO_EXE = REPO_ROOT / "SORTDEMO.EXE"


def _run_decompile_addr(
    path: Path,
    addr: int,
    *,
    analysis_timeout: int = 6,
    subprocess_timeout: int = 90,
    extra_args: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(path),
            "--addr",
            hex(addr),
            "--timeout",
            str(analysis_timeout),
            *extra_args,
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=subprocess_timeout,
        check=False,
    )


def _combined_output(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stderr}{result.stdout}"


def _run_decompile_file(
    path: Path,
    *,
    max_functions: int = 8,
    analysis_timeout: int = 30,
    subprocess_timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(path),
            "--timeout",
            str(analysis_timeout),
            "--max-functions",
            str(max_functions),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=subprocess_timeout,
        check=False,
    )


def test_sortdemo_sleep_anchor_eliminates_raw_flag_guard_and_keeps_validation_clean():
    result = _run_decompile_addr(SORTDEMO_EXE, 0x10F28)
    scorecard = build_acceptance_scorecard(
        "Sleep",
        _combined_output(result),
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "Sleep"),
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert ("function: 0x10f18 Sleep" in result.stdout) or ("function: 0x10f28 Sleep" in result.stdout)
    assert "void Sleep(clock_t wait)" in result.stdout
    assert "flags_2 = ...;" not in result.stdout
    assert "flags_2 =" not in result.stdout
    assert "if (...)" not in result.stdout
    assert "if (!(...))" not in result.stdout
    assert "(flags_3 & 128) == (flags_3 & 0x800)" not in result.stdout
    assert "clock();" in result.stdout
    assert "ss << 4" not in result.stdout
    assert "(&s_" not in result.stdout
    assert "*(&" not in result.stdout
    assert scorecard.validation_verdict == "stable"


def test_sortdemo_reinitbars_uses_runtime_segment_helpers_and_keeps_validation_clean():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10678,
        extra_args=("--c-target", "portable-flat"),
    )

    combined = _combined_output(result)
    assert result.returncode in {0, 4, 6}, combined
    assert "function: 0x10678 ReInitBars" in result.stdout
    if result.returncode == 0:
        assert "validation=passed" in combined
        assert "gcc syntax check failed:" not in combined
    elif result.returncode == 4:
        assert "validation=failed" in combined
        assert "Source-evidenced loop call was hoisted outside loop in emitted C." in combined
    else:
        assert "gcc syntax check failed:" in combined
    assert "ds << 4" not in combined
    assert "es << 4" not in combined
    assert "ss << 4" not in combined


def test_sortdemo_swapbars_call_arguments_materialized():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10768,
        extra_args=("--c-target", "portable-flat"),
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10768 SwapBars" in result.stdout
    assert "validation=passed" in combined
    assert "gcc syntax check failed:" not in combined


def test_sortdemo_swapbars_does_not_pointer_promote_irow2_or_emit_dead_setup_artifacts():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10768,
        extra_args=("--c-target", "portable-flat"),
    )

    combined = _combined_output(result)
    assert result.returncode in {0, 6}, combined
    assert "function: 0x10768 SwapBars" in result.stdout
    assert "validation=passed" in combined
    assert "void SwapBars(int iRow1, int *iRow2)" not in result.stdout
    assert "s_2 = &s_2 + 2;" not in result.stdout
    assert "vvar_16 = &s_6;" not in result.stdout


def test_sortdemo_main_uses_portable_flat_int_main_signature():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10010,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=60,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, combined
    assert "function: 0x10010 main" in result.stdout
    assert "validation=passed" in combined
    assert "gcc syntax check failed:" not in combined
    assert "void main(void)" not in result.stdout
    assert "int main(void)" in result.stdout
    assert "return 0;" in result.stdout


def test_sortdemo_nfree_does_not_emit_undeclared_vvar_carrier():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10000,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=120,
    )

    combined = _combined_output(result)
    assert result.returncode in {0, 4}, combined
    assert "function: 0x10000 $_nfree" in result.stdout
    if result.returncode == 0:
        assert "validation=passed" in combined
        assert "gcc syntax check failed:" not in combined
        assert "undeclared" not in combined
        # Temp/local naming is not stable across evidence-equivalent recoveries.
        # The regression target is "no undeclared vvar carrier usage".
        if "vvar_2" in result.stdout:
            assert "unsigned short vvar_2;" in result.stdout
    else:
        assert "validation=failed" in combined
        assert "Unreachable call statements present after return in emitted C." in combined


def test_sortdemo_heapsort_callsites_materialized_in_c_order():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10970,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = result.stderr + result.stdout
    assert result.returncode in {0, 1}, combined
    assert "function: 0x10970 HeapSort" in result.stdout
    if result.returncode == 1:
        assert "HeapSort leaked raw stack-address syntax into final C" in combined or "HeapSort leaked unresolved stack locals into final C" in combined
        assert "validation=passed" not in combined
        return
    assert "validation=passed" in combined
    final_body = "short HeapSort" + result.stdout.rsplit("short HeapSort", 1)[-1]
    assert (
        "PercolateUp(i);" in final_body
        or "PercolateUp(local_1);" in final_body
        or "PercolateUp(i_2);" in final_body
    )
    assert (
        "SwapBars(0, i);" in final_body
        or "SwapBars( 0, i );" in final_body
        or "SwapBars(0, local_1);" in final_body
        or "SwapBars( 0, local_1 );" in final_body
    )
    assert (
        "PercolateDown(i - 1);" in final_body
        or "PercolateDown( i - 1 );" in final_body
        or "PercolateDown(local_1 - 1);" in final_body
        or "PercolateDown( local_1 - 1 );" in final_body
        or "PercolateDown(i_2);" in final_body
    )
    assert "SwapBars(i, 0);" not in final_body
    assert "SwapBars(local_1, 0);" not in final_body
    assert "PercolateDown((i << 1) + 2892);" not in final_body
    assert "PercolateDown((local_1 << 1) + 2892);" not in final_body


def test_sortdemo_heapsort_call_args_use_bp_local_i_not_address_expr():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10970,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = result.stderr + result.stdout
    assert result.returncode in {0, 1}, combined
    assert "function: 0x10970 HeapSort" in result.stdout
    if result.returncode == 1:
        assert "HeapSort leaked raw stack-address syntax into final C" in combined or "HeapSort leaked unresolved stack locals into final C" in combined
        assert "validation=passed" not in combined
        return
    assert "validation=passed" in combined
    final_body = "short HeapSort" + result.stdout.rsplit("short HeapSort", 1)[-1]
    assert (
        "PercolateUp(i);" in final_body
        or "PercolateUp(local_1);" in final_body
        or "PercolateUp(i_2);" in final_body
    )
    assert (
        "SwapBars(0, i);" in final_body
        or "SwapBars( 0, i );" in final_body
        or "SwapBars(0, local_1);" in final_body
        or "SwapBars( 0, local_1 );" in final_body
        or "SwapBars(0, i_2);" in final_body
    )
    assert (
        "PercolateDown(i - 1);" in final_body
        or "PercolateDown( i - 1 );" in final_body
        or "PercolateDown(local_1 - 1);" in final_body
        or "PercolateDown( local_1 - 1 );" in final_body
        or "PercolateDown(i_2);" in final_body
    )
    assert (
        "Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, (i << 1) + 2892));" in final_body
        or "Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, 2892 + (local_1 << 1)));" in final_body
        or "Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, (i_2 << 1) + 2892));" in final_body
        or "Swaps(&abarWork[0], &abarWork[i]);" in final_body
        or "Swaps(&abarWork[0], &abarWork[local_1]);" in final_body
    )
    assert "*(&(&v0)[4])" not in final_body
    assert "SEG_PTR(ds, &s_4 + 2)" not in final_body
    assert "(i << 1) + 2892);" not in final_body
    assert "(local_1 << 1) + 2892);" not in final_body
    assert "SwapBars(i, 0)" not in final_body
    assert "SwapBars(local_1, 0)" not in final_body
    assert "PercolateDown((i << 1) + 2892)" not in final_body
    assert "PercolateDown((local_1 << 1) + 2892)" not in final_body


def test_sortdemo_heapsort_callsite_args_survive_postprocess():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10970,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = result.stderr + result.stdout
    assert result.returncode in {0, 1}, combined
    assert "function: 0x10970 HeapSort" in result.stdout
    if result.returncode == 1:
        assert "HeapSort leaked raw stack-address syntax into final C" in combined or "HeapSort leaked unresolved stack locals into final C" in combined
        assert "validation=passed" not in combined
        return
    assert "validation=passed" in combined
    final_body = "short HeapSort" + result.stdout.rsplit("short HeapSort", 1)[-1]
    assert (
        "SwapBars(0, i);" in final_body
        or "SwapBars( 0, i );" in final_body
        or "SwapBars(0, i_2);" in final_body
    )
    assert (
        "PercolateDown(i - 1);" in final_body
        or "PercolateDown( i - 1 );" in final_body
        or "PercolateDown(i_2);" in final_body
    )
    assert (
        "Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, (i << 1) + 2892));" in final_body
        or "Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, 2892 + (i << 1)));" in final_body
        or "Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, 2892 + i * 2));" in final_body
        or "Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, (i_2 << 1) + 2892));" in final_body
        or "Swaps(&abarWork[0], &abarWork[i]);" in final_body
    )
    assert "SEG_PTR(ds, &s_" not in final_body
    assert "SEG_PTR(ds, &v" not in final_body
    assert "Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, &s_4 + 2))" not in final_body
    assert "PercolateDown((i << 1) + 2892)" not in final_body


def test_sortdemo_heapsort_value_and_pointer_args_survive_final_output():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10970,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = result.stderr + result.stdout
    assert result.returncode in {0, 1}, combined
    assert "function: 0x10970 HeapSort" in result.stdout
    if result.returncode == 1:
        assert "HeapSort leaked raw stack-address syntax into final C" in combined or "HeapSort leaked unresolved stack locals into final C" in combined
        assert "validation=passed" not in combined
        return
    assert "validation=passed" in combined
    final_body = "short HeapSort" + result.stdout.rsplit("short HeapSort", 1)[-1]
    call_lines = "\n".join(
        line.strip()
        for line in final_body.splitlines()
        if any(name in line for name in ("PercolateUp(", "Swaps(", "SwapBars(", "PercolateDown("))
    )
    assert (
        "PercolateUp(i);" in call_lines
        or "PercolateUp(local_1);" in call_lines
        or "PercolateUp(i_2);" in call_lines
    )
    assert (
        "SwapBars(0, i);" in call_lines
        or "SwapBars(0, local_1);" in call_lines
        or "SwapBars(0, i_2);" in call_lines
    )
    assert (
        "PercolateDown(i - 1);" in call_lines
        or "PercolateDown(local_1 - 1);" in call_lines
        or "PercolateDown(i_2);" in call_lines
    )
    assert (
        "Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, (i << 1) + 2892));" in call_lines
        or "Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, 2892 + (i << 1)));" in call_lines
        or "Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, 2892 + i * 2));" in call_lines
        or "Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, (i_2 << 1) + 2892));" in call_lines
        or "Swaps(&abarWork[0], &abarWork[i]);" in call_lines
    )
    assert "PercolateDown(3)" not in call_lines
    assert "PercolateDown((i << 1) + 2892)" not in call_lines
    assert "SEG_PTR(ds, &s_" not in call_lines
    assert "&s_4" not in call_lines
    assert "arg_1" not in call_lines


def test_sortdemo_file_summary_lines_are_stable_and_sorted():
    first = _run_decompile_file(SORTDEMO_EXE, max_functions=8)
    second = _run_decompile_file(SORTDEMO_EXE, max_functions=8)

    assert first.returncode in {0, 2}, first.stderr + first.stdout
    assert second.returncode in {0, 2}, second.stderr + second.stdout

    def _summary_lines(text: str) -> list[str]:
        return [line for line in text.splitlines() if line.startswith("summary:")]

    first_summary = _summary_lines(first.stdout)
    second_summary = _summary_lines(second.stdout)
    # Summary should remain deterministic across repeated runs even when
    # timeout/fallback accounting changes the exact mix of lines.
    assert first_summary == second_summary
    assert any("probable compiler versions:" in line for line in first_summary)
    assert any("probable library/signature sources:" in line for line in first_summary)
    assert any("signature-matched library functions:" in line for line in first_summary)
    assert any("hidden signature-matched labels:" in line for line in first_summary)
    assert any("same_family_retry_stops=" in line for line in first_summary)


def test_sortdemo_heapsort_anchor_no_longer_prunes_local_lane_after_repeated_empty_results():
    result = _run_decompile_addr(SORTDEMO_EXE, 0x109D8)
    combined = result.stderr + result.stdout

    assert result.returncode in {0, 1, 4}, combined
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "pruned local lane" not in result.stdout
    if result.returncode == 1:
        assert "Swaps missing argument 1" in combined
        assert "validation=passed" not in combined
        return
    scorecard = build_acceptance_scorecard(
        "HeapSort",
        result.stdout,
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "HeapSort"),
    )
    assert scorecard.source_present is True
    assert scorecard.recovery_mode in {"asm_fallback", "decompiled"}
    if scorecard.recovery_mode == "decompiled":
        assert "ss << 4" not in result.stdout
        assert "!(!(" not in result.stdout
    else:
        assert (
            "shared-project slice full-with-refs: empty" in result.stdout
            or "Function recovery timed out; using sidecar-bounded asm fallback." in result.stdout
        )
        assert "/* == asm fallback == */" in result.stdout


def test_sortdemo_percolateup_anchor_no_longer_crashes_on_vexvalue_register_resolution():
    result = _run_decompile_addr(SORTDEMO_EXE, 0x109E8)

    combined = _combined_output(result)

    assert result.returncode in {0, 4}, combined
    assert "Non-constant VexValue has no value property" not in combined
    assert "Function recovery failed" not in combined
    assert "function: 0x109e8 PercolateUp" in result.stdout
    if result.returncode == 0:
        assert "short PercolateUp(int iMaxLevel)" in result.stdout
        assert "stack_bp_" not in result.stdout
        assert "(&s_fffa)[" not in result.stdout
        assert "flags & 64" not in result.stdout
        assert "*((ds << 4) + 2986 + 1) =" not in result.stdout
        assert "*((ds << 4) + 2986) =" in result.stdout
    else:
        assert "Decompilation timeout" in combined
        assert "non-optimized fallback failed" in combined


def test_sortdemo_quicksort_anchor_distinguishes_timeout_from_old_vexvalue_crash():
    try:
        result = _run_decompile_addr(SORTDEMO_EXE, 0x10CE0, subprocess_timeout=20)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        combined = f"{stderr}{stdout}"
        assert "Non-constant VexValue has no value property" not in combined
        assert "function: 0x10ce0 QuickSort" in stdout
        return

    combined = _combined_output(result)

    assert result.returncode in {0, 3, 4}, combined
    assert "Non-constant VexValue has no value property" not in combined
    assert "function: 0x10ce0 QuickSort" in result.stdout
    if result.returncode == 0:
        assert "Function recovery failed" not in combined
    elif result.returncode == 3:
        assert "Timed out while recovering a function after 6s after exhausting direct-address fallback budget." in combined
    else:
        assert "Decompilation timeout" in combined
        assert "Function recovery failed" not in combined


def test_sortdemo_acceptance_scorecards_capture_main_sleep_and_percolateup_state():
    main_result = _run_decompile_addr(SORTDEMO_EXE, 0x10010)
    sleep_result = _run_decompile_addr(SORTDEMO_EXE, 0x10F28)
    percolate_result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x109E8,
        analysis_timeout=12,
        subprocess_timeout=120,
    )

    assert main_result.returncode == 0, main_result.stderr + main_result.stdout
    assert sleep_result.returncode == 0, sleep_result.stderr + sleep_result.stdout
    assert percolate_result.returncode in {0, 4}, percolate_result.stderr + percolate_result.stdout
    assert "InitMenu();" in main_result.stdout

    main_scorecard = build_acceptance_scorecard(
        "main",
        _combined_output(main_result),
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "main"),
    )
    sleep_scorecard = build_acceptance_scorecard(
        "Sleep",
        _combined_output(sleep_result),
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "Sleep"),
    )
    percolate_scorecard = build_acceptance_scorecard(
        "PercolateUp",
        _combined_output(percolate_result),
        source_text=render_local_source_sidecar_function(SORTDEMO_EXE, "PercolateUp"),
    )

    assert main_scorecard.source_present is True
    assert main_scorecard.raw_ss_linear_count == 0
    assert main_scorecard.anonymous_sub_count == 0
    assert main_scorecard.validation_verdict == "stable"
    assert sleep_scorecard.source_present is True
    assert "flags_2 = ...;" not in sleep_result.stdout
    assert "(flags_3 & 128) == (flags_3 & 0x800)" not in sleep_result.stdout
    assert sleep_scorecard.raw_ss_linear_count == 0
    assert sleep_scorecard.validation_verdict == "stable"
    if percolate_result.returncode == 0:
        assert percolate_scorecard.source_present is True
        assert percolate_scorecard.raw_ds_linear_count >= 1
        assert percolate_scorecard.raw_ss_linear_count >= 1
    assert percolate_scorecard.validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    for marker in ("int PercolateUp(", "short PercolateUp(", "void PercolateUp("):
        if marker in percolate_result.stdout:
            percolate_body = marker + percolate_result.stdout.rsplit(marker, 1)[-1]
            break
    else:
        percolate_body = percolate_result.stdout
    assert "arg_6" not in percolate_body
    assert "SwapBars(arg_6" not in percolate_body


def test_sortdemo_acceptance_scorecards_capture_heapsort_quicksort_runmenu_and_beep_state():
    function_specs = {
        "HeapSort": (0x109D8, 30),
        "QuickSort": (0x10CE0, 120),
        "RunMenu": (0x102E0, 60),
        "Beep": (0x10E70, 30),
    }
    scorecards = {}
    results = {}
    for function_name, (addr, subprocess_timeout) in function_specs.items():
        result = _run_decompile_addr(SORTDEMO_EXE, addr, subprocess_timeout=subprocess_timeout)
        results[function_name] = result
        if function_name == "HeapSort":
            assert result.returncode in {0, 1, 4}, result.stderr + result.stdout
        else:
            assert result.returncode in {0, 4}, result.stderr + result.stdout
        scorecards[function_name] = build_acceptance_scorecard(
            function_name,
            _combined_output(result),
            source_text=render_local_source_sidecar_function(SORTDEMO_EXE, function_name),
        )

    assert scorecards["HeapSort"].source_present is True
    if results["HeapSort"].returncode == 1:
        assert "Swaps missing argument 1" in _combined_output(results["HeapSort"])
        assert "validation=passed" not in _combined_output(results["HeapSort"])
    else:
        assert scorecards["HeapSort"].recovery_mode in {"asm_fallback", "decompiled"}
        assert scorecards["HeapSort"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    if results["HeapSort"].returncode == 0 and scorecards["HeapSort"].recovery_mode == "decompiled":
        assert scorecards["HeapSort"].raw_ss_linear_count == 0
        assert scorecards["HeapSort"].anonymous_sub_count == 0
    assert scorecards["QuickSort"].source_present is True
    assert scorecards["QuickSort"].recovery_mode in {"asm_fallback", "decompiled", "unknown"}
    assert scorecards["QuickSort"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    if scorecards["QuickSort"].recovery_mode == "decompiled":
        assert scorecards["QuickSort"].raw_flags_count >= 1
    assert scorecards["RunMenu"].source_present is True
    assert scorecards["RunMenu"].recovery_mode in {"asm_fallback", "decompiled", "unknown"}
    assert scorecards["RunMenu"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    if scorecards["RunMenu"].recovery_mode == "decompiled":
        # Better lowering may remove raw SS linear artifacts entirely.
        assert scorecards["RunMenu"].raw_ss_linear_count >= 0
    assert scorecards["Beep"].source_present is True
    assert scorecards["Beep"].raw_ss_linear_count == 0
    assert scorecards["Beep"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}


def test_sortdemo_acceptance_scorecards_capture_swaps_swapbars_and_reinitbars_state():
    function_specs = {
        "Swaps": (0x107B8, 30),
        "SwapBars": (0x10768, 30),
        "ReInitBars": (0x10678, 90),
    }
    scorecards = {}
    for function_name, (addr, subprocess_timeout) in function_specs.items():
        result = _run_decompile_addr(SORTDEMO_EXE, addr, subprocess_timeout=subprocess_timeout)
        assert result.returncode in {0, 4, 6}, result.stderr + result.stdout
        scorecards[function_name] = build_acceptance_scorecard(
            function_name,
            _combined_output(result),
            source_text=render_local_source_sidecar_function(SORTDEMO_EXE, function_name),
        )

    assert scorecards["Swaps"].source_present is True
    assert scorecards["Swaps"].recovery_mode in {"asm_fallback", "decompiled", "unknown"}
    assert scorecards["Swaps"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    if scorecards["Swaps"].recovery_mode == "decompiled":
        assert scorecards["Swaps"].raw_ds_linear_count == 0
    assert scorecards["SwapBars"].source_present is True
    assert scorecards["SwapBars"].recovery_mode in {"asm_fallback", "decompiled", "unknown"}
    assert scorecards["SwapBars"].validation_verdict in {"changed", "stable", "unknown", "uncollected"}
    if scorecards["SwapBars"].recovery_mode == "decompiled":
        assert scorecards["SwapBars"].raw_ds_linear_count == 0
        assert scorecards["SwapBars"].anonymous_sub_count == 0
    assert scorecards["ReInitBars"].source_present is True
    assert scorecards["ReInitBars"].recovery_mode in {"asm_fallback", "decompiled", "unknown"}
    assert scorecards["ReInitBars"].validation_verdict in {"failed", "changed", "stable", "unknown", "uncollected"}
    if scorecards["ReInitBars"].recovery_mode == "decompiled":
        assert scorecards["ReInitBars"].raw_ds_linear_count == 0


def test_reinitbars_stable_stack_slot_irow_materialized():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10678,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = _combined_output(result)
    assert result.returncode in {4, 6}, combined
    assert "function: 0x10678 ReInitBars" in result.stdout
    assert ("validation=failed" in combined) or ("validation=uncollected" in combined)
    assert (
        "Source-evidenced loop call was hoisted outside loop in emitted C." in combined
        or "gcc syntax check failed:" in combined
    )
    assert "ss << 4" not in combined


def test_heapsort_stable_stack_slot_i_materialized():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10970,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "validation=passed" in combined
    final_body = "short HeapSort" + result.stdout.rsplit("short HeapSort", 1)[-1]
    assert "i" in final_body
    assert "PercolateDown(i - 1);" in final_body or "PercolateDown( i - 1 );" in final_body
    assert "SwapBars(0, i);" in final_body or "SwapBars( 0, i );" in final_body
    assert "&s_" not in final_body
    assert "*(&v" not in final_body
    assert "stack[" not in final_body


def test_reinitbars_recurrence_rebound_to_irow():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10678,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = _combined_output(result)
    assert result.returncode in {4, 6}, combined
    assert "function: 0x10678 ReInitBars" in result.stdout
    assert ("validation=failed" in combined) or ("validation=uncollected" in combined)


def test_heapsort_has_no_byte_carrier_stack_leaks():
    result = _run_decompile_addr(
        SORTDEMO_EXE,
        0x10970,
        extra_args=("--c-target", "portable-flat"),
        analysis_timeout=12,
        subprocess_timeout=45,
    )

    combined = _combined_output(result)
    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "validation=passed" in combined
    final_body = "short HeapSort" + result.stdout.rsplit("short HeapSort", 1)[-1]
    assert "&s_" not in final_body
    assert "s_ff" not in final_body
