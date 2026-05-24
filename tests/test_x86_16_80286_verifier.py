from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from angr_platforms.X86_16.coverage_manifest import COMPARE_VERIFIED_MOO_OPCODES
from angr_platforms.X86_16.verification_80286 import (
    REPO_ROOT,
    load_moo_cases,
    summarize_results,
    summary_to_json,
    verify_case,
    verify_moo_file,
)
from scripts.verify_80286_real_mode import (
    _exclude_cached_passes,
    _exclude_compare_covered,
    _load_passed_cache,
    _sample_compare_covered,
    _update_passed_cache,
)

SUITE_DIR = REPO_ROOT / "borrow" / "80286" / "v1_real_mode"


def _moo(opcode: str) -> Path:
    return SUITE_DIR / f"{opcode}.MOO.gz"


def test_verify_80286_add_rm8_r8_case_passes():
    summary = verify_moo_file(_moo("00"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_pusha_case_passes():
    summary = verify_moo_file(_moo("60"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_pushf_case_passes():
    summary = verify_moo_file(_moo("9C"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_push_sp_case_passes():
    summary = verify_moo_file(_moo("54"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_popf_case_passes():
    summary = verify_moo_file(_moo("9D"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_lock_pop_sp_case_passes():
    summary = verify_moo_file(_moo("5C"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_in_al_imm8_case_passes():
    summary = verify_moo_file(_moo("E4"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_in_al_dx_case_passes():
    summary = verify_moo_file(_moo("EC"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_rep_insb_case_passes():
    summary = verify_moo_file(_moo("6C"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_rep_insw_case_passes():
    summary = verify_moo_file(_moo("6D"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_repe_scasb_case_passes():
    _, cases = load_moo_cases(_moo("AE"))
    case = next(c for c in cases if c["idx"] == 16)
    result = verify_case(case, opcode="AE")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_case_checks_unchanged_registers_and_memory():
    _, cases = load_moo_cases(_moo("00"))
    result = verify_case(cases[0], opcode="00")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_xlat_case_passes():
    summary = verify_moo_file(_moo("D7"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_add_rm16_r16_case_passes():
    summary = verify_moo_file(_moo("01"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_add_rm16_r16_unaligned_word_case_passes():
    _, cases = load_moo_cases(_moo("01"))
    case = next(c for c in cases if c["idx"] == 1439)
    result = verify_case(case, opcode="01")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_adc_rm16_r16_case_passes():
    summary = verify_moo_file(_moo("11"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_add_r16_rm16_unaligned_word_case_passes():
    _, cases = load_moo_cases(_moo("03"))
    case = next(c for c in cases if c["idx"] == 1423)
    result = verify_case(case, opcode="03")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_push_es_unaligned_stack_word_case_passes():
    _, cases = load_moo_cases(_moo("06"))
    case = next(c for c in cases if c["idx"] == 1663)
    result = verify_case(case, opcode="06")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_daa_overflow_case_passes():
    _, cases = load_moo_cases(_moo("27"))
    case = next(c for c in cases if c["idx"] == 0)
    result = verify_case(case, opcode="27")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_aaa_overflow_case_passes():
    _, cases = load_moo_cases(_moo("37"))
    case = next(c for c in cases if c["idx"] == 43)
    result = verify_case(case, opcode="37")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_faulting_lodsw_updates_si_before_gp_fault():
    _, cases = load_moo_cases(_moo("AD"))
    case = next(c for c in cases if c["idx"] == 60)
    result = verify_case(case, opcode="AD")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_rep_faulting_lodsw_preserves_ax_and_decrements_cx():
    _, cases = load_moo_cases(_moo("AD"))
    case = next(c for c in cases if c["idx"] == 231)
    result = verify_case(case, opcode="AD")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_faulting_scasw_updates_di_before_gp_fault():
    _, cases = load_moo_cases(_moo("AF"))
    case = next(c for c in cases if c["idx"] == 2413)
    result = verify_case(case, opcode="AF")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_rcl_rm16_cl_masks_undefined_overflow():
    _, cases = load_moo_cases(_moo("D3.2"))
    case = next(c for c in cases if c["idx"] == 1)
    result = verify_case(case, opcode="D3.2")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_rcr_rm16_cl_masks_undefined_overflow():
    _, cases = load_moo_cases(_moo("D3.3"))
    case = next(c for c in cases if c["idx"] == 3)
    result = verify_case(case, opcode="D3.3")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_shl_rm16_cl_masks_undefined_adjust_flag():
    _, cases = load_moo_cases(_moo("D3.4"))
    case = next(c for c in cases if c["idx"] == 2575)
    result = verify_case(case, opcode="D3.4")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_shl_rm8_cl_masks_undefined_adjust_flag():
    _, cases = load_moo_cases(_moo("D2.4"))
    case = cases[0]
    result = verify_case(case, opcode="D2.4")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_lock_sbb_rm16_case_passes():
    summary = verify_moo_file(_moo("1B"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_sbb_ax_imm16_case_passes():
    summary = verify_moo_file(_moo("1D"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_cmp_ax_imm16_case_passes():
    summary = verify_moo_file(_moo("3D"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_sbb_rm8_r8_case_passes():
    summary = verify_moo_file(_moo("18"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_cwd_case_passes():
    summary = verify_moo_file(_moo("99"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_gp_faulting_memory_operand_case_passes():
    summary = verify_moo_file(_moo("D1.6"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_bound_invalid_case_passes():
    summary = verify_moo_file(_moo("62"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_jmp_short_case_passes():
    summary = verify_moo_file(_moo("EB"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_loop_prefixed_case_passes():
    _, cases = load_moo_cases(_moo("E2"))
    case = next(c for c in cases if c["idx"] == 27)
    result = verify_case(case, opcode="E2")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_loop_to_local_hlt_case_passes():
    _, cases = load_moo_cases(_moo("E2"))
    case = next(c for c in cases if c["idx"] == 3450)
    result = verify_case(case, opcode="E2")

    assert result.passed
    assert result.error is None
    assert result.mismatches == []


def test_verify_80286_far_jmp_case_passes():
    summary = verify_moo_file(_moo("EA"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_int_case_passes():
    summary = verify_moo_file(_moo("CD"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_iret_case_passes():
    summary = verify_moo_file(_moo("CF"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_hlt_case_passes():
    summary = verify_moo_file(_moo("F4"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_lock_far_call_case_passes():
    summary = verify_moo_file(_moo("9A"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_invalid_8f_case_passes():
    summary = verify_moo_file(_moo("8F"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_invalid_c6_case_passes():
    summary = verify_moo_file(_moo("C6"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_salc_case_passes():
    summary = verify_moo_file(_moo("D6"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_esc_case_passes():
    summary = verify_moo_file(_moo("D8"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_rcr_rm16_imm8_case_passes():
    summary = verify_moo_file(_moo("C1.3"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_sal_rm16_imm8_case_passes():
    summary = verify_moo_file(_moo("C1.6"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_lock_sal_rm8_imm8_case_passes():
    summary = verify_moo_file(_moo("C0.6"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_lock_rcl_rm16_imm8_case_passes():
    summary = verify_moo_file(_moo("C1.2"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_lock_int3_case_passes():
    summary = verify_moo_file(_moo("CC"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_far_indirect_call_case_passes():
    summary = verify_moo_file(_moo("FF.3"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_mul_rm8_case_passes():
    summary = verify_moo_file(_moo("F6.4"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_imul_rm8_case_passes():
    summary = verify_moo_file(_moo("F6.5"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_div_rm8_exception_case_passes():
    summary = verify_moo_file(_moo("F6.6"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_mul_rm16_case_passes():
    summary = verify_moo_file(_moo("F7.4"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_div_rm16_case_passes():
    summary = verify_moo_file(_moo("F7.6"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_imul_rm16_imm16_case_passes():
    summary = verify_moo_file(_moo("69"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_imul_rm16_imm8_case_passes():
    summary = verify_moo_file(_moo("6B"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_verify_80286_xchg_r16_rm16_case_passes():
    summary = verify_moo_file(_moo("87"), limit=1)

    assert summary["passed"] == 1
    assert summary["failed"] == 0


def test_build_80286_verification_table_script(tmp_path):
    summary = summarize_results([verify_moo_file(_moo("00"), limit=1), verify_moo_file(_moo("60"), limit=1)])
    summary_json = tmp_path / "summary.json"
    summary_json.write_text(summary_to_json(summary) + "\n")
    output_md = tmp_path / "verification.md"

    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "angr_platforms" / "scripts" / "build_80286_real_mode_verification_table.py"),
            str(summary_json),
            "--output",
            str(output_md),
        ],
        check=True,
        cwd=REPO_ROOT / "angr_platforms",
    )

    text = output_md.read_text()
    assert "`00`" in text
    assert "`60`" in text
    assert "80286 Real-Mode Verification Table" in text


def test_compare_verified_manifest_covers_known_upstream_compare_cases():
    assert "AA" in COMPARE_VERIFIED_MOO_OPCODES
    assert "D3.4" in COMPARE_VERIFIED_MOO_OPCODES
    assert "F7.3" in COMPARE_VERIFIED_MOO_OPCODES


def test_exclude_compare_covered_filters_known_cases():
    kept, skipped = _exclude_compare_covered([_moo("AA"), _moo("00"), _moo("D3.4")])

    assert _moo("00") in kept
    assert _moo("AA") in skipped
    assert _moo("D3.4") in skipped


def test_sample_compare_covered_is_deterministic_for_day():
    files = [_moo("AA"), _moo("00"), _moo("D3.4"), _moo("F7.3")]

    kept_a, sampled_a, skipped_a = _sample_compare_covered(files, day_of_month=22)
    kept_b, sampled_b, skipped_b = _sample_compare_covered(files, day_of_month=22)

    assert kept_a == kept_b
    assert sampled_a == sampled_b
    assert skipped_a == skipped_b
    assert _moo("00") in kept_a
    assert set(sampled_a).issubset(set(kept_a))
    assert set(sampled_a).isdisjoint(set(skipped_a))


def test_sample_compare_covered_changes_with_day():
    files = [_moo("AA"), _moo("D3.4"), _moo("F7.3")]

    _, sampled_day_1, _ = _sample_compare_covered(files, day_of_month=1)
    _, sampled_day_2, _ = _sample_compare_covered(files, day_of_month=2)

    assert sampled_day_1 != sampled_day_2 or not sampled_day_1 or not sampled_day_2


def test_passed_cache_roundtrip_and_filtering(tmp_path):
    cache = tmp_path / "passed.txt"
    cache.write_text("00\nD3.4\n")

    loaded = _load_passed_cache(cache)
    kept, skipped = _exclude_cached_passes([_moo("00"), _moo("60"), _moo("D3.4")], loaded)

    assert loaded == {"00", "D3.4"}
    assert _moo("60") in kept
    assert _moo("00") in skipped
    assert _moo("D3.4") in skipped


def test_update_passed_cache_adds_new_passing_opcodes(tmp_path):
    cache = tmp_path / "passed.txt"
    cache.write_text("00\n")

    updated = _update_passed_cache(
        cache,
        [
            {"opcode": "60", "failed": 0},
            {"opcode": "D0.0", "failed": 1},
        ],
    )

    assert updated == {"00", "60"}
    assert cache.read_text().splitlines() == ["00", "60"]
