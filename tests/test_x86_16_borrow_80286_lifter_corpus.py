from __future__ import annotations

import hashlib
import io
import importlib.util
import os
from pathlib import Path
import sys

import angr
import pytest

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401

_HELPER_PATH = Path(__file__).with_name("_x86_16_borrow_80286.py")
_HELPER_SPEC = importlib.util.spec_from_file_location("x86_16_borrow_80286_helper", _HELPER_PATH)
assert _HELPER_SPEC is not None and _HELPER_SPEC.loader is not None
_HELPER_MODULE = importlib.util.module_from_spec(_HELPER_SPEC)
sys.modules[_HELPER_SPEC.name] = _HELPER_MODULE
_HELPER_SPEC.loader.exec_module(_HELPER_MODULE)
Borrow80286Case = _HELPER_MODULE.Borrow80286Case
load_borrow_80286_lifter_corpus = _HELPER_MODULE.load_borrow_80286_lifter_corpus
load_borrow_80286_lifter_cases = _HELPER_MODULE.load_borrow_80286_lifter_cases

_SUCCESS_CACHE_DIR = Path(__file__).resolve().parents[1] / ".cache" / "borrow_80286_real_mode_lifter_success"


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


def _lift_case(case: Borrow80286Case) -> None:
    project = _project_from_bytes(case.instruction_bytes)
    block = project.factory.block(0x1000, size=len(case.instruction_bytes), opt_level=0)

    assert block.size >= 1, case.name
    assert block.vex is not None, case.name
    assert block.vex.statements is not None, case.name
    assert len(block.capstone.insns) >= 1, case.name
    assert block.capstone.insns[0].mnemonic, case.name


def _case_success_cache_path(case: Borrow80286Case) -> Path:
    digest = hashlib.sha256(case.instruction_bytes).hexdigest()
    return _SUCCESS_CACHE_DIR / f"{digest}.ok"


def _case_has_cached_success(case: Borrow80286Case) -> bool:
    return _case_success_cache_path(case).exists()


def _record_case_success(case: Borrow80286Case) -> None:
    marker_path = _case_success_cache_path(case)
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.write_text(f"{case.name}\n", encoding="utf-8")


def _run_full_corpus_lift(cases: tuple[Borrow80286Case, ...]) -> tuple[int, int]:
    lifted_count = 0
    cached_skip_count = 0

    for case in cases:
        if _case_has_cached_success(case):
            cached_skip_count += 1
            continue
        _lift_case(case)
        _record_case_success(case)
        lifted_count += 1

    return lifted_count, cached_skip_count


def test_borrow_80286_lifter_corpus_loader_consumes_all_filtered_tests_and_dedups() -> None:
    corpus = load_borrow_80286_lifter_corpus()

    assert corpus.total_cases > 800_000
    assert corpus.filtered_cases > 800_000
    assert corpus.skipped_bad_cases > 0
    assert corpus.skipped_lock_cases > 0
    assert corpus.deduped_cases == len(corpus.cases)
    assert corpus.deduped_cases > 250_000
    assert corpus.deduped_cases < corpus.filtered_cases


@pytest.mark.parametrize("case", load_borrow_80286_lifter_cases(256))
def test_borrow_80286_deduped_lifter_corpus_sample_block_lifts(case) -> None:
    _lift_case(case)


def test_borrow_80286_full_lifter_cache_skips_previously_successful_case(monkeypatch, tmp_path) -> None:
    case = Borrow80286Case(
        opcode_key="00",
        mnemonic_key="nop",
        name="nop",
        instruction_bytes=b"\x90",
        source_path=tmp_path / "00.MOO.gz",
    )
    calls = {"lift": 0}

    def fake_lift(_case: Borrow80286Case) -> None:
        calls["lift"] += 1

    monkeypatch.setattr(sys.modules[__name__], "_SUCCESS_CACHE_DIR", tmp_path / "success-cache")
    monkeypatch.setattr(sys.modules[__name__], "_lift_case", fake_lift)

    first_lifted, first_skipped = _run_full_corpus_lift((case,))
    second_lifted, second_skipped = _run_full_corpus_lift((case,))

    assert calls["lift"] == 1
    assert (first_lifted, first_skipped) == (1, 0)
    assert (second_lifted, second_skipped) == (0, 1)
    assert _case_has_cached_success(case) is True


def test_borrow_80286_deduped_lifter_corpus_full_block_lifts_opt_in() -> None:
    if os.environ.get("INERTIA_RUN_FULL_80286_LIFTER_CORPUS") != "1":
        pytest.skip("full deduped 80286 lifter corpus is exhaustive and opt-in")

    cases = load_borrow_80286_lifter_cases()
    lifted_count, cached_skip_count = _run_full_corpus_lift(cases)

    assert lifted_count + cached_skip_count == len(cases)
