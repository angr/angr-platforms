#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from angr_platforms.X86_16.verification_80286 import (
    DEFAULT_REVOCATION_LIST,
    DEFAULT_SUITE_DIR,
    discover_moo_files,
    load_moo_cases,
    opcode_name_for_path,
    load_revocation_hashes,
    summarize_results,
    summary_to_json,
    verify_moo_file,
)
from angr_platforms.X86_16.coverage_manifest import COMPARE_VERIFIED_MOO_OPCODES


DEFAULT_PASSED_CACHE = Path(__file__).resolve().parents[1] / ".cache" / "80286_real_mode_passed_opcodes.txt"


def _default_jobs() -> int:
    cpu_count = os.cpu_count() or 1
    return max(1, cpu_count - 1)


def _default_nice() -> int:
    if platform.system() != "Linux":
        return 0
    return 10


def _apply_nice(nice_value: int) -> None:
    if nice_value <= 0:
        return
    if platform.system() != "Linux":
        return
    try:
        os.nice(nice_value)
    except OSError:
        pass


def _verify_one_file(task: tuple[Path, int | None, bool, frozenset[str], int | None, int, int | None]) -> dict:
    path, limit, execute_halt, revoked_hashes, progress_every, case_start, case_stop = task
    return verify_moo_file(
        path,
        limit=limit,
        execute_halt=execute_halt,
        revoked_hashes=set(revoked_hashes),
        progress_every=progress_every,
        case_start=case_start,
        case_stop=case_stop,
    )


def _merge_file_summaries(parts: list[dict]) -> dict:
    first = parts[0]
    ordered_parts = sorted(parts, key=lambda item: item["results"][0]["idx"] if item["results"] else -1)
    merged_results: list[dict] = []
    for part in ordered_parts:
        merged_results.extend(part["results"])
    return {
        "opcode": first["opcode"],
        "path": first["path"],
        "cpu": first["cpu"],
        "total": sum(part["total"] for part in parts),
        "passed": sum(part["passed"] for part in parts),
        "failed": sum(part["failed"] for part in parts),
        "skipped": sum(part["skipped"] for part in parts),
        "sample_name": first["sample_name"],
        "results": merged_results,
    }


def _build_tasks(
    files: list[Path],
    *,
    limit: int | None,
    execute_halt: bool,
    revoked: set[str],
    progress_every: int | None,
    jobs: int,
) -> tuple[list[tuple[Path, int | None, bool, frozenset[str], int | None, int, int | None]], dict[tuple[str, int, int | None], str]]:
    if not files:
        return [], {}

    if len(files) >= jobs:
        tasks = [(path, limit, execute_halt, frozenset(revoked), progress_every, 0, None) for path in files]
        task_keys = {(str(path), 0, None): opcode_name_for_path(path) for path in files}
        return tasks, task_keys

    task_keys: dict[tuple[str, int, int | None], str] = {}
    tasks: list[tuple[Path, int | None, bool, frozenset[str], int | None, int, int | None]] = []
    base_chunks = max(1, jobs // len(files))
    extra_chunks = jobs % len(files)

    for index, path in enumerate(files):
        target_chunks = base_chunks + (1 if index < extra_chunks else 0)
        _, cases = load_moo_cases(path)
        total_cases = len(cases if limit is None else cases[:limit])
        if total_cases == 0:
            tasks.append((path, limit, execute_halt, frozenset(revoked), progress_every, 0, 0))
            task_keys[(str(path), 0, 0)] = opcode_name_for_path(path)
            continue
        target_chunks = min(target_chunks, total_cases)
        chunk_size = max(1, (total_cases + target_chunks - 1) // target_chunks)
        for case_start in range(0, total_cases, chunk_size):
            case_stop = min(total_cases, case_start + chunk_size)
            tasks.append((path, None, execute_halt, frozenset(revoked), progress_every, case_start, case_stop))
            task_keys[(str(path), case_start, case_stop)] = opcode_name_for_path(path)

    return tasks, task_keys


def _exclude_compare_covered(files: list[Path]) -> tuple[list[Path], list[Path]]:
    kept: list[Path] = []
    skipped: list[Path] = []
    for path in files:
        stem = path.name.removesuffix(".MOO.gz").removesuffix(".MOO")
        if stem in COMPARE_VERIFIED_MOO_OPCODES:
            skipped.append(path)
        else:
            kept.append(path)
    return kept, skipped


def _sample_compare_covered(
    files: list[Path], *, day_of_month: int
) -> tuple[list[Path], list[Path], list[Path]]:
    if not 1 <= day_of_month <= 31:
        raise ValueError("day_of_month must be in 1..31")

    kept: list[Path] = []
    sampled: list[Path] = []
    skipped: list[Path] = []
    sample_bucket = day_of_month - 1

    for path in files:
        stem = path.name.removesuffix(".MOO.gz").removesuffix(".MOO")
        if stem not in COMPARE_VERIFIED_MOO_OPCODES:
            kept.append(path)
            continue

        digest = hashlib.sha1(stem.encode("ascii")).digest()
        bucket = int.from_bytes(digest[:4], "big") % 31
        if bucket == sample_bucket:
            kept.append(path)
            sampled.append(path)
        else:
            skipped.append(path)

    return kept, sampled, skipped


def _load_passed_cache(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def _exclude_cached_passes(files: list[Path], passed_opcodes: set[str]) -> tuple[list[Path], list[Path]]:
    kept: list[Path] = []
    skipped: list[Path] = []
    for path in files:
        stem = path.name.removesuffix(".MOO.gz").removesuffix(".MOO")
        if stem in passed_opcodes:
            skipped.append(path)
        else:
            kept.append(path)
    return kept, skipped


def _update_passed_cache(path: Path, summaries: list[dict]) -> set[str]:
    passed = _load_passed_cache(path)
    for summary in summaries:
        if summary["failed"] == 0:
            passed.add(summary["opcode"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{opcode}\n" for opcode in sorted(passed)))
    return passed


def _print_summary(summary: dict) -> None:
    print(
        f"{summary['opcode']:>6}  passed={summary['passed']:>4}  failed={summary['failed']:>4}  "
        f"skipped={summary['skipped']:>4}  total={summary['total']:>4}  {summary['sample_name']}",
        flush=True,
    )
    for result in summary["results"]:
        if result["passed"] or result["skipped"]:
            continue
        if result["error"]:
            print(f"         case {result['idx']:>4}: error: {result['error']}", flush=True)
        elif result["mismatches"]:
            first = result["mismatches"][0]
            where = f" @ {first['address']:#x}" if first["address"] is not None else ""
            print(
                f"         case {result['idx']:>4}: {first['kind']} {first['name']}{where}: "
                f"expected {first['expected']:#x}, got {first['actual']:#x}",
                flush=True,
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify x86-16 real-mode execution against 80286 hardware dumps.")
    parser.add_argument(
        "suite",
        nargs="?",
        type=Path,
        default=DEFAULT_SUITE_DIR,
        help="A .MOO/.MOO.gz file or a directory containing them.",
    )
    parser.add_argument("--opcode", action="append", default=[], help="Restrict to one or more opcode filenames, e.g. 00 or 60.")
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of cases to verify per opcode file.")
    parser.add_argument(
        "--revocation-list",
        type=Path,
        default=DEFAULT_REVOCATION_LIST,
        help="Optional revocation-list file.",
    )
    parser.add_argument("--ignore-revoked", action="store_true", help="Do not skip revoked case hashes.")
    parser.add_argument(
        "--skip-compare-covered",
        action="store_true",
        help="Skip opcode files already covered by upstream-x86 compare semantics tests.",
    )
    parser.add_argument(
        "--sample-compare-covered",
        action="store_true",
        help="Keep only a deterministic day-of-month sample of compare-covered opcode files.",
    )
    parser.add_argument(
        "--sample-day",
        type=int,
        default=None,
        help="Override the day-of-month used for compare-covered sampling (1-31).",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=_default_jobs(),
        help="Worker processes to use across opcode files. Defaults to max(1, cpu_count - 1).",
    )
    parser.add_argument(
        "--nice",
        type=int,
        default=_default_nice(),
        help="Increase process nice level on Linux before running workers. Defaults to 10.",
    )
    parser.add_argument(
        "--passed-cache",
        type=Path,
        default=DEFAULT_PASSED_CACHE,
        help="Path to the persistent list of opcode files that already pass verification.",
    )
    parser.add_argument(
        "--no-skip-passed-cache",
        action="store_true",
        help="Do not skip opcode files already recorded as passing in the passed-cache.",
    )
    parser.add_argument(
        "--clear-passed-cache",
        action="store_true",
        help="Clear the persistent passed-cache before running verification.",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Print per-opcode completion progress as workers finish.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=None,
        help="When set, also print intra-file case progress every N cases.",
    )
    parser.add_argument("--json-output", type=Path, default=None, help="Optional JSON summary output path.")
    args = parser.parse_args()
    if args.jobs < 1:
        raise SystemExit("--jobs must be at least 1")
    if args.nice < 0:
        raise SystemExit("--nice must be >= 0")
    if args.skip_compare_covered and args.sample_compare_covered:
        raise SystemExit("--skip-compare-covered and --sample-compare-covered are mutually exclusive")

    _apply_nice(args.nice)

    revoked = set() if args.ignore_revoked else load_revocation_hashes(args.revocation_list)
    files = discover_moo_files(args.suite, args.opcode)
    skipped_compare: list[Path] = []
    sampled_compare: list[Path] = []
    skipped_cached: list[Path] = []
    if args.clear_passed_cache and args.passed_cache.exists():
        args.passed_cache.unlink()
    if not args.no_skip_passed_cache:
        cached_passes = _load_passed_cache(args.passed_cache)
        files, skipped_cached = _exclude_cached_passes(files, cached_passes)
    if args.skip_compare_covered:
        files, skipped_compare = _exclude_compare_covered(files)
    elif args.sample_compare_covered:
        day_of_month = args.sample_day or date.today().day
        files, sampled_compare, skipped_compare = _sample_compare_covered(files, day_of_month=day_of_month)
    if not files:
        if skipped_compare or skipped_cached:
            print("No opcode files need verification after applying skip filters.")
            if sampled_compare:
                print(f"Sampled compare-covered opcode files={len(sampled_compare)}")
            if skipped_compare:
                print(f"Skipped compare-covered opcode files={len(skipped_compare)}")
            if skipped_cached:
                print(f"Skipped cached-passing opcode files={len(skipped_cached)}")
            return 0
        raise SystemExit("No matching .MOO files found.")

    progress_every = args.progress_every if args.progress_every and args.progress_every > 0 else None
    tasks, task_keys = _build_tasks(
        files,
        limit=args.limit,
        execute_halt=True,
        revoked=revoked,
        progress_every=progress_every,
        jobs=args.jobs,
    )
    worker_count = min(args.jobs, len(tasks))

    summaries_by_opcode: dict[str, list[dict]] = {}
    start_time = time.monotonic()
    if worker_count == 1:
        for index, task in enumerate(tasks, start=1):
            summary = _verify_one_file(task)
            opcode = task_keys[(str(task[0]), task[5], task[6])]
            summaries_by_opcode.setdefault(opcode, []).append(summary)
            if args.progress:
                elapsed = time.monotonic() - start_time
                print(f"[{index}/{len(tasks)}] completed in {elapsed:.1f}s", flush=True)
                _print_summary(summary)
    else:
        with ProcessPoolExecutor(max_workers=worker_count) as executor:
            future_map = {executor.submit(_verify_one_file, task): task for task in tasks}
            for index, future in enumerate(as_completed(future_map), start=1):
                summary = future.result()
                task = future_map[future]
                opcode = task_keys[(str(task[0]), task[5], task[6])]
                summaries_by_opcode.setdefault(opcode, []).append(summary)
                if args.progress:
                    elapsed = time.monotonic() - start_time
                    print(f"[{index}/{len(tasks)}] completed in {elapsed:.1f}s", flush=True)
                    _print_summary(summary)

    summaries = [_merge_file_summaries(parts) for _, parts in sorted(summaries_by_opcode.items())]
    _update_passed_cache(args.passed_cache, summaries)
    summaries.sort(key=lambda summary: summary["opcode"])
    if not args.progress:
        for summary in summaries:
            _print_summary(summary)

    suite_summary = summarize_results(summaries)
    print(
        f"\nTotal files={suite_summary['total_files']}  cases={suite_summary['total_cases']}  "
        f"passed={suite_summary['passed_cases']}  failed={suite_summary['failed_cases']}  "
        f"skipped={suite_summary['skipped_cases']}"
    )
    if sampled_compare:
        print(f"Sampled compare-covered opcode files={len(sampled_compare)}")
    if skipped_compare:
        print(f"Skipped compare-covered opcode files={len(skipped_compare)}")
    if skipped_cached:
        print(f"Skipped cached-passing opcode files={len(skipped_cached)}")

    if args.json_output is not None:
        args.json_output.write_text(summary_to_json(suite_summary) + "\n")
    _update_passed_cache(args.passed_cache, summaries)

    return 0 if suite_summary["failed_cases"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
