#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

for _logger_name in (
    "angr.state_plugins.unicorn_engine",
    "angr.analyses.analysis",
    "angr.analyses.decompiler.clinic",
    "angr.analyses.decompiler.callsite_maker",
    "angr_platforms.X86_16.lift_86_16",
):
    logging.getLogger(_logger_name).setLevel(logging.CRITICAL)

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from angr_platforms.X86_16.corpus_scan import (
    FunctionScanResult,
    ScanTimeout,
    classify_failure,
    extract_cod_functions,
    scan_function,
    set_memory_limit,
    summarize_results,
)
from angr_platforms.X86_16.milestone_report import (
    build_x86_16_milestone_report,
    render_x86_16_tail_validation_console_summary,
)


def _timeout_result(cod_file: Path, proc_name: str, proc_kind: str, code: bytes, reason: str) -> FunctionScanResult:
    result = FunctionScanResult(
        cod_file=cod_file.name,
        proc_name=proc_name,
        proc_kind=proc_kind,
        byte_len=len(code),
        has_near_call_reloc=b"\xe8\x00\x00" in code,
        has_far_call_reloc=b"\x9a\x00\x00\x00\x00" in code,
        failure_class="timeout",
        reason=reason,
        fallback_kind="block_lift",
    )
    result.stage_reached = "decompile"
    return result


def _collect_cod_files(cod_path: Path) -> list[Path]:
    if cod_path.is_file():
        return [cod_path] if cod_path.suffix.upper() == ".COD" else []
    return sorted(cod_path.rglob("*.COD"))


def _tail_validation_cache_path(cod_dir: Path, mode: str) -> Path:
    cache_root = REPO_ROOT / ".cache" / "scan_cod_dir"
    target = cod_dir.resolve()
    suffix = target.name if target.name else "corpus"
    return cache_root / f"{suffix}.{mode}.tail_validation_console.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded staged corpus scan for .COD functions.")
    parser.add_argument("cod_dir", type=Path, help="Directory containing .COD files")
    parser.add_argument("--timeout-sec", type=int, default=5, help="Per-function timeout in seconds")
    parser.add_argument("--max-memory-mb", type=int, default=1024, help="Address-space cap for this process")
    parser.add_argument(
        "--max-cfg-bytes",
        type=int,
        default=192,
        help="In scan-safe mode, skip CFG/decompile for larger functions (0 = disable).",
    )
    parser.add_argument(
        "--max-decompile-bytes",
        type=int,
        default=384,
        help="In scan-safe mode, skip full decompilation for larger functions and stop at cfg/cleanup (0 = disable).",
    )
    parser.add_argument("--limit", type=int, default=0, help="Only scan the first N functions (0 = all)")
    parser.add_argument(
        "--progress-every",
        type=int,
        default=25,
        help="Emit a progress line to stderr after every N scanned functions (0 = disable).",
    )
    parser.add_argument(
        "--stop-after-failures",
        type=int,
        default=0,
        help="Stop scanning after collecting this many failures (0 = scan all).",
    )
    parser.add_argument(
        "--mode",
        choices=("lift", "decompile-reloc-free", "scan-safe"),
        default="scan-safe",
        help="Either just lift, decompile reloc-free blobs, or run the full staged scan-safe lane.",
    )
    parser.add_argument(
        "--milestone-report",
        action="store_true",
        help="Wrap the scan summary in the milestone report envelope with validation and readability context.",
    )
    args = parser.parse_args()

    set_memory_limit(args.max_memory_mb)

    cod_files = _collect_cod_files(args.cod_dir)
    results = []
    failures_seen = 0
    scanned_seen = 0
    started_at = time.monotonic()

    def _emit_progress(cod_file: Path | None, proc_name: str | None, proc_kind: str | None, result: FunctionScanResult | None = None) -> None:
        if args.progress_every <= 0:
            return
        elapsed = time.monotonic() - started_at
        status = "pending"
        failure_class = "-"
        fallback_kind = "-"
        if result is not None:
            status = "ok" if result.ok else "fail"
            failure_class = result.failure_class or "-"
            fallback_kind = result.fallback_kind or "-"
        location = "-"
        if cod_file is not None and proc_name is not None and proc_kind is not None:
            location = f"{cod_file.name}:{proc_name}<{proc_kind}>"
        print(
            f"[scan-safe] scanned={scanned_seen} failures={failures_seen} elapsed={elapsed:0.1f}s "
            f"status={status} location={location} failure={failure_class} fallback={fallback_kind}",
            file=sys.stderr,
            flush=True,
        )

    for cod_file in cod_files:
        print(f"[scan-safe] file-start {cod_file.name}", file=sys.stderr, flush=True)
        for proc_name, proc_kind, code in extract_cod_functions(cod_file):
            try:
                result = scan_function(
                    cod_file,
                    proc_name,
                    proc_kind,
                    code,
                    args.timeout_sec,
                    args.mode,
                    max_cfg_bytes=args.max_cfg_bytes,
                    max_decompile_bytes=args.max_decompile_bytes,
                )
            except ScanTimeout as exc:
                failure_class, reason = classify_failure("decompile", exc)
                result = _timeout_result(cod_file, proc_name, proc_kind, code, reason)
                result.failure_class = failure_class
            results.append(result)
            scanned_seen += 1
            if not result.ok:
                failures_seen += 1
            if args.progress_every and (scanned_seen % args.progress_every == 0 or not result.ok):
                _emit_progress(cod_file, proc_name, proc_kind, result)
            if args.limit and len(results) >= args.limit:
                break
            if args.stop_after_failures and failures_seen >= args.stop_after_failures:
                break
        print(
            f"[scan-safe] file-end {cod_file.name} scanned={scanned_seen} failures={failures_seen}",
            file=sys.stderr,
            flush=True,
        )
        if args.limit and len(results) >= args.limit:
            break
        if args.stop_after_failures and failures_seen >= args.stop_after_failures:
            break

    summary = summarize_results(results, args.mode)
    output = (
        build_x86_16_milestone_report(
            summary,
            corpus_slice=str(args.cod_dir),
        )
        if args.milestone_report
        else summary
    )
    tail_surface = output.get("tail_validation_surface") if isinstance(output, dict) else None
    if not isinstance(tail_surface, dict):
        tail_surface = summary.get("tail_validation_surface", {})
    rendered_tail = render_x86_16_tail_validation_console_summary(
        tail_surface,
        cache_path=_tail_validation_cache_path(args.cod_dir, args.mode),
    )
    print(
        f"[scan-safe] done scanned={summary['scanned']} ok={summary['ok']} failed={summary['failed']} "
        f"elapsed={time.monotonic() - started_at:0.1f}s",
        file=sys.stderr,
        flush=True,
    )
    for line in rendered_tail["lines"]:
        print(f"[tail-validation] {line}", file=sys.stderr, flush=True)
    if rendered_tail.get("cache_hit"):
        print("[tail-validation] console summary cache hit", file=sys.stderr, flush=True)
    print(json.dumps(output, indent=2))
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
