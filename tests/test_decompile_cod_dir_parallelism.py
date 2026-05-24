from importlib.util import module_from_spec, spec_from_file_location
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
from types import SimpleNamespace
import json
import sys

from inertia_decompiler import tail_validation as _tail_validation


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "decompile_cod_dir.py"

_spec = spec_from_file_location("decompile_cod_dir", SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
_script = module_from_spec(_spec)
sys.modules[_spec.name] = _script
_spec.loader.exec_module(_script)


def _tail_validation_metadata_payload(stderr_text: str) -> dict[str, object]:
    for line in stderr_text.splitlines():
        if line.startswith(_tail_validation.TAIL_VALIDATION_METADATA_PREFIX):
            return json.loads(line[len(_tail_validation.TAIL_VALIDATION_METADATA_PREFIX) :].strip())
    raise AssertionError(f"missing tail-validation metadata line in {stderr_text!r}")


def test_choose_parallelism_caps_to_a_small_multi_core_pool(monkeypatch):
    monkeypatch.setattr(_script.os, "cpu_count", lambda: 12)
    monkeypatch.setattr(_script, "_mem_available_mb", lambda: 128_000)

    assert _script._choose_parallelism(100, 16_000, 8) == 3


def test_choose_parallelism_stays_single_worker_for_tight_memory(monkeypatch):
    monkeypatch.setattr(_script.os, "cpu_count", lambda: 12)
    monkeypatch.setattr(_script, "_mem_available_mb", lambda: 1_800)

    assert _script._choose_parallelism(100, 16_000, 8) == 1


def test_worker_failure_formatting_is_deterministic_for_broken_pools():
    item = _script.CodWorkItem(
        cod_path=Path("/tmp/DOSFUNC.COD"),
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )
    ex = BrokenProcessPool("A process in the process pool was terminated abruptly while the future was running or pending.")

    assert _script._worker_failure_summary(item, ex) == "parent pool breakage while recovering _dos_alloc (NEAR)"
    assert _script._format_worker_failure(item, ex) == (
        "/* parent pool breakage while recovering _dos_alloc (NEAR) */"
    )
    assert "BrokenProcessPool" not in _script._format_worker_failure(item, ex)


def test_describe_returncode_separates_timeout_signal_and_memory_pressure():
    timeout_kind, timeout_detail = _script._describe_returncode(
        3,
        "/* Timed out while recovering a function after 20s. */\n",
        "",
    )
    signal_kind, signal_detail = _script._describe_returncode(-9, "", "")
    rlimit_kind, rlimit_detail = _script._describe_returncode(
        1,
        "",
        "MemoryError: unable to allocate arena",
    )

    assert timeout_kind == "timeout"
    assert "timeout" in timeout_detail
    assert signal_kind == "signal_termination"
    assert "SIGKILL" in signal_detail
    assert rlimit_kind == "rlimit_kill"
    assert "memory pressure" in rlimit_detail


def test_render_result_block_records_exit_kind_and_detail(tmp_path):
    stdout_path = tmp_path / "sample.dec.stdout"
    stdout_path.write_text("/* == c == */\nreturn 1;\n", encoding="utf-8")
    result = _script.CodWorkResult(
        cod_path=Path("/tmp/DOSFUNC.COD"),
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        stdout_path=stdout_path,
        stderr="MemoryError: unable to allocate arena\n",
        returncode=1,
        exit_kind="rlimit_kill",
        exit_detail="child exited with status 1 after memory pressure",
    )

    rendered = _script._render_result_block(result)

    assert "exit kind" in rendered
    assert "rlimit_kill" in rendered
    assert "memory pressure" in rendered
    assert "exit code" in rendered


def test_run_work_item_preserves_timeout_without_scan_safe_fallback(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )
    scan_safe_called = False

    def fake_child(_command, *, stdout_path, **_kwargs):  # noqa: ANN001
        stdout_path.write_text("/* Timed out while recovering a function after 20s. */\n", encoding="utf-8")
        return 3, "", False

    def fake_scan_safe(*_args, **_kwargs):  # noqa: ANN001
        nonlocal scan_safe_called
        scan_safe_called = True
        return None

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", fake_scan_safe)

    result = _script._run_work_item(item, timeout=20, max_memory_mb=1024)

    assert result.exit_kind == "timeout"
    assert scan_safe_called is False
    assert result.scan_safe_result is None
    rendered = _script._render_result_block(result)
    assert "exit kind timeout" in rendered
    assert "Timed out while recovering" in rendered


def test_run_work_item_normalizes_timeout_expired_bytes(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )

    def fake_child(_command, *, stdout_path, **_kwargs):  # noqa: ANN001
        stdout_path.write_text("stdout bytes\n", encoding="utf-8")
        return None, "stderr bytes\n", True

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", lambda *_args, **_kwargs: None)

    result = _script._run_work_item(item, timeout=20, max_memory_mb=1024)

    assert result.exit_kind == "subprocess_timeout"
    assert result.stderr == "stderr bytes\n"
    rendered = _script._render_result_block(result)
    assert "stderr bytes" in rendered
    assert "bytes found" not in rendered


def test_run_work_item_extracts_tail_validation_metadata_from_stderr(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )

    def fake_child(_command, *, stdout_path, **_kwargs):  # noqa: ANN001
        stdout_path.write_text("/* == c == */\nreturn 1;\n", encoding="utf-8")
        return (
            0,
            (
                "[tail-validation] whole-tail validation clean across 1 functions\n"
                '@@INERTIA_TAIL_VALIDATION@@ {"records":[{"function_addr":4096,"function_name":"_dos_alloc","structuring":{"changed":false},"postprocess":{"changed":false}}],"scanned":1}\n'
            ),
            False,
        )

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", lambda *_args, **_kwargs: None)

    result = _script._run_work_item(item, timeout=20, max_memory_mb=1024)

    assert result.stderr == ""
    assert result.tail_validation_scanned == 1
    assert result.tail_validation_records == (
        {
            "cod_file": "DOSFUNC.COD",
            "function_addr": 4096,
            "function_name": "_dos_alloc",
            "proc_name": "_dos_alloc",
            "proc_kind": "NEAR",
            "structuring": {"changed": False},
            "postprocess": {"changed": False},
        },
    )
    rendered = _script._render_result_block(result)
    assert "tail-validation" not in rendered


def test_run_work_item_reuses_success_only_cache(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )
    item.cod_path.write_text("cod text", encoding="utf-8")
    calls = {"child": 0}

    monkeypatch.setattr(_script, "_SUCCESS_CACHE_DIR", tmp_path / "success-cache")
    monkeypatch.setattr(_script, "_cache_source_digest", lambda _paths: "digest-a")

    def fake_child(_command, *, stdout_path, **_kwargs):  # noqa: ANN001
        calls["child"] += 1
        stdout_path.write_text("/* == c == */\nreturn 1;\n", encoding="utf-8")
        return (
            0,
            '@@INERTIA_TAIL_VALIDATION@@ {"records":[{"function_name":"_dos_alloc","structuring":{"changed":false},"postprocess":{"changed":false}}],"scanned":1}\n',
            False,
        )

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", lambda *_args, **_kwargs: None)

    first = _script._run_work_item(item, timeout=20, max_memory_mb=1024)
    second = _script._run_work_item(item, timeout=20, max_memory_mb=1024)

    assert calls["child"] == 1
    assert first.from_cache is False
    assert second.from_cache is True
    assert second.exit_kind == "ok"
    assert second.tail_validation_scanned == 1
    assert second.tail_validation_records[0]["proc_name"] == "_dos_alloc"
    rendered = _script._render_result_block(second)
    assert "/* == 2/15 DOSFUNC.COD :: _dos_alloc [NEAR] == */" in rendered
    assert "return 1;" in rendered


def test_run_work_item_does_not_cache_timeout(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )
    item.cod_path.write_text("cod text", encoding="utf-8")
    calls = {"child": 0}

    monkeypatch.setattr(_script, "_SUCCESS_CACHE_DIR", tmp_path / "success-cache")
    monkeypatch.setattr(_script, "_cache_source_digest", lambda _paths: "digest-a")
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", lambda *_args, **_kwargs: None)

    def fake_child(_command, *, stdout_path, **_kwargs):  # noqa: ANN001
        calls["child"] += 1
        stdout_path.write_text("/* Timed out while recovering a function after 20s. */\n", encoding="utf-8")
        return 3, "", False

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)

    first = _script._run_work_item(item, timeout=20, max_memory_mb=1024)
    second = _script._run_work_item(item, timeout=20, max_memory_mb=1024)

    assert calls["child"] == 2
    assert first.from_cache is False
    assert second.from_cache is False
    assert first.exit_kind == "timeout"
    assert second.exit_kind == "timeout"


def test_run_work_item_does_not_cache_zero_exit_fallback(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )
    item.cod_path.write_text("cod text", encoding="utf-8")
    calls = {"child": 0}

    monkeypatch.setattr(_script, "_SUCCESS_CACHE_DIR", tmp_path / "success-cache")
    monkeypatch.setattr(_script, "_cache_source_digest", lambda _paths: "digest-a")
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", lambda *_args, **_kwargs: None)

    def fake_child(_command, *, stdout_path, **_kwargs):  # noqa: ANN001
        calls["child"] += 1
        stdout_path.write_text(
            "/* Function recovery timed out; produced non-optimized slice decompilation. */\n"
            "/* == c (non-optimized fallback) == */\n"
            "return 1;\n",
            encoding="utf-8",
        )
        return 0, "", False

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)

    first = _script._run_work_item(item, timeout=20, max_memory_mb=1024)
    second = _script._run_work_item(item, timeout=20, max_memory_mb=1024)

    assert calls["child"] == 2
    assert first.exit_kind == "ok"
    assert second.exit_kind == "ok"
    assert first.from_cache is False
    assert second.from_cache is False


def test_run_work_item_replaces_null_tail_validation_identity(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "COCKPIT.COD",
        proc_name="_DoCRT",
        proc_kind="NEAR",
        proc_index=1,
        proc_total=1,
        code=b"\x90",
    )

    def fake_child(_command, *, stdout_path, **_kwargs):  # noqa: ANN001
        stdout_path.write_text("/* == c == */\nreturn 1;\n", encoding="utf-8")
        return (
            0,
            (
                '@@INERTIA_TAIL_VALIDATION@@ {"records":[{'
                '"cod_file":null,"proc_name":null,"proc_kind":null,'
                '"function_addr":4096,"function_name":"_DoCRT",'
                '"structuring":{"changed":false},"postprocess":{"changed":true}'
                '}],"scanned":1}\n'
            ),
            False,
        )

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", lambda *_args, **_kwargs: None)

    result = _script._run_work_item(item, timeout=20, max_memory_mb=1024)

    assert result.tail_validation_scanned == 1
    assert result.tail_validation_records == (
        {
            "cod_file": "COCKPIT.COD",
            "proc_name": "_DoCRT",
            "proc_kind": "NEAR",
            "function_addr": 4096,
            "function_name": "_DoCRT",
            "structuring": {"changed": False},
            "postprocess": {"changed": True},
        },
    )


def test_run_work_item_uses_bounded_child_timeout(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )
    seen: dict[str, object] = {}

    def fake_child(_command, *, stdout_path, child_timeout, **_kwargs):  # noqa: ANN001
        seen["timeout"] = child_timeout
        stdout_path.write_text("/* == c == */\nreturn 1;\n", encoding="utf-8")
        return 0, "", False

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", lambda *_args, **_kwargs: None)

    result = _script._run_work_item(item, timeout=3, max_memory_mb=1024)

    assert result.exit_kind == "ok"
    assert seen["timeout"] == 10


def test_uncollected_tail_validation_record_keeps_proc_identity():
    record = _script._uncollected_tail_validation_record(
        cod_path=Path("/tmp/COCKPIT.COD"),
        proc_name="_DisplayMaster",
        proc_kind="NEAR",
        exit_kind="timeout",
        exit_detail="decompiler CLI reported a recovery timeout",
    )

    assert record == {
        "cod_file": "COCKPIT.COD",
        "proc_name": "_DisplayMaster",
        "proc_kind": "NEAR",
        "tail_validation_uncollected": True,
        "exit_kind": "timeout",
        "exit_detail": "decompiler CLI reported a recovery timeout",
    }


def test_uncollected_tail_validation_record_keeps_proc_identity_for_missing_direct_snapshot():
    function = SimpleNamespace(
        addr=0x119D3,
        name="sub_119d3",
        project=SimpleNamespace(filename="/tmp/LIFE2.EXE", _inertia_lst_metadata=None),
    )
    item = SimpleNamespace(index=1, function=function)
    result = SimpleNamespace(
        status="timeout",
        payload="Timed out after 5s.",
        debug_output="",
        function=function,
        tail_validation=None,
    )

    records = _tail_validation.collect_tail_validation_records([item], {1: result})

    assert records == [
        {
            "cod_file": "LIFE2.EXE",
            "proc_name": "sub_119d3",
            "proc_kind": None,
            "function_addr": 0x119D3,
            "function_name": "sub_119d3",
            "tail_validation_uncollected": True,
            "exit_kind": "timeout",
            "exit_detail": "Timed out after 5s.",
        }
    ]


def test_append_tail_validation_records_empty_metadata_becomes_named_uncollected(tmp_path):
    result = _script.CodWorkResult(
        cod_path=tmp_path / "COCKPIT.COD",
        proc_name="_DisplayMaster",
        proc_kind="NEAR",
        proc_index=4,
        proc_total=9,
        stdout_path=tmp_path / "out.txt",
        stderr="",
        returncode=0,
        exit_kind="ok",
        exit_detail="",
        tail_validation_records=(),
        tail_validation_scanned=1,
    )
    records: list[dict[str, object]] = []

    scanned = _script._append_tail_validation_records_for_result(records, result)

    assert scanned == 1
    assert records == [
        {
            "cod_file": "COCKPIT.COD",
            "proc_name": "_DisplayMaster",
            "proc_kind": "NEAR",
            "tail_validation_uncollected": True,
            "exit_kind": "ok",
            "exit_detail": "tail validation metadata omitted record details",
        }
    ]


def test_append_tail_validation_records_partial_metadata_adds_named_uncollected_gap(tmp_path):
    result = _script.CodWorkResult(
        cod_path=tmp_path / "COCKPIT.COD",
        proc_name="_DoCRT",
        proc_kind="NEAR",
        proc_index=1,
        proc_total=1,
        stdout_path=tmp_path / "out.txt",
        stderr="",
        returncode=0,
        exit_kind="ok",
        exit_detail="",
        tail_validation_records=(
            {
                "cod_file": "COCKPIT.COD",
                "proc_name": "_DoCRT",
                "proc_kind": "NEAR",
                "postprocess": {"changed": True},
            },
        ),
        tail_validation_scanned=2,
    )
    records: list[dict[str, object]] = []

    scanned = _script._append_tail_validation_records_for_result(records, result)

    assert scanned == 2
    assert records == [
        {
            "cod_file": "COCKPIT.COD",
            "proc_name": "_DoCRT",
            "proc_kind": "NEAR",
            "postprocess": {"changed": True},
        },
        {
            "cod_file": "COCKPIT.COD",
            "proc_name": "_DoCRT",
            "proc_kind": "NEAR",
            "tail_validation_uncollected": True,
            "exit_kind": "ok",
            "exit_detail": "tail validation metadata omitted record details",
        },
    ]


def test_append_tail_validation_records_cached_success_gets_proc_identity(tmp_path):
    result = _script.CodWorkResult(
        cod_path=tmp_path / "COCKPIT.COD",
        proc_name="_DisplayMaster",
        proc_kind="NEAR",
        proc_index=4,
        proc_total=9,
        stdout_path=tmp_path / "out.txt",
        stderr="",
        returncode=0,
        exit_kind="ok",
        exit_detail="",
        tail_validation_records=({"postprocess": {"changed": True}},),
        tail_validation_scanned=1,
        from_cache=True,
    )
    records: list[dict[str, object]] = []

    scanned = _script._append_tail_validation_records_for_result(records, result)

    assert scanned == 1
    assert records == [
        {
            "cod_file": "COCKPIT.COD",
            "proc_name": "_DisplayMaster",
            "proc_kind": "NEAR",
            "postprocess": {"changed": True},
        }
    ]


def test_scheduler_timeout_flows_into_named_tail_validation_aggregate(tmp_path, monkeypatch):
    cod_dir = tmp_path / "cod"
    cod_dir.mkdir()
    cod_path = cod_dir / "COCKPIT.COD"
    cod_path.write_bytes(b"PROC")
    item = _script.CodWorkItem(cod_path, "_DisplayMaster", "NEAR", 1, 1, b"\x90")
    captured: dict[str, object] = {}

    class FakeFuture:
        pass

    future = FakeFuture()

    class FakeExecutor:
        def submit(self, *_args, **_kwargs):  # noqa: ANN001
            return future

        def shutdown(self, **_kwargs):  # noqa: ANN003
            return None

    monotonic_values = iter((0.0, 2.0))

    def fake_aggregate(records, *, scanned):  # noqa: ANN001
        captured["records"] = list(records)
        captured["scanned"] = scanned
        return {"summary": {}, "surface": {"severity": "uncollected"}}

    monkeypatch.setattr(sys, "argv", ["decompile_cod_dir.py", str(cod_dir), "--max-workers", "2", "--subprocess-timeout", "1"])
    monkeypatch.setattr(_script, "_resolve_selected_cod_files", lambda *_args, **_kwargs: [cod_path])
    monkeypatch.setattr(_script, "_build_work_items", lambda _path: [item])
    monkeypatch.setattr(_script, "_choose_parallelism", lambda *_args, **_kwargs: 2)
    monkeypatch.setattr(_script, "_determine_worker_memory_limit_mb", lambda *_args, **_kwargs: 1024)
    monkeypatch.setattr(_script, "_load_success_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(_script, "_make_executor", lambda *_args, **_kwargs: FakeExecutor())
    monkeypatch.setattr(_script, "wait", lambda pending, timeout, return_when: (set(), pending))
    monkeypatch.setattr(_script.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(_script, "build_x86_16_tail_validation_aggregate", fake_aggregate)
    monkeypatch.setattr(_script, "compare_x86_16_tail_validation_baseline", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(_script, "annotate_x86_16_tail_validation_surface_with_baseline", lambda surface, _comparison: surface)
    monkeypatch.setattr(_script, "emit_tail_validation_surface_summary", lambda **_kwargs: None)

    assert _script.main() == 1
    assert captured == {
        "records": [
            {
                "cod_file": "COCKPIT.COD",
                "proc_name": "_DisplayMaster",
                "proc_kind": "NEAR",
                "tail_validation_uncollected": True,
                "exit_kind": "subprocess_timeout",
                "exit_detail": "worker pool scheduler timeout after 1s",
            }
        ],
        "scanned": 1,
    }


def test_main_emits_changed_tail_validation_detail_summary_to_stderr(tmp_path, monkeypatch, capsys):
    cod_dir = tmp_path / "cod"
    cod_dir.mkdir()
    cod_path = cod_dir / "COCKPIT.COD"
    cod_path.write_bytes(b"PROC")
    item = _script.CodWorkItem(cod_path, "_DisplayMaster", "NEAR", 1, 1, b"\x90")
    stdout_path = tmp_path / "out.txt"
    stdout_path.write_text("/* == c == */\nvoid _DisplayMaster(void) {}\n", encoding="utf-8")
    result = _script.CodWorkResult(
        cod_path=cod_path,
        proc_name="_DisplayMaster",
        proc_kind="NEAR",
        proc_index=1,
        proc_total=1,
        stdout_path=stdout_path,
        stderr="",
        returncode=0,
        exit_kind="ok",
        exit_detail="",
        tail_validation_records=(
            {
                "cod_file": "COCKPIT.COD",
                "proc_name": "_DisplayMaster",
                "proc_kind": "NEAR",
                "postprocess": {
                    "changed": True,
                    "mode": "live_out",
                    "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
                    "summary_text": "helper_calls: +helper_ping",
                },
            },
        ),
        tail_validation_scanned=1,
        from_cache=True,
    )

    monkeypatch.setattr(sys, "argv", ["decompile_cod_dir.py", str(cod_dir)])
    monkeypatch.setattr(_script, "_resolve_selected_cod_files", lambda *_args, **_kwargs: [cod_path])
    monkeypatch.setattr(_script, "_build_work_items", lambda _path: [item])
    monkeypatch.setattr(_script, "_choose_parallelism", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(_script, "_determine_worker_memory_limit_mb", lambda *_args, **_kwargs: 1024)
    monkeypatch.setattr(_script, "_load_success_cache", lambda *_args, **_kwargs: result)
    monkeypatch.setattr(_script, "_load_tail_validation_baseline", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(_script, "_TAIL_VALIDATION_CONSOLE_CACHE_DIR", tmp_path / ".cache" / "console")
    monkeypatch.setattr(_script, "_TAIL_VALIDATION_DETAIL_DIR", tmp_path / ".cache" / "detail")

    assert _script.main() == 0
    captured = capsys.readouterr()
    detail_path = _script._default_tail_validation_detail_path(cod_dir, timeout=20, cod_files=[cod_path], proc_names=None)
    detail_files = sorted(detail_path.parent.glob("COCKPIT.timeout20.tail_validation_surface.*.json"))

    assert "[tail-validation] whole-tail validation failed across 1 functions" in captured.err
    assert detail_files
    assert f"[tail-validation] detail artifact {detail_files[0]}" in captured.err
    assert "[tail-validation]" not in captured.out


def test_main_emits_uncollected_tail_validation_detail_summary_to_stderr(tmp_path, monkeypatch, capsys):
    cod_dir = tmp_path / "cod"
    cod_dir.mkdir()
    cod_path = cod_dir / "COCKPIT.COD"
    cod_path.write_bytes(b"PROC")
    item = _script.CodWorkItem(cod_path, "_DisplayMaster", "NEAR", 1, 1, b"\x90")
    stdout_path = tmp_path / "out.txt"
    stdout_path.write_text("/* timeout after 20s */\n", encoding="utf-8")
    result = _script.CodWorkResult(
        cod_path=cod_path,
        proc_name="_DisplayMaster",
        proc_kind="NEAR",
        proc_index=1,
        proc_total=1,
        stdout_path=stdout_path,
        stderr="",
        returncode=0,
        exit_kind="subprocess_timeout",
        exit_detail="worker pool scheduler timeout after 20s",
        tail_validation_records=(),
        tail_validation_scanned=1,
        from_cache=True,
    )

    monkeypatch.setattr(sys, "argv", ["decompile_cod_dir.py", str(cod_dir)])
    monkeypatch.setattr(_script, "_resolve_selected_cod_files", lambda *_args, **_kwargs: [cod_path])
    monkeypatch.setattr(_script, "_build_work_items", lambda _path: [item])
    monkeypatch.setattr(_script, "_choose_parallelism", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(_script, "_determine_worker_memory_limit_mb", lambda *_args, **_kwargs: 1024)
    monkeypatch.setattr(_script, "_load_success_cache", lambda *_args, **_kwargs: result)
    monkeypatch.setattr(_script, "_load_tail_validation_baseline", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(_script, "_TAIL_VALIDATION_CONSOLE_CACHE_DIR", tmp_path / ".cache" / "console")
    monkeypatch.setattr(_script, "_TAIL_VALIDATION_DETAIL_DIR", tmp_path / ".cache" / "detail")

    assert _script.main() == 1
    captured = capsys.readouterr()
    detail_path = _script._default_tail_validation_detail_path(cod_dir, timeout=20, cod_files=[cod_path], proc_names=None)
    detail_files = sorted(detail_path.parent.glob("COCKPIT.timeout20.tail_validation_surface.*.json"))

    assert "[tail-validation] whole-tail validation not collected across 1 functions" in captured.err
    assert detail_files
    assert f"[tail-validation] detail artifact {detail_files[0]}" in captured.err
    assert "[tail-validation]" not in captured.out


def test_main_flushes_stdout_before_tail_validation_summary(tmp_path, monkeypatch):
    cod_dir = tmp_path / "cod"
    cod_dir.mkdir()
    cod_path = cod_dir / "COCKPIT.COD"
    cod_path.write_bytes(b"PROC")
    item = _script.CodWorkItem(cod_path, "_DisplayMaster", "NEAR", 1, 1, b"\x90")
    stdout_path = tmp_path / "out.txt"
    stdout_path.write_text("/* == c == */\nvoid _DisplayMaster(void) {}\n", encoding="utf-8")
    result = _script.CodWorkResult(
        cod_path=cod_path,
        proc_name="_DisplayMaster",
        proc_kind="NEAR",
        proc_index=1,
        proc_total=1,
        stdout_path=stdout_path,
        stderr="",
        returncode=0,
        exit_kind="ok",
        exit_detail="",
        tail_validation_records=(
            {
                "cod_file": "COCKPIT.COD",
                "proc_name": "_DisplayMaster",
                "proc_kind": "NEAR",
                "postprocess": {"changed": True},
            },
        ),
        tail_validation_scanned=1,
        from_cache=True,
    )

    class FakeStdout:
        def __init__(self) -> None:
            self.parts: list[str] = []
            self.flushed = False

        def write(self, text: str) -> int:
            self.parts.append(text)
            return len(text)

        def flush(self) -> None:
            self.flushed = True

    fake_stdout = FakeStdout()
    seen: dict[str, bool] = {}

    def fake_emit(**_kwargs):  # noqa: ANN001
        seen["flushed_before_emit"] = fake_stdout.flushed

    monkeypatch.setattr(sys, "argv", ["decompile_cod_dir.py", str(cod_dir)])
    monkeypatch.setattr(_script, "_resolve_selected_cod_files", lambda *_args, **_kwargs: [cod_path])
    monkeypatch.setattr(_script, "_build_work_items", lambda _path: [item])
    monkeypatch.setattr(_script, "_choose_parallelism", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(_script, "_determine_worker_memory_limit_mb", lambda *_args, **_kwargs: 1024)
    monkeypatch.setattr(_script, "_load_success_cache", lambda *_args, **_kwargs: result)
    monkeypatch.setattr(_script, "_load_tail_validation_baseline", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(_script, "emit_tail_validation_surface_summary", fake_emit)
    monkeypatch.setattr(_script.sys, "stdout", fake_stdout)

    assert _script.main() == 0
    assert seen == {"flushed_before_emit": True}


def test_wrapper_and_direct_tail_validation_detail_cache_path_contract_match(tmp_path, monkeypatch, capsys):
    cod_dir = tmp_path / "cod"
    cod_dir.mkdir()
    cod_path = cod_dir / "COCKPIT.COD"
    cod_path.write_bytes(b"PROC")
    snapshot = {
        "structuring": {
            "changed": False,
            "mode": "live_out",
            "verdict": "structuring stable",
            "summary_text": "no observable delta",
        },
        "postprocess": {
            "changed": True,
            "mode": "live_out",
            "verdict": "postprocess whole-tail validation [live_out] changed: helper_calls: +helper_ping",
            "summary_text": "helper_calls: +helper_ping",
        },
    }
    item = _script.CodWorkItem(cod_path, "_DisplayMaster", "NEAR", 1, 1, b"\x90")
    stdout_path = tmp_path / "out.txt"
    stdout_path.write_text("/* == c == */\nvoid _DisplayMaster(void) {}\n", encoding="utf-8")
    result = _script.CodWorkResult(
        cod_path=cod_path,
        proc_name="_DisplayMaster",
        proc_kind="NEAR",
        proc_index=1,
        proc_total=1,
        stdout_path=stdout_path,
        stderr="",
        returncode=0,
        exit_kind="ok",
        exit_detail="",
        tail_validation_records=(
            {
                "cod_file": "COCKPIT.COD",
                "proc_name": "_DisplayMaster",
                "proc_kind": "NEAR",
                **snapshot,
            },
        ),
        tail_validation_scanned=1,
        from_cache=True,
    )

    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_STDERR_JSON", "1")
    monkeypatch.setattr(_script, "_TAIL_VALIDATION_CONSOLE_CACHE_DIR", tmp_path / ".cache" / "cod-console")
    monkeypatch.setattr(_script, "_TAIL_VALIDATION_DETAIL_DIR", tmp_path / ".cache" / "cod-detail")
    monkeypatch.setattr(_tail_validation, "TAIL_VALIDATION_CONSOLE_CACHE_DIR", tmp_path / ".cache" / "direct-console")
    monkeypatch.setattr(_tail_validation, "TAIL_VALIDATION_DETAIL_CACHE_DIR", tmp_path / ".cache" / "direct-detail")

    monkeypatch.setattr(sys, "argv", ["decompile_cod_dir.py", str(cod_dir)])
    monkeypatch.setattr(_script, "_resolve_selected_cod_files", lambda *_args, **_kwargs: [cod_path])
    monkeypatch.setattr(_script, "_build_work_items", lambda _path: [item])
    monkeypatch.setattr(_script, "_choose_parallelism", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(_script, "_determine_worker_memory_limit_mb", lambda *_args, **_kwargs: 1024)
    monkeypatch.setattr(_script, "_load_success_cache", lambda *_args, **_kwargs: result)
    monkeypatch.setattr(_script, "_load_tail_validation_baseline", lambda *_args, **_kwargs: None)

    assert _script.main() == 0
    wrapper_metadata = _tail_validation_metadata_payload(capsys.readouterr().err)

    project = SimpleNamespace(_inertia_tail_validation_enabled=True)
    function = SimpleNamespace(addr=0x10010, name="_DisplayMaster", project=project)
    direct_item = SimpleNamespace(index=1, function_cfg=SimpleNamespace(), function=function)
    direct_result = SimpleNamespace(tail_validation=snapshot, function=function)

    _tail_validation.emit_tail_validation_console_summary([direct_item], {1: direct_result}, binary_path=cod_path)
    direct_metadata = _tail_validation_metadata_payload(capsys.readouterr().err)

    assert wrapper_metadata["surface"]["severity"] == direct_metadata["surface"]["severity"] == "changed"
    assert wrapper_metadata["surface"]["headline"] == direct_metadata["surface"]["headline"]
    assert wrapper_metadata["detail_cache_path"] is not None
    assert direct_metadata["detail_cache_path"] is not None
    assert wrapper_metadata["console_cache_path"] is not None
    assert direct_metadata["console_cache_path"] is not None


def test_tail_validation_baseline_helpers_round_trip(tmp_path, monkeypatch):
    cod_dir = tmp_path / "default"
    cod_dir.mkdir()
    cod_file = cod_dir / "DOSFUNC.COD"
    cod_file.write_bytes(b"")
    monkeypatch.setattr(_script, "_TAIL_VALIDATION_BASELINE_DIR", tmp_path / ".cache" / "tail_validation_baselines")
    baseline_path = _script._default_tail_validation_baseline_path(cod_dir, timeout=3, cod_files=[cod_file])
    baseline = {"version": 1, "entries": [{"proc_name": "_dos_alloc"}], "entry_count": 1}

    assert baseline_path.name == "DOSFUNC.timeout3.json"
    assert _script._load_tail_validation_baseline(baseline_path) is None

    _script._write_tail_validation_baseline(baseline_path, baseline)

    assert json.loads(baseline_path.read_text()) == baseline
    assert _script._load_tail_validation_baseline(baseline_path) == baseline


def test_tail_validation_cache_paths_are_stable_for_single_file_corpus(tmp_path, monkeypatch):
    cod_dir = tmp_path / "corpus"
    cod_dir.mkdir()
    cod_file = cod_dir / "DOSFUNC.COD"
    cod_file.write_bytes(b"\x90")
    monkeypatch.setattr(_script, "_TAIL_VALIDATION_CONSOLE_CACHE_DIR", tmp_path / ".cache" / "decompile_cod_dir")
    monkeypatch.setattr(_script, "_TAIL_VALIDATION_DETAIL_DIR", tmp_path / ".cache" / "tail_validation_details")

    console_path = _script._default_tail_validation_console_cache_path(cod_dir, timeout=3, cod_files=[cod_file])
    detail_path = _script._default_tail_validation_detail_path(cod_dir, timeout=3, cod_files=[cod_file])

    assert console_path.name == "DOSFUNC.timeout3.tail_validation_console.json"
    assert detail_path.name == "DOSFUNC.timeout3.tail_validation_surface.json"


def test_resolve_selected_cod_files_accepts_relative_and_basename(tmp_path):
    cod_dir = tmp_path / "cod"
    subdir = cod_dir / "f14"
    subdir.mkdir(parents=True)
    cockpit = subdir / "COCKPIT.COD"
    planes = subdir / "PLANES3.COD"
    cockpit.write_bytes(b"")
    planes.write_bytes(b"")

    selected = _script._resolve_selected_cod_files(cod_dir, ["f14/COCKPIT.COD", "PLANES3.COD"])

    assert selected == [cockpit, planes]


def test_filter_work_items_by_proc_names_reindexes_selected_items(tmp_path):
    items = [
        _script.CodWorkItem(tmp_path / "COCKPIT.COD", "_DoCRT", "NEAR", 1, 3, b"\x90"),
        _script.CodWorkItem(tmp_path / "COCKPIT.COD", "_DisplayMaster", "NEAR", 2, 3, b"\x90"),
        _script.CodWorkItem(tmp_path / "COCKPIT.COD", "_Other", "NEAR", 3, 3, b"\x90"),
    ]

    selected = _script._filter_work_items_by_proc_names(items, ["_displaymaster"])

    assert [(item.proc_name, item.proc_index, item.proc_total) for item in selected] == [
        ("_DisplayMaster", 1, 1)
    ]


def test_tail_validation_cache_paths_include_proc_selection(tmp_path, monkeypatch):
    cod_dir = tmp_path / "corpus"
    cod_dir.mkdir()
    cod_file = cod_dir / "COCKPIT.COD"
    cod_file.write_bytes(b"\x90")
    monkeypatch.setattr(_script, "_TAIL_VALIDATION_DETAIL_DIR", tmp_path / ".cache" / "tail_validation_details")

    detail_path = _script._default_tail_validation_detail_path(
        cod_dir,
        timeout=3,
        cod_files=[cod_file],
        proc_names=["_DisplayMaster"],
    )

    assert detail_path.name == "COCKPIT-_DisplayMaster.timeout3.tail_validation_surface.json"
