from __future__ import annotations

from inertia_decompiler.slice_recovery import (
    SliceRecoveryAttemptOutcome,
    SliceRecoveryAttemptTrace,
    _build_bounded_slice_verdict,
    run_bounded_slice_recovery,
)


def test_build_bounded_slice_verdict_marks_recover_timeout_as_retryable() -> None:
    verdict = _build_bounded_slice_verdict(
        SliceRecoveryAttemptTrace(failure_stage="recover"),
        status="timeout",
        partial_payload=None,
    )

    assert verdict.stage == "recover"
    assert verdict.stop_family == "timeout"
    assert verdict.can_widen_locally is True
    assert verdict.can_retry_with_fresh_project is True


def test_build_bounded_slice_verdict_marks_decompile_partial_timeout_as_preserve_only() -> None:
    verdict = _build_bounded_slice_verdict(
        SliceRecoveryAttemptTrace(failure_stage="decompile"),
        status="timeout",
        partial_payload="int partial(void) { return 1; }",
    )

    assert verdict.stage == "decompile"
    assert verdict.stop_family == "partial-timeout"
    assert verdict.can_widen_locally is False
    assert verdict.can_retry_with_fresh_project is False


def test_run_bounded_slice_recovery_marks_repeated_timeout_family_as_dead_local() -> None:
    attempts = (
        ("lean", lambda _project: (_project, _project)),
        ("full-no-refs", lambda _project: (_project, _project)),
        ("full-with-refs", lambda _project: (_project, _project)),
    )

    outcomes = run_bounded_slice_recovery(
        attempts,
        build_slice_project=lambda: object(),
        inherit_runtime_policy=lambda _project: None,
        describe_exception=str,
        decompile=lambda attempt_name, *_args: SliceRecoveryAttemptOutcome(
            attempt_name=attempt_name,
            status="ok",
            payload="ok",
        ),
        run_attempt=lambda attempt_name, _job, _trace_snapshot: SliceRecoveryAttemptOutcome(
            attempt_name=attempt_name,
            status="timeout",
            payload="Timed out after 4s.",
            attempt_trace=SliceRecoveryAttemptTrace(failure_stage="recover"),
        ),
    )

    assert [outcome.attempt_name for outcome in outcomes] == ["lean", "full-no-refs"]
    assert outcomes[0].verdict is not None
    assert outcomes[0].verdict.can_widen_locally is True
    assert outcomes[1].verdict is not None
    assert outcomes[1].verdict.can_widen_locally is False
    assert outcomes[1].verdict.stop_family == "timeout"


def test_run_bounded_slice_recovery_stops_after_partial_timeout() -> None:
    attempts = (
        ("lean", lambda _project: (_project, _project)),
        ("full-no-refs", lambda _project: (_project, _project)),
    )

    outcomes = run_bounded_slice_recovery(
        attempts,
        build_slice_project=lambda: object(),
        inherit_runtime_policy=lambda _project: None,
        describe_exception=str,
        decompile=lambda attempt_name, *_args: SliceRecoveryAttemptOutcome(
            attempt_name=attempt_name,
            status="timeout",
            payload="Timed out after 4s.",
            partial_payload="int partial(void) { return 1; }",
            attempt_trace=SliceRecoveryAttemptTrace(failure_stage="decompile"),
        ),
    )

    assert [outcome.attempt_name for outcome in outcomes] == ["lean"]
    assert outcomes[0].verdict is not None
    assert outcomes[0].verdict.stop_family == "partial-timeout"
    assert outcomes[0].verdict.can_widen_locally is False


def test_run_bounded_slice_recovery_keeps_retrying_after_repeated_empty_results() -> None:
    attempts = (
        ("lean", lambda _project: (_project, _project)),
        ("full-no-refs", lambda _project: (_project, _project)),
        ("full-with-refs", lambda _project: (_project, _project)),
    )

    outcomes = run_bounded_slice_recovery(
        attempts,
        build_slice_project=lambda: object(),
        inherit_runtime_policy=lambda _project: None,
        describe_exception=str,
        decompile=lambda attempt_name, *_args: SliceRecoveryAttemptOutcome(
            attempt_name=attempt_name,
            status="empty",
            payload="No decompilation produced.",
            attempt_trace=SliceRecoveryAttemptTrace(failure_stage="decompile"),
        ),
    )

    assert [outcome.attempt_name for outcome in outcomes] == [
        "lean",
        "full-no-refs",
        "full-with-refs",
    ]
    assert all(outcome.verdict is not None and outcome.verdict.stop_family == "empty" for outcome in outcomes)
    assert all(outcome.verdict is not None and outcome.verdict.can_widen_locally is True for outcome in outcomes)
