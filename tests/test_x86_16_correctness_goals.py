from angr_platforms.X86_16.correctness_goals import (
    CORRECTNESS_GOALS,
    describe_x86_16_correctness_goals,
    summarize_x86_16_correctness_goals,
)


def test_x86_16_correctness_goals_surface_is_deterministic():
    assert [goal.code for goal in CORRECTNESS_GOALS] == ["C6.1", "C6.2", "C6.3", "C6.4"]
    assert describe_x86_16_correctness_goals() == tuple(
        (goal.code, goal.title, goal.priority, goal.status, goal.owner_surfaces, goal.completion_signal)
        for goal in CORRECTNESS_GOALS
    )


def test_x86_16_correctness_goal_summary_reports_completion():
    assert summarize_x86_16_correctness_goals() == {
        "total": 4,
        "landed": 4,
        "partial": 0,
        "open": 0,
        "strict_percent": 100.0,
        "weighted_percent": 100.0,
        "landed_codes": ("C6.1", "C6.2", "C6.3", "C6.4"),
        "partial_codes": (),
        "open_codes": (),
    }
