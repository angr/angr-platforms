from angr_platforms.X86_16.readability_goals import (
    classify_readability_cluster,
    describe_x86_16_readability_goals,
    rank_readability_goal_queue,
    summarize_readability_focus,
    summarize_readability_goals,
)


def test_x86_16_readability_goal_surface_is_deterministic():
    goals = describe_x86_16_readability_goals()

    assert [goal[0] for goal in goals] == ["4.1", "4.2", "4.3"]
    assert goals[0][1] == "Fix the top ugly clusters, not isolated outputs"
    assert "alias and widening" in goals[1][2]
    assert "trait evidence" in goals[2][2].lower()


def test_x86_16_readability_cluster_classifier_matches_known_patterns():
    assert classify_readability_cluster("return (low << 8) | high;") == (
        "byte_pair_arithmetic",
        "Byte-pair arithmetic still survives in the text instead of widening earlier.",
    )
    assert classify_readability_cluster("if (local_4 == 0 && local_6 != 0)") == (
        "fake_locals_and_stack_noise",
        "Stack material is still rendered as noisy locals or raw stack offsets.",
    )
    assert classify_readability_cluster("sub_1234(a, b)") == (
        "weak_helper_signatures",
        "Helpers still look synthetic or weakly named.",
    )


def test_x86_16_readability_goal_summary_counts_targets():
    summary = summarize_readability_goals(
        [{"cluster": "byte_pair_arithmetic", "count": 1}],
        [
            {"cluster": "byte_pair_arithmetic", "count": 3},
            {"cluster": "boolean_noise", "count": 2},
            {"cluster": "fake_locals_and_stack_noise", "count": 4},
        ],
        {"top_ugly_clusters": [{"family": "alias_widening", "cluster": "byte_pair_arithmetic", "count": 3}]},
    )

    assert summary[0]["observed_cluster_count"] == 9
    assert summary[0]["observed_family_count"] == 3
    assert summary[1]["observed_cluster_count"] == 7
    assert summary[2]["observed_cluster_count"] == 4


def test_x86_16_readability_goal_queue_prioritizes_hot_clusters():
    summary = summarize_readability_goals(
        [{"cluster": "byte_pair_arithmetic", "count": 1}],
        [
            {"cluster": "byte_pair_arithmetic", "count": 3},
            {"cluster": "boolean_noise", "count": 2},
            {"cluster": "fake_locals_and_stack_noise", "count": 4},
        ],
        {"top_ugly_clusters": [{"family": "alias_widening", "cluster": "byte_pair_arithmetic", "count": 3}]},
    )

    queue = rank_readability_goal_queue(summary)

    assert [item["step"] for item in queue] == ["4.1", "4.2", "4.3"]
    assert queue[0]["is_next_focus"] is True
    assert queue[0]["observed_cluster_count"] == 9
    assert queue[1]["observed_cluster_count"] == 7


def test_x86_16_readability_focus_surface_keeps_queue_and_clusters():
    focus = summarize_readability_focus(
        [{"cluster": "byte_pair_arithmetic", "count": 1}],
        [{"cluster": "boolean_noise", "count": 2}],
        {"top_ugly_clusters": [{"family": "alias_widening", "cluster": "byte_pair_arithmetic", "count": 3}]},
    )

    assert focus["next_goal"]["step"] == "4.1"
    assert focus["goal_queue"][0]["rank"] == 1
    assert focus["top_ugly_clusters"][0]["cluster"] == "byte_pair_arithmetic"
