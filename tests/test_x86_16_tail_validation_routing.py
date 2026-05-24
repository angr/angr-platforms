from angr_platforms.X86_16.tail_validation_routing import build_tail_validation_family_routing


def test_tail_validation_family_routing_rows_are_stable_and_mapped():
    changed = [
        {
            "family": "stack write delta",
            "count": 1,
            "function_count": 1,
            "stages": ["postprocess"],
        },
        {
            "family": "control-flow/guard delta",
            "count": 31,
            "function_count": 28,
            "stages": ["postprocess", "structuring"],
        },
        {
            "family": "unclassified observable delta",
            "count": 2,
            "function_count": 2,
            "stages": ["postprocess"],
        },
    ]

    rows = build_tail_validation_family_routing(changed)

    assert [row["family"] for row in rows] == [
        "control-flow/guard delta",
        "unclassified observable delta",
        "stack write delta",
    ]

    control = rows[0]
    assert control["likely_layer"] == "structuring"
    assert control["next_root_cause_file"].endswith("structuring_sequences.py")
    assert "guard" in control["signal"]

    stack = rows[-1]
    assert stack["likely_layer"] == "postprocess/stack"
    assert stack["next_root_cause_file"].endswith("decompiler_postprocess_simplify.py")
    assert "stack write" in stack["signal"]

    unclassified = rows[1]
    assert unclassified["likely_layer"] == "triage"
    assert unclassified["next_root_cause_file"].endswith("tail_validation.py")
