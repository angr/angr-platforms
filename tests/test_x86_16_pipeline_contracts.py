from __future__ import annotations

"""Test the pipeline contracts: SemanticLaneState and assert_closed_loop."""

import pytest

from angr_platforms.angr_platforms.X86_16.pipeline.errors import PipelineHardError
from angr_platforms.angr_platforms.X86_16.pipeline.contracts import (
    SemanticLaneState,
    assert_pipeline_contracts_8616,
)


class TestSemanticLaneState:
    """Unit tests for SemanticLaneState."""

    def test_empty_state_is_closed(self):
        lane = SemanticLaneState(name="test")
        assert lane.is_closed
        # assert_closed_loop should not raise
        lane.assert_closed_loop(layer="test")

    def test_classified_without_materialized_raises(self):
        lane = SemanticLaneState(
            name="test",
            raw=5,
            normalized=5,
            classified=3,
            materialized=0,
        )
        assert not lane.is_closed
        with pytest.raises(PipelineHardError, match="classified but 0 materialized"):
            lane.assert_closed_loop(layer="test")

    def test_bound_without_materialized_raises(self):
        lane = SemanticLaneState(
            name="test",
            raw=5,
            normalized=5,
            classified=3,
            bound=3,
            materialized=0,
        )
        assert not lane.is_closed
        with pytest.raises(PipelineHardError, match="bindings created but 0 materialized"):
            lane.assert_closed_loop(layer="test")

    def test_classified_and_materialized_is_closed(self):
        lane = SemanticLaneState(
            name="test",
            raw=5,
            normalized=5,
            classified=3,
            bound=3,
            materialized=3,
        )
        assert lane.is_closed
        # should not raise
        lane.assert_closed_loop(layer="test")

    def test_to_dict(self):
        lane = SemanticLaneState(
            name="stack",
            raw=10,
            normalized=8,
            classified=5,
            bound=5,
            materialized=5,
            verified=5,
            failures=1,
        )
        d = lane.to_dict()
        assert d["name"] == "stack"
        assert d["raw"] == 10
        assert d["materialized"] == 5

    def test_summary_line(self):
        lane = SemanticLaneState(
            name="condition",
            raw=3,
            normalized=3,
            classified=3,
            materialized=3,
        )
        line = lane.summary_line()
        assert "condition" in line
        assert "CLOSED" in line
        assert "raw=3" in line

    def test_summary_line_broken(self):
        lane = SemanticLaneState(
            name="stack",
            raw=5,
            normalized=5,
            classified=3,
            materialized=0,
        )
        line = lane.summary_line()
        assert "BROKEN" in line


class TestAssertPipelineContracts:
    """Test integration: assert_pipeline_contracts_8616."""

    def test_no_lanes_no_error(self):
        """When no lanes are set, no error should be raised."""
        codegen = type("Codegen", (), {})()
        # Should not raise
        assert_pipeline_contracts_8616(codegen)

    def test_closed_lanes_no_error(self):
        """Both lanes closed → no error."""
        codegen = type("Codegen", (), {})()
        codegen._inertia_stack_lane = SemanticLaneState(
            name="stack",
            raw=5,
            normalized=5,
            classified=3,
            materialized=3,
        )
        codegen._inertia_condition_lane = SemanticLaneState(
            name="condition",
            raw=2,
            normalized=2,
            classified=2,
            materialized=2,
        )
        # Should not raise
        assert_pipeline_contracts_8616(codegen)

    def test_broken_stack_raises(self):
        """Broken stack lane → PipelineHardError."""
        codegen = type("Codegen", (), {})()
        codegen._inertia_stack_lane = SemanticLaneState(
            name="stack",
            raw=5,
            normalized=5,
            classified=3,
            bound=3,
            materialized=0,
        )
        codegen._inertia_condition_lane = SemanticLaneState(
            name="condition",
            raw=0,
            normalized=0,
            classified=0,
        )
        with pytest.raises(PipelineHardError, match="bindings created but 0 materialized"):
            assert_pipeline_contracts_8616(codegen)

    def test_broken_condition_raises(self):
        """Broken condition lane → PipelineHardError."""
        codegen = type("Codegen", (), {})()
        codegen._inertia_stack_lane = SemanticLaneState(
            name="stack",
            raw=0,
            normalized=0,
            classified=0,
        )
        codegen._inertia_condition_lane = SemanticLaneState(
            name="condition",
            raw=3,
            normalized=3,
            classified=3,
            materialized=0,
        )
        with pytest.raises(PipelineHardError, match="classified but 0 materialized"):
            assert_pipeline_contracts_8616(codegen)