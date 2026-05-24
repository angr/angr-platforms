"""
Tests for structuring_diagnostics module (Phase 4.2).

Tests failure classification, diagnostics collection, recovery hints,
and integration with structuring analysis.
"""

import pytest

from angr_platforms.X86_16.structuring_diagnostics import (
    DiagnosticsCollector,
    StructuringDiagnostic,
    StructuringDiagnosticsReport,
    StructuringFailureReason,
    apply_x86_16_structuring_diagnostics,
    build_failure_reason_from_stats,
    suggest_recovery_hints,
)


class TestStructuringFailureReason:
    """Test failure reason classification."""

    def test_all_reasons_defined(self):
        """Test all failure reasons are defined."""
        reasons = [
            StructuringFailureReason.MAX_ITERATIONS,
            StructuringFailureReason.NO_PROGRESS,
            StructuringFailureReason.TIMEOUT,
            StructuringFailureReason.MIXED_ENTRY_EXIT,
            StructuringFailureReason.UNSUPPORTED_PATTERN,
            StructuringFailureReason.RESOURCE_LIMIT,
            StructuringFailureReason.UNKNOWN,
        ]
        assert len(reasons) == 7

    def test_reason_values(self):
        """Test reason enum values."""
        assert StructuringFailureReason.MAX_ITERATIONS.value == "max_iterations"
        assert StructuringFailureReason.NO_PROGRESS.value == "no_progress"
        assert StructuringFailureReason.TIMEOUT.value == "timeout"


class TestStructuringDiagnostic:
    """Test diagnostic entries."""

    def test_diagnostic_creation_basic(self):
        """Test basic diagnostic creation."""
        diag = StructuringDiagnostic(
            kind="failure",
            message="max iterations reached",
        )
        assert diag.kind == "failure"
        assert diag.message == "max iterations reached"
        assert diag.iteration == 0
        assert diag.reason is None
        assert len(diag.region_ids) == 0

    def test_diagnostic_with_regions(self):
        """Test diagnostic with region IDs."""
        diag = StructuringDiagnostic(
            kind="warning",
            message="mixed entry/exit in regions",
            region_ids=(1, 2, 3),
            iteration=500,
            reason=StructuringFailureReason.MIXED_ENTRY_EXIT,
        )
        assert len(diag.region_ids) == 3
        assert diag.iteration == 500
        assert diag.reason == StructuringFailureReason.MIXED_ENTRY_EXIT

    def test_diagnostic_immutable(self):
        """Test diagnostic is immutable (frozen)."""
        diag = StructuringDiagnostic(kind="progress", message="test")
        with pytest.raises(AttributeError):
            diag.kind = "changed"


class TestDiagnosticsCollector:
    """Test diagnostics collection."""

    def test_collector_creation(self):
        """Test collector creation."""
        collector = DiagnosticsCollector()
        assert collector.current_iteration == 0
        assert collector.max_iterations == 1000
        assert len(collector.diagnostics) == 0

    def test_update_iteration(self):
        """Test updating iteration counter."""
        collector = DiagnosticsCollector()
        collector.record_iteration(100)
        assert collector.current_iteration == 100
        collector.record_iteration(500)
        assert collector.current_iteration == 500

    def test_add_progress(self):
        """Test adding progress diagnostic."""
        collector = DiagnosticsCollector()
        collector.record_iteration(10)
        collector.add_progress("simplified 5 regions", region_ids=(1, 2, 3))
        assert collector.progress_count() == 1
        assert collector.diagnostics[-1].kind == "progress"
        assert collector.diagnostics[-1].iteration == 10

    def test_add_warning(self):
        """Test adding warning diagnostic."""
        collector = DiagnosticsCollector()
        collector.add_warning("potential infinite loop detected", region_ids=(42,))
        assert collector.warning_count() == 1
        assert collector.diagnostics[-1].kind == "warning"

    def test_add_failure(self):
        """Test adding failure diagnostic."""
        collector = DiagnosticsCollector()
        collector.record_iteration(1000)
        collector.add_failure(
            "reached iteration limit",
            reason=StructuringFailureReason.MAX_ITERATIONS,
        )
        assert collector.failure_count() == 1
        assert collector.diagnostics[-1].kind == "failure"
        assert collector.diagnostics[-1].reason == StructuringFailureReason.MAX_ITERATIONS

    def test_multiple_diagnostics(self):
        """Test collecting multiple diagnostics."""
        collector = DiagnosticsCollector()
        collector.add_progress("step 1")
        collector.add_progress("step 2")
        collector.add_warning("step 3")
        collector.add_failure("step 4", reason=StructuringFailureReason.NO_PROGRESS)
        assert len(collector.diagnostics) == 4
        assert collector.progress_count() == 2
        assert collector.warning_count() == 1
        assert collector.failure_count() == 1

    def test_to_dict(self):
        """Test conversion to dictionary."""
        collector = DiagnosticsCollector()
        collector.record_iteration(50)
        collector.add_progress("progress msg")
        collector.add_warning("warning msg")
        d = collector.to_dict()
        assert d["total_diagnostics"] == 2
        assert d["progress"] == 1
        assert d["warnings"] == 1
        assert d["failures"] == 0
        assert d["current_iteration"] == 50


class TestStructuringDiagnosticsReport:
    """Test structuring failure reports."""

    def test_report_creation_success(self):
        """Test creating report for successful structuring."""
        collector = DiagnosticsCollector()
        report = StructuringDiagnosticsReport(
            func_addr=0x1000,
            func_name="main",
            succeeded=True,
            final_iteration=250,
            max_iterations=1000,
            diagnostics_collector=collector,
        )
        assert report.succeeded is True
        assert report.final_iteration == 250
        assert report.func_name == "main"
        assert report.cfg_snapshot is None

    def test_report_creation_failure(self):
        """Test creating report for failed structuring."""
        collector = DiagnosticsCollector()
        collector.add_failure(
            "no progress",
            reason=StructuringFailureReason.NO_PROGRESS,
        )
        report = StructuringDiagnosticsReport(
            func_addr=0x2000,
            func_name="handler",
            succeeded=False,
            final_iteration=1000,
            max_iterations=1000,
            diagnostics_collector=collector,
            failure_reason=StructuringFailureReason.NO_PROGRESS,
        )
        assert report.succeeded is False
        assert report.final_iteration == 1000

    def test_add_recovery_hint(self):
        """Test adding recovery hints."""
        collector = DiagnosticsCollector()
        report = StructuringDiagnosticsReport(
            func_addr=0x3000,
            func_name="process",
            succeeded=False,
            final_iteration=1000,
            max_iterations=1000,
            diagnostics_collector=collector,
        )
        report.add_recovery_hint("check for indirect jumps")
        report.add_recovery_hint("look for tail calls")
        assert len(report.recovery_hints) == 2

    def test_last_failure_reason(self):
        """Test getting last failure reason."""
        collector = DiagnosticsCollector()
        collector.add_progress("progress 1")
        collector.add_failure(
            "first failure",
            reason=StructuringFailureReason.UNSUPPORTED_PATTERN,
        )
        collector.add_failure(
            "second failure",
            reason=StructuringFailureReason.MAX_ITERATIONS,
        )
        report = StructuringDiagnosticsReport(
            func_addr=0x4000,
            func_name="func",
            succeeded=False,
            final_iteration=1000,
            max_iterations=1000,
            diagnostics_collector=collector,
        )
        # Should return the last failure's reason
        assert report.last_failure_reason() == StructuringFailureReason.MAX_ITERATIONS

    def test_summary_line_success(self):
        """Test summary line for successful structuring."""
        collector = DiagnosticsCollector()
        report = StructuringDiagnosticsReport(
            func_addr=0x1000,
            func_name="test_func",
            succeeded=True,
            final_iteration=42,
            max_iterations=1000,
            diagnostics_collector=collector,
        )
        summary = report.summary_line()
        assert "✓" in summary
        assert "test_func" in summary
        assert "42 iterations" in summary

    def test_summary_line_failure(self):
        """Test summary line for failed structuring."""
        collector = DiagnosticsCollector()
        collector.add_failure(
            "max iterations",
            reason=StructuringFailureReason.MAX_ITERATIONS,
        )
        report = StructuringDiagnosticsReport(
            func_addr=0x2000,
            func_name="failed_func",
            succeeded=False,
            final_iteration=1000,
            max_iterations=1000,
            diagnostics_collector=collector,
        )
        summary = report.summary_line()
        assert "✗" in summary
        assert "failed_func" in summary
        assert "max_iterations" in summary

    def test_to_dict(self):
        """Test conversion to dictionary."""
        collector = DiagnosticsCollector()
        collector.add_failure(
            "timeout",
            reason=StructuringFailureReason.TIMEOUT,
        )
        report = StructuringDiagnosticsReport(
            func_addr=0x1000,
            func_name="func",
            succeeded=False,
            final_iteration=500,
            max_iterations=1000,
            diagnostics_collector=collector,
            failure_reason=StructuringFailureReason.TIMEOUT,
        )
        report.add_recovery_hint("hint 1")
        d = report.to_dict()
        assert d["func_name"] == "func"
        assert d["succeeded"] is False
        assert d["failure_reason"] == "timeout"
        assert len(d["recovery_hints"]) == 1
        assert d["cfg_snapshot"] is None
        assert d["cfg_ownership"] is None
        assert d["cfg_indirect"] is None
        assert d["cfg_grouping"] is None


class TestFailureReasoning:
    """Test failure reason classification logic."""

    def test_build_failure_max_iterations(self):
        """Test classifying MAX_ITERATIONS failure."""
        class MockStats:
            max_iterations_reached = True
            iterations = 1000

        reason = build_failure_reason_from_stats(MockStats())
        assert reason == StructuringFailureReason.MAX_ITERATIONS

    def test_build_failure_no_progress(self):
        """Test classifying NO_PROGRESS failure."""
        class MockStats:
            max_iterations_reached = False
            iterations = 150
            regions_reduced = 0

        reason = build_failure_reason_from_stats(MockStats())
        assert reason == StructuringFailureReason.NO_PROGRESS

    def test_build_failure_none_for_success(self):
        """Test returning None for successful structuring."""
        class MockStats:
            max_iterations_reached = False
            iterations = 50
            regions_reduced = 20

        reason = build_failure_reason_from_stats(MockStats())
        assert reason is None

    def test_build_failure_no_stats_attribute(self):
        """Test handling missing stats attribute."""
        class MockStats:
            pass

        reason = build_failure_reason_from_stats(MockStats())
        assert reason is None


class TestRecoveryHints:
    """Test recovery hint generation."""

    def test_hints_max_iterations(self):
        """Test hints for MAX_ITERATIONS."""
        class MockStats:
            max_iterations_reached = True
            iterations = 1000
            regions_reduced = 5
            cycles_resolved = 0
            had_unstructured_gotos = False

        hints = suggest_recovery_hints(MockStats())
        assert any("iteration limit" in h for h in hints)
        assert any("indirect jumps" in h or "tail calls" in h for h in hints)

    def test_hints_slow_progress(self):
        """Test hints for slow progress."""
        class MockStats:
            max_iterations_reached = False
            iterations = 200
            regions_reduced = 2
            cycles_resolved = 0
            had_unstructured_gotos = False

        hints = suggest_recovery_hints(MockStats())
        assert any("slow progress" in h for h in hints)
        assert any("mixed entry/exit" in h for h in hints)

    def test_hints_no_cycles(self):
        """Test hints when no cycles found."""
        class MockStats:
            max_iterations_reached = False
            iterations = 100
            regions_reduced = 10
            cycles_resolved = 0
            had_unstructured_gotos = False

        hints = suggest_recovery_hints(MockStats())
        assert any("cyclic pattern" in h for h in hints)
        assert any("uncommon" in h for h in hints)

    def test_hints_unstructured_gotos(self):
        """Test hints when gotos remain."""
        class MockStats:
            max_iterations_reached = False
            iterations = 50
            regions_reduced = 15
            cycles_resolved = 5
            had_unstructured_gotos = True

        hints = suggest_recovery_hints(MockStats())
        assert any("unstructured goto" in h for h in hints)

    def test_hints_with_region_ids(self):
        """Test hints include region IDs."""
        class MockStats:
            max_iterations_reached = False
            iterations = 20
            regions_reduced = 5
            cycles_resolved = 1
            had_unstructured_gotos = False

        hints = suggest_recovery_hints(MockStats(), region_ids=(1, 2, 3))
        assert any("region" in h for h in hints)


class TestIntegration:
    """Test integration with decompiler passes."""

    def test_apply_pass_basic(self):
        """Test applying structuring diagnostics pass."""
        class MockStats:
            iterations = 100
            max_iterations_reached = False
            regions_reduced = 10
            cycles_resolved = 2
            had_unstructured_gotos = False

        class MockCFunc:
            addr = 0x1000
            name = "test_func"
            _structuring_stats = MockStats()

        class MockCodegen:
            cfunc = MockCFunc()

        codegen = MockCodegen()
        result = apply_x86_16_structuring_diagnostics(codegen)
        assert result is True
        assert hasattr(codegen.cfunc, "_recovery_metadata")
        assert "structuring_diagnostics" in codegen.cfunc._recovery_metadata

    def test_apply_pass_attaches_cfg_snapshot(self):
        """Test that pass attaches typed CFG snapshot when clinic graph exists."""
        import networkx as nx

        class MockStats:
            iterations = 10
            max_iterations_reached = False
            regions_reduced = 1
            cycles_resolved = 0
            had_unstructured_gotos = False

        class MockNode:
            def __init__(self, addr):
                self.addr = addr

        class MockClinic:
            def __init__(self):
                graph = nx.DiGraph()
                a = MockNode(0x1000)
                b = MockNode(0x1001)
                graph.add_nodes_from([a, b])
                graph.add_edge(a, b)
                self.graph = graph

        class MockCFunc:
            addr = 0x1000
            name = "snap_func"
            _structuring_stats = MockStats()

        class MockCodegen:
            cfunc = MockCFunc()
            _clinic = MockClinic()
            project = None

        codegen = MockCodegen()
        result = apply_x86_16_structuring_diagnostics(codegen)
        assert result is True
        report = codegen.cfunc._recovery_metadata["structuring_diagnostics"]
        assert report.cfg_snapshot is not None
        assert report.cfg_ownership is not None
        assert report.cfg_indirect is not None
        assert report.cfg_grouping is not None
        assert report.cfg_snapshot.entry_region_id == 0x1000
        assert report.cfg_snapshot.node_count == 2
        assert any(
            "cfg_snapshot nodes=2 edges=1 entry=0x1000" in diag.message
            for diag in report.diagnostics_collector.diagnostics
        )
        assert any(
            "cfg_ownership regions=2 shared=0 entry_fragments=0" in diag.message
            for diag in report.diagnostics_collector.diagnostics
        )
        assert any(
            "cfg_indirect candidates=0 total=2" in diag.message
            for diag in report.diagnostics_collector.diagnostics
        )
        assert any(
            "cfg_grouping grouped_candidates=0 entry_fragments=0" in diag.message
            for diag in report.diagnostics_collector.diagnostics
        )

    def test_apply_pass_with_none_cfunc(self):
        """Test applying pass with None cfunc."""
        class MockCodegen:
            cfunc = None

        codegen = MockCodegen()
        result = apply_x86_16_structuring_diagnostics(codegen)
        assert result is True  # Should not crash

    def test_apply_pass_failure_classification(self):
        """Test that pass classifies failures."""
        class MockStats:
            iterations = 1000
            max_iterations_reached = True
            regions_reduced = 5
            cycles_resolved = 0
            had_unstructured_gotos = True

        class MockCFunc:
            addr = 0x2000
            name = "failed_func"
            _structuring_stats = MockStats()

        class MockCodegen:
            cfunc = MockCFunc()

        codegen = MockCodegen()
        result = apply_x86_16_structuring_diagnostics(codegen)
        assert result is True
        report = codegen.cfunc._recovery_metadata["structuring_diagnostics"]
        assert report.last_failure_reason() == StructuringFailureReason.MAX_ITERATIONS
        assert len(report.recovery_hints) > 0

    def test_apply_pass_uses_ir_readiness_to_add_targeted_hints(self):
        """Typed IR state should shape recovery hints, not only raw structuring stats."""

        class MockStats:
            iterations = 1000
            max_iterations_reached = True
            regions_reduced = 0
            cycles_resolved = 0
            had_unstructured_gotos = False

        class MockCFunc:
            addr = 0x2100
            name = "ir_failed_func"
            _structuring_stats = MockStats()

        class MockCodegen:
            cfunc = MockCFunc()
            _inertia_vex_ir_summary = {
                "block_count": 2,
                "address_status_counts": {"provisional": 2},
                "segment_origin_counts": {"defaulted": 2},
                "condition_counts": {},
                "phi_node_count": 0,
            }

        codegen = MockCodegen()
        result = apply_x86_16_structuring_diagnostics(codegen)

        assert result is True
        report = codegen.cfunc._recovery_metadata["structuring_diagnostics"]
        assert report.ir_hints is not None
        assert report.ir_hints.readiness.level == "typed_address_only"
        assert any("Typed conditions missing" in hint for hint in report.recovery_hints)
        assert any("defaulted" in hint for hint in report.recovery_hints)
        assert any("Segmented addresses remain provisional" in hint for hint in report.recovery_hints)
        assert any("Cross-block SSA absent" in hint for hint in report.recovery_hints)
        assert any("ir_readiness level=typed_address_only" in diag.message for diag in report.diagnostics_collector.diagnostics)

    def test_apply_pass_success_case(self):
        """Test that pass handles successful structuring."""
        class MockStats:
            iterations = 50
            max_iterations_reached = False
            regions_reduced = 25
            cycles_resolved = 5
            had_unstructured_gotos = False

        class MockCFunc:
            addr = 0x3000
            name = "successful_func"
            _structuring_stats = MockStats()

        class MockCodegen:
            cfunc = MockCFunc()

        codegen = MockCodegen()
        result = apply_x86_16_structuring_diagnostics(codegen)
        assert result is True
        report = codegen.cfunc._recovery_metadata["structuring_diagnostics"]
        assert report.succeeded is True
        assert report.final_iteration == 50

    def test_apply_pass_handles_exceptions(self):
        """Test that pass handles exceptions gracefully."""
        class MockCodegen:
            cfunc = None  # Will cause iteration to skip

        codegen = MockCodegen()
        result = apply_x86_16_structuring_diagnostics(codegen)
        # Should return True even if exception would occur
        assert result is True

    def test_summary_line_display(self):
        """Test summary line is useful for logging."""
        class MockStats:
            iterations = 42
            max_iterations_reached = False
            regions_reduced = 10
            cycles_resolved = 1
            had_unstructured_gotos = False

        class MockCFunc:
            addr = 0x4000
            name = "display_func"
            _structuring_stats = MockStats()

        class MockCodegen:
            cfunc = MockCFunc()

        codegen = MockCodegen()
        apply_x86_16_structuring_diagnostics(codegen)
        report = codegen.cfunc._recovery_metadata["structuring_diagnostics"]
        summary = report.summary_line()
        assert len(summary) > 20  # Should have meaningful content
        assert "✓" in summary
