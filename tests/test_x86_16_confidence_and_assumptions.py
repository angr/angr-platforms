"""
Tests for confidence_and_assumptions module (Phase 4.1).

Tests confidence level assignment, marker tracking, function reports,
and integration with decompiler output.
"""

import pytest

from angr_platforms.X86_16.confidence_and_assumptions import (
    ConfidenceLevel,
    ConfidenceMarker,
    ConfidenceTracker,
    FunctionConfidenceReport,
    ScanConfidenceSummary,
    apply_x86_16_confidence_and_assumptions,
    build_function_with_confidence_markers,
)


class TestConfidenceLevel:
    """Test confidence level enum."""

    def test_enum_values(self):
        """Test confidence level enum has expected values."""
        assert ConfidenceLevel.HIGH.value == "HIGH"
        assert ConfidenceLevel.MEDIUM.value == "MEDIUM"
        assert ConfidenceLevel.LOW.value == "LOW"

    def test_enum_ordering(self):
        """Test confidence levels are distinct."""
        assert ConfidenceLevel.HIGH != ConfidenceLevel.MEDIUM
        assert ConfidenceLevel.MEDIUM != ConfidenceLevel.LOW
        assert ConfidenceLevel.HIGH != ConfidenceLevel.LOW


class TestConfidenceMarker:
    """Test confidence marker creation."""

    def test_marker_creation_basic(self):
        """Test basic marker creation."""
        marker = ConfidenceMarker(
            fact_kind="struct",
            fact_detail="struct Person",
            confidence=ConfidenceLevel.HIGH,
            evidence_count=3,
        )
        assert marker.fact_kind == "struct"
        assert marker.fact_detail == "struct Person"
        assert marker.confidence == ConfidenceLevel.HIGH
        assert marker.evidence_count == 3
        assert marker.reason is None

    def test_marker_with_reason(self):
        """Test marker with reason."""
        marker = ConfidenceMarker(
            fact_kind="array",
            fact_detail="array buffer[256]",
            confidence=ConfidenceLevel.MEDIUM,
            evidence_count=2,
            reason="detected from 2 access patterns",
        )
        assert marker.reason == "detected from 2 access patterns"

    def test_marker_immutable(self):
        """Test marker is immutable (frozen)."""
        marker = ConfidenceMarker(
            fact_kind="pointer",
            fact_detail="ptr_t",
            confidence=ConfidenceLevel.HIGH,
            evidence_count=1,
        )
        with pytest.raises(AttributeError):
            marker.fact_kind = "changed"


class TestConfidenceTracker:
    """Test confidence tracker aggregation."""

    def test_tracker_creation(self):
        """Test tracker creation."""
        tracker = ConfidenceTracker()
        assert tracker.total_count() == 0
        assert tracker.high_count() == 0
        assert tracker.medium_count() == 0
        assert tracker.low_count() == 0

    def test_add_single_marker(self):
        """Test adding single marker."""
        tracker = ConfidenceTracker()
        tracker.add_marker(
            fact_kind="struct",
            fact_detail="struct Point",
            confidence=ConfidenceLevel.HIGH,
            evidence_count=5,
        )
        assert tracker.total_count() == 1
        assert tracker.high_count() == 1
        assert tracker.medium_count() == 0
        assert tracker.low_count() == 0

    def test_add_multiple_markers(self):
        """Test adding multiple markers."""
        tracker = ConfidenceTracker()
        tracker.add_marker(
            "struct", "struct A", ConfidenceLevel.HIGH, evidence_count=3
        )
        tracker.add_marker(
            "array", "array buf", ConfidenceLevel.MEDIUM, evidence_count=2
        )
        tracker.add_marker(
            "pointer", "ptr field", ConfidenceLevel.LOW, evidence_count=1
        )
        assert tracker.total_count() == 3
        assert tracker.high_count() == 1
        assert tracker.medium_count() == 1
        assert tracker.low_count() == 1

    def test_count_only_relevant_confidence(self):
        """Test counting per confidence level."""
        tracker = ConfidenceTracker()
        for _ in range(4):
            tracker.add_marker(
                "struct", "s", ConfidenceLevel.HIGH, evidence_count=1
            )
        for _ in range(3):
            tracker.add_marker(
                "array", "a", ConfidenceLevel.MEDIUM, evidence_count=1
            )
        for _ in range(2):
            tracker.add_marker(
                "pointer", "p", ConfidenceLevel.LOW, evidence_count=1
            )
        assert tracker.high_count() == 4
        assert tracker.medium_count() == 3
        assert tracker.low_count() == 2
        assert tracker.total_count() == 9

    def test_to_dict(self):
        """Test conversion to dictionary."""
        tracker = ConfidenceTracker()
        tracker.add_marker(
            "struct", "struct X", ConfidenceLevel.HIGH, evidence_count=2
        )
        tracker.add_marker(
            "array", "array Y", ConfidenceLevel.LOW, evidence_count=1
        )
        d = tracker.to_dict()
        assert d["high_count"] == 1
        assert d["medium_count"] == 0
        assert d["low_count"] == 1
        assert d["total_count"] == 2
        assert len(d["markers"]) == 2


class TestFunctionConfidenceReport:
    """Test function confidence reports."""

    def test_report_creation(self):
        """Test report creation."""
        tracker = ConfidenceTracker()
        report = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="main",
            confidence_tracker=tracker,
        )
        assert report.func_addr == 0x1000
        assert report.func_name == "main"
        assert len(report.assumptions) == 0
        assert len(report.critical_unknowns) == 0

    def test_add_assumption(self):
        """Test adding assumptions."""
        tracker = ConfidenceTracker()
        report = FunctionConfidenceReport(
            func_addr=0x2000,
            func_name="process",
            confidence_tracker=tracker,
        )
        report.add_assumption("unresolved indirect target at 0x2100")
        report.add_assumption("guessed helper signature for DOS function")
        assert len(report.assumptions) == 2

    def test_add_critical_unknown(self):
        """Test adding critical unknowns."""
        tracker = ConfidenceTracker()
        report = FunctionConfidenceReport(
            func_addr=0x3000,
            func_name="data_handler",
            confidence_tracker=tracker,
        )
        report.add_critical_unknown("uncertain far pointer to DS:0x4000")
        assert len(report.critical_unknowns) == 1

    def test_overall_confidence_high(self):
        """Test overall confidence HIGH."""
        tracker = ConfidenceTracker()
        for _ in range(8):
            tracker.add_marker(
                "struct", "s", ConfidenceLevel.HIGH, evidence_count=1
            )
        tracker.add_marker("array", "a", ConfidenceLevel.MEDIUM, evidence_count=1)
        report = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="func",
            confidence_tracker=tracker,
        )
        assert report.overall_confidence() == ConfidenceLevel.HIGH

    def test_overall_confidence_medium(self):
        """Test overall confidence MEDIUM."""
        tracker = ConfidenceTracker()
        tracker.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        tracker.add_marker("array", "a", ConfidenceLevel.MEDIUM, evidence_count=1)
        tracker.add_marker("pointer", "p", ConfidenceLevel.MEDIUM, evidence_count=1)
        report = FunctionConfidenceReport(
            func_addr=0x2000,
            func_name="func",
            confidence_tracker=tracker,
        )
        assert report.overall_confidence() == ConfidenceLevel.MEDIUM

    def test_overall_confidence_low_from_low_markers(self):
        """Test overall confidence LOW from low markers."""
        tracker = ConfidenceTracker()
        tracker.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        for _ in range(4):
            tracker.add_marker(
                "pointer", "p", ConfidenceLevel.LOW, evidence_count=1
            )
        report = FunctionConfidenceReport(
            func_addr=0x3000,
            func_name="func",
            confidence_tracker=tracker,
        )
        assert report.overall_confidence() == ConfidenceLevel.LOW

    def test_overall_confidence_low_from_critical_unknowns(self):
        """Test overall confidence LOW from critical unknowns."""
        tracker = ConfidenceTracker()
        for _ in range(5):
            tracker.add_marker(
                "struct", "s", ConfidenceLevel.HIGH, evidence_count=1
            )
        report = FunctionConfidenceReport(
            func_addr=0x4000,
            func_name="func",
            confidence_tracker=tracker,
        )
        report.add_critical_unknown("cannot resolve target")
        assert report.overall_confidence() == ConfidenceLevel.LOW

    def test_comment_header_generation(self):
        """Test comment header generation."""
        tracker = ConfidenceTracker()
        tracker.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        tracker.add_marker("array", "a", ConfidenceLevel.HIGH, evidence_count=1)
        report = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="process",
            confidence_tracker=tracker,
        )
        report.add_assumption("assumption 1")
        header = report.comment_header()
        assert "// process @ 0x1000" in header
        assert "// Confidence: HIGH" in header
        assert "// Evidence: 2 HIGH, 0 MEDIUM, 0 LOW" in header
        assert "// Assumptions: 1 recorded" in header

    def test_comment_header_with_critical_unknowns(self):
        """Test comment header with critical unknowns."""
        tracker = ConfidenceTracker()
        report = FunctionConfidenceReport(
            func_addr=0x2000,
            func_name="unknown_func",
            confidence_tracker=tracker,
        )
        report.add_critical_unknown("issue 1")
        header = report.comment_header()
        assert "// ⚠️ CRITICAL UNKNOWNS:" in header
        assert "issue 1" in header

    def test_to_dict(self):
        """Test conversion to dictionary."""
        tracker = ConfidenceTracker()
        tracker.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        report = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="func",
            confidence_tracker=tracker,
        )
        report.add_assumption("assumption 1")
        d = report.to_dict()
        assert d["func_name"] == "func"
        assert d["func_addr"] == "0x1000"
        assert d["overall_confidence"] == "HIGH"
        assert d["assumptions_count"] == 1


class TestScanConfidenceSummary:
    """Test scan-wide confidence summary."""

    def test_summary_creation(self):
        """Test summary creation."""
        summary = ScanConfidenceSummary()
        assert summary.total_functions == 0
        assert summary.high_confidence_count == 0
        assert summary.high_confidence_ratio() == 0.0

    def test_add_high_confidence_function(self):
        """Test adding high-confidence function."""
        tracker = ConfidenceTracker()
        for _ in range(5):
            tracker.add_marker(
                "struct", "s", ConfidenceLevel.HIGH, evidence_count=1
            )
        report = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="func1",
            confidence_tracker=tracker,
        )
        summary = ScanConfidenceSummary()
        summary.add_function_report(report)
        assert summary.total_functions == 1
        assert summary.high_confidence_count == 1
        assert summary.high_confidence_ratio() == 1.0

    def test_add_mixed_functions(self):
        """Test adding functions with mixed confidence."""
        summary = ScanConfidenceSummary()
        # Add high-confidence function
        t1 = ConfidenceTracker()
        for _ in range(4):
            t1.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        r1 = FunctionConfidenceReport(
            func_addr=0x1000, func_name="f1", confidence_tracker=t1
        )
        summary.add_function_report(r1)
        # Add low-confidence function
        t2 = ConfidenceTracker()
        for _ in range(4):
            t2.add_marker("pointer", "p", ConfidenceLevel.LOW, evidence_count=1)
        r2 = FunctionConfidenceReport(
            func_addr=0x2000, func_name="f2", confidence_tracker=t2
        )
        summary.add_function_report(r2)
        assert summary.total_functions == 2
        assert summary.high_confidence_count == 1
        assert summary.low_confidence_count == 1
        assert summary.high_confidence_ratio() == 0.5

    def test_scan_classification_strong(self):
        """Test scan classified as STRONG."""
        summary = ScanConfidenceSummary()
        for _ in range(10):
            t = ConfidenceTracker()
            for _ in range(3):
                t.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
            r = FunctionConfidenceReport(
                func_addr=0x1000 + _,
                func_name=f"f{_}",
                confidence_tracker=t,
            )
            summary.add_function_report(r)
        assert summary.scan_classification() == "strong"

    def test_scan_classification_weak(self):
        """Test scan classified as WEAK."""
        summary = ScanConfidenceSummary()
        t = ConfidenceTracker()
        for _ in range(3):
            t.add_marker("pointer", "p", ConfidenceLevel.LOW, evidence_count=1)
        r = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="f",
            confidence_tracker=t,
        )
        r.add_critical_unknown("issue")
        summary.add_function_report(r)
        assert summary.scan_classification() == "weak"

    def test_scan_classification_partial(self):
        """Test scan classified as PARTIAL."""
        summary = ScanConfidenceSummary()
        t = ConfidenceTracker()
        t.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        t.add_marker("array", "a", ConfidenceLevel.MEDIUM, evidence_count=1)
        r = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="f",
            confidence_tracker=t,
        )
        summary.add_function_report(r)
        assert summary.scan_classification() == "partial"

    def test_add_assumptions_and_unknowns_to_summary(self):
        """Test that summary tracks assumptions and unknowns."""
        summary = ScanConfidenceSummary()
        t = ConfidenceTracker()
        t.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        r = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="f",
            confidence_tracker=t,
        )
        r.add_assumption("assumption1")
        r.add_assumption("assumption2")
        r.add_critical_unknown("unknown1")
        summary.add_function_report(r)
        assert summary.total_assumptions == 2
        assert summary.total_critical_unknowns == 1

    def test_to_dict(self):
        """Test conversion to dictionary."""
        summary = ScanConfidenceSummary()
        t = ConfidenceTracker()
        t.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        r = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="f",
            confidence_tracker=t,
        )
        summary.add_function_report(r)
        d = summary.to_dict()
        assert d["total_functions"] == 1
        assert d["high_confidence_count"] == 1
        assert d["scan_classification"] == "strong"


class TestIntegration:
    """Test integration with decompiler passes."""

    def test_apply_pass_basic(self):
        """Test applying confidence pass to mock codegen."""
        class MockCFunc:
            addr = 0x1000
            name = "test_func"
            _struct_recovery_info = None
            _array_recovery_info = None
            _segmented_memory_info = None

        class MockCodegen:
            cfunc = MockCFunc()

        codegen = MockCodegen()
        result = apply_x86_16_confidence_and_assumptions(codegen)
        assert result is True
        assert hasattr(codegen.cfunc, "_recovery_metadata")

    def test_apply_pass_with_none_cfunc(self):
        """Test applying pass with None cfunc."""
        class MockCodegen:
            cfunc = None

        codegen = MockCodegen()
        result = apply_x86_16_confidence_and_assumptions(codegen)
        assert result is True  # Should not crash

    def test_build_function_with_markers(self):
        """Test building function with markers."""
        class MockCFunc:
            addr = 0x2000
            name = "marked_func"

        cfunc = MockCFunc()
        tracker = ConfidenceTracker()
        tracker.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        report = FunctionConfidenceReport(
            func_addr=0x2000,
            func_name="marked_func",
            confidence_tracker=tracker,
        )
        result = build_function_with_confidence_markers(cfunc, report)
        assert result is True
        assert hasattr(cfunc, "_recovery_metadata")
        assert cfunc._recovery_metadata["confidence_report"] == report

    def test_empty_tracker_confidence(self):
        """Test confidence with empty tracker."""
        tracker = ConfidenceTracker()
        report = FunctionConfidenceReport(
            func_addr=0x3000,
            func_name="empty_func",
            confidence_tracker=tracker,
        )
        # Empty tracker should default to MEDIUM
        assert report.overall_confidence() == ConfidenceLevel.MEDIUM
