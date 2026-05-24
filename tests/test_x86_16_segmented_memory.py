"""
Tests for Phase 3: Segmented Memory Association Reasoning

Tests segment classification, far pointer detection,
and segment association building across functions.
"""

import pytest

from angr_platforms.X86_16.segmented_memory_reasoning import (
    FarPointerRecovery,
    SegmentAssignment,
    SegmentAssociation,
    SegmentAssociationAnalyzer,
    SegmentedAddressClassifier,
    SegmentedPointer,
    SegmentLoweringDecision,
    SegmentRegister,
    apply_x86_16_segmented_memory_reasoning,
)


class TestSegmentRegister:
    """Tests for segment register enums."""

    def test_segment_register_values(self):
        """Test segment register enum values."""
        assert SegmentRegister.CS.value == "code"
        assert SegmentRegister.DS.value == "data"
        assert SegmentRegister.SS.value == "stack"

    def test_all_segment_registers(self):
        """Test all segment registers are defined."""
        segments = {SegmentRegister.CS, SegmentRegister.DS, SegmentRegister.ES, SegmentRegister.SS}

        assert len(segments) >= 4


class TestSegmentAssignment:
    """Tests for segment assignment tracking."""

    def test_create_segment_assignment(self):
        """Test creating a segment assignment."""
        assignment = SegmentAssignment(
            segment_reg=SegmentRegister.DS,
            value=0x1000,
            source="literal",
            location="load_data_segment",
            confidence=0.9,
        )

        assert assignment.segment_reg == SegmentRegister.DS
        assert assignment.value == 0x1000
        assert assignment.confidence == 0.9

    def test_segment_assignment_repr(self):
        """Test segment assignment representation."""
        assignment = SegmentAssignment(
            segment_reg=SegmentRegister.ES,
            value=None,
            source="parameter",
            location="copy_buffer",
            confidence=0.7,
        )

        repr_str = repr(assignment)
        assert "ES" in repr_str
        assert "70.0%" in repr_str


class TestSegmentAssociation:
    """Tests for segment associations."""

    def test_create_segment_association(self):
        """Test creating a segment association."""
        assoc = SegmentAssociation(
            segment_reg=SegmentRegister.CS, associated_space="code", evidence_count=0, stability=0.5
        )

        assert assoc.segment_reg == SegmentRegister.CS
        assert assoc.associated_space == "code"

    def test_add_evidence_increases_stability(self):
        """Test that adding evidence increases stability."""
        assoc = SegmentAssociation(segment_reg=SegmentRegister.DS, associated_space="data")

        initial_stability = assoc.stability

        assignment = SegmentAssignment(
            segment_reg=SegmentRegister.DS, value=0x2000, source="literal", location="f1", confidence=0.9
        )
        assoc.add_evidence(assignment)

        assert assoc.stability >= initial_stability
        assert assoc.evidence_count == 1

    def test_evidence_accumulation(self):
        """Test accumulating multiple evidence items."""
        assoc = SegmentAssociation(segment_reg=SegmentRegister.SS, associated_space="stack")

        for i in range(5):
            assignment = SegmentAssignment(
                segment_reg=SegmentRegister.SS,
                value=0x8000 + i * 0x100,
                source="register",
                location=f"func_{i}",
                confidence=0.8,
            )
            assoc.add_evidence(assignment)

        assert assoc.evidence_count == 5
        assert assoc.stability > 0.5


class TestSegmentedPointer:
    """Tests for segmented pointer representations."""

    def test_create_segmented_pointer(self):
        """Test creating a segmented pointer."""
        ptr = SegmentedPointer(
            segment_reg=SegmentRegister.DS,
            offset_expr="bx + 4",
            known_base=0x1000,
            element_type="struct",
            confidence=0.8,
        )

        assert ptr.segment_reg == SegmentRegister.DS
        assert ptr.offset_expr == "bx + 4"
        assert ptr.known_base == 0x1000

    def test_segmented_pointer_repr(self):
        """Test segmented pointer MK_FP representation."""
        ptr = SegmentedPointer(
            segment_reg=SegmentRegister.ES,
            offset_expr="cx",
            known_base=0x2000,
            element_type="char",
            confidence=0.7,
        )

        repr_str = repr(ptr)
        assert "MK_FP" in repr_str
        assert "0x2000" in repr_str


class TestFarPointerRecovery:
    """Tests for far pointer recovery metadata."""

    def test_create_far_pointer_recovery(self):
        """Test creating far pointer recovery info."""
        ptr = SegmentedPointer(
            segment_reg=SegmentRegister.DS,
            offset_expr="si",
            known_base=None,
            element_type="buffer",
            confidence=0.6,
        )

        recovery = FarPointerRecovery(
            name="buffer_ptr", pointer_id=1, segment_part=ptr, access_count=3, functions={"read_buffer"}
        )

        assert recovery.name == "buffer_ptr"
        assert recovery.access_count == 3


class TestSegmentLoweringDecision:
    def test_requires_explicit_segmented_form(self):
        decision = SegmentLoweringDecision(
            segment_reg=SegmentRegister.DS,
            classification="single",
            associated_space="data",
            confidence=0.7,
            allow_linear_lowering=False,
            allow_object_lowering=False,
            reason="stable segment register but no constant base",
        )

        assert decision.requires_explicit_segmented_form() is True


class TestSegmentedAddressClassifier:
    """Tests for address classification."""

    def test_classify_single_segment(self):
        """Test classifying single-segment accesses."""
        classifier = SegmentedAddressClassifier()

        assignments = [
            SegmentAssignment(SegmentRegister.DS, 0x1000, "literal", "f1", 0.9),
            SegmentAssignment(SegmentRegister.DS, 0x1000, "literal", "f2", 0.9),
        ]

        classification = classifier.classify(assignments)
        assert classification == "const"

    def test_classify_over_associated(self):
        """Test classifying over-associated accesses."""
        classifier = SegmentedAddressClassifier()

        assignments = [
            SegmentAssignment(SegmentRegister.DS, 0x1000, "literal", "f1", 0.9),
            SegmentAssignment(SegmentRegister.ES, 0x2000, "literal", "f2", 0.9),
        ]

        classification = classifier.classify(assignments)
        assert classification == "over_associated"

    def test_classify_single_not_const(self):
        """Test classifying single segment without constant value."""
        classifier = SegmentedAddressClassifier()

        assignments = [
            SegmentAssignment(SegmentRegister.DS, None, "register", "f1", 0.6),
            SegmentAssignment(SegmentRegister.DS, None, "register", "f2", 0.6),
        ]

        classification = classifier.classify(assignments)
        assert classification == "single"

    def test_classify_empty(self):
        """Test classifying empty assignment list."""
        classifier = SegmentedAddressClassifier()

        classification = classifier.classify([])
        assert classification == "unknown"


class TestSegmentAssociationAnalyzer:
    """Tests for segment association analysis."""

    def test_create_analyzer(self):
        """Test creating analyzer with all segments."""
        analyzer = SegmentAssociationAnalyzer()

        # Should have associations for all segments
        assert SegmentRegister.CS in analyzer.associations
        assert SegmentRegister.DS in analyzer.associations
        assert SegmentRegister.SS in analyzer.associations

    def test_analyze_segment_assignments(self):
        """Test analyzing segment assignments."""
        analyzer = SegmentAssociationAnalyzer()

        assignments = [
            SegmentAssignment(SegmentRegister.CS, 0x0000, "literal", "main", 1.0),
            SegmentAssignment(SegmentRegister.DS, 0x1000, "literal", "load_data", 0.9),
            SegmentAssignment(SegmentRegister.SS, 0x8000, "register", "init_stack", 0.8),
        ]

        analyzer.analyze(assignments)

        # Check associations were built
        assert analyzer.associations[SegmentRegister.CS].evidence_count > 0
        assert analyzer.associations[SegmentRegister.DS].associated_space == "data"
        assert analyzer.associations[SegmentRegister.DS].classification == "const"
        assert analyzer.associations[SegmentRegister.SS].associated_space == "stack"

    def test_detect_far_pointers(self):
        """Test detecting far pointer patterns."""
        analyzer = SegmentAssociationAnalyzer()

        pointers = [
            SegmentedPointer(SegmentRegister.DS, "bx", 0x1000, "array", 0.8),
            SegmentedPointer(SegmentRegister.ES, "si", 0x2000, "buffer", 0.7),
        ]

        far_ptrs = analyzer.detect_far_pointers(pointers)

        assert len(far_ptrs) == 2

    def test_get_association_confidence(self):
        """Test querying association confidence."""
        analyzer = SegmentAssociationAnalyzer()

        assignments = [
            SegmentAssignment(SegmentRegister.DS, 0x1000, "literal", "f1", 0.9),
            SegmentAssignment(SegmentRegister.DS, 0x1000, "literal", "f2", 0.9),
        ]

        analyzer.analyze(assignments)

        confidence = analyzer.get_association_confidence(SegmentRegister.DS)
        assert confidence > 0.5  # Should have gained confidence from evidence

    def test_lowering_decision_for_const_segment_allows_linear_lowering(self):
        analyzer = SegmentAssociationAnalyzer()
        analyzer.analyze(
            [
                SegmentAssignment(SegmentRegister.DS, 0x1000, "literal", "f1", 0.9),
                SegmentAssignment(SegmentRegister.DS, 0x1000, "literal", "f2", 0.9),
            ]
        )

        decision = analyzer.lowering_decision(SegmentRegister.DS)

        assert decision.classification == "const"
        assert decision.allow_linear_lowering is True
        assert decision.allow_object_lowering is True

    def test_lowering_decision_for_single_segment_stays_segmented(self):
        analyzer = SegmentAssociationAnalyzer()
        analyzer.analyze(
            [
                SegmentAssignment(SegmentRegister.ES, None, "register", "f1", 0.7),
                SegmentAssignment(SegmentRegister.ES, None, "register", "f2", 0.7),
            ]
        )

        decision = analyzer.lowering_decision(SegmentRegister.ES)

        assert decision.classification == "single"
        assert decision.allow_linear_lowering is False
        assert decision.allow_object_lowering is False

    def test_lowering_decision_for_over_associated_segment_refuses_lowering(self):
        analyzer = SegmentAssociationAnalyzer()
        analyzer.analyze(
            [
                SegmentAssignment(SegmentRegister.DS, 0x1000, "literal", "f1", 0.9),
                SegmentAssignment(SegmentRegister.DS, 0x2000, "literal", "f2", 0.9),
            ]
        )

        decision = analyzer.lowering_decision(SegmentRegister.DS)

        assert decision.classification == "over_associated"
        assert decision.allow_linear_lowering is False
        assert decision.allow_object_lowering is False


class TestPhase3Integration:
    """Integration tests for Phase 3."""

    def test_end_to_end_segment_reasoning(self):
        """Test complete segment association pipeline."""
        analyzer = SegmentAssociationAnalyzer()

        # Build assignments from multiple functions
        assignments = [
            SegmentAssignment(SegmentRegister.CS, 0x0000, "literal", "main", 1.0),
            SegmentAssignment(SegmentRegister.DS, 0x1000, "literal", "load_data", 0.95),
            SegmentAssignment(SegmentRegister.DS, 0x1000, "literal", "process", 0.95),
            SegmentAssignment(SegmentRegister.SS, 0x8000, "fixed", "init", 0.9),
        ]

        analyzer.analyze(assignments)

        # Detect far pointers
        pointers = [
            SegmentedPointer(SegmentRegister.DS, "bx", 0x1000, "struct", 0.8),
        ]
        far_ptrs = analyzer.detect_far_pointers(pointers)

        # Verify results
        assert analyzer.associations[SegmentRegister.DS].evidence_count >= 2
        assert len(far_ptrs) >= 1
        assert analyzer.get_association_confidence(SegmentRegister.DS) >= 0.6

    def test_segmented_memory_decompiler_pass(self):
        """Test segmented memory pass integration."""

        class MockCodegen:
            cfunc = object()

        codegen = MockCodegen()
        result = apply_x86_16_segmented_memory_reasoning(codegen)

        assert result is False  # No direct modifications
        assert hasattr(codegen, "_inertia_segmented_memory_applied")
        assert codegen._inertia_segmented_memory_applied is True

    def test_over_associated_detection(self):
        """Test detecting over-associated (ambiguous) segments."""
        analyzer = SegmentAssociationAnalyzer()

        # Multiple different DS values in different functions
        assignments = [
            SegmentAssignment(SegmentRegister.DS, 0x1000, "literal", "f1", 0.9),
            SegmentAssignment(SegmentRegister.DS, 0x2000, "literal", "f2", 0.9),
            SegmentAssignment(SegmentRegister.DS, 0x3000, "literal", "f3", 0.9),
        ]

        analyzer.analyze(assignments)

        # Confidence should be lower due to over-association
        confidence = analyzer.get_association_confidence(SegmentRegister.DS)
        assert confidence < 0.5
        assert analyzer.associations[SegmentRegister.DS].classification == "over_associated"

    def test_segmented_memory_pass_records_stable_and_over_associated_summary(self):
        class MockCodegen:
            cfunc = object()
            _inertia_segment_assignments = [
                SegmentAssignment(SegmentRegister.DS, 0x1000, "literal", "f1", 0.9),
                SegmentAssignment(SegmentRegister.DS, 0x1000, "literal", "f2", 0.9),
                SegmentAssignment(SegmentRegister.ES, 0x2000, "literal", "f3", 0.9),
                SegmentAssignment(SegmentRegister.ES, 0x3000, "literal", "f4", 0.9),
            ]

        codegen = MockCodegen()
        result = apply_x86_16_segmented_memory_reasoning(codegen)

        assert result is False
        assert codegen._inertia_segmented_memory_summary["stable"]["DS"]["classification"] == "const"
        assert (
            codegen._inertia_segmented_memory_summary["over_associated"]["ES"]["classification"]
            == "over_associated"
        )
        assert codegen._inertia_segmented_memory_lowering["DS"]["allow_linear_lowering"] is True
        assert codegen._inertia_segmented_memory_lowering["ES"]["allow_linear_lowering"] is False
        assert codegen._inertia_segmented_memory_stats["segment_assignments"] == 4


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
