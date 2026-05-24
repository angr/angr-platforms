from angr_platforms.X86_16.confidence_and_assumptions import (
    ConfidenceLevel,
    apply_x86_16_confidence_and_assumptions,
)
from angr_platforms.X86_16.ir_confidence_markers import apply_x86_16_ir_confidence_markers


def test_ir_confidence_markers_attach_assumptions_and_critical_unknowns():
    class MockCFunc:
        addr = 0x1000
        name = "typed_ir_func"

    class MockCodegen:
        cfunc = MockCFunc()
        _inertia_vex_ir_summary = {
            "block_count": 2,
            "address_status_counts": {"provisional": 2},
            "segment_origin_counts": {"unknown": 1, "defaulted": 1},
            "condition_counts": {},
            "phi_node_count": 0,
        }

    codegen = MockCodegen()

    result = apply_x86_16_ir_confidence_markers(codegen)

    assert result is False
    assert "typed IR conditions are absent" in codegen.cfunc._assumptions
    assert "typed IR cross-block SSA is absent" in codegen.cfunc._assumptions
    assert "typed IR still has unknown segment identity" in codegen.cfunc._critical_unknowns


def test_ir_confidence_markers_feed_existing_confidence_pass():
    class MockCFunc:
        addr = 0x1010
        name = "typed_ir_confidence"
        _struct_recovery_info = None
        _array_recovery_info = None
        _segmented_memory_info = None

    class MockCodegen:
        cfunc = MockCFunc()
        _inertia_vex_ir_summary = {
            "block_count": 2,
            "address_status_counts": {"provisional": 1},
            "segment_origin_counts": {"unknown": 1},
            "condition_counts": {"eq": 1},
            "phi_node_count": 0,
        }

    codegen = MockCodegen()
    apply_x86_16_ir_confidence_markers(codegen)
    result = apply_x86_16_confidence_and_assumptions(codegen)

    assert result is True
    report = codegen.cfunc._recovery_metadata["confidence_report"]
    assert report.overall_confidence() == ConfidenceLevel.LOW
    assert "typed IR still has unknown segment identity" in report.critical_unknowns
