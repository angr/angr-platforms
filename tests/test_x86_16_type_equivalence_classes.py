"""
Tests for Phase 2.1: Type Equivalence Classes

Tests expression normalization, equivalence class building,
and type constraint collection for improved type inference.
"""

import pytest

from angr_platforms.X86_16.ir.core import AddressStatus, IRAddress, IRBlock, IRCondition, IRFunctionArtifact, IRInstr, IRValue, MemSpace, SegmentOrigin
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact, SSAIncomingValue, SSAPhiNode
from angr_platforms.X86_16.type_equivalence_classes import (
    EquivalenceClass,
    EquivalenceClassBuilder,
    ExpressionNormalizer,
    TypeCollector,
    TypeVariableReplacer,
    apply_x86_16_type_equivalence_classes,
)


class TestExpressionNormalizer:
    """Tests for expression normalization."""

    def test_normalize_simple_variable(self):
        """Test normalizing a simple variable expression."""
        normalizer = ExpressionNormalizer()
        pattern = normalizer.normalize("ax")

        assert pattern.pattern_type == "variable"
        assert pattern.base_expr == "ax"
        assert pattern.width == 16

    def test_normalize_pointer_arithmetic(self):
        """Test normalizing pointer arithmetic patterns."""
        normalizer = ExpressionNormalizer()

        # Test that pointer expressions are recognized
        pattern = normalizer.normalize("bx + 2")
        assert pattern.width == 16

    def test_normalize_memory_access(self):
        """Test normalizing memory access patterns."""
        normalizer = ExpressionNormalizer()

        pattern = normalizer.normalize("mem[si]")
        assert pattern.width == 16


class TestEquivalenceClass:
    """Tests for equivalence class mechanics."""

    def test_create_equivalence_class(self):
        """Test creating an equivalence class."""
        eq_class = EquivalenceClass(class_id=1)

        assert eq_class.class_id == 1
        assert len(eq_class.expressions) == 0
        assert len(eq_class.type_constraints) == 0

    def test_add_expression_to_class(self):
        """Test adding expressions to equivalence class."""
        eq_class = EquivalenceClass(class_id=1)

        eq_class.add_expression("ax")
        eq_class.add_expression("bx")

        assert "ax" in eq_class.expressions
        assert "bx" in eq_class.expressions

    def test_add_type_constraint(self):
        """Test adding type constraints to equivalence class."""
        eq_class = EquivalenceClass(class_id=1)

        eq_class.add_type_constraint("pointer")
        eq_class.add_type_constraint("integer")

        assert "pointer" in eq_class.type_constraints
        assert "integer" in eq_class.type_constraints

    def test_merge_equivalence_classes(self):
        """Test merging two equivalence classes."""
        class1 = EquivalenceClass(class_id=1, width=16)
        class2 = EquivalenceClass(class_id=2, width=32)

        class1.add_expression("ax")
        class2.add_expression("bx")
        class2.add_type_constraint("pointer")

        class1.merge(class2)

        assert "ax" in class1.expressions
        assert "bx" in class1.expressions
        assert "pointer" in class1.type_constraints
        assert class1.width == 32


class TestEquivalenceClassBuilder:
    """Tests for equivalence class building."""

    def test_build_simple_classes(self):
        """Test building equivalence classes from expressions."""
        builder = EquivalenceClassBuilder()
        expressions = ["ax", "bx", "si"]

        classes = builder.build(expressions)

        assert len(classes) == 3
        for expr in expressions:
            class_id = builder.expr_to_class[expr]
            assert expr in classes[class_id].expressions

    def test_merge_related_expressions(self):
        """Test merging related expressions into same class."""
        builder = EquivalenceClassBuilder()
        expressions = ["ax", "bx"]

        builder.build(expressions)
        builder.merge_classes("ax", "bx")

        # After merge, both should map to same class
        class_ax = builder.expr_to_class["ax"]
        class_bx = builder.expr_to_class["bx"]
        assert class_ax == class_bx

        # Both expressions should be in merged class
        merged_class = builder.classes[class_ax]
        assert "ax" in merged_class.expressions
        assert "bx" in merged_class.expressions

    def test_expr_to_class_mapping(self):
        """Test expression-to-class ID mapping."""
        builder = EquivalenceClassBuilder()
        expressions = ["ax", "bx", "si", "di"]

        classes = builder.build(expressions)

        # Each expression should map to a class
        for expr in expressions:
            assert expr in builder.expr_to_class
            class_id = builder.expr_to_class[expr]
            assert expr in builder.classes[class_id].expressions


class TestTypeCollector:
    """Tests for type constraint collection."""

    def test_collect_constraints_from_classes(self):
        """Test collecting type constraints from expressions."""
        class1 = EquivalenceClass(class_id=1)
        class1.add_expression("bx_offset")  # Pointer-like
        class1.add_expression("si + 4")

        class2 = EquivalenceClass(class_id=2)
        class2.add_expression("ax")
        class2.add_expression("cx")

        expr_classes = {1: class1, 2: class2}

        collector = TypeCollector()
        collector.collect(expr_classes)

        # Class 1 should be recognized as pointer-like
        assert "pointer" in class1.type_constraints

    def test_detect_integer_operations(self):
        """Test detecting integer operation expressions."""
        class1 = EquivalenceClass(class_id=1)
        class1.add_expression("ax * 2")
        class1.add_expression("bx << 1")

        expr_classes = {1: class1}

        collector = TypeCollector()
        collector.collect(expr_classes)

        # Class should be marked as integer
        assert "integer" in class1.type_constraints


class TestTypeVariableReplacer:
    """Tests for type variable resolution."""

    def test_resolve_pointer_types(self):
        """Test resolving pointer type variables."""
        class1 = EquivalenceClass(class_id=1)
        class1.add_type_constraint("pointer")

        replacer = TypeVariableReplacer()
        resolved = replacer.replace({1: class1})

        assert resolved[1] == "ptr_t"

    def test_resolve_integer_types(self):
        """Test resolving integer type variables."""
        class2 = EquivalenceClass(class_id=2)
        class2.add_type_constraint("integer")

        replacer = TypeVariableReplacer()
        resolved = replacer.replace({2: class2})

        assert resolved[2] == "int_t"

    def test_resolve_untyped_to_void(self):
        """Test resolving untyped expressions to void."""
        class3 = EquivalenceClass(class_id=3)
        # No constraints added

        replacer = TypeVariableReplacer()
        resolved = replacer.replace({3: class3})

        assert resolved[3] == "void_t"

    def test_resolve_multiple_classes(self):
        """Test resolving multiple classes with mixed types."""
        class1 = EquivalenceClass(class_id=1)
        class1.add_type_constraint("pointer")

        class2 = EquivalenceClass(class_id=2)
        class2.add_type_constraint("integer")

        class3 = EquivalenceClass(class_id=3)

        replacer = TypeVariableReplacer()
        resolved = replacer.replace({1: class1, 2: class2, 3: class3})

        assert resolved[1] == "ptr_t"
        assert resolved[2] == "int_t"
        assert resolved[3] == "void_t"


class TestPhase2Integration:
    """Integration tests for Phase 2.1 framework."""

    def test_end_to_end_type_analysis(self):
        """Test complete pipeline from expressions to resolved types."""
        # Build equivalence classes
        builder = EquivalenceClassBuilder()
        expressions = ["bx_offset", "si", "ax", "cx"]
        classes = builder.build(expressions)

        # Collect type constraints
        collector = TypeCollector()
        collector.collect(classes)

        # Resolve types
        replacer = TypeVariableReplacer()
        resolved = replacer.replace(classes)

        # Should have resolved types for all classes
        for class_id in classes:
            assert class_id in resolved
            assert resolved[class_id] in ["ptr_t", "int_t", "void_t"]

    def test_type_equivalence_decompiler_pass(self):
        """Test type equivalence pass integration with decompiler."""

        class MockCodegen:
            cfunc = object()
            _inertia_vex_ir_summary = {
                "aliasable_value_count": 3,
                "frame_slot_count": 1,
                "space_counts": {"ds": 2, "ss": 1},
            }

        codegen = MockCodegen()
        result = apply_x86_16_type_equivalence_classes(codegen)

        # Pass should complete without error
        assert result is False  # No direct modifications at this stage
        assert hasattr(codegen, "_inertia_type_equivalence_applied")
        assert codegen._inertia_type_equivalence_applied is True
        assert codegen._inertia_type_equivalence_stats["ir_aliasable_values"] == 3
        assert codegen._inertia_type_equivalence_ir_summary["frame_slot_count"] == 1

    def test_type_equivalence_pass_prefers_typed_ir_artifact_over_flat_summary(self):
        """Typed IR artifact should feed the bounded consumer directly."""

        class MockCodegen:
            cfunc = object()
            _inertia_vex_ir_summary = {
                "aliasable_value_count": 0,
                "frame_slot_count": 0,
                "space_counts": {},
            }
            _inertia_vex_ir_artifact = IRFunctionArtifact(
                function_addr=0x1000,
                blocks=(
                    IRBlock(
                        addr=0x1000,
                        instrs=(
                            IRInstr(
                                "LOAD",
                                IRValue(MemSpace.TMP, name="t0", size=2),
                                (
                                    IRAddress(
                                        MemSpace.DS,
                                        base=("bx", "si"),
                                        offset=2,
                                        size=2,
                                        status=AddressStatus.PROVISIONAL,
                                        segment_origin=SegmentOrigin.DEFAULTED,
                                    ),
                                ),
                                size=2,
                            ),
                            IRInstr(
                                "CJMP",
                                None,
                                (
                                    IRCondition("eq", (IRValue(MemSpace.REG, name="ax", size=2), IRValue(MemSpace.REG, name="bx", size=2))),
                                    IRValue(MemSpace.CONST, const=0x1010, size=2),
                                ),
                            ),
                        ),
                    ),
                ),
            )

        codegen = MockCodegen()
        result = apply_x86_16_type_equivalence_classes(codegen)

        assert result is False
        assert codegen._inertia_type_equivalence_stats["ir_provisional_addresses"] == 1
        assert codegen._inertia_type_equivalence_stats["ir_multi_base_addresses"] == 1
        assert codegen._inertia_type_equivalence_ir_summary["segment_origin_counts"]["defaulted"] == 1
        assert codegen._inertia_type_equivalence_ir_summary["condition_counts"] == {"eq": 1}
        assert codegen._inertia_type_equivalence_resolved_types["value:memspace.reg:ax"] == "int_t"
        assert codegen._inertia_type_equivalence_resolved_types["value:memspace.reg:bx"] == "int_t"
        assert codegen._inertia_type_equivalence_resolved_types["base:ds:bx+si"] == "address_like_t"
        assert codegen._inertia_type_equivalence_resolved_types["cond:eq"] == "bool_t"

    def test_type_equivalence_pass_promotes_stable_typed_address_to_pointer(self):
        class MockCodegen:
            cfunc = object()
            _inertia_vex_ir_artifact = IRFunctionArtifact(
                function_addr=0x2000,
                blocks=(
                    IRBlock(
                        addr=0x2000,
                        instrs=(
                            IRInstr(
                                "LOAD",
                                IRValue(MemSpace.TMP, name="t0", size=2),
                                (
                                    IRAddress(
                                        MemSpace.DS,
                                        base=("bx",),
                                        offset=4,
                                        size=2,
                                        status=AddressStatus.STABLE,
                                        segment_origin=SegmentOrigin.PROVEN,
                                    ),
                                ),
                                size=2,
                            ),
                        ),
                    ),
                ),
            )

        codegen = MockCodegen()
        result = apply_x86_16_type_equivalence_classes(codegen)

        assert result is False
        assert codegen._inertia_type_equivalence_resolved_types["base:ds:bx"] == "ptr_t"
        assert codegen._inertia_type_equivalence_stats["resolved_types"] >= 1

    def test_type_equivalence_pass_uses_function_ssa_phi_nodes(self):
        class MockCodegen:
            cfunc = object()
            _inertia_vex_ir_artifact = IRFunctionArtifact(
                function_addr=0x3000,
                blocks=(
                    IRBlock(addr=0x3000, instrs=(IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), (IRValue(MemSpace.CONST, const=1, size=2),), size=2),)),
                    IRBlock(addr=0x3010, instrs=(IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), (IRValue(MemSpace.CONST, const=2, size=2),), size=2),)),
                ),
            )
            _inertia_vex_ir_function_ssa = SSAFunctionArtifact(
                function_addr=0x3000,
                blocks=(),
                phi_nodes=(
                    SSAPhiNode(
                        block_addr=0x3020,
                        key=("reg", "ax", 0),
                        target=IRValue(MemSpace.REG, name="ax", size=2, version=1, expr=("phi", "0x3020")),
                        incoming=(
                            SSAIncomingValue(0x3000, IRValue(MemSpace.REG, name="ax", size=2, version=0)),
                            SSAIncomingValue(0x3010, IRValue(MemSpace.REG, name="ax", size=2, version=0)),
                        ),
                    ),
                ),
                predecessor_map={0x3020: (0x3000, 0x3010)},
                summary={"phi_node_count": 1},
            )

        codegen = MockCodegen()

        result = apply_x86_16_type_equivalence_classes(codegen)

        assert result is False
        assert codegen._inertia_type_equivalence_stats["ir_phi_nodes"] == 1
        assert codegen._inertia_type_equivalence_resolved_types["value:memspace.reg:ax"] == "int_t"

    def test_type_equivalence_pass_handles_no_cfunc(self):
        """Test pass gracefully handles missing cfunc."""

        class MockCodegen:
            cfunc = None

        codegen = MockCodegen()
        result = apply_x86_16_type_equivalence_classes(codegen)

        # Should return False without error
        assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
