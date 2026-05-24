"""
Tests for Phase 2.3: Structure Field Merging

Tests field access pattern collection, struct synthesis,
and multi-function struct layout merging.
"""

import pytest
from types import SimpleNamespace

from angr_platforms.X86_16.ir.core import IRBlock, IRAddress, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.type_structure_merging import (
    FieldAccessCollector,
    FieldAccessPattern,
    StructField,
    StructRecoveryInfo,
    StructType,
    StructureFieldMerger,
    apply_x86_16_structure_field_merging,
)


class TestStructField:
    """Tests for struct field representation."""

    def test_create_struct_field(self):
        """Test creating a struct field."""
        field = StructField(name="x", offset=0, width=16, field_type="int")

        assert field.name == "x"
        assert field.offset == 0
        assert field.width == 16
        assert field.access_count == 0

    def test_struct_field_repr(self):
        """Test struct field string representation."""
        field = StructField(name="count", offset=4, width=32, field_type="int", access_count=5)

        repr_str = repr(field)
        assert "count" in repr_str
        assert "offset=4" in repr_str or "+4" in repr_str

    def test_field_overlap_detection(self):
        """Test detecting overlapping fields."""
        field1 = StructField(name="a", offset=0, width=16, field_type="int")
        field2 = StructField(name="b", offset=1, width=16, field_type="int")  # Overlaps: bytes 1-2
        field3 = StructField(name="c", offset=2, width=16, field_type="int")  # Adjacent, not overlapping

        assert field1.overlaps_with(field2)
        assert not field1.overlaps_with(field3)


class TestStructType:
    """Tests for struct type definition."""

    def test_create_struct_type(self):
        """Test creating a struct type."""
        struct = StructType(name="Point", struct_id=1)

        assert struct.name == "Point"
        assert struct.struct_id == 1
        assert not struct.is_union
        assert len(struct.fields) == 0

    def test_add_field_to_struct(self):
        """Test adding fields to a struct."""
        struct = StructType(name="Data", struct_id=1)

        field1 = StructField(name="id", offset=0, width=16, field_type="int")
        field2 = StructField(name="value", offset=2, width=32, field_type="int")

        struct.add_field(field1)
        struct.add_field(field2)

        assert len(struct.fields) == 2
        assert 0 in struct.fields
        assert 2 in struct.fields

    def test_detect_union_from_overlaps(self):
        """Test detecting union types from overlapping fields."""
        struct = StructType(name="Union", struct_id=1)

        field1 = StructField(name="as_int", offset=0, width=32, field_type="int")
        field2 = StructField(name="as_bytes", offset=0, width=8, field_type="char")

        struct.add_field(field1)
        struct.add_field(field2)

        # Adding overlapping fields should mark as union
        assert struct.is_union

    def test_merge_field_into_struct(self):
        """Test merging a field into existing struct."""
        struct = StructType(name="Merged", struct_id=1)

        field1 = StructField(name="x", offset=0, width=16, field_type="int", access_count=3)
        struct.add_field(field1)

        field2 = StructField(name="x", offset=0, width=16, field_type="int", access_count=2, functions={"f2"})
        struct.merge_field(field2)

        # Merge should increase access count
        assert struct.fields[0].access_count == 5


class TestFieldAccessPattern:
    """Tests for field access patterns."""

    def test_create_field_access(self):
        """Test creating a field access pattern."""
        pattern = FieldAccessPattern(
            struct_base="obj_ptr",
            field_offset=4,
            field_width=16,
            field_name="count",
            access_type="read",
            function="init",
            line_number=42,
        )

        assert pattern.struct_base == "obj_ptr"
        assert pattern.field_offset == 4
        assert pattern.field_name == "count"

    def test_field_access_without_name(self):
        """Test field access with unknown name."""
        pattern = FieldAccessPattern(
            struct_base="ptr",
            field_offset=8,
            field_width=32,
            field_name=None,
            access_type="write",
            function="update",
            line_number=None,
        )

        assert pattern.field_name is None
        assert pattern.access_type == "write"


class TestFieldAccessCollector:
    """Tests for collecting field access patterns."""

    def test_collect_from_function(self):
        """Test collecting access patterns from a function."""
        collector = FieldAccessCollector()

        patterns = [
            FieldAccessPattern("obj", 0, 16, "id", "read", "f1", None),
            FieldAccessPattern("obj", 4, 32, "data", "write", "f1", None),
        ]

        collector.collect_from_function("f1", patterns)

        assert len(collector.patterns) == 2
        assert all(p.function == "f1" for p in collector.patterns)

    def test_get_patterns_for_base(self):
        """Test retrieving patterns for specific base pointer."""
        collector = FieldAccessCollector()

        patterns1 = [FieldAccessPattern("obj_a", 0, 16, "x", "read", "f1", None)]
        patterns2 = [FieldAccessPattern("obj_b", 4, 32, "y", "write", "f1", None)]

        collector.patterns.extend(patterns1)
        collector.patterns.extend(patterns2)

        a_patterns = collector.get_patterns_for_base("obj_a")
        assert len(a_patterns) == 1
        assert a_patterns[0].struct_base == "obj_a"

    def test_get_patterns_by_function(self):
        """Test retrieving patterns by function."""
        collector = FieldAccessCollector()

        patterns = [
            FieldAccessPattern("obj", 0, 16, None, "read", "f1", None),
            FieldAccessPattern("obj", 4, 32, None, "read", "f2", None),
            FieldAccessPattern("obj", 0, 16, None, "write", "f1", None),
        ]

        collector.patterns.extend(patterns)

        f1_patterns = collector.get_patterns_by_function("f1")
        assert len(f1_patterns) == 2
        assert all(p.function == "f1" for p in f1_patterns)


class TestStructureFieldMerger:
    """Tests for merging structs."""

    def test_merge_patterns_into_structs(self):
        """Test merging field access patterns into struct definitions."""
        merger = StructureFieldMerger()

        patterns = [
            FieldAccessPattern("obj_ptr", 0, 16, "id", "read", "func1", None),
            FieldAccessPattern("obj_ptr", 2, 32, "value", "write", "func1", None),
            FieldAccessPattern("obj_ptr", 0, 16, "id", "read", "func2", None),
            FieldAccessPattern("data_ptr", 4, 16, "size", "read", "func2", None),
        ]

        structs = merger.merge_structs(patterns)

        # Should have one struct for obj_ptr and one for data_ptr
        assert len(structs) >= 1
        assert any("obj_ptr" in name for name in structs.keys())

    def test_detect_union_in_merge(self):
        """Test detecting union types during merge."""
        merger = StructureFieldMerger()

        patterns = [
            FieldAccessPattern("var", 0, 32, "as_int", "read", "f1", None),
            FieldAccessPattern("var", 0, 8, "as_byte", "read", "f1", None),
        ]

        structs = merger.merge_structs(patterns)

        # Should mark struct as union due to overlapping field
        struct = list(structs.values())[0]
        assert struct.is_union

    def test_confidence_from_multi_function_access(self):
        """Test confidence increases with multi-function access."""
        merger = StructureFieldMerger()

        patterns = [
            FieldAccessPattern("ptr", 0, 16, "x", "read", "f1", None),
            FieldAccessPattern("ptr", 0, 16, "x", "read", "f2", None),
            FieldAccessPattern("ptr", 0, 16, "x", "read", "f3", None),
        ]

        structs = merger.merge_structs(patterns)

        struct = list(structs.values())[0]
        # More functions accessing = higher confidence
        assert struct.confidence > 0.5

    def test_are_compatible_structs(self):
        """Test checking struct compatibility."""
        merger = StructureFieldMerger()

        struct1 = StructType("s1", 1)
        struct1.add_field(StructField("a", 0, 16, "int"))
        struct1.add_field(StructField("b", 2, 32, "int"))

        struct2 = StructType("s2", 2)
        struct2.add_field(StructField("x", 0, 16, "int"))
        struct2.add_field(StructField("y", 2, 32, "int"))

        # Same layout at same offsets
        assert merger._are_compatible(struct1, struct2)

    def test_incompatible_structs_different_widths(self):
        """Test detecting incompatible structs."""
        merger = StructureFieldMerger()

        struct1 = StructType("s1", 1)
        struct1.add_field(StructField("a", 0, 16, "int"))

        struct2 = StructType("s2", 2)
        struct2.add_field(StructField("b", 0, 32, "int"))

        # Different width at same offset - incompatible
        assert not merger._are_compatible(struct1, struct2)


class TestStructRecoveryInfo:
    """Tests for struct recovery metadata."""

    def test_create_recovery_info(self):
        """Test creating struct recovery info."""
        struct_type = StructType("Data", 1)
        struct_type.add_field(StructField("x", 0, 16, "int"))
        struct_type.total_size = 2
        struct_type.confidence = 0.8

        info = StructRecoveryInfo(struct_type)

        assert info.name == "Data"
        assert info.size == 2
        assert info.confidence == 0.8


class TestPhase23Integration:
    """Integration tests for structure field merging."""

    def test_end_to_end_struct_merging(self):
        """Test complete struct merging pipeline."""
        collector = FieldAccessCollector()

        patterns = [
            FieldAccessPattern("window", 0, 16, "x", "read", "render", None),
            FieldAccessPattern("window", 2, 16, "y", "read", "render", None),
            FieldAccessPattern("window", 0, 16, "x", "write", "update", None),
            FieldAccessPattern("window", 2, 16, "y", "write", "update", None),
        ]

        collector.collect_from_function("render", patterns[:2])
        collector.collect_from_function("update", patterns[2:])

        merger = StructureFieldMerger()
        structs = merger.merge_structs(collector.patterns)

        assert len(structs) > 0
        struct = list(structs.values())[0]
        assert "x" in [f.name for f in struct.fields.values()]
        assert "y" in [f.name for f in struct.fields.values()]

    def test_struct_merging_decompiler_pass(self):
        """Test struct merging pass integration with decompiler."""

        class MockCodegen:
            cfunc = object()

        codegen = MockCodegen()
        result = apply_x86_16_structure_field_merging(codegen)

        assert result is False  # No direct modifications
        assert hasattr(codegen, "_inertia_struct_merging_applied")
        assert codegen._inertia_struct_merging_applied is True

    def test_struct_merging_uses_typed_ir_phi_backed_offsets(self):
        """Typed IR + function SSA should synthesize bounded struct-layout evidence."""

        artifact = IRFunctionArtifact(
            function_addr=0x1000,
            blocks=(
                IRBlock(
                    addr=0x1000,
                    successor_addrs=(0x1020, 0x1010),
                    instrs=(
                        IRInstr("MOV", IRValue(MemSpace.REG, name="si", size=2), (IRValue(MemSpace.CONST, const=0),), size=2),
                    ),
                ),
                IRBlock(
                    addr=0x1010,
                    successor_addrs=(0x1020,),
                    instrs=(
                        IRInstr("MOV", IRValue(MemSpace.REG, name="si", size=2), (IRValue(MemSpace.CONST, const=2),), size=2),
                    ),
                ),
                IRBlock(
                    addr=0x1020,
                    instrs=(
                        IRInstr(
                            "LOAD",
                            IRValue(MemSpace.TMP, name="t0", size=2),
                            (IRAddress(MemSpace.DS, base=("bx", "si"), offset=0, size=2),),
                            size=2,
                        ),
                        IRInstr(
                            "LOAD",
                            IRValue(MemSpace.TMP, name="t1", size=2),
                            (IRAddress(MemSpace.DS, base=("bx", "si"), offset=2, size=2),),
                            size=2,
                        ),
                    ),
                ),
            ),
        )

        codegen = SimpleNamespace(
            cfunc=SimpleNamespace(addr=0x1000),
            project=SimpleNamespace(_inertia_access_traits={}),
            _inertia_vex_ir_artifact=artifact,
            _inertia_vex_ir_function_ssa=build_x86_16_function_ssa(artifact),
        )

        result = apply_x86_16_structure_field_merging(codegen)

        assert result is False
        assert codegen._inertia_struct_merging_changed is True
        assert codegen._inertia_struct_merging_typed_ir_facts == {
            ("ds", ("bx", "si")): {
                "space": "ds",
                "base": ("bx", "si"),
                "candidate_offsets": (0, 2),
                "candidate_widths": (2,),
                "has_phi_evidence": True,
            }
        }
        assert codegen._inertia_struct_merging_stats["structs_synthesized"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
