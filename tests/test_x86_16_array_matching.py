"""
Tests for Phase 2.2: Array Expression Matching

Tests induction variable collection, array pattern detection,
and array recovery metadata synthesis.
"""

from types import SimpleNamespace

import pytest

from angr_platforms.X86_16.ir import IRAddress, IRStringEffectArtifact, IRStringEffectRecord
from angr_platforms.X86_16.ir.core import AddressStatus, MemSpace, SegmentOrigin
from angr_platforms.X86_16.type_array_matching import (
    ArrayAccessPattern,
    ArrayExpressionMatcher,
    ArrayRecoveryInfo,
    InductionVariable,
    InductionVariableCollector,
    apply_x86_16_array_expression_matching,
    _cached_access_trait_profiles_8616,
)


class TestInductionVariable:
    """Tests for induction variable representation."""

    def test_create_induction_variable(self):
        """Test creating an induction variable."""
        ind_var = InductionVariable(
            var_name="si", stride=2, base_value=0, loop_bound=100, element_width=16
        )

        assert ind_var.var_name == "si"
        assert ind_var.stride == 2
        assert ind_var.element_width == 16

    def test_induction_variable_repr(self):
        """Test induction variable string representation."""
        ind_var = InductionVariable(
            var_name="di", stride=4, base_value=0, loop_bound=None, element_width=32
        )

        repr_str = repr(ind_var)
        assert "di" in repr_str
        assert "stride=4" in repr_str


class TestArrayAccessPattern:
    """Tests for array access pattern detection."""

    def test_create_array_access_pattern(self):
        """Test creating an array access pattern."""
        pattern = ArrayAccessPattern(
            base_expr="buffer",
            index_var="i",
            stride=2,
            offset=0,
            element_type="int",
            element_width=16,
        )

        assert pattern.base_expr == "buffer"
        assert pattern.index_var == "i"
        assert pattern.stride == 2

    def test_array_access_pattern_repr(self):
        """Test array access pattern representation."""
        pattern = ArrayAccessPattern(
            base_expr="data", index_var="j", stride=4, offset=8, element_type="struct", element_width=32
        )

        repr_str = repr(pattern)
        assert "data" in repr_str
        assert "j" in repr_str


class TestArrayRecoveryInfo:
    """Tests for array recovery metadata."""

    def test_create_array_recovery_info(self):
        """Test creating array recovery metadata."""
        info = ArrayRecoveryInfo(
            array_name="numbers",
            base_ptr="base",
            element_type="int",
            element_width=16,
            element_stride=2,
            access_patterns=set(),
            confidence=0.8,
        )

        assert info.array_name == "numbers"
        assert info.element_type == "int"
        assert info.confidence == 0.8

    def test_array_recovery_info_with_patterns(self):
        """Test array recovery info tracking access patterns."""
        info = ArrayRecoveryInfo(
            array_name="arr",
            base_ptr="ptr",
            element_type="char",
            element_width=8,
            element_stride=1,
            access_patterns={"read[0]", "write[4]"},
            confidence=0.6,
        )

        assert len(info.access_patterns) == 2
        assert "read[0]" in info.access_patterns


class TestInductionVariableCollector:
    """Tests for collecting induction variables."""

    def test_collect_simple_induction(self):
        """Test collecting simple induction variables."""
        collector = InductionVariableCollector()
        expressions = ["si += 2", "di += 4", "cx -= 1"]

        vars = collector.collect(expressions)

        assert "si" in vars
        assert vars["si"].stride == 2
        assert "di" in vars
        assert vars["di"].stride == 4

    def test_stride_pattern_extraction(self):
        """Test extracting stride patterns."""
        collector = InductionVariableCollector()

        collector._analyze_update_expr("bx += 8")

        assert "bx" in collector.stride_patterns
        assert collector.stride_patterns["bx"] == 8

    def test_handle_invalid_stride(self):
        """Test gracefully handling invalid stride expressions."""
        collector = InductionVariableCollector()

        collector._analyze_update_expr("ax += invalid")

        # Should not crash, just skip
        assert "ax" not in collector.stride_patterns


class TestArrayExpressionMatcher:
    """Tests for matching array expressions."""

    def test_looks_like_array_access(self):
        """Test heuristic array access detection."""
        matcher = ArrayExpressionMatcher()

        assert matcher._looks_like_array_access("buffer[0]")
        assert matcher._looks_like_array_access("mem[si]")
        assert matcher._looks_like_array_access("base + i * 2")
        assert not matcher._looks_like_array_access("simple_var")

    def test_match_patterns_with_induction(self):
        """Test matching array patterns with induction variables."""
        matcher = ArrayExpressionMatcher()

        ind_var = InductionVariable(
            var_name="i", stride=2, base_value=0, loop_bound=100, element_width=16
        )
        induction_vars = {"i": ind_var}

        expressions = ["buffer[i]", "mem[si + i * 2]", "data[i]"]

        patterns = matcher.match_patterns(expressions, induction_vars)

        # Should detect at least one array pattern
        assert len(patterns) > 0

    def test_extract_array_pattern(self):
        """Test extracting specific array patterns."""
        matcher = ArrayExpressionMatcher()

        ind_var = InductionVariable(
            var_name="j", stride=4, base_value=0, loop_bound=None, element_width=32
        )
        induction_vars = {"j": ind_var}

        pattern = matcher._extract_array_pattern("arr[j * 4]", induction_vars)

        assert pattern is not None
        assert pattern.index_var == "j"
        assert pattern.stride == 4

    def test_synthesize_arrays_from_patterns(self):
        """Test synthesizing array recovery info from patterns."""
        matcher = ArrayExpressionMatcher()

        patterns = [
            ArrayAccessPattern("buffer", "i", 2, 0, "int", 16),
            ArrayAccessPattern("buffer", "i", 2, 2, "int", 16),
            ArrayAccessPattern("data", "j", 4, 0, "struct", 32),
        ]

        arrays = matcher.synthesize_arrays(patterns)

        assert "buffer" in arrays
        assert "data" in arrays
        assert len(arrays["buffer"].access_patterns) == 2
        assert arrays["buffer"].confidence > 0.5


class TestPhase22Integration:
    """Integration tests for array expression matching."""

    def test_end_to_end_array_matching(self):
        """Test complete array matching pipeline."""
        # Collect induction variables
        collector = InductionVariableCollector()
        expressions = ["si += 2", "di += 4"]
        ind_vars = collector.collect(expressions)

        assert len(ind_vars) > 0

        # Match array patterns
        matcher = ArrayExpressionMatcher()
        access_exprs = ["buffer[si]", "data[di]", "arr[si + 4]"]
        patterns = matcher.match_patterns(access_exprs, ind_vars)

        # Synthesize arrays
        arrays = matcher.synthesize_arrays(patterns)

        assert len(arrays) > 0

    def test_array_matching_decompiler_pass(self):
        """Test array matching pass integration with decompiler."""

        class MockCodegen:
            cfunc = object()

        codegen = MockCodegen()
        result = apply_x86_16_array_expression_matching(codegen)

        assert result is False  # No direct modifications
        assert hasattr(codegen, "_inertia_array_matching_applied")
        assert codegen._inertia_array_matching_applied is True
        assert codegen._inertia_array_matching_stats["recovered_arrays"] == 0
        assert codegen._inertia_array_matching_typed_ir_candidates == {}
        assert codegen._inertia_array_matching_string_candidates == {}

    def test_array_matching_uses_typed_string_effect_candidates(self):
        codegen = SimpleNamespace(
            cfunc=SimpleNamespace(addr=0x5000),
            project=None,
            _inertia_string_effect_artifact=IRStringEffectArtifact(
                records=(
                    IRStringEffectRecord(
                        index=0,
                        family="movs",
                        repeat_kind="rep",
                        width=2,
                        direction_mode="forward",
                        source=IRAddress(
                            space=MemSpace.DS,
                            base=("si",),
                            size=2,
                            status=AddressStatus.STABLE,
                            segment_origin=SegmentOrigin.PROVEN,
                        ),
                        destination=IRAddress(
                            space=MemSpace.ES,
                            base=("di",),
                            size=2,
                            status=AddressStatus.STABLE,
                            segment_origin=SegmentOrigin.PROVEN,
                        ),
                        zf_sensitive=False,
                        zero_seeded_accumulator=None,
                    ),
                )
            ),
        )

        result = apply_x86_16_array_expression_matching(codegen)

        assert result is False
        assert codegen._inertia_array_matching_string_candidates == {
            ("ds", ("si",), 2): {
                "space": "ds",
                "base": ("si",),
                "element_size": 2,
                "has_string_effect": True,
                "segment_origin": "proven",
                "string_family": "movs",
                "repeat_kind": "rep",
                "role": "source",
            },
            ("es", ("di",), 2): {
                "space": "es",
                "base": ("di",),
                "element_size": 2,
                "has_string_effect": True,
                "segment_origin": "proven",
                "string_family": "movs",
                "repeat_kind": "rep",
                "role": "destination",
            },
        }
        assert codegen._inertia_array_matching_stats["string_arrays"] == 2
        assert codegen._inertia_array_matching_stats["recovered_arrays"] == 2

    def test_array_matching_caps_typed_candidate_sets(self):
        records = []
        for index in range(70):
            records.append(
                IRStringEffectRecord(
                    index=index,
                    family="movs",
                    repeat_kind="rep",
                    width=2,
                    direction_mode="forward",
                    source=IRAddress(
                        space=MemSpace.DS,
                        base=(f"si{index}",),
                        size=2,
                        status=AddressStatus.STABLE,
                        segment_origin=SegmentOrigin.PROVEN,
                    ),
                    destination=IRAddress(
                        space=MemSpace.ES,
                        base=(f"di{index}",),
                        size=2,
                        status=AddressStatus.STABLE,
                        segment_origin=SegmentOrigin.PROVEN,
                    ),
                    zf_sensitive=False,
                    zero_seeded_accumulator=None,
                )
            )

        codegen = SimpleNamespace(
            cfunc=SimpleNamespace(addr=0x5000),
            project=None,
            _inertia_string_effect_artifact=IRStringEffectArtifact(records=tuple(records)),
        )

        result = apply_x86_16_array_expression_matching(codegen)

        assert result is False
        assert len(codegen._inertia_array_matching_string_candidates) == 64
        assert codegen._inertia_array_matching_stats["string_arrays"] == 64

    def test_array_matching_reuses_access_trait_profile_cache(self):
        project = SimpleNamespace(
            _inertia_access_traits={
                0x4010: {
                    "member_evidence": {
                        ("member", ("reg", "si"), 2): 3,
                    }
                }
            }
        )

        call_count = {"count": 0}

        def _build_access_trait_evidence_profiles(traits):
            call_count["count"] += 1
            return {("reg", "si"): object()}

        from angr_platforms.X86_16 import type_array_matching as array_matching

        original = array_matching.build_access_trait_evidence_profiles
        array_matching.build_access_trait_evidence_profiles = _build_access_trait_evidence_profiles
        try:
            first = _cached_access_trait_profiles_8616(project, 0x4010)
            second = _cached_access_trait_profiles_8616(project, 0x4010)
        finally:
            array_matching.build_access_trait_evidence_profiles = original

        assert first is second
        assert call_count["count"] == 1
        assert project._inertia_access_trait_profiles_cache[(0x4010, id(project._inertia_access_traits[0x4010]))] is first

    def test_array_matching_refuses_over_associated_segmented_storage(self):
        stable_key = ("ss", ("stack", "bp", -4))
        refused_key = ("ds", ("mem", 0x40))
        project = SimpleNamespace(
            _inertia_access_traits={0x4030: {"member_evidence": {}}},
        )
        codegen = SimpleNamespace(
            cfunc=SimpleNamespace(addr=0x4030),
            project=project,
            _inertia_segmented_memory_lowering={
                "SS": {
                    "classification": "const",
                    "associated_space": "stack",
                    "allow_linear_lowering": True,
                    "allow_object_lowering": True,
                    "reason": "constant stack segment",
                },
                "DS": {
                    "classification": "over_associated",
                    "associated_space": "data",
                    "allow_linear_lowering": False,
                    "allow_object_lowering": False,
                    "reason": "segment space is over-associated",
                },
            },
        )

        from inertia_decompiler.cli_access_object_hints import AccessTraitObjectHint
        from inertia_decompiler.cli_access_profiles import AccessTraitEvidenceProfile
        from angr_platforms.X86_16 import type_array_matching as array_matching

        bridge_loader = array_matching.load_storage_object_bridge
        array_matching.load_storage_object_bridge = lambda _project, _addr, *, codegen=None: bridge_loader(
            _project,
            _addr,
            codegen=codegen,
            build_access_trait_evidence_profiles=lambda _traits: {
                stable_key: AccessTraitEvidenceProfile(array_like=((0, 2, 3),)),
                refused_key: AccessTraitEvidenceProfile(array_like=((0, 2, 2),)),
            },
            build_stable_access_object_hints=lambda _traits: {
                stable_key: AccessTraitObjectHint(stable_key, "array", ((0, 2, 3),)),
                refused_key: AccessTraitObjectHint(refused_key, "array", ((0, 2, 2),)),
            },
        )
        try:
            result = apply_x86_16_array_expression_matching(codegen)
        finally:
            array_matching.load_storage_object_bridge = bridge_loader

        assert result is False
        assert set(codegen._inertia_array_matching_lowerable_arrays) == {stable_key}
        assert codegen._inertia_array_matching_refused_arrays == {
            refused_key: "segment space is over-associated"
        }
        assert codegen._inertia_array_matching_stats == {
            "induction_vars": 0,
            "array_patterns": 2,
            "recovered_arrays": 1,
            "refused_arrays": 1,
            "string_arrays": 0,
        }

    def test_array_matching_recovers_typed_ir_candidate_from_phi_index(self):
        from angr_platforms.X86_16.ir.core import (
            AddressStatus,
            IRAddress,
            IRBlock,
            IRFunctionArtifact,
            IRInstr,
            IRValue,
            MemSpace,
            SegmentOrigin,
        )
        from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact, SSAIncomingValue, SSAPhiNode

        class MockCodegen:
            cfunc = SimpleNamespace(addr=0x5000)
            _inertia_vex_ir_artifact = IRFunctionArtifact(
                function_addr=0x5000,
                blocks=(
                    IRBlock(
                        addr=0x5000,
                        instrs=(
                            IRInstr(
                                "LOAD",
                                IRValue(MemSpace.TMP, name="t0", size=2),
                                (
                                    IRAddress(
                                        MemSpace.DS,
                                        base=("bx", "si"),
                                        offset=0,
                                        size=2,
                                        status=AddressStatus.PROVISIONAL,
                                        segment_origin=SegmentOrigin.DEFAULTED,
                                    ),
                                ),
                                size=2,
                            ),
                        ),
                    ),
                ),
            )
            _inertia_vex_ir_function_ssa = SSAFunctionArtifact(
                function_addr=0x5000,
                blocks=(),
                phi_nodes=(
                    SSAPhiNode(
                        block_addr=0x5000,
                        key=("reg", "si", 0),
                        target=IRValue(MemSpace.REG, name="si", size=2, version=1, expr=("phi", "0x5000")),
                        incoming=(
                            SSAIncomingValue(0x4FF0, IRValue(MemSpace.REG, name="si", size=2, version=0)),
                            SSAIncomingValue(0x4FF8, IRValue(MemSpace.REG, name="si", size=2, version=0)),
                        ),
                    ),
                ),
                predecessor_map={0x5000: (0x4FF0, 0x4FF8)},
                summary={"phi_node_count": 1},
            )

        codegen = MockCodegen()

        result = apply_x86_16_array_expression_matching(codegen)

        assert result is False
        assert codegen._inertia_array_matching_typed_ir_candidates == {
            ("ds", ("bx", "si"), 2): {
                "space": "ds",
                "base": ("bx", "si"),
                "element_size": 2,
                "has_phi_index": True,
            }
        }
        assert codegen._inertia_array_matching_stats == {
            "induction_vars": 1,
            "array_patterns": 0,
            "recovered_arrays": 1,
            "refused_arrays": 0,
            "string_arrays": 0,
        }

    def test_multi_dimensional_array_detection(self):
        """Test detecting multi-dimensional array patterns."""
        matcher = ArrayExpressionMatcher()

        ind_var1 = InductionVariable("i", stride=10, base_value=0, loop_bound=100, element_width=16)
        ind_var2 = InductionVariable("j", stride=1, base_value=0, loop_bound=10, element_width=16)

        induction_vars = {"i": ind_var1, "j": ind_var2}

        expressions = ["matrix[i + j * 10]", "grid[i * 10 + j]"]
        patterns = matcher.match_patterns(expressions, induction_vars)

        # Should detect multi-dimensional patterns
        assert len(patterns) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
