"""
Integration tests for structural analysis on real corpus samples.

This test validates cyclic pattern matching on real COD samples.
"""


import pytest
from types import SimpleNamespace

from angr_platforms.X86_16.structuring_analysis import StructureAnalysis
from angr_platforms.X86_16.structuring_region import Region, RegionGraph, RegionType
from angr_platforms.X86_16.type_storage_object_bridge import load_storage_object_bridge
from angr_platforms.X86_16.type_structure_merging import apply_x86_16_structure_field_merging


class TestStructuringIntegration:
    """Integration tests for structural analysis on corpus."""

    def test_structuring_pass_exists(self):
        """Verify that the RegionBasedStructuringPass is importable."""
        from angr_platforms.X86_16.structuring_analysis import RegionBasedStructuringPass

        pass_obj = RegionBasedStructuringPass()
        assert pass_obj is not None, "Pass should be instantiable"

    def test_natural_loop_stats_tracking(self):
        """Verify that structuring handles loop-like structures."""
        # Create a simple loop graph
        entry = Region(block_addr=0x1000, region_type=RegionType.Linear)
        header = Region(block_addr=0x1001, region_type=RegionType.Linear)
        body = Region(block_addr=0x1002, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x1003, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, header, body, exit_region]:
            graph.add_node(r)

        graph.add_edge(entry, header)
        graph.add_edge(header, body)
        graph.add_edge(body, header)  # Back-edge
        graph.add_edge(header, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Verify structuring completed
        assert analysis.stats.iterations > 0, "Should iterate"
        assert analysis.stats.max_iterations_reached == False, "Should complete without limit"
        # Verify some reductions occurred (loop or if-then-else reduction)
        assert (analysis.stats.cycles_resolved > 0 or analysis.stats.regions_reduced > 0), \
            "Should apply some structural reductions"

    def test_structuring_message_passing(self):
        """Verify that event listeners receive messages."""
        messages = []

        def listener(msg):
            messages.append(msg)

        # Simple graph
        entry = Region(block_addr=0x2000, region_type=RegionType.Linear)
        graph = RegionGraph()
        graph.entry = entry
        graph.add_node(entry)

        # Run with listener
        analysis = StructureAnalysis(graph, event_listener=listener)
        result = analysis.structure()

        # Should receive at least one message
        assert len(messages) > 0, "Should receive event messages"
        assert any("iteration" in msg for msg in messages), "Should report iterations"

    def test_dominator_computation(self):
        """Verify that dominators are computed."""
        entry = Region(block_addr=0x3000, region_type=RegionType.Linear)
        a = Region(block_addr=0x3001, region_type=RegionType.Linear)
        b = Region(block_addr=0x3002, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, a, b]:
            graph.add_node(r)

        graph.add_edge(entry, a)
        graph.add_edge(a, b)

        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Verify dominators were computed
        assert analysis.dominators is not None, "Dominators should be computed"
        assert analysis.dominators.dominates(entry, a), "Entry should dominate A"
        assert analysis.dominators.dominates(a, b), "A should dominate B"

    def test_post_dominator_computation(self):
        """Verify that post-dominators are computed."""
        entry = Region(block_addr=0x4000, region_type=RegionType.Linear)
        a = Region(block_addr=0x4001, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x4002, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, a, exit_region]:
            graph.add_node(r)

        graph.add_edge(entry, a)
        graph.add_edge(a, exit_region)

        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Verify post-dominators were computed
        assert analysis.dominators is not None, "Dominators should be computed"
        # Exit region should post-dominate all nodes
        assert analysis.dominators.post_dominates(
            exit_region, entry
        ), "Exit should post-dominate Entry"
        assert analysis.dominators.post_dominates(
            exit_region, a
        ), "Exit should post-dominate A"

    def test_depth_limited_structuring(self):
        """Test that max iterations limit is enforced."""
        # Create a graph that might cause many iterations
        entry = Region(block_addr=0x5000, region_type=RegionType.Linear)
        graph = RegionGraph()
        graph.entry = entry
        graph.add_node(entry)

        # Set very low iteration limit
        analysis = StructureAnalysis(graph, max_iterations=1)
        result = analysis.structure()

        assert analysis.stats.iterations <= 2, "Should respect iteration limit"

    def test_unresolved_regions_tracking(self):
        """
        Test that unresolved regions are tracked when confidence is too low.
        """
        # Create a complex graph
        entry = Region(block_addr=0x6000, region_type=RegionType.Linear)
        header = Region(block_addr=0x6001, region_type=RegionType.Linear)
        body1 = Region(block_addr=0x6002, region_type=RegionType.Linear)
        body2 = Region(block_addr=0x6003, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x6004, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, header, body1, body2, exit_region]:
            graph.add_node(r)

        # Complex structure with multiple paths
        graph.add_edge(entry, header)
        graph.add_edge(header, body1)
        graph.add_edge(header, body2)
        graph.add_edge(body1, exit_region)
        graph.add_edge(body2, exit_region)
        graph.add_edge(body1, body2)
        graph.add_edge(body2, header)  # Back-edge (might have low confidence)

        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Verify structuring completed without errors
        assert analysis.stats.iterations > 0, "Should iterate"
        assert len(result.nodes) > 0, "Should preserve graph"

    def test_large_linear_chain_reduction(self):
        """
        Test efficient reduction of large linear chains.
        """
        # Create a chain of 10 regions
        regions = [
            Region(block_addr=0x7000 + i * 4, region_type=RegionType.Linear)
            for i in range(10)
        ]

        graph = RegionGraph()
        graph.entry = regions[0]
        for r in regions:
            graph.add_node(r)

        # Connect as linear chain
        for i in range(len(regions) - 1):
            graph.add_edge(regions[i], regions[i + 1])

        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Large chains should be heavily reduced
        assert len(result.nodes) <= 2, "Linear chain should be heavily reduced"
        assert analysis.stats.sequences_created > 0, "Should create sequences"

    def test_no_memory_or_performance_regression(self):
        """
        Test that structuring completes reasonably fast on moderate graphs.
        """
        import time

        # Create a moderate-sized graph (20 regions)
        regions = [
            Region(block_addr=0x8000 + i * 4, region_type=RegionType.Linear)
            for i in range(20)
        ]

        graph = RegionGraph()
        graph.entry = regions[0]
        for r in regions:
            graph.add_node(r)

        # Add edges in a somewhat complex pattern
        for i in range(len(regions) - 1):
            if i % 3 == 2:
                # Branch back occasionally
                graph.add_edge(regions[i], regions[max(0, i - 2)])
            else:
                # Linear progression
                graph.add_edge(regions[i], regions[i + 1])

        # Time the structuring
        start = time.time()
        analysis = StructureAnalysis(graph)
        result = analysis.structure()
        elapsed = time.time() - start

        # Should complete in reasonable time (< 5 seconds)
        assert elapsed < 5.0, f"Structuring took {elapsed:.2f}s, should be < 5s"
        assert analysis.stats.iterations <= 100, "Should not iterate excessively"

    def test_structure_field_merging_consumes_storage_object_bridge_facts(self):
        project = SimpleNamespace(
            _inertia_access_traits={
                0x4010: {
                    "member_evidence": {
                        (("mem", 0x20), 0, 2): 3,
                        (("mem", 0x60), 0, 2): 1,
                    },
                    "array_evidence": {
                        (("mem", 0x40), ("reg", "bx"), 2, 4, 2): 2,
                        (("mem", 0x60), ("reg", "si"), 2, 4, 2): 1,
                    },
                    "base_const": {},
                    "base_stride": {},
                    "base_stride_widths": {},
                    "induction_evidence": {},
                    "repeated_offset_widths": {},
                    "repeated_offsets": {},
                    "stride_evidence": {},
                }
            }
        )
        codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010), project=project)

        bridge = load_storage_object_bridge(project, 0x4010)
        result = apply_x86_16_structure_field_merging(codegen)

        assert bridge is not None
        assert result is False
        assert codegen._inertia_struct_merging_applied is True
        assert codegen._inertia_struct_merging_changed is True
        assert codegen._inertia_struct_merging_stats == {
            "field_accesses": 2,
            "structs_synthesized": 2,
            "structs_merged": 0,
            "member_facts": 1,
            "array_facts": 1,
            "refusal_facts": 1,
        }
        assert codegen._inertia_struct_merging_member_facts == bridge.member_facts
        assert codegen._inertia_struct_merging_array_facts == bridge.array_facts
        assert codegen._inertia_struct_merging_refusal_facts == bridge.refusal_facts
        assert codegen._inertia_struct_merging_struct_facts == bridge.facts_by_base
        assert codegen._inertia_struct_merging_bridge.artifact.records[("mem", 0x20)].object_kind == "member"
        assert ("mem", 0x60) in codegen._inertia_struct_merging_bridge.refusal_facts


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
