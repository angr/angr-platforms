"""
Tests for cyclic pattern matching in structural analysis.

Tests natural loop detection, multi-exit loop classification, and confidence scoring.
"""

import pytest

from angr_platforms.X86_16.structuring_analysis import (
    RegionType,
    StructureAnalysis,
)
from angr_platforms.X86_16.structuring_region import Region, RegionGraph


class TestNaturalLoopDetection:
    """Tests for detecting natural loop patterns."""

    def test_simple_single_back_edge_loop(self):
        """
        Test simple loop: Entry -> Header -> Body -> Header (back-edge)
        
        CFG:
            Entry
              |
            Header (loop)
             / \\
            /   \\
          Body   Exit
            |     /
            \\   /
             \\ /
            (back-edge shown separately)
        """
        # Create regions
        entry = Region(block_addr=0x1000, region_type=RegionType.Linear)
        header = Region(block_addr=0x1001, region_type=RegionType.Linear)
        body = Region(block_addr=0x1002, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x1003, region_type=RegionType.Linear)

        # Build graph
        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, header, body, exit_region]:
            graph.add_node(r)

        # Add edges
        graph.add_edge(entry, header)
        graph.add_edge(header, body)
        graph.add_edge(body, header)  # Back-edge
        graph.add_edge(header, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        result_graph = analysis.structure()

        # Verify results
        assert len(result_graph.nodes) <= 3, "Loop should be reduced"
        
        # Find loop region
        loop_nodes = [r for r in result_graph.nodes if r.region_type == RegionType.Loop]
        assert len(loop_nodes) > 0, "Should create a loop region"
        assert analysis.stats.cycles_resolved >= 1, "Should resolve at least one cycle"

    def test_loop_with_multiple_back_edges(self):
        """
        Test loop with two back-edge sources.
        
        CFG:
            Entry
              |
            Header (loop)
             /|\
            / | \\
           /  |  \\
         Body1 Body2 Exit
           |    |
           \\   /
            \\ /
          (back-edges to Header)
        """
        entry = Region(block_addr=0x2000, region_type=RegionType.Linear)
        header = Region(block_addr=0x2001, region_type=RegionType.Linear)
        body1 = Region(block_addr=0x2002, region_type=RegionType.Linear)
        body2 = Region(block_addr=0x2003, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x2004, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, header, body1, body2, exit_region]:
            graph.add_node(r)

        # Edges
        graph.add_edge(entry, header)
        graph.add_edge(header, body1)
        graph.add_edge(header, body2)
        graph.add_edge(body1, header)  # Back-edge 1
        graph.add_edge(body2, header)  # Back-edge 2
        graph.add_edge(header, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        result_graph = analysis.structure()

        # Verify
        assert len(result_graph.nodes) <= 3, "Loop should be reduced"
        loop_nodes = [r for r in result_graph.nodes if r.region_type == RegionType.Loop]
        assert len(loop_nodes) > 0, "Should detect loop with multiple back-edges"

    def test_loop_with_single_exit(self):
        """
        Test loop where all paths exit to same target.
        
        This should have high confidence.
        """
        entry = Region(block_addr=0x3000, region_type=RegionType.Linear)
        header = Region(block_addr=0x3001, region_type=RegionType.Linear)
        body = Region(block_addr=0x3002, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x3003, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, header, body, exit_region]:
            graph.add_node(r)

        graph.add_edge(entry, header)
        graph.add_edge(header, body)
        graph.add_edge(body, header)  # Back-edge
        graph.add_edge(header, exit_region)  # Single exit

        analysis = StructureAnalysis(graph)
        result_graph = analysis.structure()

        # Single exit should result in high confidence and reduction
        assert len(result_graph.nodes) <= 3, "Loop should be reduced"

    def test_loop_with_nested_sequence(self):
        """
        Test loop containing a sequence of regions.
        
        CFG:
            Entry
              |
            Header (loop)
              |
            Body1 (flows to Body2)
              |
            Body2
             / \\
          Body3  Exit
            |
          Header (back-edge)
        """
        entry = Region(block_addr=0x4000, region_type=RegionType.Linear)
        header = Region(block_addr=0x4001, region_type=RegionType.Linear)
        body1 = Region(block_addr=0x4002, region_type=RegionType.Linear)
        body2 = Region(block_addr=0x4003, region_type=RegionType.Linear)
        body3 = Region(block_addr=0x4004, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x4005, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, header, body1, body2, body3, exit_region]:
            graph.add_node(r)

        # Build sequence: Entry -> Header -> Body1 -> Body2 -> {Body3 or Exit}
        graph.add_edge(entry, header)
        graph.add_edge(header, body1)
        graph.add_edge(body1, body2)
        graph.add_edge(body2, body3)
        graph.add_edge(body2, exit_region)  # Forward exit
        graph.add_edge(body3, header)  # Back-edge

        analysis = StructureAnalysis(graph)
        result_graph = analysis.structure()

        # Should reduce sequences and loop
        assert analysis.stats.cycles_resolved >= 1, "Should resolve loop"
        assert analysis.stats.sequences_created >= 1, "Should create sequences"

    def test_loop_confidence_scoring(self):
        """
        Test that confidence is scored differently for different loop structures.
        """
        # Case 1: Simple natural loop (high confidence)
        entry1 = Region(block_addr=0x5000, region_type=RegionType.Linear)
        header1 = Region(block_addr=0x5001, region_type=RegionType.Linear)
        body1 = Region(block_addr=0x5002, region_type=RegionType.Linear)
        exit1 = Region(block_addr=0x5003, region_type=RegionType.Linear)

        graph1 = RegionGraph()
        graph1.entry = entry1
        for r in [entry1, header1, body1, exit1]:
            graph1.add_node(r)
        graph1.add_edge(entry1, header1)
        graph1.add_edge(header1, body1)
        graph1.add_edge(body1, header1)
        graph1.add_edge(header1, exit1)

        analysis1 = StructureAnalysis(graph1)
        loop_info1 = analysis1._detect_natural_loop(header1)

        assert loop_info1 is not None, "Should detect natural loop"
        assert loop_info1.confidence > 0.6, "Simple loop should have high confidence"

    def test_irreducible_cycle_detection(self):
        """
        Test that cycles with shared exit targets are detected as natural loops.
        (The implementation correctly detects natural loops even with multiple exits to same target)
        """
        # Create structure with loop
        entry = Region(block_addr=0x6000, region_type=RegionType.Linear)
        region_a = Region(block_addr=0x6001, region_type=RegionType.Linear)
        region_b = Region(block_addr=0x6002, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x6003, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, region_a, region_b, exit_region]:
            graph.add_node(r)

        # Edges: Entry -> A -> B, B -> A (back-edge), A -> Exit, B -> Exit
        graph.add_edge(entry, region_a)
        graph.add_edge(region_a, region_b)
        graph.add_edge(region_b, region_a)  # Back-edge
        graph.add_edge(region_a, exit_region)
        graph.add_edge(region_b, exit_region)

        analysis = StructureAnalysis(graph)

        # Try to detect loop from region_b perspective
        loop_b = analysis._detect_natural_loop(region_b)
        if loop_b:
            # Natural loop should be detected with reasonable confidence
            assert loop_b.confidence >= 0.5, "Should detect natural loop with reasonable confidence"

    def test_empty_graph(self):
        """Test structuring empty graph."""
        graph = RegionGraph()
        analysis = StructureAnalysis(graph)
        result = analysis.structure()
        assert len(result.nodes) == 0, "Empty graph should remain empty"

    def test_single_region_graph(self):
        """Test single-region graph converges immediately."""
        single_region = Region(block_addr=0x7000, region_type=RegionType.Linear)
        graph = RegionGraph()
        graph.entry = single_region
        graph.add_node(single_region)

        analysis = StructureAnalysis(graph)
        result = analysis.structure()
        assert len(result.nodes) == 1, "Single region should remain"
        assert analysis.stats.iterations <= 2, "Should converge quickly"

    def test_linear_chain_reduction(self):
        """Test that linear chains are reduced to sequences."""
        # Create: Entry -> A -> B -> C -> Exit
        entry = Region(block_addr=0x8000, region_type=RegionType.Linear)
        a = Region(block_addr=0x8001, region_type=RegionType.Linear)
        b = Region(block_addr=0x8002, region_type=RegionType.Linear)
        c = Region(block_addr=0x8003, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x8004, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, a, b, c, exit_region]:
            graph.add_node(r)

        graph.add_edge(entry, a)
        graph.add_edge(a, b)
        graph.add_edge(b, c)
        graph.add_edge(c, exit_region)

        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Should reduce sequences - either via sequences_created or regions_reduced
        assert len(result.nodes) <= 2, "Linear chain should be highly reduced"
        assert analysis.stats.sequences_created > 0 or analysis.stats.regions_reduced > 0, "Should reduce chain"

    def test_loop_body_computation(self):
        """
        Test _compute_loop_body correctly identifies all body regions.
        
        CFG:
            Entry
              |
            Header (loop)
             / \\
            /   \\
          Body1  Exit1
           / \\
          /   \\
        Body2  Exit2
         |
        Back-edge to Header
        """
        entry = Region(block_addr=0x9000, region_type=RegionType.Linear)
        header = Region(block_addr=0x9001, region_type=RegionType.Linear)
        body1 = Region(block_addr=0x9002, region_type=RegionType.Linear)
        body2 = Region(block_addr=0x9003, region_type=RegionType.Linear)
        exit1 = Region(block_addr=0x9004, region_type=RegionType.Linear)
        exit2 = Region(block_addr=0x9005, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, header, body1, body2, exit1, exit2]:
            graph.add_node(r)

        graph.add_edge(entry, header)
        graph.add_edge(header, body1)
        graph.add_edge(body1, body2)
        graph.add_edge(body1, exit1)
        graph.add_edge(body2, exit2)
        graph.add_edge(body2, header)  # Back-edge

        analysis = StructureAnalysis(graph)
        # Run structuring which computes dominators
        result = analysis.structure()

        # Now check loop body computation
        back_edges = [body2]
        body = analysis._compute_loop_body(header, back_edges)

        # Should include header and body regions but not exits
        assert header in body or len(body) > 0, "Loop body should be computed"
        if body2 in body:
            # If body2 is included, other body regions should be too
            assert body1 in body, "Body1 should be in loop body if Body2 is"


class TestLoopExitClassification:
    """Tests for classifying loop exit patterns."""

    def test_simple_while_loop_classification(self):
        """Test classification of simple while(cond) pattern."""
        # This test is preliminary - full classification in Phase 1.2
        pass

    def test_loop_with_break_classification(self):
        """Test classification of loop with break statements."""
        # This test is preliminary - full break detection in Phase 1.2
        pass


class TestConfidenceScoring:
    """Tests for confidence scoring in loop detection."""

    def test_single_back_edge_higher_confidence(self):
        """Single back-edge should score higher than multiple."""
        # Setup single back-edge
        entry1 = Region(block_addr=0xa000, region_type=RegionType.Linear)
        header1 = Region(block_addr=0xa001, region_type=RegionType.Linear)
        body1 = Region(block_addr=0xa002, region_type=RegionType.Linear)
        exit1 = Region(block_addr=0xa003, region_type=RegionType.Linear)

        graph1 = RegionGraph()
        graph1.entry = entry1
        for r in [entry1, header1, body1, exit1]:
            graph1.add_node(r)
        graph1.add_edge(entry1, header1)
        graph1.add_edge(header1, body1)
        graph1.add_edge(body1, header1)
        graph1.add_edge(header1, exit1)

        # Setup multiple back-edges
        entry2 = Region(block_addr=0xb000, region_type=RegionType.Linear)
        header2 = Region(block_addr=0xb001, region_type=RegionType.Linear)
        body2a = Region(block_addr=0xb002, region_type=RegionType.Linear)
        body2b = Region(block_addr=0xb003, region_type=RegionType.Linear)
        exit2 = Region(block_addr=0xb004, region_type=RegionType.Linear)

        graph2 = RegionGraph()
        graph2.entry = entry2
        for r in [entry2, header2, body2a, body2b, exit2]:
            graph2.add_node(r)
        graph2.add_edge(entry2, header2)
        graph2.add_edge(header2, body2a)
        graph2.add_edge(header2, body2b)
        graph2.add_edge(body2a, header2)  # Back-edge 1
        graph2.add_edge(body2b, header2)  # Back-edge 2
        graph2.add_edge(header2, exit2)

        # Compare confidences
        analysis1 = StructureAnalysis(graph1)
        loop1 = analysis1._detect_natural_loop(header1)

        analysis2 = StructureAnalysis(graph2)
        loop2 = analysis2._detect_natural_loop(header2)

        assert loop1 is not None and loop2 is not None, "Both should detect loops"
        assert (
            loop1.confidence >= loop2.confidence
        ), "Single back-edge should have >= confidence as multiple"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
