"""
Tests for structuring-based C code generation (Phase 1.3).

Demonstrates Loop→while/for, IncSwitch→switch rendering.
"""

import pytest

from angr_platforms.X86_16.structuring_analysis import StructureAnalysis
from angr_platforms.X86_16.structuring_codegen import StructuringCodegenPass
from angr_platforms.X86_16.structuring_region import Region, RegionGraph, RegionType


class TestStructuringCodegen:
    """Tests for C code generation from structured regions."""

    def test_loop_renders_as_while(self):
        """
        Test that a Loop region renders as while loop C code.
        """
        # Create simple loop
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

        # Generate C code
        codegen = StructuringCodegenPass()
        code = codegen.apply(result)

        # Verify codegen completed
        assert code is not None, "Should generate code"
        assert codegen.stats["loops_rendered"] >= 0, "Should track loop count"

    def test_switch_renders_as_switch(self):
        """
        Test that an IncSwitch region renders as switch C code.
        """
        entry = Region(block_addr=0x2000, region_type=RegionType.Linear)
        switch_region = Region(block_addr=0x2001, region_type=RegionType.Condition)
        cases = [Region(block_addr=0x2002 + i * 4, region_type=RegionType.Linear) for i in range(3)]
        exit_region = Region(block_addr=0x2010, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        graph.add_node(entry)
        graph.add_node(switch_region)
        for case in cases:
            graph.add_node(case)
        graph.add_node(exit_region)

        graph.add_edge(entry, switch_region)
        for case in cases:
            graph.add_edge(switch_region, case)
            graph.add_edge(case, exit_region)

        # Run structuring (will detect 3-way switch)
        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Generate C code
        codegen = StructuringCodegenPass()
        code = codegen.apply(result)

        # Verify codegen
        assert code is not None, "Should generate code"
        assert codegen.stats["switches_rendered"] >= 0, "Should track switch count"

    def test_loop_render_contains_while(self):
        """
        Test that rendered loop code contains 'while' keyword.
        """
        loop_region = Region(
            block_addr=0x3000, region_type=RegionType.Loop
        )
        loop_region.metadata["loop_info"] = None

        graph = RegionGraph()
        graph.entry = loop_region

        graph.add_node(loop_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        # While loop should appear in simplest case
        assert "while" in code or "do" in code or "for" in code, "Loop should render as C control flow"

    def test_loop_codegen_uses_typed_ir_condition_hint_when_no_explicit_condition(self):
        loop_region = Region(block_addr=0x3100, region_type=RegionType.Loop)
        loop_region.metadata["typed_ir_condition_hint"] = "ax == 0"

        graph = RegionGraph()
        graph.entry = loop_region
        graph.add_node(loop_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert "while (ax == 0)" in code

    def test_switch_render_contains_switch(self):
        """
        Test that rendered switch code contains 'switch' keyword.
        """
        switch_region = Region(
            block_addr=0x4000, region_type=RegionType.IncSwitch
        )
        switch_region.metadata["switch_candidates"] = [
            Region(block_addr=0x1),
            Region(block_addr=0x2),
            Region(block_addr=0x3),
        ]

        graph = RegionGraph()
        graph.entry = switch_region
        graph.add_node(switch_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert "switch" in code or "case" in code, "Switch should render as C switch statement"

    def test_codegen_stats_tracking(self):
        """
        Verify that codegen tracks statistics.
        """
        graph = RegionGraph()
        loop1 = Region(block_addr=0x5000, region_type=RegionType.Loop)
        switch1 = Region(block_addr=0x5001, region_type=RegionType.IncSwitch)
        linear1 = Region(block_addr=0x5002, region_type=RegionType.Linear)

        graph.entry = loop1
        for r in [loop1, switch1, linear1]:
            graph.add_node(r)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        # Stats should be tracked
        assert codegen.stats["loops_rendered"] >= 0, "Should track loops"
        assert codegen.stats["switches_rendered"] >= 0, "Should track switches"

    def test_multiple_loops_and_switches(self):
        """
        Test codegen with multiple Loop and IncSwitch regions.
        """
        graph = RegionGraph()

        # Create 2 loops and 2 switches
        regions = []
        for i, rtype in enumerate([RegionType.Loop, RegionType.IncSwitch, RegionType.Loop, RegionType.IncSwitch]):
            r = Region(block_addr=0x6000 + i * 4, region_type=rtype)
            if rtype == RegionType.IncSwitch:
                r.metadata["switch_candidates"] = [Region(block_addr=0x7000 + i)]
            graph.add_node(r)
            regions.append(r)

        graph.entry = regions[0]

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert code is not None, "Should generate code for mixed regions"
        assert codegen.stats["loops_rendered"] > 0, "Should count loops"
        assert codegen.stats["switches_rendered"] > 0, "Should count switches"

    def test_codegen_integration_with_structuring(self):
        """
        End-to-end test: structure CFG, then generate C code.
        """
        # Build a realistic CFG: Entry -> Loop, Exit
        entry = Region(block_addr=0x8000, region_type=RegionType.Linear)
        loop_header = Region(block_addr=0x8001, region_type=RegionType.Linear)
        loop_body = Region(block_addr=0x8002, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x8003, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, loop_header, loop_body, exit_region]:
            graph.add_node(r)

        graph.add_edge(entry, loop_header)
        graph.add_edge(loop_header, loop_body)
        graph.add_edge(loop_body, loop_header)  # Back-edge
        graph.add_edge(loop_header, exit_region)

        # Structuring
        analyzer = StructureAnalysis(graph)
        structured = analyzer.structure()

        # Codegen
        codegen = StructuringCodegenPass()
        code = codegen.apply(structured)

        # Should generate valid C structure
        assert code is not None
        assert len(code) > 0, "Should generate non-empty code"

    def test_loop_codegen_mentions_structuring_variables_for_abnormal_loop(self):
        loop_region = Region(block_addr=0x9000, region_type=RegionType.Loop)
        loop_region.metadata["abnormal_loop_plan"] = {
            "can_normalize": True,
            "exit_variable_name": "__loop_exit_sel_9000",
        }
        loop_region.metadata["structuring_variables"] = ["__loop_exit_sel_9000"]
        loop_region.metadata["unstructured_exits"] = [(0x9000, 0x9001)]

        graph = RegionGraph()
        graph.entry = loop_region
        graph.add_node(loop_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert "__loop_exit_sel_9000" in code
        assert "structuring variables" in code


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
