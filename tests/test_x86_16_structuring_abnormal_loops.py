from angr_platforms.X86_16.structuring_abnormal_loops import (
    AbnormalLoopStructureAnalysis,
    build_abnormal_loop_normalization_plan,
)
from angr_platforms.X86_16.structuring_loops import NaturalLoopInfo
from angr_platforms.X86_16.structuring_region import Region, RegionGraph, RegionType, compute_dominators


def test_build_abnormal_loop_plan_marks_multi_exit_loop():
    entry = Region(block_addr=0x1000, region_type=RegionType.Linear)
    header = Region(block_addr=0x1001, region_type=RegionType.Linear)
    body = Region(block_addr=0x1002, region_type=RegionType.Linear)
    exit_a = Region(block_addr=0x1003, region_type=RegionType.Linear)
    exit_b = Region(block_addr=0x1004, region_type=RegionType.Linear)

    graph = RegionGraph()
    graph.entry = entry
    for region in (entry, header, body, exit_a, exit_b):
        graph.add_node(region)

    graph.add_edge(entry, header)
    graph.add_edge(header, body)
    graph.add_edge(body, header)
    graph.add_edge(header, exit_a)
    graph.add_edge(body, exit_b)

    dominators = compute_dominators(graph)
    loop_info = NaturalLoopInfo(
        header=header,
        back_edges=[body],
        body_regions={header, body},
        exit_edges=[(header, exit_a), (body, exit_b)],
        is_reducible=False,
        confidence=0.4,
        has_single_exit=False,
    )
    plan = build_abnormal_loop_normalization_plan(graph, dominators, loop_info)

    assert plan.can_normalize is True
    assert plan.exit_variable_name == "__loop_exit_sel_1001"
    assert sorted(edge.target_region_id for edge in plan.abnormal_exits) == [0x1003, 0x1004]


def test_build_abnormal_loop_plan_marks_abnormal_entry():
    entry = Region(block_addr=0x2000, region_type=RegionType.Linear)
    header = Region(block_addr=0x2001, region_type=RegionType.Linear)
    body = Region(block_addr=0x2002, region_type=RegionType.Linear)
    fragment = Region(block_addr=0x2003, region_type=RegionType.Linear)
    exit_region = Region(block_addr=0x2004, region_type=RegionType.Linear)

    graph = RegionGraph()
    graph.entry = entry
    for region in (entry, header, body, fragment, exit_region):
        graph.add_node(region)

    graph.add_edge(entry, header)
    graph.add_edge(header, body)
    graph.add_edge(body, header)
    graph.add_edge(fragment, body)
    graph.add_edge(header, exit_region)

    dominators = compute_dominators(graph)
    loop_info = NaturalLoopInfo(
        header=header,
        back_edges=[body],
        body_regions={header, body},
        exit_edges=[(header, exit_region)],
        is_reducible=True,
        confidence=0.4,
        has_single_exit=True,
    )
    plan = build_abnormal_loop_normalization_plan(graph, dominators, loop_info)

    assert plan.can_normalize is True
    assert plan.entry_variable_name == "__loop_entry_sel_2001"
    assert [(edge.source_region_id, edge.target_region_id) for edge in plan.abnormal_entries] == [
        (0x2003, 0x2002)
    ]


def test_abnormal_loop_analysis_records_plan_on_loop_region():
    entry = Region(block_addr=0x3000, region_type=RegionType.Linear)
    header = Region(block_addr=0x3001, region_type=RegionType.Linear)
    body = Region(block_addr=0x3002, region_type=RegionType.Linear)
    exit_a = Region(block_addr=0x3003, region_type=RegionType.Linear)
    exit_b = Region(block_addr=0x3004, region_type=RegionType.Linear)

    graph = RegionGraph()
    graph.entry = entry
    for region in (entry, header, body, exit_a, exit_b):
        graph.add_node(region)

    graph.add_edge(entry, header)
    graph.add_edge(header, body)
    graph.add_edge(body, header)
    graph.add_edge(header, exit_a)
    graph.add_edge(body, exit_b)

    analysis = AbnormalLoopStructureAnalysis(graph)
    result = analysis.structure()

    loop_regions = [region for region in result.nodes if region.region_type == RegionType.Loop]
    assert loop_regions
    plan = loop_regions[0].metadata["abnormal_loop_plan"]
    assert plan["can_normalize"] is True
    assert plan["exit_variable_name"] == "__loop_exit_sel_3001"
    assert loop_regions[0].metadata["structuring_variables"] == ["__loop_exit_sel_3001"]


def test_build_abnormal_loop_plan_respects_typed_ir_normalization_gate():
    entry = Region(block_addr=0x4000, region_type=RegionType.Linear)
    header = Region(block_addr=0x4001, region_type=RegionType.Linear)
    body = Region(block_addr=0x4002, region_type=RegionType.Linear)
    exit_a = Region(block_addr=0x4003, region_type=RegionType.Linear)
    exit_b = Region(block_addr=0x4004, region_type=RegionType.Linear)
    header.metadata["typed_ir_allow_abnormal_loop_normalization"] = False

    graph = RegionGraph()
    graph.entry = entry
    for region in (entry, header, body, exit_a, exit_b):
        graph.add_node(region)

    graph.add_edge(entry, header)
    graph.add_edge(header, body)
    graph.add_edge(body, header)
    graph.add_edge(header, exit_a)
    graph.add_edge(body, exit_b)

    dominators = compute_dominators(graph)
    loop_info = NaturalLoopInfo(
        header=header,
        back_edges=[body],
        body_regions={header, body},
        exit_edges=[(header, exit_a), (body, exit_b)],
        is_reducible=False,
        confidence=0.4,
        has_single_exit=False,
    )
    plan = build_abnormal_loop_normalization_plan(graph, dominators, loop_info)

    assert plan.abnormal_exits
    assert plan.exit_variable_name is None
    assert plan.can_normalize is False
