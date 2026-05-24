import networkx as nx

from angr_platforms.X86_16.decompiler_structuring_stage import DECOMPILER_STRUCTURING_PASSES
from angr_platforms.X86_16.structuring_cross_entry import (
    apply_x86_16_cross_entry_grouping,
    describe_x86_16_cross_entry_grouping_surface,
)


class _Node:
    def __init__(self, addr):
        self.addr = addr


class _Clinic:
    def __init__(self, graph):
        self.graph = graph


class _CFunc:
    def __init__(self, addr):
        self.addr = addr
        self.name = "func"


class _Codegen:
    def __init__(self, addr, clinic):
        self.cfunc = _CFunc(addr)
        self._clinic = clinic
        self.project = None


def test_cross_entry_grouping_pass_runs_before_region_structuring():
    assert DECOMPILER_STRUCTURING_PASSES[0].name == "_cross_entry_cfg_grouping_8616"


def test_cross_entry_grouping_surface_and_attrs_are_stable():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, c)
    graph.add_edge(b, c)

    codegen = _Codegen(0x1000, _Clinic(graph))
    changed = apply_x86_16_cross_entry_grouping(codegen)

    assert changed is True
    assert codegen._inertia_grouped_entry_candidate_ids == (0x1002,)
    assert codegen._inertia_entry_fragment_ids == (0x1001,)
    assert codegen._inertia_cross_entry_unit_members == (0x1000, 0x1001, 0x1002)
    assert codegen._inertia_grouped_region_graph is not None
    assert describe_x86_16_cross_entry_grouping_surface() == {
        "producer": "build_cfg_grouping_artifact",
        "artifact_attr": "_inertia_cfg_grouping_artifact",
        "candidate_attr": "_inertia_grouped_entry_candidate_ids",
        "entry_fragment_attr": "_inertia_entry_fragment_ids",
        "grouped_unit_attr": "_inertia_cross_entry_grouped_units",
        "grouped_graph_attr": "_inertia_grouped_region_graph",
        "purpose": "Run CFG grouping export before region structuring/codegen.",
    }


def test_cross_entry_grouping_aggregates_members_across_multiple_units():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    d = _Node(0x1003)
    e = _Node(0x1004)
    graph.add_nodes_from([a, b, c, d, e])
    graph.add_edge(a, c)
    graph.add_edge(b, c)
    graph.add_edge(a, d)
    graph.add_edge(c, d)
    graph.add_edge(b, e)

    codegen = _Codegen(0x1000, _Clinic(graph))
    changed = apply_x86_16_cross_entry_grouping(codegen)

    assert changed is True
    assert codegen._inertia_cross_entry_unit_members == (0x1000, 0x1001, 0x1002, 0x1003, 0x1004)
