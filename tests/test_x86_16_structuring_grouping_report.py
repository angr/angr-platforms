import networkx as nx

from angr_platforms.X86_16.structuring_grouping_report import (
    build_x86_16_structuring_grouping_report,
    describe_x86_16_structuring_grouping_report_surface,
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


def test_structuring_grouping_report_summarizes_cfg_grouping_rows():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, c)
    graph.add_edge(b, c)

    report = build_x86_16_structuring_grouping_report(_Codegen(0x1000, _Clinic(graph)))

    assert report is not None
    assert report.to_dict() == {
        "rows": [
            {
                "grouping_kind": "primary_entry",
                "count": 1,
                "likely_layer": "cfg_grouping",
                "next_root_cause_file": "angr_platforms/angr_platforms/X86_16/structuring_cfg_grouping.py",
            },
            {
                "grouping_kind": "entry_fragment",
                "count": 1,
                "likely_layer": "cfg_grouping",
                "next_root_cause_file": "angr_platforms/angr_platforms/X86_16/structuring_cfg_grouping.py",
            },
            {
                "grouping_kind": "grouped_entry_candidate",
                "count": 1,
                "likely_layer": "cfg_grouping",
                "next_root_cause_file": "angr_platforms/angr_platforms/X86_16/structuring_cfg_grouping.py",
            },
        ]
    }


def test_structuring_grouping_report_surface_is_deterministic():
    assert describe_x86_16_structuring_grouping_report_surface() == {
        "consumer": "structuring_grouping_report",
        "producer": "build_cfg_grouping_artifact",
        "surface": "cfg_grouping",
        "typed_rows": (
            "grouping_kind",
            "count",
            "likely_layer",
            "next_root_cause_file",
        ),
        "purpose": "Expose grouped-entry and entry-fragment CFG evidence to validation/reporting consumers.",
    }
