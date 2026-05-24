import networkx as nx

from angr_platforms.X86_16.structuring_grouped_refusal_report import (
    build_x86_16_structuring_grouped_refusal_report,
    describe_x86_16_structuring_grouped_refusal_report_surface,
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


def test_structuring_grouped_refusal_report_counts_refusal_reasons():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    d = _Node(0x1003)
    graph.add_nodes_from([a, b, c, d])
    graph.add_edge(a, b)
    graph.add_edge(b, c)
    graph.add_edge(c, d)
    graph.add_edge(d, c)

    report = build_x86_16_structuring_grouped_refusal_report(_Codegen(0x1000, _Clinic(graph)))

    assert report is not None
    assert report.to_dict() == {
        "rows": [
            {
                "refusal_reason": "no_external_entry_context",
                "count": 1,
                "likely_layer": "cross_entry_grouping",
                "next_root_cause_file": "angr_platforms/angr_platforms/X86_16/structuring_grouped_units.py",
            }
        ]
    }


def test_structuring_grouped_refusal_report_surface_is_stable():
    assert describe_x86_16_structuring_grouped_refusal_report_surface() == {
        "consumer": "structuring_grouped_refusal_report",
        "producer": "build_x86_16_cross_entry_grouped_units",
        "surface": "cross_entry_grouped_unit_refusals",
        "typed_rows": (
            "refusal_reason",
            "count",
            "likely_layer",
            "next_root_cause_file",
        ),
        "purpose": "Expose explicit multi-entry grouping refusal reasons to validation/reporting consumers.",
    }
