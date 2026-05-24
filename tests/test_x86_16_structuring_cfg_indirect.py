import networkx as nx

from angr_platforms.X86_16.structuring_cfg_indirect import build_cfg_indirect_site_artifact


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


def test_cfg_indirect_marks_fanout_dispatch_candidate():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    d = _Node(0x1003)
    graph.add_nodes_from([a, b, c, d])
    graph.add_edge(a, b)
    graph.add_edge(a, c)
    graph.add_edge(a, d)

    artifact = build_cfg_indirect_site_artifact(_Codegen(0x1000, _Clinic(graph)))

    assert artifact is not None
    assert artifact.candidate_region_ids == (0x1000,)
    by_id = {record.region_id: record for record in artifact.records}
    assert by_id[0x1000].classification == "fanout_dispatch_candidate"
    assert by_id[0x1000].refusal_reason is None


def test_cfg_indirect_rejects_low_fanout_nodes():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    graph.add_nodes_from([a, b])
    graph.add_edge(a, b)

    artifact = build_cfg_indirect_site_artifact(_Codegen(0x1000, _Clinic(graph)))

    assert artifact is not None
    assert artifact.candidate_region_ids == ()
    assert all(record.refusal_reason == "insufficient_fanout" for record in artifact.records)
