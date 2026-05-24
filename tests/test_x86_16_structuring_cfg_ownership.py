import networkx as nx

from angr_platforms.X86_16.structuring_cfg_ownership import build_cfg_ownership_artifact


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


def test_cfg_ownership_marks_shared_owner_and_entry():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, c)
    graph.add_edge(b, c)
    clinic = _Clinic(graph)

    artifact = build_cfg_ownership_artifact(_Codegen(0x1000, clinic))

    assert artifact is not None
    assert artifact.shared_region_ids == (0x1002,)
    assert artifact.entry_fragment_region_ids == (0x1001,)
    ownership = {record.region_id: record for record in artifact.records}
    assert ownership[0x1000].ownership_kind == "entry"
    assert ownership[0x1002].refusal_reason == "mixed_reachability_predecessors"
    assert ownership[0x1002].reachable_from_entry is True


def test_cfg_ownership_returns_none_without_snapshot():
    class _EmptyCodegen:
        def __init__(self):
            self.cfunc = _CFunc(0x1000)
            self._clinic = None
            self.project = None

    assert build_cfg_ownership_artifact(_EmptyCodegen()) is None


def test_cfg_ownership_marks_mixed_reachability_shared_owner():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    d = _Node(0x1003)
    graph.add_nodes_from([a, b, c, d])
    graph.add_edge(a, c)
    graph.add_edge(b, c)
    graph.add_edge(c, d)
    clinic = _Clinic(graph)

    artifact = build_cfg_ownership_artifact(_Codegen(0x1000, clinic))

    assert artifact is not None
    ownership = {record.region_id: record for record in artifact.records}
    assert ownership[0x1002].ownership_kind == "shared_owner"
    assert ownership[0x1002].refusal_reason == "mixed_reachability_predecessors"
