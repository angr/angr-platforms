import networkx as nx

from angr_platforms.X86_16.structuring_cfg_snapshot import build_cfg_snapshot


class _Node:
    def __init__(self, addr):
        self.addr = addr


class _Clinic:
    def __init__(self, graph):
        self.graph = graph


class _CFunc:
    def __init__(self, addr, name="func"):
        self.addr = addr
        self.name = name


class _Codegen:
    def __init__(self, addr, clinic=None):
        self.cfunc = _CFunc(addr)
        self._clinic = clinic
        self.project = None


def _make_graph():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, b)
    graph.add_edge(a, c)
    graph.add_edge(b, c)
    return graph


def test_build_cfg_snapshot_is_deterministic_and_marks_shared_nodes():
    clinic = _Clinic(_make_graph())
    codegen = _Codegen(0x1000, clinic=clinic)

    snapshot = build_cfg_snapshot(codegen)

    assert snapshot is not None
    assert snapshot.entry_region_id == 0x1000
    assert snapshot.node_count == 3
    assert snapshot.edge_count == 3
    assert tuple(node.region_id for node in snapshot.nodes) == (0x1000, 0x1001, 0x1002)
    assert snapshot.shared_region_ids == (0x1002,)
    assert snapshot.nodes[-1].ownership == "shared"
    assert all(node.reachable_from_entry for node in snapshot.nodes)


def test_build_cfg_snapshot_returns_none_without_graph():
    codegen = _Codegen(0x1000, clinic=None)

    snapshot = build_cfg_snapshot(codegen)

    assert snapshot is None


def test_build_cfg_snapshot_marks_unreachable_nodes():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, b)
    clinic = _Clinic(graph)
    codegen = _Codegen(0x1000, clinic=clinic)

    snapshot = build_cfg_snapshot(codegen)

    assert snapshot is not None
    by_id = {node.region_id: node for node in snapshot.nodes}
    assert by_id[0x1000].reachable_from_entry is True
    assert by_id[0x1001].reachable_from_entry is True
    assert by_id[0x1002].reachable_from_entry is False
