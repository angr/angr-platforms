import networkx as nx

from angr_platforms.X86_16.structuring_cfg_grouping import build_cfg_grouping_artifact


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


def test_cfg_grouping_exports_entry_fragments_and_grouped_candidates():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, c)
    graph.add_edge(b, c)

    artifact = build_cfg_grouping_artifact(_Codegen(0x1000, _Clinic(graph)))

    assert artifact is not None
    assert artifact.grouped_entry_candidate_ids == (0x1002,)
    assert artifact.entry_fragment_ids == (0x1001,)
    by_id = {record.region_id: record for record in artifact.records}
    assert by_id[0x1000].grouping_kind == "primary_entry"
    assert by_id[0x1001].grouping_kind == "entry_fragment"
    assert by_id[0x1002].grouping_kind == "grouped_entry_candidate"


def test_cfg_grouping_returns_none_without_cfg():
    class _EmptyCodegen:
        def __init__(self):
            self.cfunc = _CFunc(0x1000)
            self._clinic = None
            self.project = None

    assert build_cfg_grouping_artifact(_EmptyCodegen()) is None
