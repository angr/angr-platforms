import networkx as nx

from angr_platforms.X86_16.structuring_graph_builder import (
    build_region_graph,
    resolve_clinic_from_codegen,
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


class _Functions:
    def __init__(self, func):
        self._func = func

    def function(self, addr, create=False):
        del create
        if addr == self._func.addr:
            return self._func
        return None


class _Project:
    def __init__(self, func):
        self.kb = type("_KB", (), {"functions": _Functions(func)})()


class _Func:
    def __init__(self, addr, clinic):
        self.addr = addr
        self._clinic = clinic


class _Codegen:
    def __init__(self, addr, clinic=None, project=None):
        self.cfunc = _CFunc(addr)
        self._clinic = clinic
        self.project = project


def _make_graph():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, b)
    graph.add_edge(b, c)
    return graph


def test_build_region_graph_uses_direct_clinic():
    clinic = _Clinic(_make_graph())
    codegen = _Codegen(0x1000, clinic=clinic)

    result = build_region_graph(codegen)

    assert result.graph is not None
    assert result.entry is not None
    assert result.entry.region_id == 0x1000
    assert len(result.graph.nodes) == 3


def test_resolve_clinic_from_project_fallback():
    clinic = _Clinic(_make_graph())
    func = _Func(0x1000, clinic)
    project = _Project(func)
    codegen = _Codegen(0x1000, clinic=None, project=project)

    resolved = resolve_clinic_from_codegen(codegen)
    result = build_region_graph(codegen)

    assert resolved is clinic
    assert result.graph is not None
    assert result.entry is not None
    assert result.entry.region_id == 0x1000


def test_build_region_graph_returns_empty_when_no_clinic():
    codegen = _Codegen(0x1000, clinic=None, project=None)

    result = build_region_graph(codegen)

    assert result.graph is None
    assert result.entry is None
