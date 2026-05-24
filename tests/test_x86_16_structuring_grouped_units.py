import networkx as nx
import pytest

from angr_platforms.X86_16.structuring_grouped_units import (
    apply_x86_16_cross_entry_grouped_units,
    build_x86_16_cross_entry_grouped_units,
    describe_x86_16_cross_entry_grouped_unit_surface,
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


def test_cross_entry_grouped_units_materialize_one_unit_from_grouping_artifact():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, c)
    graph.add_edge(b, c)

    artifact = build_x86_16_cross_entry_grouped_units(_Codegen(0x1000, _Clinic(graph)))

    assert artifact is not None
    assert artifact.to_dict() == {
        "grouping": artifact.grouping.to_dict(),
        "refused_anchor_region_ids": [],
        "refusals": [],
        "units": [
            {
                "anchor_shared_region_id": "0x1002",
                "primary_entry_region_ids": ["0x1000"],
                "entry_fragment_region_ids": ["0x1001"],
                "shared_region_ids": ["0x1002"],
                "member_region_ids": ["0x1000", "0x1001", "0x1002"],
                "refusal_reason": None,
            }
        ],
    }


def test_cross_entry_grouped_units_surface_and_attrs_are_stable():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, c)
    graph.add_edge(b, c)

    codegen = _Codegen(0x1000, _Clinic(graph))
    changed = apply_x86_16_cross_entry_grouped_units(codegen)

    assert changed is True
    assert codegen._inertia_cross_entry_unit_members == (0x1000, 0x1001, 0x1002)
    assert describe_x86_16_cross_entry_grouped_unit_surface() == {
        "producer": "build_x86_16_cross_entry_grouped_units",
        "artifact_attr": "_inertia_cross_entry_grouped_units",
        "member_attr": "_inertia_cross_entry_unit_members",
        "purpose": "Materialize grouped multi-entry CFG units before region structuring.",
    }


def test_cross_entry_grouped_units_split_multiple_shared_anchors_and_refuse_ambiguous_predecessor():
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

    artifact = build_x86_16_cross_entry_grouped_units(_Codegen(0x1000, _Clinic(graph)))

    assert artifact is not None
    assert artifact.refused_anchor_region_ids == ()
    assert artifact.refusals == ()
    assert artifact.to_dict()["units"] == [
        {
            "anchor_shared_region_id": "0x1002",
            "primary_entry_region_ids": ["0x1000"],
            "entry_fragment_region_ids": ["0x1001"],
            "shared_region_ids": ["0x1002", "0x1003"],
            "member_region_ids": ["0x1000", "0x1001", "0x1002", "0x1003"],
            "refusal_reason": None,
        },
        {
            "anchor_shared_region_id": "0x1004",
            "primary_entry_region_ids": [],
            "entry_fragment_region_ids": ["0x1001"],
            "shared_region_ids": ["0x1004"],
            "member_region_ids": ["0x1001", "0x1004"],
            "refusal_reason": None,
        },
    ]


def test_cross_entry_grouped_units_refuse_component_without_external_entry_context():
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

    artifact = build_x86_16_cross_entry_grouped_units(_Codegen(0x1000, _Clinic(graph)))

    assert artifact is not None
    assert artifact.units == ()
    assert artifact.refused_anchor_region_ids == (0x1002,)
    assert artifact.to_dict()["refusals"] == [
        {
            "anchor_shared_region_id": "0x1002",
            "shared_region_ids": ["0x1002"],
            "external_predecessor_region_ids": ["0x1001", "0x1003"],
            "ambiguous_predecessor_region_ids": [],
            "refusal_reason": "no_external_entry_context",
        }
    ]


def test_cross_entry_grouped_units_refuse_component_with_missing_snapshot_node(monkeypatch: pytest.MonkeyPatch):
    from angr_platforms.X86_16 import structuring_grouped_units as mod

    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, c)
    graph.add_edge(b, c)

    original_builder = mod.build_cfg_grouping_artifact

    def _build_without_shared_snapshot(codegen):
        artifact = original_builder(codegen)
        assert artifact is not None
        ownership = artifact.indirect.ownership
        snapshot = ownership.snapshot
        stripped_snapshot = snapshot.__class__(
            entry_region_id=snapshot.entry_region_id,
            node_count=snapshot.node_count - 1,
            edge_count=snapshot.edge_count,
            nodes=tuple(node for node in snapshot.nodes if node.region_id != 0x1002),
            shared_region_ids=(),
            external_entry_region_ids=snapshot.external_entry_region_ids,
            indirect_site_ids=snapshot.indirect_site_ids,
        )
        stripped_ownership = ownership.__class__(
            snapshot=stripped_snapshot,
            records=ownership.records,
            shared_region_ids=ownership.shared_region_ids,
            entry_fragment_region_ids=ownership.entry_fragment_region_ids,
        )
        stripped_indirect = artifact.indirect.__class__(
            ownership=stripped_ownership,
            records=artifact.indirect.records,
            candidate_region_ids=artifact.indirect.candidate_region_ids,
        )
        return artifact.__class__(
            indirect=stripped_indirect,
            records=artifact.records,
            grouped_entry_candidate_ids=artifact.grouped_entry_candidate_ids,
            entry_fragment_ids=artifact.entry_fragment_ids,
        )

    monkeypatch.setattr(mod, "build_cfg_grouping_artifact", _build_without_shared_snapshot)

    artifact = build_x86_16_cross_entry_grouped_units(_Codegen(0x1000, _Clinic(graph)))

    assert artifact is not None
    assert artifact.units == ()
    assert artifact.refused_anchor_region_ids == (0x1002,)
    assert artifact.to_dict()["refusals"] == [
        {
            "anchor_shared_region_id": "0x1002",
            "shared_region_ids": ["0x1002"],
            "external_predecessor_region_ids": [],
            "ambiguous_predecessor_region_ids": [],
            "refusal_reason": "missing_snapshot_node",
        }
    ]
