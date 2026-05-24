from angr_platforms.X86_16.structuring_loops import (
    compute_loop_body,
    compute_loop_confidence,
    detect_natural_loop,
)
from angr_platforms.X86_16.structuring_region import Region, RegionGraph, RegionType, compute_dominators


def _make_simple_loop():
    entry = Region(block_addr=0x1000, region_type=RegionType.Linear)
    header = Region(block_addr=0x1001, region_type=RegionType.Linear)
    body = Region(block_addr=0x1002, region_type=RegionType.Linear)
    exit_region = Region(block_addr=0x1003, region_type=RegionType.Linear)

    graph = RegionGraph()
    graph.entry = entry
    for region in (entry, header, body, exit_region):
        graph.add_node(region)

    graph.add_edge(entry, header)
    graph.add_edge(header, body)
    graph.add_edge(body, header)
    graph.add_edge(header, exit_region)
    return graph, header, body


def test_detect_natural_loop_returns_typed_summary():
    graph, header, body = _make_simple_loop()
    dominators = compute_dominators(graph)

    info = detect_natural_loop(graph, dominators, header)

    assert info is not None
    assert info.header == header
    assert info.back_edges == [body]
    assert info.has_single_exit is True
    assert info.is_reducible is True
    assert info.confidence > 0.6


def test_compute_loop_body_excludes_exit_regions():
    graph, header, body = _make_simple_loop()
    dominators = compute_dominators(graph)

    loop_body = compute_loop_body(graph, dominators, header, [body])

    assert header in loop_body
    assert body in loop_body
    assert len(loop_body) == 2


def test_compute_loop_confidence_penalizes_large_body():
    graph, header, body = _make_simple_loop()
    dominators = compute_dominators(graph)
    small_body = compute_loop_body(graph, dominators, header, [body])
    small_confidence = compute_loop_confidence(
        header,
        [body],
        small_body,
        [(header, next(iter(set(graph.successors(header)) - {body})))],
        True,
    )

    large_body = set(small_body)
    for index in range(60):
        large_body.add(Region(block_addr=0x2000 + index, region_type=RegionType.Linear))

    large_confidence = compute_loop_confidence(
        header,
        [body],
        large_body,
        [(header, Region(block_addr=0x3000, region_type=RegionType.Linear))],
        True,
    )

    assert large_confidence < small_confidence
