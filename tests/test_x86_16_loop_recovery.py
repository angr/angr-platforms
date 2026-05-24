"""Tests for loop recovery: back-edges, natural loops, induction, guards."""
from __future__ import annotations

import pytest
from angr_platforms.X86_16.structuring.loop_recovery import (
    CFGView,
    BlockSemantics,
    InductionUpdate,
    LoopBackEdge,
    LoopGuard,
    NaturalLoop,
    RecoveredLoop,
    compute_dominators,
    find_back_edges,
    build_natural_loop,
    recover_natural_loops,
    match_induction_update,
    find_loop_induction,
    match_loop_guard,
    find_loop_guard,
    recover_loops,
)


# ── Minimal CFG stub for testing ──

class SimpleCFG:
    """Simple directed graph as CFG."""

    def __init__(self, edges: list[tuple[int, int]]):
        self._succ: dict[int, list[int]] = {}
        self._pred: dict[int, list[int]] = {}
        for src, dst in edges:
            self._succ.setdefault(src, []).append(dst)
            self._pred.setdefault(dst, []).append(src)
        self._succ.setdefault(edges[0][0], [])
        self._pred.setdefault(edges[0][0], [])

    def successors(self, block: int):
        return self._succ.get(block, [])

    def predecessors(self, block: int):
        return self._pred.get(block, [])


# ── Test 1: simple back-edge ──

def test_simple_back_edge_forms_loop():
    """A single back-edge should create a NaturalLoop."""
    #  0 → 1 → 2 → 1  (back-edge 2 → 1)
    cfg = SimpleCFG([(0, 1), (1, 2), (2, 1)])
    blocks = [0, 1, 2]
    back_edges = find_back_edges(cfg, entry=0, blocks=blocks)
    assert len(back_edges) == 1
    assert back_edges[0] == LoopBackEdge(header=1, latch=2)

    loops = recover_natural_loops(cfg, entry=0, blocks=blocks)
    assert len(loops) == 1
    loop = loops[0]
    assert loop.header == 1
    assert loop.latch == 2
    assert 0 not in loop.blocks
    assert 1 in loop.blocks
    assert 2 in loop.blocks


# ── Test 2: no dominator → no loop ──

def test_no_dominator_no_loop():
    """A forward edge that is not a back-edge should not produce a loop."""
    #  0 → 1 → 2 → 3  (no back-edge)
    cfg = SimpleCFG([(0, 1), (1, 2), (2, 3)])
    blocks = [0, 1, 2, 3]
    back_edges = find_back_edges(cfg, entry=0, blocks=blocks)
    assert len(back_edges) == 0
    loops = recover_natural_loops(cfg, entry=0, blocks=blocks)
    assert len(loops) == 0


# ── Test 3: induction + guard → recovered loop ──

class FakeConst:
    def __init__(self, value: int):
        self.value = value


class FakeVar:
    def __init__(self, name: str):
        self._name = name

    def __repr__(self):
        return f"FakeVar({self._name!r})"


class FakeAssign:
    def __init__(self, target: object, value: object):
        self.lhs = target
        self.target = target
        self.rhs = value
        self.value = value


class FakeBinaryOp:
    def __init__(self, op: str, left: object, right: object):
        self.op = op
        self.lhs = left
        self.left = left
        self.rhs = right
        self.right = right


class FakeCondition:
    def __init__(self, op: str, left: object, right: object):
        self.op = op
        self.lhs = left
        self.left = left
        self.rhs = right
        self.right = right


def test_induction_and_guard_recovery():
    """Induction i=i+1 with guard i<N should be recovered."""
    i = FakeVar("i")
    N = FakeVar("N")

    class Semantics:
        def statements(self, block):
            if block == 2:  # latch
                inc = FakeBinaryOp("Add", i, FakeConst(1))
                return [FakeAssign(i, inc)]
            return []

        def terminator_condition(self, block):
            if block == 1:  # header
                return FakeCondition("LT", i, N)
            return None

    #  0 → 1 → 2 → 1  (loop header=1, latch=2)
    cfg = SimpleCFG([(0, 1), (1, 2), (2, 1)])
    blocks = [0, 1, 2]
    loops = recover_loops(cfg, Semantics(), entry=0, blocks=blocks)

    assert len(loops) == 1
    recovered = loops[0]
    assert recovered.loop.header == 1
    assert recovered.induction is not None
    assert recovered.induction.step == 1
    assert recovered.guard is not None
    assert recovered.guard.op == "LT"
    assert recovered.confidence == 0.9


# ── Test 4: two induction candidates → no confident induction ──

def test_two_induction_candidates_no_induction():
    """When two candidates exist, no single induction is returned."""
    i = FakeVar("i")
    j = FakeVar("j")

    class Semantics:
        def statements(self, block):
            if block == 2:
                inc_i = FakeBinaryOp("Add", i, FakeConst(1))
                inc_j = FakeBinaryOp("Add", j, FakeConst(1))
                return [FakeAssign(i, inc_i), FakeAssign(j, inc_j)]
            return []

        def terminator_condition(self, block):
            return None

    cfg = SimpleCFG([(0, 1), (1, 2), (2, 1)])
    loops = recover_loops(cfg, Semantics(), entry=0, blocks=[0, 1, 2])

    assert len(loops) == 1
    recovered = loops[0]
    assert recovered.induction is None


# ── Test 5: unknown condition → loop recovered, guard=None ──

def test_unknown_condition_guard_none():
    """When no recognizable guard exists, guard should be None."""
    i = FakeVar("i")

    class Semantics:
        def statements(self, block):
            if block == 2:
                return [FakeAssign(i, FakeBinaryOp("Add", i, FakeConst(1)))]
            return []

        def terminator_condition(self, block):
            # Return an unrecognizable condition
            return FakeCondition("UnknownOp", i, FakeConst(0))

    cfg = SimpleCFG([(0, 1), (1, 2), (2, 1)])
    loops = recover_loops(cfg, Semantics(), entry=0, blocks=[0, 1, 2])

    assert len(loops) == 1
    recovered = loops[0]
    assert recovered.induction is not None
    assert recovered.guard is None
    # confidence: 0.4 base + 0.25 induction = 0.65
    assert recovered.confidence == 0.65


# ── Test 6: dominators computed correctly ──

def test_dominators_diamond():
    """Dominators should be correct for a diamond CFG."""
    #  0 → 1, 0 → 2, 1 → 3, 2 → 3
    cfg = SimpleCFG([(0, 1), (0, 2), (1, 3), (2, 3)])
    blocks = [0, 1, 2, 3]
    dom = compute_dominators(cfg, entry=0, blocks=blocks)
    assert dom[0] == {0}
    assert 0 in dom[1]
    assert 0 in dom[2]
    assert dom[3] == {0, 3}


# ── Test 7: Sub step (negative step) ──

def test_negative_step_induction():
    """i = i - 1 should produce step=-1."""
    i = FakeVar("i")

    class Semantics:
        def statements(self, block):
            if block == 2:
                dec = FakeBinaryOp("Sub", i, FakeConst(1))
                return [FakeAssign(i, dec)]
            return []

        def terminator_condition(self, block):
            if block == 1:
                return FakeCondition("GT", i, FakeConst(0))
            return None

    cfg = SimpleCFG([(0, 1), (1, 2), (2, 1)])
    loops = recover_loops(cfg, Semantics(), entry=0, blocks=[0, 1, 2])

    assert len(loops) == 1
    recovered = loops[0]
    assert recovered.induction is not None
    assert recovered.induction.step == -1
    assert recovered.guard is not None
    assert recovered.guard.op == "GT"