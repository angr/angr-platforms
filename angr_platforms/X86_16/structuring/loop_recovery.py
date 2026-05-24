from __future__ import annotations

"""Layer: Structuring (control-flow recovery).

Loop detection: find back-edges from raw CFG, build natural loops,
detect induction variables and loop guards from structured IR evidence.

Output: metadata-only dataclasses (RecoveredLoop, etc.).
Do NOT emit C `for` loops here — lowering belongs in a later pass.

Forbidden: text matching, asm/C regex, sample-specific address hacks."""

from dataclasses import dataclass
from typing import Iterable, Protocol

__all__ = [
    "LoopBackEdge",
    "NaturalLoop",
    "InductionUpdate",
    "LoopGuard",
    "RecoveredLoop",
    "CFGView",
    "BlockSemantics",
    "compute_dominators",
    "find_back_edges",
    "build_natural_loop",
    "recover_natural_loops",
    "match_induction_update",
    "find_loop_induction",
    "match_loop_guard",
    "find_loop_guard",
    "recover_loops",
]


@dataclass(frozen=True, slots=True)
class LoopBackEdge:
    header: int
    latch: int


@dataclass(frozen=True, slots=True)
class NaturalLoop:
    header: int
    latch: int
    blocks: frozenset[int]


@dataclass(frozen=True, slots=True)
class InductionUpdate:
    variable: object
    initial: object | None
    step: int
    update_block: int
    confidence: float


@dataclass(frozen=True, slots=True)
class LoopGuard:
    variable: object
    bound: object
    op: str
    signed: bool
    guard_block: int
    confidence: float


@dataclass(frozen=True, slots=True)
class RecoveredLoop:
    loop: NaturalLoop
    induction: InductionUpdate | None
    guard: LoopGuard | None
    confidence: float


class CFGView(Protocol):
    def successors(self, block: int) -> Iterable[int]: ...
    def predecessors(self, block: int) -> Iterable[int]: ...


class BlockSemantics(Protocol):
    def statements(self, block: int) -> Iterable[object]: ...
    def terminator_condition(self, block: int) -> object | None: ...


def compute_dominators(cfg: CFGView, entry: int, blocks: Iterable[int]) -> dict[int, set[int]]:
    block_set = set(blocks)
    dom = {b: set(block_set) for b in block_set}
    dom[entry] = {entry}

    changed = True
    while changed:
        changed = False
        for b in sorted(block_set):
            if b == entry:
                continue
            preds = [p for p in cfg.predecessors(b) if p in block_set]
            if not preds:
                new_dom = {b}
            else:
                new_dom = set.intersection(*(dom[p] for p in preds)) | {b}
            if new_dom != dom[b]:
                dom[b] = new_dom
                changed = True

    return dom


def find_back_edges(cfg: CFGView, entry: int, blocks: Iterable[int]) -> list[LoopBackEdge]:
    block_list = list(blocks)
    dom = compute_dominators(cfg, entry, block_list)
    edges: list[LoopBackEdge] = []

    for src in block_list:
        for dst in cfg.successors(src):
            if dst in dom.get(src, set()):
                edges.append(LoopBackEdge(header=dst, latch=src))

    return sorted(edges, key=lambda e: (e.header, e.latch))


def build_natural_loop(cfg: CFGView, edge: LoopBackEdge) -> NaturalLoop:
    members = {edge.header, edge.latch}
    worklist = [edge.latch]

    while worklist:
        b = worklist.pop()
        for pred in cfg.predecessors(b):
            if pred not in members:
                members.add(pred)
                worklist.append(pred)

    return NaturalLoop(
        header=edge.header,
        latch=edge.latch,
        blocks=frozenset(members),
    )


def recover_natural_loops(cfg: CFGView, entry: int, blocks: Iterable[int]) -> list[NaturalLoop]:
    return [build_natural_loop(cfg, edge) for edge in find_back_edges(cfg, entry, blocks)]


# ── Induction variable detection ──

def _is_const(expr: object) -> bool:
    return hasattr(expr, "value") and isinstance(getattr(expr, "value"), int)


def _same_var(a: object, b: object) -> bool:
    return repr(a) == repr(b)


def match_induction_update(stmt: object) -> InductionUpdate | None:
    """Match:  i = i + c  or  i = i - c

    Operates on structured IR node objects, not rendered text.
    """
    target = getattr(stmt, "target", None) or getattr(stmt, "lhs", None)
    value = getattr(stmt, "value", None) or getattr(stmt, "rhs", None)
    if target is None or value is None:
        return None

    op = getattr(value, "op", None)
    left = getattr(value, "left", None) or getattr(value, "lhs", None)
    right = getattr(value, "right", None) or getattr(value, "rhs", None)

    if op not in ("Add", "Sub"):
        return None
    if not _same_var(target, left):
        return None
    if not _is_const(right):
        return None

    c = int(getattr(right, "value"))
    step = c if op == "Add" else -c

    return InductionUpdate(variable=target, initial=None, step=step, update_block=-1, confidence=0.75)


def find_loop_induction(loop: NaturalLoop, semantics: BlockSemantics) -> InductionUpdate | None:
    candidates: list[InductionUpdate] = []

    for block in sorted(loop.blocks):
        for stmt in semantics.statements(block):
            match = match_induction_update(stmt)
            if match is not None:
                candidates.append(
                    InductionUpdate(
                        variable=match.variable,
                        initial=match.initial,
                        step=match.step,
                        update_block=block,
                        confidence=match.confidence,
                    )
                )

    return candidates[0] if len(candidates) == 1 else None


# ── Loop guard detection ──

def match_loop_guard(cond: object, induction: InductionUpdate | None, guard_block: int) -> LoopGuard | None:
    """Match:  i < N, i <= N, i != N, i > N, i >= N

    Operates on typed condition objects, not text.
    """
    if cond is None or induction is None:
        return None

    op = getattr(cond, "op", None)
    left = getattr(cond, "left", None) or getattr(cond, "lhs", None)
    right = getattr(cond, "right", None) or getattr(cond, "rhs", None)

    if op is None or left is None or right is None:
        return None

    op_str = str(op)
    known = {"LT", "LE", "GT", "GE", "NE", "EQ"}
    if op_str not in known and op_str.lstrip("SU") not in known:
        return None

    if not _same_var(left, induction.variable):
        return None

    signed = op_str.startswith("S")
    normalized_op = op_str
    if normalized_op.startswith(("S", "U")):
        normalized_op = normalized_op[1:]

    return LoopGuard(
        variable=left,
        bound=right,
        op=normalized_op,
        signed=signed,
        guard_block=guard_block,
        confidence=0.75,
    )


def find_loop_guard(
    loop: NaturalLoop,
    semantics: BlockSemantics,
    induction: InductionUpdate | None,
) -> LoopGuard | None:
    for block in (loop.header, loop.latch):
        cond = semantics.terminator_condition(block)
        guard = match_loop_guard(cond, induction, block)
        if guard is not None:
            return guard
    return None


# ── Final recovery API ──

def recover_loops(
    cfg: CFGView,
    semantics: BlockSemantics,
    *,
    entry: int,
    blocks: Iterable[int],
) -> list[RecoveredLoop]:
    recovered: list[RecoveredLoop] = []

    for loop in recover_natural_loops(cfg, entry, blocks):
        induction = find_loop_induction(loop, semantics)
        guard = find_loop_guard(loop, semantics, induction)

        confidence = 0.4
        if induction is not None:
            confidence += 0.25
        if guard is not None:
            confidence += 0.25

        recovered.append(
            RecoveredLoop(
                loop=loop,
                induction=induction,
                guard=guard,
                confidence=min(confidence, 0.95),
            )
        )

    return sorted(recovered, key=lambda x: (x.loop.header, x.loop.latch))