from __future__ import annotations

from dataclasses import dataclass, field

from .core import IRFunctionArtifact, IRValue, MemSpace
from .ssa import SSABlock, build_x86_16_block_local_ssa

__all__ = [
    "SSAFunctionArtifact",
    "SSAIncomingValue",
    "SSAPhiNode",
    "build_x86_16_function_ssa",
]


@dataclass(frozen=True, slots=True)
class SSAIncomingValue:
    source_block_addr: int
    value: IRValue

    def to_dict(self) -> dict[str, object]:
        return {
            "source_block_addr": self.source_block_addr,
            "value": self.value.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class SSAPhiNode:
    block_addr: int
    key: tuple[str, str | None, int]
    target: IRValue
    incoming: tuple[SSAIncomingValue, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "block_addr": self.block_addr,
            "key": list(self.key),
            "target": self.target.to_dict(),
            "incoming": [item.to_dict() for item in self.incoming],
        }


@dataclass(frozen=True, slots=True)
class SSAFunctionArtifact:
    function_addr: int
    blocks: tuple[SSABlock, ...]
    phi_nodes: tuple[SSAPhiNode, ...] = ()
    predecessor_map: dict[int, tuple[int, ...]] = field(default_factory=dict)
    summary: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "function_addr": self.function_addr,
            "blocks": [block.to_dict() for block in self.blocks],
            "phi_nodes": [phi.to_dict() for phi in self.phi_nodes],
            "predecessor_map": {hex(addr): [hex(pred) for pred in preds] for addr, preds in sorted(self.predecessor_map.items())},
            "summary": dict(self.summary),
        }


def _value_key(value: IRValue) -> tuple[str, str | None, int] | None:
    if value.space in {MemSpace.CONST, MemSpace.UNKNOWN}:
        return None
    return (value.space.value, value.name, value.offset)


def _block_exit_versions(block: SSABlock) -> dict[tuple[str, str | None, int], IRValue]:
    exit_versions: dict[tuple[str, str | None, int], IRValue] = {}
    for binding in block.bindings:
        key = _value_key(binding.target)
        if key is None:
            continue
        exit_versions[key] = binding.target
    return exit_versions


def _predecessor_map(artifact: IRFunctionArtifact) -> dict[int, tuple[int, ...]]:
    block_addrs = {block.addr for block in artifact.blocks}
    pred_map: dict[int, set[int]] = {block.addr: set() for block in artifact.blocks}
    for block in artifact.blocks:
        for succ in block.successor_addrs:
            if succ in block_addrs:
                pred_map.setdefault(succ, set()).add(block.addr)
    return {addr: tuple(sorted(preds)) for addr, preds in sorted(pred_map.items())}


def _distinct_incoming_values(values: tuple[SSAIncomingValue, ...]) -> bool:
    seen = {
        (
            item.source_block_addr,
            item.value.space.value,
            item.value.name,
            item.value.offset,
            item.value.const,
            item.value.version,
        )
        for item in values
    }
    return len(seen) > 1


def _make_phi_target(block_addr: int, key: tuple[str, str | None, int], incoming: tuple[SSAIncomingValue, ...]) -> IRValue:
    max_version = max((item.value.version or 0) for item in incoming)
    return IRValue(
        space=MemSpace(key[0]),
        name=key[1],
        offset=key[2],
        size=max((item.value.size for item in incoming), default=0),
        version=max_version + 1,
        expr=("phi", hex(block_addr)),
    )


def build_x86_16_function_ssa(artifact: IRFunctionArtifact) -> SSAFunctionArtifact:
    local_blocks = tuple(build_x86_16_block_local_ssa(block) for block in artifact.blocks)
    local_by_addr = {block.addr: block for block in local_blocks}
    pred_map = _predecessor_map(artifact)
    exits_by_addr = {block.addr: _block_exit_versions(block) for block in local_blocks}
    phi_nodes: list[SSAPhiNode] = []

    for block_addr, preds in pred_map.items():
        if len(preds) < 2:
            continue
        candidate_keys = sorted({key for pred in preds for key in exits_by_addr.get(pred, {})})
        for key in candidate_keys:
            incoming = tuple(
                SSAIncomingValue(source_block_addr=pred, value=exits_by_addr[pred][key])
                for pred in preds
                if key in exits_by_addr.get(pred, {})
            )
            if len(incoming) < 2 or not _distinct_incoming_values(incoming):
                continue
            phi_nodes.append(
                SSAPhiNode(
                    block_addr=block_addr,
                    key=key,
                    target=_make_phi_target(block_addr, key, incoming),
                    incoming=tuple(sorted(incoming, key=lambda item: item.source_block_addr)),
                )
            )

    summary = {
        "block_count": len(local_blocks),
        "phi_node_count": len(phi_nodes),
        "join_block_count": sum(1 for preds in pred_map.values() if len(preds) > 1),
    }
    return SSAFunctionArtifact(
        function_addr=artifact.function_addr,
        blocks=tuple(sorted(local_by_addr.values(), key=lambda block: block.addr)),
        phi_nodes=tuple(sorted(phi_nodes, key=lambda node: (node.block_addr, node.key))),
        predecessor_map=pred_map,
        summary=summary,
    )
