from __future__ import annotations

from dataclasses import dataclass

from .core import IRAtom, IRBlock, IRCondition, IRInstr, IRValue, MemSpace

__all__ = ["SSABinding", "SSABlock", "build_x86_16_block_local_ssa"]


@dataclass(frozen=True, slots=True)
class SSABinding:
    target: IRValue
    version: int
    instr_index: int

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target.to_dict(),
            "version": self.version,
            "instr_index": self.instr_index,
        }


@dataclass(frozen=True, slots=True)
class SSABlock:
    addr: int
    instrs: tuple[IRInstr, ...]
    bindings: tuple[SSABinding, ...]
    refusals: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "addr": self.addr,
            "instrs": [item.to_dict() for item in self.instrs],
            "bindings": [item.to_dict() for item in self.bindings],
            "refusals": list(self.refusals),
        }


def _version_key(value: IRValue) -> tuple[str, str | None, int]:
    return (value.space.value, value.name, value.offset)


def _versioned(value: IRValue, version: int) -> IRValue:
    return IRValue(
        space=value.space,
        name=value.name,
        offset=value.offset,
        const=value.const,
        size=value.size,
        version=version,
        expr=value.expr,
    )


def _rewrite_value(value: IRValue, versions: dict[tuple[str, str | None, int], int]) -> IRValue:
    if value.space in {MemSpace.CONST, MemSpace.UNKNOWN}:
        return value
    key = _version_key(value)
    version = versions.get(key, 0)
    return _versioned(value, version)


def _rewrite_atom(atom: IRAtom, versions: dict[tuple[str, str | None, int], int]) -> IRAtom:
    if isinstance(atom, IRCondition):
        return IRCondition(
            op=atom.op,
            args=tuple(_rewrite_atom(arg, versions) for arg in atom.args),
            expr=atom.expr,
        )
    if not isinstance(atom, IRValue):
        return atom
    return _rewrite_value(atom, versions)


def build_x86_16_block_local_ssa(block: IRBlock) -> SSABlock:
    versions: dict[tuple[str, str | None, int], int] = {}
    rewritten: list[IRInstr] = []
    bindings: list[SSABinding] = []
    for index, instr in enumerate(block.instrs):
        rewritten_args: list[IRAtom] = []
        for arg in instr.args:
            rewritten_args.append(_rewrite_atom(arg, versions))
        rewritten_dst = instr.dst
        if rewritten_dst is not None and rewritten_dst.space not in {MemSpace.CONST, MemSpace.UNKNOWN}:
            key = _version_key(rewritten_dst)
            version = versions.get(key, -1) + 1
            versions[key] = version
            rewritten_dst = _versioned(rewritten_dst, version)
            bindings.append(SSABinding(target=rewritten_dst, version=version, instr_index=index))
        rewritten.append(
            IRInstr(
                op=instr.op,
                dst=rewritten_dst,
                args=tuple(rewritten_args),
                size=instr.size,
                addr=instr.addr,
            )
        )
    return SSABlock(addr=block.addr, instrs=tuple(rewritten), bindings=tuple(bindings))
