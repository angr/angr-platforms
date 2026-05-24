from __future__ import annotations

from dataclasses import dataclass

from ..ir.core import IRAddress, IRValue, MemSpace

__all__ = ["MemRange", "Storage", "may_alias", "overlap", "storage_of"]


@dataclass(frozen=True, slots=True)
class Storage:
    space: MemSpace
    base: tuple[str, ...]
    offset: int
    size: int


@dataclass(frozen=True, slots=True)
class MemRange:
    space: MemSpace
    base: tuple[str, ...]
    offset: int
    size: int


def storage_of(value: IRValue | IRAddress) -> Storage | None:
    if isinstance(value, IRAddress):
        if value.space == MemSpace.UNKNOWN:
            return None
        return Storage(
            space=value.space,
            base=value.base,
            offset=value.offset,
            size=max(int(value.size or 0), 1),
        )
    if value.space in {MemSpace.CONST, MemSpace.TMP, MemSpace.UNKNOWN}:
        return None
    return Storage(
        space=value.space,
        base=() if value.name is None else (value.name,),
        offset=value.offset,
        size=max(int(value.size or 0), 1),
    )


def overlap(left: MemRange, right: MemRange) -> bool:
    if left.space != right.space or left.base != right.base:
        return False
    return not (left.offset + left.size <= right.offset or right.offset + right.size <= left.offset)


def may_alias(left: Storage, right: Storage) -> bool:
    return overlap(
        MemRange(left.space, left.base, left.offset, left.size),
        MemRange(right.space, right.base, right.offset, right.size),
    )
