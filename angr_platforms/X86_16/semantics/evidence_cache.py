from __future__ import annotations

"""Layer: Semantics

Responsibility: canonical evidence cache for raw semantic accesses.

The cache is populated during VEX lifting (via access.py's
_record_semantic_memory_access) and consumed by the normalized
collector (collect_normalized_semantic_alias_facts_from_project_8616).

Keys are function addresses (int).  Values are lists of
AccessRecord8616 (function_addr, insn_addr, mode, IRAddress).

This replaces the old sys.modules hack for module-level cache access.
"""

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

__all__ = [
    "AccessRecord8616",
    "record_access",
    "get_accesses_for_function",
    "set_current_function_addr",
    "get_current_function_addr",
    "clear_accesses_for_function",
]


@dataclass(frozen=True)
class AccessRecord8616:
    function_addr: int
    insn_addr: int | None
    mode: int
    addr: object


# Module-level cache: {func_addr: [AccessRecord8616]}
_accesses_by_function: dict[int, list[AccessRecord8616]] = defaultdict(list)

# Module-level block-keyed cache: {block_addr: [AccessRecord8616]}
# Used during initial CFG construction when function context is unknown.
# Migrated to function-keyed via migrate_block_accesses_to_function().
_accesses_by_block: dict[int, list[AccessRecord8616]] = defaultdict(list)

# Module-level function context: set before block lifting, read during access recording.
# This bridges the gap between the CLI layer (which knows the function address)
# and the lifter (which only knows the instruction address).
_current_function_addr: int | None = None
_current_instruction_addr: int | None = None


def set_current_function_addr(function_addr: int | None, insn_addr: int | None = None) -> None:
    """Set the current function and instruction addresses before block lifting."""
    global _current_function_addr, _current_instruction_addr
    _current_function_addr = function_addr
    _current_instruction_addr = insn_addr


def get_current_function_addr() -> int | None:
    """Get the current function address (set before block lifting)."""
    return _current_function_addr


def record_access(
    function_addr: int,
    mode: int,
    addr: object,
    *,
    insn_addr: int | None = None,
) -> None:
    """Record a raw semantic access for a function."""
    if not isinstance(function_addr, int):
        return
    _accesses_by_function[function_addr].append(
        AccessRecord8616(
            function_addr=function_addr,
            insn_addr=insn_addr,
            mode=mode,
            addr=addr,
        )
    )


def get_accesses_for_function(function_addr: int) -> list[AccessRecord8616]:
    """Get all raw semantic accesses for a function."""
    return list(_accesses_by_function.get(function_addr, ()))


def record_access_by_block(
    block_addr: int,
    mode: int,
    addr: object,
    *,
    insn_addr: int | None = None,
) -> None:
    """Record a raw semantic access keyed by block address.

    Used during initial CFG construction when the function address is
    not yet known.  Migrated to function-keyed later via
    migrate_block_accesses_to_function().
    """
    if not isinstance(block_addr, int):
        return
    _accesses_by_block[block_addr].append(
        AccessRecord8616(
            function_addr=block_addr,  # temporary; migrated later
            insn_addr=insn_addr,
            mode=mode,
            addr=addr,
        )
    )


def get_accesses_for_block(block_addr: int) -> list[AccessRecord8616]:
    """Get raw semantic accesses recorded for a block."""
    return list(_accesses_by_block.get(block_addr, ()))


def migrate_block_accesses_to_function(
    block_addr: int,
    function_addr: int,
) -> int:
    """Migrate block-keyed accesses to function-keyed and clear block entry.

    Returns the number of accesses migrated.
    """
    records = _accesses_by_block.pop(block_addr, None)
    if not records:
        return 0
    migrated = [
        AccessRecord8616(
            function_addr=function_addr,
            insn_addr=r.insn_addr,
            mode=r.mode,
            addr=r.addr,
        )
        for r in records
    ]
    _accesses_by_function[function_addr].extend(migrated)
    return len(migrated)


def clear_accesses_for_function(function_addr: int) -> None:
    """Clear accesses for a function (used between test runs)."""
    _accesses_by_function.pop(function_addr, None)


def clear_accesses_for_block(block_addr: int) -> None:
    """Clear block-keyed access cache (used between test runs)."""
    _accesses_by_block.pop(block_addr, None)
