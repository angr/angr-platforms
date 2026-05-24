from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FastTraceResult:
    entries: tuple[int, ...]
    call_targets: tuple[int, ...]
    jump_targets: tuple[int, ...]
    returns: tuple[int, ...]
    scores: dict[int, int]


def _looks_like_16bit_function_prologue(code: bytes, offset: int) -> bool:
    window = code[offset : offset + 4]
    return window.startswith(b"\x55\x8B\xEC")


def _looks_like_16bit_entry_byte(code: bytes, offset: int) -> bool:
    if offset < 0 or offset >= len(code):
        return False
    byte = code[offset]
    return byte not in {0x00, 0x90, 0xCC}


def _resolve_16bit_function_start(code: bytes, offset: int, *, max_padding: int = 0x10) -> int | None:
    if offset < 0 or offset >= len(code):
        return None
    if _looks_like_16bit_function_prologue(code, offset):
        return offset
    padded = offset
    limit = min(len(code), offset + max_padding)
    while padded < limit and code[padded] in {0x00, 0x90, 0xCC}:
        padded += 1
    if padded < len(code) and _looks_like_16bit_function_prologue(code, padded):
        return padded
    return None


def _resolve_16bit_call_target(code: bytes, offset: int) -> int | None:
    canonical = _resolve_16bit_function_start(code, offset)
    if canonical is not None:
        return canonical
    if _looks_like_16bit_entry_byte(code, offset):
        return offset
    return None


def trace_16bit_seed_candidates(
    project,
    code: bytes,
    *,
    linked_base: int,
    windows: list[tuple[int, int]],
) -> FastTraceResult:
    image_end = linked_base + len(code)
    call_targets: set[int] = set()
    jump_targets: set[int] = set()
    returns: set[int] = set()
    scores: dict[int, int] = {}

    def _in_windows(addr: int) -> bool:
        return any(start <= addr < end for start, end in windows)

    def _add(addr: int, weight: int, bucket: set[int]) -> None:
        if not (linked_base <= addr < image_end):
            return
        if not _in_windows(addr):
            return
        bucket.add(addr)
        scores[addr] = scores.get(addr, 0) + weight

    try:
        disasm = getattr(getattr(project, "arch", None), "capstone", None)
    except Exception:
        disasm = None
    if disasm is None:
        return FastTraceResult(entries=tuple(), call_targets=tuple(), jump_targets=tuple(), returns=tuple(), scores={})

    align_bytes = {0x00, 0x90, 0xCC}
    for window_start, window_end in windows:
        if window_start >= window_end:
            continue
        offset = max(0, window_start - linked_base)
        stop = min(len(code), window_end - linked_base)
        while offset < stop:
            insn = next(disasm.disasm(code[offset : offset + 16], linked_base + offset, 1), None)
            if insn is None or insn.size <= 0:
                break
            opcode = code[offset]
            addr = insn.address
            if opcode == 0xE8 and offset + 2 < len(code):
                rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
                target = addr + 3 + rel
                canonical = _resolve_16bit_call_target(code, target - linked_base)
                _add(linked_base + canonical, 10, call_targets) if canonical is not None else None
            elif opcode == 0x9A and offset + 4 < len(code):
                off = int.from_bytes(code[offset + 1 : offset + 3], "little")
                seg = int.from_bytes(code[offset + 3 : offset + 5], "little")
                target = linked_base + (seg << 4) + off
                canonical = _resolve_16bit_call_target(code, target - linked_base)
                _add(linked_base + canonical, 12, call_targets) if canonical is not None else None
            elif opcode == 0xE9 and offset + 2 < len(code):
                rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
                target = addr + 3 + rel
                canonical = _resolve_16bit_function_start(code, target - linked_base)
                _add(linked_base + canonical, 2, jump_targets) if canonical is not None else None
            elif opcode == 0xEB and offset + 1 < len(code):
                rel = int.from_bytes(code[offset + 1 : offset + 2], "little", signed=True)
                target = addr + 2 + rel
                canonical = _resolve_16bit_function_start(code, target - linked_base)
                _add(linked_base + canonical, 2, jump_targets) if canonical is not None else None
            elif 0x70 <= opcode <= 0x7F and offset + 1 < len(code):
                rel = int.from_bytes(code[offset + 1 : offset + 2], "little", signed=True)
                target = addr + 2 + rel
                canonical = _resolve_16bit_function_start(code, target - linked_base)
                _add(linked_base + canonical, 2, jump_targets) if canonical is not None else None

            if code[offset : offset + 3] == b"\x55\x8b\xec":
                _add(addr, 3, jump_targets)

            offset += insn.size
            if insn.mnemonic.lower() in {"ret", "retf", "iret"}:
                returns.add(addr)
                next_offset = offset
                while next_offset < stop and code[next_offset] in align_bytes:
                    next_offset += 1
                if next_offset < stop and _looks_like_16bit_function_prologue(code, next_offset):
                    _add(linked_base + next_offset, 1, jump_targets)
                continue

    entries = tuple(sorted(scores, key=lambda seed: (-scores[seed], seed)))
    return FastTraceResult(
        entries=entries,
        call_targets=tuple(sorted(call_targets)),
        jump_targets=tuple(sorted(jump_targets)),
        returns=tuple(sorted(returns)),
        scores=scores,
    )
