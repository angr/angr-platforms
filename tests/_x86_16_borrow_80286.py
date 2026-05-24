from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import gzip
import json
import struct
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BORROW_80286_ROOT = REPO_ROOT / "borrow" / "80286" / "v1_real_mode"
BORROW_80286_METADATA = BORROW_80286_ROOT / "metadata.json"


@dataclass(frozen=True, slots=True)
class Borrow80286Case:
    opcode_key: str
    mnemonic_key: str
    name: str
    instruction_bytes: bytes
    source_path: Path


@dataclass(frozen=True, slots=True)
class Borrow80286Corpus:
    cases: tuple[Borrow80286Case, ...]
    total_cases: int
    filtered_cases: int
    deduped_cases: int
    skipped_bad_cases: int
    skipped_lock_cases: int


def _iter_test_names_and_bytes_from_moo(data: bytes):
    mv = memoryview(data)
    if data[:4] != b"MOO ":
        raise ValueError("Not a MOO file")

    offset = 4
    header_len = struct.unpack_from("<I", mv, offset)[0]
    offset += 4 + header_len

    while offset < len(data):
        tag = bytes(mv[offset : offset + 4]).decode("ascii")
        offset += 4
        length = struct.unpack_from("<I", mv, offset)[0]
        offset += 4
        if tag != "TEST":
            offset += length
            continue

        test_offset = offset + 4
        test_end = offset + length
        name = None
        instruction_bytes = None
        while test_offset < test_end:
            subt = bytes(mv[test_offset : test_offset + 4]).decode("ascii")
            test_offset += 4
            slen = struct.unpack_from("<I", mv, test_offset)[0]
            test_offset += 4
            if subt == "NAME":
                name_len = struct.unpack_from("<I", mv, test_offset)[0]
                name = bytes(mv[test_offset + 4 : test_offset + 4 + name_len]).decode()
            elif subt == "BYTS":
                byte_count = struct.unpack_from("<I", mv, test_offset)[0]
                instruction_bytes = bytes(mv[test_offset + 4 : test_offset + 4 + byte_count])
            test_offset += slen

        if isinstance(name, str) and instruction_bytes:
            yield name, instruction_bytes
        offset += length


_SEGMENT_OVERRIDES = frozenset({"cs", "ds", "es", "ss", "fs", "gs"})
_INSTR_PREFIXES = frozenset({"lock", "rep", "repe", "repne"})


def _mnemonic_key(name: str) -> str:
    tokens = name.lower().split()
    if not tokens:
        raise ValueError("Instruction name is empty")
    # Segment overrides (cs, ds, etc.) may precede instruction prefixes (lock, rep, etc.)
    # in cases like "cs lock movsb". Shift past segment overrides so the prefix rule
    # still applies.
    if tokens[0] in _SEGMENT_OVERRIDES and len(tokens) > 2 and tokens[1] in _INSTR_PREFIXES:
        return f"{tokens[1]}:{tokens[2]}"
    if tokens[0] in _INSTR_PREFIXES and len(tokens) > 1:
        return f"{tokens[0]}:{tokens[1]}"
    return tokens[0]


def _normalized_instruction_bytes(raw_instruction_bytes: bytes) -> bytes:
    if raw_instruction_bytes and raw_instruction_bytes[-1] == 0xF4:
        return raw_instruction_bytes[:-1]
    return raw_instruction_bytes


@lru_cache(maxsize=1)
def load_borrow_80286_lifter_corpus() -> Borrow80286Corpus:
    metadata = json.loads(BORROW_80286_METADATA.read_text())
    opcodes = metadata.get("opcodes", {})
    if not isinstance(opcodes, dict):
        raise ValueError("borrow/80286 metadata missing opcode map")

    cases: list[Borrow80286Case] = []
    seen_instruction_bytes: set[bytes] = set()
    total_cases = 0
    filtered_cases = 0
    skipped_bad_cases = 0
    skipped_lock_cases = 0

    for opcode_key in sorted(opcodes):
        details = opcodes.get(opcode_key)
        if not isinstance(details, dict):
            continue
        if details.get("status") != "normal":
            continue
        if details.get("arch") != "86":
            continue

        source_path = BORROW_80286_ROOT / f"{opcode_key}.MOO.gz"
        if not source_path.exists():
            continue

        for name, raw_instruction_bytes in _iter_test_names_and_bytes_from_moo(gzip.decompress(source_path.read_bytes())):
            total_cases += 1
            if name.startswith("(bad)"):
                skipped_bad_cases += 1
                continue
            mnemonic_key = _mnemonic_key(name)
            if mnemonic_key.startswith("lock:"):
                skipped_lock_cases += 1
                continue
            instruction_bytes = _normalized_instruction_bytes(raw_instruction_bytes)
            if not instruction_bytes:
                continue
            filtered_cases += 1
            if instruction_bytes in seen_instruction_bytes:
                continue
            seen_instruction_bytes.add(instruction_bytes)
            cases.append(
                Borrow80286Case(
                    opcode_key=opcode_key,
                    mnemonic_key=mnemonic_key,
                    name=name,
                    instruction_bytes=instruction_bytes,
                    source_path=source_path,
                )
            )

    return Borrow80286Corpus(
        cases=tuple(cases),
        total_cases=total_cases,
        filtered_cases=filtered_cases,
        deduped_cases=len(cases),
        skipped_bad_cases=skipped_bad_cases,
        skipped_lock_cases=skipped_lock_cases,
    )


def load_borrow_80286_lifter_cases(limit: int | None = None) -> tuple[Borrow80286Case, ...]:
    cases = load_borrow_80286_lifter_corpus().cases
    if limit is None:
        return cases
    if limit >= len(cases):
        return cases
    # Evenly sample across the full dedupped corpus so every opcode group is covered.
    step = len(cases) / limit
    return tuple(cases[int(i * step)] for i in range(limit))
