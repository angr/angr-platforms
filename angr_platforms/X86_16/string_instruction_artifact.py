from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = [
    "StringInstructionArtifact",
    "StringInstructionRecord",
    "StringInstructionRefusal",
    "apply_x86_16_string_instruction_artifact",
    "build_x86_16_string_instruction_artifact",
    "build_x86_16_string_instruction_artifact_from_linear_range",
]


@dataclass(frozen=True, slots=True)
class StringInstructionRecord:
    index: int
    family: str
    mnemonic: str
    repeat_kind: str
    width: int
    source_segment: str | None
    destination_segment: str | None
    direction_mode: str
    zero_seeded_accumulator: bool | None
    zf_sensitive: bool


@dataclass(frozen=True, slots=True)
class StringInstructionRefusal:
    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class StringInstructionArtifact:
    records: tuple[StringInstructionRecord, ...] = ()
    refusals: tuple[StringInstructionRefusal, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "records": [
                {
                    "index": rec.index,
                    "family": rec.family,
                    "mnemonic": rec.mnemonic,
                    "repeat_kind": rec.repeat_kind,
                    "width": rec.width,
                    "source_segment": rec.source_segment,
                    "destination_segment": rec.destination_segment,
                    "direction_mode": rec.direction_mode,
                    "zero_seeded_accumulator": rec.zero_seeded_accumulator,
                    "zf_sensitive": rec.zf_sensitive,
                }
                for rec in self.records
            ],
            "refusals": [{"kind": item.kind, "detail": item.detail} for item in self.refusals],
        }


def _decode_linear_insns(project, start: int, end: int) -> tuple[Any, ...]:
    if end <= start:
        return ()
    code = bytes(project.loader.memory.load(start, end - start))
    capstone = project.arch.capstone
    previous_detail = getattr(capstone, "detail", False)
    try:
        capstone.detail = True
        return tuple(capstone.disasm(code, start))
    finally:
        capstone.detail = previous_detail


def _block_insns(project, function) -> tuple[Any, ...]:
    block_addrs = tuple(sorted(getattr(function, "block_addrs_set", ()) or ()))
    if not block_addrs:
        return ()
    insns: list[Any] = []
    for block_addr in block_addrs:
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        capstone_block = getattr(block, "capstone", None)
        block_insns = tuple(getattr(capstone_block, "insns", ()) or ())
        insns.extend(block_insns)
    return tuple(insns)


def _normalize_string_mnemonic(mnemonic: str) -> tuple[str, str]:
    parts = mnemonic.strip().lower().split()
    if not parts:
        return "none", ""
    if parts[0] in {"rep", "repe", "repz", "repne", "repnz"}:
        prefix = parts[0]
        base = parts[-1]
        if prefix in {"rep", "repe", "repz"}:
            repeat_kind = "repz" if prefix != "rep" else "rep"
        else:
            repeat_kind = "repnz"
        return repeat_kind, base
    return "none", parts[-1]


def _string_family(base: str) -> tuple[str, int, str | None, str | None, bool] | None:
    if base.startswith("movs"):
        return "movs", _width_for_base(base), "ds", "es", False
    if base.startswith("lods"):
        return "lods", _width_for_base(base), "ds", None, False
    if base.startswith("stos"):
        return "stos", _width_for_base(base), None, "es", False
    if base.startswith("scas"):
        return "scas", _width_for_base(base), None, "es", True
    if base.startswith("cmps"):
        return "cmps", _width_for_base(base), "ds", "es", True
    return None


def _width_for_base(base: str) -> int:
    if base.endswith("b"):
        return 1
    if base.endswith("w"):
        return 2
    if base.endswith("d"):
        return 4
    return 0


def _register_zero_seed(insn, al_zero: bool, ax_zero: bool) -> tuple[bool, bool]:
    mnemonic = str(getattr(insn, "mnemonic", "")).strip().lower()
    op_str = str(getattr(insn, "op_str", "")).strip().lower()
    text = f"{mnemonic} {op_str}".strip()
    if text in {"xor al, al", "mov al, 0", "mov al, 0x0"}:
        return True, ax_zero
    if text in {"xor ax, ax", "mov ax, 0", "mov ax, 0x0"}:
        return True, True
    if mnemonic in {"mov", "lea", "lodsb", "lodsw"} and op_str.startswith("al"):
        return False, ax_zero
    if mnemonic in {"mov", "lea"} and op_str.startswith("ax"):
        return False, False
    return al_zero, ax_zero


def _direction_state(insn, current: str) -> str:
    mnemonic = str(getattr(insn, "mnemonic", "")).strip().lower()
    if mnemonic == "cld":
        return "forward"
    if mnemonic == "std":
        return "backward"
    return current


def _records_from_insns(insns: tuple[Any, ...]) -> StringInstructionArtifact:
    if not insns:
        return StringInstructionArtifact(
            refusals=(StringInstructionRefusal("no_instruction_signal", "no instruction stream available"),)
        )

    records: list[StringInstructionRecord] = []
    direction_mode = "unknown"
    al_zero = False
    ax_zero = False
    for insn in insns:
        direction_mode = _direction_state(insn, direction_mode)
        al_zero, ax_zero = _register_zero_seed(insn, al_zero, ax_zero)
        repeat_kind, base = _normalize_string_mnemonic(str(getattr(insn, "mnemonic", "")))
        info = _string_family(base)
        if info is None:
            continue
        family, width, source_segment, destination_segment, zf_sensitive = info
        zero_seed = None
        if family == "scas":
            zero_seed = al_zero if width == 1 else ax_zero
        records.append(
            StringInstructionRecord(
                index=len(records),
                family=family,
                mnemonic=base,
                repeat_kind=repeat_kind,
                width=width,
                source_segment=source_segment,
                destination_segment=destination_segment,
                direction_mode=direction_mode,
                zero_seeded_accumulator=zero_seed,
                zf_sensitive=zf_sensitive,
            )
        )

    if not records:
        return StringInstructionArtifact(
            refusals=(StringInstructionRefusal("no_string_signal", "instruction stream contains no x86 string instructions"),)
        )
    refusals: list[StringInstructionRefusal] = []
    concrete_directions = {item.direction_mode for item in records if item.direction_mode in {"forward", "backward"}}
    if len(concrete_directions) > 1:
        refusals.append(
            StringInstructionRefusal(
                "mixed_direction_signal",
                "string instruction stream contains both forward and backward direction evidence",
            )
        )
    return StringInstructionArtifact(records=tuple(records), refusals=tuple(refusals))


def build_x86_16_string_instruction_artifact(project, function) -> StringInstructionArtifact:
    return _records_from_insns(_block_insns(project, function))


def build_x86_16_string_instruction_artifact_from_linear_range(
    project,
    *,
    start: int,
    end: int,
) -> StringInstructionArtifact:
    return _records_from_insns(_decode_linear_insns(project, start, end))


def apply_x86_16_string_instruction_artifact(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return False
    function = project.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        return False
    artifact = build_x86_16_string_instruction_artifact(project, function)
    setattr(codegen, "_inertia_string_instruction_artifact", artifact)
    info = getattr(function, "info", None)
    if isinstance(info, dict):
        info["x86_16_string_instruction_artifact"] = artifact.to_dict()
    return False
