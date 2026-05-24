#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


ENTRY_RE = re.compile(r"^\s*\*\*\*\s+[0-9A-Fa-f]+\s+(?:[0-9A-Fa-f]{2}\s+)+(.*)$")
MNEMONIC_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\b")


@dataclass(frozen=True)
class MnemonicRow:
    mnemonic: str
    aliases: tuple[str, ...]
    lifter: str
    simulator: str
    tests: str
    covered_forms: str = ""
    missing_forms: str = ""
    notes: str = ""


ALU_BIN = "reg/reg, reg/mem, mem/reg, reg/imm, mem/imm, accum/imm; 8+16-bit"
ALU_UNARY = "reg, mem; 8+16-bit"
JCC_SHORT = "short rel8"
SHIFT_ROT = "reg, mem; count=1/imm8/CL; 8+16-bit"


ROWS: tuple[MnemonicRow, ...] = (
    MnemonicRow("aaa", (), "yes", "yes", "compare", "implicit AL/AH/flags"),
    MnemonicRow("aad", (), "yes", "yes", "compare", "aad imm8 (tested with base 10)"),
    MnemonicRow("aam", (), "yes", "yes", "compare", "aam imm8 (tested with base 10)"),
    MnemonicRow("aas", (), "yes", "yes", "compare", "implicit AL/AH/flags"),
    MnemonicRow("adc", (), "yes", "yes", "compare", ALU_BIN),
    MnemonicRow("add", (), "yes", "yes", "corpus", ALU_BIN),
    MnemonicRow("and", (), "yes", "yes", "corpus", ALU_BIN),
    MnemonicRow("bound", (), "no", "no", "none", "", "reg16, mem16 bounds pair"),
    MnemonicRow("call", ("lcall",), "yes", "yes", "compare+smoke", "near imm16, near r/m16, far ptr16:16, far m16:16", "-"),
    MnemonicRow("cbw", (), "yes", "yes", "compare", "implicit AL->AX"),
    MnemonicRow("clc", (), "yes", "yes", "compare", "implicit"),
    MnemonicRow("cld", (), "yes", "yes", "none", "implicit"),
    MnemonicRow("cli", (), "yes", "yes", "none", "implicit"),
    MnemonicRow("cmc", (), "yes", "yes", "compare", "implicit"),
    MnemonicRow("cmp", (), "yes", "yes", "corpus", ALU_BIN),
    MnemonicRow("cmps", ("cmpsb", "cmpsw"), "yes", "yes", "compare+corpus", "cmpsb, cmpsw; repeat-aware"),
    MnemonicRow("cwd", (), "yes", "yes", "compare", "implicit AX->DX:AX"),
    MnemonicRow("daa", (), "yes", "yes", "compare", "implicit AL/flags"),
    MnemonicRow("das", (), "yes", "yes", "compare", "implicit AL/flags"),
    MnemonicRow("dec", (), "yes", "yes", "corpus", ALU_UNARY),
    MnemonicRow("div", (), "yes", "yes", "smoke", "reg, mem; 8+16-bit", "full quotient/remainder oracle matrix", "Divide-by-zero lift regression exists; quotient semantics are not broadly compare-tested."),
    MnemonicRow("enter", (), "yes", "yes", "smoke+runtime", "enter imm16, imm8", "-", "Runtime coverage now includes nested real-mode frame setup."),
    MnemonicRow("esc", (), "partial", "partial", "none", "narrow FPU escape subset", "general non-FPU modeling", "Only narrow FPU escape groups exist; integer-model coverage is intentionally deferred."),
    MnemonicRow("hlt", (), "yes", "yes", "none", "implicit"),
    MnemonicRow("idiv", (), "yes", "yes", "smoke", "reg, mem; 8+16-bit"),
    MnemonicRow("imul", (), "yes", "yes", "compare", "1-op reg/mem 8+16-bit; 2-op/3-op 16-bit immediate forms"),
    MnemonicRow("in", (), "yes", "yes", "none", "AL/AX <- imm8 or DX"),
    MnemonicRow("inc", (), "yes", "yes", "none", ALU_UNARY),
    MnemonicRow("ins", (), "yes", "yes", "runtime", "insb, insw; repeat-aware DI/ES semantics"),
    MnemonicRow("int", ("int3",), "yes", "yes", "compare+runtime", "int3, int imm8"),
    MnemonicRow("into", (), "yes", "yes", "smoke+runtime", "implicit OF-gated int 4"),
    MnemonicRow("iret", (), "yes", "yes", "compare+smoke", "implicit far return from interrupt frame"),
    MnemonicRow("ja", ("jnbe",), "yes", "yes", "none", JCC_SHORT),
    MnemonicRow("jae", ("jnb", "jnc"), "yes", "yes", "none", JCC_SHORT),
    MnemonicRow("jb", ("jc", "jnae"), "yes", "yes", "none", JCC_SHORT),
    MnemonicRow("jbe", ("jna",), "yes", "yes", "none", JCC_SHORT),
    MnemonicRow("jcxz", (), "yes", "yes", "none", "short rel8"),
    MnemonicRow("je", ("jz",), "yes", "yes", "smoke", "short rel8, near rel16"),
    MnemonicRow("jg", ("jnle",), "yes", "yes", "none", JCC_SHORT),
    MnemonicRow("jge", ("jnl",), "yes", "yes", "none", JCC_SHORT),
    MnemonicRow("jl", ("jnge",), "yes", "yes", "none", JCC_SHORT),
    MnemonicRow("jle", ("jng",), "yes", "yes", "none", JCC_SHORT),
    MnemonicRow("jmp", ("ljmp",), "yes", "yes", "compare+smoke", "short rel8, near rel16, near r/m16, far ptr16:16, far m16:16"),
    MnemonicRow("jne", ("jnz",), "yes", "yes", "none", "short rel8, near rel16"),
    MnemonicRow("jno", (), "yes", "yes", "none", JCC_SHORT),
    MnemonicRow("jns", (), "yes", "yes", "none", JCC_SHORT),
    MnemonicRow("jnp", ("jpo",), "yes", "yes", "none", JCC_SHORT),
    MnemonicRow("jo", (), "yes", "yes", "none", JCC_SHORT),
    MnemonicRow("jp", ("jpe",), "yes", "yes", "none", JCC_SHORT),
    MnemonicRow("js", (), "yes", "yes", "none", JCC_SHORT),
    MnemonicRow("lahf", (), "yes", "yes", "compare", "implicit flags->AH"),
    MnemonicRow("lds", (), "yes", "yes", "compare", "reg16, mem32"),
    MnemonicRow("lea", (), "yes", "yes", "corpus", "reg16, mem16"),
    MnemonicRow("leave", (), "yes", "yes", "runtime", "implicit"),
    MnemonicRow("les", (), "yes", "yes", "compare", "reg16, mem32"),
    MnemonicRow("lock", (), "no", "no", "none", "", "prefix 0xF0 parsing + legality checks", "Prefix parsing does not currently recognize 0xF0."),
    MnemonicRow("lods", ("lodsb", "lodsw"), "yes", "yes", "compare", "lodsb, lodsw; repeat-aware"),
    MnemonicRow("loop", (), "yes", "yes", "compare", "short rel8"),
    MnemonicRow("loope", ("loopz",), "yes", "yes", "none", "short rel8"),
    MnemonicRow("loopne", ("loopnz",), "yes", "yes", "none", "short rel8"),
    MnemonicRow("mov", (), "yes", "yes", "corpus", "reg/reg, reg/mem, mem/reg, reg/imm, mem/imm, moffs, seg-reg moves; 8+16-bit"),
    MnemonicRow("movs", ("movsb", "movsw"), "yes", "yes", "compare+corpus", "movsb, movsw; repeat-aware"),
    MnemonicRow("mul", (), "yes", "yes", "none", "reg, mem; 8+16-bit"),
    MnemonicRow("neg", (), "yes", "yes", "compare", ALU_UNARY),
    MnemonicRow("nop", (), "yes", "yes", "none", "implicit"),
    MnemonicRow("not", (), "yes", "yes", "compare", ALU_UNARY),
    MnemonicRow("or", (), "yes", "yes", "corpus", ALU_BIN),
    MnemonicRow("out", (), "yes", "yes", "none", "imm8 or DX <- AL/AX"),
    MnemonicRow("outs", (), "yes", "yes", "runtime", "outsb, outsw; repeat-aware SI/DS semantics"),
    MnemonicRow("pop", (), "yes", "yes", "compare", "reg16, seg-reg, r/m16"),
    MnemonicRow("popa", (), "yes", "yes", "runtime", "implicit"),
    MnemonicRow("popf", (), "yes", "yes", "runtime", "implicit"),
    MnemonicRow("push", (), "yes", "yes", "none", "reg16, seg-reg, r/m16, imm8, imm16"),
    MnemonicRow("pusha", (), "yes", "yes", "runtime", "implicit"),
    MnemonicRow("pushf", (), "yes", "yes", "runtime", "implicit"),
    MnemonicRow("rcl", (), "yes", "yes", "compare", SHIFT_ROT),
    MnemonicRow("rcr", (), "yes", "yes", "compare", SHIFT_ROT),
    MnemonicRow("rep", ("repe", "repz", "repne", "repnz"), "partial", "partial", "compare+corpus", "repeat on stos/lods/scas/cmps/movsb/movsw/ins/outs subset", "generic prefix coverage beyond the current string-op subset", "Repeat prefixes are implemented for the current string-op subset, not as a universal prefix surface."),
    MnemonicRow("ret", ("retn", "retf"), "yes", "yes", "compare+smoke", "ret, ret imm16, retf, retf imm16"),
    MnemonicRow("rol", (), "yes", "yes", "compare", SHIFT_ROT),
    MnemonicRow("ror", (), "yes", "yes", "compare", SHIFT_ROT),
    MnemonicRow("sahf", (), "yes", "yes", "compare", "implicit AH->flags"),
    MnemonicRow("sal", ("shl",), "yes", "yes", "compare", SHIFT_ROT, "-", "Alias of `shl`; byte/word CL and immediate forms are implemented."),
    MnemonicRow("sar", (), "yes", "yes", "compare", SHIFT_ROT),
    MnemonicRow("sbb", (), "yes", "yes", "compare", ALU_BIN),
    MnemonicRow("scas", ("scasb", "scasw"), "yes", "yes", "compare", "scasb, scasw; repeat-aware"),
    MnemonicRow("shr", (), "yes", "yes", "compare", SHIFT_ROT),
    MnemonicRow("stc", (), "yes", "yes", "compare", "implicit"),
    MnemonicRow("std", (), "yes", "yes", "none", "implicit"),
    MnemonicRow("sti", (), "yes", "yes", "none", "implicit"),
    MnemonicRow("stos", ("stosb", "stosw"), "yes", "yes", "compare", "stosb, stosw; repeat-aware"),
    MnemonicRow("sub", (), "yes", "yes", "corpus", ALU_BIN),
    MnemonicRow("test", (), "yes", "yes", "compare", "reg/reg, reg/mem, reg/imm, mem/imm, accum/imm; 8+16-bit"),
    MnemonicRow("wait", (), "yes", "yes", "smoke", "implicit"),
    MnemonicRow("xchg", (), "yes", "yes", "compare", "accum/reg, reg/reg, mem/reg; 8+16-bit"),
    MnemonicRow("xlat", (), "yes", "yes", "compare+smoke", "implicit AL <- [BX+AL] via DS"),
    MnemonicRow("xor", (), "yes", "yes", "corpus", ALU_BIN),
)


def collect_mnemonics(cod_dir: Path) -> Counter[str]:
    counts: Counter[str] = Counter()
    for cod_path in sorted(cod_dir.rglob("*.COD")):
        for line in cod_path.read_text(errors="ignore").splitlines():
            entry_match = ENTRY_RE.match(line)
            if not entry_match:
                continue
            asm = entry_match.group(1).split(";", 1)[0]
            mnemonic_match = MNEMONIC_RE.match(asm)
            if mnemonic_match is None:
                continue
            counts[mnemonic_match.group(1).lower()] += 1
    return counts


def corpus_count(row: MnemonicRow, counts: Counter[str]) -> int:
    return sum(counts.get(name, 0) for name in (row.mnemonic, *row.aliases))


def render_markdown(cod_dir: Path) -> str:
    counts = collect_mnemonics(cod_dir)
    total = len(ROWS)
    supported = sum(1 for row in ROWS if row.lifter == "yes")
    partial = sum(1 for row in ROWS if row.lifter == "partial")
    unsupported = sum(1 for row in ROWS if row.lifter == "no")

    lines = [
        "# x86-16 Mnemonic Coverage",
        "",
        "Generated by `scripts/build_x86_16_mnemonic_coverage.py`.",
        "",
        "This table tracks the non-FPU 80C186-style mnemonic surface we care about right now.",
        "It is intentionally practical rather than encyclopedic: aliases are grouped onto canonical rows, and FPU mnemonics are left out for now.",
        "",
        f"- Total canonical rows: `{total}`",
        f"- Lifter `yes`: `{supported}`",
        f"- Lifter `partial`: `{partial}`",
        f"- Lifter `no`: `{unsupported}`",
        "",
        "Status meanings:",
        "- `yes`: opcode/path exists in the shared instruction implementation used by both lifting and execution",
        "- `partial`: some forms or prefix behavior exist, but the full mnemonic surface is not complete",
        "- `no`: no current support",
        "",
        "| Mnemonic | Aliases | COD count | Lifter | Simulator | Focused tests | Covered forms | Missing forms | Notes |",
        "| --- | --- | ---: | --- | --- | --- | --- | --- | --- |",
    ]

    for row in sorted(ROWS, key=lambda item: (-corpus_count(item, counts), item.mnemonic)):
        aliases = ", ".join(row.aliases) if row.aliases else "-"
        covered = row.covered_forms or "-"
        missing = row.missing_forms or "-"
        notes = row.notes or "-"
        lines.append(
            f"| `{row.mnemonic}` | {aliases} | {corpus_count(row, counts)} | {row.lifter} | {row.simulator} | {row.tests} | {covered} | {missing} | {notes} |"
        )

    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- `COD count` comes from scanning `../cod/**/*.COD` textual disassembly listings.",
            "- `Simulator` tracks the shared execution path in `instr_base.py` / `instr16.py`; it does not imply the instruction already has a dedicated regression.",
            "- `Focused tests` is a human summary of explicit coverage in smoke/compare/runtime-style tests, not a full proof matrix.",
            "- `Covered forms` and `Missing forms` are intentionally human-maintained summaries so we can see operand-shape gaps such as reg/mem, 8/16-bit, near/far, or repeat behavior.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a markdown coverage table for x86-16 mnemonics.")
    parser.add_argument("cod_dir", type=Path, help="Directory containing .COD files")
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output markdown path. If omitted, print to stdout.",
    )
    args = parser.parse_args()

    markdown = render_markdown(args.cod_dir)
    if args.output is None:
        print(markdown, end="")
    else:
        args.output.write_text(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
