#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path


ENTRY_RE = re.compile(r"^\s*\*\*\*\s+[0-9A-Fa-f]+\s+(?:[0-9A-Fa-f]{2}\s+)+(.*)$")
MNEMONIC_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\b")


def _extract_mnemonic(line: str) -> str | None:
    entry_match = ENTRY_RE.match(line)
    if not entry_match:
        return None
    asm = entry_match.group(1).split(";", 1)[0]
    mnemonic_match = MNEMONIC_RE.match(asm)
    if not mnemonic_match:
        return None
    return mnemonic_match.group(1).lower()


def collect_mnemonics(cod_dir: Path) -> Counter[str]:
    counts: Counter[str] = Counter()
    for cod_path in sorted(cod_dir.rglob("*.COD")):
        for line in cod_path.read_text(errors="ignore").splitlines():
            mnemonic = _extract_mnemonic(line)
            if mnemonic is not None:
                counts[mnemonic] += 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Count mnemonics present in .COD disassembly listings.")
    parser.add_argument("cod_dir", type=Path, help="Directory containing .COD files")
    parser.add_argument("--top", type=int, default=100, help="How many mnemonics to print")
    parser.add_argument("--json", action="store_true", help="Print full counts as JSON")
    args = parser.parse_args()

    counts = collect_mnemonics(args.cod_dir)

    if args.json:
        print(json.dumps(dict(counts.most_common()), indent=2, sort_keys=False))
        return 0

    for mnemonic, count in counts.most_common(args.top):
        print(f"{count:6d}  {mnemonic}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
