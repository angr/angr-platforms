#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import angr


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import angr_platforms.X86_16  # noqa: F401

from angr_platforms.X86_16.arch_86_16 import Arch86_16


def _parse_int(value: str) -> int:
    return int(value, 0)


def _build_project(path: Path, *, force_blob: bool, base_addr: int, entry_point: int):
    suffix = path.suffix.lower()
    if force_blob or suffix in {".bin", ".raw", ".com"}:
        return angr.Project(
            path,
            auto_load_libs=False,
            main_opts={
                "backend": "blob",
                "arch": Arch86_16(),
                "base_addr": base_addr,
                "entry_point": entry_point,
            },
            simos="DOS" if suffix == ".com" else None,
        )
    return angr.Project(path, auto_load_libs=False)


def _next_repr(block) -> str:
    nxt = block.vex.next
    con = getattr(nxt, "con", None)
    if con is not None:
        return hex(con.value)
    return str(nxt)


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect x86-16 block-level control flow.")
    parser.add_argument("binary", type=Path, help="Binary to inspect.")
    parser.add_argument("--addr", type=_parse_int, default=None, help="Start address. Defaults to project entry.")
    parser.add_argument("--blob", action="store_true", help="Force blob loading.")
    parser.add_argument("--base-addr", type=_parse_int, default=0x1000, help="Blob/.COM base address.")
    parser.add_argument("--entry-point", type=_parse_int, default=0x1000, help="Blob/.COM entry point.")
    parser.add_argument("--blocks", type=int, default=4, help="Maximum number of recovered blocks to print.")
    parser.add_argument("--window", type=_parse_int, default=0x200, help="CFG recovery window from addr.")
    args = parser.parse_args()

    project = _build_project(
        args.binary,
        force_blob=args.blob,
        base_addr=args.base_addr,
        entry_point=args.entry_point,
    )
    start = project.entry if args.addr is None else args.addr
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[start],
        regions=[(start, start + args.window)],
        normalize=True,
        force_complete_scan=False,
    )
    if start not in cfg.functions:
        print(f"function {start:#x} was not recovered")
        return 1

    func = cfg.functions[start]
    print(f"binary: {args.binary}")
    print(f"arch: {project.arch.name}")
    print(f"entry: {project.entry:#x}")
    print(f"function: {func.addr:#x} {func.name}")
    print()

    for idx, block_addr in enumerate(sorted(func.block_addrs_set)):
        if idx >= args.blocks:
            break
        block = project.factory.block(block_addr, opt_level=0)
        print(f"== block {block_addr:#x} ==")
        print(f"jumpkind: {block.vex.jumpkind}")
        print(f"next: {_next_repr(block)}")
        print("-- asm --")
        for insn in block.capstone.insns:
            print(f"{insn.address:#06x}: {insn.mnemonic} {insn.op_str}".rstrip())
        print("-- vex --")
        print(block.vex._pp_str())
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
