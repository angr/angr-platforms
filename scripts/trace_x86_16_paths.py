#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import angr
import claripy
from angr import options as o


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import angr_platforms.X86_16  # noqa: F401

from angr_platforms.X86_16.analysis_helpers import (
    collect_dos_int21_calls,
    DOSInt21Call,
    decode_com_dollar_string,
    extend_cfg_for_far_calls,
    infer_com_region,
    render_dos_int21_call,
)
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


def _insn_bytes(project, addr: int) -> bytes | None:
    try:
        block = project.factory.block(addr, num_inst=1, opt_level=0)
    except Exception:
        return None
    size = block.size
    if size <= 0:
        return None
    try:
        return bytes(project.loader.memory.load(addr, size))
    except Exception:
        return None


def _has_binary_bytes(project, addr: int) -> bool:
    try:
        project.loader.memory.load(addr, 1)
    except Exception:
        return False
    return True


def _format_block(project, addr: int) -> tuple[str, str]:
    block = project.factory.block(addr, num_inst=1, opt_level=0)
    asm_lines = [f"{ins.address:#06x}: {ins.mnemonic} {ins.op_str}".rstrip() for ins in block.capstone.insns]
    next_expr = block.vex.next
    next_con = getattr(next_expr, "con", None)
    next_text = hex(next_con.value) if next_con is not None else str(next_expr)
    header = f"jumpkind={block.vex.jumpkind} next={next_text}"
    return header, "\n".join(asm_lines) if asm_lines else "<no instructions>"


def _dos_int21_annotations(function, binary: Path, api_style: str) -> dict[int, str]:
    return {
        call.insn_addr: render_dos_int21_call(call, api_style)
        for call in collect_dos_int21_calls(function, binary)
    }


def _trace_exec(project, *, start: int, max_steps: int) -> str:
    state = project.factory.blank_state(
        addr=start,
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
    )
    simgr = project.factory.simgr(state)
    seen: dict[int, int] = {}
    lines = []
    pending_fallthrough: int | None = None
    pending_helper_annotation: str | None = None
    ah: int | None = None
    ax: int | None = None
    dx: int | None = None

    for step_idx in range(max_steps):
        if not simgr.active:
            lines.append(f"stopped: no active states after {step_idx} steps")
            break
        if len(simgr.active) > 1:
            lines.append(f"stopped: branched into {len(simgr.active)} active states at step {step_idx}")
            break

        active = simgr.active[0]
        addr = active.solver.eval(active.regs.ip) if hasattr(active.regs, "ip") else active.addr
        addr = active.addr if active.addr is not None else addr
        seen[addr] = seen.get(addr, 0) + 1
        lines.append(f"== step {step_idx} @ {addr:#x} ==")

        if _has_binary_bytes(project, addr):
            header, asm = _format_block(project, addr)
            lines.append(header)
            lines.append(asm)
            pending_fallthrough = addr + project.factory.block(addr, num_inst=1, opt_level=0).size

            insn = next(project.arch.capstone.disasm(_insn_bytes(project, addr) or b"", addr, 1), None)
            if insn is not None:
                operands = getattr(insn, "operands", ())
                if insn.mnemonic == "mov" and len(operands) == 2:
                    dst, src = operands
                    if dst.type == 1 and src.type == 2:
                        reg_name = insn.reg_name(dst.reg).lower()
                        imm = src.imm & 0xFFFF
                        if reg_name == "ah":
                            ah = imm & 0xFF
                            ax = None if ax is None else ((ah << 8) | (ax & 0x00FF))
                        elif reg_name == "ax":
                            ax = imm
                            ah = (ax >> 8) & 0xFF
                        elif reg_name == "dx":
                            dx = imm
                    elif dst.type == 1:
                        reg_name = insn.reg_name(dst.reg).lower()
                        if reg_name == "ah":
                            ah = None
                            ax = None
                        elif reg_name == "ax":
                            ax = None
                            ah = None
                        elif reg_name == "dx":
                            dx = None
                elif (
                    insn.mnemonic == "xor"
                    and len(operands) == 2
                    and operands[0].type == 1
                    and operands[1].type == 1
                ):
                    dst_name = insn.reg_name(operands[0].reg).lower()
                    src_name = insn.reg_name(operands[1].reg).lower()
                    if dst_name == src_name:
                        if dst_name == "ax":
                            ax = 0
                            ah = 0
                        elif dst_name == "dx":
                            dx = 0
                        elif dst_name == "ah":
                            ah = 0
                            ax = None if ax is None else (ax & 0x00FF)
                elif insn.mnemonic == "int" and insn.op_str.lower() == "0x21":
                    binary_path = Path(project.filename) if project.filename is not None else None
                    pending_helper_annotation = render_dos_int21_call(
                        DOSInt21Call(
                            insn_addr=insn.address,
                            ah=ah,
                            ax=ax,
                            dx=dx,
                            string_literal=decode_com_dollar_string(binary_path, dx),
                        ),
                        "modern",
                    )
                    dx = None
        else:
            simproc = project.hooked_by(addr)
            proc_name = simproc.__class__.__name__ if simproc is not None else "external"
            helper_line = f"helper={proc_name}"
            if pending_helper_annotation is not None:
                helper_line = f"{helper_line} ; {pending_helper_annotation}"
            lines.append(helper_line)
            lines.append("<no binary bytes at this address>")
            pending_helper_annotation = None

        if seen[addr] > 2:
            lines.append(f"stopped: loop detected at {addr:#x}")
            break

        if _has_binary_bytes(project, addr):
            insn_bytes = _insn_bytes(project, addr)
            if insn_bytes is None:
                lines.append("stopped: could not recover instruction bytes")
                break
            simgr.step(num_inst=1, insn_bytes=insn_bytes)
        else:
            no_ret = bool(getattr(project.hooked_by(addr), "NO_RET", False))
            if no_ret:
                lines.append("stopped: helper is no-return")
                break
            if pending_fallthrough is None:
                lines.append("stopped: helper fallthrough is unknown")
                break
            active.regs.ip = claripy.BVV(pending_fallthrough, 16)
            simgr.stashes["active"] = [active]
    else:
        lines.append(f"stopped: reached max steps ({max_steps})")

    return "\n".join(lines) + "\n"


def _trace_cfg(project, binary: Path, *, start: int, window: int, max_blocks: int, api_style: str) -> str:
    if binary.suffix.lower() == ".com":
        regions = [infer_com_region(binary, base_addr=start, window=window, arch=project.arch)]
    else:
        regions = [(start, start + window)]

    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[start],
        regions=regions,
        normalize=True,
        force_complete_scan=False,
    )
    if start not in cfg.functions:
        return f"function {start:#x} was not recovered\n"

    function = cfg.functions[start]
    if project.arch.name == "86_16":
        ext = extend_cfg_for_far_calls(project, function, entry_window=window)
        if ext is not None and start in ext.functions:
            cfg = ext
            function = cfg.functions[start]

    helper_annotations = _dos_int21_annotations(function, binary, api_style)

    lines = [f"function: {function.addr:#x} {function.name}"]
    for idx, block_addr in enumerate(sorted(function.block_addrs_set)):
        if idx >= max_blocks:
            lines.append(f"... truncated after {max_blocks} blocks")
            break
        block = project.factory.block(block_addr, opt_level=0)
        succs = sorted(
            {
                edge_dst.addr
                for edge_src, edge_dst in function.graph.edges()
                if edge_src.addr == block_addr
            }
        )
        succ_text = ", ".join(hex(s) for s in succs) if succs else "-"
        lines.append(f"== block {block_addr:#x} ==")
        lines.append(f"jumpkind={block.vex.jumpkind} succs={succ_text}")
        for ins in block.capstone.insns:
            line = f"{ins.address:#06x}: {ins.mnemonic} {ins.op_str}".rstrip()
            annotation = helper_annotations.get(ins.address)
            if annotation is not None:
                line = f"{line} ; {annotation}"
            lines.append(line)
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Trace bounded x86-16 code paths with angr.")
    parser.add_argument("binary", type=Path, help="Binary to inspect.")
    parser.add_argument("--addr", type=_parse_int, default=None, help="Start address. Defaults to entry.")
    parser.add_argument("--blob", action="store_true", help="Force blob loading.")
    parser.add_argument("--base-addr", type=_parse_int, default=0x1000, help="Blob/.COM base address.")
    parser.add_argument("--entry-point", type=_parse_int, default=0x1000, help="Blob/.COM entry point.")
    parser.add_argument("--mode", choices=("exec", "cfg"), default="exec", help="Trace concrete execution or CFG flow.")
    parser.add_argument("--max-steps", type=int, default=16, help="Maximum concrete execution steps.")
    parser.add_argument("--max-blocks", type=int, default=16, help="Maximum CFG blocks to print.")
    parser.add_argument("--window", type=_parse_int, default=0x200, help="Recovery window from start address.")
    parser.add_argument(
        "--api-style",
        choices=("modern", "dos", "raw", "pseudo", "service", "msc", "compiler"),
        default="modern",
        help="Render recovered DOS helpers in modern, DOS/compiler, pseudo-callee, or raw style.",
    )
    args = parser.parse_args()

    project = _build_project(
        args.binary,
        force_blob=args.blob,
        base_addr=args.base_addr,
        entry_point=args.entry_point,
    )
    start = project.entry if args.addr is None else args.addr

    if args.mode == "exec":
        output = _trace_exec(project, start=start, max_steps=args.max_steps)
    else:
        output = _trace_cfg(project, args.binary, start=start, window=args.window, max_blocks=args.max_blocks, api_style=args.api_style)

    print(f"binary: {args.binary}")
    print(f"arch: {project.arch.name}")
    print(f"entry: {project.entry:#x}")
    print(f"mode: {args.mode}")
    print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
