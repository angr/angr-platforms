from __future__ import annotations

from dataclasses import asdict, dataclass
import logging
import os

from .analysis_helpers import collect_neighbor_call_targets
from .callee_name_normalization import normalize_callee_name_8616

__all__ = ["CallsiteSummary8616", "summarize_x86_16_callsite"]

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CallsiteSummary8616:
    callsite_addr: int
    target_addr: int | None
    return_addr: int | None
    kind: str | None
    arg_count: int | None
    arg_widths: tuple[int, ...]
    stack_cleanup: int | None
    return_register: str | None
    return_used: bool | None
    stack_probe_helper: bool = False
    helper_return_state: str = "none"
    helper_return_space: str | None = None
    helper_return_width: int | None = None
    helper_return_address_kind: str = "none"
    push_arg_sources: tuple[tuple | None, ...] = ()

    def brief(self) -> str:
        return (
            f"callsite={self.callsite_addr:#x} "
            f"target={None if self.target_addr is None else hex(self.target_addr)} "
            f"args={self.arg_count} "
            f"helper_return={self.helper_return_state} "
            f"helper_space={self.helper_return_space} "
            f"helper_width={self.helper_return_width} "
            f"helper_addr_kind={self.helper_return_address_kind}"
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _is_stack_probe_target_name_8616(name: str | None) -> bool:
    if not isinstance(name, str):
        return False
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return False
    return normalized.lower() in {
        "anchkstk",
        "chkstk",
        "_chkstk",
        "__chkstk",
        "__aNchkstk".lower(),
    }


def _lookup_target_name_8616(function, target_addr: int | None) -> str | None:
    if not isinstance(target_addr, int):
        return None
    project = getattr(function, "project", None)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    lookup_addrs = [target_addr]
    if isinstance(original_delta, int):
        lookup_addrs.append(target_addr + original_delta)
        rebased = target_addr - original_delta
        if rebased >= 0:
            lookup_addrs.append(rebased)
    deduped_addrs: list[int] = []
    for addr in lookup_addrs:
        if addr not in deduped_addrs:
            deduped_addrs.append(addr)

    for candidate_project in (project, getattr(project, "_inertia_original_project", None)):
        kb_functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
        lookup = getattr(kb_functions, "function", None)
        for candidate_addr in deduped_addrs:
            if callable(lookup):
                try:
                    callee = lookup(addr=candidate_addr, create=False)
                except Exception as ex:
                    log.debug(
                        "callsite target lookup failed project=%r addr=%#x: %s",
                        candidate_project,
                        candidate_addr,
                        ex,
                    )
                    callee = None
                name = getattr(callee, "name", None)
                if isinstance(name, str) and name:
                    return name
            for labels in (
                getattr(getattr(candidate_project, "kb", None), "labels", None),
                getattr(getattr(candidate_project, "_inertia_lst_metadata", None), "code_labels", None),
            ):
                if labels is None:
                    continue
                try:
                    label = labels.get(candidate_addr)
                except Exception as ex:
                    log.debug(
                        "callsite label lookup failed project=%r addr=%#x: %s",
                        candidate_project,
                        candidate_addr,
                        ex,
                    )
                    label = None
                if isinstance(label, str) and label:
                    return label
    return None


def _mnemonic(insn) -> str:
    return str(getattr(insn, "mnemonic", "") or "").strip().lower()


def _capstone_insn(insn):
    return getattr(insn, "insn", insn)


def _operand_reg_name(insn, operand) -> str | None:
    reg = getattr(operand, "reg", None)
    if not isinstance(reg, int):
        return None
    capstone_insn = _capstone_insn(insn)
    reg_name = getattr(capstone_insn, "reg_name", None)
    if callable(reg_name):
        try:
            value = reg_name(reg)
        except Exception as ex:
            log.debug("capstone reg_name lookup failed reg=%r: %s", reg, ex)
            value = None
        if isinstance(value, str) and value:
            return value.lower()
    return None


def _operand_imm_value(operand) -> int | None:
    operand_type = getattr(operand, "type", None)
    if isinstance(operand_type, int) and operand_type != 2:
        return None
    imm = getattr(operand, "imm", None)
    return imm if isinstance(imm, int) else None


def _operand_is_reg(insn, operand, names: set[str]) -> bool:
    reg_name = _operand_reg_name(insn, operand)
    return reg_name in names if reg_name is not None else False


def _instruction_operands(insn) -> tuple:
    return tuple(getattr(_capstone_insn(insn), "operands", ()) or ())


def _find_call_index(insns: tuple, callsite_addr: int) -> int | None:
    for idx, insn in enumerate(insns):
        insn_addr = getattr(insn, "address", None)
        if insn_addr == callsite_addr and _mnemonic(insn).startswith("call"):
            return idx
        insn_size = getattr(insn, "size", None)
        if (
            isinstance(insn_addr, int)
            and isinstance(insn_size, int)
            and insn_size > 0
            and insn_addr < callsite_addr < insn_addr + insn_size
            and _mnemonic(insn).startswith("call")
        ):
            return idx
    return None


def _block_insns_for_callsite(function, callsite_addr: int) -> tuple:
    project = getattr(function, "project", None)
    if project is None:
        return ()

    debug = bool(os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"))

    def _debug_insns(label: str, insns: tuple) -> None:
        if not debug:
            return
        rendered = ", ".join(
            f"{getattr(insn, 'address', None):#x}:{getattr(insn, 'mnemonic', '')} {getattr(insn, 'op_str', '')}"
            for insn in insns[:12]
        )
        log.warning("[callsite-window] callsite=%#x %s count=%d %s", callsite_addr, label, len(insns), rendered)

    def _decode_linear_window(start_addr: int) -> tuple:
        if not isinstance(start_addr, int) or start_addr > callsite_addr:
            return ()
        size = max(callsite_addr - start_addr + 16, 16)
        try:
            block = project.factory.block(
                start_addr,
                size=size,
                num_inst=max(callsite_addr - start_addr + 8, 8),
                strict_block_end=False,
                opt_level=0,
            )
        except Exception as ex:
            log.debug("callsite linear-window decode failed start=%#x callsite=%#x: %s", start_addr, callsite_addr, ex)
            block = None
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()) if block is not None else ()
        _debug_insns(f"factory-window start={start_addr:#x}", insns)
        if _find_call_index(insns, callsite_addr) is not None:
            return insns
        capstone_engine = getattr(getattr(project, "arch", None), "capstone", None)
        memory = getattr(getattr(project, "loader", None), "memory", None)
        if capstone_engine is None or memory is None:
            return insns
        try:
            data = bytes(memory.load(start_addr, size))
            capstone_insns = tuple(capstone_engine.disasm(data, start_addr))
            _debug_insns(f"capstone-window start={start_addr:#x}", capstone_insns)
            return capstone_insns
        except Exception as ex:
            log.debug("callsite capstone-window decode failed start=%#x callsite=%#x: %s", start_addr, callsite_addr, ex)
            return insns

    candidate_addrs = [callsite_addr]
    func_addr = getattr(function, "addr", None)
    if isinstance(func_addr, int) and func_addr <= callsite_addr:
        candidate_addrs.append(func_addr)
    for block_addr in tuple(sorted(getattr(function, "block_addrs_set", ()) or ())):
        if block_addr == callsite_addr:
            continue
        if block_addr > callsite_addr:
            break
        candidate_addrs.append(block_addr)

    for block_addr in reversed(candidate_addrs):
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception as ex:
            log.debug("callsite block decode failed block=%#x: %s", block_addr, ex)
            continue
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        _debug_insns(f"factory-block start={block_addr:#x}", insns)
        call_idx = _find_call_index(insns, callsite_addr)
        if call_idx is not None and call_idx > 0:
            return insns
        if call_idx is not None:
            for start_addr in reversed(candidate_addrs):
                window_insns = _decode_linear_window(start_addr)
                window_idx = _find_call_index(window_insns, callsite_addr)
                if window_idx is not None and window_idx > 0:
                    return window_insns
            return insns
    return ()


def _next_linear_block_insns(function, callsite_addr: int) -> tuple:
    project = getattr(function, "project", None)
    if project is None:
        return ()
    candidate_addrs = sorted(addr for addr in (getattr(function, "block_addrs_set", ()) or ()) if addr > callsite_addr)
    for block_addr in candidate_addrs:
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception as ex:
            log.debug("callsite next block decode failed block=%#x: %s", block_addr, ex)
            continue
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        if insns:
            return insns
    return ()


def _push_arg_width(insn) -> int:
    operands = _instruction_operands(insn)
    if operands:
        size = getattr(operands[0], "size", None)
        if isinstance(size, int) and size > 0:
            return size
    return 2


def _is_segment_register_push_8616(insn) -> bool:
    if not _mnemonic(insn).startswith("push"):
        return False
    operands = _instruction_operands(insn)
    return len(operands) == 1 and _operand_reg_name(insn, operands[0]) in {"cs", "ds", "es", "ss"}


def _transparent_between_push_args_8616(insn) -> bool:
    mnemonic = _mnemonic(insn)
    if mnemonic == "nop":
        return True
    if mnemonic in {"mov", "lea"}:
        operands = _instruction_operands(insn)
        if len(operands) != 2:
            return False
        return _operand_reg_name(insn, operands[0]) not in {"sp", "bp", "ss", "ds", "es", "cs"}

    if mnemonic not in {"add", "sub", "shl", "shr", "and", "or", "xor", "inc", "dec"}:
        return False
    operands = _instruction_operands(insn)
    if mnemonic in {"inc", "dec"}:
        if len(operands) != 1:
            return False
        dest_name = _operand_reg_name(insn, operands[0])
        return dest_name not in {"sp", "bp", "ss", "ds", "es", "cs"} if dest_name is not None else False

    if len(operands) != 2:
        return False
    dest_name = _operand_reg_name(insn, operands[0])
    if dest_name in {"sp", "bp", "ss", "ds", "es", "cs"}:
        return False
    return dest_name is not None


def _collect_push_args_before_call(insns: tuple, idx: int) -> tuple[int, ...]:
    widths: list[int] = []
    scan = idx - 1
    skipped_transparents = 0
    skipped_call_segment = False
    while scan >= 0:
        insn = insns[scan]
        if _mnemonic(insn).startswith("push"):
            if not widths and _is_segment_register_push_8616(insn):
                skipped_call_segment = True
                scan -= 1
                continue
            widths.append(_push_arg_width(insn))
            scan -= 1
            continue
        if not widths and skipped_call_segment and _transparent_between_push_args_8616(insn):
            scan -= 1
            continue
        if widths and skipped_transparents < 4 and _transparent_between_push_args_8616(insn):
            skipped_transparents += 1
            scan -= 1
            continue
        break
    widths.reverse()
    return tuple(widths)


def _push_arg_source(insn) -> tuple | None:
    operands = _instruction_operands(insn)
    if len(operands) != 1:
        return None
    operand = operands[0]
    mem = getattr(operand, "mem", None)
    if mem is not None:
        base = getattr(mem, "base", None)
        disp = getattr(mem, "disp", None)
        if isinstance(base, int) and isinstance(disp, int):
            base_name = _operand_reg_name(insn, type("_PushMemOperand", (), {"reg": base})())
            if base_name == "bp" and int(getattr(mem, "index", 0) or 0) == 0:
                return ("bp", int(disp))
    imm = _operand_imm_value(operand)
    if isinstance(imm, int):
        return ("imm", imm)
    return None


def _source_from_mov_operand(insn, operand) -> tuple | None:
    imm = _operand_imm_value(operand)
    if isinstance(imm, int):
        return ("imm", imm)
    mem = getattr(operand, "mem", None)
    if mem is not None:
        base = getattr(mem, "base", None)
        disp = getattr(mem, "disp", None)
        if isinstance(base, int) and isinstance(disp, int):
            base_name = _operand_reg_name(insn, type("_MovMemOperand", (), {"reg": base})())
            if base_name == "bp" and int(getattr(mem, "index", 0) or 0) == 0:
                return ("bp", int(disp))
    return None


def _push_arg_source_from_context(insns: tuple, idx: int) -> tuple | None:
    source = _push_arg_source(insns[idx])
    if source is not None:
        return source
    operands = _instruction_operands(insns[idx])
    if len(operands) != 1:
        return None
    pushed_reg = _operand_reg_name(insns[idx], operands[0])
    if pushed_reg is None or pushed_reg in {"sp", "bp", "ss", "ds", "es", "cs"}:
        return None
    scan = idx - 1
    skipped = 0
    ops: list[tuple[str, int]] = []
    while scan >= 0 and skipped < 6:
        insn = insns[scan]
        operands = _instruction_operands(insn)
        mnemonic = _mnemonic(insn)
        if mnemonic == "mov" and len(operands) == 2 and _operand_reg_name(insn, operands[0]) == pushed_reg:
            base_source = _source_from_mov_operand(insn, operands[1])
            if base_source is None:
                return None
            if not ops:
                return base_source
            return ("expr", base_source, tuple(reversed(ops)))
        if mnemonic in {"add", "sub", "shl", "shr"} and len(operands) == 2 and _operand_reg_name(insn, operands[0]) == pushed_reg:
            value = _operand_imm_value(operands[1])
            if not isinstance(value, int):
                return None
            ops.append((mnemonic, value))
            scan -= 1
            skipped += 1
            continue
        if _mnemonic(insn).startswith(("call", "push", "pop", "ret", "jmp")):
            return None
        if not _transparent_between_push_args_8616(insn):
            return None
        skipped += 1
        scan -= 1
    return None


def _collect_push_arg_sources_before_call(insns: tuple, idx: int) -> tuple[tuple | None, ...]:
    sources: list[tuple | None] = []
    scan = idx - 1
    skipped_transparents = 0
    skipped_call_segment = False
    while scan >= 0:
        insn = insns[scan]
        if _mnemonic(insn).startswith("push"):
            if not sources and _is_segment_register_push_8616(insn):
                skipped_call_segment = True
                scan -= 1
                continue
            sources.append(_push_arg_source_from_context(insns, scan))
            scan -= 1
            continue
        if not sources and skipped_call_segment and _transparent_between_push_args_8616(insn):
            scan -= 1
            continue
        if sources and skipped_transparents < 4 and _transparent_between_push_args_8616(insn):
            skipped_transparents += 1
            scan -= 1
            continue
        break
    sources.reverse()
    return tuple(sources)


def _trim_push_args_to_stack_cleanup(arg_widths: tuple[int, ...], cleanup: int | None) -> tuple[int, ...]:
    if not isinstance(cleanup, int) or cleanup <= 0 or not arg_widths:
        return arg_widths
    total = 0
    kept: list[int] = []
    for width in reversed(arg_widths):
        if total + width > cleanup:
            break
        kept.append(width)
        total += width
        if total == cleanup:
            return tuple(reversed(kept))
    return arg_widths


def _trim_push_arg_sources_to_stack_cleanup(
    arg_widths: tuple[int, ...],
    arg_sources: tuple[tuple | None, ...],
    cleanup: int | None,
) -> tuple[tuple | None, ...]:
    if not isinstance(cleanup, int) or cleanup <= 0 or not arg_widths or not arg_sources:
        return arg_sources
    if len(arg_widths) != len(arg_sources):
        return arg_sources
    total = 0
    kept: list[tuple | None] = []
    for width, source in reversed(tuple(zip(arg_widths, arg_sources))):
        if total + width > cleanup:
            break
        kept.append(source)
        total += width
        if total == cleanup:
            return tuple(reversed(kept))
    return arg_sources


def _stack_cleanup_after_call(function, insns: tuple, idx: int, callsite_addr: int) -> int | None:
    follow_insns = insns[idx + 1 :] if idx + 1 < len(insns) else ()
    if not follow_insns:
        follow_insns = _next_linear_block_insns(function, callsite_addr)
    if not follow_insns:
        return None
    insn = follow_insns[0]
    if _mnemonic(insn) != "add":
        return None
    operands = _instruction_operands(insn)
    if len(operands) != 2:
        return None
    if not _operand_is_reg(insn, operands[0], {"sp", "esp"}):
        return None
    return _operand_imm_value(operands[1])


def _instruction_reads_return_reg(insn, reg_names: set[str]) -> bool:
    operands = _instruction_operands(insn)
    if not operands:
        return False
    for operand in operands:
        if _operand_is_reg(insn, operand, reg_names):
            return True
    return False


def _return_use_after_call(function, insns: tuple, idx: int, callsite_addr: int) -> tuple[str | None, bool | None]:
    follow_insns = list(insns[idx + 1 : idx + 3])
    if len(follow_insns) < 2:
        follow_insns.extend(_next_linear_block_insns(function, callsite_addr)[: 2 - len(follow_insns)])
    for insn in follow_insns[:2]:
        if _instruction_reads_return_reg(insn, {"ax", "al", "ah"}):
            return "ax", True
    return None, False


def summarize_x86_16_callsite(function, callsite_addr: int) -> CallsiteSummary8616 | None:
    project = getattr(function, "project", None)
    if project is None or getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return None

    target_addr = None
    return_addr = None
    kind = None
    for seed in collect_neighbor_call_targets(function):
        if seed.callsite_addr != callsite_addr:
            continue
        target_addr = seed.target_addr
        return_addr = seed.return_addr
        kind = seed.kind
        break

    insns = _block_insns_for_callsite(function, callsite_addr)
    stack_probe_helper = _is_stack_probe_target_name_8616(_lookup_target_name_8616(function, target_addr))
    if not insns:
        helper_return_state = "stack_address" if stack_probe_helper else "none"
        helper_return_space = "ss" if stack_probe_helper else None
        helper_return_width = 2 if stack_probe_helper else None
        helper_return_address_kind = "stack" if stack_probe_helper else "none"
        return CallsiteSummary8616(
            callsite_addr,
            target_addr,
            return_addr,
            kind,
            None,
            (),
            None,
            None,
            None,
            stack_probe_helper,
            helper_return_state=helper_return_state,
            helper_return_space=helper_return_space,
            helper_return_width=helper_return_width,
            helper_return_address_kind=helper_return_address_kind,
        )
    call_idx = _find_call_index(insns, callsite_addr)
    if call_idx is None:
        helper_return_state = "stack_address" if stack_probe_helper else "none"
        helper_return_space = "ss" if stack_probe_helper else None
        helper_return_width = 2 if stack_probe_helper else None
        helper_return_address_kind = "stack" if stack_probe_helper else "none"
        return CallsiteSummary8616(
            callsite_addr,
            target_addr,
            return_addr,
            kind,
            None,
            (),
            None,
            None,
            None,
            stack_probe_helper,
            helper_return_state=helper_return_state,
            helper_return_space=helper_return_space,
            helper_return_width=helper_return_width,
            helper_return_address_kind=helper_return_address_kind,
        )

    cleanup = _stack_cleanup_after_call(function, insns, call_idx, callsite_addr)
    raw_arg_widths = _collect_push_args_before_call(insns, call_idx)
    raw_arg_sources = _collect_push_arg_sources_before_call(insns, call_idx)
    arg_widths = _trim_push_args_to_stack_cleanup(raw_arg_widths, cleanup)
    push_arg_sources = _trim_push_arg_sources_to_stack_cleanup(raw_arg_widths, raw_arg_sources, cleanup)
    if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
        log.warning(
            "[callsite-summary] callsite=%#x call_idx=%s cleanup=%r raw_widths=%r raw_sources=%r widths=%r sources=%r",
            callsite_addr,
            call_idx,
            cleanup,
            raw_arg_widths,
            raw_arg_sources,
            arg_widths,
            push_arg_sources,
        )
    arg_count = len(arg_widths)
    return_register, return_used = _return_use_after_call(function, insns, call_idx, callsite_addr)
    helper_return_state = "none"
    helper_return_space = None
    helper_return_width = None
    helper_return_address_kind = "none"
    if stack_probe_helper:
        if return_register not in {None, "ax"}:
            helper_return_state = "unknown"
            helper_return_address_kind = "unknown"
        elif return_used is True:
            helper_return_state = "stack_address"
            helper_return_space = "ss"
            helper_return_width = 2
            helper_return_address_kind = "stack"
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=target_addr,
        return_addr=return_addr,
        kind=kind,
        arg_count=arg_count,
        arg_widths=arg_widths,
        stack_cleanup=cleanup,
        return_register=return_register,
        return_used=return_used,
        stack_probe_helper=stack_probe_helper,
        helper_return_state=helper_return_state,
        helper_return_space=helper_return_space,
        helper_return_width=helper_return_width,
        helper_return_address_kind=helper_return_address_kind,
        push_arg_sources=push_arg_sources,
    )
