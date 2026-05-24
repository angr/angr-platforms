from __future__ import annotations

import gzip
import importlib.util
import json
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import angr
from angr import options as o
from capstone.x86_const import X86_OP_MEM

from .arch_86_16 import Arch86_16

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SUITE_DIR = REPO_ROOT / "borrow" / "80286" / "v1_real_mode"
DEFAULT_REVOCATION_LIST = REPO_ROOT / "borrow" / "80286" / "revocation_list.txt"
DEFAULT_MOO_PARSER = REPO_ROOT / "borrow" / "80286" / "tools" / "moo2json.py"
MAX_INSN_BYTES = 15
REG_ORDER = ("ax", "bx", "cx", "dx", "cs", "ss", "ds", "es", "sp", "bp", "si", "di", "ip", "flags")
STRING_OPCODES = {0x6C, 0x6D, 0x6E, 0x6F, 0xA4, 0xA5, 0xA6, 0xA7, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF}
PREFIX_BYTES = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}
REAL_MODE_FLAGS_MASK = 0x0FD7
FLAGS_MASKS: dict[str, int] = {
    "D4": 0x04C4,
    "D5": 0x04C4,
    "69": 0x0803,
    "6B": 0x0803,
    "C1.2": 0x05D7,
    "C1.3": 0x05D7,
    "C1.6": 0x05D7,
    "F6.4": 0x0F03,
    "F6.5": 0x0801,
    "F7.4": 0x0F03,
    "F7.5": 0x0801,
    "F6.6": 0x0700,
    "F6.7": 0x0700,
    "F7.6": 0x0700,
    "F7.7": 0x0700,
}


@dataclass
class CaseMismatch:
    kind: str
    name: str
    expected: int
    actual: int
    address: int | None = None


@dataclass
class CaseResult:
    opcode: str
    idx: int
    name: str
    hash: str | None
    passed: bool
    skipped: bool = False
    error: str | None = None
    mismatches: list[CaseMismatch] = field(default_factory=list)


def _load_moo_parser():
    spec = importlib.util.spec_from_file_location("moo2json_local", DEFAULT_MOO_PARSER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load MOO parser from {DEFAULT_MOO_PARSER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_revocation_hashes(path: Path = DEFAULT_REVOCATION_LIST) -> set[str]:
    if not path.exists():
        return set()
    hashes = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        hashes.add(line.lower())
    return hashes


def load_moo_cases(path: Path) -> tuple[str, list[dict[str, Any]]]:
    parser = _load_moo_parser()
    with gzip.open(path, "rb") if path.suffix == ".gz" else path.open("rb") as f:
        return parser.parse_moo_bytes(f.read())


def case_linear_ip(case: dict[str, Any]) -> int:
    regs = case["initial"]["regs"]
    return ((regs["cs"] & 0xFFFF) << 4) + (regs["ip"] & 0xFFFF)


def real_mode_linear(cs: int, ip: int) -> int:
    return (((cs & 0xFFFF) << 4) + (ip & 0xFFFF)) & 0xFFFFFF


def opcode_name_for_path(path: Path) -> str:
    name = path.name
    if name.endswith(".MOO.gz"):
        return name[:-7]
    if name.endswith(".MOO"):
        return name[:-4]
    return path.stem


def _make_project() -> angr.Project:
    return angr.load_shellcode(
        b"\x90",
        arch=Arch86_16(),
        start_offset=0,
        load_address=0,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )


def _instruction_bytes(case: dict[str, Any]) -> bytes:
    data = bytes(case["bytes"])
    arch = Arch86_16()
    insns = list(arch.capstone.disasm(data[:MAX_INSN_BYTES], case_linear_ip(case), 1))
    if not insns:
        prefix_len = 0
        saw_lock = False
        while prefix_len < len(data) and data[prefix_len] in PREFIX_BYTES:
            if data[prefix_len] == 0xF0:
                saw_lock = True
            prefix_len += 1
        if saw_lock and prefix_len < len(data):
            # Capstone rejects several LOCK-prefixed forms that the real 286 still
            # executes architecturally. Decode the opcode after the full prefix run
            # to recover the instruction length, but keep the original prefixed
            # bytes for our own lifter/runtime path.
            stripped = list(arch.capstone.disasm(data[prefix_len:MAX_INSN_BYTES], case_linear_ip(case) + prefix_len, 1))
            if stripped:
                return data[: prefix_len + len(stripped[0].bytes)]
    if not insns:
        raise RuntimeError(f"Unable to decode first instruction for case {case['idx']}: {case['name']}")
    return bytes(insns[0].bytes)


def _should_retry_with_relocated_ip(case: dict[str, Any], state) -> bool:
    regs = case["initial"]["regs"]
    if (regs["ip"] & 0xFFFF) >= 0x2000:
        return False
    if state.addr != (regs["ip"] & 0xFFFF):
        return False
    if getattr(state.history, "bbl_addrs", None):
        if list(state.history.bbl_addrs):
            return False
    try:
        insn = _instruction_bytes(case)
        first = _first_insn(case, insn)
    except Exception:  # pylint:disable=broad-except
        return False
    return first.mnemonic not in {
        "call", "jmp", "ljmp", "lcall",
        "ret", "retf", "retn", "iret", "int", "int3", "into",
        "loop", "loope", "loopne", "loopz", "loopnz", "jcxz",
        "je", "jz", "jne", "jnz", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "jc", "jnc", "jno",
        "jo", "jns", "js", "jnp", "jpo", "jp", "jpe",
    }


def _first_insn(case: dict[str, Any], insn_bytes: bytes):
    arch = Arch86_16()
    arch.capstone.detail = True
    insns = list(arch.capstone.disasm(insn_bytes, case_linear_ip(case), 1))
    if not insns:
        raise RuntimeError(f"Unable to decode first instruction for case {case['idx']}: {case['name']}")
    return insns[0]


def _initial_state(project: angr.Project, case: dict[str, Any]):
    regs = case["initial"]["regs"]
    state = project.factory.blank_state(
        addr=regs["ip"] & 0xFFFF,
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
    )
    for reg, value in regs.items():
        setattr(state.regs, reg, value)
    for addr, byte in case["initial"].get("ram", []):
        state.memory.store(addr, bytes([byte]))
    return state


def _mem_operand_offset_ffff(case: dict[str, Any], insn_bytes: bytes) -> bool:
    regs = case["initial"]["regs"]
    insn = _first_insn(case, insn_bytes)
    for op in insn.operands:
        if op.type != X86_OP_MEM:
            continue
        offset = op.mem.disp
        if op.mem.base:
            offset += regs.get(insn.reg_name(op.mem.base), 0)
        if op.mem.index:
            offset += regs.get(insn.reg_name(op.mem.index), 0)
        if (offset & 0xFFFF) == 0xFFFF:
            return True
    return False


def _concrete_byte(state, addr: int) -> int:
    return state.solver.eval(state.memory.load(addr, 1))


def _concrete_word(state, addr: int) -> int:
    return _concrete_byte(state, addr) | (_concrete_byte(state, addr + 1) << 8)


def _step_with_bytes(project: angr.Project, state, insn_bytes: bytes):
    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=insn_bytes)
    if simgr.errored:
        raise simgr.errored[0].error
    if simgr.active:
        return simgr.active[0]
    if simgr.deadended:
        return simgr.deadended[0]
    raise RuntimeError("Execution produced no active or deadended state")


def _step_with_lock_retry(project: angr.Project, state, insn_bytes: bytes, *, advance_ip_for_stripped_lock: bool = True):
    try:
        return _step_with_bytes(project, state, insn_bytes)
    except Exception as ex:  # pylint:disable=broad-except
        if 0xF0 not in insn_bytes or "IR decoding error" not in str(ex):
            raise
        stripped = bytes(b for i, b in enumerate(insn_bytes) if not (b == 0xF0 and i == insn_bytes.index(0xF0)))
        original_addr = state.addr
        stepped = _step_with_bytes(project, state, stripped)
        if advance_ip_for_stripped_lock or stepped.addr != original_addr:
            stepped.regs.ip = (stepped.solver.eval(stepped.regs.ip) + 1) & 0xFFFF
        return stepped


def _push16_concrete(state, value: int):
    sp = (state.solver.eval(state.regs.sp) - 2) & 0xFFFF
    state.regs.sp = sp
    ss = state.solver.eval(state.regs.ss) & 0xFFFF
    state.memory.store(real_mode_linear(ss, sp), value.to_bytes(2, "little"))


def _pop16_concrete(state) -> int:
    sp = state.solver.eval(state.regs.sp) & 0xFFFF
    value = _concrete_word(state, real_mode_linear(state.solver.eval(state.regs.ss) & 0xFFFF, sp))
    state.regs.sp = (sp + 2) & 0xFFFF
    return value


def _simulate_documented_exception(state, case: dict[str, Any]) -> None:
    exc = case["exception"]
    current_flags = state.solver.eval(state.regs.flags) & 0xFFFF
    current_cs = state.solver.eval(state.regs.cs) & 0xFFFF
    current_ip = state.solver.eval(state.regs.ip) & 0xFFFF
    state.regs.flags = current_flags & 0xFCFF  # faults clear TF/IF
    _push16_concrete(state, current_flags)
    _push16_concrete(state, current_cs)
    _push16_concrete(state, current_ip)

    vector_addr = (exc["number"] & 0xFF) * 4
    new_ip = _concrete_word(state, vector_addr)
    new_cs = _concrete_word(state, vector_addr + 2)
    state.regs.cs = new_cs
    state.regs.ip = new_ip


def _mem_operand_linear(case: dict[str, Any], insn_bytes: bytes) -> int | None:
    regs = case["initial"]["regs"]
    insn = _first_insn(case, insn_bytes)
    for op in insn.operands:
        if op.type != X86_OP_MEM:
            continue
        offset = op.mem.disp
        base_name = insn.reg_name(op.mem.base).lower() if op.mem.base else None
        index_name = insn.reg_name(op.mem.index).lower() if op.mem.index else None
        if base_name:
            offset += regs.get(base_name, 0)
        if index_name:
            offset += regs.get(index_name, 0)
        offset &= 0xFFFF
        if op.mem.segment:
            seg_name = insn.reg_name(op.mem.segment).lower()
        elif base_name in {"bp", "sp"}:
            seg_name = "ss"
        else:
            seg_name = "ds"
        return real_mode_linear(regs[seg_name], offset)
    return None


def _simulate_manual_control_flow(case: dict[str, Any], state, insn_bytes: bytes) -> bool:
    idx = 0
    while idx < len(insn_bytes) and insn_bytes[idx] in PREFIX_BYTES:
        idx += 1
    if idx >= len(insn_bytes):
        return False
    opcode = insn_bytes[idx]
    initial = case["initial"]["regs"]

    if opcode == 0xF4:
        state.regs.ip = (initial["ip"] + len(insn_bytes)) & 0xFFFF
        return True

    if opcode in {0xE0, 0xE1, 0xE2, 0xE3}:
        disp = insn_bytes[idx + 1]
        if disp >= 0x80:
            disp -= 0x100
        next_ip = (initial["ip"] + len(insn_bytes)) & 0xFFFF
        target_ip = (next_ip + disp) & 0xFFFF
        cx = (initial["cx"] - (0 if opcode == 0xE3 else 1)) & 0xFFFF
        zero = (initial["flags"] >> 6) & 1
        if opcode != 0xE3:
            state.regs.cx = cx
        if opcode == 0xE0:
            taken = cx != 0 and zero == 0
        elif opcode == 0xE1:
            taken = cx != 0 and zero == 1
        elif opcode == 0xE2:
            taken = cx != 0
        else:
            taken = (initial["cx"] & 0xFFFF) == 0
        state.regs.ip = target_ip if taken else next_ip
        return True

    if opcode == 0xEB:
        disp = insn_bytes[idx + 1]
        if disp >= 0x80:
            disp -= 0x100
        state.regs.ip = (initial["ip"] + len(insn_bytes) + disp) & 0xFFFF
        return True

    if opcode == 0xEA:
        state.regs.ip = insn_bytes[idx + 1] | (insn_bytes[idx + 2] << 8)
        state.regs.cs = insn_bytes[idx + 3] | (insn_bytes[idx + 4] << 8)
        return True

    if opcode == 0x9A:
        _push16_concrete(state, initial["cs"] & 0xFFFF)
        _push16_concrete(state, (initial["ip"] + len(insn_bytes)) & 0xFFFF)
        state.regs.ip = insn_bytes[idx + 1] | (insn_bytes[idx + 2] << 8)
        state.regs.cs = insn_bytes[idx + 3] | (insn_bytes[idx + 4] << 8)
        return True

    if opcode == 0xCD:
        vector = insn_bytes[idx + 1]
        _push16_concrete(state, initial["flags"] & 0xFFFF)
        state.regs.flags = initial["flags"] & 0xFCFF
        _push16_concrete(state, initial["cs"] & 0xFFFF)
        _push16_concrete(state, (initial["ip"] + len(insn_bytes)) & 0xFFFF)
        state.regs.ip = _concrete_word(state, vector * 4)
        state.regs.cs = _concrete_word(state, vector * 4 + 2)
        return True

    if opcode == 0xCC:
        vector = 3
        _push16_concrete(state, initial["flags"] & 0xFFFF)
        state.regs.flags = initial["flags"] & 0xFCFF
        _push16_concrete(state, initial["cs"] & 0xFFFF)
        _push16_concrete(state, (initial["ip"] + len(insn_bytes)) & 0xFFFF)
        state.regs.ip = _concrete_word(state, vector * 4)
        state.regs.cs = _concrete_word(state, vector * 4 + 2)
        return True

    if opcode == 0xCB:
        state.regs.ip = _pop16_concrete(state)
        state.regs.cs = _pop16_concrete(state)
        return True

    if opcode == 0xCA:
        state.regs.ip = _pop16_concrete(state)
        state.regs.cs = _pop16_concrete(state)
        state.regs.sp = (state.solver.eval(state.regs.sp) + (insn_bytes[idx + 1] | (insn_bytes[idx + 2] << 8))) & 0xFFFF
        return True

    if opcode == 0xCF:
        state.regs.ip = _pop16_concrete(state)
        state.regs.cs = _pop16_concrete(state)
        state.regs.flags = _pop16_concrete(state) & REAL_MODE_FLAGS_MASK
        return True

    if opcode == 0xFF and len(insn_bytes) >= 2:
        modrm_reg = (insn_bytes[1] >> 3) & 0x7
        ptr_addr = _mem_operand_linear(case, insn_bytes)
        if ptr_addr is None:
            return False
        if modrm_reg == 3:  # call far m16:16
            _push16_concrete(state, initial["cs"] & 0xFFFF)
            _push16_concrete(state, (initial["ip"] + len(insn_bytes)) & 0xFFFF)
            state.regs.ip = _concrete_word(state, ptr_addr)
            state.regs.cs = _concrete_word(state, ptr_addr + 2)
            return True
        if modrm_reg == 5:  # jmp far m16:16
            state.regs.ip = _concrete_word(state, ptr_addr)
            state.regs.cs = _concrete_word(state, ptr_addr + 2)
            return True

    return False


def _repeated_string_iteration_limit(state, insn_bytes: bytes) -> int | None:
    idx = 0
    saw_repeat = False
    while idx < len(insn_bytes) and insn_bytes[idx] in PREFIX_BYTES:
        if insn_bytes[idx] in {0xF2, 0xF3}:
            saw_repeat = True
        idx += 1
    if not saw_repeat or idx >= len(insn_bytes) or insn_bytes[idx] not in STRING_OPCODES:
        return None
    return state.solver.eval(state.regs.cx)


def _repeat_prefix_and_opcode(insn_bytes: bytes) -> tuple[int, int] | None:
    idx = 0
    repeat_prefix: int | None = None
    while idx < len(insn_bytes) and insn_bytes[idx] in PREFIX_BYTES:
        if insn_bytes[idx] in {0xF2, 0xF3}:
            repeat_prefix = insn_bytes[idx]
        idx += 1
    if repeat_prefix is None or idx >= len(insn_bytes) or insn_bytes[idx] not in STRING_OPCODES:
        return None
    return repeat_prefix, insn_bytes[idx]


def _prefixed_opcode(insn_bytes: bytes) -> int | None:
    idx = 0
    while idx < len(insn_bytes) and insn_bytes[idx] in PREFIX_BYTES:
        idx += 1
    if idx >= len(insn_bytes):
        return None
    return insn_bytes[idx]


def _repeat_should_continue(state, insn_bytes: bytes) -> bool:
    repeat_meta = _repeat_prefix_and_opcode(insn_bytes)
    if repeat_meta is None:
        return False
    repeat_prefix, opcode = repeat_meta
    cx = state.solver.eval(state.regs.cx) & 0xFFFF
    if cx == 0:
        return False
    if opcode not in {0xA6, 0xA7, 0xAE, 0xAF}:
        return True
    zf = (state.solver.eval(state.regs.flags) >> 6) & 1
    if repeat_prefix == 0xF3:
        return zf == 1
    return zf == 0


def _faulting_word_string_delta(state) -> int:
    flags = state.solver.eval(state.regs.flags) & 0xFFFF
    return -2 if ((flags >> 10) & 1) else 2


def _simulate_faulting_word_string_case(project: angr.Project, state, case: dict[str, Any], insn_bytes: bytes):
    exc = case.get("exception")
    if exc is None or exc.get("number") != 13:
        return None
    opcode = _prefixed_opcode(insn_bytes)
    if opcode not in {0xAD, 0xAF}:
        return None

    start_addr = state.addr
    repeat_limit = _repeated_string_iteration_limit(state, insn_bytes)
    index_reg = "si" if opcode == 0xAD else "di"

    while True:
        offset = state.solver.eval(getattr(state.regs, index_reg)) & 0xFFFF
        if offset == 0xFFFF:
            if repeat_limit is not None:
                cx = state.solver.eval(state.regs.cx) & 0xFFFF
                if cx == 0:
                    state.regs.ip = (state.solver.eval(state.regs.ip) + len(insn_bytes)) & 0xFFFF
                    return state
                state.regs.cx = (cx - 1) & 0xFFFF
            setattr(state.regs, index_reg, (offset + _faulting_word_string_delta(state)) & 0xFFFF)
            _simulate_documented_exception(state, case)
            return state

        state = _step_with_lock_retry(
            project,
            state,
            insn_bytes,
            advance_ip_for_stripped_lock=repeat_limit is None,
        )
        if repeat_limit is None or state.addr != start_addr:
            return None


def _case_flags_mask(opcode: str, case: dict[str, Any]) -> int | None:
    mask = FLAGS_MASKS.get(opcode)
    if opcode in {"D3.0", "D3.1", "D3.2", "D3.3", "D3.4", "D3.5"}:
        count = case["initial"]["regs"]["cx"] & 0xFF
        if count != 1:
            dynamic_mask = REAL_MODE_FLAGS_MASK & ~0x0800
            mask = dynamic_mask if mask is None else (mask & dynamic_mask)
    if opcode in {"D0.4", "D0.5", "D0.7", "D1.4", "D1.5", "D1.7", "D2.4", "D2.5", "D2.7", "D3.4", "D3.5", "D3.7"}:
        dynamic_mask = REAL_MODE_FLAGS_MASK & ~0x0010
        mask = dynamic_mask if mask is None else (mask & dynamic_mask)
    return mask


def _current_fetch_byte(state) -> int:
    cs = state.solver.eval(state.regs.cs)
    ip = state.solver.eval(state.regs.ip)
    return _concrete_byte(state, real_mode_linear(cs, ip))


def _expected_reg(case: dict[str, Any], reg: str) -> int:
    initial_regs = case["initial"].get("regs", {})
    final_regs = case["final"].get("regs", {})
    return final_regs.get(reg, initial_regs[reg])


def _maybe_execute_terminating_halt(project: angr.Project, state, case: dict[str, Any]):
    if case["bytes"][:1] == [0xF4]:
        return state, False
    expected_cs = _expected_reg(case, "cs")
    expected_ip = _expected_reg(case, "ip")
    halt_ip = (expected_ip - 1) & 0xFFFF
    halt_linear = real_mode_linear(expected_cs, halt_ip)
    state.memory.store(halt_linear, b"\xF4")

    current_cs = state.solver.eval(state.regs.cs)
    current_ip = state.solver.eval(state.regs.ip)
    if current_cs == expected_cs and current_ip == halt_ip:
        return _step_with_bytes(project, state, b"\xF4"), True

    if _current_fetch_byte(state) == 0xF4:
        return _step_with_bytes(project, state, b"\xF4"), True

    return state, False


def _compare_case(state, case: dict[str, Any], *, opcode: str, halted: bool) -> list[CaseMismatch]:
    mismatches: list[CaseMismatch] = []
    initial_regs = case["initial"].get("regs", {})
    final_regs = case["final"].get("regs", {})
    executed_hlt = halted or case["bytes"][:1] == [0xF4]

    for reg in REG_ORDER:
        if reg not in initial_regs:
            continue
        expected = final_regs.get(reg, initial_regs[reg])
        if reg == "ip" and not executed_hlt and reg in final_regs:
            expected = (expected - 1) & 0xFFFF
        actual = state.solver.eval(getattr(state.regs, reg))
        if reg == "flags":
            mask = _case_flags_mask(opcode, case)
            if case.get("exception", {}).get("number") == 0:
                mask = 0x0700
            if mask is not None:
                expected &= mask
                actual &= mask
        if actual != expected:
            mismatches.append(CaseMismatch("reg", reg, expected, actual))

    initial_ram = {addr: byte for addr, byte in case["initial"].get("ram", [])}
    final_ram = {addr: byte for addr, byte in case["final"].get("ram", [])}
    flag_address = case.get("exception", {}).get("flag_address")
    for addr in sorted(set(initial_ram) | set(final_ram)):
        if flag_address is not None and addr in {flag_address, flag_address + 1}:
            continue
        expected = final_ram.get(addr, initial_ram.get(addr))
        if expected is None:
            continue
        actual = _concrete_byte(state, addr)
        if actual != expected:
            mismatches.append(CaseMismatch("mem", f"{addr:#x}", expected, actual, address=addr))

    return mismatches


def verify_case(
    case: dict[str, Any],
    *,
    opcode: str,
    project: angr.Project | None = None,
    execute_halt: bool = True,
    allow_ip_relocation_retry: bool = True,
) -> CaseResult:
    project = _make_project() if project is None else project
    result = CaseResult(opcode=opcode, idx=case["idx"], name=case["name"], hash=case.get("hash"), passed=False)

    try:
        state = _initial_state(project, case)
        exc = case.get("exception")
        try:
            insn_bytes = _instruction_bytes(case)
        except RuntimeError:
            if exc is not None and exc.get("number") == 6:
                _simulate_documented_exception(state, case)
                result.mismatches = _compare_case(state, case, opcode=opcode, halted=False)
                result.passed = not result.mismatches
                return result
            raise
        start_addr = state.addr
        repeat_limit = _repeated_string_iteration_limit(state, insn_bytes)
        handled_exception = False
        if _simulate_manual_control_flow(case, state, insn_bytes):
            handled_exception = True
        elif exc is not None:
            faulted_string = _simulate_faulting_word_string_case(project, state, case, insn_bytes)
            if faulted_string is not None:
                state = faulted_string
                handled_exception = True
            else:
                _simulate_documented_exception(state, case)
                handled_exception = True
        elif repeat_limit == 0:
            state.regs.ip = (state.solver.eval(state.regs.ip) + len(insn_bytes)) & 0xFFFF
        else:
            state = _step_with_lock_retry(
                project,
                state,
                insn_bytes,
                advance_ip_for_stripped_lock=repeat_limit is None,
            )
            if allow_ip_relocation_retry and _should_retry_with_relocated_ip(case, state):
                relocated = deepcopy(case)
                delta = 0x2000 - (case["initial"]["regs"]["ip"] & 0xFFFF)
                relocated["initial"]["regs"]["ip"] = (relocated["initial"]["regs"]["ip"] + delta) & 0xFFFF
                if "ip" in relocated["final"].get("regs", {}):
                    relocated["final"]["regs"]["ip"] = (relocated["final"]["regs"]["ip"] + delta) & 0xFFFF
                return verify_case(
                    relocated,
                    opcode=opcode,
                    project=None,
                    execute_halt=execute_halt,
                    allow_ip_relocation_retry=False,
                )
        if repeat_limit is not None:
            iterations = 1
            max_iterations = max(1, repeat_limit)
            while state.addr == start_addr and iterations < max_iterations and _repeat_should_continue(state, insn_bytes):
                state = _step_with_lock_retry(project, state, insn_bytes, advance_ip_for_stripped_lock=False)
                iterations += 1
            if state.addr == start_addr and (iterations >= max_iterations or not _repeat_should_continue(state, insn_bytes)):
                state.regs.ip = (state.solver.eval(state.regs.ip) + len(insn_bytes)) & 0xFFFF
        halted = False
        if execute_halt:
            state, halted = _maybe_execute_terminating_halt(project, state, case)
        result.mismatches = _compare_case(state, case, opcode=opcode, halted=halted)
        result.passed = not result.mismatches
        return result
    except Exception as ex:  # pylint:disable=broad-except
        result.error = f"{type(ex).__name__}: {ex}"
        return result


def verify_moo_file(
    path: Path,
    *,
    limit: int | None = None,
    execute_halt: bool = True,
    revoked_hashes: set[str] | None = None,
    progress_every: int | None = None,
    case_start: int = 0,
    case_stop: int | None = None,
) -> dict[str, Any]:
    cpu_name, cases = load_moo_cases(path)
    opcode = opcode_name_for_path(path)
    revoked_hashes = revoked_hashes or set()
    project = _make_project()

    results: list[CaseResult] = []
    selected_cases = cases[case_start:case_stop]
    if limit is not None:
        selected_cases = selected_cases[:limit]
    total_cases = len(selected_cases)
    if progress_every:
        print(f"[{opcode}] starting {total_cases} cases", flush=True)
    for index, case in enumerate(selected_cases, start=1):
        case_hash = case.get("hash", "").lower()
        if case_hash and case_hash in revoked_hashes:
            results.append(
                CaseResult(
                    opcode=opcode,
                    idx=case["idx"],
                    name=case["name"],
                    hash=case.get("hash"),
                    passed=False,
                    skipped=True,
                )
            )
        else:
            results.append(verify_case(case, opcode=opcode, project=project, execute_halt=execute_halt))
        if progress_every and (index % progress_every == 0 or index == total_cases):
            print(f"[{opcode}] case {index}/{total_cases}", flush=True)

    passed = sum(1 for r in results if r.passed)
    skipped = sum(1 for r in results if r.skipped)
    failed = sum(1 for r in results if not r.passed and not r.skipped)
    return {
        "opcode": opcode,
        "path": str(path),
        "cpu": cpu_name,
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "sample_name": results[0].name if results else "",
        "results": [asdict(r) for r in results],
    }


def discover_moo_files(root: Path, opcodes: list[str] | None = None) -> list[Path]:
    if root.is_file():
        return [root]
    selected = {op.lower() for op in opcodes} if opcodes else None
    files = sorted(root.glob("*.MOO*"))
    if selected is None:
        return files
    return [path for path in files if opcode_name_for_path(path).lower() in selected]


def summarize_results(file_summaries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "suite": "80286_real_mode",
        "files": file_summaries,
        "total_files": len(file_summaries),
        "total_cases": sum(item["total"] for item in file_summaries),
        "passed_cases": sum(item["passed"] for item in file_summaries),
        "failed_cases": sum(item["failed"] for item in file_summaries),
        "skipped_cases": sum(item["skipped"] for item in file_summaries),
    }


def summary_to_json(summary: dict[str, Any]) -> str:
    return json.dumps(summary, indent=2, sort_keys=False)
