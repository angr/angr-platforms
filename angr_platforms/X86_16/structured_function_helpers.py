from __future__ import annotations

from dataclasses import dataclass

from capstone import CsInsn
from capstone.x86_const import (
    X86_INS_CALL,
    X86_INS_DEC,
    X86_INS_INT,
    X86_INS_JE,
    X86_INS_MOV,
    X86_INS_NOT,
    X86_INS_OR,
    X86_INS_POP,
    X86_INS_PUSH,
    X86_INS_REPE_SCASB,
    X86_INS_RET,
    X86_INS_XCHG,
    X86_INS_XOR,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AH,
    X86_REG_AX,
    X86_REG_BP,
    X86_REG_BX,
    X86_REG_CX,
    X86_REG_DI,
    X86_REG_DX,
)

from .analysis_helpers import INT21_SERVICE_SPECS, normalize_api_style

__all__ = ["StructuredHelperRender", "try_render_x86_16_structured_helper_c"]


@dataclass(frozen=True, slots=True)
class StructuredHelperRender:
    c_text: str
    family: str


def _decode_linear_insns(project, start: int, limit: int = 0x40) -> list[CsInsn]:
    code = bytes(project.loader.memory.load(start, limit))
    capstone = project.arch.capstone
    previous_detail = getattr(capstone, "detail", False)
    try:
        capstone.detail = True
        return list(capstone.disasm(code, start))
    finally:
        capstone.detail = previous_detail


def _op_reg(insn: CsInsn, index: int) -> int | None:
    if len(insn.operands) <= index or insn.operands[index].type != X86_OP_REG:
        return None
    return int(insn.operands[index].reg)


def _op_imm(insn: CsInsn, index: int) -> int | None:
    if len(insn.operands) <= index or insn.operands[index].type != X86_OP_IMM:
        return None
    return int(insn.operands[index].imm)


def _op_mem_bp_disp(insn: CsInsn, index: int) -> int | None:
    if len(insn.operands) <= index or insn.operands[index].type != X86_OP_MEM:
        return None
    mem = insn.operands[index].mem
    if int(mem.base) != X86_REG_BP or int(mem.index) != 0:
        return None
    return int(mem.disp)


def _is_push_bp_plus_4(insn: CsInsn) -> bool:
    return insn.id == X86_INS_PUSH and _op_mem_bp_disp(insn, 0) == 4


def _is_mov_reg_imm(insn: CsInsn, reg: int, imm: int) -> bool:
    return insn.id == X86_INS_MOV and _op_reg(insn, 0) == reg and _op_imm(insn, 1) == imm


def _is_mov_reg_reg(insn: CsInsn, dst: int, src: int) -> bool:
    return insn.id == X86_INS_MOV and _op_reg(insn, 0) == dst and _op_reg(insn, 1) == src


def _is_push_reg(insn: CsInsn, reg: int) -> bool:
    return insn.id == X86_INS_PUSH and _op_reg(insn, 0) == reg


def _is_pop_reg(insn: CsInsn, reg: int) -> bool:
    return insn.id == X86_INS_POP and _op_reg(insn, 0) == reg


def _is_ret_imm(insn: CsInsn, imm: int) -> bool:
    return insn.id == X86_INS_RET and _op_imm(insn, 0) == imm


def _resolved_helper_name(project, addr: int) -> str:
    func = project.kb.functions.function(addr=addr, create=False)
    if func is None or not getattr(func, "name", None):
        return f"sub_{addr:x}"
    return str(func.name)


def _write_decl_and_name(api_style: str) -> tuple[str, str, str]:
    api_style = normalize_api_style(api_style)
    spec = INT21_SERVICE_SPECS[0x40]
    if api_style == "pseudo":
        return spec.pseudo_decl or "int dos_write(int handle, const void *buffer, unsigned int count);", spec.pseudo_name, ""
    if api_style in {"dos", "msc", "compiler"}:
        return (
            spec.dos_decl or "int _dos_write(unsigned short handle, const void far *buffer, unsigned short count);",
            spec.dos_name,
            "(const void far *)",
        )
    return spec.modern_decl or "int write(int fd, const void *buf, unsigned int count);", spec.modern_name, ""


def _match_lookup_then_stderr_write(project, function) -> StructuredHelperRender | None:
    insns = _decode_linear_insns(project, function.addr)
    if len(insns) < 21:
        return None

    window = insns[:21]
    if not (
        _is_push_reg(window[0], X86_REG_BP)
        and _is_mov_reg_reg(window[1], X86_REG_BP, X86_REG_SP)
        and _is_push_reg(window[2], X86_REG_DI)
        and _is_push_bp_plus_4(window[3])
        and window[4].id == X86_INS_CALL
        and window[5].id == X86_INS_OR
        and _op_reg(window[5], 0) == X86_REG_AX
        and _op_reg(window[5], 1) == X86_REG_AX
        and window[6].id == X86_INS_JE
        and window[7].id == X86_INS_XCHG
        and {_op_reg(window[7], 0), _op_reg(window[7], 1)} == {X86_REG_AX, X86_REG_DX}
        and _is_mov_reg_reg(window[8], X86_REG_DI, X86_REG_DX)
        and window[9].id == X86_INS_XOR
        and _op_reg(window[9], 0) == X86_REG_AX
        and _op_reg(window[9], 1) == X86_REG_AX
        and _is_mov_reg_imm(window[10], X86_REG_CX, 0xFFFF)
        and window[11].id == X86_INS_REPE_SCASB
        and window[12].id == X86_INS_NOT
        and _op_reg(window[12], 0) == X86_REG_CX
        and window[13].id == X86_INS_DEC
        and _op_reg(window[13], 0) == X86_REG_CX
        and _is_mov_reg_imm(window[14], X86_REG_BX, 2)
        and _is_mov_reg_imm(window[15], X86_REG_AH, 0x40)
        and window[16].id == X86_INS_INT
        and _op_imm(window[16], 0) == 0x21
        and _is_pop_reg(window[17], X86_REG_DI)
        and _is_mov_reg_reg(window[18], X86_REG_SP, X86_REG_BP)
        and _is_pop_reg(window[19], X86_REG_BP)
        and _is_ret_imm(window[20], 2)
    ):
        return None

    call_target = _op_imm(window[4], 0)
    if call_target is None:
        return None
    helper_name = _resolved_helper_name(project, call_target)
    write_decl, write_name, pointer_cast = _write_decl_and_name("modern")
    if normalize_api_style("modern") != "modern":
        return None
    func_name = getattr(function, "name", None) or f"sub_{function.addr:x}"
    c_text = (
        f"{write_decl}\n"
        f"const char *{helper_name}(unsigned short a1);\n\n"
        f"int {func_name}(unsigned short a1)\n"
        "{\n"
        "    const char *message;\n"
        "    unsigned int length;\n\n"
        f"    message = {helper_name}(a1);\n"
        "    if (message == 0)\n"
        "        return 0;\n"
        "    length = 0;\n"
        "    while (message[length] != 0)\n"
        "        length += 1;\n"
        f"    return {write_name}(2, {pointer_cast}message, length);\n"
        "}\n"
    )
    return StructuredHelperRender(c_text=c_text, family="lookup_then_stderr_write")


def try_render_x86_16_structured_helper_c(project, function, *, api_style: str = "modern") -> StructuredHelperRender | None:
    if getattr(project.arch, "name", None) != "86_16":
        return None
    api_style = normalize_api_style(api_style)
    if api_style == "raw":
        return None
    return _match_lookup_then_stderr_write(project, function)
