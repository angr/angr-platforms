import contextlib
import logging
from typing import Any

import bitstring
from pyvex.lifting import register
from pyvex.lifting.util import GymratLifter, Instruction, JumpKind, ParseError
from pyvex.lifting.util.vex_helper import Type

from .arch_86_16 import Arch86_16
from .ir.core import AddressStatus, IRCondition, IRAddress, MemSpace, SegmentOrigin
from .emulator import Emulator
from .instr16 import Instr16
from .instr32 import Instr32
from .instruction import InstrData
from .ir.condition_ir import (
    ConditionSource,
    ConditionIR,
    ConditionFailure,
    JCC_UGE_MNEMONICS_8616,
    JCC_UGT_MNEMONICS_8616,
    JCC_ULE_MNEMONICS_8616,
    JCC_ULT_MNEMONICS_8616,
    JCC_EQ_MNEMONICS_8616,
    JCC_NE_MNEMONICS_8616,
    JCC_SGE_MNEMONICS_8616,
    JCC_SGT_MNEMONICS_8616,
    JCC_SLE_MNEMONICS_8616,
    JCC_SLT_MNEMONICS_8616,
    _JCC_COMPARISON_MNEMONICS_8616,
    build_condition_from_cmp_8616,
    build_condition_from_test_8616,
    deduplicate_conditions_8616,
)
from .jcc_condition import _direct_jcc_condition_from_last_condition_8616
from .parse import CHSZ_AD, CHSZ_OP
from .regs import reg16_t

logger = logging.getLogger(__name__)


def _bitstream_is_empty(bitstrm: bitstring.ConstBitStream) -> bool:
    try:
        bitstrm.peek(1)
        return False
    except bitstring.ReadError:
        return True


class _LifterInstructionFacade:
    """
    Combine the raw IRSB customizer API with the higher-level Instruction helpers.
    Modern pyvex exposes jump/get/put on Instruction, but low-level IR building
    helpers like _append_stmt() and _settmp() still live on the IRSB customizer.
    """

    def __init__(self, irsb_c: Any, instruction: Instruction) -> None:
        self._irsb_c = irsb_c
        self._instruction = instruction

    def __getattr__(self, name: str) -> Any:
        if hasattr(self._instruction, name):
            return getattr(self._instruction, name)
        return getattr(self._irsb_c, name)


class Instruction_ANY(Instruction):
    _REG8_NAMES = {"al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"}
    _REG16_NAMES = {"ax", "bx", "cx", "dx", "sp", "bp", "si", "di", "ip", "flags"}
    _SIMPLE_JCC_8616: frozenset[str] = frozenset(
        JCC_EQ_MNEMONICS_8616
        | JCC_NE_MNEMONICS_8616
        | JCC_ULT_MNEMONICS_8616
        | JCC_UGE_MNEMONICS_8616
        | JCC_ULE_MNEMONICS_8616
        | JCC_UGT_MNEMONICS_8616
        | JCC_SLT_MNEMONICS_8616
        | JCC_SGE_MNEMONICS_8616
        | JCC_SLE_MNEMONICS_8616
        | JCC_SGT_MNEMONICS_8616
        | _JCC_COMPARISON_MNEMONICS_8616
    )

    _BLOCK_TERMINATORS = {
        "call",
        "jmp",
        *_SIMPLE_JCC_8616,
        "ret",
        "retf",
        "iret",
        "int",
        "int3",
        "hlt",
    }

    # Convert everything that's not an instruction into a No-op to meet the BF spec
    bin_format = "xxxxxxxx" # We don't care, match it all
    name = "nop"

    def lift(self, irsb_c, past_instructions, future_instructions):
        self.irsb_c = irsb_c
        self.mark_instruction_start()
        self.emu.irsb = irsb_c
        # Set the block address on the emulator so facts are keyed by block.
        # The actual IRSB is available via self.emu.irsb.irsb (pyvex pattern).
        # Fall back to self.addr (instruction address).
        actual_irsb = getattr(self.emu.irsb, "irsb", self.emu.irsb)
        block_addr = getattr(actual_irsb, "addr", self.addr)
        self.emu._inertia_current_block_addr = block_addr
        self.emu.set_lifter_instruction(_LifterInstructionFacade(irsb_c, self))
        self._past_instructions = past_instructions
        self._future_instructions = future_instructions
        if self.simple_semantics is not None:
            self._lift_simple()
            return
        self.compute_result()

    def __init__(self, bitstrm, arch, addr):
        self.bitstrm = bitstrm
        self.arch = arch
        self.addr = addr
        self.instr = InstrData()
        self.emu = Emulator(arch, None)
        # Set block address and function address on emulator so _record_semantic_memory_access
        # can key facts into _inertia_module_alias_fact_cache and evidence_cache
        self.emu._inertia_current_block_addr = addr
        self.emu._inertia_current_function_addr = addr
        self.instr16 = Instr16(self.emu, self.instr)
        self.instr32 = Instr32(self.emu, self.instr)
        self.emu.set_lifter_instruction(None)
        self.emu.set_bitstream(bitstrm)
        self.simple_semantics = None
        super().__init__(bitstrm, arch, addr)

        self.reg_offsets = {
            reg16_t.AX: 0,
            reg16_t.CX: 2,
            reg16_t.DX: 4,
            reg16_t.BX: 6,
            reg16_t.BP: 10,
            reg16_t.SI: 12,
            reg16_t.DI: 14,
            reg16_t.FLAGS: 18,
            20: 20,  # SS offset
            22: 22,  # CS offset
            reg16_t.IP: 24,
            reg16_t.SP: 8,
        }

    def parse(self, bitstrm):
        self.start = bitstrm.bytepos
        raw = bytes(bitstrm[self.start * 8: self.start * 8 + 15 * 8])
        cs_prefix_len = 0
        instr = list(self.arch.capstone.disasm(raw, self.addr, 1))
        if not instr:
            # Capstone rejects several LOCK-prefixed forms that the real 286 still
            # executes, and also segment-override + LOCK combinations.
            # Decode the underlying opcode for mnemonic discovery, but let our
            # own parser consume the real prefix byte stream below.
            for strip_len in range(1, min(4, len(raw))):
                instr = list(self.arch.capstone.disasm(raw[strip_len:], self.addr + strip_len, 1))
                if instr:
                    cs_prefix_len = strip_len
                    break
        if not instr:
            raise ParseError("Couldn't disassemble instruction")
        self.cs = instr[0]
        logger.debug("cs dis: %s %s", self.cs.mnemonic, self.cs.op_str)
        self.name = self.cs.insn_name()
        self.simple_semantics = self._match_simple_semantics()
        if self.simple_semantics is not None:
            bitstrm.bytepos = self.start + cs_prefix_len + self.cs.size
            self.bitwidth = (cs_prefix_len + self.cs.size) * 8
            self.is_mode32 = False
            self.chsz_op = False
            return {"x": "00000000"}


        self.is_mode32 = False  #emu.is_mode32()
        prefix = self.instr32.parse_prefix() if self.is_mode32 else self.instr16.parse_prefix()
        self.chsz_op = prefix & CHSZ_OP
        chsz_ad = prefix & CHSZ_AD

        if self.is_mode32 ^ bool(self.chsz_op):
            self.instr32.set_chsz_ad(not (self.is_mode32 ^ bool(chsz_ad)))
            self.instr32.parse()
            #assert self.name == self.instr32.instrfuncs[self.instr32.instr.opcode].__name__.split('_')[0]
        else:
            self.instr16.set_chsz_ad(self.is_mode32 ^ bool(chsz_ad))
            self.instr16.parse()
            #assert self.name == self.instr16.instrfuncs[self.instr16.instr.opcode].__name__.split('_')[0]
        self.bitwidth = (bitstrm.bytepos - self.start) * 8
        return {"x": "00000000"}

    def _match_simple_semantics(self):
        ops = getattr(self.cs, "operands", ())
        if self.cs.mnemonic == "nop":
            return ("nop",)
        if self.cs.mnemonic == "ret":
            if len(ops) == 1 and ops[0].type == 2:
                return ("ret_imm16", ops[0].imm & 0xFFFF)
            return ("ret",)
        if self.cs.mnemonic == "leave":
            return ("leave",)
        if self.cs.mnemonic == "enter" and len(ops) == 2 and all(op.type == 2 for op in ops):
            return ("enter", ops[0].imm & 0xFFFF, ops[1].imm & 0xFF)
        if self.cs.mnemonic in {"push", "pop"} and len(ops) == 1:
            reg_name = self._reg16_name(ops[0])
            mem = self._bp_mem(ops[0])
            if reg_name:
                return (f"{self.cs.mnemonic}_reg16", reg_name)
            if self.cs.mnemonic == "push" and ops[0].type == 2:
                return ("push_imm16", ops[0].imm & 0xFFFF)
            if self.cs.mnemonic == "push" and mem:
                return ("push_mem16", mem)
        if self.cs.mnemonic == "call" and len(ops) == 1 and ops[0].type == 2:
            return ("call", ops[0].imm)
        if self.cs.mnemonic in {"jmp", *self._SIMPLE_JCC_8616} and len(ops) == 1 and ops[0].type == 2:
            return (self.cs.mnemonic, ops[0].imm)
        if len(ops) != 2:
            return None

        dst, src = ops
        dst_reg = self._reg16_name(dst)
        src_reg = self._reg16_name(src)
        src_imm = self._imm16_value(src)
        src_imm8 = self._imm8_value(src)
        dst_mem = self._bp_mem(dst)
        src_mem = self._bp_mem(src)
        dst_abs_mem = self._direct_mem16(dst)
        src_abs_mem = self._direct_mem16(src)
        dst_abs_mem8 = self._direct_mem8(dst)
        src_reg8 = self._reg8_name(src)
        dst_reg8 = self._reg8_name(dst)

        if self.cs.mnemonic == "mov" and dst_reg and src_imm is not None:
            return ("mov_reg_imm16", dst_reg, src_imm)
        if self.cs.mnemonic == "mov" and dst_reg and src_reg:
            return ("mov_reg_reg16", dst_reg, src_reg)
        if self.cs.mnemonic == "mov" and dst_reg and src_mem:
            return ("mov_reg_mem16", dst_reg, src_mem)
        if self.cs.mnemonic == "mov" and dst_mem and src_reg:
            return ("mov_mem_reg16", dst_mem, src_reg)
        if self.cs.mnemonic == "mov" and dst_mem and src_imm is not None:
            return ("mov_mem_imm16", dst_mem, src_imm)
        if self.cs.mnemonic == "lea" and dst_reg and src_mem:
            return ("lea_reg_bpdisp16", dst_reg, src_mem)
        if self.cs.mnemonic == "cmp" and dst_reg:
            if src_reg:
                return (f"{self.cs.mnemonic}_reg_reg16", dst_reg, src_reg)
            if src_mem:
                return (f"{self.cs.mnemonic}_reg_mem16", dst_reg, src_mem)
            if src_imm is not None:
                return (f"{self.cs.mnemonic}_reg_imm16", dst_reg, src_imm)
        if self.cs.mnemonic == "cmp" and dst_mem:
            if src_reg:
                return ("cmp_mem_reg16", dst_mem, src_reg)
            if src_imm is not None:
                return ("cmp_mem_imm16", dst_mem, src_imm)
        if self.cs.mnemonic == "cmp" and dst_abs_mem is not None:
            if src_imm is not None:
                return ("cmp_abs_imm16", dst_abs_mem, src_imm)
            if src_reg:
                return ("cmp_abs_reg16", dst_abs_mem, src_reg)
        if self.cs.mnemonic == "cmp" and dst_reg and src_abs_mem is not None:
            return ("cmp_reg_abs16", dst_reg, src_abs_mem)
        if self.cs.mnemonic == "cmp" and dst_abs_mem8 is not None:
            if src_imm8 is not None:
                return ("cmp_abs_imm8", dst_abs_mem8, src_imm8)
            if src_reg8:
                return ("cmp_abs_reg8", dst_abs_mem8, src_reg8)
        if self.cs.mnemonic == "cmp" and dst_reg8 and dst_reg8 in self._REG8_NAMES:
            src_abs_mem8 = self._direct_mem8(src)
            if src_abs_mem8 is not None:
                return ("cmp_reg_abs8", dst_reg8, src_abs_mem8)
        return None

    def _reg8_name(self, operand):
        if operand.type != 1 or getattr(operand, "size", None) != 1:
            return None
        reg_name = self.cs.reg_name(operand.reg).lower()
        return reg_name if reg_name in self._REG8_NAMES else None

    def _reg16_name(self, operand):
        if operand.type != 1 or getattr(operand, "size", None) != 2:
            return None
        reg_name = self.cs.reg_name(operand.reg).lower()
        return reg_name if reg_name in self._REG16_NAMES else None

    @staticmethod
    def _imm8_value(operand):
        if operand.type != 2:
            return None
        return operand.imm & 0xFF

    @staticmethod
    def _imm16_value(operand):
        if operand.type != 2:
            return None
        return operand.imm & 0xFFFF

    def _get_reg16(self, reg_name):
        return self.get(reg_name, Type.int_16)

    def _const16(self, value):
        return self.constant(value & 0xFFFF, Type.int_16)

    def _const32(self, value):
        return self.constant(value & 0xFFFFFFFF, Type.int_32)

    def _bp_mem(self, operand):
        if operand.type != 3 or getattr(operand, "size", None) != 2:
            return None
        mem = operand.mem
        base = self.cs.reg_name(mem.base).lower() if mem.base else None
        index = self.cs.reg_name(mem.index).lower() if mem.index else None
        if index is not None:
            return None
        if base not in {"bp", "sp"}:
            return None
        return (base, mem.disp & 0xFFFF, mem.disp)

    def _direct_mem16(self, operand):
        if operand.type != 3 or getattr(operand, "size", None) != 2:
            return None
        mem = operand.mem
        if mem.base or mem.index:
            return None
        return mem.disp & 0xFFFF

    def _direct_mem8(self, operand):
        if operand.type != 3 or getattr(operand, "size", None) != 1:
            return None
        mem = operand.mem
        if mem.base or mem.index:
            return None
        return mem.disp & 0xFFFF

    def _addr_from_bp_mem(self, mem_spec):
        base, _, signed_disp = mem_spec
        addr = self._get_reg16(base)
        if signed_disp == 0:
            return addr
        return addr + self._const16(signed_disp)

    def _ss_addr_from_bp_mem(self, mem_spec):
        return self._real_mode_linear("ss", self._addr_from_bp_mem(mem_spec))

    def _record_bp_mem_access(self, mem_spec, mode: int, *, size: int = 2) -> None:
        base, _, signed_disp = mem_spec
        self._record_mem_access(
            "ss",
            int(signed_disp),
            mode,
            base=(str(base),),
            size=size,
            segment_origin=SegmentOrigin.DEFAULTED,
            status=AddressStatus.STABLE,
        )

    def _load_mem16(self, mem_spec):
        self._record_bp_mem_access(mem_spec, 0, size=2)
        return self.load(self._ss_addr_from_bp_mem(mem_spec), Type.int_16)

    def _store_mem16(self, mem_spec, value):
        self._record_bp_mem_access(mem_spec, 1, size=2)
        self.store(value, self._ss_addr_from_bp_mem(mem_spec))

    def _record_mem_access(
        self,
        seg: str,
        offset: int,
        mode: int = 0,
        *,
        base: tuple[str, ...] = (),
        size: int = 2,
        segment_origin=None,
        status=None,
    ) -> None:
        try:
            from .semantics.evidence_cache import (
                get_current_function_addr,
                record_access,
                record_access_by_block,
            )
            space = getattr(MemSpace, seg.upper())
            addr = IRAddress(
                space=space,
                base=base,
                offset=offset,
                size=size,
                status=status if status is not None else AddressStatus.STABLE,
                segment_origin=segment_origin if segment_origin is not None else SegmentOrigin.PROVEN,
                expr=(seg, *base),
            )
            func_addr = get_current_function_addr()
            if isinstance(func_addr, int):
                record_access(func_addr, mode, addr)
            else:
                block_addr = getattr(self.emu, "_inertia_current_block_addr", None)
                if isinstance(block_addr, int):
                    record_access_by_block(block_addr, mode, addr)
        except Exception:
            pass

    def _load_abs16(self, offset):
        self._record_mem_access("ds", offset, 0)
        return self.load(self._real_mode_linear("ds", self._const16(offset)), Type.int_16)

    def _load_abs8(self, offset):
        self._record_mem_access("ds", offset, 0)
        return self.load(self._real_mode_linear("ds", self._const16(offset)), Type.int_8)

    def _real_mode_linear(self, seg_reg, off16):
        seg = self._get_reg16(seg_reg).cast_to(Type.int_32)
        off32 = off16.cast_to(Type.int_32)
        return (seg << self.constant(4, Type.int_8)) + off32

    def _stack_load16(self, off16):
        off_val = getattr(off16, "constant", None)
        if isinstance(off_val, int):
            self._record_mem_access("ss", off_val, 0, base=("sp",), size=2)
        return self.load(self._real_mode_linear("ss", off16), Type.int_16)

    def _stack_store16(self, off16, value):
        off_val = getattr(off16, "constant", None)
        if isinstance(off_val, int):
            self._record_mem_access("ss", off_val, 1, base=("sp",), size=2)
        self.store(value, self._real_mode_linear("ss", off16))

    def _set_zf_from_cond(self, cond):
        self._set_flag_bit(6, cond)

    def _set_flag_bit(self, bit, cond):
        flags = self._get_reg16("flags")
        mask = self._const16(1 << bit)
        value = cond.ite(mask, self._const16(0))
        self.put((flags & ~mask) | value, "flags")

    def _update_cmp_flags(self, lhs, rhs):
        result = lhs - rhs
        lhs_sign = lhs[15]
        rhs_sign = rhs[15]
        res_sign = result[15]
        low8 = result.cast_to(Type.int_8)
        parity = low8 ^ (low8 >> self.constant(4, Type.int_8))
        parity = parity ^ (parity >> self.constant(2, Type.int_8))
        parity = parity ^ (parity >> self.constant(1, Type.int_8))
        af = (((lhs ^ rhs) ^ result) & self._const16(0x0010)) != self._const16(0)

        self._set_flag_bit(0, lhs < rhs)
        self._set_flag_bit(2, (~parity & self.constant(1, Type.int_8)) != self.constant(0, Type.int_8))
        self._set_flag_bit(4, af)
        self._set_flag_bit(6, lhs == rhs)
        self._set_flag_bit(7, res_sign != self._const16(0))
        overflow = (lhs_sign != rhs_sign) & (res_sign != lhs_sign)
        self._set_flag_bit(11, overflow)

    def _update_cmp_flags8(self, lhs, rhs):
        result = lhs - rhs
        lhs_sign = lhs[7]
        rhs_sign = rhs[7]
        res_sign = result[7]
        parity = lhs - rhs
        parity = parity ^ (parity >> self.constant(4, Type.int_8))
        parity = parity ^ (parity >> self.constant(2, Type.int_8))
        parity = parity ^ (parity >> self.constant(1, Type.int_8))
        af = (((lhs ^ rhs) ^ result) & self.constant(0x10, Type.int_8)) != self.constant(0, Type.int_8)

        self._set_flag_bit(0, lhs < rhs)
        self._set_flag_bit(2, (~parity & self.constant(1, Type.int_8)) != self.constant(0, Type.int_8))
        self._set_flag_bit(4, af)
        self._set_flag_bit(6, lhs == rhs)
        self._set_flag_bit(7, res_sign != self.constant(0, Type.int_8))
        overflow = (lhs_sign != rhs_sign) & (res_sign != lhs_sign)
        self._set_flag_bit(11, overflow)

    def _flag_is_set(self, bit):
        return (self._get_reg16("flags") & self._const16(1 << bit)) != self._const16(0)

    def _flag_is_clear(self, bit):
        return (self._get_reg16("flags") & self._const16(1 << bit)) == self._const16(0)

    def _binop_reg_reg(self, op_name, dst_reg, src_reg):
        dst = self._get_reg16(dst_reg)
        src = self._get_reg16(src_reg)
        if op_name == "add":
            result = dst + src
        elif op_name == "sub":
            result = dst - src
        elif op_name == "xor":
            result = dst ^ src
        elif op_name == "and":
            result = dst & src
        elif op_name == "or":
            result = dst | src
        elif op_name == "cmp":
            self._record_cmp_condition_source(dst, src)
            if not self._next_instruction_is_simple_jcc():
                self._update_cmp_flags(dst, src)
            return
        else:
            raise NotImplementedError(op_name)
        self.put(result, dst_reg)

    def _binop_reg_imm(self, op_name, dst_reg, imm):
        dst = self._get_reg16(dst_reg)
        src = self._const16(imm)
        if op_name == "add":
            result = dst + src
        elif op_name == "sub":
            result = dst - src
        elif op_name == "xor":
            result = dst ^ src
        elif op_name == "and":
            result = dst & src
        elif op_name == "or":
            result = dst | src
        elif op_name == "cmp":
            self._record_cmp_condition_source(dst, src)
            if not self._next_instruction_is_simple_jcc():
                self._update_cmp_flags(dst, src)
            return
        else:
            raise NotImplementedError(op_name)
        self.put(result, dst_reg)

    def _binop_reg_mem(self, op_name, dst_reg, mem_spec):
        dst = self._get_reg16(dst_reg)
        src = self._load_mem16(mem_spec)
        if op_name == "add":
            result = dst + src
        elif op_name == "sub":
            result = dst - src
        elif op_name == "xor":
            result = dst ^ src
        elif op_name == "and":
            result = dst & src
        elif op_name == "or":
            result = dst | src
        elif op_name == "cmp":
            self._record_cmp_condition_source(dst, src)
            if not self._next_instruction_is_simple_jcc():
                self._update_cmp_flags(dst, src)
            return
        else:
            raise NotImplementedError(op_name)
        self.put(result, dst_reg)

    def _cmp_operands_from_semantics(self, semantics):
        kind = semantics[0]
        if kind == "cmp_reg_reg16":
            _, lhs_reg, rhs_reg = semantics
            return self._get_reg16(lhs_reg), self._get_reg16(rhs_reg)
        if kind == "cmp_reg_imm16":
            _, lhs_reg, imm = semantics
            return self._get_reg16(lhs_reg), self._const16(imm)
        if kind == "cmp_reg_mem16":
            _, lhs_reg, mem_spec = semantics
            return self._get_reg16(lhs_reg), self._load_mem16(mem_spec)
        if kind == "cmp_reg_abs16":
            _, lhs_reg, offset = semantics
            return self._get_reg16(lhs_reg), self._load_abs16(offset)
        if kind == "cmp_mem_reg16":
            _, mem_spec, rhs_reg = semantics
            return self._load_mem16(mem_spec), self._get_reg16(rhs_reg)
        if kind == "cmp_mem_imm16":
            _, mem_spec, imm = semantics
            return self._load_mem16(mem_spec), self._const16(imm)
        if kind == "cmp_abs_reg16":
            _, offset, rhs_reg = semantics
            return self._load_abs16(offset), self._get_reg16(rhs_reg)
        if kind == "cmp_abs_imm16":
            _, offset, imm = semantics
            return self._load_abs16(offset), self._const16(imm)
        if kind == "cmp_reg_abs8":
            _, lhs_reg, offset = semantics
            return self.get(lhs_reg, Type.int_8), self._load_abs8(offset)
        if kind == "cmp_abs_reg8":
            _, offset, rhs_reg = semantics
            return self._load_abs8(offset), self.get(rhs_reg, Type.int_8)
        if kind == "cmp_abs_imm8":
            _, offset, imm = semantics
            return self._load_abs8(offset), self.constant(imm, Type.int_8)
        return None

    def _next_instruction_is_simple_jcc(self):
        if not getattr(self, "_future_instructions", None):
            return False
        nxt = self._future_instructions[0]
        nxt_semantics = getattr(nxt, "simple_semantics", None)
        if nxt_semantics is None:
            return False
        return nxt_semantics[0] in self._SIMPLE_JCC_8616

    def _direct_jcc_condition(self, kind):
        if not getattr(self, "_past_instructions", None):
            return None
        prev = self._past_instructions[-1]
        prev_emu = getattr(prev, "emu", None)
        last_condition = getattr(prev_emu, "get_last_condition", lambda: None)()

        def _finish(result):
            if isinstance(last_condition, IRCondition) and prev_emu is not None:
                with contextlib.suppress(Exception):
                    prev_emu.clear_last_condition()
            return result

        if isinstance(last_condition, IRCondition):
            branch_cond = _direct_jcc_condition_from_last_condition_8616(self, kind, last_condition)
            if branch_cond is not None:
                return _finish(branch_cond)
        prev_semantics = getattr(prev, "simple_semantics", None)
        if prev_semantics is None:
            return None
        operands = self._cmp_operands_from_semantics(prev_semantics)
        if operands is None:
            return None
        lhs, rhs = operands

        if kind in JCC_EQ_MNEMONICS_8616:
            return _finish(lhs == rhs)
        if kind in JCC_NE_MNEMONICS_8616:
            return _finish(lhs != rhs)
        if kind in JCC_SLE_MNEMONICS_8616:
            return _finish(lhs.signed <= rhs.signed)
        if kind in JCC_SGT_MNEMONICS_8616:
            return _finish(lhs.signed > rhs.signed)
        if kind in JCC_SLT_MNEMONICS_8616:
            return _finish(lhs.signed < rhs.signed)
        if kind in JCC_SGE_MNEMONICS_8616:
            return _finish(lhs.signed >= rhs.signed)
        if kind in JCC_ULT_MNEMONICS_8616:
            return _finish(lhs < rhs)
        if kind in JCC_UGE_MNEMONICS_8616:
            return _finish(lhs >= rhs)
        if kind in JCC_ULE_MNEMONICS_8616:
            return _finish(lhs <= rhs)
        if kind in JCC_UGT_MNEMONICS_8616:
            return _finish(lhs > rhs)
        return None

    def _record_cmp_condition_source(self, lhs, rhs, *, width_bits: int = 16) -> None:
        """Record CMP operands on the emulator for downstream JCC consumption."""
        block_addr = getattr(self.emu, "_inertia_current_block_addr", self.addr)
        source = ConditionSource(
            kind="cmp",
            lhs=lhs,
            rhs=rhs,
            width_bits=width_bits,
            addr=self.addr,
            block_addr=block_addr if isinstance(block_addr, int) else None,
        )
        self.emu._inertia_last_condition_source = source

    def _record_test_condition_source(self, value, *, width_bits: int = 16) -> None:
        """Record TEST/self-test operands for downstream JCC consumption."""
        block_addr = getattr(self.emu, "_inertia_current_block_addr", self.addr)
        source = ConditionSource(
            kind="test",
            lhs=value,
            rhs=None,
            width_bits=width_bits,
            addr=self.addr,
            block_addr=block_addr if isinstance(block_addr, int) else None,
        )
        self.emu._inertia_last_condition_source = source

    def _emit_simple_jcc(self, taken_cond, target):
        # Before emitting, record the typed ConditionIR if source available
        source = getattr(self.emu, "_inertia_last_condition_source", None)
        if not isinstance(source, ConditionSource) and getattr(self, "_past_instructions", None):
            prev_emu = getattr(self._past_instructions[-1], "emu", None)
            source = getattr(prev_emu, "_inertia_last_condition_source", None)
        if isinstance(source, ConditionSource):
            jcc_mnemonic = self.simple_semantics[0] if self.simple_semantics else ""
            block_addr = getattr(self.emu, "_inertia_current_block_addr", None)
            if not isinstance(block_addr, int):
                block_addr = source.block_addr
            if source.kind == "cmp":
                cond_ir = build_condition_from_cmp_8616(
                    source.lhs,
                    source.rhs,
                    jcc_mnemonic,
                    width_bits=source.width_bits,
                    src_insn=self.addr,
                    block_addr=block_addr if isinstance(block_addr, int) else None,
                )
            elif source.kind == "test":
                cond_ir = build_condition_from_test_8616(
                    source.lhs,
                    jcc_mnemonic,
                    width_bits=source.width_bits,
                    src_insn=self.addr,
                    block_addr=block_addr if isinstance(block_addr, int) else None,
                )
            else:
                cond_ir = ConditionFailure(
                    "unknown_condition_source_kind",
                    source=("jcc", jcc_mnemonic),
                    detail=f"kind={source.kind}",
                )
            self._record_typed_condition_8616(cond_ir)
        self.jump(taken_cond, target, JumpKind.Boring)

    # Module-level condition cache for transfer from lifter to codegen.
    # Keyed by block address → list[ConditionIR | ConditionFailure].
    _inertia_module_condition_cache: dict[int, list[ConditionIR | ConditionFailure]] = {}

    def _record_typed_condition_8616(self, cond: ConditionIR | ConditionFailure) -> None:
        """Record a typed condition on the emulator AND module cache for function-level transfer."""
        log = getattr(self.emu, "_inertia_typed_conditions", None)
        if not isinstance(log, list):
            log = []
            self.emu._inertia_typed_conditions = log
        log.append(cond)
        # Also write into module-level cache (keyed by block address)
        block_addr = getattr(self.emu, "_inertia_current_block_addr", self.addr)
        cache = Instruction_ANY._inertia_module_condition_cache
        if block_addr not in cache:
            cache[block_addr] = []
        cache[block_addr].append(cond)

    def _lift_simple(self):
        kind = self.simple_semantics[0]
        if kind == "nop":
            return
        if kind == "push_reg16":
            _, reg_name = self.simple_semantics
            value = self._get_reg16(reg_name)
            sp = self._get_reg16("sp") - self._const16(2)
            self.put(sp, "sp")
            if reg_name == "sp":
                value = sp + self._const16(2)
            self._stack_store16(sp, value)
            return
        if kind == "push_imm16":
            _, imm = self.simple_semantics
            sp = self._get_reg16("sp") - self._const16(2)
            self.put(sp, "sp")
            self._stack_store16(sp, self._const16(imm))
            return
        if kind == "push_mem16":
            _, mem_spec = self.simple_semantics
            sp = self._get_reg16("sp") - self._const16(2)
            self.put(sp, "sp")
            self._stack_store16(sp, self._load_mem16(mem_spec))
            return
        if kind == "pop_reg16":
            _, reg_name = self.simple_semantics
            sp = self._get_reg16("sp")
            value = self._stack_load16(sp)
            next_sp = sp + self._const16(2)
            if reg_name == "sp":
                self.put(value, "sp")
            else:
                self.put(value, reg_name)
                self.put(next_sp, "sp")
            return
        if kind == "inc_reg16":
            _, reg_name = self.simple_semantics
            self.put(self._get_reg16(reg_name) + self._const16(1), reg_name)
            return
        if kind == "call":
            _, target = self.simple_semantics
            ret_addr = self._const16(self.addr + self.cs.size)
            sp = self._get_reg16("sp") - self._const16(2)
            self.put(sp, "sp")
            self._stack_store16(sp, ret_addr)
            self.jump(None, self._const16(target), JumpKind.Call)
            return
        if kind == "enter":
            _, frame_size, nesting = self.simple_semantics
            nesting &= 0x1F
            old_bp = self._get_reg16("bp")
            sp = self._get_reg16("sp") - self._const16(2)
            self.put(sp, "sp")
            self._stack_store16(sp, old_bp)
            frame_temp = sp
            if nesting:
                bp_cursor = old_bp
                for _ in range(1, nesting):
                    bp_cursor = bp_cursor - self._const16(2)
                    sp = sp - self._const16(2)
                    self._stack_store16(sp, self._stack_load16(bp_cursor))
                sp = sp - self._const16(2)
                self._stack_store16(sp, frame_temp)
            self.put(frame_temp, "bp")
            self.put(sp - self._const16(frame_size), "sp")
            return
        if kind == "leave":
            bp = self._get_reg16("bp")
            self.put(bp, "sp")
            self.put(self._stack_load16(bp), "bp")
            self.put(bp + self._const16(2), "sp")
            return
        if kind == "mov_reg_imm16":
            _, reg_name, imm = self.simple_semantics
            self.put(self._const16(imm), reg_name)
            return
        if kind == "mov_reg_reg16":
            _, dst_reg, src_reg = self.simple_semantics
            self.put(self._get_reg16(src_reg), dst_reg)
            return
        if kind == "mov_reg_mem16":
            _, dst_reg, mem_spec = self.simple_semantics
            self.put(self._load_mem16(mem_spec), dst_reg)
            return
        if kind == "mov_mem_reg16":
            _, mem_spec, src_reg = self.simple_semantics
            self._store_mem16(mem_spec, self._get_reg16(src_reg))
            return
        if kind == "mov_mem_imm16":
            _, mem_spec, imm = self.simple_semantics
            self._store_mem16(mem_spec, self._const16(imm))
            return
        if kind == "lea_reg_bpdisp16":
            _, dst_reg, mem_spec = self.simple_semantics
            self.put(self._addr_from_bp_mem(mem_spec), dst_reg)
            return
        if kind == "add_reg_imm16":
            _, reg_name, imm = self.simple_semantics
            self._binop_reg_imm("add", reg_name, imm)
            return
        if kind.endswith("_reg_reg16"):
            op_name, dst_reg, src_reg = self.simple_semantics
            self._binop_reg_reg(op_name[:-10], dst_reg, src_reg)
            return
        if kind.endswith("_reg_mem16"):
            op_name, dst_reg, mem_spec = self.simple_semantics
            self._binop_reg_mem(op_name[:-10], dst_reg, mem_spec)
            return
        if kind.endswith("_reg_imm16"):
            op_name, dst_reg, imm = self.simple_semantics
            self._binop_reg_imm(op_name[:-10], dst_reg, imm)
            return
        if kind == "cmp_mem_reg16":
            _, mem_spec, src_reg = self.simple_semantics
            lhs_val = self._load_mem16(mem_spec)
            rhs_val = self._get_reg16(src_reg)
            self._record_cmp_condition_source(lhs_val, rhs_val)
            if not self._next_instruction_is_simple_jcc():
                self._update_cmp_flags(lhs_val, rhs_val)
            return
        if kind == "cmp_mem_imm16":
            _, mem_spec, imm = self.simple_semantics
            lhs_val = self._load_mem16(mem_spec)
            rhs_val = self._const16(imm)
            self._record_cmp_condition_source(lhs_val, rhs_val)
            if not self._next_instruction_is_simple_jcc():
                self._update_cmp_flags(lhs_val, rhs_val)
            return
        if kind == "cmp_abs_reg16":
            _, offset, src_reg = self.simple_semantics
            lhs_val = self._load_abs16(offset)
            rhs_val = self._get_reg16(src_reg)
            self._record_cmp_condition_source(lhs_val, rhs_val)
            if not self._next_instruction_is_simple_jcc():
                self._update_cmp_flags(lhs_val, rhs_val)
            return
        if kind == "cmp_abs_imm16":
            _, offset, imm = self.simple_semantics
            lhs_val = self._load_abs16(offset)
            rhs_val = self._const16(imm)
            self._record_cmp_condition_source(lhs_val, rhs_val)
            if not self._next_instruction_is_simple_jcc():
                self._update_cmp_flags(lhs_val, rhs_val)
            return
        if kind == "cmp_reg_abs8":
            _, dst_reg, offset = self.simple_semantics
            lhs_val = self.get(dst_reg, Type.int_8)
            rhs_val = self._load_abs8(offset)
            self._record_cmp_condition_source(lhs_val, rhs_val, width_bits=8)
            if not self._next_instruction_is_simple_jcc():
                self._update_cmp_flags8(lhs_val, rhs_val)
            return
        if kind == "cmp_abs_reg8":
            _, offset, src_reg = self.simple_semantics
            lhs_val = self._load_abs8(offset)
            rhs_val = self.get(src_reg, Type.int_8)
            self._record_cmp_condition_source(lhs_val, rhs_val, width_bits=8)
            if not self._next_instruction_is_simple_jcc():
                self._update_cmp_flags8(lhs_val, rhs_val)
            return
        if kind == "cmp_abs_imm8":
            _, offset, imm = self.simple_semantics
            lhs_val = self._load_abs8(offset)
            rhs_val = self.constant(imm, Type.int_8)
            self._record_cmp_condition_source(lhs_val, rhs_val, width_bits=8)
            if not self._next_instruction_is_simple_jcc():
                self._update_cmp_flags8(lhs_val, rhs_val)
            return
        if kind == "cmp_reg_abs16":
            _, lhs_reg, offset = self.simple_semantics
            lhs_val = self._get_reg16(lhs_reg)
            rhs_val = self._load_abs16(offset)
            self._record_cmp_condition_source(lhs_val, rhs_val)
            if not self._next_instruction_is_simple_jcc():
                self._update_cmp_flags(lhs_val, rhs_val)
            return
        if kind in (self._SIMPLE_JCC_8616 | {"jmp"}):
            _, abs_target = self.simple_semantics
            target = self._const16(abs_target)
            if kind == "jmp":
                self.jump(None, target, JumpKind.Boring)
                return
            cond = self._direct_jcc_condition(kind)
            if cond is None:
                zf = self._flag_is_set(6)
                cf = self._flag_is_set(0)
                sf = self._flag_is_set(7)
                of = self._flag_is_set(11)
                nof = self._flag_is_clear(11)
                nzf = self._flag_is_clear(6)
                ncf = self._flag_is_clear(0)
            else:
                self._emit_simple_jcc(cond, target)
                return
            if kind in JCC_EQ_MNEMONICS_8616:
                cond = zf
            elif kind in JCC_NE_MNEMONICS_8616:
                cond = nzf
            elif kind in JCC_SLE_MNEMONICS_8616:
                cond = zf | (sf != of)
            elif kind in JCC_SGT_MNEMONICS_8616:
                cond = nzf & (sf == of)
            elif kind in JCC_SLT_MNEMONICS_8616:
                cond = sf != of
            elif kind in JCC_SGE_MNEMONICS_8616:
                cond = sf == of
            elif kind in JCC_ULT_MNEMONICS_8616:
                cond = cf
            elif kind in JCC_UGE_MNEMONICS_8616:
                cond = ncf
            elif kind in JCC_ULE_MNEMONICS_8616:
                cond = cf | zf
            elif kind in JCC_UGT_MNEMONICS_8616:
                cond = ncf & nzf
            elif kind == "jo":
                cond = of
            elif kind == "jno":
                cond = nof
            elif kind == "js":
                cond = sf
            elif kind == "jns":
                cond = ~sf
            elif kind in {"jp", "jpe"}:
                cond = self._flag_is_set(2)
            elif kind in {"jnp", "jpo"}:
                cond = ~self._flag_is_set(2)
            else:
                raise NotImplementedError(kind)
            self._emit_simple_jcc(cond, target)
            return
        if kind == "ret":
            sp = self._get_reg16("sp")
            ret_addr = self._stack_load16(sp)
            self.put(sp + self._const16(2), "sp")
            self.jump(None, ret_addr, JumpKind.Ret)
            return
        if kind == "ret_imm16":
            _, imm = self.simple_semantics
            sp = self._get_reg16("sp")
            ret_addr = self._stack_load16(sp)
            self.put(sp + self._const16(2 + imm), "sp")
            self.jump(None, ret_addr, JumpKind.Ret)
            return
        raise NotImplementedError(f"unknown simple semantics: {kind}")

    def compute_result(self):
        try:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Lifting instruction at %04x: %s %s", self.addr, self.cs.mnemonic, self.cs.op_str)
            if self.is_mode32 ^ bool(self.chsz_op):
                self.instr32.exec()
            else:
                self.instr16.exec()

            if logger.isEnabledFor(logging.DEBUG):
                if hasattr(self.emu, 'irsb') and self.emu.irsb:
                    logger.debug("IRSB at %04x: %s", self.addr, self.emu.irsb)
                    irsb_obj = self.emu.irsb.irsb if hasattr(self.emu.irsb, 'irsb') else self.emu.irsb
                    if hasattr(irsb_obj, 'statements'):
                        for stmt in irsb_obj.statements:
                            logger.debug("Statement: %s (type: %s)", type(stmt).__name__, type(stmt))

                logger.debug("IRSB generated successfully for %04x", self.addr)

        except Exception as ex:
            if ex.__class__.__name__ == "ScanTimeout":
                logger.warning(
                    "Lifting timed out at %04x (bytes: %s)",
                    self.addr,
                    self.cs.bytes.hex(),
                )
                raise
            logger.error(f"Lifting failed at {self.addr:04x} (bytes: {self.cs.bytes.hex()}): {ex}")
            logger.exception("Exception during instruction execution")
            raise

    def disassemble(self):
        return self.start, self.cs.insn_name(), [str(i) for i in self.cs.operands]

    def ends_block(self):
        return self.cs.mnemonic in self._BLOCK_TERMINATORS

class Lifter86_16(GymratLifter):
    instrs = {Instruction_ANY}

    def decode(self):
        try:
            self.create_bitstrm()
            instructions = []
            addr = self.irsb.addr
            bytepos = self.bitstrm.bytepos

            while not _bitstream_is_empty(self.bitstrm):
                instr = self._decode_next_instruction(addr)
                if not instr:
                    break
                instructions.append(instr)
                addr += self.bitstrm.bytepos - bytepos
                bytepos = self.bitstrm.bytepos
                if getattr(instr, "ends_block", None) and instr.ends_block():
                    break
            return instructions
        except Exception as exc:
            self.errors = str(exc)
            logger.exception("Error decoding x86-16 block:")
            raise


register(Lifter86_16, "86_16")


def main():
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    tests = [
        b"\x90",  # NOP
        b"\xb8\x01\x02",  # MOV AX, 0x0201
        b"\xc3",  # RET
        b"\x01\xc0",  # ADD AX, AX
        b"\x89\xc1",  # MOV CX, AX
        b"\xeb\x01",  # JMP short +2 (example)
    ]
    print("Decoder test:")
    for num, test in enumerate(tests):
        print(num)
        lifter = Lifter86_16(Arch86_16(), 0)
        lifter.lift(data=test)

    print("Lifter test:")
    for test in tests:
        lifter = Lifter86_16(Arch86_16(), 0)
        lifter.lift(data=test)
        lifter.irsb.pp()

    print("Full tests:")
    fulltest = b"".join(tests)
    lifter = Lifter86_16(Arch86_16(), 0)
    lifter.lift(data=fulltest)
    lifter.irsb.pp()


if __name__ == "__main__":
    main()
