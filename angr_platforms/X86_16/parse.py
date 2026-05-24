import logging
import struct
from typing import TYPE_CHECKING

from pyvex.lifting.util import ParseError
from pyvex.lifting.util.vex_helper import Type

if TYPE_CHECKING:
    from .emulator import Emulator
from .addressing_helpers import decode_width_case_for_profile, decode_width_profile
from .instruction import *

CHSZ_NONE: int = 0
CHSZ_OP: int = 1
CHSZ_AD: int = 2

logger = logging.getLogger(__name__)

class ParseInstr(X86Instruction):
    def __init__(self, emu: Emulator, instr: InstrData, mode32: bool):
        super().__init__(emu, instr, mode32)
        self.emu: Emulator = emu
        self.chk = [InstrFlags()] * MAX_OPCODE
        self.chsz = CHSZ_NONE
        self.chsz_ad = False

    def parse_prefix(self) -> int:
        chsz = 0
        prefix_len = 0

        while True:
            #code = self.emu.get_code8_(bitstream)
            code = self.emu.bitstream.peek("uint:8")
            match code:
                case 0x26:
                    self.instr.pre_segment = sgreg_t.ES
                case 0x2E:
                    self.instr.pre_segment = sgreg_t.CS
                case 0x36:
                    self.instr.pre_segment = sgreg_t.SS
                case 0x3E:
                    self.instr.pre_segment = sgreg_t.DS
                case 0x64:
                    self.instr.pre_segment = sgreg_t.FS
                case 0x65:
                    self.instr.pre_segment = sgreg_t.GS
                case 0x66:
                    chsz |= CHSZ_OP
                case 0x67:
                    chsz |= CHSZ_AD
                case 0xF2:
                    self.instr.pre_repeat = REPNZ
                case 0xF3:
                    self.instr.pre_repeat = REPZ
                case 0xF0:
                    # LOCK is a valid real-mode prefix. For our current single-core
                    # verifier path it does not change architectural results, so we
                    # keep it as a consumed prefix and let the following opcode lift.
                    pass
                case _:
                    self.chsz = chsz
                    self.chsz_ad = bool(chsz & CHSZ_AD)
                    self.instr.prefix_len = prefix_len
                    return chsz

            self.emu.bitstream.read("uint:8")
            self.instr.prefix = code
            prefix_len += 1
            #self.emu.update_eip(1)

    def parse(self) -> None:
        start = self.emu.bitstream.bytepos
        widths = decode_width_profile(
            self.emu.is_mode32(),
            bool(self.chsz & CHSZ_OP),
            bool(self.chsz & CHSZ_AD),
        )
        self.instr.operand_bits = widths.operand_bits
        self.instr.address_bits = widths.address_bits
        self.instr.width_case = decode_width_case_for_profile(widths.operand_bits, widths.address_bits).name
        self.instr.displacement_bits = 0
        self.parse_opcode()

        opcode = self.instr.opcode
        if opcode >> 8 == 0x0F:
            opcode = (opcode & 0xFF) | 0x0100

        if opcode >= len(self.chk) or isinstance(self.chk[opcode], InstrFlags):
            logger.error(
                "Unknown opcode at %08x: %02x, next bytes: %08x",
                self.emu.bitstream.bytepos,
                opcode,
                self.emu.bitstream.peek("uint:32"),
            )
            raise ParseError(f"Unknown opcode {self.emu.bitstream.bytepos:08x}: {opcode:02x}{self.emu.bitstream.peek('uint:32'):08x}")
            #sys.exit(1)
        if self.chk[opcode] & CHK_MODRM:
            self.parse_modrm_sib_disp()

        if self.chk[opcode] & CHK_IMM32:
            self.instr.imm32 = self.emu.get_code32(0)
            #self.emu.update_eip(4)
        if self.chk[opcode] & CHK_IMM16:
            self.instr.imm16 = self.emu.get_code16(0)
            #self.emu.update_eip(2)
        if self.chk[opcode] & CHK_IMM8:
            self.instr.imm8 = struct.unpack("b", struct.pack("B", self.emu.get_code8(0)))[0]
            #self.emu.update_eip(1)
        if self.chk[opcode] & CHK_PTR16:
            self.instr.ptr16 = self.emu.get_code16(0)
            #self.emu.update_eip(2)

        if self.chk[opcode] & CHK_MOFFS:
            self.parse_moffs()

        if opcode == 0xF6 and self.instr.modrm.reg in (0, 1):  # test
            self.instr.imm8 = self.emu.get_code8(0)
        if opcode == 0xF7 and self.instr.modrm.reg in (0, 1):  # test
            self.instr.imm16 = self.emu.get_code16(0)

        self.instr.size = self.instr.prefix_len + (self.emu.bitstream.bytepos - start)
        self.instr.repeat_class = self._repeat_class_name()
        self.instr.control_flow_class = self._classify_control_flow(opcode)

    def _repeat_class_name(self) -> str:
        if self.instr.pre_repeat == REPZ:
            return "repz"
        if self.instr.pre_repeat == REPNZ:
            return "repnz"
        return "none"

    def _classify_control_flow(self, opcode: int) -> str:
        if opcode in {0xCC, 0xCD, 0xCE}:
            return "interrupt"
        if opcode == 0xCF:
            return "iret"
        if opcode in {0xC2, 0xC3}:
            return "near_ret"
        if opcode in {0xCA, 0xCB}:
            return "far_ret"
        if opcode == 0x9A or (opcode == 0xFF and self.instr.modrm.reg == 3):
            return "far_call"
        if opcode == 0xE8 or (opcode == 0xFF and self.instr.modrm.reg == 2):
            return "near_call"
        if opcode == 0xEA or (opcode == 0xFF and self.instr.modrm.reg == 5):
            return "far_jump"
        if opcode in {0xE9, 0xEB} or (opcode == 0xFF and self.instr.modrm.reg == 4):
            return "near_jump"
        if opcode in {
            0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
            0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
            0x0F80, 0x0F81, 0x0F82, 0x0F83, 0x0F84, 0x0F85, 0x0F86, 0x0F87,
            0x0F88, 0x0F89, 0x0F8A, 0x0F8B, 0x0F8C, 0x0F8D, 0x0F8E, 0x0F8F,
            0xE0, 0xE1, 0xE2, 0xE3,
        }:
            return "conditional_jump"
        return "none"


    def parse_opcode(self) -> None:
        self.instr.opcode = self.emu.get_code8(0)
        #self.emu.update_eip(1)

        # two byte opcode
        if self.instr.opcode == 0x0F:
            self.instr.opcode = (self.instr.opcode << 8) + self.emu.get_code8(0)
            #self.emu.update_eip(1)
        logger.debug(f"opcode: {self.instr.opcode:0x}")

    def parse_modrm_sib_disp(self) -> None:
        modrm = self.emu.get_code8(0)
        self.instr.modrm.mod = modrm >> 6
        self.instr.modrm.reg = (modrm >> 3) & 0b111
        self.instr.modrm.rm = modrm & 0b111
        #self.emu.update_eip(1)

        if self.instr.address_bits == 32:
            self.parse_modrm32()
        else:
            self.parse_modrm16()

    def parse_modrm32(self) -> None:
        if self.instr.modrm.mod != 3 and self.instr.modrm.rm == 4:
            sib = self.emu.get_code8(0)
            self.instr.sib.scale = sib >> 6
            self.instr.sib.index = (sib >> 3) & 0b111
            self.instr.sib.base = sib & 0b111
            #self.emu.update_eip(1)

        if (
            self.instr.modrm.mod == 2
            or (self.instr.modrm.mod == 0 and self.instr.modrm.rm == 5)
            or (self.instr.modrm.mod == 0 and self.instr.sib.base == 5)
        ):
            self.instr.disp32 = self.emu.get_code32(0)
            self.instr.displacement_bits = 32
            #self.emu.update_eip(4)
        elif self.instr.modrm.mod == 1:
            self.instr.disp8 = struct.unpack("b", struct.pack("B", self.emu.get_code8(0)))[0]
            self.instr.displacement_bits = 8
            #self.emu.update_eip(1)

    def parse_modrm16(self) -> None:
        if (self.instr.modrm.mod == 0 and self.instr.modrm.rm == 6) or self.instr.modrm.mod == 2:
            self.instr.disp16 = self.emu.constant(self.emu.get_code16(0), Type.int_16)
            self.instr.displacement_bits = 16
            #self.emu.update_eip(2)
        elif self.instr.modrm.mod == 1:
            self.instr.disp8 = self.emu.constant(struct.unpack("b", struct.pack("B", self.emu.get_code8(0)))[0], Type.int_8)
            self.instr.displacement_bits = 8
            #self.emu.update_eip(1)

    def parse_moffs(self) -> None:
        if self.instr.address_bits == 32:
            self.instr.moffs = self.emu.get_code32(0)
            self.instr.displacement_bits = 32
            #self.emu.update_eip(4)
        else:
            self.instr.moffs = self.emu.get_code16(0)
            self.instr.displacement_bits = 16
            #self.emu.update_eip(2)
