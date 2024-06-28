#pylint: disable=wildcard-import, unused-wildcard-import, unused-argument, arguments-differ
import logging

from pyvex.lifting import register
from pyvex.lifting.util import Instruction, ParseError, GymratLifter

from .parse import CHSZ_AD, CHSZ_OP

from .arch_86_16 import Arch86_16
from .emulator import Emulator
from .instr16 import Instr16
from .instr32 import Instr32
from .instruction import InstrData

logger = logging.getLogger(__name__)


class Instruction_ANY(Instruction):
    # Convert everything that's not an instruction into a No-op to meet the BF spec
    bin_format = "xxxxxxxx" # We don't care, match it all
    name = "nop"

    def __init__(self, *args, **kwargs):
        self.emu = Emulator()
        self.instr = InstrData()

        self.instr16 = Instr16(self.emu, self.instr)
        self.instr32 = Instr32(self.emu, self.instr)
        self.emu.set_lifter_instruction(self)
        super().__init__(*args, **kwargs)

    def parse(self, bitstrm):
        self.start = bitstrm.bytepos
        instr = list(self.arch.capstone.disasm(bytes(bitstrm[self.start * 8: self.start * 8 + 15 * 8]), 0, 1))
        if not instr:
            raise ParseError("Couldn't disassemble instruction")
        self.cs = instr[0]
        logger.debug("cs dis: %s %s", self.cs.mnemonic, self.cs.op_str)
        self.name = self.cs.insn_name()

        self.emu.set_bitstream(bitstrm)

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

    def compute_result(self):
        try:
            if self.is_mode32 ^ bool(self.chsz_op):
                self.instr32.exec()
            else:
                self.instr16.exec()
        except Exception as ex:
            logger.error("Exception during instruction execution: %s", ex)
            raise ex from Exception

    def disassemble(self):
        return self.start, self.cs.insn_name(), [str(i) for i in self.cs.operands]

class Lifter86_16(GymratLifter):

    instrs = {Instruction_ANY}


register(Lifter86_16, "86_16")


def main():
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    tests = [
        b"\x90",  # NOP
        b"\xb8\x01\x02",  # MOVW
        b"\xc3",  # RET
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
