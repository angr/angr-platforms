# pylint: disable=W0221
from .instruction_patterns import J_Instruction
from pyvex.lifting.util import Type

class Instruction_JAL(J_Instruction):
    opcode = '1101111'
    name='JAL'

    def compute_result(self, imm):
        return_addr = self.addr + self.constant(4, Type.int_32)
        addr = self.addr+imm
        self.jump(None, self.constant(addr, Type.int_32))
        return return_addr
