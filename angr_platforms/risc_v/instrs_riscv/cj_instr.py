# pylint: disable=W0221
from .instruction_patterns import CJ_Instruction
from pyvex.lifting.util import Type

class Instruction_CJ(CJ_Instruction):
    opcode = '01'
    func3 = '101'
    name = "CJ"

    def compute_result(self, imm):
        self.jump(None, self.addr + imm)

class Instruction_CJAL(CJ_Instruction):
    opcode = '01'
    func3 = '001'
    name = "CJAL"

    def compute_result(self, imm):
        self.put(self.addr + self.constant(2, Type.int_32), 1)  # Not sure if this is right
        self.jump(None, self.addr+imm)
