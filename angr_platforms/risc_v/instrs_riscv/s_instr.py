# pylint: disable=R0201,W0221
from .instruction_patterns import S_Instruction
from pyvex.lifting.util import Type

class Instruction_SB(S_Instruction):
    func3='000'
    opcode= '0100011'
    name="SB"

    def compute_result(self, val):
        return val.cast_to(Type.int_8)

class Instruction_SH(S_Instruction):
    func3='001'
    opcode= '0100011'
    name='SH'

    def compute_result(self, val):
        return val.cast_to(Type.int_16)

class Instruction_SW(S_Instruction):
    func3='010'
    opcode= '0100011'
    name='SW'

    def compute_result(self, val):
        return val
