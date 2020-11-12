# pylint: disable=W0221
from .instruction_patterns import B_Instruction

class Instruction_BEQ(B_Instruction):
    func3='000'
    opcode='1100011'
    name='BEQ'

    def compute_result(self, src1, src2, imm):
        addr = self.addr + imm
        self.jump(src1 == src2, addr)

class Instruction_BNE(B_Instruction):
    func3='001'
    opcode = '1100011'
    name='BNE'

    def compute_result(self, src1, src2, imm):
        addr = self.addr + imm
        self.jump(src1 != src2, addr)

class Instruction_BLT(B_Instruction):
    func3='100'
    opcode='1100011'
    name='BLT'

    def compute_result(self, src1, src2, imm):
        addr = self.addr + imm
        self.jump(src1.signed < src2.signed, addr)

class Instruction_BGE(B_Instruction):
    func3='101'
    opcode = '1100011'
    name='BGE'

    def compute_result(self, src1, src2, imm):
        addr = self.addr + imm
        self.jump(src1.signed >= src2.signed, addr)

class Instruction_BLTU(B_Instruction):
    func3='110'
    opcode='1100011'
    name='BLTU'

    def compute_result(self, src1, src2, imm):
        src1.is_signed = False
        src2.is_signed = False
        addr = self.addr + imm
        self.jump(src1 < src2, addr)

class Instruction_BGEU(B_Instruction):
    func3='111'
    opcode='1100011'
    name='BGEU'

    def compute_result(self, src1, src2, imm):
        src1.is_signed = False
        src2.is_signed = False
        addr = self.addr + imm
        self.jump(src1 >= src2, addr)
