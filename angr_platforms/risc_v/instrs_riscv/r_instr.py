# pylint: disable=W0613,R0201,W0221
from pyvex.lifting.util import Type
from .instruction_patterns import R_Instruction

class Instruction_ADD(R_Instruction):
    func3 = '000'
    func7 = '0000000'
    opcode = '0110011'
    name = 'ADD'

    def compute_result(self, src1, src2):
        return src1 + src2


class Instruction_SUB(R_Instruction):
    func3 = '000'
    func7 = '0100000'
    opcode = '0110011'
    name = 'SUB'

    def compute_result(self, src1, src2):
        return src1 - src2


class Instruction_XOR(R_Instruction):
    func3 = '100'
    func7 = '0000000'
    opcode = '0110011'
    name= 'XOR'

    def compute_result(self, src1, src2):
        return src1 ^ src2


class Instruction_OR(R_Instruction):
    func3 = '110'
    func7 = '0000000'
    opcode = '0110011'
    name = 'OR'

    def compute_result(self, src1, src2):
        return src1 | src2


class Instruction_AND(R_Instruction):
    func3 = '111'
    func7 = '0000000'
    opcode = '0110011'
    name = 'AND'

    def compute_result(self, src1, src2):
        return src1 & src2


class Instruction_SLL(R_Instruction):
    func3 = '001'
    func7 = '0000000'
    opcode = '0110011'
    name = 'SLL'

    def compute_result(self, src1, src2):
        shftamnt = src2.narrow_low(Type.int_5).cast_to(Type.int_8)
        return (src1 << shftamnt) & self.constant(0xffffffff, Type.int_32)


class Instruction_SRL(R_Instruction):
    func3 = '101'
    func7 = '0000000'
    opcode = '0110011'
    name = 'SRL'

    def compute_result(self, src1, src2):
        shftamnt = src2.narrow_low(Type.int_5).cast_to(Type.int_8)
        return (src1 >> shftamnt) & self.constant(0xffffffff, Type.int_32)

# Arithmetic shift is not easily mapped, so leaving this as an TODO


class Instruction_SRA(R_Instruction):
    func3 = '101'
    func7 = '0100000'
    opcode = '0110011'
    name = 'SRA'

    def compute_result(self, src1, src2):
        shftamnt = src2.narrow_low(Type.int_5).cast_to(Type.int_8)
        return src1.sar(shftamnt).cast_to(Type.int_32)


class Instruction_SLT(R_Instruction):
    func3 = '010'
    func7 = '0000000'
    opcode = '0110011'
    name='SLT'

    def compute_result(self, src1, src2):
        return (src1.signed < src2.signed).ite(1, 0)


class Instruction_SLTU(R_Instruction):
    func3 = '011'
    func7 = '0000000'
    opcode = '0110011'
    name = 'SLTU'

    def compute_result(self, src1, src2):
        return (src1 < src2).ite(1, 0)


class Instruction_MUL(R_Instruction):
    func3='000'
    func7='0000001'
    opcode='0110011'
    name='MUL'

    def compute_result(self, src1, src2):
        return (src1*src2) & self.constant(0xFFFF_FFFF, Type.int_32)

class Instruction_MULH(R_Instruction):
    func3='001'
    func7='0000001'
    opcode='0110011'
    name='MULH'

    def compute_result(self, src1, src2):
        return (src1*src2) >> self.constant(32, Type.int_8)

class Instruction_MULSU(R_Instruction):
    func3='010'
    func7='0000001'
    opcode='0110011'
    name='MULSU'

    def compute_result(self, src1, src2):
        src1 = src1.signed
        src2.is_signed = False
        return (src1*src2) & self.constant(0xFFFF_FFFF, Type.int_32)

class Instruction_MULHU(R_Instruction):
    func3='011'
    func7='0000001'
    opcode='0110011'
    name='MULHU'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src2.is_signed = False
        return (src1*src2) >> self.constant(32, Type.int_8)

class Instruction_DIV(R_Instruction):
    func3='100'
    func7='0000001'
    opcode='0110011'
    name='DIV'

    def compute_result(self, src1, src2):
        src1 = src1.signed
        src2 = src2.signed
        return src1//src2

class Instruction_DIVU(R_Instruction):
    func3='101'
    func7='0000001'
    opcode='0110011'
    name='DIVU'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src2.is_signed = False
        return src1//src2

class Instruction_REM(R_Instruction):
    func3='110'
    func7='0000001'
    opcode='0110011'
    name='REM'

    def compute_result(self, src1, src2):
        return src1.signed % src2.signed

class Instruction_REMU(R_Instruction):
    func3='111'
    func7='0000001'
    opcode='0110011'
    name ='REMU'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src2.is_signed = False
        return src1 % src2
