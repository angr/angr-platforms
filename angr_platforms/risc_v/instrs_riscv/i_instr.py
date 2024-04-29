# pylint: disable=W0613,R0201,W0221,W0223
from .instruction_patterns import I_Instruction
from pyvex.lifting.util import Type, ParseError, JumpKind


class Instruction_ADDI(I_Instruction):
    func3 = '000'
    opcode = '0010011'
    name = 'ADDI'

    def compute_result(self, src1, imm):
        return src1 + imm.signed


class Instruction_XORI(I_Instruction):
    func3 = '100'
    opcode = '0010011'
    name = 'XORI'

    def compute_result(self, src1, imm):
        return src1 ^ imm


class Instruction_ORI(I_Instruction):
    func3 = '110'
    opcode = '0010011'
    name = 'ORI'

    def compute_result(self, src1, imm):
        return src1 | imm


class Instruction_ANDI(I_Instruction):
    func3 = '111'
    opcode = '0010011'
    name = 'ANDI'

    def compute_result(self, src1, imm):
        return src1 & imm


class Instruction_SLLI(I_Instruction):
    func3 = '001'
    func7 = '0000000'
    opcode = '0010011'
    name = 'SLLI'

    def extra_constraints(self, data, bitstream):
        if (data['i'] != self.func7):
            raise ParseError("The func7 did not match")
        return data

    def compute_result(self, src1, _):
        return (src1 << self.get_shift_amount()) & self.constant(0xffffffff, Type.int_32)


class Instruction_SRLI(I_Instruction):
    func3 = '101'
    func7 = '0000000'
    opcode = '0010011'
    name = "SRLI"

    def extra_constraints(self, data, bitstream):
        if (data['i'] != self.func7):
            raise ParseError("The func7 did not match")
        return data

    def compute_result(self, src1, _):
        return (src1 >> self.get_shift_amount()) & self.constant(0xffffffff, Type.int_32)


# Once again issue with arithmetic right shifts, so for the moment still a TODO like SRA
class Instruction_SRAI(I_Instruction):
    func3 = '101'
    func7 = '0100000'
    opcode = '0010011'
    name = "SRAI"

    def extra_constraints(self, data, bitstream):
        if (data['i'] != self.func7):
            raise ParseError("The func7 did not match")
        return data

    def compute_result(self, src1, _):
        shftamnt = self.get_shift_amount()
        return src1.sar(shftamnt).cast_to(Type.int_32)


class Instruction_SLTI(I_Instruction):
    func3 = '010'
    opcode = '0010011'
    name = 'SLTI'


    # TODO: ISA manual mentions sign extension, check if properly implemented
    def compute_result(self, src1, imm):
        return (src1.signed < imm.signed).ite(1, 0)


class Instruction_SLTIU(I_Instruction):
    func3 = '011'
    opcode = '0010011'
    name = 'SLTIU'

    def compute_result(self, src1, imm):
        return (src1 < imm).ite(1, 0)

class Instruction_LB(I_Instruction):
    func3='000'
    opcode='0000011'
    name='LB'

    def compute_result(self, src, imm):
        addr = src + imm.signed
        value = self.load(addr, Type.int_8).widen_signed(Type.int_32)
        return value.signed

class Instruction_LH(I_Instruction):
    func3='001'
    opcode='0000011'
    name='LH'

    def compute_result(self, src, imm):
        addr = src + imm
        value = self.load(addr, Type.int_16).widen_signed(Type.int_32)
        return value.signed

class Instruction_LW(I_Instruction):
    func3='010'
    opcode='0000011'
    name='LW'

    def compute_result(self, src, imm):
        addr = src + imm.signed
        value = self.load(addr, Type.int_32)
        return value.signed

class Instruction_LBU(I_Instruction):
    func3='100'
    opcode = '0000011'
    name='LBU'

    def compute_result(self, src, imm):
        addr = src + imm.signed

        return self.load(addr, Type.int_8).widen_unsigned(Type.int_32)

class Instruction_LHU(I_Instruction):
    func3='101'
    opcode='0000011'
    name="LHU"

    def compute_result(self, src, imm):
        addr= src+imm.signed
        return self.load(addr, Type.int_16).widen_unsigned(Type.int_32)


class Instruction_JALR(I_Instruction):
    func3='000'
    opcode = '1100111'
    name='JALR'

    def compute_result(self, src, imm):
        return_addr = self.addr + self.constant(4, Type.int_32)
        addr = (src + imm.value) & self.constant(0xffff_fffe, Type.int_32)
        self.jump(None, addr, JumpKind.Call)
        return return_addr

#Control stataus instruction not sure how to model these so atm don't do anything
class Instruction_CSRRW(I_Instruction):
    opcode = '1110011'
    func3 = '001'
    name = 'CSRRW'

class Instruction_CSRRS(I_Instruction):
    opcode = '1110011'
    func3 = '010'
    name = 'CSRRS'

class Instruction_CSRRC(I_Instruction):
    opcode = '1110011'
    func3 = '011'
    name = 'CSRRC'

class Instruction_CSRRWI(I_Instruction):
    opcode = '1110011'
    func3 = '101'
    name = 'CSRRWI'

class Instruction_CSRRSI(I_Instruction):
    opcode = '1110011'
    func3 = '110'
    name = 'CSRRSI'

class Instruction_CSRRCI(I_Instruction):
    opcode = '1110011'
    func3 = '111'
    name = 'CSRRCI'

class Instruction_ECALL(I_Instruction):
    opcode = '1110011'
    func3 = '000'
    name = 'ecall'

    def compute_result(self, data, bitstream):
        return_addr = self.addr + self.constant(4, Type.int_32)
        sp_addr = self.get('sp', Type.int_32)
        self.put(self.constant(0xfffffffc, Type.int_32), 'sp')
        self.jump(None, self.constant(0x80000180, Type.int_32), JumpKind.Syscall)
        self.put(sp_addr, 'sp')
        return return_addr
