import abc
from pyvex.lifting.util import Instruction, JumpKind, ParseError, Type
import bitstring
from bitstring import Bits, BitArray
import logging
l = logging.getLogger(__name__)

REGISTER_TYPE = Type.int_32
BYTE_TYPE = Type.int_8
INDEX_TYPE = Type.int_16


# Lots of things are going to be interpreted as signed immediates. Here's a quickie to load them
def bits_to_signed_int(s):
    return Bits(bin=s).int

class RISCV_Instruction(Instruction):

    def get(self, reg, ty):
        if (reg==0):
            return self.constant(0, ty)
        else:
            return super().get(reg, ty)

class R_Instruction(RISCV_Instruction):
    '''
    bitformat:
    o = opcode
    d = destination register
    s = source register
    S = source 2 register
    f = func3 
    F = func7
    '''
    opcode = NotImplemented  # binary string of length 7 consisting of the opcode
    func7 = NotImplemented  # binary string of length 7 consisting of the func7 code
    func3 = NotImplemented  # binary string of length 3 consisting of the func3 code

    bin_format = NotImplemented
    def __init__(self, bitstrm, arch, addr):
        self.bin_format = "{0}SSSSSsssss{1}ddddd{2}".format(self.func7, self.func3, self.opcode)
        super().__init__( bitstrm, arch, addr)


    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def get_dst_reg(self):
        return int(self.data['d'], 2)

    def get_src1(self):
        return self.get(int(self.data['s'], 2), Type.int_32)

    def get_src2(self):
        return self.get(int(self.data['S'], 2), Type.int_32)

    def fetch_operands(self):
        return self.get_src1(), self.get_src2()

    def commit_result(self, result):
        self.put(result, self.get_dst_reg())


class I_Instruction(RISCV_Instruction):
    '''
    bitformat:
    o = opcode
    d = destination register
    s = source register
    f = func3 code
    I = first 5 bits of the immediate
    i = last 7 bits of the immediate

    A split was made between i and I since the shift instruction use on the first 5 bits of the
    immediate to determine what the shift amount. The other 7 are used as a func7 value.
    '''
    opcode = NotImplemented  # binary string of length 7 consisting of the opcode
    func3 = NotImplemented  # binary string of length 3 consisting of the func3 code

    bin_format = NotImplemented
    def __init__(self, bitstrm, arch, addr):
        self.bin_format = "iiiiiiiIIIIIsssss{0}ddddd{1}".format(self.func3, self.opcode)
        super().__init__( bitstrm, arch, addr)

    '''In the shift instruction extend this function to also check the last 7 bits of the immediate'''

    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def get_dst_reg(self):
        return int(self.data['d'], 2)

    def get_src(self):
        return self.get(int(self.data['s'], 2), Type.int_32)

    def get_imm(self):
        data = BitArray(bin="{0}{1}".format(self.data['i'],self.data['I'])).int
        return self.constant(data, Type.int_32)

    def get_shift_amount(self):
        num = BitArray(bin = self.data['I']).int;
        return self.constant(num, Type.int_8)

    def get_optional_func7(self):
        return self.data['i']

    def fetch_operands(self):
        return self.get_src(), self.get_imm()

    def commit_result(self, result):
        self.put(result, self.get_dst_reg())


class S_Instruction(RISCV_Instruction):
    '''
    bitformat:
    o = opcode
    i = first 5 bits of the immediate
    f = func3 code
    s = address where to store the value
    S = value to be stored
    I = last 7 bits of the immediate
    '''
    opcode = NotImplemented  # binary string of length 7 consisting of the opcode
    func3 = NotImplemented  # binary string of length 3 consisting of the func3 code

    bin_format = NotImplemented
    def __init__(self, bitstrm, arch, addr):
        self.bin_format = "IIIIIIISSSSSsssss{0}iiiii{1}".format(self.func3, self.opcode)
        super().__init__( bitstrm, arch, addr)

    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    '''This is the address + offset'''

    def get_addr(self):
        addr = self.get(int(self.data['s'], 2), Type.int_32)
        
        offset = BitArray(bin = '{0}{1}'.format(self.data['I'], self.data['i'])).int
        return addr+offset

    '''Value is returned as int32 caller must cast it to store half words or bytes'''

    def get_val(self):
        return self.get(int(self.data['S'], 2), Type.int_32)

    def fetch_operands(self):
        return self.get_val(),

    def commit_result(self, result):
        self.store(result, self.get_addr())


class B_Instruction(RISCV_Instruction):
    '''
    bitformat:
    o = opcode
    i = first 5 bits of the immediate
    f = func3 code
    s = source register
    S = source 2 register
    I = last 7 bits of the immediate
    '''
    opcode = NotImplemented  # binary string of length 7 consisting of the opcode
    func3 = NotImplemented  # binary string of length 3 consisting of the func3 code


    bin_format = NotImplemented
    def __init__(self, bitstrm, arch, addr):
        self.bin_format = "IIIIIIISSSSSsssss{0}iiiii{1}".format(self.func3, self.opcode)
        super().__init__( bitstrm, arch, addr)


    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def get_src1(self):
        return self.get(int(self.data['s'], 2), Type.int_32)

    def get_src2(self):
        return self.get(int(self.data['S'], 2), Type.int_32)

    ''' The offset for B instructions is as follows inst[31]inst[7]inst[30:25]inst[11:8] just had to be carefull with the endianness'''

    def get_offset(self):
        begin = self.data['i'][0:4]
        middle = self.data['I'][1:7]
        x = self.data['i'][4]
        sign = self.data['I'][0]
        offset = "{3}{2}{1}{0}0".format(begin, middle, x, sign)
        b = BitArray(bin=offset)
        val = self.constant(b.int, Type.int_32)
        return val.signed

    def fetch_operands(self):
        return self.get_src1(), self.get_src2(), self.get_offset()


class U_Instruction(RISCV_Instruction):
    '''
    bitformat:
    o = opcode
    d = destination register
    i = immediate
    '''

    opcode = NotImplemented  # binary string of length 7 consisting of the opcode


    bin_format = NotImplemented
    def __init__(self, bitstrm, arch, addr):
        self.bin_format = "iiiiiiiiiiiiiiiiiiiiddddd{0}".format(self.opcode)
        super().__init__( bitstrm, arch, addr)


    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def get_dst(self):
        return int(self.data['d'], 2)

    def get_imm(self):
        val = BitArray(bin=self.data['i']).int
        return self.constant(val, Type.int_32)

    def fetch_operands(self):
        return self.get_dst(), self.get_imm()

    def commit_result(self, result):
        self.put(result, self.get_dst())

class J_Instruction(RISCV_Instruction):
    '''
    bitformat:
    o = opcode
    d = destination register
    i = immediate
    '''

    opcode = NotImplemented  # binary string of length 7 consisting of the opcode


    bin_format = NotImplemented
    def __init__(self, bitstrm, arch, addr):
        self.bin_format = "iiiiiiiiiiiiiiiiiiiiddddd{0}".format(self.opcode)
        super().__init__( bitstrm, arch, addr)


    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def get_dst(self):
        return int(self.data['d'], 2)

    ''''
    Some weird way to parse the immediate according to risc-v isa
    '''

    def get_imm(self):
        i = self.data['i']
        imm = "{0}{1}{2}{3}0".format(i[0],i[12:20],i[11],i[1:11])

        return  BitArray(bin=imm).int

    def fetch_operands(self):
        return self.get_imm(),

    def commit_result(self, result):
        self.put(result, self.get_dst())

class CR_Instruction(RISCV_Instruction):
    '''
    bin_format:
    o = opcode of 2 bits
    s = src2 of 5 bits
    d = dst or src1 of 5 bits
    f = func4 of 4 bits
    '''
    opcode = NotImplemented
    func4 = NotImplemented

    bin_format = NotImplemented
    def __init__(self, bitstrm, arch, addr):
        self.bin_format = "{0}dddddsssss{1}".format(self.func4, self.opcode)
        super().__init__( bitstrm, arch, addr)


    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def get_src1(self):
        return self.get(int(self.data['s'],2), Type.int_32)
    
    def get_src2(self):
        return self.get(int(self.data['d'], 2), Type.int_32)

    def get_dst_addr(self):
        return int(self.data['d'],2)

    def fetch_operands(self):
        return self.get_src1(), self.get_src2()

class CI_Instruction(RISCV_Instruction):
    '''
    bin_format:
    o = opcode 2 bits
    i = immediate of 5
    I = imm2 1 bit
    s = src1/rd of 5 bits
    f = func3 of 3 bits
    '''

    opcode = NotImplemented
    func3 = NotImplemented


    bin_format = NotImplemented
    def __init__(self, bitstrm, arch, addr):
        self.bin_format = "{0}Isssssiiiii{1}".format(self.func3, self.opcode)
        super().__init__( bitstrm, arch, addr)


    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def get_dst(self):
        return int(self.data['s'],2)

    def fetch_operands(self):
        return self.get(self.get_dst(), Type.int_32),

class Instruction_CSWSP(RISCV_Instruction):
    '''
    bin_format:
    o = opcode 2 bits
    s = src1 5 bits
    i = imm 6 bits
    f = func3 3 bits
    '''

    name = 'CSWSP'

    bin_format = '110iiiiiisssss10'

    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def get_imm(self):
        val = "{0}{1}00".format(self.data['i'][3:6],self.data['i'][0:3])
        res = self.constant(BitArray(bin=val).uint, Type.int_32)
        return res.signed

    def commit_result(self, result):
        self.store(result, self.get_imm() + self.get(2, Type.int_32))

class CIW_Instruction(RISCV_Instruction):
    '''
    bin_format:
    o = opcode 2 bits
    d = dst 3 bits
    i = imm 8 bits
    f = func3 3 bits
    '''
    opcode = NotImplemented
    func3 = NotImplemented


    bin_format = NotImplemented
    def __init__(self, bitstrm, arch, addr):
        self.bin_format = "{0}iiiiiiiiddd{1}".format(self.func3, self.opcode)
        super().__init__( bitstrm, arch, addr)


    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)

        return True
    
    def fetch_operands(self):
        return int(self.data['d'],2)+8,

class CL_Instruction(RISCV_Instruction):
    '''
    bin_format:
    o = opcode 2 bits
    d = dst 3 bits
    i = imm 2 bits
    I = imm 3 bits
    s = src 3 bits
    f = func3 3 bits
    '''
    opcode = NotImplemented
    func3 = NotImplemented

    bin_format = NotImplemented
    def __init__(self, bitstrm, arch, addr):
        self.bin_format = "{0}IIIsssiiddd{1}".format(self.func3, self.opcode)
        super().__init__( bitstrm, arch, addr)

    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def get_src1(self):
        return self.get(int(self.data['s'],2)+8, Type.int_32)

    def get_dst_addr(self):
        return int(self.data['d'], 2)    


    def fetch_operands(self):
        return self.get_src1(), self.get_dst_addr()

class CS_Instruction(RISCV_Instruction):
    '''
    bin_format:
    o = opcode 2 bits
    S = src2 3 bits
    i = imm 2 bits
    I = imm2 3 bits
    s = src1 3 bits
    f = func3
    '''

    opcode = NotImplemented
    func3 = NotImplemented

    bin_format = NotImplemented
    def __init__(self, bitstrm, arch, addr):
        self.bin_format = "{0}IIIsssiiSSS{1}".format(self.func3, self.opcode)
        super().__init__( bitstrm, arch, addr)


    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def fetch_operands(self):
        src1 = self.get(int(self.data['s'],2)+8, Type.int_32)
        src2 = self.get(int(self.data['S'],2)+8, Type.int_32)
        return src1, src2

    def commit_result(self, res):
        self.put(res, self.get_dst())

    def get_dst(self):
        return int(self.data['s'],2)+8


class CB_Instruction(RISCV_Instruction):
    '''
    bin_format:
    o = opcode 2 bits
    O = offset 5 bits
    I = offset2 3 bits
    s = src1 3 bits
    f = func3 3 bits
    '''
    opcode = NotImplemented
    func3 = NotImplemented

    bin_format = 'fffIIIsssOOOOOoo'

    bin_format = NotImplemented
    def __init__(self, bitstrm, arch, addr):
        self.bin_format = "{0}IIIsssOOOOO{1}".format(self.func3, self.opcode)
        super().__init__( bitstrm, arch, addr)


    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True
    
    def fetch_operands(self):
        return self.get(int(self.data['s'],2)+8, Type.int_32),
        
class CJ_Instruction(RISCV_Instruction):
    '''
    bin_format:
    o = opcode 2 bits
    j = jump target 11 bits
    f = func3 3 bits
    '''
    opcode = NotImplemented
    func3 = NotImplemented

    bin_format = 'fffjjjjjjjjjjjoo'

    bin_format = NotImplemented
    def __init__(self, bitstrm, arch, addr):
        self.bin_format = "{0}jjjjjjjjjjj{1}".format(self.func3, self.opcode)
        super().__init__( bitstrm, arch, addr)


    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True
    
    def fetch_operands(self):
        i = self.data['j']
        parsed = "{0}{1}{2}{3}{4}{5}{6}{7}0".format(i[0],i[4],i[2:4], i[6], i[5], i[10], i[1], i[7:10])
        val = self.constant(BitArray(bin=parsed).int, Type.int_32)
        return val.signed,


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
        shftamnt = self.get(int(self.data['S'],2), Type.int_8)
        return (src1 << shftamnt) & self.constant(0xffffffff, Type.int_32)


class Instruction_SRL(R_Instruction):
    func3 = '101'
    func7 = '0000000'
    opcode = '0110011'
    name = 'SRL'

    def compute_result(self, src1, src2):
        shftamnt = self.get(int(self.data['S'],2), Type.int_8)
        return (src1 >> shftamnt) & self.constant(0xffffffff, Type.int_32)

# Arithmetic shift is not easily mapped, so leaving this as an TODO


class Instruction_SRA(R_Instruction):
    func3 = '101'
    func7 = '0100000'
    opcode = '0110011'
    name = 'SRA'

    def compute_result(self, src1, src2):
        shftamnt = self.get(int(self.data['S'],2), Type.int_8)
        return (src1 >> shftamnt) & self.constant(0xffffffff, Type.int_32)


class Instruction_SLT(R_Instruction):
    func3 = '010'
    func7 = '0000000'
    opcode = '0110011'
    name='SLT'

    def compute_result(self, src1, src2):
        src1.is_signed = True
        src2.is_signed = True
        val = 1 if src1 < src2 else 0
        return self.constant(val, Type.int_32)


class Instruction_SLTU(R_Instruction):
    func3 = '011'
    func7 = '0000000'
    opcode = '0110011'
    name = 'SLTU'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src1.is_signed = False
        val = 1 if src1 < src2 else 0
        return self.constant(val, Type.int_32)


class Instruction_ADDI(I_Instruction):
    func3 = '000'
    opcode = '0010011'
    name='ADDI'

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
    name='SLLI'

    def extra_constraints(self, data, bitstream):
        if(data['i'] != self.func7):
            raise ParseError("The func7 did not match")
        return data

    def compute_result(self, src1, _):
        return (src1 << self.get_shift_amount()) & self.constant(0xffffffff, Type.int_32)

class Instruction_SRLI(I_Instruction):
    func3='101'
    func7='0000000'
    opcode='0010011'
    name= "SRLI"

    def extra_constraints(self, data, bitstream):
        if(data['i'] != self.func7):
            raise ParseError("The func7 did not match")
        return data

    def compute_result(self, src1, _):
        return (src1 >> self.get_shift_amount()) & self.constant(0xffffffff, Type.int_32)

#Once again issue with arithmetic right shifts, so for the moment still a TODO like SRA
class Instruction_SRAI(I_Instruction):
    func3='101'
    func7='0100000'
    opcode='0010011'
    name="SRAI"

    def extra_constraints(self, data, bitstream):
        if(data['i'] != self.func7):
            raise ParseError("The func7 did not match")
        return data

    def compute_result(self, src1, _):
        return (src1 >> self.get_shift_amount()) & self.constant(0xffffffff, Type.int_32)

class Instruction_SLTI(I_Instruction):
    func3='010'
    opcode='0010011'
    name='SLTI'

    def compute_result(self, src1, imm):
        src1.is_signed = True
        imm.is_signed = True
        val = 1 if src1.signed < imm.signed else 0
        return self.constant(val, Type.int_32)
    
class Instruction_SLTIU(I_Instruction):
    func3='011'
    opcode='0010011'
    name = 'SLTIU'

    def compute_result(self, src1, imm):
        src1.is_signed = False
        imm.is_signed = False
        val = 1 if src1 < imm else 0
        return self.constant(val, Type.int_32)
    
class Instruction_MUL(R_Instruction):
    func3='000'
    func7='0000001'
    opcode='0110011'
    name='MUL'

    def compute_result(self, src1, src2):
        return (src1*src2) & self.constant(0xFFFF, Type.int_32)

class Instruction_MULH(R_Instruction):
    func3='001'
    func7='0000001'
    opcode='0110011'
    name='MULH'

    def compute_result(self, src1, src2):
        return (src1*src2)>>self.constant(32,Type.int_8)

class Instruction_MULSU(R_Instruction):
    func3='010'
    func7='0000001'
    opcode='0110011'
    name='MULSU'

    def compute_result(self, src1, src2):
        src1 = src1.signed
        src2.is_signed = False
        return (src1*src2) & self.constant(0xFFFF, Type.int_32)

class Instruction_MULHU(R_Instruction):
    func3='011'
    func7='0000001'
    opcode='0110011'
    name='MULHU'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src2.is_signed = False
        return (src1*src2)>>self.constant(32,Type.int_8)

'''Dvision disabled due to exceeding recusion depth'''
class Instruction_DIV(R_Instruction):
    func3='100'
    func7='0000001'
    opcode='0110011'
    name='DIV'

    def compute_result(self, src1, src2):
        src1 = src1.signed
        src2 = src2.signed
    #   return src1/src2

'''Division disabled due to exceeding recusrion dpeth'''
class Instruction_DIVU(R_Instruction):
    func3='101'
    func7='0000001'
    opcode='0110011'
    name='DIVU'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src2.is_signed = False
       # return src1/src2

class Instruction_REM(R_Instruction):
    func3='110'
    func7='0000001'
    opcode='0110011'
    name='REM'

    def compute_result(self, src1, src2):
        return src1.signed%src2.signed

class Instruction_REMU(R_Instruction):
    func3='111'
    func7='0000001'
    opcode='0110011'
    name ='REMU'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src2.is_signed = False
        return src1%src2

class Instruction_LB(I_Instruction):
    func3='000'
    opcode='0000011'
    name='LB'

    def compute_result(self, src, imm):
        addr = src + imm.signed
        value = self.load(addr, Type.int_8)
        return value.signed

class Instruction_LH(I_Instruction):
    func3='001'
    opcode='0000011'
    name='LH'

    def compute_result(self, src, imm):
        addr = src + imm
        value = self.load(addr, Type.int_16)
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
        return self.load(addr, Type.int_8)

class Instruction_LHU(I_Instruction):
    func3='101'
    opcode='0000011'
    name="LHU"

    def compute_result(self, src, imm):
        addr= src+imm.signed
        return self.load(addr, Type.int_16)

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
        addr = self.addr+imm
        self.jump(src1!=src2, addr)
        return None

class Instruction_BLT(B_Instruction):
    func3='100'
    opcode='1100011'
    name='BLT'

    def compute_result(self, src1, src2, imm):
        addr = self.addr + imm
        self.jump(src1.signed<src2.signed, addr)

class Instruction_BGE(B_Instruction):
    func3='101'
    opcode = '1100011'
    name='BGE'

    def compute_result(self, src1, src2, imm):
        addr = self.addr + imm
        self.jump(src1.signed>=src2.signed, addr)

class Instruction_BLTU(B_Instruction):
    func3='110'
    opcode='1100011'
    name='BLTU'

    def compute_result(self, src1, src2, imm):
        src1.is_signed = False
        src2.is_signed = False
        addr = self.addr + imm
        self.jump(src1<src2, addr)

class Instruction_BGEU(B_Instruction):
    func3='111'
    opcode='1100011'
    name='BGEU'

    def compute_result(self, src1, src2, imm):
        src1.is_signed = False
        src2.is_signed = False
        addr = self.addr + imm
        self.jump(src1>= src2, addr)

class Instruction_JALR(I_Instruction):
    func3='000'
    opcode = '1100111'
    name='JALR'

    def compute_result(self, src, imm):
        return_addr = self.addr + self.constant(4, Type.int_32)
        addr = src + imm.value
        self.jump(None, addr, JumpKind.Call)
        return return_addr

class Instruction_JAL(J_Instruction):
    opcode = '1101111'
    name='JAL'

    def compute_result(self, imm):
        return_addr = self.addr + self.constant(4, Type.int_32)
        addr = self.addr+imm
        self.jump(None, self.constant(addr, Type.int_32))
        return return_addr

class Instruction_LUI(U_Instruction):
    opcode='0110111'
    name='LUI'

    def compute_result(self, _, imm):
        return (imm << self.constant(12, Type.int_8)) & self.constant(0xffffffff, Type.int_32)

class Instruction_AUIPC(U_Instruction):
    opcode='0010111'
    name='AUIPC'

    def compute_result(self, _ , imm):
        return self.addr + (imm << self.constant(12, Type.int_8))

class Instruction_CJR(CR_Instruction):
    opcode = '10'
    func4='1000'
    name = 'CJR'
    
    def extra_constraints(self, data, bitstream):
        if data['s'] != '00000':
            raise ParseError('Expected field to be 0 but it wasnt')
        if data['d'] == '00000':
            raise ParseError('Expected src2 to be non zero')
        return data

    def compute_result(self, _, src2):
        self.jump(None, src2)

class Instruction_CJALR(CR_Instruction):
    opcode = '10'
    func4='1001'
    name = 'CJALR'

    def extra_constraints(self, data, bitstream):
        if data['s'] != '00000':
            raise ParseError('Expected field src1 to be 0')
        if data['d'] == '00000':
            raise ParseError('Expected src2 to be non zero')
        return data

    def compute_result(self, _, src2):
        self.put(self.addr+self.constant(4, Type.int_32), 1)
        self.jump(None, src2)

class Instruction_CMV(CR_Instruction):
    opcode = '10'
    func4='1000'
    name = 'CMV'

    def extra_constraints(self, data, bitstream):
        if data['d'] == '00000':
            raise ParseError('Expected destination to be non zero')
        if data['s'] == '00000':
            raise ParseError('Expected source to be non zero')
        return data

    def compute_result(self, src1, _):
        dst = int(self.data['d'], 2)
        self.put(src1, dst)

class Instruction_CADD(CR_Instruction):
    opcode = '10'
    func4='1001'
    name = 'CADD'

    def extra_constraints(self, data, bitstream):
        if data['d'] == '00000':
            raise ParseError('Expected destination to be non zero')
        if data['s'] == '00000':
            raise ParseError('Expected source to be non zero')
        return data

    def compute_result(self, src1, src2):
        dst = int(self.data['d'],2)
        self.put(src1+src2, dst)

class Instruction_EB(CR_Instruction):
    opcode = '10'
    func4 = '1001'
    name = 'EB'

    def extra_constraints(self, data, bitstream):
        if data['d'] != '00000':
            raise ParseError('Expected dst to be 0')
        if data['s'] != '00000':
            raise ParseError('Expected src1 to be 0')
        return data

#no idea what EBreak does so not modelling it for the moment

class Instruction_CBEQZ(CB_Instruction):
    opcode = '01'
    func3='110'
    name = 'CBEQZ'

    def compute_result(self, src1):
        imm = "{0}{1}{2}{3}{4}".format(self.data['O'][2:4], self.data['I'][1:3], self.data["O"][4], self.data['O'][0:2], self.data['I'][0])
        offset = self.constant(BitArray(bin=imm).int, Type.int_32)
        addr = self.addr + offset
        self.jump(src1 == self.constant(0, Type.int_32), addr)

class Instruction_CBNEZ(CB_Instruction):
    opcode = '01'
    func3='111'
    name = 'CBNEZ'

    def compute_result(self, src1):
        imm = "{0}{1}{2}{3}{4}".format(self.data['O'][2:4], self.data['I'][1:3], self.data["O"][4], self.data['O'][0:2], self.data['I'][0])
        offset = self.constant(BitArray(bin=imm).int, Type.int_32)
        addr = self.addr + offset
        self.jump(src1 != self.constant(0, Type.int_32), addr)

class Instruction_CANDI(CB_Instruction):
    opcode = '01'
    func3 = '100'
    name = 'CANDI'

    def extra_constraints(self, data, bitstream):
        if data['I'] != '110' and data['I'] != '010':
            raise ParseError("Couldn't parse it for this instruction")
        return data
    
    def compute_result(self, src1):
        str_offset = '{0}{1}'.format(self.data['I'][0], self.data['O'])
        imm = self.constant(BitArray(bin=str_offset).uint, Type.int_32)
        dst = int(self.data['s'], 2)+8
        self.put(src1 & imm, dst)

class Instruction_CSRLI(CB_Instruction):
    opcode = '01'
    func3 = '100'
    name = 'CSRLI'

    def extra_constraints(self, data, bitstream):
        if data['I'][1:3] != '00':
            raise ParseError("Couldn't parse it for this instruction")
        if data['O'] == '000' and data['I'][0] == '0':
            raise ParseError("Shift amount should be non zero")
        return data

    def compute_result(self, src1):
        shftamnt = self.constant(BitArray(bin=self.data['O']).uint, Type.int_8)
        result = (src1>>shftamnt) & self.constant(0xffffffff, Type.int_32)
        dst = int(self.data['s'], 2)+8
        self.put(result, dst)


class Instruction_CSRAI(CB_Instruction):
    opcode = '01'
    func3 = '100'
    name = 'CSRAI'

    def extra_constraints(self, data, bitstream):
        if data['I'][1:3] != '01':
            raise ParseError("Couldn't parse it for this instruction")
        if data['O'] == '000' and data['I'][0] == '0':
            raise ParseError("Shift amount should be non zero")
#Once again not don't know how to do the arithmetic shift
    def compute_result(self, src1):
        shftamnt = self.constant(BitArray(bin=self.data['O']).uint, Type.int_8)
        result = (src1>>shftamnt) & self.constant(0xffffffff, Type.int_32)
        dst = int(self.data['s'], 2)+8
        self.put(result, dst)
    
    
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
        self.put(self.addr + self.constant(4, Type.int_32), 1)
        self.jump(None, self.addr+imm)
        
class Instruction_CSW(CS_Instruction):
    opcode = '00'
    func3 = '110'
    name = 'CSW'

    def compute_result(self, src1, src2):
        imm_str = "{0}{1}{2}00".format(self.data['i'][0], self.data['I'], self.data['i'][1])
        offset = self.constant(BitArray(bin=imm_str).uint, Type.int_32)
        self.store(src1, offset+ src2)

class Instruction_CSUB(CS_Instruction):
    opcode = '01'
    func3 = '100'
    name = 'CSUB'

    def extra_constraints(self, data, bitstream):
        if data['I'] != '011':
            raise ParseError("Extra parsing did not meet the specs")
        if data['i'] != '00':
            raise ParseError('Extra parsing did not meet the specs')

    def compute_result(self, src1, src2):
        return src1 - src2

class Instruction_CAND(CS_Instruction):
    opcode = '01'
    func3 = '100'
    name = 'CAND'

    def extra_constraints(self, data, bitstream):
        if data['I'] != '011':
            raise ParseError("Extra parsing did not meet the specs of CAND")
        if data['i'] != '11':
            raise ParseError("Extra parsing did not meet the specs of CAND")
    
    def compute_result(self, src1, src2):
        return src1 & src2

class Instruction_COR(CS_Instruction):
    opcode = '01'
    func3='100'
    name = 'COR'

    def extra_constraints(self, data, bitstream):
        if data['I'] != '011':
            raise ParseError("Extra parsing did not meet the specs of COR")
        if data['i'] != '10':
            raise ParseError("Extra parsing did not meet the specs of COR")
        return data

    def compute_result(self, src1, src2):
        return src1 | src2

class Instruction_CXOR(CS_Instruction):
    opcode = '01'
    func3 = '100'
    name = 'CXOR'

    def extra_constraints(self, data, bitstream):
        if data['I'] != '011':
            raise ParseError("Extra parsing did not meet the specs of CXOR")
        if data['i'] != '01':
            raise ParseError("Extra parsing did not meet the specs of CXOR")

    def compute_result(self, src1, src2):
        return src1 ^ src2

class Instruction_CADDI(CI_Instruction):
    opcode = '01'
    func3 = '000'
    name = 'CADDI'

    def extra_constraints(self, data, bitstream):
        
        if data['i'] == '00000' and data['I'] == '0':
            raise ParseError("Immediate can not be 0")
        if data['s'] == '00000':
            raise ParseError("Destination can not be 0")
        return data

    def compute_result(self, src1):
        bitstr = '{0}{1}'.format(self.data['I'], self.data['i'])
        val = self.constant(BitArray(bin=bitstr).int, Type.int_32)
        self.put(val.signed+src1, self.get_dst())

class Instruction_CLWSP(CI_Instruction):
    opcode = '10'
    func3 = '010'
    name = 'CLWSP'

    def compute_result(self, _):
        bitstr = '{0}{1}{2}00'.format(self.data['I'], self.data['i'][0:3], self.data['i'][3:5])
        offset = self.constant(BitArray(bin=bitstr).uint, Type.int_32)
        val = self.load(offset + self.get(2, Type.int_32), Type.int_32)
        self.put(val, self.get_dst())

class Instruction_CLW(CL_Instruction):
    opcode = '00'
    func3 = '010'
    name = 'CLW'

    def compute_result(self, src1, dst_addr):
        bitstr = '{0}{1}{2}00'.format(self.data['i'][0], self.data['I'], self.data['i'][1])
        offset = self.constant(BitArray(bin=bitstr).uint, Type.int_32)
        val = self.load(offset + src1, Type.int_32)
        self.put(val, dst_addr)

class Instruction_CLI(CI_Instruction):
    opcode = '01'
    func3 = '010'
    name = 'CLI'

    def extra_constraints(self, data, bitstream):
        if data['s'] == '000':
            raise ParseError("Destination can not be 0")
        return data

    def compute_result(self, _):
        imm = BitArray(bin='{0}{1}'.format(self.data['I'], self.data['i'])).int
        val = self.constant(imm, Type.int_32).signed
        self.put(val, self.get_dst())
        
class Instruction_CLUI(CI_Instruction):
    opcode = '01'
    func3 = '011'
    name = 'CLUI'

    def extra_constraints(self, data, bitstream):
        if data['s'] == '00000' or data['s'] == '00010':
            raise ParseError("Destination can not be 0 or 2")
        if data['i']=='00000' and data['I'] == '0':
            raise ParseError("Immediate can not be zero")        
        return data

    def compute_result(self, _):
        imm = BitArray(bin='{0}{1}000000000000'.format(self.data['I'], self.data['i'])).int
        val = self.constant(imm, Type.int_32).signed
        self.put(val, self.get_dst())

class Instruction_CADDI4SP(CIW_Instruction):
    opcode = '00'
    func3 = '000'
    name = 'CADDI4SP'

    def extra_constraints(self, data, bitstream):
        if data['i']=='00000000':
            raise ParseError("Immediate can not be 0")
        return data
    
    def compute_result(self, dst):
        immstr = '{0}{1}{2}{3}'.format(self.data['i'][0:2], self.data['i'][2:6], self.data['i'][7], self.data['i'][6])
        val = self.constant(BitArray(bin=immstr).uint, Type.int_32)
        self.put(val, dst)

class Instruction_CADDI16SP(CI_Instruction):
    opcode = '01'
    func3 = '011'
    name = 'CADDI16SP'

    def extra_constraints(self, data, bitstream):
        if data['s'] !=  '00010':
            raise ParseError("Destination must be 2 for this instruction")
        return data
    
    def compute_result(self, sp):
        i = self.data['i']
        immstr = '{0}{1}{2}{3}{4}0000'.format(self.data['I'], i[2:4], i[1], i[4], i[0])
        result = sp + self.constant(BitArray(bin=immstr).int, Type.int_32).signed
        self.put(result, 2)


class Instruction_NOP(Instruction):

    bin_format = '0000000000000001'
    name = 'NOP'

    def match_instruction(self, data, bitstream):
        return True

class Instruction_CSLLI(CI_Instruction):

    opcode = '10'
    func3 = '000'
    name = 'CSLLI'

    def extra_constraints(self, data, bitstream):
        if data['s'] == '00000':
            raise ParseError("Destination is not allowed to be 0")
        if data['I'] == '0' and data['i'] == '00000':
            raise ParseError('Immediate is not allowed to be 0')

    def compute_result(self, src1):
        data = '{0}{1}'.format(self.data['I'], self.data['i'])
        imm = self.constant(BitArray(bin=data).uint, Type.int_8)
        res = (src1 << imm) & self.constant(0xffffffff, Type.int_32)
        self.put(res, self.get_dst())


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

