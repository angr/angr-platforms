# pylint: disable=W0221,W0223
from pyvex.lifting.util import Type, Instruction
from bitstring import BitArray

class RISCV_Instruction(Instruction):

    def get(self, reg, ty):
        if reg == 0:
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
        super().__init__(bitstrm, arch, addr)

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
        super().__init__(bitstrm, arch, addr)

    #'''In the shift instruction extend this function to also check the last 7 bits of the immediate'''

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
        data = BitArray(bin="{0}{1}".format(self.data['i'], self.data['I'])).int
        return self.constant(data, Type.int_32)

    def get_shift_amount(self):
        num = BitArray(bin=self.data['I']).uint
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
        super().__init__(bitstrm, arch, addr)

    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    #'''This is the address + offset'''

    def get_addr(self):
        addr = self.get(int(self.data['s'], 2), Type.int_32)

        offset = BitArray(bin='{0}{1}'.format(self.data['I'], self.data['i'])).int
        return addr + offset

    #'''Value is returned as int32 caller must cast it to store half words or bytes'''

    def get_val(self):
        return self.get(int(self.data['S'], 2), Type.int_32)

    def fetch_operands(self):
        return (self.get_val(),)

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
        super().__init__(bitstrm, arch, addr)

    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def get_src1(self):
        return self.get(int(self.data['s'], 2), Type.int_32)

    def get_src2(self):
        return self.get(int(self.data['S'], 2), Type.int_32)

    #''' The offset for B instructions is as follows inst[31]inst[7]inst[30:25]inst[11:8] just had to be carefull with the endianness'''

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
        super().__init__(bitstrm, arch, addr)

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
        super().__init__(bitstrm, arch, addr)

    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def get_dst(self):
        return int(self.data['d'], 2)

    #Some weird way to parse the immediate according to risc-v isa

    def get_imm(self):
        i = self.data['i']
        imm = "{0}{1}{2}{3}0".format(i[0], i[12:20], i[11], i[1:11])

        return BitArray(bin=imm).int

    def fetch_operands(self):
        return (self.get_imm(),)

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
        super().__init__(bitstrm, arch, addr)

    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def get_src1(self):
        return self.get(int(self.data['s'], 2), Type.int_32)

    def get_src2(self):
        return self.get(int(self.data['d'], 2), Type.int_32)

    def get_dst_addr(self):
        return int(self.data['d'], 2)

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
        super().__init__(bitstrm, arch, addr)

    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def get_dst(self):
        return int(self.data['s'], 2)

    def fetch_operands(self):
        return (self.get(self.get_dst(), Type.int_32),)


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
        super().__init__(bitstrm, arch, addr)

    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)

        return True

    def fetch_operands(self):
        return (int(self.data['d'], 2) + 8,)


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
        super().__init__(bitstrm, arch, addr)

    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def get_src1(self):
        return self.get(int(self.data['s'], 2) + 8, Type.int_32)

    def get_dst_addr(self):
        return int(self.data['d'], 2) + 8

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
        super().__init__(bitstrm, arch, addr)

    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def fetch_operands(self):
        src1 = self.get(int(self.data['s'], 2) + 8, Type.int_32)
        src2 = self.get(int(self.data['S'], 2) + 8, Type.int_32)
        return src1, src2

    def commit_result(self, res):
        self.put(res, self.get_dst())

    def get_dst(self):
        return int(self.data['s'], 2) + 8


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
        super().__init__(bitstrm, arch, addr)

    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def fetch_operands(self):
        return (self.get(int(self.data['s'], 2) + 8, Type.int_32),)


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
        super().__init__(bitstrm, arch, addr)

    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True

    def fetch_operands(self):
        i = self.data['j']
        parsed = "{0}{1}{2}{3}{4}{5}{6}{7}0".format(i[0], i[4], i[2:4], i[6], i[5], i[10], i[1], i[7:10])
        val = self.constant(BitArray(bin=parsed).int, Type.int_32)
        return (val.signed,)
