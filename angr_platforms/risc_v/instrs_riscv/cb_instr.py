# pylint: disable=W0613,R0201,W0221
from .instruction_patterns import CB_Instruction
from pyvex.lifting.util import Type, ParseError
from bitstring import BitArray

class Instruction_CBEQZ(CB_Instruction):
    opcode = '01'
    func3 = '110'
    name = 'CBEQZ'

    def compute_result(self, src1):
        imm = "{4}{3}{2}{1}{0}0".format(self.data['O'][2:4], self.data['I'][1:3], self.data["O"][4], self.data['O'][0:2],
                                       self.data['I'][0])
        offset = self.constant(BitArray(bin=imm).int, Type.int_32)
        addr = self.addr + offset
        self.jump(src1 == self.constant(0, Type.int_32), addr)


class Instruction_CBNEZ(CB_Instruction):
    opcode = '01'
    func3 = '111'
    name = 'CBNEZ'

    def compute_result(self, src1):
        imm = "{4}{3}{2}{1}{0}0".format(self.data['O'][2:4], self.data['I'][1:3], self.data["O"][4], self.data['O'][0:2],
                                       self.data['I'][0])
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
        imm = self.constant(BitArray(bin=str_offset).int, Type.int_32)
        dst = int(self.data['s'], 2) + 8
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
        result = (src1 >> shftamnt) & self.constant(0xffffffff, Type.int_32)
        dst = int(self.data['s'], 2) + 8
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

    # Once again not don't know how to do the arithmetic shift
    def compute_result(self, src1):
        shftamnt = self.constant(BitArray(bin=self.data['O']).uint, Type.int_8)
        result = (~((~src1) >> shftamnt)) & self.constant(0xffffffff, Type.int_32)
        dst = int(self.data['s'], 2) + 8
        self.put(result, dst)
