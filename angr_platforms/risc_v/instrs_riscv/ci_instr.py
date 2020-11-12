# pylint: disable=W0613,R0201,W0221
from .instruction_patterns import CI_Instruction
from pyvex.lifting.util import Type, ParseError
from bitstring import BitArray


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
        self.put(val.signed + src1, self.get_dst())


class Instruction_CLWSP(CI_Instruction):
    opcode = '10'
    func3 = '010'
    name = 'CLWSP'

    def compute_result(self, _):
        bitstr = '{2}{0}{1}00'.format(self.data['I'], self.data['i'][0:3], self.data['i'][3:5])
        offset = self.constant(BitArray(bin=bitstr).int, Type.int_32)
        val = self.load(offset + self.get(2, Type.int_32), Type.int_32)
        self.put(val, self.get_dst())

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
        if data['i' ]=='00000' and data['I'] == '0':
            raise ParseError("Immediate can not be zero")
        return data

    def compute_result(self, _):
        imm = BitArray(bin='{0}{1}000000000000'.format(self.data['I'], self.data['i'])).int
        val = self.constant(imm, Type.int_32).signed
        self.put(val, self.get_dst())


class Instruction_CADDI16SP(CI_Instruction):
    opcode = '01'
    func3 = '011'
    name = 'CADDI16SP'

    def extra_constraints(self, data, bitstream):
        if data['s'] != '00010':
            raise ParseError("Destination must be 2 for this instruction")
        return data

    def compute_result(self, sp):
        i = self.data['i']
        immstr = '{0}{1}{2}{3}{4}0000'.format(self.data['I'], i[2:4], i[1], i[4], i[0])
        result = sp + self.constant(BitArray(bin=immstr).int, Type.int_32).signed
        self.put(result, 2)


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
