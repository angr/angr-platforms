# pylint: disable=W0613,R0201,W0221,W0223
from .instruction_patterns import CR_Instruction
from pyvex.lifting.util import Type, ParseError

class Instruction_CJR(CR_Instruction):
    opcode = '10'
    func4 = '1000'
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
    func4 = '1001'
    name = 'CJALR'

    def extra_constraints(self, data, bitstream):
        if data['s'] != '00000':
            raise ParseError('Expected field src1 to be 0')
        if data['d'] == '00000':
            raise ParseError('Expected src2 to be non zero')
        return data

    def compute_result(self, _, src2):
        self.put(self.addr + self.constant(2, Type.int_32), 1)
        self.jump(None, src2)


class Instruction_CMV(CR_Instruction):
    opcode = '10'
    func4 = '1000'
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
    func4 = '1001'
    name = 'CADD'

    def extra_constraints(self, data, bitstream):
        if data['d'] == '00000':
            raise ParseError('Expected destination to be non zero')
        if data['s'] == '00000':
            raise ParseError('Expected source to be non zero')
        return data

    def compute_result(self, src1, src2):
        dst = int(self.data['d'], 2)
        self.put(src1 + src2, dst)


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

# no idea what EBreak does so not modelling it for the moment
