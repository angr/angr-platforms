# pylint: disable=W0613,R0201,W0221
from .instruction_patterns import CS_Instruction
from pyvex.lifting.util import Type, ParseError
from bitstring import BitArray

class Instruction_CSW(CS_Instruction):
    opcode = '00'
    func3 = '110'
    name = 'CSW'

    def compute_result(self, src1, src2):
        imm_str = "{2}{1}{0}00".format(self.data['i'][0], self.data['I'], self.data['i'][1])
        offset = self.constant(BitArray(bin=imm_str).int, Type.int_32)  # TODO check if this is a mistake
        self.store(src1, offset + src2)

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
    func3 ='100'
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
