# pylint: disable=W0613,R0201,W0221, W0223
from .instruction_patterns import RISCV_Instruction, CL_Instruction, CIW_Instruction
from pyvex.lifting.util import Type, Instruction, ParseError
from bitstring import BitArray


class Instruction_CSWSP(RISCV_Instruction):
    '''
    bin_format:
    o = opcode 2 bits
    s = src1 5 bits
    i = imm 6 bits
    f = func3 3 bits
    '''
    #opcode = '10'
    #func3 = '110'
    name = 'CSWSP'

    bin_format = '110iiiiiisssss10'
    """"
    def __init__(self, bitstrm, arch, addr):
        self.bin_format = "{0}iiiiiisssss{1}".format(self.func3, self.opcode)
        super().__init__(bitstrm, arch, addr)


    def match_instruction(self, data, bitstream):
        if hasattr(self, "extra_constraints"):
            # pylint: disable=E1101
            self.extra_constraints(data, bitstream)
        return True
    """
    def get_src1(self):
        return self.get(int(self.data['s'], 2), Type.int_32)

    def fetch_operands(self):
        return (self.get_src1(),)

    def get_imm(self):
        val = "{0}{1}00".format(self.data['i'][4:6], self.data['i'][0:4])
        res = self.constant(BitArray(bin=val).int, Type.int_32)
        return res

    def compute_result(self, src1):
        return src1

    def commit_result(self, result):
        self.store(result, self.get(2, Type.int_32) + self.get_imm())

class Instruction_CLW(CL_Instruction):
    opcode = '00'
    func3 = '010'
    name = 'CLW'

    def compute_result(self, src1, dst_addr):
        bitstr = '{2}{1}{0}00'.format(self.data['i'][0], self.data['I'], self.data['i'][1])
        offset = self.constant(BitArray(bin=bitstr).int, Type.int_32)
        val = self.load(offset + src1, Type.int_32)
        self.put(val, dst_addr)


class Instruction_CADDI4SP(CIW_Instruction):
    opcode = '00'
    func3 = '000'
    name = 'CADDI4SP'

    def extra_constraints(self, data, bitstream):
        if data['i'] == '00000000':
            raise ParseError("Immediate can not be 0")
        return data

    def compute_result(self, dst):
        immstr = '{1}{0}{2}{3}00'.format(self.data['i'][0:2], self.data['i'][2:6], self.data['i'][7], self.data['i'][6])
        val = self.constant(BitArray(bin=immstr).int, Type.int_32) + self.get(2, Type.int_32)
        self.put(val, dst)


class Instruction_NOP(Instruction):
    bin_format = '0000000000000001'
    name = 'NOP'

    def match_instruction(self, data, bitstream):
        return True
