
import logging

import archinfo
from pyvex.lifting.util import *
from pyvex.lifting import register


log = logging.getLogger("lift_bpf")

MAX_INSTR_ID = 4096
arch_bpf = archinfo.arch_from_id('BPF')

def switch_endianness(n):
    return (n >> 24) | ((n >> 8) & 0xff00) | ((n & 0xff00) << 8) | ((n & 0xff) << 24)


class Inst_LDDATA(Instruction):
    name = "loaddata"
    bin_format = bin(0x20)[2:].zfill(8) + '0' * 24 + 'n' * 32

    def parse(self, bitstrm):
        data = super(Inst_LDDATA, self).parse(bitstrm)
        self.n = switch_endianness(int(data['n'], 2))

    def compute_result(self):
        addr = self.constant(arch_bpf.DATA_BASE + self.n, Type.int_32)
        val = self.load(addr, Type.int_32)
        self.put(val, 'A')


class Inst_LDCONST(Instruction):
    name = "loadconst"
    bin_format = '0' * 32 + 'n' * 32

    def parse(self, bitstrm):
        data = super(Inst_LDCONST, self).parse(bitstrm)
        self.n = switch_endianness(int(data['n'], 2))

    def compute_result(self):
        val = self.constant(self.n, Type.int_32)
        self.put(val, 'A')


class Inst_LDXCONST(Instruction):
    name = "loadxconst"
    bin_format = bin(0x1)[2:].zfill(8) + '0' * 24 + 'n' * 32

    def parse(self, bitstrm):
        data = super(Inst_LDXCONST, self).parse(bitstrm)
        self.n = switch_endianness(int(data['n'], 2))

    def compute_result(self):
        val = self.constant(self.n, Type.int_32)
        self.put(val, 'X')


class Inst_LDTEMP(Instruction):
    name = "loadtemp"
    bin_format = bin(0x60)[2:].zfill(8) + '0' * 24 + 'n' * 32

    def parse(self, bitstrm):
        data = super(Inst_LDTEMP, self).parse(bitstrm)
        self.n = switch_endianness(int(data['n'], 2))

    def compute_result(self):
        addr = self.constant(arch_bpf.TEMP_BASE + self.n * 4, Type.int_32)
        val = self.load(addr, Type.int_32)
        self.put(val, 'A')


class Inst_LDXTEMP(Instruction):
    name = "loadxtemp"
    bin_format = bin(0x61)[2:].zfill(8) + '0' * 24 + 'n' * 32

    def parse(self, bitstrm):
        data = super(Inst_LDXTEMP, self).parse(bitstrm)
        self.n = switch_endianness(int(data['n'], 2))

    def compute_result(self):
        addr = self.constant(arch_bpf.TEMP_BASE + self.n * 4, Type.int_32)
        val = self.load(addr, Type.int_32)
        self.put(val, 'X')


class Inst_SDTEMP(Instruction):
    name = "storetemp"
    bin_format = bin(0x2)[2:].zfill(8) + (bin(0)[2:].zfill(8)) * 3 + 'n' * 32

    def parse(self, bitstrm):
        data = super(Inst_SDTEMP, self).parse(bitstrm)
        self.n = switch_endianness(int(data['n'], 2))

    def compute_result(self):
        addr = self.constant(arch_bpf.TEMP_BASE + self.n * 4, Type.int_32)
        val = self.get('A', Type.int_32)
        self.store(val, addr)


class Inst_SDXTEMP(Instruction):
    name = "storextemp"
    bin_format = bin(0x3)[2:].zfill(8) + (bin(0)[2:].zfill(8)) * 3 + 'n' * 32

    def parse(self, bitstrm):
        data = super(Inst_SDXTEMP, self).parse(bitstrm)
        self.n = switch_endianness(int(data['n'], 2))

    def compute_result(self):
        addr = self.constant(arch_bpf.TEMP_BASE + self.n * 4, Type.int_32)
        val = self.get('X', Type.int_32)
        self.store(val, addr)


class Inst_JEQ(Instruction):
    name = "jeq"
    bin_format = bin(0x15)[2:].zfill(8) + '0' * 8 + 't' * 8 + 'f' * 8 + 'n' * 32

    def parse(self, bitstrm):
        data = super(Inst_JEQ, self).parse(bitstrm)

        self.true_step = int(data['t'], 2) * 8
        self.false_step = int(data['f'], 2) * 8
        self.n = switch_endianness(int(data['n'], 2))

    def compute_result(self):

        val = self.get('A', Type.int_32)
        addr = self.addr + 8

        if self.true_step == 0:
            self.jump(val != self.constant(self.n, Type.int_32),
                      self.constant(addr + self.false_step, Type.int_32),
                      jumpkind=JumpKind.Boring,
                      ip_offset=arch_bpf.registers['pc'][0],
                      )
        elif self.false_step == 0:
            self.jump(val == self.constant(self.n, Type.int_32),
                      self.constant(addr + self.true_step, Type.int_32),
                      jumpkind=JumpKind.Boring,
                      ip_offset=arch_bpf.registers['pc'][0],
                      )
        else:
            raise Exception("OUCH not supported")

        #self.jump(None, self.constant(addr + 8, Type.int_32),
        #          JumpKind.Boring
        #          )


class Inst_RET(Instruction):
    name = "return"
    bin_format = bin(0x6)[2:].zfill(8) + '0' * 24 + 'r' * 32

    def compute_result(self):

        ret = switch_endianness(int(self.data['r'], 2))

        if ret == 0x7fff0000:
            # ALLOW
            self.put(self.constant(1, Type.int_32), 'res')
        elif ret == 0:
            # DENY
            self.put(self.constant(0, Type.int_32), 'res')
        else:
            raise Exception('OUCH not supported')

        self.jump(0, self.constant(MAX_INSTR_ID * 8, Type.int_32),  # TODO: FIXME
                  JumpKind.Ret
                  )


class Inst_TAX(Instruction):
    name = "tax"
    bin_format = bin(0x7)[2:].zfill(8) + '0' * 56

    def compute_result(self):

        a = self.get('A', Type.int_32)
        self.put(a, 'X')


class Inst_TXA(Instruction):
    name = "txa"
    bin_format = bin(0x87)[2:].zfill(8) + '0' * 56

    def compute_result(self):

        x = self.get('X', Type.int_32)
        self.put(x, 'A')


class Inst_Arithmetic(Instruction):
    bin_format = 'o' * 8 + '0' * 24 + 'x' * 32

    def fetch_operands(self):
        x = switch_endianness(int(self.data['x'], 2))
        return [ x ]


class Inst_ADD(Inst_Arithmetic):
    # opcode: 0x4
    name = "add"
    bin_format = bin(0x4)[2:].zfill(8) + '0' * 24 + 'x' * 32

    def compute_result(self, x):
        a = self.get('A', Type.int_32)
        self.put(a + self.constant(x, Type.int_32), 'A')


class Inst_ADDX(Inst_Arithmetic):
    # opcode: 0xc
    name = "addx"
    bin_format = bin(0xc)[2:].zfill(8) + '0' * 24 + 'x' * 32

    def compute_result(self, unused):
        a = self.get('A', Type.int_32)
        x = self.get('X', Type.int_32)
        self.put(a + x, 'A')



class Inst_MUL(Inst_Arithmetic):
    name = "mul"
    bin_format = bin(0x24)[2:].zfill(8) + '0' * 24 + 'x' * 32

    def compute_result(self, x):
        a = self.get('A', Type.int_32)
        self.put(a * self.constant(x, Type.int_32), 'A')


class Inst_DIV(Inst_Arithmetic):
    name = "div"
    bin_format = bin(0x34)[2:].zfill(8) + '0' * 24 + 'x' * 32

    def compute_result(self, x):
        a = self.get('A', Type.int_32)
        c = self.constant(x, Type.int_32)
        tmp_a = a // c
        self.put(tmp_a, 'A')


class Inst_AND(Inst_Arithmetic):
    name = "and"
    bin_format = bin(0x54)[2:].zfill(8) + '0' * 24 + 'x' * 32

    def compute_result(self, x):
        a = self.get('A', Type.int_32)
        self.put(a & self.constant(x, Type.int_32), 'A')


class Inst_XORX(Inst_Arithmetic):
    name = "xorx"
    bin_format = bin(0xac)[2:].zfill(8) + '0' * 24 + 'x' * 32

    def compute_result(self, unused):
        a = self.get('A', Type.int_32)
        x = self.get('X', Type.int_32)
        self.put(a ^ x, 'A')



class Inst_NEG(Inst_Arithmetic):
    name = "neg"
    bin_format = bin(0x84)[2:].zfill(8) + '0' * 24 + 'x' * 32

    def compute_result(self, x):
        a = self.get('A', Type.int_32)
        # Minus one
        a -= 1
        # Invert each bit
        a = ~a
        self.put(a, 'A')


class Inst_RSH(Inst_Arithmetic):
    name = "rsh"
    bin_format = bin(0x74)[2:].zfill(8) + '0' * 24 + 'x' * 32

    def compute_result(self, x):
        a = self.get('A', Type.int_32)
        shifted = a >> self.constant(x, Type.int_8)
        self.put(shifted, 'A')


# Special optimizations

class Inst_FANCYXOR(Instruction):

    # It's equivalent to (A % 65537)

    bin_format = bin(0x34)[2:].zfill(8) + '0' * 24 + bin(switch_endianness(65537))[2:].zfill(32) + \
                 bin(0x24)[2:].zfill(8) + '0' * 24 + bin(switch_endianness(65537))[2:].zfill(32) + \
                 bin(0x84)[2:].zfill(8) + '0' * 56 + \
                 bin(0xc)[2:].zfill(8) + '0' * 24 + 'a' * 32 + \
                 bin(0x15)[2:].zfill(8) + '0' * 16 + bin(1)[2:].zfill(8) + bin(switch_endianness(65536))[2:].zfill(32) + \
                 '0' * 64

    def compute_result(self):
        # print "FANCYXOR is hit"
        a = self.get('A', Type.int_32)
        r = a % self.constant(65537, Type.int_32)
        self.put(r - self.constant(1, Type.int_32), 'A')


class Inst_FANCYITE(Instruction):

    bin_format = bin(0x15)[2:].zfill(8) + '0' * 16 + bin(1)[2:].zfill(8) + '0' * 32 + \
                 '0' * 32 + bin(switch_endianness(65536))[2:].zfill(32)


    def compute_result(self):
        # print "FANCYITE is hit"
        # do nothing for now
        #a = self.get('A', Type.int_32)
        #self.put(a, 'A')
        self.jump(None, self.constant(self.addr + 16, Type.int_32))


all_instrs = [
    #Inst_FANCYXOR,
    #Inst_FANCYITE,
    Inst_LDDATA,
    Inst_LDCONST,
    Inst_LDXCONST,
    Inst_LDTEMP,
    Inst_LDXTEMP,
    Inst_SDTEMP,
    Inst_SDXTEMP,
    Inst_JEQ,
    Inst_RET,
    Inst_TAX,
    Inst_TXA,
    Inst_ADD,
    Inst_ADDX,
    Inst_MUL,
    Inst_DIV,
    Inst_AND,
    Inst_XORX,
    Inst_NEG,
    Inst_RSH,
]


class LifterBPF(GymratLifter):
    instrs = all_instrs

# Tell PyVEX that this lifter exists.
register(LifterBPF, 'BPF')
