from pyvex.lifting.util import *

def binify(x):
    return '{:08b}'.format(ord(x))

def flipy(x):
    y = [x[56 - i * 8 : 64 - i * 8] for i in range(8)]
    return ''.join(y)

REG_TY = Type.int_64

class Length14Instruction(Instruction):
    @property
    def bin_format(self):
        return 'c' * 64 + binify(self.opcode) + 'a' * 8 + 'b' * 8 + 'd' * 8 + '0000111100001011'

    def disassemble(self):
        operands = self._fetch_operands()
        if self.takes_const:
            operands[-1] = hex(operands[-1])
        return self.addr, self.name, self.format_operands(operands)

    def _fetch_operands(self):
        const = int(flipy(self.data['c']), 2)
        if const & (1 << 63):
            const -= (1 << 64)
        a = int(self.data['a'], 2)
        b = int(self.data['b'], 2)
        d = int(self.data['d'], 2)
        others = [a, b, d]
        start = 0 if self.uses_result else 1
        operands = others[start:self.num_operands+1]
        operands = [self.arch.register_index[n] for n in operands]
        if self.takes_const:
            operands.append(const)
        return operands

    def fetch_operands(self):
        reg_args = self._fetch_operands()
        if self.takes_const:
            *reg_args, const = reg_args
            const = self.constant(const, Type.int_64)
        if self.uses_result:
            ret, *reg_args = reg_args
        reg_args = [self.get(reg, Type.int_64) for reg in reg_args]
        operands = reg_args
        if self.takes_const:
            operands.append(const)
        if self.uses_result:
            operands = [ret, *operands]
        return operands

    def commit_result(self, res):
        assert self.uses_result
        ret = self.fetch_operands()[0]
        self.put(res, ret)

    def format_operands(self, operands):
        return operands

class Instruction_NEQConst(Length14Instruction):
    opcode = '\x24'
    name = 'NEQConst'
    num_operands = 1
    takes_const = True
    uses_result = True

    def compute_result(self, ret, arg1, const):
        """
        :param VexValue const:
        :param VexValue ret:
        :param VexValue arg1:
        """
        return const == arg1

class Instruction_LoadConst(Length14Instruction):
    opcode = '\x09'
    name = 'LoadConst'
    num_operands = 0
    takes_const = True
    uses_result = True

    def compute_result(self, ret, const):
        return const

class Instruction_Mov(Length14Instruction):
    opcode = '\x18'
    name = 'Mov'
    num_operands = 1
    takes_const = False
    uses_result = True

    def compute_result(self, ret, arg1):
        return arg1

class Instruction_RetNZ(Length14Instruction):
    opcode = '\x2a'
    name = 'RetNZ'
    num_operands = 1
    takes_const = False
    uses_result = False

    def compute_result(self, arg1):
        rsp = self.get('rsp', REG_TY)
        ret_addr = self.load(rsp, REG_TY)
        self.put(rsp + 8, 'rsp')
        self.jump(arg1 != 0, ret_addr, jumpkind=JumpKind.Ret)
        self.put(ret_addr, 'rip')

class Instruction_AddConst(Length14Instruction):
    opcode = '\x2c'
    name = 'AddConst'
    num_operands = 1
    takes_const = True
    uses_result = True

    def compute_result(self, ret, arg1, const):
        return arg1 + const

class GetAtInstruction(Length14Instruction):
    def format_operands(self, operands):
        const = int(operands[2], 16)
        if const >= 0:
            return [operands[0], '{}+{}'.format(operands[1], operands[2])]
        else:
            return [operands[0], '{}{}'.format(operands[1], operands[2])]


class Instruction_GetAtOffsetFrom(GetAtInstruction):
    opcode = '\x10'
    name = 'Load'
    num_operands = 1
    takes_const = True
    uses_result = True

    def compute_result(self, ret, arg1, const):
        addr = arg1 + const
        return self.load(addr, Type.int_64)

class Instruction_GetByteAtOffsetFrom(GetAtInstruction):
    opcode = '\x0a'
    name = 'LoadByte'
    num_operands = 1
    takes_const = True
    uses_result = True

    def compute_result(self, ret, arg1, const):
        addr = arg1 + const
        return self.load(addr, Type.int_8).widen_unsigned(Type.int_64)

class Instruction_GetWordSXAtOffsetFrom(GetAtInstruction):
    opcode = '\x0d'
    name = 'LoadWordSX'
    num_operands = 1
    takes_const = True
    uses_result = True

    def compute_result(self, ret, arg1, const):
        addr = arg1 + const
        return self.load(addr, Type.int_16).widen_signed(Type.int_64)

class Instruction_Push(Length14Instruction):
    opcode = '\x15'
    name = 'Push'
    num_operands = 1
    takes_const = False
    uses_result = False

    def compute_result(self, arg1):
        rsp = self.get('rsp', Type.int_64)
        newsp = rsp - 8
        self.put(newsp, 'rsp')
        self.store(arg1, newsp)

class Instruction_Pop(Length14Instruction):
    opcode = '\x17'
    name = 'Pop'
    num_operands = 0
    takes_const = False
    uses_result = True

    def compute_result(self, ret):
        rsp = self.get('rsp', REG_TY)
        newsp = rsp + 8
        self.store(newsp, 'rsp')
        return self.load(rsp, Type.int_64)

class Instruction_WriteAtOffsetFrom(Length14Instruction):
    opcode = '\x14'
    name = 'Store'
    num_operands = 2
    takes_const = True
    uses_result = False

    def format_operands(self, operands):
        const = int(operands[2], 16)
        if const >= 0:
            return ['{}+{}'.format(operands[0], operands[2]), operands[1]]
        else:
            return ['{}{}'.format(operands[0], operands[2]), operands[1]]

    def compute_result(self, arg1, arg2, const):
        destaddr = arg1 + const
        self.store(destaddr, arg2)

class Instruction_Call(Length14Instruction):
    opcode = '\x28'
    name = 'Call'
    num_operands = 0
    takes_const = True
    uses_result = False

    def compute_result(self, const):
        Instruction_Push.compute_result(self, self.get('rsp', Type.int_64))
        self.jump(None, const, JumpKind.Call)

class Instruction_JZ(Length14Instruction):
    opcode = '\x26'
    name = 'JZ'
    num_operands = 1
    takes_const = True
    uses_result = False

    def compute_result(self, arg1, const):
        self.jump(arg1 == 0, const)

class Instruction_JNZ(Length14Instruction):
    opcode = '\x27'
    name = 'JNZ'
    num_operands = 1
    takes_const = True
    uses_result = False

    def compute_result(self, arg1, const):
        self.jump(arg1 != 0, const)

class Instruction_Add(Length14Instruction):
    opcode = '\x01'
    name = 'Add'
    num_operands = 2
    takes_const = False
    uses_result = True

    def compute_result(self, ret, arg1, arg2):
        return arg1 + arg2

class Instruction_Sub(Length14Instruction):
    opcode = '\x02'
    name = 'Sub'
    num_operands = 2
    takes_const = False
    uses_result = True

    def compute_result(self, ret, arg1, arg2):
        return arg1 - arg2

class Instruction_Mul(Length14Instruction):
    opcode = '\x03'
    name = 'Mul'
    num_operands = 2
    takes_const = False
    uses_result = True

    def compute_result(self, ret, arg1, arg2):
        return arg1 * arg2

class Instruction_Div(Length14Instruction):
    opcode = '\x04'
    name = 'Div'
    num_operands = 2
    takes_const = False
    uses_result = True

    def compute_result(self, ret, arg1, arg2):
        return arg1.signed / arg2.signed

class Instruction_Mod(Length14Instruction):
    opcode = '\x05'
    name = 'Mod'
    num_operands = 2
    takes_const = False
    uses_result = True

    def compute_result(self, ret, arg1, arg2):
        return arg1 % arg2

class Instruction_Or(Length14Instruction):
    opcode = '\x19'
    name = 'Or'
    num_operands = 2
    takes_const = False
    uses_result = True

    def compute_result(self, ret, arg1, arg2):
        return arg1 | arg2

class Instruction_And(Length14Instruction):
    opcode = '\x1a'
    name = 'And'
    num_operands = 2
    takes_const = False
    uses_result = True

    def compute_result(self, ret, arg1, arg2):
        return arg1 & arg2

class Instruction_Xor(Length14Instruction):
    opcode = '\x1b'
    name = 'Xor'
    num_operands = 2
    takes_const = False
    uses_result = True

    def compute_result(self, ret, arg1, arg2):
        return arg1 ^ arg2

class Instruction_Negate(Length14Instruction):
    opcode = '\x08'
    name = 'Negate'
    num_operands = 1
    takes_const = False
    uses_result = True

    def compute_result(self, ret, arg1):
        return (- arg1)

class Instruction_Dup(Length14Instruction):
    opcode = '\x29'
    name = 'Dup'
    num_operands = 0
    takes_const = False
    uses_result = False

    def compute_result(self):
        rsp = self.get('rsp', Type.int_64)
        val = self.load(rsp, Type.int_64)
        Instruction_Push.compute_result(val)

class Instruction_DupIfZero(Length14Instruction):
    opcode = '\x2b'
    name = 'DupIfZero'
    num_operands = 1
    takes_const = False
    uses_result = False

    def compute_result(self, arg1):
        is_zero = arg1 == 0
        rsp = self.get('rsp', Type.int_64)
        val = self.load(rsp, Type.int_64)
        offset = (-8) * is_zero
        newsp = rsp + offset
        self.store(val, newsp)
        self.put(newsp, 'rsp')

class Instruction_RShift(Length14Instruction):
    opcode = '\x2d'
    name = 'RShift'
    num_operands = 1
    takes_const = True
    uses_result = True

    def compute_result(self, ret, arg1, const):
        return arg1 >> const

class Instruction_LShift(Length14Instruction):
    opcode = '\x2e'
    name = 'LShift'
    num_operands = 1
    takes_const = True
    uses_result = True

    def compute_result(self, ret, arg1, const):
        return arg1 << const

class Instruction_Eq(Length14Instruction):
    opcode = '\x21'
    name = 'Eq'
    num_operands = 2
    takes_const = False
    uses_result = True

    def compute_result(self, ret, arg1, const):
        return arg1 == const
