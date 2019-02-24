from pyvex.lifting.util import *
import claripy

def binify(x):
    return '{:04b}'.format(x)

def flipy(x):
    y = [x[56 - i * 8 : 64 - i * 8] for i in range(8)]
    return ''.join(y)

REG_TY = Type.int_8

class Rev3alInstruction(Instruction):
    ignores_mode = False
    stores_to_memory = False

    @property
    def bin_format(self):
        return 'z' * 12 + binify(self.opcode) + 'z' * 12 + 'ss' + 'dd'

    def _fetch_operands(self):
        src = int(self.data['s'], 2)
        dst = int(self.data['d'], 2)
        return dst, src

    def fetch_operands(self):
        dst, src = self._fetch_operands()
        assert src != 3 and dst != 3
        dstreg, srcreg = self.get(dst, Type.int_8), self.get(src, Type.int_8)
        if self.ignores_mode:
            return dstreg, srcreg
        else:
            return self.get_reg(dst), self.get_reg(src)
            #return self.ite(self.is_mem_mode(), self.load(dstreg, REG_TY), dstreg), \
            #       self.ite(self.is_mem_mode(), self.load(dstreg, REG_TY), srcreg)

    def commit_result(self, res):
        ret = self._fetch_operands()[0]
        if self.stores_to_memory:
            self.store(res, self.get(ret, REG_TY))
        else:
            self.put(res, ret)

    def disassemble(self):
        operands = self._fetch_operands()
        return self.addr, self.name, self.format_operands(operands)

    def format_operands(self, operands):
        return operands

    def load_register_with_indirect(self, state, *args, **kwargs):
        mode = state.globals['thingything']
        value = state.registers.load(self.lookup_register(self.arch, args[0].args[0]))[7:0]
        if mode:
            return state.memory.load(value, 1), []
        else:
            return value, []


    def get_mode_func(self, state, *args, **kwargs):
        return claripy.BVV(int(state.globals['thingything']), 1), []

    def get_mode(self):
        return self.ccall(Type.int_1, self.get_mode_func, ())

    def get_reg(self, reg):
        return self.ccall(Type.int_8, self.load_register_with_indirect, (self.constant(reg, Type.int_2).rdt,))

    def is_mem_mode(self):
        return self.get_mode() == 1

class Instruction_Add(Rev3alInstruction):
    opcode = 1
    name = 'Add'

    def compute_result(self, dst, src):
        return src + dst

class Instruction_Sub(Rev3alInstruction):
    opcode = 2
    name = 'Sub'

    def compute_result(self, dst, src):
        return dst - src

class Instruction_Mul(Rev3alInstruction):
    opcode = 3
    name = 'Mul'

    def compute_result(self, dst, src):
        return dst * src

class Instruction_Div(Rev3alInstruction):
    opcode = 4
    name = 'Div'

    def compute_result(self, dst, src):
        return dst / src

class Instruction_Mov(Rev3alInstruction):
    opcode = 5
    name = 'Mov'

    def compute_result(self, dst, src):
        return src

class Instruction_Store(Rev3alInstruction):
    opcode = 6
    name = 'Store'
    stores_to_memory = True

    def compute_result(self, dst, src):
        return src.cast_to(Type.int_8)

class Instruction_LoadIm(Rev3alInstruction):
    opcode = 10
    name = 'LoadIm'

    def compute_result(self, dst, src):
        return self.constant(self._fetch_operands()[1], Type.int_8)

class Instruction_Inc(Rev3alInstruction):
    opcode = 0xb
    name = 'Inc'

    def compute_result(self, dst, src):
        return dst + 1

class Instruction_ModeFlip(Rev3alInstruction):
    opcode = 8
    name = 'Mode'

    def do_the_thing(self, state, *args, **kwargs):
        state.globals['thingything'] = not state.globals['thingything']
        return claripy.BVS('x', 64), []

    def compute_result(self, dst, src):
        self.ccall(Type.int_64, self.do_the_thing, ())

class Instruction_Jmp(Rev3alInstruction):
    opcode = 7
    name = 'Jmp'
    ignores_mode = True

    def compute_result(self, dst, src):
        self.jump(None, dst.cast_to(Type.int_64) * 4)

class Instruction_JmpZero(Rev3alInstruction):
    opcode = 9
    name = 'JmpZ'
    ignores_mode = True

    def compute_result(self, dst, src):
        self.jump(dst != 0, self.ite(self.is_mem_mode(), self.addr + src.cast_to(Type.int_64) * 4, src.cast_to(Type.int_64) * 4))
