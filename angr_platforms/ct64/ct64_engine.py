import angr
import claripy

class CT64KMixin(angr.engines.SuccessorsMixin):
    def process_successors(self, successors, **kwargs):
        state = self.state
        if state.arch.name != 'CT64K':
            return super().process_successors(successors, **kwargs)

        ins = decode(state, successors.addr)
        ins.execute(state, successors)

        successors.processed = True
        successors.description = str(ins)

class UberEngineWithCT64K(angr.engines.UberEngine, CT64KMixin):
    pass

# pylint: disable=abstract-method
class Instruction:
    NAME = 'UNKNOWN'
    LEN = 0

    def execute(self, state, successors):
        raise NotImplementedError

    def __eq__(self, other):
        if type(self) is not type(other):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((type(self),) + tuple(x[1] for x in sorted(self.__dict__.items())))

    @staticmethod
    def name_reg(r, double=False):
        if double:
            return '[%s]' % Instruction.name_reg(r)

        if r.op != 'BVV':
            return '[symbolic]'
        r = r.args[0]

        if r == 0:
            return 'ip'
        elif r == 1:
            return 'sp'
        elif r == 2:
            return 'bp'
        elif r < 0x10:
            return 'sc%X' % r
        elif r < 0x40:
            return 'r%X' % r
        elif r < 0x100:
            return 's%X' % r
        elif r < 0x300:
            return 'p%X' % r
        elif r < 0x1000:
            return 'stack%X' % r
        else:
            return '[%#x]' % r


class Instruction2(Instruction):
    LEN = 2

    def __init__(self, rm, mem):
        self.rm = rm
        self.mem = mem

    def __str__(self):
        return '%s %s, %s' % (self.NAME, self.name_reg(self.rm), self.name_reg(self.mem))

    def execute(self, state, successors):
        value = self.value(state)
        dest = self.destination(state)

        state.regs._ip += self.LEN
        state.memory.store(dest, value)
        successors.add_successor(state, state.regs._ip, state.solver.true, 'Ijk_Boring')

    def value(self, state):
        raise NotImplementedError

    def destination(self, state): # pylint: disable=unused-argument
        return self.rm

class MI(Instruction2):
    NAME = 'MI'

    def __str__(self):
        return '%s %s, %s' % (self.NAME, self.name_reg(self.rm), self.mem)

    def value(self, state):
        return self.mem

class MV(Instruction2):
    NAME = 'MV'

    def value(self, state):
        return state.memory.load(self.mem, size=1)

class MD(Instruction2):
    NAME = 'MD'

    def __str__(self):
        return '%s %s, %s' % (self.NAME, self.name_reg(self.rm), self.name_reg(self.mem, True))

    def value(self, state):
        return state.memory.load(state.memory.load(self.mem, size=1), size=1)

class LD(Instruction2):
    NAME = 'LD'

    def __str__(self):
        return '%s %s, %s' % (self.NAME, self.name_reg(self.rm, True), self.name_reg(self.mem))

    def value(self, state):
        return state.memory.load(self.mem, size=1)

    def destination(self, state):
        return state.memory.load(self.rm, size=1)

class ST(Instruction2):
    NAME = 'ST'

    def __str__(self):
        return '%s %s, %s' % (self.NAME, self.name_reg(self.mem, True), self.name_reg(self.rm))

    def value(self, state):
        return state.memory.load(self.rm, size=1)

    def destination(self, state):
        return state.memory.load(self.mem, size=1)

class AD(Instruction2):
    NAME = 'AD'

    def value(self, state):
        return state.memory.load(self.rm, size=1) + state.memory.load(self.mem, size=1)

class SB(Instruction2):
    NAME = 'SB'

    def value(self, state):
        return state.memory.load(self.rm, size=1) - state.memory.load(self.mem, size=1)

class ND(Instruction2):
    NAME = 'ND'

    def value(self, state):
        return state.memory.load(self.rm, size=1) & state.memory.load(self.mem, size=1)

class OR(Instruction2):
    NAME = 'OR'

    def value(self, state):
        return state.memory.load(self.rm, size=1) | state.memory.load(self.mem, size=1)

class XR(Instruction2):
    NAME = 'XR'

    def value(self, state):
        return state.memory.load(self.rm, size=1) ^ state.memory.load(self.mem, size=1)

class SR(Instruction2):
    NAME = 'SR'

    def value(self, state):
        return state.solver.LShR(state.memory.load(self.rm, size=1), state.memory.load(self.mem, size=1))

class SL(Instruction2):
    NAME = 'SL'

    def value(self, state):
        return state.memory.load(self.rm, size=1) << state.memory.load(self.mem, size=1)

class SA(Instruction2):
    NAME = 'SA'

    def value(self, state):
        return state.memory.load(self.rm, size=1) >> state.memory.load(self.mem, size=1)

#END instruction2 type

class InstructionJump(Instruction):
    LEN = 3

    def __init__(self, rm, mem, imm):
        self.rm = rm
        self.mem = mem
        self.imm = imm

    def __str__(self):
        return '%s %s, %s -> %s' % (self.NAME, self.name_reg(self.rm), self.name_reg(self.mem), self.imm)

    def execute(self, state, successors):
        guard = self.condition(state)

        yes_state = state
        no_state = state.copy()

        jumpkind = 'Ijk_Exit' if self.NAME == 'HF' and state.solver.is_true(self.imm == successors.addr) else 'Ijk_Boring'
        successors.add_successor(yes_state, self.imm, guard, jumpkind)
        successors.add_successor(no_state, state.solver.BVV(successors.addr + self.LEN, 16), state.solver.Not(guard), jumpkind)

    def condition(self, state):
        raise NotImplementedError

class JG(InstructionJump):
    NAME = 'JG'

    def condition(self, state):
        return state.solver.UGT(state.memory.load(self.rm, size=1), state.memory.load(self.mem, size=1))

class JL(InstructionJump):
    NAME = 'JL'

    def condition(self, state):
        return state.solver.ULT(state.memory.load(self.rm, size=1), state.memory.load(self.mem, size=1))

class JQ(InstructionJump):
    NAME = 'JQ'

    def __init__(self, *args):
        super(JQ, self).__init__(*args)

        if claripy.is_true(self.rm) == 0 and claripy.is_true(self.mem == 0):
            self.NAME = 'HF'

    def condition(self, state):
        return state.memory.load(self.rm, size=1) == state.memory.load(self.mem, size=1)

ALL_INSTRUCTIONS = [MI, MV, MD, LD, ST, AD, SB, ND, OR, XR, SR, SL, SA, JG, JL, JQ]

def decode(state, addr):
    ins = state.memory.load(addr, size=1)
    op = ins[15:12]
    rm = ins & 0xFFF
    mem = state.memory.load(addr + 1, size=1)

    try:
        op = state.solver.eval_one(op)
    except angr.SimSolverError:
        raise angr.SimError("Cannot execute symbolic data")

    if op <= 0xC:
        return ALL_INSTRUCTIONS[op](rm, mem)
    else:
        imm = state.memory.load(addr + 2, size=1)
        return ALL_INSTRUCTIONS[op](rm, mem, imm)

def disasm(state, addr, length=None):
    b = addr
    while length is not None and b < addr + length:
        ins = decode(state, b)
        print(hex(b), ins)
        b += ins.LEN

        if isinstance(b, InstructionJump):
            break
        elif isinstance(b, Instruction2) and claripy.is_true(b.rm == 0):
            break
