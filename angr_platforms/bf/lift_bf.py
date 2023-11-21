import bitstring
from pyvex.lifting.util import *
from pyvex.lifting import register


# This is actually a BrainFuck lifter for pyVEX.  I'm not joking.
# Created by edg on 1/14/2017
# Rewrote by edg for gymrat on 9/4/2017
# The goal of this, and any other lifter, is to convert one basic block of raw bytes into
# a set of VEX instructions representing what the code does.
# A basic block, in this case is defined a set of instructions terminated by:
# !) a conditional branch
# 2) A function call
# 3) A system call
# 4) the end of the program
#
# We need to build an IRSB, a grouping of VEX code, and associated metadata representing one block.
# This is then used by angr itself to perform static analysis and symbolic execution.

##
# These helper functions are how we resolve jumps in BF.
# Because they require scanning the actual code to resolve, they require a global view of the program's memory.
# Lifters in pyvex only get block-at-a-time access to memory, so we solve this by using a "CCall", which tells VEX
# /angr to execute a side-effect-less function and put the result in a variable.
# We therefore let angr resolve all jumps at "run"-time.
# TODO: FIXME: We need to refactor CCall to be more friendly to adding CCalls.  I will document the process
# here as best I can.


# For the sake of my sanity, the ptr is 64 bits wide.
# By the spec, cells are 8 bits, and do all the usual wrapping stuff.
PTR_TYPE = Type.int_64
CELL_TYPE = Type.int_8
PTR_REG = 'ptr'
INOUT_REG = 'inout'


class Instruction_NOP(Instruction):
    # Convert everything that's not an instruction into a No-op to meet the BF spec
    bin_format = 'xxxxxxxx' # We don't care, match it all
    name = 'nop'

    def parse(self, bitstrm):
        self.last_instruction = False
        data = Instruction.parse(self, bitstrm)
        try:
            bitstrm.peek(8)
        except bitstring.ReadError:
            # We ran off the end!
            self.last_instruction = True
        return data

    def compute_result(self):
        if self.last_instruction:
            self.jump(None, self.constant(self.addr, PTR_TYPE), jumpkind=JumpKind.Exit)


# These are the standard BrainFuck instructions.


class Instruction_INCPTR(Instruction):
    bin_format = bin(ord(">"))[2:].zfill(8)
    name = 'incptr'

    def compute_result(self, *args):
        """
        '>': move the ptr register to the right one cell, or
        ptr += 1
        :param irsb_c:
        :type irsb_c: vex_helpers.IRSBCustomizer
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        ptr += 1
        self.put(ptr, PTR_REG)


class Instruction_DECPTR(Instruction):
    bin_format = bin(ord("<"))[2:].zfill(8)
    name = 'decptr'

    def compute_result(self, *args):
        """
        '<': Move the ptr register to the left one cell, or
        ptr -= 1
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        ptr -= 1
        self.put(ptr, PTR_REG)

class Instruction_INC(Instruction):
    bin_format = bin(ord("+"))[2:].zfill(8)
    name = 'inc'

    def compute_result(self, *args):
        """
        '+': Increment the value of the data memory pointed at by the ptr register, or:
        ptr* += 1

        :type irsb_c: vex_helper.IRSBCustomizer
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        val = self.load(ptr, CELL_TYPE)
        val += 1
        self.store(val, ptr)


class Instruction_DEC(Instruction):
    bin_format = bin(ord("-"))[2:].zfill(8)
    name = 'dec'

    def compute_result(self, *args):
        """
        '-': Increment the data memory value pointed at by the ptr register, or:
        ptr* -= 1
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        val = self.load(ptr, CELL_TYPE)
        val -= 1
        self.store(val, ptr)


class BracketInstruction(Instruction):
    jump_table = {}

    def calculate_jump(self, relevant_instructions):
        bracket_stack = [self]
        if self.addr in self.jump_table:
            return self.jump_table[self.addr]
        for instr in relevant_instructions:
            if isinstance(instr, self.__class__):
                bracket_stack.append(instr)
            elif isinstance(instr, self.closing):
                bracket_stack.pop()
                if len(bracket_stack) == 0:
                    self.jump_table[self.addr] = instr.addr + 1
                    self.jump_table[instr.addr] = self.addr + 1
                    return instr.addr + 1
        if len(bracket_stack) > 0:
            raise Exception('Missing matching %s for %s at address %d' % (self.closing.name, self.name, self.addr))

class Instruction_SKZ(BracketInstruction):
    bin_format = bin(ord("["))[2:].zfill(8)
    name = 'skz'

    def lift(self, irsb_c, past_instructions, future_instructions):
        self.jump_addr = self.calculate_jump(future_instructions)
        BracketInstruction.lift(self, irsb_c, past_instructions, future_instructions)

    def compute_result(self, *args):
        """
        '[': Skip to the matching ], IF the value pointed at by the ptr register is zero.
        The matching ] is defined by pairs of matched braces, not necessarily the next ].

        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        val = self.load(ptr, CELL_TYPE)
        # NOTE: VEX doesn't support non-constant values for conditional exits.
        # What we do to avoid this is to make the default exit of this block the conditional one,
        # and make the other take us to the next instruction.  Therefore, we invert the comparison.
        # Go to the next instruction if *ptr != 0
        next_instr = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(val == 0, next_instr)
        # And go to the next ] if *ptr == 0
        self.jump(None, self.jump_addr)


class Instruction_SKNZ(BracketInstruction):
    bin_format = bin(ord("]"))[2:].zfill(8)
    name = 'sknz'

    def lift(self, irsb_c, past_instructions, future_instructions): # TODO make sure matching brackets has same jump target
        self.jump_addr = self.calculate_jump(past_instructions)
        BracketInstruction.lift(self, irsb_c, past_instructions, future_instructions)

    def compute_result(self, *args):
        """
        ']': Skip to the matching [ backward if the value pointed at by the ptr register is not zero.
        Similar to the above, see that for important notes.
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        val = self.load(ptr, CELL_TYPE)
        next_instr = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(val != 0, next_instr)
        self.jump(None, self.jump_addr) # TODO will this break when stuff is split across blocks?

Instruction_SKZ.closing = Instruction_SKNZ
Instruction_SKNZ.closing = Instruction_SKZ


class Instruction_IN(Instruction):
    bin_format = bin(ord(","))[2:].zfill(8)
    name = 'in'

    def compute_result(self, *args):
        """
        ',': Get one byte from standard input.
        We use a "syscall" here, see simos_bf.py for the SimProcedures that get called.
        :return:
        """
        # Having a 0 in the "inout" register tells VEX to kick off simos_bf.WriteByteToPtr()
        self.put(self.constant(0, PTR_TYPE), INOUT_REG)
        dst = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(None, dst, jumpkind=JumpKind.Syscall)

class Instruction_OUT(Instruction):
    bin_format = bin(ord("."))[2:].zfill(8)
    name = 'out'

    def compute_result(self, *args):
        """
        '.': Get the current value pointed at by the ptr register and print it to stdout
        As above, we use a Syscall / simprocedure to do this
        """
        # Putting a 1 in "inout", executes simos_bf.ReadValueAtPtr()
        self.put(self.constant(1, PTR_TYPE), INOUT_REG)
        # Go to the next instruction after, but set the Syscall jumpkind
        dst = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(None, dst, jumpkind=JumpKind.Syscall)


# The instrs are in this order so we try NOP last.
all_instrs = [
    Instruction_INCPTR,
    Instruction_DECPTR,
    Instruction_INC,
    Instruction_DEC,
    Instruction_SKZ,
    Instruction_SKNZ,
    Instruction_IN,
    Instruction_OUT,
    Instruction_NOP
]


class LifterBF(GymratLifter):
    instrs = all_instrs

# Tell PyVEX that this lifter exists.
register(LifterBF, 'BF')
