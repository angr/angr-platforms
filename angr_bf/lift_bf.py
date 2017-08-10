import archinfo
import pyvex
from functools import wraps
from pyvex.expr import *
from pyvex.lift import Lifter, register
from pyvex.lift.util.vex_helper import *
from pyvex.lift.util.irsb_postprocess import irsb_postproc_flatten
from arch_bf import ArchBF
import sys
import os
import claripy
from angr.engines.vex import ccall
from angr import SimValueError

# This is actually a BrainFuck lifter for pyVEX.  I'm not joking.
# Created by edg on 1/14/2017
# The goal of this, and any other lifter, is to convert one basic block of raw bytes into
# a set of VEX instructions representing what the code does.
# A basic block, in this case is defined a set of instructions terminated by:
# !) a conditional branch
# 2) A function call
# 3) A system call
# 4) the end of the program
#
# We need to build an IRSB, a grouping of VEX code, and associated metadata representing one block.
# This is then used by angr to interpret the program, and angr itself to perform static analysis.

##
# These helper functions are how we resolve jumps in BF.
# Because they require scanning the actual code to resolve, they require a global view of the program's memory.
# Lifters in pyvex only get block-at-a-time access to memory, so we solve this by using a "CCall", which tells VEX
# /angr to execute a side-effect-less function and put the result in a variable.
# We therefore let angr resolve all jumps at "run"-time.
# TODO: FIXME: We need to refactor CCall to be more friendly to adding CCalls.  I will document the process
# here as best I can.


def _build_jump_table(state):
    """
    This is the standard stack algorithm for bracket-matching, which is also how we resolve jumps in BF
    :param state:
    :return:
    """
    jump_table = {}
    jstack = []
    addr = 0
    while True:
        try:
            inst = chr(state.mem_concrete(addr, 1))
        except SimValueError:
            break
        except KeyError:
            break
        if inst == '[':
            jstack.append(addr)
        elif inst == ']':
            try:
                src = jstack.pop()
                dest = addr
                jump_table.update({src: dest + 1})
                jump_table.update({dest: src + 1})
            except IndexError:
                raise ValueError("Extra ] at offset %d" % inst)
        addr += 1
    if jstack:
        raise ValueError("Unmatched [s at: " + ",".join(jstack))
    return jump_table


def bf_resolve_jump(state):
    """
    Resolve the jump at the current IP of the state.
    :param state:
    :return:
    """
    # CCall won't give us the addr of the current instruction, so we have to figure that out.  Ugh.
    real_ip = state.se.eval(state.ip)
    offset = 0
    while True:
        inst = chr(state.mem_concrete(real_ip + offset, 1))
        if inst == "]" or inst == '[':
            addr = real_ip + offset
            break
        offset += 1
    # We don't have a persistent place to compute the jump table, and because brackets can be nested, we must construct
    # the full table each time instead of doing a scan back/forward.
    # Some day, if we ever get a nice place to put this, this should only be computed once.
    jtable = _build_jump_table(state)
    real_ip = state.se.eval(addr)
    try:
        return (claripy.BVV(jtable[real_ip], 64), [])
    except KeyError:
        raise ValueError("There is no entry in the jump table at " + repr(real_ip))
# Add the ccall to the module, so angr knows how to find it.  THis is dirty, I know.
setattr(ccall,'bf_resolve_jump',bf_resolve_jump)


class InstructionEncoding:
    """
    This defines an "encoding" for instructions.  In larger lifters for things other than BF, this becomes
    a really useful abstraction.
    """

    def __init__(self, name, op, rewriter):
        self.name = name
        self.op = op
        self.rewriter = rewriter

    def __str__(self):
        return "<InstructionEncoding {}: Rewriter: {}>".format(
            self.name, self.rewriter)


class LifterBF(Lifter):

    def __init__(self, irsb, data, num_inst, num_bytes, bytes_offset, opt_level=None, traceflags=None, allow_lookback=None, decode_only=False):
        """
        This is a "gymrat" out-of-VEX lifter for BrainFuck.

        That's right, BrainFuck.

        Will do a one-pass disassembly of your BrainFuck, and return a set of pyvex objects in an
        IRSB.

        """
        # Call the parent's constructor
        Lifter.__init__(self, irsb, data, num_inst, num_bytes, bytes_offset, opt_level, traceflags, allow_lookback)
        self.logger = logging.getLogger('pyvex')
        # Our goal, when lifting, is to fill out this IRSB object with instructions, particularly,
        # the "statements" list.
        self.irsb = irsb
        # This is the data we're supposed to lift.  We get the current block onward, to some VEX-specified maximum bytes.
        # Note that this MAY NOT be a string, but instead a cffi.CData, so don't do anything too stringy with it.
        self.data = data
        # THis probably doesn't do what you expect.  Don't use it.
        self.num_inst = num_inst
        # This is how many bytes are in that data object.
        self.num_bytes = num_bytes
        # Offset into the binary in which these bytes were pulled.
        self.bytes_offset = bytes_offset
        self._error = None  # TODO: Update this
        # If we're here, this should be ArchBF.  You may need to do other things if writing your own.
        self.arch = ArchBF()
        # A flag I use for dupming the VEX instructions.
        self.decode_only=decode_only

    def normal_instruction(func):
        """
        A normal instruction.
        All instructions start with the VEX IMark, then some code, followed by a move to the next instruction.
        If this isn't the end of the block, we set the jumpkind to Invalid.

        :return:
        """
        @wraps(func)
        def decor(self, op, irsb_c, addr, args):
            irsb_c.imark(addr, 1, 0)
            r = func(self, op, irsb_c, addr, args)
            r.next = Const(U64(addr + 1))
            r.jumpkind = JumpKind.Invalid
            assert r.typecheck()
            return r
        return decor


    @normal_instruction
    def _nop(self, op, irsb_c, addr, args):
        """
        No-op
        """
        irsb_c.noop()
        return irsb_c.irsb



    # These are the standard BrainFuck instructions, as VEX "re-writers".
    @normal_instruction
    def _incptr(self, op, irsb_c, addr, args):
        """
        '>': move the ptr register to the right one cell, or
        ptr += 1
        :param irsb_c:
        :type irsb_c: vex_helpers.IRSBCustomizer
        """

        tmp_src = irsb_c.mktmp(Get(self.arch.registers['ptr'][0], Type.int_64))
        one = irsb_c.mktmp(make_const(Type.int_64, 1))
        plusone = irsb_c.mktmp(irsb_c.op_add(RdTmp(tmp_src),RdTmp(one)))
        irsb_c.put(RdTmp(plusone), self.arch.registers['ptr'][0])
        return irsb_c.irsb

    @normal_instruction
    def _decptr(self, op, irsb_c, addr, args):
        """
        '<': Move the ptr register to the left one cell, or
        ptr -= 1
        """

        tmp_src = irsb_c.mktmp(Get(self.arch.registers['ptr'][0], Type.int_64))
        one = irsb_c.mktmp(make_const(Type.int_64, 1))
        minusone = irsb_c.mktmp(irsb_c.op_sub(RdTmp(tmp_src), RdTmp(one)))
        irsb_c.put(RdTmp(minusone), self.arch.registers['ptr'][0])
        return irsb_c.irsb

    @normal_instruction
    def _inc(self, op, irsb_c, addr, args):
        """
        '+': Increment the value of the data memory pointed at by the ptr register, or:
        ptr* += 1

        :type irsb_c: vex_helper.IRSBCustomizer
        """

        tmp_val = irsb_c.mktmp(Load("Iend_LE",Type.byte,Get(self.arch.registers['ptr'][0], Type.int_64)))
        tmp_one = irsb_c.mktmp(make_const(Type.byte, 1))
        tmp_added = irsb_c.mktmp(irsb_c.op_add(RdTmp(tmp_val), RdTmp(tmp_one)))
        irsb_c.store(Get(self.arch.registers['ptr'][0], Type.int_64), RdTmp(tmp_added), 'Iend_LE')
        return irsb_c.irsb

    @normal_instruction
    def _dec(self, op, irsb_c, addr, args):
        """
        '+': Increment the data memory value pointed at by the ptr register, or:
        ptr* -= 1
        """
        tmp_val = irsb_c.mktmp(Load("Iend_LE", Type.byte, Get(self.arch.registers['ptr'][0], Type.int_64)))
        tmp_one = irsb_c.mktmp(make_const(Type.byte, 1))
        tmp_subbed = irsb_c.mktmp(irsb_c.op_sub(RdTmp(tmp_val), RdTmp(tmp_one)))
        irsb_c.store(Get(self.arch.registers['ptr'][0], Type.int_64), RdTmp(tmp_subbed), 'Iend_LE')
        return irsb_c.irsb

    def _skz(self, op, irsb_c, addr, args):
        """
        '[': Skip to the matching ], IF the value pointed at by the ptr register is zero.
        The matching ] is defined by pairs of matched braces, not necessarily the next ].

        """

        irsb_c.imark(addr, 1, 0)

        tmp_val = irsb_c.mktmp(Load("Iend_LE", Type.byte, Get(self.arch.registers['ptr'][0], Type.int_64)))
        tmp_zero = irsb_c.mktmp(make_const(Type.byte, 0))
        # NOTE: VEX doesn't support non-constant values for conditional exits.
        # What we do to avoid this is to make the default exit of this block the conditional one,
        # and make the other take us to the next instruction.  Therefore, we invert the comparison.
        cmp = irsb_c.op_cmp("NE", RdTmp(tmp_val),RdTmp(tmp_zero))
        # We use a "CCall" to let VEX resolve these at "run"-time, since we may not be able to see the ]
        # This uses the above helper functions to find the matching ]
        dst = irsb_c.mktmp(irsb_c.op_ccall(Type.int_64, "bf_resolve_jump", []))
        jk = JumpKind.Boring
        # Go to the next instruction if *ptr == 0
        irsb_c.add_exit(cmp, U64(addr + 1), jk, addr)
        irsb_c.irsb.next = RdTmp(dst)
        irsb_c.irsb.jumpkind = JumpKind.Boring

        assert irsb_c.irsb.typecheck()
        return irsb_c.irsb

    def _sknz(self, op, irsb_c, addr, args):
        """
        ']': Skip to the matching [ backward if the value pointed at by the ptr register is not zero.
        Similar to the above, see that for important notes.
        """
        irsb_c.imark(addr, 1, 0)
        tmp_val = irsb_c.mktmp(Load("Iend_LE", Type.byte, Get(self.arch.registers['ptr'][0], Type.int_64)))
        tmp_zero = irsb_c.mktmp(make_const(Type.byte, 0))
        cmp = irsb_c.op_cmp_eq(RdTmp(tmp_val), RdTmp(tmp_zero))
        dst = irsb_c.mktmp(irsb_c.op_ccall(Type.int_64, "bf_resolve_jump", []))
        jk = JumpKind.Boring
        irsb_c.add_exit(cmp, U64(addr + 1), jk, addr)
        irsb_c.irsb.next = RdTmp(dst)
        irsb_c.irsb.jumpkind = JumpKind.Boring
        assert irsb_c.irsb.typecheck()
        return irsb_c.irsb

    def _in(self, op, irsb_c, addr, args):
        """
        ',': Get one byte from standard input.
        We use a "syscall" here, see simos_bf.py for the SimProcedures that get called.
        :return:
        """
        irsb_c.imark(addr, 1, 0)
        tmp_one = irsb_c.mktmp(make_const(Type.byte, 1))
        # Having a 1 in the "inout" register tells VEX to kick off simos_bf.WriteByteToPtr()
        irsb_c.put(RdTmp(tmp_one), self.arch.registers['inout'][0])
        irsb_c.irsb.next = Const(U64(addr + 1))
        irsb_c.irsb.jumpkind = JumpKind.Syscall
        assert irsb_c.irsb.typecheck()
        return irsb_c.irsb

    def _out(self, op, irsb_c, addr, args):
        """
        '.': Get the current value pointed at by the ptr register and print it to stdout
        As above, we use a Syscall / simprocedure to do this
        """
        irsb_c.imark(addr, 1, 0)

        tmp_zero = irsb_c.mktmp(make_const(Type.byte, 0))
        # Putting a 0 in "inout", executes simos_bf.ReadValueAtPtr()
        irsb_c.put(RdTmp(tmp_zero), self.arch.registers['inout'][0])
        irsb_c.irsb.next = Const(U64(addr + 1))
        irsb_c.irsb.jumpkind = JumpKind.Syscall
        assert irsb_c.irsb.typecheck()
        return irsb_c.irsb

    def _pp(self, op, irsb_c, addr, args):
        """A pretty-printer for debugging"""
        s = "%s %s " % (hex(addr), op.name)
        print s

    def _unimplemented(self, op, irsb_c, addr, args):
        raise NotImplementedError('Rewriter for Opcode {} at address {} with args {} was not implemented yet!'.format(op, addr, args))

    # This is our "decoder", mapping the values in the data buffer to instruction names, and their rewriters.
    # You'll need something more complex, probably involving bitmasks and instruction formats,
    # for a real architecture.
    known_instruction_encodings = {
        InstructionEncoding('incptr', ">", _incptr),
        InstructionEncoding('decptr', "<", _decptr),
        InstructionEncoding('inc', "+", _inc),
        InstructionEncoding('dec', "-", _dec),
        InstructionEncoding('in', ".", _in),
        InstructionEncoding('out', ",", _out),
        InstructionEncoding('skz', "[", _skz),
        InstructionEncoding('sknz', "]", _sknz),
    }

    def decode_instruction(self, irsb, addr, bytes_buf, endness=None, decode_only=False):
        """
        Decode a BF instruction

        :param irsb: an IRSB to decode into
        :type irsb: pyvex.block.IRSB
        :param addr: Address to decode from
        :type addr: long
        :param bytes_buf: Bytes to decode
        :type bytes_buf: str or bytes or cffi.FFI.CData
        :param decode_only: Just print out the decoded instructions
        """

        # First, let's make sure everything's a string.
        # Depending on how the lifter is called, this may not be true (e.g., a CData as the data)
        if isinstance(bytes_buf, int):
            val = chr(bytes_buf)
        else:
            val = bytes_buf

        found_op = None
        args = {}
        for encoding in self.known_instruction_encodings:
            if val != encoding.op:
                continue
            # It's a good best-practice to have this here, for larger ISAs.
            assert found_op is None, "Why does {} match both {} and {}???? Ambiguous opcode definitions!".format(
                hex(val), found_op, encoding)
            found_op = encoding

        next_addr = addr + 1
        if val == '\0':
            # CLE puts a null at the end.  we're done
            self.logger.debug("Program ended at " + hex(addr))
            rewriter_ = LifterBF._nop
            irsb = rewriter_(self, found_op, IRSBCustomizer(irsb), addr, args)
            irsb.jumpkind = JumpKind.Exit
            return irsb, next_addr
        elif found_op is None:
            # Technically, BF can have all kinds of stuff in it that isn't code, and only the
            # actual instructions get interpreted.  This allows for that.
            self.logger.debug("Replacing invalid instruction with NOP at " + hex(addr))
            rewriter_ = LifterBF._nop
        elif decode_only:
            rewriter_ = LifterBF._pp
        else:
            rewriter_ = found_op.rewriter

        return rewriter_(self, found_op, IRSBCustomizer(irsb), addr, args), next_addr

    def lift(self):
        """
        This is the method called by pyvex and angr to convert the bytes in self.data into
        the VEX code in self.irsb.statements.

        :return:
        """
        # The IRSB knows what addr to start at, so start there.
        next_addr = self.irsb._addr
        idx = self.bytes_offset
        count = 0
        while count < self.num_bytes:
            prev_addr = next_addr
            # We get the IRSB, as well as the next address we should look at.
            # In the case of BF, this is always the next byte.  In the case of a variable-width
            # instruction set, you'd need to fiddle with this.
            self.irsb, next_addr = self.decode_instruction(self.irsb, next_addr, self.data[idx], decode_only=self.decode_only)
            idx += next_addr - prev_addr
            # I use the convention of setting the JumpKind to INVALID when the block isn't done.
            if not self.decode_only and self.irsb.jumpkind != JumpKind.Invalid:
                # The block is over, get out
                return self.irsb
        if not self.decode_only and self.irsb.jumpkind == JumpKind.Invalid:
            # The program is over, get out
            self.irsb.next = Const(U64(addr + 1))
            self.irsb.jumpkind = JumpKind.Exit
        return self.irsb


# Tell PyVEX that this lifter exists.
register(LifterBF)

if __name__ == '__main__':
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    import logging
    logging.getLogger('pyvex').setLevel(logging.DEBUG)
    logging.basicConfig()

    irsb_ = pyvex.IRSB(None, 0, arch=archinfo.arch_from_id('bf'))
    test1 = '<>+-[].,'
    test2 = '<>+-[].,'
    lifter = LifterBF(irsb_, test1,len(test1) , len(test1), 0, None,  decode_only=True)
    lifter.lift()
    irsb_ = pyvex.IRSB(None, 0, arch=archinfo.ArchBF())
    lifter = LifterBF(irsb_, test2, len(test2),len(test2),0,  None)
    lifter.lift()
    lifter.irsb.pp()

    i = pyvex.IRSB(test1, 0x0, arch=archinfo.ArchBF())
