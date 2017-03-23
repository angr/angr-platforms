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
from simuvex.engines.vex import ccall
from simuvex import SimValueError

# This is actually a BrainFuck lifter for pyVEX.  I'm not joking.
# Created by edg on 1/14/2017

# TODO: FIXME: We need to refactor CCall

def _build_jump_table(state):
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
    real_ip = state.se.any_int(state.ip)
    offset = 0
    while True:
        inst = chr(state.mem_concrete(real_ip + offset, 1))
        if inst == "]" or inst == '[':
            addr = real_ip + offset
            break
        offset += 1
    jtable = _build_jump_table(state)
    real_ip = state.se.any_int(addr)
    try:
        return (claripy.BVV(jtable[real_ip], 64), [])
    except KeyError:
        raise ValueError("There is no entry in the jump table at " + repr(real_ip))
# This is really dirty and I feel bad about it.
setattr(ccall,'bf_resolve_jump',bf_resolve_jump)


class InstructionEncoding:
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
        Lifter.__init__(self, irsb, data, num_inst, num_bytes, bytes_offset, opt_level, traceflags, allow_lookback)
        self.logger = logging.getLogger('pyvex')
        self.irsb = irsb
        self.data = data
        self.num_inst = num_inst
        self.num_bytes = num_bytes
        self.bytes_offset = bytes_offset
        self._error = None  # TODO: Update this
        self.arch = ArchBF()
        self.decode_only=decode_only

    def lift(self):
        next_addr = self.irsb._addr
        idx = self.bytes_offset
        count = 0
        while count < self.num_bytes:
            prev_addr = next_addr
            self.irsb,next_addr = self.decode_instruction(self.irsb, next_addr, self.data[idx], decode_only=self.decode_only, return_next=True)
            idx += next_addr - prev_addr
            if not self.decode_only and self.irsb.jumpkind != JumpKind.Invalid:
                # The block is over, get out
                return self.irsb
        if not self.decode_only and self.irsb.jumpkind == JumpKind.Invalid:
            # The program is over, get out
            self.irsb.next = Const(U64(addr + 1))
            self.irsb.jumpkind = JumpKind.Exit
        return self.irsb

    #################################
    #        Some helper wrappers   #
    #################################

    def normal_instruction(func):
            @wraps(func)
            def decor(self, op, irsb_c, addr, args):
                irsb_c.imark(addr, 1, 0)
                r = func(self, op, irsb_c, addr, args)
                r.next = Const(U64(addr + 1))
                r.jumpkind = JumpKind.Invalid
                assert r.typecheck()
                return r
            return decor

    #################################
    #         VEX Rewriters         #
    #################################

    @normal_instruction
    def _nop(self, op, irsb_c, addr, args):
        """
        No-op
        """
        irsb_c.noop()
        return irsb_c.irsb

    @normal_instruction
    def _incptr(self, op, irsb_c, addr, args):
        """
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
        ptr* -= 1
        """
        tmp_val = irsb_c.mktmp(Load("Iend_LE", Type.byte, Get(self.arch.registers['ptr'][0], Type.int_64)))
        tmp_one = irsb_c.mktmp(make_const(Type.byte, 1))
        tmp_subbed = irsb_c.mktmp(irsb_c.op_sub(RdTmp(tmp_val), RdTmp(tmp_one)))
        irsb_c.store(Get(self.arch.registers['ptr'][0], Type.int_64), RdTmp(tmp_subbed), 'Iend_LE')
        return irsb_c.irsb

    def _skz(self, op, irsb_c, addr, args):
        irsb_c.imark(addr, 1, 0)
        tmp_val = irsb_c.mktmp(Load("Iend_LE", Type.byte, Get(self.arch.registers['ptr'][0], Type.int_64)))
        tmp_zero = irsb_c.mktmp(make_const(Type.byte, 0))
        cmp = irsb_c.op_cmp("NE", RdTmp(tmp_val),RdTmp(tmp_zero))
        # find the ]
        dst = irsb_c.mktmp(irsb_c.op_ccall(Type.int_64, "bf_resolve_jump", []))
        jk = JumpKind.Boring
        irsb_c.add_exit(cmp, U64(addr + 1), jk, addr)
        irsb_c.irsb.next = RdTmp(dst)
        irsb_c.irsb.jumpkind = JumpKind.Boring
        if not irsb_c.irsb.typecheck():
            irsb_c.irsb.pp()
        assert irsb_c.irsb.typecheck()
        return irsb_c.irsb

    def _sknz(self, op, irsb_c, addr, args):
        irsb_c.imark(addr, 1, 0)
        tmp_val = irsb_c.mktmp(Load("Iend_LE", Type.byte, Get(self.arch.registers['ptr'][0], Type.int_64)))
        tmp_zero = irsb_c.mktmp(make_const(Type.byte, 0))
        cmp = irsb_c.op_cmp_eq(RdTmp(tmp_val), RdTmp(tmp_zero))
        dst = irsb_c.mktmp(irsb_c.op_ccall(Type.int_64, "bf_resolve_jump", []))
        jk = JumpKind.Boring
        irsb_c.add_exit(cmp, U64(addr + 1), jk, addr)
        irsb_c.irsb.next = RdTmp(dst)
        irsb_c.irsb.jumpkind = JumpKind.Boring
        if not irsb_c.irsb.typecheck():
            irsb_c.irsb.pp()
        assert irsb_c.irsb.typecheck()
        return irsb_c.irsb

    def _in(self, op, irsb_c, addr, args):
        irsb_c.imark(addr, 1, 0)
        tmp_one = irsb_c.mktmp(make_const(Type.byte, 1))
        irsb_c.put(RdTmp(tmp_one), self.arch.registers['inout'][0])
        irsb_c.irsb.next = Const(U64(addr + 1))
        irsb_c.irsb.jumpkind = JumpKind.Syscall
        assert irsb_c.irsb.typecheck()
        return irsb_c.irsb

    def _out(self, op, irsb_c, addr, args):
        irsb_c.imark(addr, 1, 0)
        tmp_zero = irsb_c.mktmp(make_const(Type.byte, 0))
        irsb_c.put(RdTmp(tmp_zero), self.arch.registers['inout'][0])
        irsb_c.irsb.next = Const(U64(addr + 1))
        irsb_c.irsb.jumpkind = JumpKind.Syscall
        assert irsb_c.irsb.typecheck()
        return irsb_c.irsb

    def _pp(self, op, irsb_c, addr, args):
        s = "%s %s " % (hex(addr), op.name)
        print s

    def _unimplemented(self, op, irsb_c, addr, args):
        raise NotImplementedError('Rewriter for Opcode {} at address {} with args {} was not implemented yet!'.format(op, addr, args))


    #################################
    #      Instruction Decoder      #
    #################################
    # For reference:

    known_instruction_encodings = {
        InstructionEncoding('incptr',">",_incptr),
        InstructionEncoding('decptr',"<",_decptr),
        InstructionEncoding('inc', "+", _inc),
        InstructionEncoding('dec', "-", _dec),
        InstructionEncoding('in', ".", _in),
        InstructionEncoding('out',",", _out),
        InstructionEncoding('skz',"[", _skz),
        InstructionEncoding('sknz',"]", _sknz),
    }

    def decode_instruction(self, irsb, addr, bytes_buf, endness=None, decode_only=False, return_next=False):
        """
        Decode a BF instruction

        :param irsb: an IRSB to decode into
        :type irsb: pyvex.block.IRSB
        :param addr: Address to decode from
        :type addr: long
        :param bytes_buf: Bytes to decode
        :type bytes_buf: str or bytes or cffi.FFI.CData
        :param decode_only: Just print out the decoded instructions
        :parse return_next: Return the next addr to decode, too
        """
        if isinstance(bytes_buf,int):
            val = chr(bytes_buf)
        else:
            val = bytes_buf
        found_op = None
        args = {}
        for encoding in self.known_instruction_encodings:
            if val != encoding.op:
                continue

            assert found_op is None, "Why does {} match both {} and {}???? Ambiguous opcode definitions!".format(hex(val), found_op, encoding)
            found_op = encoding
        next_addr = addr + 1
        if val == '\0':
            # we're done
            self.logger.debug("Program ended at " + hex(addr))
            rewriter_ = LifterBF._nop
            irsb = rewriter_(self, found_op, IRSBCustomizer(irsb), addr, args)
            irsb.jumpkind = JumpKind.Exit
            return irsb, next_addr
        if found_op is None:
            self.logger.debug("Replacing invalid instruction with NOP at " + hex(addr))
            rewriter_ = LifterBF._nop
        rewriter_ = found_op.rewriter
        if decode_only:
            rewriter_ = LifterBF._pp
        if return_next:
            r = rewriter_(self, found_op, IRSBCustomizer(irsb), addr, args), next_addr
            return r
        else:
            return rewriter_(self, found_op, IRSBCustomizer(irsb), addr, args)

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
    #flattened = irsb_postproc_flatten(irsb_)
    #flattened.pp()
