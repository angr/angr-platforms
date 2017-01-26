import archinfo
import pyvex
from functools import wraps
from pyvex.expr import *
from pyvex.lift import Lifter, register
from pyvex.lift.util.vex_helper import *
from pyvex.lift.util.irsb_postprocess import irsb_postproc_flatten
import sys
import os

# This is actually a BrainFuck lifter for pyVEX.  I'm not joking.
# Created by edg on 1/14/2017

class InstructionEncoding:
    def __init__(self, name, op, rewriter):
        self.name = name
        self.op = op
        self.rewriter = rewriter


    def __str__(self):
        return "<InstructionEncoding {}: Rewriter: {}>".format(
            self.name, self.rewriter)


class LifterBF(Lifter):

    def __init__(self, irsb, data, num_inst, num_bytes, bytes_offset, traceflags, decode_only=False):
        """
        This is a "gymrat" out-of-VEX lifter for BrainFuck.

        That's right, BrainFuck.

        Will do a one-pass disassembly of your BrainFuck, and return a set of pyvex objects in an
        IRSB.

        """
        self.irsb = irsb
        self.data = data
        self.num_inst = num_inst
        self.num_bytes = num_bytes
        self.bytes_offset = bytes_offset
        self._error = None  # TODO: Update this
        self.arch = archinfo.ArchBF()
        self.decode_only=decode_only

    def lift(self):
        next_addr = self.irsb._addr
        idx = self.bytes_offset
        count = 0
        while idx < len(self.data) and count < self.num_bytes and count < self.num_inst:
            prev_addr = next_addr
            self.irsb,next_addr = self.decode_instruction(self.irsb, next_addr, self.data[idx], decode_only=self.decode_only, return_next=True)
            idx += next_addr - prev_addr
            if not self.decode_only and self.irsb.jumpkind != JumpKind.Invalid:
                return
        if not self.decode_only and self.irsb.jumpkind == JumpKind.Invalid:
            self.irsb.next = Const(U64(addr + 1))
            self.irsb.jumpkind = JumpKind.Boring
        return True

    
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
        tmp_result = irsb_c.mktmp(irsb_c.op_cmp_eq(RdTmp(tmp_val),RdTmp(tmp_zero)))
        irsb_c.irsb.next = pyvex.expr.ITE(RdTmp(tmp_result), Const(U64(addr + 1)), Const(U64(addr + 2)))
        irsb_c.irsb.jumpkind = JumpKind.Boring
        assert irsb_c.irsb.typecheck()
        return irsb_c.irsb

    def _sknz(self, op, irsb_c, addr, args):
        irsb_c.imark(addr, 1, 0)
        tmp_val = irsb_c.mktmp(Load("Iend_LE", Type.byte, Get(self.arch.registers['ptr'][0], Type.int_64)))
        tmp_zero = irsb_c.mktmp(make_const(Type.byte, 0))
        tmp_result = irsb_c.mktmp(irsb_c.op_cmp("NE", RdTmp(tmp_val), RdTmp(tmp_zero)))

        irsb_c.irsb.next = pyvex.expr.ITE(RdTmp(tmp_result), Const(U64(addr + 1)), Const(U64(addr + 2)))
        irsb_c.irsb.jumpkind = JumpKind.Boring
        assert irsb_c.irsb.typecheck()
        return irsb_c.irsb

    def _in(self, op, irsb_c, addr, args):
        irsb_c.imark(addr, 1, 0)
        tmp_one = irsb_c.mktmp(make_const(Type.byte, 0))
        irsb_c.put(RdTmp(tmp_one), self.arch.registers['inout'][0])
        irsb_c.irsb.next = Const(U64(addr + 1))
        irsb_c.irsb.jumpkind = JumpKind.Syscall
        assert irsb_c.irsb.typecheck()
        return irsb_c.irsb

    def _out(self, op, irsb_c, addr, args):
        irsb_c.imark(addr, 1, 0)
        tmp_zero = irsb_c.mktmp(make_const(Type.byte, 0))
        irsb_c.put(RdTmp(tmp_zero), self.arch.registers['inout'][0])
        irsb_c.irsb.next = Const(U64(addr + 2))
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
        Decode an AVR instruction

        :param irsb: an IRSB to decode into
        :type irsb: pyvex.block.IRSB
        :param addr: Address to decode from
        :type addr: long
        :param bytes_buf: Bytes to decode
        :type bytes_buf: str or bytes or cffi.FFI.CData
        :param decode_only: Just print out the decoded instructions
        :parse return_next: Return the next addr to decode, too
        """

        val = bytes_buf[0]
        found_op = None
        for encoding in self.known_instruction_encodings:
            if val != encoding.op:
                continue

            assert found_op is None, "Why does {} match both {} and {}???? Ambiguous opcode definitions!".format(hex(val), found_op, encoding)
            found_op = encoding

        if found_op is None:
            raise ValueError("Invalid instruction at " + hex(addr))
        next_addr = addr+1
        args = {}
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
