import abc
from .arch_msp430 import ArchMSP430
from pyvex.lifting.util import Instruction, JumpKind, ParseError, Type
import bitstring
from bitstring import Bits
import logging
l = logging.getLogger(__name__)

REGISTER_TYPE = Type.int_16
BYTE_TYPE = Type.int_8
INDEX_TYPE = Type.int_16
STATUS_REG_IND = 2
CARRY_BIT_IND = 0
NEGATIVE_BIT_IND = 2
ZERO_BIT_IND = 1
OVERFLOW_BIT_IND = 8

##
## NOTE: The bitstream legend for this arch is:
# s: source
# d: destination
# A: source addressing mode
# a: destination addressing mode
# S: Extension word source immediate
# D: extension word destination immediate
# b: byte/word flag
# o: opcode
# O: Offset immediate


# Lots of things are going to be interpreted as signed immediates. Here's a quickie to load them
def bits_to_signed_int(s):
    return Bits(bin=s).int

class MSP430Instruction(Instruction):
    opcode = None
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.commit_func = None

    # Default flag handling
    def zero(self, *args):
        #pylint: disable=unused-argument
        retval = args[-1]
        return retval == self.constant(0, retval.ty)

    def negative(self, *args):
        #pylint: disable=unused-argument
        retval = args[-1]
        return retval[15] if self.data['b'] == '0' else retval[7]

    def carry(self, *args):
        #pylint: disable=unused-argument,no-self-use
        return None

    def overflow(self, *args):
        #pylint: disable=unused-argument,no-self-use
        return None

    # Some common stuff we use around

    def get_sr(self):
        return self.get('sr', REGISTER_TYPE)

    def get_pc(self):
        return self.get('pc', REGISTER_TYPE)

    def put_sr(self, val):
        return self.put(val, 2)

    def get_carry(self):
        return self.get_sr()[CARRY_BIT_IND]

    def get_zero(self):
        return self.get_sr()[ZERO_BIT_IND]

    def get_negative(self):
        return self.get_sr()[NEGATIVE_BIT_IND]

    def get_overflow(self):
        return self.get_sr()[OVERFLOW_BIT_IND]

    def commit_result(self, res):
        #pylint: disable=not-callable
        if self.commit_func is not None:
            self.commit_func(res)

    def match_instruction(self, data, bitstrm):
        # NOTE: The matching behavior for instructions is a "try-them-all-until-it-fits" approach.
        # Static bits are already checked, so we just look for the opcode.
        if data['o'] != self.opcode:
            raise ParseError("Invalid opcode, expected %s, got %s" % (self.opcode, data['o']))
        return True

    def parse(self, bitstrm):
        """
        MSP430 instructions can have one or two extension words for 16 bit immediates
        We therefore extend the normal parsing so that we make sure we can
        get another word if we have to.
        """
        data = Instruction.parse(self, bitstrm)
        data['S'] = None
        data['D'] = None
        # We don't always have a source or destination.
        # Theoretically I could put these in the TypeXInstruction classes, but
        # I'm lazy. Note that we resolve these here, as opposed to later, due to
        # needing to fiddle with the bitstream.
        l.debug(data)
        if 's' in data:
            src_mode = int(data['A'], 2)
            if (src_mode == ArchMSP430.Mode.INDEXED_MODE and data['s'] != '0011') \
                    or (data['s'] == '0000' and src_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE):
                data['S'] = bitstring.Bits(uint=bitstrm.read('uintle:16'), length=16).bin
                self.bitwidth += 16 # pylint: disable=no-member
        if 'd' in data:
            dst_mode = int(data['a'], 2)
            if dst_mode == ArchMSP430.Mode.INDEXED_MODE:
                data['D'] = bitstring.Bits(uint=bitstrm.read('uintle:16'), length=16).bin
                self.bitwidth += 16 # pylint: disable=no-member
        return data

    def compute_flags(self, *args):
        """
        Compute the flags touched by each instruction
        and store them in the status register
        """
        z = self.zero(*args)
        n = self.negative(*args)
        c = self.carry(*args) # pylint: disable=assignment-from-no-return,assignment-from-none
        o = self.overflow(*args) # pylint: disable=assignment-from-no-return,assignment-from-none
        self.set_flags(z, n, c, o)

    def set_flags(self, z, n, c, o):
        # TODO: FIXME: This isn't actually efficient.
        if not z and not o and not c and not n:
            return
        flags = [(z, ZERO_BIT_IND, 'Z'),
                 (n, NEGATIVE_BIT_IND, 'N'),
                 (o, OVERFLOW_BIT_IND, 'V'),
                 (c, CARRY_BIT_IND, 'C')]
        sreg = self.get_sr()
        for flag, offset, _ in flags:
            if flag:
                sreg = sreg & ~(1 << offset) | (flag.cast_to(Type.int_16) << offset).cast_to(sreg.ty)
        self.put_sr(sreg)

    ##
    ## Functions for dealing with MSP430's complex addressing modes
    ##

    def decorate_src(self, src_bits, mode_bits, imm_bits):
        """
        Computes the decorated source operand for disassembly
        """
        src = ArchMSP430.register_index[int(src_bits, 2)]
        src_mode = int(mode_bits, 2)
        # Load the immediate word
        src_imm = None
        if imm_bits:
            src_imm = bits_to_signed_int(imm_bits)
        # Symbolic and Immediate modes use the PC as the source.
        if src == 'pc':
            if src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.SYMBOLIC_MODE
            elif src_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
                src_mode = ArchMSP430.Mode.IMMEDIATE_MODE
        # Resolve the constant generator stuff.
        elif src == 'cg':
            if src_mode == ArchMSP430.Mode.REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE0
            elif src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE1
            elif src_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE2
            else:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE_NEG1
        # If you use the SR as the source. things get weird.
        elif src == 'sr':
            if src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.ABSOLUTE_MODE
            elif src_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE4
            elif src_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE8
        # Fetch constants
        if src_mode == ArchMSP430.Mode.CONSTANT_MODE0:
            src_str = "#0"
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE1:
            src_str = "#1"
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE2:
            src_str = "#2"
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE4:
            src_str = "#4"
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE8:
            src_str = "#8"
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE_NEG1:
            src_str = "#-1"
        # Fetch immediate.
        elif src_mode == ArchMSP430.Mode.IMMEDIATE_MODE:
            src_str = str(bits_to_signed_int(imm_bits))
        # Symbolic mode: Add the immediate to the PC
        elif src_mode == ArchMSP430.Mode.SYMBOLIC_MODE:
            src_str = "%s+%d" % (src, bits_to_signed_int(imm_bits))
        else:
            # Register mode can write-out to the source for one-operand, so set the writeout
            src_str = self.decorate_reg(src, src_mode, src_imm)
        return src_str

    def fetch_src(self, src_bits, mode_bits, imm_bits, ty):
        """
        Fetch the ``source'' operand of an instruction.
        Returns the source as a VexValue, and, if it exists, a function for how it can be written
        to if needed (e.g., one-operand instructions)
        :param src_bits: bit-string of the src
        :param mode_bits: bit-string of the mode
        :param imm_bits: bit-string of the immediate
        :param ty: The type to use (the byte type or word type)
        :return: The src as a VexValue, and a lambda describing how to write to it if necessary
        """
        src_num = int(src_bits, 2)
        src_name = ArchMSP430.register_index[src_num]
        src_mode = int(mode_bits, 2)
        writeout = None
        # Load the immediate word
        src_imm = None
        if imm_bits:
            src_imm = bits_to_signed_int(imm_bits)
        # Symbolic and Immediate modes use the PC as the source.
        if src_name == 'pc':
            if src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.SYMBOLIC_MODE
            elif src_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
                src_mode = ArchMSP430.Mode.IMMEDIATE_MODE
        # Resolve the constant generator stuff.
        elif src_name == 'cg':
            if src_mode == ArchMSP430.Mode.REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE0
            elif src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE1
            elif src_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE2
            else:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE_NEG1
        # If you use the SR as the source. things get weird.
        elif src_name == 'sr':
            if src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.ABSOLUTE_MODE
            elif src_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE4
            elif src_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE8
        # Fetch constants
        if src_mode == ArchMSP430.Mode.CONSTANT_MODE0:
            src_vv = self.constant(0, ty)
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE1:
            src_vv = self.constant(1, ty)
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE2:
            src_vv = self.constant(2, ty)
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE4:
            src_vv = self.constant(4, ty)
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE8:
            src_vv = self.constant(8, ty)
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE_NEG1:
            src_vv = self.constant(-1, ty)
        # Fetch immediate.
        elif src_mode == ArchMSP430.Mode.IMMEDIATE_MODE:
            src_vv = self.constant(bits_to_signed_int(imm_bits), ty)
        # Symbolic mode: Add the immediate to the PC
        elif src_mode == ArchMSP430.Mode.SYMBOLIC_MODE:
            src_vv = self.get(src_num, Type.int_16) + bits_to_signed_int(imm_bits) + 2
        else:
            # Register mode can write-out to the source for one-operand, so set the writeout
            src_vv, writeout = self.fetch_reg(src_num, src_mode, src_imm, ty)
        return src_vv, writeout

    def decorate_dst(self, dst_bits, mode_bits, imm_bits):
        """
        Computes the decorated destination operand for disassembly
        """
        dst = ArchMSP430.register_index[int(dst_bits, 2)]
        dst_mode = int(mode_bits, 2)
        dst_imm = None
        # Using sr as the dst enables "absolute addressing"
        if dst == 'sr' and dst_mode == ArchMSP430.Mode.INDEXED_MODE:
            dst_mode = ArchMSP430.Mode.ABSOLUTE_MODE
        if imm_bits:
            dst_imm = bits_to_signed_int(imm_bits)

        # two-op instructions always have a dst
        dst_str = self.decorate_reg(dst, dst_mode, dst_imm)
        # val = val.cast_to(ty)
        return dst_str

    def fetch_dst(self, dst_bits, mode_bits, imm_bits, ty, do_fetch=True):
        """
        Fetch the destination argument.
        :param dst_bits:
        :param mode_bits:
        :param imm_bits:
        :param ty:
        :param do_fetch:
        :return: The VexValue representing the destination (if do_fetch is set;
                 else None), and the writeout function for it
        """
        dst_num = int(dst_bits, 2)
        dst_name = ArchMSP430.register_index[dst_num]
        dst_mode = int(mode_bits, 2)
        dst_imm = None
        # Using sr as the dst enables "absolute addressing"
        if dst_name == 'sr' and dst_mode == ArchMSP430.Mode.INDEXED_MODE:
            dst_mode = ArchMSP430.Mode.ABSOLUTE_MODE
        if imm_bits:
            dst_imm = int(imm_bits, 2)

        # two-op instructions always have a dst and a writeout
        val, writeout = self.fetch_reg(dst_num, dst_mode, dst_imm, ty, do_fetch)
        # val = val.cast_to(ty)
        return val, writeout

    def decorate_reg(self, reg_name, reg_mode, imm):
        # pylint: disable=no-self-use
        """
        Decorate the register argument used for disassembly
        """

        # Boring register mode.  A write is just a Put.
        if reg_mode == ArchMSP430.Mode.REGISTER_MODE:
            reg_str = reg_name
        # Indexed mode, add the immediate to the register
        elif reg_mode == ArchMSP430.Mode.INDEXED_MODE:
            reg_str = "%d(%s)" % (imm, reg_name)
        # Indirect mode; fetch address in register; store is a write there.
        elif reg_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
            reg_str = "@%s" % reg_name
        # Indirect Autoincrement mode. Increment the register by the type size, then access it
        elif reg_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
            reg_str = "@%s+" % reg_name
        elif reg_mode == ArchMSP430.Mode.ABSOLUTE_MODE:
            reg_str = imm
        else:
            raise Exception('Unknown mode found')
        return reg_str

    def fetch_reg(self, reg_num, reg_mode, imm, ty, do_fetch=True):
        """
        Resolve the operand for register-based modes.
        :param reg_num: The Register Number
        :param reg_mode: The Register Mode
        :param imm: The immediate word, if any
        :param ty: The Type (byte or word)
        :return: The VexValue of the operand, and the writeout function, if any.
        """
        val = None
        # Boring register mode.  A write is just a Put.
        if reg_mode == ArchMSP430.Mode.REGISTER_MODE:
            # Fetch the register
            if do_fetch:
                val = self.get(reg_num, ty)
            writeout = lambda v: self.put(v.cast_to(REGISTER_TYPE), reg_num)
        # Indexed mode, add the immediate to the register
        # A write here is a store to reg + imm
        elif reg_mode == ArchMSP430.Mode.INDEXED_MODE:
            # Fetch the register
            reg_vv = self.get(reg_num, REGISTER_TYPE)
            addr_val = reg_vv + imm
            if do_fetch:
                val = self.load(addr_val, ty)
            writeout = lambda v: self.store(v, addr_val)
        # Indirect mode; fetch address in register; store is a write there.
        elif reg_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
            # Fetch the register
            reg_vv = self.get(reg_num, REGISTER_TYPE)
            if do_fetch:
                val = self.load(reg_vv, ty)
            writeout = lambda v: self.store(v, reg_vv)
        # Indirect Autoincrement mode. Increment the register by the type size, then access it
        elif reg_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
            if ty == Type.int_16:
                incconst = self.constant(2, REGISTER_TYPE)
            else:
                incconst = self.constant(1, REGISTER_TYPE)
            # Fetch the register
            reg_vv = self.get(reg_num, REGISTER_TYPE)
            # Do the increment, now
            self.put(reg_vv + incconst, reg_num)
            # Now load it.
            if do_fetch:
                val = self.load(reg_vv, ty)
            writeout = lambda v: self.store(v, reg_num)
        elif reg_mode == ArchMSP430.Mode.ABSOLUTE_MODE:
            imm_vv = self.constant(imm, REGISTER_TYPE)
            if do_fetch:
                val = self.load(imm_vv, ty)
            writeout = lambda v: self.store(v, imm_vv)
        else:
            raise Exception('Unknown mode found')
        return val, writeout

    # The TypeXInstruction classes will do this.
    @abc.abstractmethod
    def fetch_operands(self):
        pass

##
## MSP430 has three instruction "types" (which type is which varies depending on which docs you read)
## These define the formats, and number of arguments.
## Here are the classes for those:
##

class Type1Instruction(MSP430Instruction):
    # A single argument
    bin_format = "000100ooobAAssss"

    def disassemble(self):
        self.name = self.name if self.data['b'] == '0' else self.name + ".b"
        src = self.decorate_src(self.data['s'], self.data['A'], self.data['S'])
        return self.addr, self.name, [src, ]

    @abc.abstractmethod
    def compute_result(self, src):
        # pylint: disable=arguments-differ
        pass

    def fetch_operands(self):
        ty = Type.int_16 if self.data['b'] == '0' else Type.int_8
        src, self.commit_func = self.fetch_src(self.data['s'], self.data['A'], self.data['S'], ty)
        return (src, )


class Type2Instruction(MSP430Instruction):
    # No argument; jumps and branches
    bin_format = "001oooOOOOOOOOOO"

    def disassemble(self):
        return self.addr, self.name, ["$" + str((bits_to_signed_int(self.data['O']) + 1) * 2)]

    # No flags for all of type2
    def compute_flags(self, *args):
        pass

    @abc.abstractmethod
    def compute_result(self, offset):
        # pylint: disable=arguments-differ
        pass

    def fetch_operands(self):
        dst = self.addr + ((bits_to_signed_int(self.data['O']) + 1) * 2)
        return (self.constant(dst, Type.int_16), )


class Type3Instruction(MSP430Instruction):
    # Two arguments
    bin_format = 'oooossssabAAdddd'

    def disassemble(self):
        self.name = self.name if self.data['b'] == '0' else self.name + ".b"
        src = self.decorate_src(self.data['s'], self.data['A'], self.data['S'])
        dst = self.decorate_dst(self.data['d'], self.data['a'], self.data['D'])
        return self.addr, self.name, [src, dst]

    @abc.abstractmethod
    def compute_result(self, src, dst):
        # pylint: disable=arguments-differ
        pass

    def fetch_operands(self, do_fetch=True):
        ty = Type.int_16 if self.data['b'] == '0' else Type.int_8
        src, _ = self.fetch_src(self.data['s'], self.data['A'], self.data['S'], ty)
        dst, self.commit_func = self.fetch_dst(self.data['d'], self.data['a'], self.data['D'], ty, do_fetch)
        return src, dst

##
## Single Operand Instructions (type 1)
##


class Instruction_RRC(Type1Instruction):
    # Rotate Right logical with carry-in.
    opcode = "000"
    name = 'rrc'

    def compute_result(self, src):
        # Get carry-in
        carryin = self.get_carry().cast_to(src.ty)
        # Do it
        src >>= 1
        # Put the carry-in in the right place
        if self.data['b'] == '1':
            src[7] = carryin
        else:
            src[15] = carryin
        # Write it out
        return src

    def carry(self, src, ret):
        # pylint: disable=arguments-differ
        return src[0]


class Instruction_SWPB(Type1Instruction):
    # Swap byte halves.  No B/W forms.
    opcode = '001'
    name = 'swpb'

    def compute_result(self, src):
        low_half = src.cast_to(Type.int_8).cast_to(Type.int_16) << self.constant(8, Type.int_8) # FIXME: TODO:
        high_half = src >> 8
        return high_half | low_half


class Instruction_RRA(Type1Instruction):
    # Rotate Right Arithmetic.  Right shift with sign-extend.
    opcode = "010"
    name = 'rra'

    def compute_result(self, src):
        # Do it
        src >>= 1
        # A shitty sign-extend
        if self.data['b'] == '1':
            src[7] = src[6]
        else:
            src[15] = src[14]
        return src

    def carry(self, src, ret):
        # pylint: disable=arguments-differ
        return src[0]


class Instruction_SXT(Type1Instruction):
    # Sign extend 8 to 16 bits.
    # No b/w form.
    opcode = '011'
    name = 'sxt'

    def compute_result(self, src):
        return src.cast_to(Type.int_16, signed=True)


class Instruction_PUSH(Type1Instruction):
    # Push src onto the stack.
    opcode = '100'
    name = 'push'

    def compute_result(self, src):
        # Decrement SP
        sp = self.get(1, REGISTER_TYPE)
        sp -= 2
        # Store src at SP
        self.store(src, sp)
        # Store SP.  No write-out.
        self.put(sp, 'sp')

    # No flags.
    def negative(self, src, ret):
        # pylint: disable=arguments-differ
        pass

    def zero(self, src, ret):
        # pylint: disable=arguments-differ
        pass


class Instruction_CALL(Type1Instruction):
    opcode = '101'
    name = 'call'
    # Call src.  Pushes PC. No flags.

    def compute_result(self, src):
        # Push the next instruction's address
        pc = self.get_pc() + self.bytewidth
        sp = self.get('sp', Type.int_16)
        sp = sp - 2
        self.store(pc, sp)
        self.put(sp, 'sp')
        # This ends the BB, update the IRSB
        self.jump(None, src, jumpkind=JumpKind.Call)

    def negative(self, src, ret):
        # pylint: disable=arguments-differ
        pass

    def zero(self, src, ret):
        # pylint: disable=arguments-differ
        pass


class Instruction_RETI(Type1Instruction):
    # Return *from interrupt*
    # Pop SR AND PC.
    opcode = '110'
    name = 'reti'

    def disassemble(self):
        return self.addr, self.name, []

    def compute_result(self, src):
        # Pop the saved SR
        sp = self.get(1, REGISTER_TYPE)
        sr = self.get_sr()
        sp += 2
        # Pop the saved PC
        newpc = self.load(sp, Type.int_16)
        sp += 2
        # Store the popped values
        self.put_sr(sr)
        # Jump to PC (setting the jumpkind)
        self.jump(None, newpc, jumpkind=JumpKind.Ret)

    def negative(self, *args):
        pass

    def zero(self, *args):
        pass

##
## Two operand instructions.
##


class Instruction_MOV(Type3Instruction):
    # Boring move.  No flags.
    opcode = '0100'
    name = 'mov'

    # NOTE: MOV is the only Type3Instruction that does *not* read its
    # destination operand (i.e., do_fetch=False), as it will be overwritten
    def fetch_operands(self):
        if self.data['s'] == '0001' and self.data['d'] == '0000':
            return None, None
        else:
            return Type3Instruction.fetch_operands(self, do_fetch=False)

    def disassemble(self):
        # support useful pseudo-ops for disassembly
        addr, name, args = Type3Instruction.disassemble(self)
        if self.data['d'] == '0000':
            if self.data['s'] == '0001':
                return addr, 'ret', []
            else:
                # If we're setting PC, but not from SP+, it's a BR instead
                return addr, 'br', [args[0]]
        else:
            return addr, name, args

    def compute_result(self, src, dst):
        # HACK: In MSP430, a MOV to R0 from SP is a RET.
        # VEX would like it very much if you set the jumpkind.
        if self.data['d'] == '0000':
            if self.data['s'] == '0001':
                sp = self.get('sp', REGISTER_TYPE)
                newpc = self.load(sp, REGISTER_TYPE)
                sp = sp + 2
                self.put(sp, 'sp')
                self.jump(None, newpc, jumpkind=JumpKind.Ret)
            else:
                # If we're setting PC, but not from SP+, it's a BR instead
                self.jump(None, src)
        return src

    def negative(self, src, dst, ret):
        # pylint: disable=arguments-differ
        pass

    def zero(self, src, dst, ret):
        # pylint: disable=arguments-differ
        pass


class Instruction_ADD(Type3Instruction):
    # Add src + dst, set carry
    opcode = '0101'
    name = 'add'

    def compute_result(self, src, dst):
        return dst + src

    def carry(self, src, dst, ret):
        if self.data['b'] == '0':
            src17 = src.cast_to(Type.int_17)
            dst17 = dst.cast_to(Type.int_17)
            ret17 = self.compute_result(src17, dst17)
            c = ret17[16]
        else:
            src9 = src.cast_to(Type.int_9)
            dst9 = dst.cast_to(Type.int_9)
            ret9 = self.compute_result(src9, dst9)
            c = ret9[8]

        return c

    def overflow(self, src, dst, ret):
        # pylint: disable=arguments-differ
        if self.data['b'] == '0':
            return (ret[15] ^ src[15]) & (ret[15] ^ dst[15])
        else:
            return (ret[7] ^ src[7]) & (ret[7] ^ dst[7])


class Instruction_ADDC(Instruction_ADD):
    # dst = src + dst + C
    opcode = '0110'
    name = 'addc'

    def compute_result(self, src, dst):
        return dst + src + self.get_carry().cast_to(src.ty)


class Instruction_SUB(Type3Instruction):
    # dst = dst + ~src + 1
    # or
    # dst = dst - src
    opcode = '1000'
    name = "sub"

    def compute_result(self, src, dst):
        return dst - src

    def carry(self, src, dst, ret):
        # pylint: disable=arguments-differ
        return dst >= src

    def overflow(self, src, dst, ret):
        # pylint: disable=arguments-differ
        if self.data['b'] == '0':
            return (dst[15] ^ src[15]) & (ret[15] ^ dst[15])
        else:
            return (dst[7] ^ src[7]) & (ret[7] ^ dst[7])


class Instruction_SUBC(Instruction_SUB):
    # dst = dst + ~src + C
    # or
    # dst = dst - src - 1 + C
    opcode = '0111'
    name = 'subc'

    def compute_result(self, src, dst):
        return dst - src - self.constant(1, src.ty) + self.get_carry().cast_to(src.ty)

    def carry(self, src, dst, ret):
        # Works for .w and .b mode
        # Equivalent with checking the carry out of the MSB of dst + ~src + C
        src17 = src.cast_to(Type.int_17)
        dst17 = dst.cast_to(Type.int_17)
        one17 = self.constant(1, Type.int_17)
        cr17 = self.get_carry().cast_to(Type.int_17)
        return dst17 >= src17 + one17 - cr17

class Instruction_CMP(Instruction_SUB):
    opcode = '1001'
    name = 'cmp'

    def commit_result(self, res):
        pass


class Instruction_DADD(Type3Instruction):
    opcode = '1010'
    name = 'dadd'

    def compute_result(self, src, dst):
        # Ya know... fuck this...
        srcs = []
        dsts = []
        bits = 8 if self.data['b'] == '1' else 16
        ret = self.constant(0, BYTE_TYPE if self.data['b'] == '1' else REGISTER_TYPE)
        for x in range(0, bits, 4):
            srcs += src[x:x+3]
            dsts += dst[x:x+3]
        carry = self.get_carry().cast_to(src.ty)
        rets = []
        for s, d in zip(srcs, dsts):
            r = s + d + carry
            carry = r // 10
            r %= 10
            rets.append(r)
        self._carry = carry #Carry computed in-line. save it.
        # Smash the digits back together
        for r, x in zip(rets, range(0, bits, 4)):
                ret |= (r << x).cast_to(src.ty)
        return ret

    def carry(self, src, dst, ret):
        # pylint: disable=arguments-differ
        return self._carry

    def overflow(self, src, dst, ret):
        # pylint: disable=arguments-differ
        return None # WTF: Docs say this is actually undefined!?


class Instruction_BIC(Type3Instruction):
    # Bit Clear.  dst = ~src & dst
    opcode = '1100'
    name = 'bic'

    def compute_result(self, src, dst):
        return ~src & dst

    def negative(self, src, dst, ret):
        # pylint: disable=arguments-differ
        pass

    def zero(self, src, dst, ret):
        # pylint: disable=arguments-differ
        pass


class Instruction_BIS(Type3Instruction):
    # Bit Set.  Normal people call this "or"
    opcode = '1101'
    name = 'bis'

    def compute_result(self, src, dst):
        return src | dst


class Instruction_XOR(Type3Instruction):
    # Exclusive Or
    opcode = "1110"
    name = 'xor'

    def compute_result(self, src, dst):
        return src ^ dst

    def carry(self, src, dst, ret):
        # pylint: disable=arguments-differ
        return ret != self.constant(0, ret.ty)

    def overflow(self, src, dst, ret):
        # pylint: disable=arguments-differ
        if self.data['b'] == '1':
            return src[7] & dst[7]
        else:
            return src[15] & dst[15]


class Instruction_AND(Type3Instruction):
    # Logical and.
    opcode = "1111"
    name = 'and'

    def compute_result(self, src, dst):
        return src & dst

    def overflow(self, src, dst, ret):
        # pylint: disable=arguments-differ
        return self.constant(0, ret.ty)

    def carry(self, src, dst, ret):
        # pylint: disable=arguments-differ
        return ret != self.constant(0, ret.ty)


class Instruction_BIT(Instruction_AND):
    # Bit Test. Just update flags.  No write-out
    opcode = "1011"
    name = "bit"

    def commit_result(self, *args):
        pass


##
## Zero-operand Jumps
##


class Instruction_JNE(Type2Instruction):
    opcode = '000'
    name = 'jne'

    def compute_result(self, dst):
        self.jump(self.get_zero() == 0, dst)


class Instruction_JEQ(Type2Instruction):
    opcode = '001'
    name = 'jeq'

    def compute_result(self, dst):
        self.jump(self.get_zero() != 0, dst)


class Instruction_JNC(Type2Instruction):
    opcode = '010'
    name = 'jnc'

    def compute_result(self, dst):
        self.jump(self.get_carry() == 0, dst)


class Instruction_JC(Type2Instruction):
    opcode = '011'
    name = 'jc'

    def compute_result(self, dst):
        self.jump(self.get_carry() != 0, dst)


class Instruction_JN(Type2Instruction):
    opcode = '100'
    name = 'jn'

    def compute_result(self, dst):
        self.jump(self.get_negative() != 0, dst)


class Instruction_JGE(Type2Instruction):
    opcode = '101'
    name = 'jge'

    def compute_result(self, dst):
        self.jump(self.get_negative() == self.get_overflow(), dst)


class Instruction_JL(Type2Instruction):
    opcode = '110'
    name = 'jl'

    def compute_result(self, dst):
        self.jump(self.get_negative() != self.get_overflow(), dst)


class Instruction_JMP(Type2Instruction):
    opcode = '111'
    name = 'jmp'

    def compute_result(self, dst):
        self.jump(None, dst)
