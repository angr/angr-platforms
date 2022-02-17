"""
Collections of eBPF instructions
"""

import abc
import bitstring

from .instr_enums import \
    InstrClass, OpcodeSrc, AluOrAlu64Operation, JmpOperation, Jmp32Operation, OpcodeMode, OperandSize
from pyvex.lifting.util import Instruction, ParseError, Type, JumpKind, VexValue

import logging

logger = logging.getLogger(__name__)

REGISTER_TYPE = Type.int_64
REGULAR_INSN_SZ = 8  # in bytes

"""
How access to registers and memory typed:
    - Except for `BPF_IMM | DW | LD`, all instructions are 8-byte, so the immediate must be 32-bits long. This means 
    whenever we use an immediate as an instruction operand, we give it a type `Type.int_32`. I'm not sure whether it 
    should be uint or int though -- TODO: need to check int vs uint in other lifters
    
    - Registers are assumed to be `Type.int_64` but 2 questions:
        - how to handle 32-bit sub-registers
        - int vs uint
"""


class EbpfInstruction(Instruction, metaclass=abc.ABCMeta):
    """
    Represents an eBPF instruction.

    This class is responsible for matching the instruction class (in the sense that
    we're given a binary stream from an executable, and we match 32 or 64 bit chunks
    of the stream to instructions). The matching happens in a hierarchical manner
    where first we match based on the instruction class. Depending on the class,
    we can then extract the opcode (since different classes can have different
    opcode structure).
    """

    bin_format = 8 * 'O' + 4 * 's' + 4 * 'd' + 16 * 'o' + 32 * 'i'
    """
    Overrides `bin_format` property in `Instruction`
    
    Look up what `bin_format` is in the documentation for `Instruction` class.
    
    An eBPF instruction has the following format  
        op:8 dst_reg:4 src_reg:4 off:16 imm:32
    where 
        op - opcode, dst_reg - destination register, `src_reg` - source register, 
        and `imm` - 32-bit immediate (little-endian)
    """

    @property
    @abc.abstractmethod
    def _instr_class(self):
        """
        Represents "instruction class", where class is in the eBPF ISA sense, not OOP.

        Needs to be overridden by subclasses for specific eBPF instruction classes, ie ALU, ALU64, JMP, etc.
        """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.opcode = int(self.data['O'], 2)
        self.dst_reg = int(self.data['d'], 2)
        self.src_reg = int(self.data['s'], 2)
        self.offset = bitstring.Bits(bin=self.data['o']).intle

        assert (len(self.data['i']) != 32 or len(self.data['i']) != 64)
        self.imm = bitstring.Bits(bin=self.data['i']).intle

    def match_instruction(self, data, bitstrm):
        """
        Match an instruction by instruction class.

        Subclasses need to override this method but call it first
        to make sure they operate in correct instruction class.
        """

        # note: here we can't use `self.opcode` because `match_instruction` is used in the parent-class constructor
        # so if we call `self.opcode`, we try to get `.opcode` before it's set (after the call to parent constructor)
        opcode = int(data['O'], 2)  # type: int
        opcode_instr_class = InstrClass.extract_from_opcode(opcode)  # type: InstrClass

        if not (self._instr_class == opcode_instr_class):
            raise ParseError("Invalid opcode instruction class, "
                             "expected %d, got %d" % (self._instr_class, opcode_instr_class))

        data['opcode'] = opcode
        data['opcode_instr_class'] = opcode_instr_class

        return data

    def get_ip(self):
        """
        A helper function to get the instruction pointer value
        """
        return self.get('ip', REGISTER_TYPE)

    def get_offset_in_bytes(self):
        offset_nb_insns = self.offset + 1  # we do `+ 1` because `ip` should jump also over the current insn
        return self.constant(offset_nb_insns * REGULAR_INSN_SZ, Type.int_64)  # offset in bytes


class ArithOrJmpInstruction(EbpfInstruction, metaclass=abc.ABCMeta):
    """
      +----------------+--------+--------------------+
      |   4 bits       |  1 bit |   3 bits           |
      | operation code | source | instruction class  |
      +----------------+--------+--------------------+
      (MSB)                                      (LSB)
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._operation_src = OpcodeSrc.extract_from_opcode(self.opcode)

    @abc.abstractmethod
    def _extract_operation_from_opcode(self, opcode):
        """
        Each class for an instruction class (in ISA, not OOP sense) needs to override this
        """

    @property
    @abc.abstractmethod
    def _operation(self):
        """
        Must be overridden by each instruction.
        """

    def match_instruction(self, data, bitstrm):
        updated_data = super().match_instruction(data, bitstrm)

        opcode = updated_data['opcode']
        operation_from_opcode = self._extract_operation_from_opcode(opcode)
        operation_src_from_opcode = OpcodeSrc.extract_from_opcode(opcode)

        if not (self._operation == operation_from_opcode):
            raise ParseError("Invalid opcode operation, expected %d, got %d" %
                             (self._operation, operation_from_opcode))

        updated_data['operation'] = operation_from_opcode
        updated_data['operation_src'] = operation_src_from_opcode

        return data


class LoadOrStoreInstruction(EbpfInstruction, metaclass=abc.ABCMeta):
    """
      +--------+--------+-------------------+
      | 3 bits | 2 bits |   3 bits          |
      |  mode  |  size  | instruction class |
      +--------+--------+-------------------+
      (MSB)                             (LSB)
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.size = OperandSize.extract_from_opcode(self.opcode)
        self.mode = OpcodeMode.extract_from_opcode(self.opcode)


class LoadInstruction(LoadOrStoreInstruction, metaclass=abc.ABCMeta):
    _instr_class = InstrClass.BPF_LD
    name = 'bpf_ld'

    def _extra_parsing(self, data, bitstrm):
        """
        If the instruction is `BPF_IMM | DW | LD`,
        the instruction is a 16-byte instruction, so we need to read 64 more bits.
        """
        opcode = data['opcode']
        assert (isinstance(opcode, int))
        size = OperandSize.extract_from_opcode(opcode)
        if size == OperandSize.BPF_DW and OpcodeMode.extract_from_opcode(opcode) == OpcodeMode.BPF_IMM:
            snd_instr = bitstrm.read(f'bin:{self.bitwidth:d}')
            le_imm = snd_instr[32:]
            data['i'] += le_imm
            self.rawbits += f'{int(snd_instr, 2):016x}'
            self.bitwidth *= 2

        return data


class AluOrAlu64Instruction(ArithOrJmpInstruction, metaclass=abc.ABCMeta):
    """
    Class that unites functionality common to ALU and ALU64 eBPF instructions
    """

    def _extract_operation_from_opcode(self, opcode):
        return AluOrAlu64Operation.extract_from_opcode(opcode)


class AluInstruction(AluOrAlu64Instruction, metaclass=abc.ABCMeta):
    """
    class for ALU instruction class
    different from Alu64Instruction
    """

    _instr_class = InstrClass.BPF_ALU


class Alu64Instruction(AluOrAlu64Instruction, metaclass=abc.ABCMeta):
    _instr_class = InstrClass.BPF_ALU64

    def commit_result(self, res):
        self.put(res, self.dst_reg)


class JmpInstruction(ArithOrJmpInstruction, metaclass=abc.ABCMeta):
    _instr_class = InstrClass.BPF_JMP

    def _extract_operation_from_opcode(self, opcode):
        return JmpOperation.extract_from_opcode(opcode)


class Jmp32Instruction(ArithOrJmpInstruction, metaclass=abc.ABCMeta):
    _instr_class = InstrClass.BPF_JMP32

    def _extract_operation_from_opcode(self, opcode):
        return Jmp32Operation.extract_from_opcode(opcode)


class Alu64OneOperandInstruction(Alu64Instruction, metaclass=abc.ABCMeta):
    def fetch_operands(self):
        return self.get(self.dst_reg, REGISTER_TYPE),


class Alu64TwoOperandInstruction(Alu64Instruction, metaclass=abc.ABCMeta):
    """
    Does everything an ALU64 instruction needs to do except
    for computing the result
    """

    def fetch_operands(self):
        dst_reg = self.get(self.dst_reg, REGISTER_TYPE)
        if self._operation_src == OpcodeSrc.IMM:
            return self.constant(self.imm, Type.int_32), dst_reg
        elif self._operation_src == OpcodeSrc.SRC_REG:
            return self.get(self.src_reg, REGISTER_TYPE), dst_reg
        else:
            assert False


class Instruction_BpfAdd(Alu64TwoOperandInstruction):
    name = 'bpf_add'
    _operation = AluOrAlu64Operation.BPF_ADD

    def compute_result(self, src, dst):
        return src + dst


class Instruction_BpfSub(Alu64TwoOperandInstruction):
    name = 'bpf_sub'
    _operation = AluOrAlu64Operation.BPF_SUB

    def compute_result(self, src, dst):
        return dst - src


class Instruction_BpfMul(Alu64TwoOperandInstruction):
    name = 'bpf_mul'
    _operation = AluOrAlu64Operation.BPF_MUL

    def compute_result(self, src, dst):
        return dst * src


class Instruction_BpfDiv(Alu64TwoOperandInstruction):
    name = 'bpf_div'
    _operation = AluOrAlu64Operation.BPF_DIV

    def compute_result(self, src, dst):
        return dst / src


class Instruction_BpfOr(Alu64TwoOperandInstruction):
    name = 'bpf_or'
    _operation = AluOrAlu64Operation.BPF_OR

    def compute_result(self, src, dst):
        return dst | src


class Instruction_BpfAnd(Alu64TwoOperandInstruction):
    name = 'bpf_and'
    _operation = AluOrAlu64Operation.BPF_AND

    def compute_result(self, src, dst):
        return dst & src


class Instruction_BpfLSH(Alu64Instruction):
    name = 'bpf_lsh'
    _operation = AluOrAlu64Operation.BPF_LSH

    def fetch_operands(self):
        dst_reg = self.get(self.dst_reg, REGISTER_TYPE)
        if self._operation_src == OpcodeSrc.IMM:
            return self.constant(self.imm, Type.int_8), dst_reg
        elif self._operation_src == OpcodeSrc.SRC_REG:
            return self.get(self.src_reg, Type.int_8), dst_reg
        else:
            assert False

    def compute_result(self, src, dst):
        return dst << src


class Instruction_BpfRSH(Alu64TwoOperandInstruction):
    name = 'bpf_rsh'
    _operation = AluOrAlu64Operation.BPF_RSH

    def compute_result(self, src, dst):
        return dst >> src


class Instruction_BpfNEG(Alu64OneOperandInstruction):
    name = 'bpf_neg'
    _operation = AluOrAlu64Operation.BPF_NEG

    def compute_result(self, v):
        return -v


class Instruction_BpfMOD(Alu64TwoOperandInstruction):
    name = 'bpf_mod'
    _operation = AluOrAlu64Operation.BPF_MOD

    def compute_result(self, src, dst):
        return dst % src


class Instruction_BpfXOR(Alu64TwoOperandInstruction):
    name = 'bpf_xor'
    _operation = AluOrAlu64Operation.BPF_XOR

    def compute_result(self, src, dst):
        return dst ^ src


class Instruction_BpfMov(Alu64Instruction):
    name = 'bpf_mov_64'
    _operation = AluOrAlu64Operation.BPF_MOV

    def fetch_operands(self):
        if self._operation_src == OpcodeSrc.IMM:
            return self.constant(self.imm, Type.int_32),
        elif self._operation_src == OpcodeSrc.SRC_REG:
            return self.get(self.src_reg, REGISTER_TYPE),
        else:
            assert False

    def compute_result(self, src):
        return src


class Instruction_BpfARSH(Alu64Instruction):
    name = 'bpf_arsh'
    _operation = AluOrAlu64Operation.BPF_ARSH

    def fetch_operands(self):
        dst_reg = self.get(self.dst_reg, REGISTER_TYPE)
        if self._operation_src == OpcodeSrc.IMM:
            return self.constant(self.imm, Type.int_8), dst_reg
        elif self._operation_src == OpcodeSrc.SRC_REG:
            return self.get(self.src_reg, Type.int_8), dst_reg
        else:
            assert False

    def compute_result(self, src: 'VexValue', dst: 'VexValue'):
        return dst.sar(src)


class Instruction_BpfEND(Alu64OneOperandInstruction):
    name = 'bpf_end'
    _operation = AluOrAlu64Operation.BPF_END

    def compute_result(self, src, dst):
        return


class Instruction_BpfJmpExit(JmpInstruction):
    name = 'bpf_exit'
    _operation = JmpOperation.BPF_EXIT

    def compute_result(self, *args):
        self.jump(None, 0, JumpKind.Boring)


class Instruction_JA(JmpInstruction):
    name = 'bpf_ja'
    _operation = JmpOperation.BPF_JA

    def compute_result(self, *args):
        ip = self.get_ip()
        offset = self.get_offset_in_bytes()
        self.jump(None, ip + offset, JumpKind.Boring)


class JmpInstructionTwoOperands(JmpInstruction, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def _condition(self, op, dst):
        """
        returns jump condition
        """

    def fetch_operands(self):
        if self._operation_src == OpcodeSrc.SRC_REG:
            return self.get(self.src_reg, REGISTER_TYPE),
        else:
            return self.constant(self.imm, REGISTER_TYPE),

    def compute_result(self, operand):
        ip = self.get_ip()
        dst = self.get(self.dst_reg, REGISTER_TYPE)
        offset = self.get_offset_in_bytes()
        self.jump(self._condition(operand, dst), ip + offset, JumpKind.Boring)


class Instruction_JEQ(JmpInstructionTwoOperands):
    name = 'bpf_jeq'
    _operation = JmpOperation.BPF_JEQ

    def _condition(self, operand, dst):
        return operand == dst


class Instruction_JGT(JmpInstructionTwoOperands):
    name = 'bpf_jgt'
    _operation = JmpOperation.BPF_JGT

    def _condition(self, op, dst):
        return dst > op


class Instruction_JGE(JmpInstructionTwoOperands):
    name = 'bpf_jge'
    _operation = JmpOperation.BPF_JGE

    def _condition(self, op, dst):
        return dst >= op


class Instruction_JSET(JmpInstructionTwoOperands):
    name = 'bpf_jset'
    _operation = JmpOperation.BPF_JSET

    def _condition(self, op, dst):
        return dst & op


class Instruction_JNE(JmpInstructionTwoOperands):
    name = 'bpf_jne'
    _operation = JmpOperation.BPF_JNE

    def _condition(self, op, dst):
        return dst != op


class Instruction_JSGT(JmpInstructionTwoOperands):
    name = 'bpf_jsgt'
    _operation = JmpOperation.BPF_JSGT

    def _condition(self, op, dst):
        return dst.signed > op


class Instruction_JSGE(JmpInstructionTwoOperands):
    name = 'bpf_jsge'
    _operation = JmpOperation.BPF_JSGE

    def _condition(self, op, dst):
        return dst.signed >= op


class Instruction_JLT(JmpInstructionTwoOperands):
    name = 'bpf_jlt'
    _operation = JmpOperation.BPF_JLT

    def _condition(self, op, dst):
        return dst < op


class Instruction_JLE(JmpInstructionTwoOperands):
    name = 'bpf_jle'
    _operation = JmpOperation.BPF_JLE

    def _condition(self, op, dst):
        return dst <= op


class Instruction_JSLT(JmpInstructionTwoOperands):
    name = 'bpf_jslt'
    _operation = JmpOperation.BPF_JSLT

    def _condition(self, op, dst):
        return dst.signed < op


class Instruction_JSLE(JmpInstructionTwoOperands):
    name = 'bpf_jsle'
    _operation = JmpOperation.BPF_JSLE

    def _condition(self, op, dst):
        return dst.signed <= op


class Instruction_CALL(JmpInstruction):
    name = 'bpf_call'
    _operation = JmpOperation.BPF_CALL

    def compute_result(self, *args):
        raise Exception('Implement me')


class Instruction_LD(LoadInstruction):
    def fetch_operands(self):
        # for how LD instruction class works,
        # see https://github.com/qmonnet/rbpf/blob/6c524b3669d7b19736ceaf8d155b43aee93479c3/src/jit.rs#L528-L564
        if self.mode == OpcodeMode.BPF_IMM:
            return self.constant(self.imm, self.size.to_type()),
        elif self.mode == OpcodeMode.BPF_ABS:
            raise Exception("Not implemented")  # FIXME
        elif self.mode == OpcodeMode.BPF_IND:
            raise Exception("Not implemented")  # FIXME
        elif self.mode == OpcodeMode.BPF_MEM or \
                self.mode == OpcodeMode.BPF_XADD:
            assert False  # because unexpected instruction structure
        else:
            assert False

    def compute_result(self, arg):
        return arg

    def commit_result(self, v):
        self.put(v, self.dst_reg)


class Instruction_LDX(LoadInstruction):
    _instr_class = InstrClass.BPF_LDX
    name = 'bpf_ldx'

    def fetch_operands(self):
        # for how LDX instruction class works,
        # see https://github.com/qmonnet/rbpf/blob/6c524b3669d7b19736ceaf8d155b43aee93479c3/src/jit.rs#L566-L574
        if self.mode == OpcodeMode.BPF_MEM:
            type_ = self.size.to_type()
            src = self.get(self.src_reg, REGISTER_TYPE)
            return self.load(src + self.offset, type_),
        elif self.mode == OpcodeMode.BPF_IMM or \
                self.mode == OpcodeMode.BPF_ABS or \
                self.mode == OpcodeMode.BPF_IND or \
                self.mode == OpcodeMode.BPF_XADD:
            assert False  # because unexpected instruction structure
        else:
            assert False

    def compute_result(self, arg):
        return arg

    def commit_result(self, v):
        self.put(v, self.dst_reg)


class Instruction_ST(LoadOrStoreInstruction):
    name = 'bpf_st'
    _instr_class = InstrClass.BPF_ST

    def fetch_operands(self):
        type_ = self.size.to_type()
        if self.mode == OpcodeMode.BPF_IMM:
            return self.constant(self.imm, type_),
        elif self.mode == OpcodeMode.BPF_ABS or \
                self.mode == OpcodeMode.BPF_IND or \
                self.mode == OpcodeMode.BPF_MEM or \
                self.mode == OpcodeMode.BPF_XADD:
            assert False

    def compute_result(self, v):
        return v

    def commit_result(self, res):
        d = self.get(self.dst_reg, REGISTER_TYPE) + self.offset
        self.store(res, d)


class Instruction_STX(LoadOrStoreInstruction):
    name = 'bpf_stx'
    _instr_class = InstrClass.BPF_STX

    def fetch_operands(self):
        type_ = self.size.to_type()
        if self.mode == OpcodeMode.BPF_MEM:
            return self.get(self.src_reg, type_), None
        elif self.mode == OpcodeMode.BPF_XADD:  # TODO: real atomic add
            assert (self.size >= OperandSize.BPF_W)  # this op doesn't support 1 or 2 byte operands
            return self.get(self.src_reg, type_), self.get(self.dst_reg, type_)
        elif self.mode == OpcodeMode.BPF_IMM or \
                self.mode == OpcodeMode.BPF_ABS or \
                self.mode == OpcodeMode.BPF_IND:
            assert False

    def compute_result(self, src, dst):
        return src if dst is None else src + dst

    def commit_result(self, res):
        d = self.get(self.dst_reg, REGISTER_TYPE) + self.offset
        self.store(res, d)
