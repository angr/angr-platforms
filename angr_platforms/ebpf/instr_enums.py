from enum import IntEnum

from pyvex.lifting.util import Type

"""
General overview of eBPF instructions (see more details in comments below):

eBPF instructions are 64-bit and have the following form:

op:8 dst_reg:4 src_reg:4 off:16 imm:32

where left of colon is the meaning what it is and on the right is the number of bits.

- `op` is opcode
- `dst_reg` is the destination register used by the instruction
- `src_reg` is the source register used by the instruction
- `off` is the offset
- `imm` is the immediate value

`op` has the following form:

+----------------+--------+--------------------+
|  5 instruction class    |   3 bits           |
|     specific bits       | instruction class  |
+----------------+--------+--------------------+
(MSB)                                      (LSB)

Three LSB bits store instruction class which is one of:

  eBPF classes:

  BPF_LD    0x00
  BPF_LDX   0x01
  BPF_ST    0x02
  BPF_STX   0x03
  BPF_ALU   0x04
  BPF_JMP   0x05
  BPF_JMP32 0x06
  BPF_ALU64 0x07
"""

INSTRUCTION_CLASS_BITS = 7


class InstrClass(IntEnum):
    """
    Represents various instruction classes present in eBPF ISA
    """
    BPF_LD = 0x00
    BPF_LDX = 0x01
    BPF_ST = 0x02
    BPF_STX = 0x03
    BPF_ALU = 0x04
    BPF_JMP = 0x05
    BPF_JMP32 = 0x06
    BPF_ALU64 = 0x07

    @staticmethod
    def extract_from_opcode(opcode: int):
        """
        Should be used to extract the instruction class from an opcode,
        e.g., ``opcode & INSTRUCTION_CLASS_BITS == BPF_LD`` to check whether an opcode is of class ``BPF_LD``
        """
        return InstrClass(opcode & INSTRUCTION_CLASS_BITS)


'''
For arithmetic and jump instructions the 8-bit 'code'
field is divided into three parts:

+----------------+--------+--------------------+
|   4 bits       |  1 bit |   3 bits           |
| operation code | source | instruction class  |
+----------------+--------+--------------------+
(MSB)                                      (LSB)

When BPF_CLASS(code) == BPF_ALU or BPF_JMP, 4th bit encodes source operand ...

  BPF_K     0x00
  BPF_X     0x08

 * in eBPF, this means:

  BPF_SRC(code) == BPF_X - use 'src_reg' register as source operand
  BPF_SRC(code) == BPF_K - use 32-bit immediate as source operand

... and four MSB bits store operation code.

If BPF_CLASS(code) == BPF_ALU or BPF_ALU64 [ in eBPF ], BPF_OP(code) is one of:

  BPF_ADD   0x00
  BPF_SUB   0x10
  BPF_MUL   0x20
  BPF_DIV   0x30
  BPF_OR    0x40
  BPF_AND   0x50
  BPF_LSH   0x60
  BPF_RSH   0x70
  BPF_NEG   0x80
  BPF_MOD   0x90
  BPF_XOR   0xa0
  BPF_MOV   0xb0  /* eBPF only: mov reg to reg */
  BPF_ARSH  0xc0  /* eBPF only: sign extending shift right */
  BPF_END   0xd0  /* eBPF only: endianness conversion */

If BPF_CLASS(code) == BPF_JMP or BPF_JMP32 [ in eBPF ], BPF_OP(code) is one of:

  BPF_JA    0x00  /* BPF_JMP only */
  BPF_JEQ   0x10
  BPF_JGT   0x20
  BPF_JGE   0x30
  BPF_JSET  0x40
  BPF_JNE   0x50  /* eBPF only: jump != */
  BPF_JSGT  0x60  /* eBPF only: signed '>' */
  BPF_JSGE  0x70  /* eBPF only: signed '>=' */
  BPF_CALL  0x80  /* eBPF BPF_JMP only: function call */
  BPF_EXIT  0x90  /* eBPF BPF_JMP only: function return */
  BPF_JLT   0xa0  /* eBPF only: unsigned '<' */
  BPF_JLE   0xb0  /* eBPF only: unsigned '<=' */
  BPF_JSLT  0xc0  /* eBPF only: signed '<' */
  BPF_JSLE  0xd0  /* eBPF only: signed '<=' */

BPF_ADD | BPF_X | BPF_ALU means 32-bit addition in eBPF. 
In eBPF it means `dst_reg = (u32) dst_reg + (u32) src_reg`; 

similarly, BPF_XOR | BPF_K | BPF_ALU means `src_reg = (u32) src_reg ^ (u32) imm32` in eBPF.
'''

OPERATION_BITS = 0xf0
OPERATION_SRC_BITS = 0x08


class OpcodeSrc(IntEnum):
    IMM = 0x00
    SRC_REG = 0x08

    @staticmethod
    def extract_from_opcode(opcode: int):
        return OpcodeSrc(opcode & OPERATION_SRC_BITS)


class AluOrAlu64Operation(IntEnum):
    BPF_ADD = 0x00
    BPF_SUB = 0x10
    BPF_MUL = 0x20
    BPF_DIV = 0x30
    BPF_OR = 0x40
    BPF_AND = 0x50
    BPF_LSH = 0x60
    BPF_RSH = 0x70
    BPF_NEG = 0x80
    BPF_MOD = 0x90
    BPF_XOR = 0xa0
    BPF_MOV = 0xb0  # / * eBPF only: mov reg to reg * /
    BPF_ARSH = 0xc0  # / * eBPF only: sign extending shift right * /
    BPF_END = 0xd0  # / * eBPF only: endianness conversion * /

    @staticmethod
    def extract_from_opcode(opcode: int):
        return AluOrAlu64Operation(opcode & OPERATION_BITS)


class JmpOperation(IntEnum):
    BPF_JA = 0x00  # BPF_JMP only
    BPF_JEQ = 0x10
    BPF_JGT = 0x20
    BPF_JGE = 0x30
    BPF_JSET = 0x40
    BPF_JNE = 0x50  # jump !=
    BPF_JSGT = 0x60  # signed '>'
    BPF_JSGE = 0x70  # signed '>='
    BPF_CALL = 0x80  # BPF_JMP only
    BPF_EXIT = 0x90  # BPF_JMP only
    BPF_JLT = 0xa0  # unsigned '<'
    BPF_JLE = 0xb0  # unsigned '<='
    BPF_JSLT = 0xc0  # signed '<'
    BPF_JSLE = 0xd0  # signed '<='

    @staticmethod
    def extract_from_opcode(opcode):
        return JmpOperation(opcode & OPERATION_BITS)


class Jmp32Operation(IntEnum):
    BPF_JEQ = 0x10
    BPF_JGT = 0x20
    BPF_JGE = 0x30
    BPF_JSET = 0x40
    BPF_JNE = 0x50  # jump !=
    BPF_JSGT = 0x60  # signed '>'
    BPF_JSGE = 0x70  # signed '>='
    BPF_JLT = 0xa0  # unsigned '<'
    BPF_JLE = 0xb0  # unsigned '<='
    BPF_JSLT = 0xc0  # signed '<'
    BPF_JSLE = 0xd0  # signed '<='

    @staticmethod
    def extract_from_opcode(opcode):
        return Jmp32Operation(opcode & OPERATION_BITS)


'''
For load and store instructions the 8-bit 'code' field is divided as:

  +--------+--------+-------------------+
  | 3 bits | 2 bits |   3 bits          |
  |  mode  |  size  | instruction class |
  +--------+--------+-------------------+
  (MSB)                             (LSB)

Size modifier is one of ...

  BPF_W   0x00    /* word */
  BPF_H   0x08    /* half word */
  BPF_B   0x10    /* byte */
  BPF_DW  0x18    /* eBPF only, double word */

... which encodes size of load/store operation:

 B  - 1 byte
 H  - 2 byte
 W  - 4 byte
 DW - 8 byte (eBPF only)

Mode modifier is one of:

  BPF_IMM  0x00  /* used for 32-bit mov in classic BPF and 64-bit in eBPF */
  BPF_ABS  0x20
  BPF_IND  0x40
  BPF_MEM  0x60
  BPF_LEN  0x80  /* classic BPF only, reserved in eBPF */
  BPF_MSH  0xa0  /* classic BPF only, reserved in eBPF */
  BPF_XADD 0xc0  /* eBPF only, exclusive add */

eBPF has two non-generic instructions: (BPF_ABS | <size> | BPF_LD) and
(BPF_IND | <size> | BPF_LD) which are used to access packet data.
'''

OPCODE_SIZE_BITS = 0x18
OPCODE_MODE_BITS = 0xe0


class OperandSize(IntEnum):
    BPF_W = 0x00  # word
    BPF_H = 0x08  # half word
    BPF_B = 0x10  # byte
    BPF_DW = 0x18  # double word

    @staticmethod
    def extract_from_opcode(opcode: int):
        return OperandSize(opcode & OPCODE_SIZE_BITS)

    def to_type(self):
        if self is OperandSize.BPF_W:
            return Type.int_32
        elif self is OperandSize.BPF_H:
            return Type.int_16
        elif self is OperandSize.BPF_B:
            return Type.int_8
        elif self is OperandSize.BPF_DW:
            return Type.int_64
        else:
            assert False  # unexpected


class OpcodeMode(IntEnum):
    BPF_IMM = 0x00  # used for 64-bit mov in eBPF
    BPF_ABS = 0x20
    BPF_IND = 0x40
    BPF_MEM = 0x60
    BPF_XADD = 0xc0  # eBPF only, exclusive add

    @staticmethod
    def extract_from_opcode(opcode: int):
        return OpcodeMode(opcode & OPCODE_MODE_BITS)
