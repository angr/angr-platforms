from .emulator import Emulator
from .regs import sgreg_t

# Constants for repeat prefixes
NONE = 0
REPZ = 1
REPNZ = 2

# Constants for instruction flags
CHK_MODRM = 1 << 0
CHK_IMM32 = 1 << 1
CHK_IMM16 = 1 << 2
CHK_IMM8 = 1 << 3
CHK_PTR16 = 1 << 4
CHK_MOFFS = 1 << 5

MAX_OPCODE = 0x200

# ModR/M byte structure
class ModRM:
    def __init__(self):
        self.rm = 0  # Register/memory operand
        self.reg = 0  # Register operand or opcode extension
        self.mod = 0  # Addressing mode

# SIB byte structure
class SIB:
    def __init__(self):
        self.base = 0  # Base register
        self.index = 0  # Index register
        self.scale = 0  # Scaling factor

# X86Instruction data structure
class InstrData:
    def __init__(self):
        self.prefix = 0  # X86Instruction prefix
        self.pre_segment = 0  # Segment override prefix
        self.pre_repeat = NONE  # Repeat prefix

        self.segment: int = 0  # Default segment register
        self.opcode = 0  # Opcode
        self.modrm = ModRM()  # ModR/M byte
        self.sib = SIB()  # SIB byte
        self.disp8 = 0  # 8-bit displacement
        self.disp16 = 0  # 16-bit displacement
        self.disp32 = 0  # 32-bit displacement
        self.imm8 = 0  # 8-bit immediate value
        self.imm16 = 0  # 16-bit immediate value
        self.imm32 = 0  # 32-bit immediate value
        self.ptr16 = 0  # 16-bit far pointer
        self.moffs = 0  # Memory offset

# Base class for instruction handlers
class X86Instruction:
    def __init__(self, emu: Emulator, instr: InstrData, mode32: bool):
        self.emu = emu
        self.instr = instr
        self.mode32 = mode32
        self.chsz_ad = False

    def select_segment(self):
        return sgreg_t(self.instr.pre_segment if self.instr.prefix else self.instr.segment)

# Class for executing instructions

class InstrFlags:
    def __init__(self):
        self.modrm = False
        self.imm32 = False
        self.imm16 = False
        self.imm8 = False
        self.ptr16 = False
        self.moffs = False
        self.moffs8 = False

    @property
    def flags(self):
        """Returns a byte representation of the flags."""
        return (
                (self.modrm << 0)
                | (self.imm32 << 1)
                | (self.imm16 << 2)
                | (self.imm8 << 3)
                | (self.ptr16 << 4)
                | (self.moffs << 5)
                | (self.moffs8 << 6)
        )

    @flags.setter
    def flags(self, value):
        """Sets the flags from a byte representation."""
        self.modrm = bool(value & 1)
        self.imm32 = bool(value & (1 << 1))
        self.imm16 = bool(value & (1 << 2))
        self.imm8 = bool(value & (1 << 3))
        self.ptr16 = bool(value & (1 << 4))
        self.moffs = bool(value & (1 << 5))
        self.moffs8 = bool(value & (1 << 6))


