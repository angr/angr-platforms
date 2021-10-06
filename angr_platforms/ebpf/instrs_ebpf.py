# pylint: disable=arguments-differ disable=no-self-use

"""
Collections of eBPF instructions
"""

import abc
from typing import (
    Any,
    ClassVar,
    Mapping,
    Optional,
    Protocol,
    Tuple,
    Union,
    cast,
)

import bitstring
from pyvex.lifting.util import Instruction, Type, JumpKind, VexValue

REGISTER_TYPE = cast(str, Type.int_64)


class InstructionProtocol(Protocol):
    """Typing helper representing an Instruction"""

    data: Union[Mapping[str, str], Any]  # TODO get rid of Any

    @property
    def name(self) -> str:
        ...

    def get(self, reg: Union[int, str], typ: Any) -> VexValue:
        ...

    def put(self, val: VexValue, reg: Union[int, str]) -> None:
        ...

    def load(self, addr: VexValue, ty: str) -> VexValue:
        ...

    def store(self, val: VexValue, addr: VexValue) -> None:
        ...

    def constant(self, val: int, typ: Any) -> VexValue:
        ...

    def fetch_operands(self) -> Tuple[VexValue, ...]:
        ...

    def jump(
        self, condition: Optional[VexValue], to_addr: VexValue, jumpkind: str = ...
    ) -> None:
        ...


# --


class EBPFInstruction(Instruction, abc.ABC):
    """Base Instruction for eBPF"""

    src_reg_bin: ClassVar[str] = "0" * 4
    dest_reg_bin: ClassVar[str] = "0" * 4
    offset_bin: ClassVar[str] = "0" * 16
    immediate_bin: ClassVar[str] = "0" * 32

    @property
    @abc.abstractmethod
    def opcode_bin(self) -> str:
        ...

    @property
    def bin_format(self) -> str:
        ret = "".join(
            (
                self.opcode_bin,
                self.src_reg_bin,
                self.dest_reg_bin,
                self.offset_bin,
                self.immediate_bin,
            )
        )
        return ret


class WithDestRegProtocol(Protocol):
    """Typing helper for classes implementing WithDestReg"""

    @property
    def dest_reg(self: InstructionProtocol) -> int:
        ...


class WithDestReg:
    """Mixin to parse the destination register"""

    dest_reg_bin = "dddd"

    @property
    def dest_reg(self: InstructionProtocol) -> int:
        return int(self.data["d"], 2)  # pylint: disable=no-member


class InstructionWithDestRegProtocol(
    WithDestRegProtocol, InstructionProtocol, Protocol
):
    """Typing helper for classes implementing WithDestReg and Instruction"""


class WithSrcRegProtocol(Protocol):
    """Typing helper for classes implementing WithSrcReg"""

    @property
    def src_reg(self: InstructionProtocol) -> int:
        ...


class WithSrcReg:
    """Mixin to parse the source register"""

    src_reg_bin = "ssss"

    @property
    def src_reg(self: InstructionProtocol) -> int:
        return int(self.data["s"], 2)  # pylint: disable=no-member


class InstructionWithSrcRegProtocol(WithSrcRegProtocol, InstructionProtocol, Protocol):
    """Typing helper for classes implementing WithSrcReg and Instruction"""


class WithOffsetProtocol(Protocol):
    """Typing helper for classes implementing WithOffset"""

    @property
    def offset(self: InstructionProtocol) -> int:
        ...


class WithOffset:
    """Mixin to parse the offset"""

    offset_bin = "o" * 16

    @property
    def offset(self: InstructionProtocol) -> int:
        raw = self.data["o"]  # pylint: disable=no-member
        return bitstring.Bits(bin=raw).intle


class WithImmediateProtocol(Protocol):
    """Typing helper for classes implementing WithImmediate"""

    immediate_bin: ClassVar[str]

    @property
    def immediate(self) -> int:
        ...


class WithImmediate:
    """Mixin to parse the immediate value"""

    immediate_bin = "i" * 32

    @property
    def immediate(self: InstructionProtocol) -> int:
        raw = self.data["i"]  # pylint: disable=no-member
        return bitstring.Bits(bin=raw).intle


class InstructionWithImmediateProtocol(
    WithImmediateProtocol, InstructionProtocol, Protocol
):
    """Typing helper for classes implementing WithImmediate and Instruction"""


# type of instructions


class ArithmeticOrJumpInstruction(EBPFInstruction, abc.ABC):
    """Base Instruction for ALU or jumps"""

    @property
    @abc.abstractmethod
    def class_bin(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def source_bin(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def operation_bin(self) -> str:
        ...

    @property
    def opcode_bin(self) -> str:
        return self.operation_bin + self.source_bin + self.class_bin


class ALUInstructionProtocol(WithDestRegProtocol, InstructionProtocol, Protocol):
    """Typing helper for classes implementing WithDestReg and Instruction"""

    @property
    def size(self) -> str:
        ...

    @property
    def size_name(self) -> str:
        ...

    @property
    def operation_name(self) -> str:
        ...

    @property
    def source_name(self) -> str:
        ...


class ALUInstruction(WithDestReg, ArithmeticOrJumpInstruction):
    """Base Instruction for ALU computations"""

    @property
    @abc.abstractmethod
    def size(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def size_name(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def operation_name(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def source_name(self) -> str:
        ...

    @property
    def name(self) -> str:
        return f"{self.operation_name}{self.size_name}_{self.source_name}"

    def commit_result(self: ALUInstructionProtocol, res: VexValue) -> None:
        assert res.ty == self.size
        self.put(res, self.dest_reg)


class JumpInstruction(ArithmeticOrJumpInstruction):
    """Base Instruction for jumps"""


class LoadOrStoreInstruction(WithDestReg, EBPFInstruction, abc.ABC):
    """Base Instruction for load or store"""

    @property
    @abc.abstractmethod
    def class_bin(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def mode_bin(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def width_bin(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def width_name(self) -> str:
        ...

    @property
    def opcode_bin(self) -> str:
        return self.mode_bin + self.width_bin + self.class_bin


# classes


class LoadNonStandardInstruction(LoadOrStoreInstruction):
    """Base Instruction for non standard loads"""

    class_bin = "000"


class LoadInRegisterInstruction(LoadOrStoreInstruction):
    """Base Instruction for loads into registers"""

    class_bin = "001"


class StoreImmediateInstruction(LoadOrStoreInstruction):
    """Base Instruction for store from immediate value"""

    class_bin = "010"


class StoreFromRegisterInstruction(LoadOrStoreInstruction):
    """Base Instruction for store from registers"""

    class_bin = "011"


class ALU32Instruction(ALUInstruction):
    """Base Instruction for 32bits ALU"""

    class_bin = "100"
    size = cast(str, Type.int_32)
    size_name = "32"


class Jump64Instruction(JumpInstruction):
    """Base Instruction for 64bits jumps"""

    class_bin = "101"
    size = cast(str, Type.int_64)
    size_name = "64"


class Jump32Instruction(JumpInstruction):
    """Base Instruction for 32bits jumps"""

    class_bin = "110"
    size = cast(str, Type.int_32)
    size_name = "32"


class ALU64Instruction(ALUInstruction):
    """Base Instruction for 64bits ALU"""

    class_bin = "111"
    size = cast(str, Type.int_64)
    size_name = "64"


class ALUInstructionWithImmediateProtocol(
    WithImmediateProtocol, ALUInstructionProtocol, Protocol
):
    """Typing helper for classes implementing WithImmediate and ALUInstruction"""


# source mixin


class SourcedProtocol(Protocol):
    """Typing helper for classes with a source value"""

    source_name: ClassVar[str]

    @property
    def src_value(self: ALUInstructionWithImmediateProtocol) -> VexValue:
        ...


class ImmediateSource(WithImmediate):
    """Extract source value from the immediate field"""

    source_bin = "0"
    source_name = "imm"

    @property
    def src_value(self: ALUInstructionWithImmediateProtocol) -> VexValue:
        return self.constant(self.immediate, self.size)  # pylint: disable=no-member


class RegisterSource(WithSrcReg):
    """Extract source value from loading the source register"""

    source_bin = "1"
    source_name = "reg"

    @property
    def src_value(self: InstructionWithSrcRegProtocol) -> VexValue:
        return self.get(self.src_reg, REGISTER_TYPE)  # pylint: disable=no-member


# operands mixin
# TODO get rid of ignored types


class FetchSource:
    """Fetch source value with other operands"""

    def fetch_operands(self: Any) -> Tuple[VexValue, ...]:
        return super().fetch_operands() + (self.src_value,)  # type: ignore # pylint: disable=no-member


class FetchDestination(WithDestReg):
    """Fetch destination register with other operands"""

    def fetch_operands(self: Any) -> Tuple[VexValue, ...]:
        return super().fetch_operands() + (self.get(self.dest_reg, REGISTER_TYPE),)  # type: ignore # pylint: disable=no-member


class FetchPC:
    """Fetch instruction pointer with other operands"""

    def fetch_operands(self: Any) -> Tuple[VexValue, ...]:
        return super().fetch_operands() + (self.get("ip", REGISTER_TYPE),)  # type: ignore # pylint: disable=no-member


# ALU operations


class AddOp(FetchDestination, FetchSource):
    """Addition operation"""

    operation_bin = "0000"
    operation_name = "add"

    def compute_result(self, src, dst):
        return dst + src


class SubOp(FetchDestination, FetchSource):
    """Subtraction operation"""

    operation_bin = "0001"
    operation_name = "sub"

    def compute_result(self, src, dst):
        return dst - src


class MulOp(FetchDestination, FetchSource):
    """Multiplication operation"""

    operation_bin = "0010"
    operation_name = "mul"

    def compute_result(self, src, dst):
        return dst * src


class DivOp(FetchDestination, FetchSource):
    """Division operation"""

    operation_bin = "0011"
    operation_name = "div"

    def compute_result(self, src, dst):
        return dst / src


class OrOp(FetchDestination, FetchSource):
    """Bitwise OR operation"""

    operation_bin = "0100"
    operation_name = "or"

    def compute_result(self, src, dst):
        return dst | src


class AndOp(FetchDestination, FetchSource):
    """Bitwise AND operation"""

    operation_bin = "0101"
    operation_name = "and"

    def compute_result(self, src, dst):
        return dst & src


class LshOp(FetchDestination, FetchSource):
    """Left shift operation"""

    operation_bin = "0110"
    operation_name = "lsh"

    def compute_result(self, src, dst):
        return dst << src


class RshOp(FetchDestination, FetchSource):
    """Right logical shift instruction"""

    operation_bin = "0111"
    operation_name = "rsh"

    def compute_result(self, src, dst):
        return dst >> src


class NegOp(FetchSource):
    """Bitwise NOT operation"""

    operation_bin = "1000"
    operation_name = "neg"

    def compute_result(self, src):
        return ~src


class ModOp(FetchDestination, FetchSource):
    """Modulo operation"""

    operation_bin = "1001"
    operation_name = "mod"

    def compute_result(self, src, dst):
        return dst % src


class XorOp(FetchDestination, FetchSource):
    """Bitwise XOR operation"""

    operation_bin = "1010"
    operation_name = "xor"

    def compute_result(self, src, dst):
        return dst ^ src


class MovOp(FetchSource):
    """Mov operation"""

    operation_bin = "1011"
    operation_name = "mov"

    def compute_result(self, src):
        return src


class ArshOp(FetchDestination, FetchSource):
    """Right arithmetic shift instruction"""

    operation_bin = "1100"
    operation_name = "arsh"

    def compute_result(self, src, dst):
        return dst.sar(src)


#


class End32Reg(ALU32Instruction):
    """Arithmetic endianness conversion instruction"""

    operation_bin = "1101"
    operation_name = "byteconv"

    source_bin = "0"
    source_name = "src"

    def compute_result(self, dst):
        raise NotImplementedError(dst)  # TODO

    def commit_result(self: InstructionWithDestRegProtocol, res: Any) -> None:
        self.put(res, self.dest_reg)


ALU = {
    type(
        f"{op.__name__[:-2]}{cls.__name__[:-11]}{source.__name__[:3]}",
        (op, source, cls),
        {},
    )
    for op in (
        AddOp,
        SubOp,
        MulOp,
        DivOp,
        OrOp,
        AndOp,
        LshOp,
        RshOp,
        NegOp,
        ModOp,
        XorOp,
        MovOp,
        ArshOp,
    )
    for cls in (ALU32Instruction, ALU64Instruction)
    for source in (ImmediateSource, RegisterSource)
} | {End32Reg}


# jump operations


class SourcedConditionalJumpInstructionProtocol(
    SourcedProtocol, WithOffsetProtocol, InstructionProtocol, Protocol
):
    """Typing helper for classes implementing Sourced, WithOffset and Instruction"""

    @abc.abstractmethod
    def condition(self, src: VexValue, dst: VexValue) -> VexValue:
        ...

    @property
    @abc.abstractmethod
    def operation_name(self) -> str:
        ...


class ConditionalJumpOp(WithOffset, FetchDestination, FetchSource, FetchPC):
    """Jump with a condition"""

    @abc.abstractmethod
    def condition(self, src: VexValue, dst: VexValue) -> VexValue:
        ...

    @property
    @abc.abstractmethod
    def operation_name(self) -> str:
        ...

    @property
    def name(self: SourcedConditionalJumpInstructionProtocol):
        return f"{self.operation_name}_{self.source_name}"  # pylint: disable=no-member

    def compute_result(self: SourcedConditionalJumpInstructionProtocol, pc, src, dst):
        cond = self.condition(src, dst)
        self.jump(cond, pc + self.offset, JumpKind.Boring)  # pylint: disable=no-member


class JeqOp(ConditionalJumpOp):
    """Jump if equals"""

    operation_bin = "0001"
    operation_name = "jeq"

    def condition(self, src, dst):
        return dst == src


class JgtOp(ConditionalJumpOp):
    """Jump if greater than (unsigned)"""

    operation_bin = "0010"
    operation_name = "jgt"

    def condition(self, src, dst):
        assert not (src.signed or dst.signed)
        return dst > src


class JgeOp(ConditionalJumpOp):
    """Jump if greater than or equals (unsigned)"""

    operation_bin = "0011"
    operation_name = "jge"

    def condition(self, src, dst):
        assert not (src.signed or dst.signed)
        return dst >= src


class JsetOp(ConditionalJumpOp):
    """Jump if bit is set"""

    operation_bin = "0100"
    operation_name = "jset"

    def condition(self, src, dst):
        return (dst & src) != 0


class JneOp(ConditionalJumpOp):
    """Jump if not equals"""

    operation_bin = "0101"
    operation_name = "jne"

    def condition(self, src, dst):
        return dst != src


class JsgtOp(ConditionalJumpOp):
    """Jump if greater than (signed)"""

    operation_bin = "0110"
    operation_name = "jsgt"

    def condition(self, src: VexValue, dst: VexValue):
        return dst.signed > src.signed


class JsgeOp(ConditionalJumpOp):
    """Jump if greater than or equals (signed)"""

    operation_bin = "0111"
    operation_name = "jsge"

    def condition(self, src, dst):
        return dst.signed >= src.signed


class CallOp(ImmediateSource):
    """Call function from immediate"""

    name = "call"

    operation_bin = "1000"

    def compute_result(self: InstructionWithImmediateProtocol):
        # pylint: disable=no-member
        syscall = self.constant(self.immediate, self.size)
        self.put(syscall, "syscall")
        ip = self.get("ip", REGISTER_TYPE)
        self.jump(None, ip + 8, JumpKind.Syscall)


# LLVM generates theses but it's not documented
class CallXOp(WithImmediate, RegisterSource):
    """Call function from register"""

    name = "callx"

    operation_bin = "1000"

    def fetch_operands(self: InstructionWithImmediateProtocol):
        # pylint: disable=no-member
        addr = self.constant(self.immediate, Type.int_32)
        return (self.load(addr, REGISTER_TYPE),)

    def compute_result(self: InstructionProtocol, addr):
        self.jump(None, addr, JumpKind.Call)  # pylint: disable=no-member


#


class Ja64(WithOffset, FetchPC, Jump64Instruction):
    """Jump ahead"""

    name = "ja"

    source_bin = "0"
    operation_bin = "0000"

    def compute_result(self, pc):
        self.jump(None, pc + (self.offset + 1) * 8, JumpKind.Boring)


class Exit64(Jump64Instruction):
    """Exit"""

    name = "exit"

    source_bin = "0"
    operation_bin = "1001"

    def compute_result(self):
        self.jump(None, 0, JumpKind.Exit)  # irrelevant addr


Jump = (
    {
        type(
            f"{op.__name__[:-2]}{cls.__name__[4:-11]}{source.__name__[:3]}",
            (op, source, cls),
            {},
        )
        for op in (
            JeqOp,
            JgtOp,
            JgeOp,
            JsetOp,
            JneOp,
            JsgtOp,
            JsgeOp,
        )
        for cls in (Jump32Instruction, Jump64Instruction)
        for source in (ImmediateSource, RegisterSource)
    }
    | {
        type(
            f"{op.__name__[:-2]}{cls.__name__[4:-11]}",
            (op, cls),
            {},
        )
        for op in (CallOp, CallXOp)
        for cls in (Jump32Instruction, Jump64Instruction)
    }
    | {Ja64, Exit64}
)

## load operation

# modes


class ImmediateMode:
    """Load/Store from immediate"""

    mode_bin = "000"


class AbsoluteMode:
    """Obsolete mode"""

    mode_bin = "001"


class IndirectMode:
    """Obsolete mode"""

    mode_bin = "010"


class MemoryMode:
    """Load/Store from memory"""

    mode_bin = "011"


class AtomicMode:
    """Load/Store but atomically"""

    mode_bin = "100"


# sizes


class WidthedProtocol(Protocol):
    """Typing helper representing a class with a width"""

    width: ClassVar[str]


class Word:
    """Width of 32bits"""

    width = cast(str, Type.int_32)
    width_bin = "00"
    width_name = "w"


class HalfWord:
    """Width of 16bits"""

    width = cast(str, Type.int_16)
    width_bin = "01"
    width_name = "h"


class Byte:
    """Width of 8bits"""

    width = cast(str, Type.int_8)
    width_bin = "10"
    width_name = "b"


class DoubleWord:
    """Width of 64bits"""

    width = cast(str, Type.int_64)
    width_bin = "11"
    width_name = "dw"


# load/store operations


class WidthedInstructionProtocol(WidthedProtocol, InstructionProtocol, Protocol):
    """Typing helper for classes implementing Widthed and Instruction"""


class StoreFromRegisterOp(
    MemoryMode,
    WithOffset,
    FetchSource,
    FetchDestination,
    RegisterSource,
    StoreFromRegisterInstruction,
):
    """Store into memory from register"""

    @property
    def name(self) -> str:
        return f"stx{self.width_name}"

    def compute_result(self, dst, src):
        # pylint: disable=no-member
        if self.width != REGISTER_TYPE:
            src = src.widen_unsigned(self.width)
        self.store(src, dst + self.offset)


class StoreImmediateOp(
    MemoryMode,
    WithOffset,
    WithImmediate,
    FetchDestination,
    StoreImmediateInstruction,
):
    """Store into memory from immediate"""

    @property
    def name(self) -> str:
        return f"st{self.width_name}"

    def compute_result(self, dst):
        imm = self.constant(self.immediate, self.width)  # pylint: disable=no-member
        self.store(imm, dst + self.offset)


class LoadInRegisterOp(
    MemoryMode, WithOffset, FetchSource, RegisterSource, LoadInRegisterInstruction
):
    """Load into register from memory"""

    @property
    def name(self) -> str:
        return f"ldx{self.width_name}"

    def fetch_operands(self):
        (src,) = super().fetch_operands()
        return (self.load(src + self.offset, self.width),)  # pylint: disable=no-member

    def compute_result(self, res):
        # pylint: disable=no-member
        if self.width != REGISTER_TYPE:
            res = res.widen_unsigned(REGISTER_TYPE)
        return res

    def commit_result(self: InstructionWithDestRegProtocol, res):
        self.put(res, self.dest_reg)


# TODO add atomic


class Load64Imm(
    WithImmediate,
    DoubleWord,
    ImmediateMode,
    LoadNonStandardInstruction,
):
    """Load into register from immediate"""

    immediate_bin = "0" * 32 + "i" * 64

    @property
    def name(self) -> str:
        return f"ld{self.width_name}"

    def compute_result(self):
        return self.constant(self.immediate, Type.int_64)

    def commit_result(self, res):
        self.put(res, self.dest_reg)


LoadStore = {
    type(
        f"{size.__name__}{op.__name__[:-2]}",
        (size, op),
        {},
    )
    for op in (LoadInRegisterOp, StoreImmediateOp, StoreFromRegisterOp)
    for size in (Byte, HalfWord, Word, DoubleWord)
} | {Load64Imm}
