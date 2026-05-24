from pyvex.expr import Binop, Const, Get, Load, Unop
from pyvex.lifting.util.syntax_wrapper import VexValue
from pyvex.lifting.util.vex_helper import Type
from pyvex.stmt import Put

from .cr import CR
from .eflags import Eflags
from .regs import dtreg_t, reg8_t, reg16_t, reg32_t, register_name_8616, sgreg_t

# Constants for general-purpose registers

# Constants for segment registers

# Constants for descriptor table registers


TYPES = {reg8_t: Type.int_8, reg16_t: Type.int_16, reg32_t: Type.int_32, sgreg_t: Type.int_16}

# General-purpose register structure

class GPRegister:
    def __init__(self):
        self.reg32 = 0  # 32-bit register value

    @property
    def reg16(self):
        return self.reg32 & 0xFFFF

    @reg16.setter
    def reg16(self, value):
        self.reg32 = (self.reg32 & 0xFFFF0000) | (value & 0xFFFF)

    @property
    def reg8_l(self):
        return self.reg32 & 0xFF

    @reg8_l.setter
    def reg8_l(self, value):
        self.reg32 = (self.reg32 & 0xFFFFFF00) | (value & 0xFF)

    @property
    def reg8_h(self):
        return (self.reg32 >> 8) & 0xFF

    @reg8_h.setter
    def reg8_h(self, value):
        self.reg32 = (self.reg32 & 0xFFFF00FF) | ((value & 0xFF) << 8)

# Segment register cache structure

class SGRegCache:
    def __init__(self):
        self.base = 0  # Base address of the segment
        self.limit = 0  # Limit of the segment
        self.flags = SegDescFlags()  # Flags for the segment descriptor

# Segment descriptor flags structure

class SegDescFlags:
    def __init__(self):
        self.raw = 0  # Raw flags value

    @property
    def type(self):
        return self.raw & 0xF

    @type.setter
    def type(self, value):
        self.raw = (self.raw & 0xFFF0) | (value & 0xF)

    @property
    def S(self):
        return bool(self.raw & (1 << 4))

    @S.setter
    def S(self, value):
        self.raw = (self.raw & ~(1 << 4)) | (value << 4)

    @property
    def DPL(self):
        return (self.raw >> 5) & 3

    @DPL.setter
    def DPL(self, value):
        self.raw = (self.raw & ~(3 << 5)) | (value << 5)

    @property
    def P(self):
        return bool(self.raw & (1 << 7))

    @P.setter
    def P(self, value):
        self.raw = (self.raw & ~(1 << 7)) | (value << 7)

    @property
    def AVL(self):
        return bool(self.raw & (1 << 8))

    @AVL.setter
    def AVL(self, value):
        self.raw = (self.raw & ~(1 << 8)) | (value << 8)

    @property
    def DB(self):
        return bool(self.raw & (1 << 10))

    @DB.setter
    def DB(self, value):
        self.raw = (self.raw & ~(1 << 10)) | (value << 10)

    @property
    def G(self):
        return bool(self.raw & (1 << 11))

    @G.setter
    def G(self, value):
        self.raw = (self.raw & ~(1 << 11)) | (value << 11)

# Segment register structure
class SGRegister:
    def __init__(self):
        self.raw = 0  # Raw segment selector value
        self.cache = SGRegCache()  # Cached segment descriptor information

    @property
    def RPL(self):
        return self.raw & 3

    @RPL.setter
    def RPL(self, value):
        self.raw = (self.raw & ~3) | (value & 3)

    @property
    def TI(self):
        return bool(self.raw & (1 << 2))

    @TI.setter
    def TI(self, value):
        self.raw = (self.raw & ~(1 << 2)) | (value << 2)

    @property
    def index(self):
        return (self.raw >> 3) & 0x1FFF

    @index.setter
    def index(self, value):
        self.raw = (self.raw & 0x7) | ((value & 0x1FFF) << 3)

# Descriptor table register structure
class DTRegister:
    def __init__(self):
        self.selector = 0  # Selector for LDTR and TR
        self.base = 0  # Base address of the descriptor table
        self.limit = 0  # Limit of the descriptor table

# Processor class
class Processor(Eflags, CR):
    def __init__(self):
        super().__init__()
        self.lifter_instruction = None
        self.vex_offsets = None
        self._last_condition = None
        self.flags = 0
        self.eip = 0  # X86Instruction pointer
        self.gpregs = [GPRegister() for _ in range(reg32_t.GPREGS_COUNT.value)]  # General-purpose registers
        self.sgregs = [SGRegister() for _ in range(sgreg_t.SGREGS_COUNT.value)]  # Segment registers
        self.dtregs = [DTRegister() for _ in range(dtreg_t.DTREGS_COUNT.value)]  # Descriptor table registers

        self.halt = False

        self.set_eip(0xFFFF0)
        self.set_crn(0, 0x60000010)
        self.set_eflags(2)

        self.sgregs[sgreg_t.CS.value].raw = 0xF000
        self.sgregs[sgreg_t.CS.value].cache.base = 0xFFFF0000
        self.sgregs[sgreg_t.CS.value].cache.flags.type = 0x18  # Code segment
        for i in range(sgreg_t.SGREGS_COUNT.value):
            self.sgregs[i].cache.limit = 0xFFFF
            self.sgregs[i].cache.flags.P = 1
            self.sgregs[i].cache.flags.S = 1
            self.sgregs[i].cache.flags.type = 0x10  # Data segment

        self.dtregs[dtreg_t.IDTR.value].base = 0
        self.dtregs[dtreg_t.IDTR.value].limit = 0xFFFF
        self.dtregs[dtreg_t.GDTR.value].base = 0
        self.dtregs[dtreg_t.GDTR.value].limit = 0xFFFF
        self.dtregs[dtreg_t.LDTR.value].base = 0
        self.dtregs[dtreg_t.LDTR.value].limit = 0xFFFF

    def set_last_condition(self, condition) -> None:
        self._last_condition = condition

    def get_last_condition(self):
        return self._last_condition

    def clear_last_condition(self) -> None:
        self._last_condition = None

    def dump_regs(self):
        gpreg_name = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
        sgreg_name = ["ES", "CS", "SS", "DS", "FS", "GS"]
        dtreg_name = ["GDTR", "IDTR", "LDTR", " TR "]

        print(f"EIP = 0x{self.eip:08x}")
        for i in range(reg32_t.GPREGS_COUNT.value):
            print(
                f"{gpreg_name[i]} = 0x{self.gpregs[i].reg32:08x} : 0x{self.gpregs[i].reg16:04x} (0x{self.gpregs[i].reg8_h:02x}/0x{self.gpregs[i].reg8_l:02x})",
            )
        print(f"EFLAGS = 0x{self.get_eflags():08x}")

        for i in range(sgreg_t.SGREGS_COUNT.value):
            cache = self.sgregs[i].cache
            print(
                f"{sgreg_name[i]} = 0x{self.sgregs[i].raw:04x} {{base = 0x{cache.base:08x}, limit = {cache.limit:08x}, flags = {cache.flags.raw:04x}}}",
            )

        for i in range(dtreg_t.LDTR.value):
            print(
                f"{dtreg_name[i]} =        {{base = 0x{self.dtregs[i].base:08x}, limit = {self.dtregs[i].limit:08x}}}",
            )
        for i in range(dtreg_t.LDTR.value, dtreg_t.DTREGS_COUNT.value):
            print(
                f"{dtreg_name[i]} = 0x{self.dtregs[i].selector:04x} {{base = 0x{self.dtregs[i].base:08x}, limit = {self.dtregs[i].limit:08x}}}",
            )

        for i in range(5):
            print(f"CR{i}=0x{self.get_crn(i):08x} ", end="")
        print()

    def get_eip(self):
        return self.eip

    @staticmethod
    def _reg8_base(reg: reg8_t) -> reg16_t:
        return reg16_t(reg.value & 0b11)

    @staticmethod
    def _reg8_is_high(reg: reg8_t) -> bool:
        return reg.value >= 4

    def get_ip(self):
        if self.lifter_instruction is None:
            return self.eip & 0xFFFF
        offset = self.vex_offsets.get('ip', 0)
        return VexValue(self.lifter_instruction, self.lifter_instruction.rdreg(offset, Type.int_16))

    def get_gpreg(self, n):
        if isinstance(n, VexValue):
            if self.lifter_instruction is not None:
                return n
            raise ValueError("Cannot get gpreg from a non-constant VexValue without an active lifter instruction")
        name = register_name_8616(n)
        if isinstance(n, reg8_t):
            base = self.get_gpreg(self._reg8_base(n))
            if self._reg8_is_high(n):
                return (base >> 8).cast_to(Type.int_8) if self.lifter_instruction is not None else (base >> 8) & 0xFF
            return base.cast_to(Type.int_8) if self.lifter_instruction is not None else base & 0xFF
        if self.lifter_instruction is not None:
            if self.vex_offsets is None:
                raise ValueError("vex_offsets not initialized for lifting mode")
            offset = self.vex_offsets.get(name, 0)
            return VexValue(self.lifter_instruction, self.lifter_instruction.rdreg(offset, TYPES[type(n)]))
        # concrete mode
        if isinstance(n, reg32_t):
            idx = n.value
            if idx < reg32_t.GPREGS_COUNT.value:
                return self.gpregs[idx].reg32
            elif idx == reg32_t.EIP.value:
                return self.eip
            elif idx == reg32_t.EFLAGS.value:
                return self.flags
        elif isinstance(n, reg16_t):
            idx = n.value
            if idx < reg32_t.GPREGS_COUNT.value:  # 8 for 16-bit views
                return self.gpregs[idx].reg16
            elif idx == reg16_t.IP.value:
                return self.eip & 0xFFFF
            elif idx == reg16_t.FLAGS.value:
                return self.flags & 0xFFFF
        raise ValueError(f"Cannot get gpreg {n} without lifter_instruction in concrete mode")

    def constant(self, n, type_=Type.int_8):
        if self.lifter_instruction is not None:
            return VexValue(self.lifter_instruction, self.lifter_instruction.mkconst(n, type_))
        return n

    def get_sgreg(self, n):
        if isinstance(n, VexValue):
            if self.lifter_instruction is not None:
                return n
            raise ValueError("Cannot get sgreg from a non-constant VexValue without an active lifter instruction")
        name = register_name_8616(n)
        if self.lifter_instruction is not None:
            if self.vex_offsets is None:
                raise ValueError("vex_offsets not initialized for lifting mode")
            offset = self.vex_offsets.get(name, 0)
            return VexValue(self.lifter_instruction, self.lifter_instruction.rdreg(offset, Type.int_16))
        return self.sgregs[n.value].raw

    def get_segment(self, n):
        return self.get_sgreg(n)

    def get_carry(self):
        # Get the carry flag (bit 0 of FLAGS register)
        flags = self.get_gpreg(reg16_t.FLAGS)
        return flags[0]

    def set_carry_flag(self, flags, carry):
        # Set the carry flag (bit 0 of FLAGS register)
        flags = super().set_carry(flags, carry)
        self.set_gpreg(reg16_t.FLAGS, flags)
        return flags

    def set_overflow_flag(self, flags, overflow):
        # Set the overflow flag (bit 11 of FLAGS register)
        flags = super().set_overflow(flags, overflow)
        self.set_gpreg(reg16_t.FLAGS, flags)
        return flags

    def get_dtreg_selector(self, n):
        #assert n < dtreg_t.DTREGS_COUNT.value
        return self.dtregs[n].selector

    def get_dtreg_base(self, n):
        assert n < dtreg_t.DTREGS_COUNT.value
        return self.dtregs[n].base

    def get_dtreg_limit(self, n):
        assert n < dtreg_t.DTREGS_COUNT.value
        return self.dtregs[n].limit

    def set_eip(self, value):
        self.set_gpreg(reg32_t.EIP, value)

    def set_ip(self, value):
        if self.lifter_instruction is None:
            self.eip = (self.eip & 0xFFFF0000) | (value & 0xFFFF)
            return
        self.set_gpreg(reg16_t.IP, value)

    def set_gpreg(self, n, value):
        name = register_name_8616(n)
        if isinstance(n, reg8_t):
            if isinstance(value, int):
                value = self.constant(value, Type.int_8) if self.lifter_instruction is not None else value & 0xFF
            base_reg = self._reg8_base(n)
            if self.lifter_instruction is not None:
                base = self.get_gpreg(base_reg)
                if isinstance(base, VexValue):
                    base = VexValue(self.lifter_instruction, base.rdt)
                if isinstance(value, VexValue):
                    value_v = VexValue(self.lifter_instruction, value.rdt)
                else:
                    value_v = VexValue(self.lifter_instruction, self.lifter_instruction._settmp(value))
                if self._reg8_is_high(n):
                    new_base = ((value_v.cast_to(Type.int_16) << 8) | (base & 0x00FF))
                else:
                    new_base = ((base & 0xFF00) | value_v.cast_to(Type.int_16))
                self.set_gpreg(base_reg, new_base)
                return

            idx = base_reg.value
            if self._reg8_is_high(n):
                self.gpregs[idx].reg8_h = value
            else:
                self.gpregs[idx].reg8_l = value
            return
        if self.lifter_instruction is not None:
            if self.vex_offsets is None:
                raise ValueError("vex_offsets not initialized for lifting mode")
            offset = self.vex_offsets.get(name, 0)
            if isinstance(value, int):
                value = self.constant(value, TYPES[type(n)])
            if isinstance(value, VexValue):
                value = value.rdt
            self.lifter_instruction._append_stmt(Put(value, offset))
            return
        # concrete mode
        if isinstance(value, int):
            if isinstance(n, reg32_t):
                idx = n.value
                if idx < reg32_t.GPREGS_COUNT.value:
                    self.gpregs[idx].reg32 = value
                elif idx == reg32_t.EIP.value:
                    self.eip = value
                elif idx == reg32_t.EFLAGS.value:
                    self.flags = value
                return
            elif isinstance(n, reg16_t):
                idx = n.value
                if idx < reg32_t.GPREGS_COUNT.value:
                    self.gpregs[idx].reg16 = value
                elif idx == reg16_t.IP.value:
                    self.eip = (self.eip & 0xFFFF0000) | (value & 0xFFFF)
                elif idx == reg16_t.FLAGS.value:
                    self.flags = (self.flags & 0xFFFF0000) | (value & 0xFFFF)
                return
        raise TypeError(f"Cannot set {n} from non-concrete value of type {type(value)} in concrete mode")

    def set_sgreg(self, n, reg):
        name = register_name_8616(n)
        if self.lifter_instruction is not None:
            if self.vex_offsets is None:
                raise ValueError("vex_offsets not initialized for lifting mode")
            offset = self.vex_offsets.get(name, 0)
            if isinstance(reg, int):
                reg = self.constant(reg, Type.int_16)
            if isinstance(reg, VexValue):
                reg = reg.rdt
            self.lifter_instruction._append_stmt(Put(reg, offset))
            return
        if isinstance(reg, (Get, Const, Binop, Load, Unop)):
            return
        self.sgregs[n.value].raw = reg

    def set_segment(self, n, value):
        self.set_sgreg(n, value)

    def set_dtreg(self, n, sel, base, limit):
        assert n < dtreg_t.DTREGS_COUNT.value
        self.dtregs[n].selector = sel
        self.dtregs[n].base = base
        self.dtregs[n].limit = limit

    def update_eip(self, value):
        return self.update_gpreg(reg32_t.EIP, value)

    def update_ip(self, value):
        return self.update_gpreg(reg16_t.IP, value)

    def update_gpreg(self, n, value):
        result = self.get_gpreg(n)
        if self.lifter_instruction is not None:
            if isinstance(value, int):
                value = self.constant(value, TYPES[type(n)])
            elif not isinstance(value, VexValue):
                value = VexValue(self.lifter_instruction, self.lifter_instruction._settmp(value))
            result = result + value
        else:
            result = result + value
        self.set_gpreg(n, result)
        return result

    def is_halt(self):
        return self.halt

    def do_halt(self, h):
        self.halt = h

    def is_mode32(self):
        return False
        return self.sgregs[sgreg_t.CS.value].cache.flags.DB

    def set_lifter_instruction(self, lifter_instruction):
        self.lifter_instruction = lifter_instruction
