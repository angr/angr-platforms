from pyvex.lifting.util.vex_helper import Type

from .cr import CR
from .eflags import Eflags
from .regs import dtreg_t, reg8_t, reg16_t, reg32_t, sgreg_t

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
        return

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

    def get_ip(self):
        return self.lifter_instruction.get("ip", Type.int_16)
        return self.eip & 0xFFFF

    def get_gpreg(self, n):
        return self.lifter_instruction.get(n.name.lower(), TYPES[type(n)])

    def constant(self, n, type_=Type.int_8):
        return self.lifter_instruction.constant(n, type_)

    def get_sgreg(self, n):
        return self.lifter_instruction.get(n.name.lower(), TYPES[type(n)])

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
        self.eip = value

    def set_ip(self, value):
        assert False
        self.set_gpreg(self, "ip", self.lifter_instruction.constant(value, Type.int_16))

    def set_gpreg(self, n, value):
        if isinstance(value, int):
            val = self.lifter_instruction.constant(value, TYPES[type(n)])
        else:
            val = value
        self.lifter_instruction.put(val, n.name.lower())

    def set_sgreg(self, n, reg):
        self.set_gpreg(n, reg)

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
        result += value
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
