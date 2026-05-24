import claripy
from angr import SimProcedure
from angr.calling_conventions import (
    SimCC,
    SimRegArg,
    SimStackArg,
    register_default_cc,
    register_syscall_cc,
)
from angr.simos import SimOS, register_simos

from .arch_86_16 import Arch86_16

INTERRUPT_BASE_ADDR = 0xFF000
INTERRUPT_VECTOR_COUNT = 0x100


def interrupt_addr(vector: int) -> int:
    return INTERRUPT_BASE_ADDR + (vector & 0xFF)


def runtime_interrupt_addr(vector: int) -> int:
    return interrupt_addr(vector) & 0xFFFF


class InterruptHandler(SimProcedure):
    INT_VECTOR = None
    INT_NAME = "interrupt"
    IS_BIOS = False
    IS_DOS = False
    NO_RET = False

    def run(self):  # pylint:disable=arguments-differ
        return claripy.BVS(f"{self.INT_NAME}_ax", 16, explicit_name=True)


class BIOSInterruptHandler(InterruptHandler):
    IS_BIOS = True


class DOSInterruptHandler(InterruptHandler):
    IS_DOS = True


class BIOSInt10Video(BIOSInterruptHandler):
    INT_VECTOR = 0x10
    INT_NAME = "bios_int10_video"

    def run(self):  # pylint:disable=arguments-differ
        ah = self.state.regs.ah
        # Common text-mode services can be treated as pure side-effect stubs.
        if self.state.solver.is_true(ah == 0x0E):
            return claripy.ZeroExt(8, self.state.regs.al)
        return claripy.BVS("bios_int10_ax", 16, explicit_name=True)


class BIOSInt11Equipment(BIOSInterruptHandler):
    INT_VECTOR = 0x11
    INT_NAME = "bios_int11_equipment"

    def run(self):  # pylint:disable=arguments-differ
        self.state.regs.ax = claripy.BVV(0, 16)
        return self.state.regs.ax


class BIOSInt12MemorySize(BIOSInterruptHandler):
    INT_VECTOR = 0x12
    INT_NAME = "bios_int12_memory_size"

    def run(self):  # pylint:disable=arguments-differ
        # Conventional memory size in KiB.
        self.state.regs.ax = claripy.BVV(640, 16)
        return self.state.regs.ax


class BIOSInt13Disk(BIOSInterruptHandler):
    INT_VECTOR = 0x13
    INT_NAME = "bios_int13_disk"


class BIOSInt14Serial(BIOSInterruptHandler):
    INT_VECTOR = 0x14
    INT_NAME = "bios_int14_serial"


class BIOSInt15System(BIOSInterruptHandler):
    INT_VECTOR = 0x15
    INT_NAME = "bios_int15_system"


class BIOSInt16Keyboard(BIOSInterruptHandler):
    INT_VECTOR = 0x16
    INT_NAME = "bios_int16_keyboard"

    def run(self):  # pylint:disable=arguments-differ
        ah = self.state.regs.ah
        if self.state.solver.is_true(ah == 0x00):
            self.state.regs.ax = claripy.BVV(0, 16)
            return self.state.regs.ax
        return claripy.BVS("bios_int16_ax", 16, explicit_name=True)


class BIOSInt17Printer(BIOSInterruptHandler):
    INT_VECTOR = 0x17
    INT_NAME = "bios_int17_printer"


class BIOSInt1AClock(BIOSInterruptHandler):
    INT_VECTOR = 0x1A
    INT_NAME = "bios_int1a_clock"

    def run(self):  # pylint:disable=arguments-differ
        ah = self.state.regs.ah
        if self.state.solver.is_true(ah == 0x00):
            self.state.regs.ax = claripy.BVV(0, 16)
            self.state.regs.cx = claripy.BVV(0, 16)
            self.state.regs.dx = claripy.BVV(0, 16)
            return self.state.regs.ax
        return claripy.BVS("bios_int1a_ax", 16, explicit_name=True)


class DOSInt20Terminate(DOSInterruptHandler):
    INT_VECTOR = 0x20
    INT_NAME = "dos_int20_terminate"
    NO_RET = True

    def run(self):  # pylint:disable=arguments-differ
        self.exit(0)


class DOSInt21(DOSInterruptHandler):
    INT_VECTOR = 0x21
    INT_NAME = "dos_int21"

    def run(self):  # pylint:disable=arguments-differ
        ah = self.state.regs.ah

        if self.state.solver.is_true(ah == 0x09):
            self.state.regs.al = claripy.BVV(ord("$"), 8)
            return claripy.BVV(ord("$"), 16)

        if self.state.solver.is_true(ah == 0x19):
            self.state.regs.al = claripy.BVV(2, 8)
            return claripy.BVV(2, 16)

        if self.state.solver.is_true(ah == 0x30):
            self.state.regs.al = claripy.BVV(5, 8)
            self.state.regs.ah = claripy.BVV(0, 8)
            return claripy.BVV(0x0005, 16)

        if self.state.solver.is_true(ah == 0x35):
            self.state.regs.es = claripy.BVV(0, 16)
            self.state.regs.bx = claripy.BVV(0, 16)
            self.state.regs.ax = claripy.BVV(0, 16)
            return self.state.regs.ax

        if self.state.solver.is_true(ah == 0x25):
            self.state.regs.ax = claripy.BVV(0, 16)
            return self.state.regs.ax

        if self.state.solver.is_true(ah == 0x4C):
            self.exit(claripy.ZeroExt(8, self.state.regs.al))

        return claripy.BVS("dos_int21_ax", 16, explicit_name=True)


class DOSInt25AbsoluteDiskRead(DOSInterruptHandler):
    INT_VECTOR = 0x25
    INT_NAME = "dos_int25_abs_disk_read"


class DOSInt26AbsoluteDiskWrite(DOSInterruptHandler):
    INT_VECTOR = 0x26
    INT_NAME = "dos_int26_abs_disk_write"


class DOSInt27TerminateStayResident(DOSInterruptHandler):
    INT_VECTOR = 0x27
    INT_NAME = "dos_int27_tsr"
    NO_RET = True

    def run(self):  # pylint:disable=arguments-differ
        self.exit(0)


class DOSInt2FMultiplex(DOSInterruptHandler):
    INT_VECTOR = 0x2F
    INT_NAME = "dos_int2f_multiplex"


def _generic_interrupt_class(vector: int):
    category = "bios" if 0x10 <= vector <= 0x1F else "dos" if 0x20 <= vector <= 0x2F else "interrupt"
    base = BIOSInterruptHandler if category == "bios" else DOSInterruptHandler if category == "dos" else InterruptHandler
    return type(
        f"Interrupt{vector:02X}",
        (base,),
        {
            "INT_VECTOR": vector,
            "INT_NAME": f"{category}_int{vector:02x}",
        },
    )


_HANDLER_CLASSES = {
    cls.INT_VECTOR: cls
    for cls in (
        BIOSInt10Video,
        BIOSInt11Equipment,
        BIOSInt12MemorySize,
        BIOSInt13Disk,
        BIOSInt14Serial,
        BIOSInt15System,
        BIOSInt16Keyboard,
        BIOSInt17Printer,
        BIOSInt1AClock,
        DOSInt20Terminate,
        DOSInt21,
        DOSInt25AbsoluteDiskRead,
        DOSInt26AbsoluteDiskWrite,
        DOSInt27TerminateStayResident,
        DOSInt2FMultiplex,
    )
}


def get_interrupt_handler_class(vector: int):
    vector &= 0xFF
    return _HANDLER_CLASSES.setdefault(vector, _generic_interrupt_class(vector))


class SimDOSintcall(SimCC):
    ARG_REGS = ["ax", "bx", "cx", "dx"]
    RETURN_VAL = SimRegArg("ax", 2)
    ARCH = Arch86_16

    @staticmethod
    def _match(arch, args: list, sp_delta):  # pylint: disable=unused-argument
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.ax


class SimDOS86_16(SimOS):
    def __init__(self, project, **kwargs):
        super().__init__(project, name="DOS", **kwargs)

    def configure_project(self):
        super().configure_project()
        for vector in range(INTERRUPT_VECTOR_COUNT):
            handler_cls = get_interrupt_handler_class(vector)
            self.project.hook(interrupt_addr(vector), handler_cls(), replace=True)
            runtime_addr = runtime_interrupt_addr(vector)
            if runtime_addr != interrupt_addr(vector):
                self.project.hook(runtime_addr, handler_cls(), replace=True)


class SimCC8616MSCsmall(SimCC):
    ARG_REGS = []
    FP_ARG_REGS = []
    STACKARG_SP_DIFF = 2
    RETURN_ADDR = SimStackArg(0, 2)
    RETURN_VAL = SimRegArg("ax", 2)
    OVERFLOW_RETURN_VAL = SimRegArg("dx", 2)
    ARCH = Arch86_16
    STACK_ALIGNMENT = 2
    CALLEE_CLEANUP = True


class SimCC8616MSCmedium(SimCC):
    ARG_REGS = []
    FP_ARG_REGS = []
    STACKARG_SP_DIFF = 2
    RETURN_ADDR = SimStackArg(0, 2)
    RETURN_VAL = SimRegArg("ax", 2)
    OVERFLOW_RETURN_VAL = SimRegArg("dx", 2)
    ARCH = Arch86_16
    STACK_ALIGNMENT = 2
    CALLEE_CLEANUP = True


# Legacy compatibility alias for callers that imported the pre-memory-model
# default Microsoft C calling convention by the unsuffixed name.
SimCC8616MSC = SimCC8616MSCsmall


register_simos("DOS", SimDOS86_16)
register_default_cc("86_16", SimCC8616MSCsmall)
register_default_cc("86_16", SimCC8616MSCsmall, platform="DOS")
register_syscall_cc("86_16", "Linux", SimDOSintcall)
register_syscall_cc("86_16", "default", SimDOSintcall)
