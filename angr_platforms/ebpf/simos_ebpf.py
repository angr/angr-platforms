from angr.procedures.definitions import SimSyscallLibrary
from angr.calling_conventions import (
    SimCC,
    SimCCSyscall,
    register_default_cc,
    SimRegArg,
    register_syscall_cc,
)
from angr.simos import SimUserland, register_simos
from angr.sim_procedure import SimProcedure
from claripy import BVS, BVV

from . import ArchExtendedBPF


class SimCcEbpf(SimCC):
    """CC for eBPF"""

    ARCH = ArchExtendedBPF

    ARG_REGS = ["R1", "R2", "R3", "R4", "R5"]
    CALLER_SAVED_REGS = ["R6", "R7", "R8", "R9"]

    RETURN_VAL = SimRegArg("R0", 8)


register_default_cc("eBPF", SimCcEbpf)


class SimCcSyscallEbpf(SimCCSyscall):
    """CC syscall for eBPF"""

    ARCH = ArchExtendedBPF

    ARG_REGS = ["R1", "R2", "R3", "R4", "R5"]
    CALLER_SAVED_REGS = ["R6", "R7", "R8", "R9"]

    RETURN_VAL = SimRegArg("R0", 8)
    RETURN_ADDR = SimRegArg("ip_at_syscall", 8)

    @staticmethod
    def syscall_num(state):
        return state.regs.syscall


register_syscall_cc("eBPF", "eBPF", SimCcSyscallEbpf)


class ExitSimProcedure(SimProcedure):
    """End of program"""

    NO_RET = True
    ADDS_EXITS = True

    def run(self):
        # pylint: disable=arguments-differ
        self.exit(self.state.regs.R0)


class KtimeGetNSSimProcedure(SimProcedure):
    """Elapsed nano-seconds since system boot"""

    KEY = "last_ktime"

    @property
    def last_time(self):
        return self.state.globals.get(self.KEY, None)

    @last_time.setter
    def last_time(self, v):
        self.state.globals[self.KEY] = v

    def run(self):
        # pylint: disable=arguments-differ
        ret = BVS("ns", self.state.arch.bits)

        if self.last_time is not None:
            self.state.add_constraints(ret.SGE(self.last_time))
        else:
            self.state.add_constraints(ret.SGE(0))
        self.last_time = ret

        return ret


P = {
    "exit": (0, ExitSimProcedure),
    "ktime_get_ns": (5, KtimeGetNSSimProcedure),
}

syscall_lib = SimSyscallLibrary()
syscall_lib.set_library_names("eBPF")
syscall_lib.add_all_from_dict({k: v[1] for k, v in P.items()})
syscall_lib.add_number_mapping_from_dict("abi", {v[0]: k for k, v in P.items()})


class SimOsEbpf(SimUserland):
    """Simulate parts of the eBPF env"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, syscall_library=syscall_lib, name="eBPF", **kwargs)

    def state_blank(self, *args, context: bytes = bytes(0x10_000), **kwargs):
        state = super().state_blank(*args, **kwargs)

        context_addr = BVV(0x100_000, 64)
        state.memory.store(context_addr, context)
        state.r1 = context_addr

        return state


register_simos("UNIX - System V", SimOsEbpf)
