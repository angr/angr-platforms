import archinfo
from angr import SimCC
from angr.calling_conventions import register_default_cc, SimRegArg, SimStackArg
from angr.simos import SimOS, register_simos
from angr.sim_procedure import SimProcedure

from . import ArchEbpf


class ExitProcedureCC(SimCC):
    ARG_REGS = ['R0']


class ExitSimProcedure(SimProcedure):
    NO_RET = True
    ADDS_EXITS = True

    def __init__(self):
        super(ExitSimProcedure, self).__init__()
        self.cc = ExitProcedureCC(ArchEbpf(endness=archinfo.Endness.LE))

    def run(self, exit_code):
        self.exit(exit_code)


class SimOsEbpf(SimOS):
    SYSCALL_TABLE = {}  # TODO: update

    def __init__(self, *args, **kwargs):
        super(SimOsEbpf, self).__init__(*args, name="eBPF", **kwargs)
        self.project.hook(0, ExitSimProcedure())


register_simos('UNIX - System V', SimOsEbpf)


class SimCcEbpf(SimCC):
    """
    This class implements a function calling convention present in eBPF ISA.
    However, since the only functions that an eBPF program can call are
    ["bpf helpers"](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html),
    which are helper functions specifically for eBPF programs in kernel,
    this CC could be a "syscall" calling convention. We register this CC as the
    default CC for the eBPF architecture, nevertheless.
    """
    ARG_REGS = ['R1', 'R2', 'R3', 'R4', 'R5']
    STACKARG_SP_DIFF = 8  # FIXME
    RETURN_ADDR = SimStackArg(0, 8)  # FIXME
    RETURN_VAL = SimRegArg('R0', 8)
    ARCH = ArchEbpf


register_default_cc('eBPF', SimCcEbpf)
