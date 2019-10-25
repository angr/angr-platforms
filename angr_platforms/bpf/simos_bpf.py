from angr.simos import SimUserland, register_simos
from angr.calling_conventions import SimStackArg, SimRegArg, SimCC, register_syscall_cc, register_default_cc, SimCC

from .arch_bpf import ArchBPF


class SimCCBPF(SimCC):
    ARG_REGS = [ ]
    FP_ARG_REGS = [ ]
    STACKARG_SP_DIFF = 0
    RETURN_ADDR = SimStackArg(0, 4)
    RETURN_VAL = SimRegArg('acc', 4)
    ARCH = ArchBPF


class SimBPF(SimUserland):
    # Syscalls are for lamers
    SYSCALL_TABLE = {}

    def __init__(self, *args, **kwargs):
        super(SimBPF, self).__init__(*args, name="BPF", **kwargs)

    def state_blank(self, data_region_size=0x8000, **kwargs): # pylint:disable=arguments-differ
        state = super(SimBPF, self).state_blank(**kwargs)  # pylint:disable=invalid-name
        return state


class SimBPFSyscall(SimCC):
    ARG_REGS = [ ]
    # RETURN_VAL = ""
    ARCH = ArchBPF

    @staticmethod
    def _match(arch, args, sp_delta):   # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.inout

register_simos('BPF', SimBPF)
register_syscall_cc('BPF', 'default', SimBPFSyscall)
register_default_cc('BPF', SimCCBPF)
