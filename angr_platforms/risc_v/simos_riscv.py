from angr.simos import SimOS, register_simos
from angr.sim_procedure import SimProcedure
from angr.engines.vex import SimEngineVEX
from angr.calling_conventions import SimStackArg, SimRegArg, SimCC, register_syscall_cc, register_default_cc, SimCC
from .arch_riscv import ArchRISCV


class SimCCRISCV(SimCC):
    ARG_REGS = [ 'a0', 'a1', 'a2', 'a3', 'a4', 'a5','a6', 'a7']
    FP_ARG_REGS = []    # TODO: ???
    STACK_ALIGNMENT = 16
    RETURN_ADDR = SimStackArg(4, 4)
    RETURN_VAL = SimRegArg('ra', 4)
    ARCH = ArchRISCV

class SimRISCV(SimOS):
    # Syscalls are for lamers
    SYSCALL_TABLE = {}


    def __init__(self, *args, **kwargs):
        super(SimRISCV, self).__init__(*args, name='RISCV', **kwargs)

    def configure_project(self):
        super(SimRISCV, self).configure_project()

        #self._load_syscalls(SimMSP430.SYSCALL_TABLE, "bf")

    def state_blank(self, data_region_size=0x8000, **kwargs):
        # pylint:disable=arguments-differ
        state = super(SimRISCV, self).state_blank(**kwargs)  # pylint:disable=invalid-name
        # PTR starts halfway through memory
        return state

    def state_entry(self, **kwargs):
        state = super(SimRISCV, self).state_entry(**kwargs)
        return state


class SimRISCVSyscall(SimCC):
    ARG_REGS = [ ]
    #RETURN_VAL = ""
    ARCH = ArchRISCV

    @staticmethod
    def _match(arch, args, sp_delta):   # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.inout

register_simos('UNIX - System V', SimRISCV)
register_syscall_cc('RISCV', 'default', SimRISCVSyscall)
register_default_cc('RISCV', SimCCRISCV)
