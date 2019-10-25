from angr.simos import SimOS, register_simos
from angr.sim_procedure import SimProcedure
from angr.calling_conventions import SimStackArg, SimRegArg, register_syscall_cc, register_default_cc, SimCC
from .arch_msp430 import ArchMSP430


# http://mspgcc.sourceforge.net/manual/x1248.html
class SimCCMSP430(SimCC):
    ARG_REGS = [ 'r15', 'r14', 'r13', 'r12' ]
    FP_ARG_REGS = []    # TODO: ???
    STACKARG_SP_DIFF = 2
    RETURN_ADDR = SimStackArg(0, 2)
    RETURN_VAL = SimRegArg('r15', 2)
    ARCH = ArchMSP430

class MCstopexec(SimProcedure):

    NO_RET = True
    def run(self):
        self.exit(0)

class MCputs(SimProcedure):
    def run(self):
        return 1

class MCgetsn(SimProcedure):
    """
    Microcorruption's getsn:
    Args: R15 has an address to write to.
          R14 has the max number of bytes to read

    """
    num_args = 2
    NUM_ARGS = 2
    # pylint:disable=arguments-differ

    def run(self, ptr, maxbytes):
        self.state.posix.fd[0].read(ptr, maxbytes)
        # NOTE: The behavior of EOF (this is zero) is undefined!!!
        return self.state.solver.Unconstrained('getsn', self.state.arch.bits)


class SimMSP430(SimOS):
    # Syscalls are for lamers
    SYSCALL_TABLE = {}


    def __init__(self, *args, **kwargs):
        super(SimMSP430, self).__init__(*args, name="MSP430", **kwargs)

    def configure_project(self):
        super(SimMSP430, self).configure_project()

        #self._load_syscalls(SimMSP430.SYSCALL_TABLE, "bf")

    def state_blank(self, data_region_size=0x8000, **kwargs):
        # pylint:disable=arguments-differ
        state = super(SimMSP430, self).state_blank(**kwargs)  # pylint:disable=invalid-name
        # PTR starts halfway through memory
        return state

    def state_entry(self, **kwargs):
        state = super(SimMSP430, self).state_entry(**kwargs)
        return state


class SimMSP430Syscall(SimCC):
    ARG_REGS = [ ]
    #RETURN_VAL = ""
    ARCH = ArchMSP430

    @staticmethod
    def _match(arch, args, sp_delta):   # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.inout

register_simos('Standalone App', SimMSP430)
register_syscall_cc('MSP430', 'default', SimMSP430Syscall)
register_default_cc('MSP430', SimCCMSP430)
