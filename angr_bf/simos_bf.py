from angr.simos import SimOS, register_simos
from simuvex import SimCC, SimProcedure
from simuvex.s_cc import register_syscall_cc, register_default_cc, SimCCUnknown
from . import ArchBF


class WriteByteAtPtr(SimProcedure):
    """
    Defines what to do for the "." instruction.
    """


    IS_SYSCALL = True
    NUM_ARGS = 0
    num_args = 0
    # pylint:disable=arguments-differ
    def run(self, state):
        fd = 1  # POSIX STDOUT
        data = self.state.memory.load(self.state.regs.ptr, 1)
        self.state.posix.write(fd, data, 1)
        return None


class ReadByteToPtr(SimProcedure):
    """
    Defines what to do for the "," instruction
    """

    IS_SYSCALL = True
    num_args = 0
    NUM_ARGS = 0
    # pylint:disable=arguments-differ

    def run(self, state):
        fd = 0 # Posix STDIN
        read_length = self.state.posix.read(fd, self.state.regs.ptr, 1)
        # NOTE: The behavior of EOF (this is zero) is undefined!!!
        return None


class SimBF(SimOS):
    """
    Defines the "OS" of a BrainFuck program.

    This means:
    -  The memory layout (separate code and data)
    -  The "syscalls" (read stdin and write stdout)

    """
    SYSCALL_TABLE = {
        0: ('read_byte_to_ptr', ReadByteToPtr),
        1: ('write_byte_at_ptr', WriteByteAtPtr),
    }

    def __init__(self, *args, **kwargs):
        super(SimBF, self).__init__(*args, name="BF", **kwargs)

    def configure_project(self):
        super(SimBF, self).configure_project()

        self._load_syscalls(SimBF.SYSCALL_TABLE, "bf")

    def state_blank(self, fs=None, **kwargs):
        state = super(SimBF, self).state_blank(**kwargs)  # pylint:disable=invalid-name
        # PTR starts halfway through memory
        state.regs.ptr = 0x80000000
        state.memory.store(state.regs.ptr,0,0xffffffff - state.regs.ptr)
        return state

    def state_entry(self, **kwargs):
        state = super(SimBF, self).state_entry(**kwargs)
        # PTR starts halfway through memory
        state.regs.ptr = 0x80000000
        state.memory.store(state.regs.ptr,0,0xffffffff - state.regs.ptr)
        return state


class SimBFSyscall(SimCC):
    """
    This defines our syscall format.
    Obviously this is pretty dumb, for BrainFuck
    This is really just here to make the two simprocedures work.
    """

    # No need to pull the regs out, we always just want ptr straight up.
    # THis is usually a list of string register names.
    ARG_REGS = [ 'ptr' ]
    # We never return anything to registers, but if we did, we'd use a RegArg object here.
    #RETURN_VAL = ""
    ARCH = ArchBF

    @staticmethod
    def _match(arch, args, sp_delta):   # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.inout


register_simos('bf', SimBF)
register_syscall_cc('BF','default',SimBFSyscall)
register_default_cc('BF',SimCCUnknown)
