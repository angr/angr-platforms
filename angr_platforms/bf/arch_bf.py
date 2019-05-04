from archinfo.arch import Arch, Register, Endness
from archinfo.arch import register_arch


class ArchBF(Arch):

    memory_endness = Endness.LE
    bits = 64
    vex_arch = None
    name = "BF"
    instruction_alignment = 1

    # Things I did not want to include but were necessary unfortunately :-(
    # self.cs_mode = capstone.CS_MODE_LITTLE_ENDIAN if endness == 'Iend_LE' else capstone.CS_MODE_BIG_ENDIAN
    # END
    # registers is a dictionary mapping register names, to a tuple of
    # register offset, and their width, in bytes

    register_list = [
        Register(name="ip", size=8, vex_offset=0),
        Register(name="ptr", size=8, vex_offset=8),
        Register(name="inout", size=1, vex_offset=16),
        Register(name="ip_at_syscall", size=8, vex_offset=24),
    ]
    ip_offset = 0

    def __init__(self, endness=Endness.LE):

        # forces little endian
        super().__init__(Endness.LE)


register_arch(['bf|brainfuck'], 64, 'any', ArchBF)
