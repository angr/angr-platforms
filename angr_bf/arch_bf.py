from archinfo.arch import Arch
from archinfo import register_arch

class ArchBF(Arch):
    def __init__(self, endness="Iend_LE"):
        super(ArchBF, self).__init__('Iend_LE'f)

        self.bits = 64
        self.vex_arch = None
        self.name = "BF"

        # Things I did not want to include but were necessary unfortunately :-(
        # self.cs_mode = capstone.CS_MODE_LITTLE_ENDIAN if endness == 'Iend_LE' else capstone.CS_MODE_BIG_ENDIAN
        # END

        self.registers = {}
        self.registers["pc"] =       (0, 1)
        self.registers["ptr"] =       (1, 1)
        self.registers["inout"] =      (2, 1)
        self.registers["ip_at_syscall"] =      (3, 1)

        self.register_names = {}
        self.register_names[self.registers['pc'][0]] = 'pc'

        self.ip_offset = self.registers["pc"][0]

register_arch(['bf|brainfuck'], 64, 'any', ArchBF)
