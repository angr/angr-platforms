from archinfo.arch import Arch
from archinfo.arch import register_arch

class ArchBF(Arch):
    def __init__(self, endness="Iend_LE"):
        super(ArchBF, self).__init__('Iend_LE')

        self.bits = 64
        self.vex_arch = None
        self.name = "BF"

        # Things I did not want to include but were necessary unfortunately :-(
        # self.cs_mode = capstone.CS_MODE_LITTLE_ENDIAN if endness == 'Iend_LE' else capstone.CS_MODE_BIG_ENDIAN
        # END
        # registers is a dictionary mapping register names, to a tuple of
        # register number, and their width, in bytes
        self.registers = {}
        self.registers["ip"] =       (0, 8)
        self.registers["ptr"] =       (1, 8)
        self.registers["inout"] =      (2, 1)
        self.registers["ip_at_syscall"] =      (3, 8)

        self.register_names = {}
        self.register_names[self.registers['ip'][0]] = 'pc'
        self.register_names[self.registers['ip'][1]] = 'ip'

        self.ip_offset = self.registers["ip"][0]

register_arch(['bf|brainfuck'], 64, 'any', ArchBF)
