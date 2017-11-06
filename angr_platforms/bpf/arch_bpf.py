
from archinfo.arch import Arch
from archinfo.arch import register_arch


class ArchBPF(Arch):
    def __init__(self, endness="Iend_LE"):
        super(ArchBPF, self).__init__('Iend_LE')

        self.bits = 32
        self.vex_arch = None
        self.name = "BPF"
        self.memory_endness = 'Iend_LE'

        self.registers = {}
        self.registers['A'] = (0, 4)
        self.registers['X'] = (4, 4)
        self.registers['pc'] = (8, 4)
        self.registers['ip'] = (8, 4)
        self.registers['res'] = (12, 4)

        self.register_names = { }
        self.register_names[0] = 'A'
        self.register_names[4] = 'X'
        self.register_names[8] = 'pc'
        self.register_names[12] = 'res'

        self.ip_offset = self.registers["pc"][0]


register_arch(['bpf'], 32, 'any', ArchBPF)
