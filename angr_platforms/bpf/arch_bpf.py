
from archinfo.arch import Arch
from archinfo.arch import register_arch


class ArchBPF(Arch):

    # The beginning address of the data variables
    DATA_BASE = 0x800000
    # The beginning address of the temporary variables
    TEMP_BASE = 0x900000

    def __init__(self, endness="Iend_LE"):
        super(ArchBPF, self).__init__('Iend_LE')

    bits = 32
    vex_arch = None
    name = "BPF"
    instruction_endness = 'Iend_BE'
    memory_endness = 'Iend_LE'

    registers = {
        'A': (0, 4),
        'X': (4, 4),
        'pc': (8, 4),
        'ip': (8, 4),
        'res': (12, 4)
    }

    register_names = {
        0: 'A',
        4: 'X',
        8: 'pc',
        12: 'res'
    }

    ip_offset = registers["pc"][0]


register_arch(['bpf'], 32, 'any', ArchBPF)
