from archinfo.arch import register_arch, Arch

class ArchMSP430(Arch):
    def __init__(self, endness="Iend_LE"):
        super(ArchMSP430, self).__init__(endness)
        # TODO: Define function prologs
        self.ip_offset = 0
        self.sp_offset = 2
        # bp_offset = 128
        # ret_offset = 16
        # lr_offset = 132
        # syscall_num_offset = 16
        self.call_pushes_ret = True
        self.stack_change = -2
        self.branch_delay_slot = False
        self.default_register_values = [(n, 0, False, None) for n in self.register_index]
    sizeof = {'short': 16, 'int': 16, 'long': 32, 'long long': 64}
    function_prologs = {}
    function_epilogs = {}
    qemu_name = 'msp430'

    bits = 16
    name = "MSP430"
    vex_arch = None
    instruction_endness = "Iend_LE" # Yep.  MSP's instructions are endy-flipped when stored relative to the ISA.
    ida_processor = 'msp430'
    max_inst_bytes = 6
    ret_instruction = "\x98\x00"
    nop_instruction = ""
    instruction_alignment = 1
    persistent_regs = []

    entry_register_values = {
    }

    default_symbolic_registers = []

    class Mode:
        REGISTER_MODE = 0
        INDEXED_MODE = 1
        INDIRECT_REGISTER_MODE = 2
        INDIRECT_AUTOINCREMENT_MODE = 3
        SYMBOLIC_MODE = 4
        ABSOLUTE_MODE = 5
        IMMEDIATE_MODE = 6
        CONSTANT_MODE0 = 7
        CONSTANT_MODE1 = 8
        CONSTANT_MODE2 = 9
        CONSTANT_MODE4 = 10
        CONSTANT_MODE8 = 11
        CONSTANT_MODE_NEG1 = 12
        OFFSET = 13

    register_index = [
        'pc',
        'sp',
        'sr',
        'cg',
        'r4',
        'r5',
        'r6',
        'r7',
        'r8',
        'r9',
        'r10',
        'r11',
        'r12',
        'r13',
        'r14',
        'r15'
    ]
    register_names = {
        0: 'pc',
        2: 'sp',
        4: 'sr',
        6: 'zero',
        8: 'r4',
        10: 'r5',
        12: 'r6',
        14: 'r7',
        16: 'r8',
        18: 'r9',
        20: 'r10',
        22: 'r11',
        24: 'r12',
        26: 'r13',
        28: 'r14',
        30: 'r15'
    }

    registers = {
        'r0': (0, 2),
        'pc': (0, 2),
        'ip': (0, 2),
        'r1': (2, 2),
        'sp': (2, 2),
        'r2': (4, 2),
        'sr': (4, 2),
        'r3': (6, 2),
        'zero': (6, 2),
        'cg': (6, 2),
        'r4': (8, 2),
        'r5': (10, 2),
        'r6': (12, 2),
        'r7': (14, 2),
        'r8': (16, 2),
        'r9': (18, 2),
        'r10': (20, 2),
        'r11': (22, 2),
        'r12': (24, 2),
        'r13': (26, 2),
        'r14': (28, 2),
        'r15': (30, 2)
    }
    argument_registers = {
        registers['r4'][0],
        registers['r5'][0],
        registers['r6'][0],
        registers['r7'][0],
        registers['r8'][0],
        registers['r9'][0],
        registers['r10'][0],
        registers['r11'][0],
        registers['r12'][0],
        registers['r13'][0],
        registers['r14'][0],
        registers['r15'][0],
    }

    # EDG: Can you even use PIC here? I don't think so
    dynamic_tag_translation = {}

register_arch([r'msp|msp430|em_msp430'], 32, 'Iend_LE' , ArchMSP430)
