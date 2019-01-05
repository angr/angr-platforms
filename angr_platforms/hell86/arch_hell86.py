from archinfo.arch import register_arch, Arch

class ArchHell86(Arch):
    def __init__(self, endness="Iend_LE"):
        super(ArchHell86, self).__init__(endness)
        # TODO: Define function prologs
        self.ip_offset = self.registers['ip'][0]
        self.sp_offset = self.registers['sp'][0]
        #self.call_pushes_ret = True
        #self.stack_change = -2
        #self.branch_delay_slot = False
        #self.default_register_values = [(n, 0, False, None) for n in self.register_index]
    sizeof = {'short': 16, 'int': 16, 'long': 32, 'long long': 64}
    function_prologs = {}
    function_epilogs = {}

    bits = 64
    name = "hell86"
    instruction_endness = "Iend_BE" # Yep.  MSP's instructions are endy-flipped when stored relative to the ISA.
    max_inst_bytes = 16
    ret_instruction = ""
    nop_instruction = ""
    instruction_alignment = 1
    persistent_regs = []

    entry_register_values = {
    }

    default_symbolic_registers = []

    register_index = [
        'r8',
        'r9',
        'r10',
        'r11',
        'r12',
        'r13',
        'r14',
        'r15',
        'rdi',
        'rsi',
        'rbp',
        'rbx',
        'rdx',
        'rax',
        'rcx',
        'rsp',
        'rip'
    ]

    register_names = {8 * i : s for i, s in enumerate(register_index)}

    registers = {s : (8 * i, 8 * i + 8) for i, s in enumerate(register_index)}
    registers['sp'] = registers['rsp']
    registers['ip'] = registers['rip']

    # EDG: Can you even use PIC here? I don't think so
    dynamic_tag_translation = {}

register_arch([r'hell86'], 32, 'Iend_LE' , ArchHell86)
