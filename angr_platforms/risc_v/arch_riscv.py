from archinfo.arch import register_arch, Arch, Register
from archinfo.tls import TLSArchInfo
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV32

#copied from arch msp430
class ArchRISCV(Arch):
    def __init__(self, endness="Iend_LE"):
        super(ArchRISCV, self).__init__(endness)
        self.call_pushes_ret = False
        self.branch_delay_slot = False
    sizeof = {'short': 16, 'int': 32, 'long': 32, 'long long': 64}
    function_prologs = {}
    function_epilogs = {}

    bits = 32
    name = "RISCV"
    cs_arch = CS_ARCH_RISCV
    cs_mode = CS_MODE_RISCV32 
    instruction_endness = "Iend_LE" 
    max_inst_bytes = 4
    instruction_alignment = 4
    persistent_regs = []
    ret_instruction=b"\x00\x00\x80\x67"
    nop_instruction=b"\x13\x00\x00\x00"
    elf_tls = TLSArchInfo(1, 8, [], [0], [], 0, 0)

    register_list = [
       Register(name="x0", size = 4, alias_names=('zero',), vex_offset=0, default_value=(0,False, 0)),
       Register(name='x1', size = 4, alias_names=('ra','lr',), general_purpose=True, vex_offset = 4),
       Register(name='x2', size = 4, alias_names=('sp','bp'), general_purpose=True, default_value=(Arch.initial_sp, True, 'global'), vex_offset=8),
       Register(name='x3', size = 4, alias_names=('gp',), general_purpose=True, vex_offset=12),
       Register(name='x4', size = 4, alias_names=('tp',), general_purpose=True, vex_offset=16),
       Register(name='x5', size = 4, alias_names=('t0',), general_purpose=True, vex_offset=20),
       Register(name='x6', size = 4, alias_names=('t1',), general_purpose=True, vex_offset=24),
       Register(name='x7', size = 4, alias_names=('t2',), general_purpose=True, vex_offset=28),
       Register(name='x8', size = 4, alias_names=('s0','fp'), general_purpose=True, vex_offset=32),
       Register(name='x9', size = 4, alias_names=('s1',), general_purpose=True, vex_offset=36),
       Register(name='x10', size = 4, alias_names=('a0',), general_purpose=True, argument=True, vex_offset=40),
       Register(name='x11', size = 4, alias_names=('a1',), general_purpose=True, argument=True, vex_offset=44),
       Register(name='x12', size = 4, alias_names=('a2',), general_purpose=True, argument=True, vex_offset=48),
       Register(name='x13', size = 4, alias_names=('a3',), general_purpose=True, argument=True, vex_offset=52),
       Register(name='x14', size = 4, alias_names=('a4',), general_purpose=True, argument=True, vex_offset=56),
       Register(name='x15', size = 4, alias_names=('a5',), general_purpose=True, argument=True, vex_offset=60),
       Register(name='x16', size = 4, alias_names=('a6',), general_purpose=True, argument=True, vex_offset=64),
       Register(name='x17', size = 4, alias_names=('a7',), general_purpose=True, argument=True, vex_offset=68),
       Register(name='x18', size = 4, alias_names=('s2',), general_purpose=True, vex_offset=72),
       Register(name='x19', size = 4, alias_names=('s3',), general_purpose=True, vex_offset=76),
       Register(name='x20', size = 4, alias_names=('s4',), general_purpose=True, vex_offset=80),
       Register(name='x21', size = 4, alias_names=('s5',), general_purpose=True, vex_offset=84),
       Register(name='x22', size = 4, alias_names=('s6',), general_purpose=True, vex_offset=88),
       Register(name='x23', size = 4, alias_names=('s7',), general_purpose=True, vex_offset=92),
       Register(name='x24', size = 4, alias_names=('s8',), general_purpose=True, vex_offset=96),
       Register(name='x25', size = 4, alias_names=('s9',), general_purpose=True, vex_offset=100),
       Register(name='x26', size = 4, alias_names=('s10',), general_purpose=True, vex_offset=104),
       Register(name='x27', size = 4, alias_names=('s11',), general_purpose=True, vex_offset=108),
       Register(name='x28', size = 4, alias_names=('t3',), general_purpose=True, vex_offset=112),
       Register(name='x29', size = 4, alias_names=('t4',), general_purpose=True, vex_offset=116),
       Register(name='x30', size = 4, alias_names=('t5',), general_purpose=True, vex_offset=120),
       Register(name='x31', size = 4, alias_names=('t6',), general_purpose=True, vex_offset=124),
       Register(name='ip', alias_names={'pc',}, size=4, vex_offset=128),
    ]

register_arch([r'riscv32|riscv|RISCV|em_riscv|em_riscv32'], 32, 'Iend_LE' , ArchRISCV)
