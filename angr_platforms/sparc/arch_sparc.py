import logging

l = logging.getLogger("archinfo.arch_sparc")

try:
    import capstone as _capstone
except ImportError:
    _capstone = None

try:
    import keystone as _keystone
except ImportError:
    _keystone = None

try:
    import unicorn as _unicorn
except ImportError:
    _unicorn = None

from .arch import Arch, register_arch, Endness, Register
from .tls import TLSArchInfo
from .archerror import ArchError

class ArchSPARC(Arch):
    def __init__(self, endness=Endness.BE):
        if endness != Endness.BE:
            raise ArchError('Arch SPARC must be big endian')
        super(ArchSPARC, self).__init__(endness)
        self.call_pushes_ret = False
        self.branch_delay_slot = False

    bits = 32
    name = 'SPARC'

    vex_arch = None  # No VEX support
    qemu_name = 'Sparc'
    ida_processor = 'SPARCII'
    triplet = None  # No linux support
    max_inst_bytes = 4

    ip_offset = 60
    sp_offset = 56
    bp_offset = 56
    lr_offset = 124
    ret_offset = 96

    vex_conditional_helpers = False
    syscall_num_offset = 28
    call_pushes_ret = False
    stack_change = -4

    memory_endness = Endness.BE
    register_endness = Endness.BE
    instruction_endness = Endness.BE
    sizeof = {'short': 16, 'int': 32, 'long': 32, 'long long': 64}

    if _capstone:
        cs_arch = _capstone.CS_ARCH_SPARC
        cs_mode = _capstone.CS_MODE_BIG_ENDIAN

    if _keystone:
        ks_arch = _keystone.KS_ARCH_SPARC
        ks_mode = _keystone.KS_MODE_SPARC32 + _keystone.KS_MODE_BIG_ENDIAN

    if _unicorn:
        uc_arch = _unicorn.UC_ARCH_SPARC
        uc_mode = _unicorn.UC_MODE_SPARC32
        uc_const = _unicorn.sparc_const
        uc_prefix = 'UC_SPARC_'

    function_prologs = {
        br"\x9d\xe3\xb0\x50"
        #save %sp, -80, %sp
        #10011101111000111011000001010000
    }

    function_epilogs = {
        br"\x81\xc7\xe0\x08"
        #jmpl %i7+8, %g0
        #10000001110001111110000000001000
        br"\x81\xc7\xe0\x0c"
        #jmpl %i7+12, %g0
        #10000001110001111110000000001100
        br"\x91\xed\x20\x00"
        #restore %l4, 0, %o0
        #10000001111010000010000000000000
        br"\x81\xe8\x20\x00"
        #restore %g0, 0, %g0
        #10000001111010000010000000000000
    }

    ret_instruction = b"\x81\xc7\xe0\x08"
    #jmpl %i7+8, %g0
    #10000001110001111110000000001000
    nop_instruction = b"\x01\x00\x00\x00"
    #nop
    #00000001000000000000000000000000
    instruction_alignment = 4

    register_list = [
        Register(name='r0', size=4, alias_names=('g0',), general_purpose=True, vex_offset=0, default_value=(0, False, 0)),
        Register(name='r1', size=4, alias_names=('g1',), general_purpose=True, vex_offset=4),
        Register(name='r2', size=4, alias_names=('g2',), general_purpose=True, vex_offset=8),
        Register(name='r3', size=4, alias_names=('g3',), general_purpose=True, vex_offset=12),
        Register(name='r4', size=4, alias_names=('g4',), general_purpose=True, vex_offset=16),
        Register(name='r5', size=4, alias_names=('g5',), general_purpose=True, vex_offset=20),
        Register(name='r6', size=4, alias_names=('g6',), general_purpose=True, vex_offset=24),
        Register(name='r7', size=4, alias_names=('g7',), general_purpose=True, vex_offset=28),
        Register(name='r8', size=4, alias_names=('o0',), general_purpose=True, vex_offset=32),
        Register(name='r9', size=4, alias_names=('o1',), general_purpose=True, vex_offset=36),
        Register(name='r10', size=4, alias_names=('o2',), general_purpose=True, vex_offset=40),
        Register(name='r11', size=4, alias_names=('o3',), general_purpose=True, vex_offset=44),
        Register(name='r12', size=4, alias_names=('o4',), general_purpose=True, vex_offset=48),
        Register(name='r13', size=4, alias_names=('o5',), general_purpose=True, vex_offset=52),
        Register(name='r14', size=4, alias_names=('o6', 'sp', 'bp',), general_purpose=True, vex_offset=56, default_value=(Arch.initial_sp, True, 'local')),
        Register(name='r15', size=4, alias_names=('o7',), general_purpose=True, vex_offset=60),
        Register(name='r16', size=4, alias_names=('l0',), general_purpose=True, vex_offset=64),
        Register(name='r17', size=4, alias_names=('l1',), general_purpose=True, vex_offset=68),
        Register(name='r18', size=4, alias_names=('l2',), general_purpose=True, vex_offset=72),
        Register(name='r19', size=4, alias_names=('l3',), general_purpose=True, vex_offset=76),
        Register(name='r20', size=4, alias_names=('l4',), general_purpose=True, vex_offset=80),
        Register(name='r21', size=4, alias_names=('l5',), general_purpose=True, vex_offset=84),
        Register(name='r22', size=4, alias_names=('l6',), general_purpose=True, vex_offset=88),
        Register(name='r23', size=4, alias_names=('l7',), general_purpose=True, vex_offset=92),
        Register(name='r24', size=4, alias_names=('i0',), general_purpose=True, vex_offset=96),
        Register(name='r25', size=4, alias_names=('i1',), general_purpose=True, vex_offset=100),
        Register(name='r26', size=4, alias_names=('i2',), general_purpose=True, vex_offset=104),
        Register(name='r27', size=4, alias_names=('i3',), general_purpose=True, vex_offset=108),
        Register(name='r28', size=4, alias_names=('i4',), general_purpose=True, vex_offset=112),
        Register(name='r29', size=4, alias_names=('i5',), general_purpose=True, vex_offset=116),
        Register(name='r30', size=4, alias_names=('i6', 'fp',), general_purpose=True, vex_offset=120),
        Register(name='r31', size=4, alias_names=('i7', 'lr',), general_purpose=True, vex_offset=124),
    ]

    lib_paths = None
    got_section_name = ".got"
    ld_linux_name = None
    byte_width = 8
    elf_tls = TLSArchInfo(2, 56, [8], [4], [0], 0, 0)  #I'm not sure how to determine the value of this formula

register_arch([r'sparc|sparc32|sparcv8'], 32, 'Iend_BE', ArchSPARC)


