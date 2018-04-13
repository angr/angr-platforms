from archinfo.arch import register_arch, Arch, Endness
from archinfo.tls import TLSArchInfo
"""from angr.simos import register_simos
register_simos('SH4', SimMSP430)"""

class ArchSH4(Arch):
    def __init__(self, endness=Endness.BE):
        super(ArchSH4, self).__init__(endness)
        self.ip_offset = 72
        self.sp_offset = 68
        self.call_pushes_ret = True
        self.stack_change = -4
        self.branch_delay_slot = True # jmp is delayed branch instruction in sh4
        self.memory_endness = endness
        self.register_endness = endness
        self.default_register_values = [
            ( 'pc', 0xA0000000, True, 'global' ),
            ( 'fpscr', 0x40001, False, None ),
            ( 'vbr', 0x0, False, None ),
            ( 'fpscr', 0x40001, False, None ),
        ]
    sizeof = {'short': 16, 'int': 16, 'long': 32, 'long long': 64}
    # mov.l [r8-r14], @-r15)*; (sts.l pr, @-r15)*; (add #-h'??, r15)*; (mov
    # r15, r14)*
    """
    .text:00414AD8 86 2F                             mov.l   r8, @-r15
    .text:00414ADA 96 2F                             mov.l   r9, @-r15
    .text:00414ADC A6 2F                             mov.l   r10, @-r15
    .text:00414ADE B6 2F                             mov.l   r11, @-r15
    .text:00414AE0 C6 2F                             mov.l   r12, @-r15
    .text:00414AE2 D6 2F                             mov.l   r13, @-r15
    .text:00414AE4 E6 2F                             mov.l   r14, @-r15
    .text:00414AE6 22 4F                             sts.l   pr, @-r15
    .text:00414AE8 E0 7F                             add     #-h'20, r15
    .text:00414AEA F3 6E                             mov     r15, r14
    """
    function_prologs = [
        br"([\x86\x96\xa6\xb6\xc6\xd6\xe6]{1}\x2f)*(\x22\x4f)*([\x00-\xff]\x7f)*(\xf3\x6e)*"
    ]
    # add #h'??, r14; mov r14, r15; lds.l @r15+, pr; (mov.l @r15+, [r8-r14])*;
    # rts
    """
    .text:00414BF0 20 7E                             add     #h'20, r14
    .text:00414BF2 E3 6F                             mov     r14, r15
    .text:00414BF4 26 4F                             lds.l   @r15+, pr
    .text:00414BF6 F6 6E                             mov.l   @r15+, r14
    .text:00414BF8 F6 6D                             mov.l   @r15+, r13
    .text:00414BFA F6 6C                             mov.l   @r15+, r12
    .text:00414BFC F6 6B                             mov.l   @r15+, r11
    .text:00414BFE F6 6A                             mov.l   @r15+, r10
    .text:00414C00 F6 69                             mov.l   @r15+, r9
    .text:00414C02 0B 00                             rts
    ##################[please check these regexes out]###################
    .text:00415544 10 7E                             add     #h'10, r14
    .text:00415546 E3 6F                             mov     r14, r15
    .text:00415548 26 4F                             lds.l   @r15+, pr
    .text:0041554A 0B 00                             rts
    .text:0041554C F6 6E                             mov.l   @r15+, r14
    """
    function_epilogs = [
        br"[\x00-\xff]{1}\x7e\xe3\x6f\x26\x4f\xf6[\x68\x69\x6a\x6b\x6c\x6d\x6e]{1}\x0b\x00"
    ]
    qemu_name = 'sh4'
    vex_arch = "None" # doesn't support right now :>
    bits = 32
    name = "sh4"
    linux_name = 'sh4'
    triplet = 'sh4-linux-gnu' # ? https://github.com/flashrom/flashrom-buildbot/blob/master/build-libftdi1#L28
    #instruction_endness = Endness.LE # It's bi-endian, LE/BE but default LE
    ida_processor = 'sh4'
    max_inst_bytes = 4
    lr_offset = 76
    ip_offset = 72
    sp_offset = 68
    bp_offset = 64
    ret_offset = 8
    syscall_num_offset = 8 # didn't find it in official docs - derivated from prizm cpus
    # there's another return called RTE used to return from change to
    # supervisor mode exceptions, but RTS is used in combination with RTS for
    # subroutine procedure calls
	# Adam: commented this out due to weird crash
    #ret_instruction = b"\x0b\x00" # RTS (ReTurn from Subroutine)
    #nop_instruction = b"\x09\x00"
    instruction_alignment = 1
    persistent_regs = [ 'r8', 'r9', 'r10', 'r11', 'r12', 'r13' ] # does it mean permanent registers ?

    entry_register_values = {
    }

    default_symbolic_registers = [ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8'
                                  'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'pc'
                                  'pr', 'gbr', 'vbr', 'mach', 'macl', 'sr', 'fpul', 'fr0' ]
    register_index = [
        'r0',
        'r1',
        'r2',
        'r3',
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
        'r15',
        'pc',
        'pr',
        'gbr',
        'vbr',
        'mach',
        'macl',
        'sr'
    ]
    register_names = {
        8: 'r0',
        12: 'r1',
        16: 'r2',
        20: 'r3',
        24: 'r4',
        28: 'r5',
        32: 'r6',
        36: 'r7',
        40: 'r8',
        44: 'r9',
        48: 'r10',
        52: 'r11',
        56: 'r12',
        60: 'r13',
        64: 'r14',
        68: 'r15',
        72: 'pc',
        76: 'pr',
        80: 'gbr',
        84: 'vbr',
        88: 'mach',
        92: 'macl',
        96: 'sr',
        100: 'fpul',
        104: 'fpscr',
        #single-precision floating-point registers
        108: 'fr0',
        112: 'fr1',
        116: 'fr2',
        120: 'fr3',
        124: 'fr4',
        128: 'fr5',
        132: 'fr6',
        136: 'fr7',
        140: 'fr8',
        144: 'fr9',
        148: 'fr10',
        152: 'fr11',
        156: 'fr12',
        160: 'fr13',
        164: 'fr14',
        168: 'fr15',
        172: 'ssr',
        176: 'spc',
        180: 'dbr',
        184: 'sgr',
        # single-precision floating-point extended registers
        188: 'xf0',
        192: 'xf1',
        196: 'xf2',
        200: 'xf3',
        204: 'xf4',
        208: 'xf5',
        212: 'xf6',
        216: 'xf7',
        220: 'xf8',
        224: 'xf9',
        228: 'xf10',
        232: 'xf11',
        236: 'xf12',
        240: 'xf13',
        244: 'xf14',
        248: 'xf15'
    }
    registers = {
        'r0': (8, 4),
        'r1': (12, 4),
        'r2': (16, 4),
        'r3': (20, 4),
        'r4': (24, 4),
        'r5': (28, 4),
        'r6': (32, 4),
        'r7': (36, 4),
        'r8': (40, 4),
        'r9': (44, 4),
        'r10': (48, 4),
        'r11': (52, 4),
        'r12': (56, 4),
        'gp': (56, 4),
        'r13': (60, 4),
        'r14': (64, 4),
        'fp': (64, 4),
        'r15': (68, 4),
        'sp': (68, 4),
        'pc': (72, 4),
        'ip': (72, 4),
        'pr': (76, 4),
        'gbr': (80, 4),
        'vbr': (84, 4),
        'mach': (88, 4),
        'macl': (92, 4),
        'sr': (96, 4),
        'fpul': (100, 4),
        'fpscr': (104, 4),
        # fv0 -> (dr0 -> (fr0, fr1), dr1 -> (fr2, fr3))
        'fr0': (108, 4),
        'fr1': (112, 4),
        'dr0': (108, 8),
        'fr2': (116, 4),
        'fr3': (120, 4),
        'dr2': (116, 8),
        'fv0': (108, 16),
        # fv4 -> (dr4 -> (fr4, fr5), dr6 -> (fr6, fr7))
        'fr4': (124, 4),
        'fr5': (128, 4),
        'dr4': (124, 8),
        'fr6': (132, 4),
        'fr7': (136, 4),
        'dr6': (132, 8),
        'fv4': (124, 16),
        # fv8 -> (dr8 -> (fr8, fr9), dr10 -> (fr10, fr11))
        'fr8': (136, 4),
        'fr9': (140, 4),
        'dr8': (136, 8),
        'fr10': (144, 4),
        'fr11': (148, 4),
        'dr10': (144, 8),
        'fv8': (136, 16),
        # fv12 -> (dr12 -> (fr12, fr13), dr14 -> (fr14, fr15))
        'fr12': (152, 4),
        'fr13': (156, 4),
        'dr12': (152, 8),
        'fr14': (160, 4),
        'fr15': (164, 4),
        'dr14': (160, 8),
        'fv12': (152, 16),
        'xmtrx': (108, 64)
    }
    argument_registers = {
        registers['r0'][0],
        registers['r1'][0],
        registers['r2'][0],
        registers['r3'][0],
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
        registers['fr4'][0],
        registers['fr5'][0],
        registers['fr6'][0],
        registers['fr7'][0],
        registers['fr8'][0],
        registers['fr9'][0],
        registers['fr10'][0],
        registers['fr11'][0]
    }

    dynamic_tag_translation = {
        0x0: 'R_SH_NONE',
        0x1: 'R_SH_DIR32',
        0x2: 'R_SH_REL32',
        0x3: 'R_SH_DIR8WPN',
        0x4: 'R_SH_IND12W',
        0x5: 'R_SH_DIR8WPL',
        0x6: 'R_SH_DIR8WPZ',
        0x7: 'R_SH_DIR8BP',
        0x8: 'R_SH_DIR8W',
        0x9: 'R_SH_DIR8L',
        0xa0: 'R_SH_GOT32',
        0xa1: 'R_SH_PLT32',
        0xa2: 'R_SH_COPY',
        0xa3: 'R_SH_GLOB_DAT',
        0xa4: 'R_SH_JMP_SLOT',
        0xa5: 'R_SH_RELATIVE',
        0xa6: 'R_SH_GOTOFF',
        0xa7: 'R_SH_GOTPC',
        0xa8: 'R_SH_GOTPLT32',
        0xa9: 'R_SH_GOTPLT_LOW16',
        0xaa: 'R_SH_GOTPLT_MEDLOW16',
        0xab: 'R_SH_GOTPLT_MEDHI16',
        0xac: 'R_SH_GOTPLT_HI16',
        0xb1: 'R_SH_PLT_LOW16',
        0xb2: 'R_SH_PLT_MEWLOW16',
        0xb3: 'R_SH_PLT_MEDHI16',
        0xb4: 'R_SH_PLT_HI16',
        0xb5: 'R_SH_GOTOFF_LOW16',
        0xb6: 'R_SH_GOTOFF_MEWLOW16',
        0xb7: 'R_SH_GOTOFF_MEDHI16',
        0xb8: 'R_SH_GOTOFF_HI16',
        0xb9: 'R_SH_GOTPC_LOW16',
        0xba: 'R_SH_GOTPC_MEDLOW16',
        0xbb: 'R_SH_GOTPC_MEDHI16',
        0xbc: 'R_SH_GOTPC_HI16',
        0xbd: 'R_SH_GOTPLT10BY4',
        0xbf: 'R_SH_GOTPLT10BY8',
        0xc1: 'R_SH_COPY64',
        0xc2: 'R_SH_GLOB_DAT64',
        0xc3: 'R_SH_JMP_SLOT64',
        0xc4: 'R_SH_RELATIVE64',
        0xfe: 'R_SH_64',
        0xff: 'R_SH_64_PCREL'
    }

    got_section_name = '.got'
    ld_linux_name = 'ld-linux-sh4.so.2'
    elf_tls = TLSArchInfo(2, 56, [8], [4], [0], 0, 0)
	
register_arch([r'.*sh4.*|.*sh.*|em_sh'], 32, 'any' , ArchSH4)
