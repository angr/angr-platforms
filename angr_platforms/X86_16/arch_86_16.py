from archinfo import ArchError, RegisterOffset

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

import pyvex
from archinfo.arch import Arch, Endness, Register, register_arch


class Arch86_16(Arch):

    def __init__(self, endness=Endness.LE):
        import logging
        self.logger = logging.getLogger(__name__)
        super().__init__(endness)
        self.endness = 'Iend_LE'
        self.reg_blacklist = []
        self.reg_blacklist_offsets = []
        self.vex_archinfo = None
        self.vex_cc_regs = None
        self.vex_to_unicorn_map = None
        #self.registers = self.register_list

        # Enforce 16-bit primary types
        self.bits = 16

        offset = 0
        for reg in self.register_list:
            reg.vex_offset = offset
            offset += (reg.size // 8)  # Bytes for VEX alignment
            if reg.name in ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ip', 'flags', 'cs', 'ds', 'es', 'fs', 'gs', 'ss']:
                offset += 2  # Ensure 2-byte alignment for 16-bit regs, skip artificial

        self.logger.info("Arch86_16 init: Register offsets set (16-bit primary, sequential)")
        for reg in self.register_list:
            self.logger.debug(f"Reg {reg.name}: size {reg.size}, vex_offset {reg.vex_offset}")

        self.vex_offsets = {reg.name.lower(): reg.vex_offset for reg in self.register_list}

    name = "86_16"
    bits = 16
    stack_change = -2
    vex_arch = pyvex.ARCH_X86
    vex_support = True
    vex_conditional_helpers = False
    sizeof = {"short": 16, "int": 16, "long": 32, "long long": 32}
    ld_linux_name = None
    linux_name = None
    lib_paths = []
    #max_inst_bytes = 4
    #ip_offset = 0x80000000
    #sp_offset = 16
    call_pushes_ret = True
    instruction_endness = Endness.LE
    # FIXME: something in angr assumes that sizeof(long) == sizeof(return address on stack)
    #initial_sp = 0x7fff
    call_sp_fix = 2
    instruction_alignment = 1
    #ioreg_offset = 0x20
    memory_endness = Endness.LE
    register_endness = Endness.LE


    elf_tls = None
    if _capstone:
        cs_arch = _capstone.CS_ARCH_X86  # Disassembler
        cs_mode = _capstone.CS_MODE_16 + _capstone.CS_MODE_LITTLE_ENDIAN
    _cs_x86_syntax = None  # Set it to 'att' in order to use AT&T syntax for x86
    if _keystone:
        ks_arch = _keystone.KS_ARCH_X86  # Assembler
        ks_mode = _keystone.KS_MODE_16 + _keystone.KS_MODE_LITTLE_ENDIAN
    _ks_x86_syntax = None
    uc_arch = _unicorn.UC_ARCH_X86 if _unicorn else None  # Emulator
    uc_mode = (_unicorn.UC_MODE_16 + _unicorn.UC_MODE_LITTLE_ENDIAN) if _unicorn else None
    uc_const = _unicorn.x86_const if _unicorn else None
    uc_prefix = "UC_X86_" if _unicorn else None
    function_prologs = {rb"\x55\x8b\xec", rb"\xc8"}  # push bp; mov bp, sp
    function_epilogs = {
        rb"\xc9\xc3", rb"\xc9\xcb",  # leave; ret
        rb"\x5d\xc3", rb"\x5d\xcb"}  # pop <reg>; ret
    ret_offset = RegisterOffset(0)  # ax - syscall return register?
    ret_instruction = b"\xc3"
    nop_instruction = b"\x90"


    register_list = [
        # Primary 16-bit registers only (size=2, no 32-bit to avoid recursion in name resolution)
        Register(
            name="ax",
            size=2,
            subregisters=[("al", 0, 1), ("ah", 1, 1)],
            general_purpose=True,
            argument=True,
            vex_offset=0,
        ),
        Register(
            name="cx",
            size=2,
            subregisters=[("cl", 0, 1), ("ch", 1, 1)],
            general_purpose=True,
            vex_offset=2,
        ),
        Register(
            name="dx",
            size=2,
            subregisters=[("dl", 0, 1), ("dh", 1, 1)],
            general_purpose=True,
            vex_offset=4,
        ),
        Register(
            name="bx",
            size=2,
            subregisters=[("bl", 0, 1), ("bh", 1, 1)],
            general_purpose=True,
            vex_offset=6,
        ),
        Register(
            name="sp",
            size=2,
            alias_names=("stack_base",),
            general_purpose=True,
            default_value=(0x7fff, True, "global"),
            vex_offset=8,
        ),
        Register(
            name="bp",
            size=2,
            general_purpose=True,
            argument=True,
            vex_offset=10,
        ),
        Register(
            name="si",
            size=2,
            vex_offset=12,
            general_purpose=True,
        ),
        Register(
            name="di",
            size=2,
            vex_offset=14,
            general_purpose=True,
        ),
        Register(
            name="ip",
            size=2,
            alias_names=("pc", "eip"),
            vex_offset=16,  # PC at fixed offset, no subreg/alias cycle
        ),
        Register(
            name="flags",
            size=2,
            alias_names=("eflags",),
            vex_offset=18,
        ),
        Register(name="cs", size=2, vex_offset=20),
        Register(name="ds", size=2, vex_offset=22),
        Register(name="es", size=2, vex_offset=24),
        Register(name="fs", size=2, default_value=(0, False, None), concrete=False, vex_offset=26),
        Register(name="gs", size=2, default_value=(0, False, None), concrete=False, vex_offset=28),
        Register(name="ss", size=2, vex_offset=30),
        # Flags and helpers (4-byte, artificial, no subregs)
        Register(name="d", size=4, alias_names=("dflag",), default_value=(1, False, None), concrete=False, artificial=True, vex_offset=32),
        Register(name="id", size=4, alias_names=("idflag",), default_value=(1, False, None), concrete=False, artificial=True, vex_offset=36),
        Register(name="ac", size=4, alias_names=("acflag",), default_value=(0, False, None), concrete=False, artificial=True, vex_offset=40),
        Register(name="cmstart", size=4, vex_offset=44),
        Register(name="cmlen", size=4, vex_offset=48),
        Register(name="nraddr", size=4, artificial=True, vex_offset=52),
        Register(name="sc_class", size=4, artificial=True, vex_offset=56),
        Register(name="ip_at_syscall", size=4, concrete=False, artificial=True, vex_offset=60),
        # FPU (unchanged, offset after)
        Register(
            name="fpreg",
            size=64,
            alias_names=("fpu_regs",),
            floating_point=True,
            concrete=False,
            vex_offset=64,
        ),
        Register(name="fptag", size=8, alias_names=("fpu_tags",), floating_point=True, default_value=(0, False, None), vex_offset=128),
        Register(name="fpround", size=4, floating_point=True, default_value=(0, False, None), vex_offset=136),
        Register(name="fc3210", size=4, floating_point=True, vex_offset=140),
    ]

    @property
    def capstone_x86_syntax(self):
        """Get the current syntax Capstone uses for x86. It can be 'intel' or 'at&t'

        :return: Capstone's current x86 syntax
        :rtype: str
        """
        return self._cs_x86_syntax

    @capstone_x86_syntax.setter
    def capstone_x86_syntax(self, new_syntax):
        """Set the syntax that Capstone outputs for x86.
        """
        if new_syntax not in ("intel", "at&t"):
            raise ArchError('Unsupported Capstone x86 syntax. It must be either "intel" or "at&t".')

        if new_syntax != self._cs_x86_syntax:
            self._cs = None
            self._cs_x86_syntax = new_syntax

    def _configure_capstone(self):
        self._cs.syntax = (
            _capstone.CS_OPT_SYNTAX_ATT if self._cs_x86_syntax == "at&t" else _capstone.CS_OPT_SYNTAX_INTEL
        )

    @property
    def keystone_x86_syntax(self):
        """Get the current syntax Keystone uses for x86. It can be 'intel',
        'at&t', 'nasm', 'masm', 'gas' or 'radix16'

        :return: Keystone's current x86 syntax
        :rtype: str
        """
        return self._ks_x86_syntax

    @keystone_x86_syntax.setter
    def keystone_x86_syntax(self, new_syntax):
        """Set the syntax that Keystone uses for x86.
        """
        if new_syntax not in ("intel", "at&t", "nasm", "masm", "gas", "radix16"):
            raise ArchError(
                "Unsupported Keystone x86 syntax. It must be one of the following: "
                '"intel", "at&t", "nasm", "masm", "gas" or "radix16".',
            )

        if new_syntax != self._ks_x86_syntax:
            self._ks = None
            self._ks_x86_syntax = new_syntax

    def _configure_keystone(self):
        if self._ks_x86_syntax == "at&t":
            self._ks.syntax = _keystone.KS_OPT_SYNTAX_ATT
        elif self._ks_x86_syntax == "nasm":
            self._ks.syntax = _keystone.KS_OPT_SYNTAX_NASM
        elif self._ks_x86_syntax == "masm":
            self._ks.syntax = _keystone.KS_OPT_SYNTAX_MASM
        elif self._ks_x86_syntax == "gas":
            self._ks.syntax = _keystone.KS_OPT_SYNTAX_GAS
        elif self._ks_x86_syntax == "radix16":
            self._ks.syntax = _keystone.KS_OPT_SYNTAX_RADIX16
        else:
            self._ks.syntax = _keystone.KS_OPT_SYNTAX_INTEL


register_arch([r"86_16"], 16, "Iend_LE", Arch86_16)
