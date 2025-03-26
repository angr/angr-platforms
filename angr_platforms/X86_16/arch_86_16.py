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

from archinfo.arch import Arch, Endness, Register, register_arch


class Arch86_16(Arch):

    def __init__(self, endness=Endness.LE):
        offset = 0
        for reg in self.register_list:
            reg.vex_offset = offset
            offset += reg.size

        super().__init__(endness)
        self.reg_blacklist = []
        self.reg_blacklist_offsets = []
        self.vex_archinfo = None
        self.vex_cc_regs = None
        self.vex_to_unicorn_map = None
        #self.registers = self.register_list

    name = "86_16"
    bits = 16
    stack_change = -2
    vex_arch = None
    vex_support = False
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
    function_prologs = {rb"\x55\x8b\xec",  # push ebp; mov ebp, esp
        rb"\x55\x89\xe5"}  # push ebp; mov ebp, esp
    function_epilogs = {
        rb"\xc9\xc3",  # leave; ret
        rb"([^\x41][\x50-\x5f]{1}|\x41[\x50-\x5f])\xc3"}  # pop <reg>; ret
    ret_offset = RegisterOffset(0)  # ax - syscall return register?
    ret_instruction = b"\xc3"
    nop_instruction = b"\x90"


    register_list = [
        Register(
            name="eax",
            size=4,
            subregisters=[("ax", 0, 2), ("al", 0, 1), ("ah", 1, 1)],
            general_purpose=True,
            argument=True,
            linux_entry_value=0x1C,
        ),
        Register(
            name="ecx",
            size=4,
            subregisters=[("cx", 0, 2), ("cl", 0, 1), ("ch", 1, 1)],
            general_purpose=True,
        ),
        Register(
            name="edx",
            size=4,
            subregisters=[("dx", 0, 2), ("dl", 0, 1), ("dh", 1, 1)],
            general_purpose=True,
        ),
        Register(
            name="ebx",
            size=4,
            subregisters=[("bx", 0, 2), ("bl", 0, 1), ("bh", 1, 1)],
            general_purpose=True,
        ),
        Register(
            name="esp",
            size=4,
            subregisters=[("sp", 0, 2)],
            alias_names=("stack_base",),
            #alias_names=("sp",),
            general_purpose=True,
            default_value=(Arch.initial_sp, True, "global"),
        ),
        Register(name="ebp", size=4, subregisters=[("bp", 0, 2)], general_purpose=True, argument=True,
                 ),
        Register(
            name="esi",
            size=4,
            subregisters=[("si", 0, 2), ("sil", 0, 1), ("sih", 1, 1)],
            general_purpose=True,
        ),
        Register(
            name="edi",
            size=4,
            subregisters=[("di", 0, 2), ("dil", 0, 1), ("dih", 1, 1)],
            general_purpose=True,
        ),
        # Register(name="cc_op", size=4, default_value=(0, False, None), concrete=False, artificial=True),
        # Register(name="cc_dep1", size=4, concrete=False, artificial=True),
        # Register(name="cc_dep2", size=4, concrete=False, artificial=True),
        # Register(name="cc_ndep", size=4, concrete=False, artificial=True),
        Register(name="d", size=4, alias_names=("dflag",), default_value=(1, False, None), concrete=False,
                 ),
        Register(name="id", size=4, alias_names=("idflag",), default_value=(1, False, None), concrete=False,
                 ),
        Register(name="ac", size=4, alias_names=("acflag",), default_value=(0, False, None), concrete=False,
                 ),
        Register(name="eip", size=4, alias_names=("pc"), subregisters=[("ip", 0, 2)],
                 ),
        Register(
            name="fpreg",
            size=64,
            subregisters=[
                ("mm0", 0, 8),
                ("mm1", 8, 8),
                ("mm2", 16, 8),
                ("mm3", 24, 8),
                ("mm4", 32, 8),
                ("mm5", 40, 8),
                ("mm6", 48, 8),
                ("mm7", 56, 8),
            ],
            alias_names=("fpu_regs",),
            floating_point=True,
            concrete=False,
        ),
        Register(name="fptag", size=8, alias_names=("fpu_tags",), floating_point=True, default_value=(0, False, None),
                 ),
        Register(name="fpround", size=4, floating_point=True, default_value=(0, False, None),
                 ),
        Register(name="fc3210", size=4, floating_point=True),
        # Register(name="ftop", size=4, floating_point=True, default_value=(7, False, None), artificial=True),
        #Register(name="sseround", size=4, vector=True, default_value=(0, False, None),
        #         vex_offset=72,
        #         ),
        Register(name="cs", size=2),
        Register(name="ds", size=2),
        Register(name="es", size=2),
        Register(name="fs", size=2, default_value=(0, False, None), concrete=False),
        Register(name="gs", size=2, default_value=(0, False, None), concrete=False),
        Register(name="ss", size=2),
        # Register(name="ldt", size=8, default_value=(0, False, None), concrete=False),
        # Register(name="gdt", size=8, default_value=(0, False, None), concrete=False),
        # Register(name="emnote", size=4, artificial=True),
        Register(name="cmstart", size=4),
        Register(name="cmlen", size=4),
        Register(name="nraddr", size=4, artificial=True),
        Register(name="sc_class", size=4, artificial=True),
        Register(name="ip_at_syscall", size=4, concrete=False, artificial=True),
        Register(
            name="eflags",
            size=4,
            subregisters=[("flags", 0, 2)],
        ),
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
