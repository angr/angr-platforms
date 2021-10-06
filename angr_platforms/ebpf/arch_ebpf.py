import archinfo
from archinfo import Register


class ArchEbpf(archinfo.Arch):
    name = "eBPF"
    qemu_name = 'eBPF'

    sizeof = {'short': 16, 'int': 32, 'long': 32, 'long long': 64}

    bits = 32  # number of bits in a word

    ret_offset = 0
    bp_offset = 80
    sp_offset = 80
    ip_offset = 88

    vex_arch = None
    # at the time of this writing, there wasn't a VexArch corresponding to eBPF ISA
    # https://github.com/angr/vex/blob/3440a5601cc9752af5cd2de433bebbbfc01e7c4b/pub/libvex.h#L52-L66

    ida_processor = 'eBPF'  # "IDA Pro" is a disassembler and debugger

    max_inst_bytes = 16

    instruction_alignment = 1

    # TODO (future work): add support for [Capstone](https://github.com/capstone-engine/capstone)
    # cs_arch = 'BPF'
    # cs_mode = 'CS_MODE_BPF_EXTENDED'

    register_list = [
        # return value from in-kernel function, and exit value for eBPF
        Register(name='R0', size=8, vex_offset=0),

        # arguments from eBPF program to in-kernel function
        Register(name='R1', size=8, vex_offset=8, argument=True),
        Register(name='R2', size=8, vex_offset=16, argument=True),
        Register(name='R3', size=8, vex_offset=24, argument=True),
        Register(name='R4', size=8, vex_offset=32, argument=True),
        Register(name='R5', size=8, vex_offset=40, argument=True),

        # callee-saved registers that in-kernel function will preserve
        Register(name='R6', size=8, vex_offset=48, general_purpose=True),
        Register(name='R7', size=8, vex_offset=56, general_purpose=True),
        Register(name='R8', size=8, vex_offset=64, general_purpose=True),
        Register(name='R9', size=8, vex_offset=72, general_purpose=True),

        # read-only frame pointer to access stack
        Register(name='R10', size=8, vex_offset=80, alias_names=('bp', 'sp')),

        Register(name='ip', size=8, vex_offset=88)  # "insn pointer" register, which actually doesn't exist in eBPF ISA
    ]


archinfo.register_arch(
    ['Linux BPF - in-kernel virtual machine', 'eBPF', 'ebpf', 'bpf', 'BPF'],
    64, archinfo.Endness.LE, ArchEbpf)
