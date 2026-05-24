#!/usr/bin/env python3
import angr
from angr_platforms.angr_platforms.X86_16.arch_86_16 import Arch86_16

arch_16 = Arch86_16()
byte_string = b'\x55\xb8\x1b\x00\x3d\x1b\x00\x74\x03\x05\x01\x00\x5d\xc3'
p = angr.load_shellcode(byte_string, arch=arch_16, start_offset=0x0, load_address=0x0, selfmodifying_code=False, rebase_granularity=0x1000)

# Generate the control flow graph
cfg = p.analyses.CFG(force_complete_scan=False, data_references=True, normalize=True)

# Get the function at address 0x0
entry_func = cfg.kb.functions.function(addr=0x0)

# Decompile the entry function
decomp = entry_func.decompiled

# Print the decompiled code
print(decomp.text if decomp else "Decompilation failed")