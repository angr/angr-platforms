# Test Programs for angr-platforms

This directory contains test binaries for various platforms supported by angr-platforms.

## x86_16

- **simple.com**: A simple 16-bit x86 COM file for testing decompilation. Contains basic instructions: MOV AX,1; ADD AX,2; RET.

Binary format: COM (raw executable, no header, loads at 0x100). Use with `backend='blob'` in angr.Project for loading.

Example usage:
```python
import angr
p = angr.Project('angr_platforms/test_programs/x86_16/simple.com', backend='blob', arch='X86_16')
cfg = p.analyses.CFG()
decomp = p.analyses.Decompiler(target_addr=0x100)
print(decomp.code)
```

See [AGENTS.md](AGENTS.md) for more details on x86-16 support.