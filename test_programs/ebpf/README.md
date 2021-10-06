Binary programs for eBPF compiled on Ubuntu

Compiling C programs to eBPF bytecode:

```
clang -O0 -g -Wall -target bpf prog.c -c -o prog.o
```

If you use some eBPF specific libs:

```
clang -O2 -Wall -target bpf -c -o xdp.o \
  -I <path to kernel source>/tools/testing/selftests/bpf \
  -I <path to kernel source>/tools/include/uapi \
  xdp.c
```

To see bytecode:

```
$ llvm-objdump -d prog.o
indirect.o:     file format ELF64-BPF

Disassembly of section .text:
g:
       0:       bf 12 00 00 00 00 00 00         r2 = r1
       1:       63 1a fc ff 00 00 00 00         *(u32 *)(r10 - 4) = r1
       2:       61 a1 fc ff 00 00 00 00         r1 = *(u32 *)(r10 - 4)
       3:       07 01 00 00 01 00 00 00         r1 += 1
       4:       bf 10 00 00 00 00 00 00         r0 = r1
       5:       7b 2a f0 ff 00 00 00 00         *(u64 *)(r10 - 16) = r2
       6:       95 00 00 00 00 00 00 00         exit

main:
       7:       b7 01 00 00 00 00 00 00         r1 = 0
       8:       63 1a fc ff 00 00 00 00         *(u32 *)(r10 - 4) = r1
       9:       b7 01 00 00 01 00 00 00         r1 = 1
      10:       85 10 00 00 f5 ff ff ff         call -11
      11:       07 00 00 00 01 00 00 00         r0 += 1
      12:       95 00 00 00 00 00 00 00         exit
```
