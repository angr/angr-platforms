Binary programs for eBPF compiled on Ubuntu

Compiling C programs to eBPF bytecode:
When calling external BPF functions, you'll need libbpf and corresponding cflags

```
clang -target bpf prog.c -c -o prog.o
```

To see bytecode:

```
llvm-objdump -d prog.o
```
