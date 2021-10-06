/* 
$ clang -O3 -Wall -target bpf return_42.c -c -o return_42.o    # to compile for eBPF
$ clang -O3 -Wall return_42.c -c -o return_42_x86_64.o         # to compile for x86-64

$ llvm-objdump -d return_42.o                                  # to view instructions

return_42.o:    file format ELF64-BPF

Disassembly of section .text:
main:
       0:       b7 00 00 00 2a 00 00 00         r0 = 42
       1:       95 00 00 00 00 00 00 00         exit

$ llvm-objdump -d return_42_x86_64.o

return_42_x86_64.o:     file format ELF64-x86-64

Disassembly of section .text:
main:
       0:       b8 2a 00 00 00  movl    $42, %eax
       5:       c3      retq
*/
int main()
{
  return 42;
}