This is a SH4 lifter for angr/pyvex.

Written by Adam O. (bob123456678)

Drop these files into an angr workspace, then run either of the test scripts to test the lifter.

Additional work is needed to complete floating-point instructions.

The following instructions have been tested and verified to work on the CADET0001 binary:
'ADD', 'ADDI', 'AND', 'BF', 'BRA', 'BT', 'CMPEQ', 'CMPGT', 'CMPHI', 'CMPHS', 'CMPPZ', 'EXTS', 'FLDS', 'FSTS', 'JMP', 'JSR', 'LDSFPUL', 'LDSLPR', 'MOV', 'MOVBL', 'MOVBL0', 'MOVBL4', 'MOVBS', 'MOVBS0', 'MOVBS4', 'MOVBSG', 'MOVI', 'MOVLI', 'MOVLL', 'MOVLL4', 'MOVLM', 'MOVLP', 'MOVLS', 'MOVLS4', 'MOVT', 'MOVW', 'MOVWS0', 'NEGC', 'NOP', 'RTS', 'SETT', 'SHAR', 'SHLL', 'STSFPUL', 'STSLPR', 'SUB', 'SUBC', 'TST', 'XOR'

A total of 126 instructions are implemented, but those not listed above have only seen limited testing.
