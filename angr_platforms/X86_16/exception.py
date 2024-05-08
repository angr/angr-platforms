# Exception types
EXP_DE = 0  # Divide Error
EXP_DB = 1  # Debug
EXP_BP = 3  # Breakpoint
EXP_OF = 4  # Overflow
EXP_BR = 5  # BOUND Range Exceeded
EXP_UD = 6  # Invalid Opcode
EXP_NM = 7  # Device Not Available
EXP_DF = 8  # Double Fault
EXP_TS = 10 # Invalid TSS
EXP_NP = 11 # Segment Not Present
EXP_SS = 12 # Stack-Segment Fault
EXP_GP = 13 # General Protection
EXP_PF = 14 # Page Fault
EXP_MF = 16 # x87 FPU Floating-Point Error
EXP_AC = 17 # Alignment Check
EXP_MC = 18 # Machine Check
EXP_XF = 19 # SIMD Floating-Point Exception
EXP_VE = 20 # Virtualization Exception
EXP_SX = 30 # Security Exception

# Helper functions for raising exceptions

def EXCEPTION(n, c):
    if c:
        print(f"WARN: Exception interrupt {n} ({c})")
        raise Exception(n)


def EXCEPTION_WITH(n, c, e):
    if c:
        print(f"WARN: Exception interrupt {n} ({c})")
        e()
        raise Exception(n)
