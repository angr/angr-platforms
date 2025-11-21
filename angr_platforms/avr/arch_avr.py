from __future__ import annotations

from archinfo.arch import register_arch, Arch, Endness, Register
from archinfo.tls import TLSArchInfo

class ArchAVR(Arch):

    def __init__(self, endness=Endness.LE):
        super().__init__(endness)

        self.register_index: dict[int, str] = {}
        for reg_name, (reg_offset, _) in self.registers.items():
            self.register_index[reg_offset] = reg_name


    name = "AVR"
    bits = 32
    max_inst_bytes = 4
    ip_offset = 0x80000000
    sp_offset = 0x5d
    call_pushes_ret = True
    instruction_endness = Endness.LE
    sizeof = {"long" : 24}
    # FIXME: something in angr assumes that sizeof(long) == sizeof(return address on stack)
    initial_sp = 0x7fff
    # call_sp_fix = 3
    call_sp_fix = 2
    instruction_alignment = 2
    nop_instruction = b'\x00\x00'
    # flash_offset = 1 << 31
    flash_offset = 0
    ioreg_offset = 0x20

    elf_tls = TLSArchInfo(1, 8, [], [0], [], 0, 0) # TODO ?
    register_list = [
        Register(name="R1_R0", size=2, subregisters=[("R1", 1, 1), ("R0", 0, 1)], vex_offset=0),
        Register(name="R3_R2", size=2, subregisters=[("R3", 1, 1), ("R2", 0, 1)], vex_offset=2),
        Register(name="R5_R4", size=2, subregisters=[("R5", 1, 1), ("R4", 0, 1)], vex_offset=4),
        Register(name="R7_R6", size=2, subregisters=[("R7", 1, 1), ("R6", 0, 1)], vex_offset=6),
        Register(name="R9_R8", size=2, subregisters=[("R9", 1, 1), ("R8", 0, 1)], vex_offset=8),
        Register(name="R11_R10", size=2, subregisters=[("R11", 1, 1), ("R10", 0, 1)], vex_offset=10),
        Register(name="R13_R12", size=2, subregisters=[("R13", 1, 1), ("R12", 0, 1)], vex_offset=12),
        Register(name="R15_R14", size=2, subregisters=[("R15", 1, 1), ("R14", 0, 1)], vex_offset=14),
        Register(name="R17_R16", size=2, subregisters=[("R17", 1, 1), ("R16", 0, 1)], vex_offset=16),
        Register(name="R19_R18", size=2, subregisters=[("R19", 1, 1), ("R18", 0, 1)], vex_offset=18),
        Register(name="R21_R20", size=2, subregisters=[("R21", 1, 1), ("R20", 0, 1)], vex_offset=20),
        Register(name="R23_R22", size=2, subregisters=[("R23", 1, 1), ("R22", 0, 1)], vex_offset=22),
        Register(name="R25_R24", size=2, subregisters=[("R25", 1, 1), ("R24", 0, 1)], vex_offset=24),
        Register(name="R27_R26", size=2, alias_names=("X",), subregisters=[("R27", 1, 1), ("R26", 0, 1), ("XL", 1, 1), ("XH", 0, 1)], vex_offset=26),
        Register(name="R29_R28", size=2, alias_names=("Y",), subregisters=[("R29", 1, 1), ("R28", 0, 1), ("YL", 1, 1), ("YH", 0, 1)], vex_offset=28),
        Register(name="R31_R30", size=2, alias_names=("Z",), subregisters=[("R31", 1, 1), ("R30", 0, 1), ("ZL", 1, 1), ("ZH", 0, 1)], vex_offset=30),

        Register(name="EEDR", size=1, vex_offset=0x40),
        Register(name="EEARL", size=1, vex_offset=0x41),
        Register(name="EEARH", size=1, vex_offset=0x42),
        Register(name="GTCCR", size=1, vex_offset=0x43),
        Register(name="TCCR0A", size=1, vex_offset=0x44),
        Register(name="TCCR0B", size=1, vex_offset=0x45),
        Register(name="TCNT0", size=1, vex_offset=0x46),
        Register(name="OCR0A", size=1, vex_offset=0x47),
        Register(name="OCR0B", size=1, vex_offset=0x48),
        Register(name="IO_0x29", size=1, vex_offset=0x49),
        Register(name="GPIOR1", size=1, vex_offset=0x4a),
        Register(name="GPIOR2", size=1, vex_offset=0x4b),
        Register(name="SPCR", size=1, vex_offset=0x4c),
        Register(name="SPSR", size=1, vex_offset=0x4d),
        Register(name="SPDR", size=1, vex_offset=0x4e),
        Register(name="IO_0x2f", size=1, vex_offset=0x4f),
        Register(name="ACSR", size=1, vex_offset=0x50),
        Register(name="IO_0x31", size=1, vex_offset=0x51),
        Register(name="IO_0x32", size=1, vex_offset=0x52),
        Register(name="SMCR", size=1, vex_offset=0x53),
        Register(name="MCUSR", size=1, vex_offset=0x54),
        Register(name="MCUCR", size=1, vex_offset=0x55),
        Register(name="IO_0x36", size=1, vex_offset=0x56),
        Register(name="SPMCSR", size=1, vex_offset=0x57),
        Register(name="RAMPD", size=1, vex_offset=0x58, default_value=(0x80, False, None)),
        Register(name="RAMPX", size=1, vex_offset=0x59),
        Register(name="RAMPY", size=1, vex_offset=0x5a),
        Register(name="RAMPZ", size=1, vex_offset=0x5b),
        Register(name="EIND", size=1, vex_offset=0x5c),
        Register(name="SP", size=2, alias_names=("sp",), subregisters=[("SPL", 0, 1), ("SPH", 1, 1)], vex_offset=0x5d),
        Register(name="SREG", size=1, vex_offset=0x5f),

        Register(name="WDTCSR", size=1, vex_offset=0x60),
        Register(name="CLKPR", size=1, vex_offset=0x61),
        Register(name="PRR", size=1, vex_offset=0x64),
        Register(name="OSCCAL", size=1, vex_offset=0x66),
        Register(name="PCICR", size=1, vex_offset=0x68),
        Register(name="EICRA", size=1, vex_offset=0x69),
        Register(name="PCMSK0", size=1, vex_offset=0x6b),
        Register(name="PCMSK2", size=1, vex_offset=0x6d),
        Register(name="PCMSK1", size=1, vex_offset=0x6c),
        Register(name="TIMSK0", size=1, vex_offset=0x6e),
        Register(name="TIMSK1", size=1, vex_offset=0x6f),
        Register(name="TIMSK2", size=1, vex_offset=0x70),
        Register(name="ADCL", size=1, vex_offset=0x78),
        Register(name="ADCH", size=1, vex_offset=0x79),
        Register(name="ADCSRA", size=1, vex_offset=0x7a),
        Register(name="ADCSRB", size=1, vex_offset=0x7b),
        Register(name="ADMUX", size=1, vex_offset=0x7c),
        Register(name="DIDR0", size=1, vex_offset=0x7e),
        Register(name="DIDR1", size=1, vex_offset=0x7f),
        Register(name="TCCR1A", size=1, vex_offset=0x80),
        Register(name="TCCR1B", size=1, vex_offset=0x81),
        Register(name="TCCR1C", size=1, vex_offset=0x82),
        Register(name="TCNT1H", size=1, vex_offset=0x85),
        Register(name="TCNT1L", size=1, vex_offset=0x84),
        Register(name="ICR1H", size=1, vex_offset=0x87),
        Register(name="ICR1L", size=1, vex_offset=0x86),
        Register(name="OCR1AH", size=1, vex_offset=0x89),
        Register(name="OCR1AL", size=1, vex_offset=0x88),
        Register(name="OCR1BH", size=1, vex_offset=0x8b),
        Register(name="OCR1BL", size=1, vex_offset=0x8a),
        Register(name="TCCR2A", size=1, vex_offset=0xb0),
        Register(name="TCCR2B", size=1, vex_offset=0xb1),
        Register(name="TCNT2", size=1, vex_offset=0xb2),
        Register(name="OCR2A", size=1, vex_offset=0xb3),
        Register(name="OCR2B", size=1, vex_offset=0xb4),
        Register(name="ASSR", size=1, vex_offset=0xb6),
        Register(name="TWBR", size=1, vex_offset=0xb8),
        Register(name="TWSR", size=1, vex_offset=0xb9),
        Register(name="TWAR", size=1, vex_offset=0xba),
        Register(name="TWDR", size=1, vex_offset=0xbb),
        Register(name="TWCR", size=1, vex_offset=0xbc),
        Register(name="TWAMR", size=1, vex_offset=0xbd),
        Register(name="UCSR0A", size=1, vex_offset=0xc0),
        Register(name="UCSR0B", size=1, vex_offset=0xc1),
        Register(name="UCSR0C", size=1, vex_offset=0xc2),
        Register(name="UBRR0H", size=1, vex_offset=0xc5),
        Register(name="UBRR0L", size=1, vex_offset=0xc4),
        Register(name="UDR0", size=1, vex_offset=0xc6),

        Register(name="ip", size=4, alias_names=('pc'), vex_offset=0x80000000),
    ]


register_arch([r'em_avr'], 32, 'Iend_LE', ArchAVR)
