from angr_platforms.X86_16.regs import reg16_t, reg32_t, sgreg_t
from angr_platforms.X86_16.stack_helpers import (
    branch_rel8,
    branch_rel16,
    branch_rel32,
    emit_near_call16,
    emit_near_call32,
    emit_near_jump16,
    emit_near_jump32,
    enter16,
    leave16,
    near_relative_target16,
    near_relative_target32,
    near_return_ip16,
    pop16,
    pop16_register,
    pop32_register,
    pop_all16,
    pop_all32,
    pop_far_return_frame16,
    pop_far_return_frame32,
    pop_flags16,
    pop_flags32,
    pop_interrupt_frame16,
    pop_interrupt_frame32,
    pop_segment16,
    pop_segment32,
    push16,
    push16_register,
    push32_register,
    push_all16,
    push_all32,
    push_far_return_frame16,
    push_far_return_frame32,
    push_flags16,
    push_flags32,
    push_immediate16,
    push_immediate32,
    push_privilege_stack32,
    push_segment16,
    push_segment32,
    return_far16,
    return_far32,
    return_interrupt16,
    return_interrupt32,
    return_near16,
    return_near32,
)


class _StackEmu:
    def __init__(self):
        self.gpregs = {
            reg16_t.AX: 0x1111,
            reg16_t.CX: 0x2222,
            reg16_t.DX: 0x3333,
            reg16_t.BX: 0x4444,
            reg16_t.SP: 0x1000,
            reg16_t.BP: 0x2222,
            reg16_t.SI: 0x5555,
            reg16_t.DI: 0x6666,
            reg16_t.IP: 0x0100,
            reg32_t.EAX: 0x11111111,
            reg32_t.ECX: 0x22222222,
            reg32_t.EDX: 0x33333333,
            reg32_t.EBX: 0x44444444,
            reg32_t.ESP: 0x2000,
            reg32_t.EBP: 0x55555555,
            reg32_t.ESI: 0x66666666,
            reg32_t.EDI: 0x77777777,
        }
        self.sgregs = {sgreg_t.CS: 0x1234, sgreg_t.SS: 0x2000}
        self.memory = {}
        self.irsb = type("_IRSB", (), {"next": None, "jumpkind": None})()
        self.lifter_instruction = type("_Lifter", (), {"jump": self._jump})()
        self.flags = 0xF002

    def update_gpreg(self, reg, delta):
        self.gpregs[reg] = self.gpregs[reg] + delta

    def get_gpreg(self, reg):
        return self.gpregs[reg]

    def set_gpreg(self, reg, value):
        self.gpregs[reg] = value
        if reg == reg16_t.FLAGS:
            self.flags = value

    def set_eip(self, value):
        self.gpregs[reg32_t.EIP] = value

    def get_eip(self):
        return self.gpregs.get(reg32_t.EIP, 0)

    def get_sgreg(self, reg):
        if isinstance(reg, str):
            reg = sgreg_t[reg]
        return self.sgregs[reg]

    def v2p(self, seg, off):
        return (seg << 4) + off

    def set_sgreg(self, reg, value):
        if isinstance(reg, str):
            reg = sgreg_t[reg]
        self.sgregs[reg] = value

    def get_segment(self, reg):
        return self.get_sgreg(reg)

    def set_segment(self, reg, value):
        self.set_sgreg(reg, value)

    def get_flags(self):
        return self.flags

    def set_flags(self, value):
        self.flags = value

    def get_eflags(self):
        return self.flags

    def set_eflags(self, value):
        self.flags = value

    def write_mem16_seg(self, seg, addr, value):
        self.memory[(seg, addr)] = value

    def read_mem16_seg(self, seg, addr):
        return self.memory[(seg, addr)]

    def write_mem32_seg(self, seg, addr, value):
        self.memory[(seg, addr)] = value

    def read_mem32_seg(self, seg, addr):
        return self.memory[(seg, addr)]

    def constant(self, value, _ty):
        return value

    def _jump(self, _cond, target, jumpkind):
        self.irsb.next = target
        self.irsb.jumpkind = jumpkind


def test_stack_helpers_push_and_pop_16_bit_values():
    emu = _StackEmu()

    push16(emu, 0xABCD)
    assert emu.get_gpreg(reg16_t.SP) == 0x0FFE
    assert emu.memory[(sgreg_t.SS, 0x0FFE)] == 0xABCD
    assert pop16(emu) == 0xABCD
    assert emu.get_gpreg(reg16_t.SP) == 0x1000


def test_stack_helpers_register_immediate_and_flags_primitives_cover_both_widths():
    emu = _StackEmu()

    push16_register(emu, reg16_t.AX)
    push32_register(emu, reg32_t.EAX)
    push_immediate16(emu, 0xBEEF)
    push_immediate32(emu, 0xCAFEBABE)
    push_flags16(emu)
    push_flags32(emu)

    assert emu.memory[(sgreg_t.SS, 0x1FFC)] == 0x11111111
    assert emu.memory[(sgreg_t.SS, 0x0FFE)] == 0x1111
    assert emu.memory[(sgreg_t.SS, 0x0FFC)] == 0xBEEF
    assert emu.memory[(sgreg_t.SS, 0x1FF8)] == 0xCAFEBABE
    assert emu.memory[(sgreg_t.SS, 0x0FFA)] == 0xF002
    assert emu.memory[(sgreg_t.SS, 0x1FF4)] == 0xF002

    assert pop_flags32(emu) == 0xF002
    assert pop_flags16(emu) == 0x0002

    pop32_register(emu, reg32_t.EAX)
    pop16_register(emu, reg16_t.AX)
    assert emu.get_gpreg(reg32_t.EAX) == 0xCAFEBABE
    assert emu.get_gpreg(reg16_t.AX) == 0xBEEF


def test_stack_helpers_push16_register_preserves_original_sp_value():
    emu = _StackEmu()

    push16_register(emu, reg16_t.SP)

    assert emu.get_gpreg(reg16_t.SP) == 0x0FFE
    assert emu.memory[(sgreg_t.SS, 0x0FFE)] == 0x1000


def test_stack_helpers_segment16_helpers_round_trip_segment_registers():
    emu = _StackEmu()
    emu.sgregs[sgreg_t.DS] = 0xBEEF

    push_segment16(emu, sgreg_t.DS)
    emu.sgregs[sgreg_t.DS] = 0
    pop_segment16(emu, sgreg_t.DS)

    assert emu.get_sgreg(sgreg_t.DS) == 0xBEEF
    assert emu.get_gpreg(reg16_t.SP) == 0x1000


def test_stack_helpers_flags16_helpers_mask_reserved_bits():
    emu = _StackEmu()
    emu.flags = 0xAAAA

    push_flags16(emu)
    emu.flags = 0
    masked = pop_flags16(emu)

    assert masked == ((0xAAAA & 0x0FD5) | 0x0002)
    assert emu.get_flags() == masked


def test_stack_helpers_form_far_call_frames_in_cs_ip_order():
    emu = _StackEmu()

    push_far_return_frame16(emu, 0x0105)

    assert emu.get_gpreg(reg16_t.SP) == 0x0FFC
    assert emu.memory[(sgreg_t.SS, 0x0FFE)] == 0x1234
    assert emu.memory[(sgreg_t.SS, 0x0FFC)] == 0x0105
    assert pop_far_return_frame16(emu) == (0x0105, 0x1234)


def test_stack_helpers_pop_interrupt_frames_in_ip_cs_flags_order():
    emu = _StackEmu()
    emu.gpregs[reg16_t.SP] = 0x0FF8
    emu.memory[(sgreg_t.SS, 0x0FF8)] = 0xAAAA
    emu.memory[(sgreg_t.SS, 0x0FFA)] = 0xBBBB
    emu.memory[(sgreg_t.SS, 0x0FFC)] = 0xCCCC

    assert pop_interrupt_frame16(emu) == (0xAAAA, 0xBBBB, 0xCCCC)


def test_stack_helpers_return_helpers_restore_far_and_interrupt_state():
    emu = _StackEmu()
    emu.gpregs[reg16_t.SP] = 0x0FF8
    emu.memory[(sgreg_t.SS, 0x0FF8)] = 0xAAAA
    emu.memory[(sgreg_t.SS, 0x0FFA)] = 0xBBBB
    emu.memory[(sgreg_t.SS, 0x0FFC)] = 0xCCCC

    assert return_far16(emu, 4) == (0xAAAA, 0xBBBB)
    assert emu.get_gpreg(reg16_t.SP) == 0x1000
    assert emu.get_gpreg(reg16_t.IP) == 0xAAAA
    assert emu.get_sgreg(sgreg_t.CS) == 0xBBBB
    assert emu.irsb.jumpkind == "Ijk_Ret"

    emu.gpregs[reg16_t.SP] = 0x0FF8
    emu.irsb.next = None
    emu.irsb.jumpkind = None

    assert return_interrupt16(emu) == (0xAAAA, 0xBBBB, 0xCCCC)
    assert emu.get_gpreg(reg16_t.IP) == 0xAAAA
    assert emu.get_sgreg(sgreg_t.CS) == 0xBBBB
    assert emu.get_flags() == 0xCCCC
    assert emu.irsb.jumpkind == "Ijk_Ret"


def test_stack_helpers_32bit_far_and_interrupt_helpers_use_dword_frames():
    emu = _StackEmu()
    emu.gpregs[reg32_t.ESP] = 0x1FF0
    emu.memory[(sgreg_t.SS, 0x1FF0)] = 0x11112222
    emu.memory[(sgreg_t.SS, 0x1FF4)] = 0x33334444
    emu.memory[(sgreg_t.SS, 0x1FF8)] = 0x55556666

    assert push_far_return_frame32(emu, 0x77778888) == 0x77778888
    assert emu.memory[(sgreg_t.SS, 0x1FE8)] == 0x77778888
    assert emu.memory[(sgreg_t.SS, 0x1FEC)] == 0x1234

    emu.gpregs[reg32_t.ESP] = 0x1FF0
    emu.irsb.next = None
    emu.irsb.jumpkind = None
    assert pop_far_return_frame32(emu) == (0x11112222, 0x33334444)

    emu.gpregs[reg32_t.ESP] = 0x1FF0
    emu.irsb.next = None
    emu.irsb.jumpkind = None
    assert return_far32(emu, 4) == (0x11112222, 0x33334444)
    assert emu.get_gpreg(reg32_t.ESP) == 0x1FFC
    assert emu.get_gpreg(reg32_t.EIP) == 0x11112222
    assert emu.get_sgreg(sgreg_t.CS) == 0x33334444

    emu.gpregs[reg32_t.ESP] = 0x1FF0
    emu.irsb.next = None
    emu.irsb.jumpkind = None
    assert pop_interrupt_frame32(emu) == (0x11112222, 0x33334444, 0x55556666)

    emu.gpregs[reg32_t.ESP] = 0x1FF0
    emu.irsb.next = None
    emu.irsb.jumpkind = None
    assert return_interrupt32(emu) == (0x11112222, 0x33334444, 0x55556666)
    assert emu.get_gpreg(reg32_t.EIP) == 0x11112222
    assert emu.get_sgreg(sgreg_t.CS) == 0x33334444
    assert emu.get_eflags() == 0x55556666


def test_stack_helpers_privilege_stack_save_uses_ss_and_esp_order():
    emu = _StackEmu()
    emu.gpregs[reg32_t.ESP] = 0x1FF0

    saved_ss, saved_esp = push_privilege_stack32(emu)

    assert saved_ss == 0x2000
    assert saved_esp == 0x1FF0
    assert emu.memory[(sgreg_t.SS, 0x1FEC)] == 0x2000
    assert emu.memory[(sgreg_t.SS, 0x1FE8)] == 0x1FF0


def test_stack_helpers_enter_and_leave_manage_the_frame_pointer():
    emu = _StackEmu()
    emu.gpregs[reg16_t.SP] = 0x1000
    emu.gpregs[reg16_t.BP] = 0x1111

    enter16(emu, 4, 0)

    assert emu.get_gpreg(reg16_t.BP) == 0x0FFE
    assert emu.get_gpreg(reg16_t.SP) == 0x0FFA
    assert emu.memory[(sgreg_t.SS, 0x0FFE)] == 0x1111

    leave16(emu)

    assert emu.get_gpreg(reg16_t.BP) == 0x1111
    assert emu.get_gpreg(reg16_t.SP) == 0x1000


def test_stack_helpers_compute_near_return_ip_from_instruction_size():
    emu = _StackEmu()

    assert near_return_ip16(emu, 3) == 0x0103


def test_stack_helpers_compute_relative_targets_from_current_ip_and_eip():
    emu = _StackEmu()
    emu.gpregs[reg32_t.EIP] = 0x1000

    assert near_relative_target16(emu, 4, 3) == 0x0107
    assert near_relative_target32(emu, 8, 5) == 0x100D


def test_stack_helpers_push_all16_preserves_original_sp_slot():
    emu = _StackEmu()

    push_all16(emu)

    assert emu.get_gpreg(reg16_t.SP) == 0x0FF0
    assert emu.memory[(sgreg_t.SS, 0x0FFE)] == 0x1111
    assert emu.memory[(sgreg_t.SS, 0x0FFC)] == 0x2222
    assert emu.memory[(sgreg_t.SS, 0x0FFA)] == 0x3333
    assert emu.memory[(sgreg_t.SS, 0x0FF8)] == 0x4444
    assert emu.memory[(sgreg_t.SS, 0x0FF6)] == 0x1000
    assert emu.memory[(sgreg_t.SS, 0x0FF4)] == 0x2222
    assert emu.memory[(sgreg_t.SS, 0x0FF2)] == 0x5555
    assert emu.memory[(sgreg_t.SS, 0x0FF0)] == 0x6666


def test_stack_helpers_pop_all16_restores_registers_and_skips_saved_sp():
    emu = _StackEmu()
    emu.gpregs[reg16_t.SP] = 0x0FF0
    emu.memory[(sgreg_t.SS, 0x0FF0)] = 0x6666
    emu.memory[(sgreg_t.SS, 0x0FF2)] = 0x5555
    emu.memory[(sgreg_t.SS, 0x0FF4)] = 0x2222
    emu.memory[(sgreg_t.SS, 0x0FF6)] = 0x1000
    emu.memory[(sgreg_t.SS, 0x0FF8)] = 0x4444
    emu.memory[(sgreg_t.SS, 0x0FFA)] = 0x3333
    emu.memory[(sgreg_t.SS, 0x0FFC)] = 0x2222
    emu.memory[(sgreg_t.SS, 0x0FFE)] = 0x1111

    pop_all16(emu)

    assert emu.get_gpreg(reg16_t.DI) == 0x6666
    assert emu.get_gpreg(reg16_t.SI) == 0x5555
    assert emu.get_gpreg(reg16_t.BP) == 0x2222
    assert emu.get_gpreg(reg16_t.BX) == 0x4444
    assert emu.get_gpreg(reg16_t.DX) == 0x3333
    assert emu.get_gpreg(reg16_t.CX) == 0x2222
    assert emu.get_gpreg(reg16_t.AX) == 0x1111
    assert emu.get_gpreg(reg16_t.SP) == 0x1000


def test_stack_helpers_return_near16_sets_ip_and_ret_jumpkind():
    emu = _StackEmu()
    emu.gpregs[reg16_t.SP] = 0x0FFE
    emu.memory[(sgreg_t.SS, 0x0FFE)] = 0x3456

    assert return_near16(emu) == 0x3456
    assert emu.get_gpreg(reg16_t.IP) == 0x3456
    assert emu.get_gpreg(reg16_t.SP) == 0x1000
    assert emu.irsb.next == 0x3456
    assert emu.irsb.jumpkind == "Ijk_Ret"


def test_stack_helpers_return_near16_applies_extra_stack_adjust():
    emu = _StackEmu()
    emu.gpregs[reg16_t.SP] = 0x0FFE
    emu.memory[(sgreg_t.SS, 0x0FFE)] = 0x3456

    return_near16(emu, stack_adjust=4)

    assert emu.get_gpreg(reg16_t.IP) == 0x3456
    assert emu.get_gpreg(reg16_t.SP) == 0x1004


def test_stack_helpers_emit_near_call_and_jump_set_control_transfer_edges():
    emu = _StackEmu()
    emu.gpregs[reg32_t.EIP] = 0x1000

    emit_near_call16(emu, 0x2222, instruction_size=3)
    assert emu.get_gpreg(reg16_t.IP) == 0x2222
    assert emu.memory[(sgreg_t.SS, 0x0FFE)] == 0x0103
    assert emu.irsb.jumpkind == "Ijk_Call"

    emu.gpregs[reg16_t.SP] = 0x1000
    emit_near_jump16(emu, 0x3333)
    assert emu.get_gpreg(reg16_t.IP) == 0x3333
    assert emu.irsb.jumpkind == "Ijk_Boring"

    emit_near_call32(emu, 0x2000)
    assert emu.get_gpreg(reg32_t.EIP) == 0x2000
    assert emu.memory[(sgreg_t.SS, 0x1FFC)] == 0x1000
    assert emu.irsb.jumpkind == "Ijk_Call"

    emit_near_jump32(emu, 0x3000)
    assert emu.get_gpreg(reg32_t.EIP) == 0x3000
    assert emu.irsb.jumpkind == "Ijk_Boring"


def test_stack_helpers_branch_rel32_uses_shared_jump_emission_for_taken_branches():
    emu = _StackEmu()
    emu.gpregs[reg32_t.EIP] = 0x1000

    assert branch_rel32(emu, True, 0x20) == 0x1020
    assert emu.get_gpreg(reg32_t.EIP) == 0x1020
    assert emu.irsb.jumpkind == "Ijk_Boring"

    emu.gpregs[reg32_t.EIP] = 0x2000
    assert branch_rel32(emu, False, 0x20) is None
    assert emu.get_gpreg(reg32_t.EIP) == 0x2000


def test_stack_helpers_branch_rel8_and_rel16_share_relative_target_emission():
    emu = _StackEmu()

    emu.gpregs[reg16_t.IP] = 0x0100
    assert branch_rel8(emu, True, 0x10) == 0x0112
    assert emu.get_gpreg(reg16_t.IP) == 0x0112

    emu.gpregs[reg16_t.IP] = 0x0200
    assert branch_rel16(emu, True, 0x20, instruction_size=4) == 0x0224
    assert emu.get_gpreg(reg16_t.IP) == 0x0224

    emu.gpregs[reg16_t.IP] = 0x0300
    assert branch_rel8(emu, False, 0x10) is None
    assert branch_rel16(emu, False, 0x20, instruction_size=4) is None


def test_stack_helpers_push_and_pop_all32_preserve_saved_esp_slot():
    emu = _StackEmu()

    push_all32(emu)

    assert emu.get_gpreg(reg32_t.ESP) == 0x1FE0
    assert emu.memory[(sgreg_t.SS, 0x1FFC)] == 0x11111111
    assert emu.memory[(sgreg_t.SS, 0x1FF8)] == 0x22222222
    assert emu.memory[(sgreg_t.SS, 0x1FF4)] == 0x33333333
    assert emu.memory[(sgreg_t.SS, 0x1FF0)] == 0x44444444
    assert emu.memory[(sgreg_t.SS, 0x1FEC)] == 0x2000
    assert emu.memory[(sgreg_t.SS, 0x1FE8)] == 0x55555555
    assert emu.memory[(sgreg_t.SS, 0x1FE4)] == 0x66666666
    assert emu.memory[(sgreg_t.SS, 0x1FE0)] == 0x77777777

    pop_all32(emu)

    assert emu.get_gpreg(reg32_t.EAX) == 0x11111111
    assert emu.get_gpreg(reg32_t.ECX) == 0x22222222
    assert emu.get_gpreg(reg32_t.EDX) == 0x33333333
    assert emu.get_gpreg(reg32_t.EBX) == 0x44444444
    assert emu.get_gpreg(reg32_t.EBP) == 0x55555555
    assert emu.get_gpreg(reg32_t.ESI) == 0x66666666
    assert emu.get_gpreg(reg32_t.EDI) == 0x77777777
    assert emu.get_gpreg(reg32_t.ESP) == 0x2000


def test_stack_helpers_segment32_helpers_round_trip_segment_registers():
    emu = _StackEmu()
    emu.sgregs[sgreg_t.DS] = 0xBEEF

    push_segment32(emu, sgreg_t.DS)
    emu.sgregs[sgreg_t.DS] = 0
    pop_segment32(emu, sgreg_t.DS)

    assert emu.get_sgreg(sgreg_t.DS) == 0xBEEF
    assert emu.get_gpreg(reg32_t.ESP) == 0x2000


def test_stack_helpers_return_near32_sets_eip_and_ret_jumpkind():
    emu = _StackEmu()
    emu.gpregs[reg32_t.ESP] = 0x1FFC
    emu.memory[(sgreg_t.SS, 0x1FFC)] = 0x12345678

    assert return_near32(emu) == 0x12345678
    assert emu.get_gpreg(reg32_t.ESP) == 0x2000
    assert emu.irsb.next == 0x12345678
    assert emu.irsb.jumpkind == "Ijk_Ret"
