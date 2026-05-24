import inspect

from angr_platforms.X86_16 import access, instr16, instr32
from angr_platforms.X86_16 import emu as emu_mod
from angr_platforms.X86_16.instr_base import GROUP2_BYTE_SHIFT_ROTATE_HANDLERS, InstrBase


def test_x86_16_instruction_core_registration_tables_cover_hot_ranges():
    assert instr16.X86_16_OPCODE_HELPERS == (
        (0x40, 0x47, "inc_r16", 0),
        (0x48, 0x4F, "dec_r16", 0),
        (0x50, 0x57, "push_r16", 0),
        (0x58, 0x5F, "pop_r16", 0),
        (0x91, 0x97, "xchg_r16_ax", 0),
        (0xB8, 0xBF, "mov_r16_imm16", 4),
    )
    assert GROUP2_BYTE_SHIFT_ROTATE_HANDLERS[4] == "shl_rm8"
    assert GROUP2_BYTE_SHIFT_ROTATE_HANDLERS[6] == "shl_rm8"


def test_x86_16_instruction_core_base_exposes_registration_helper():
    assert hasattr(InstrBase, "_register_opcode_range")


def test_x86_16_instruction_core_base_groups_ax_immediates_under_shared_helpers():
    source = (
        inspect.getsource(instr16.Instr16.add_ax_imm16)
        + inspect.getsource(instr16.Instr16.adc_ax_imm16)
        + inspect.getsource(instr16.Instr16.sbb_ax_imm16)
        + inspect.getsource(instr16.Instr16.or_ax_imm16)
        + inspect.getsource(instr16.Instr16.and_ax_imm16)
        + inspect.getsource(instr16.Instr16.sub_ax_imm16)
        + inspect.getsource(instr16.Instr16.xor_ax_imm16)
        + inspect.getsource(instr16.Instr16.cmp_ax_imm16)
    )

    assert "binary_operation(" in source
    assert "binary_operation_with_carry(" in source
    assert "compare_operation(" in source
    assert "_binary_ax_imm16" not in source
    assert "_binary_ax_imm16_with_carry" not in source
    assert "_compare_ax_imm16" not in source


def test_x86_16_instruction_core_base_groups_byte_immediates_under_shared_helpers():
    source = (
        inspect.getsource(instr16.InstrBase.add_al_imm8)
        + inspect.getsource(instr16.InstrBase.adc_al_imm8)
        + inspect.getsource(instr16.InstrBase.sbb_al_imm8)
        + inspect.getsource(instr16.InstrBase.or_al_imm8)
        + inspect.getsource(instr16.InstrBase.and_al_imm8)
        + inspect.getsource(instr16.InstrBase.sub_al_imm8)
        + inspect.getsource(instr16.InstrBase.xor_al_imm8)
        + inspect.getsource(instr16.InstrBase.cmp_al_imm8)
        + inspect.getsource(instr16.InstrBase.add_rm8_imm8)
        + inspect.getsource(instr16.InstrBase.adc_rm8_imm8)
        + inspect.getsource(instr16.InstrBase.sbb_rm8_imm8)
        + inspect.getsource(instr16.InstrBase.or_rm8_imm8)
        + inspect.getsource(instr16.InstrBase.and_rm8_imm8)
        + inspect.getsource(instr16.InstrBase.sub_rm8_imm8)
        + inspect.getsource(instr16.InstrBase.xor_rm8_imm8)
        + inspect.getsource(instr16.InstrBase.cmp_rm8_imm8)
    )

    assert "binary_operation(" in source
    assert "binary_operation_with_carry(" in source
    assert "compare_operation(" in source
    assert "_binary_al_imm8" not in source
    assert "_binary_al_imm8_with_carry" not in source
    assert "_binary_rm8_imm8" not in source
    assert "_binary_rm8_imm8_with_carry" not in source
    assert "_compare_al_imm8" not in source
    assert "_compare_rm8_imm8" not in source


def test_x86_16_instruction_core_base_reuses_resolved_memory_operands_for_byte_memory_paths():
    source = inspect.getsource(InstrBase.xchg_r8_rm8) + inspect.getsource(InstrBase.esc)

    assert "_resolved_rm_operand(8)" in source
    assert "select_segment()" not in source
    assert "get_m()" not in source


def test_x86_16_exec_resolved_memory_operands_use_effective_address_width():
    source = inspect.getsource(InstrBase._resolved_rm_operand) + inspect.getsource(InstrBase._resolved_moffs_operand)

    assert "effective_address_bits(" in source


def test_x86_16_instruction_core_uses_addressing_helpers_for_xlat_and_bound_pairs():
    source = inspect.getsource(instr16.Instr16.xlat) + inspect.getsource(instr16.Instr16.bound_r16_m16)

    assert "resolve_linear_operand(" in source
    assert "load_resolved_operand(" in source
    assert "load_word_pair16(" in source
    assert "effective_address_bits(" in source


def test_x86_16_instruction_core_uses_shared_rm8_access_for_movzx_and_movsx():
    source = inspect.getsource(instr16.Instr16.movzx_r16_rm8) + inspect.getsource(instr16.Instr16.movsx_r16_rm8)

    assert "self.get_rm8()" in source
    assert "calc_modrm()" not in source
    assert "self.emu.get_data8(" not in source


def test_x86_16_instruction_core_uses_string_helpers_for_string_memory_access():
    source = (
        inspect.getsource(instr16.Instr16.movsb_m8_m8)
        + inspect.getsource(instr16.Instr16.movsw_m16_m16)
        + inspect.getsource(instr16.Instr16.lodsb_al_m8)
        + inspect.getsource(instr16.Instr16.lodsw_ax_m16)
        + inspect.getsource(instr16.Instr16.scasb_al_m8)
        + inspect.getsource(instr16.Instr16.scasw_ax_m16)
        + inspect.getsource(instr16.Instr16.cmps_m8_m8)
        + inspect.getsource(instr16.Instr16.cmps_m16_m16)
        + inspect.getsource(instr16.Instr16.insb_m8_dx)
        + inspect.getsource(instr16.Instr16.insw_m16_dx)
        + inspect.getsource(instr16.Instr16.outsb_dx_m8)
        + inspect.getsource(instr16.Instr16.outsw_dx_m16)
    )

    assert "string_load(" in source
    assert "string_store(" in source


def test_x86_16_instruction_core_uses_string_helpers_for_32bit_string_compare_access():
    source = inspect.getsource(instr32.Instr32.cmps_m8_m8) + inspect.getsource(instr32.Instr32.cmps_m32_m32)

    assert "string_load(" in source
    assert "self.emu.get_data8(" not in source
    assert "self.emu.get_data32(" not in source


def test_x86_16_instruction_core_uses_decode_width_api_for_far_pointer_paths():
    source = inspect.getsource(instr16.Instr16._load_far_pointer) + inspect.getsource(instr32.Instr32.callf_m16_32) + inspect.getsource(instr32.Instr32.jmpf_m16_32)

    assert "effective_address_bits(" in source
    assert "address_width_bits(" not in source


def test_x86_16_instruction_core_uses_stack_helpers_for_pusha_and_popa():
    source = inspect.getsource(instr16.Instr16.pusha) + inspect.getsource(instr16.Instr16.popa)

    assert "push_all16(" in source
    assert "pop_all16(" in source
    assert "self.emu.push16(" not in source
    assert "self.emu.pop16(" not in source


def test_x86_16_instruction_core_uses_stack_helpers_for_near_returns():
    source = inspect.getsource(instr16.Instr16.ret) + inspect.getsource(instr16.Instr16.ret_imm16)

    assert "return_near16(" in source
    assert "self.emu.pop16(" not in source
    assert "self.emu.irsb.jumpkind" not in source


def test_x86_16_instruction_core_uses_stack_helpers_for_segment_flags_and_near_control_transfer():
    source = (
        inspect.getsource(instr16.Instr16.push_es)
        + inspect.getsource(instr16.Instr16.pop_es)
        + inspect.getsource(instr16.Instr16.push_cs)
        + inspect.getsource(instr16.Instr16.push_ss)
        + inspect.getsource(instr16.Instr16.pop_ss)
        + inspect.getsource(instr16.Instr16.push_ds)
        + inspect.getsource(instr16.Instr16.pop_ds)
        + inspect.getsource(instr16.Instr16.pushf)
        + inspect.getsource(instr16.Instr16.popf)
        + inspect.getsource(instr16.Instr16.call_rel16)
        + inspect.getsource(instr16.Instr16.jmp_rel16)
        + inspect.getsource(instr16.Instr16.call_rm16)
        + inspect.getsource(instr16.Instr16.jmp_rm16)
    )

    assert "push_segment16(" in source
    assert "pop_segment16(" in source
    assert "push_flags16(" in source
    assert "pop_flags16(" in source
    assert "emit_near_call16(" in source
    assert "emit_near_jump16(" in source
    assert "near_relative_target16(" in source


def test_x86_16_instruction_core_uses_stack_helpers_for_32bit_stack_families():
    source = (
        inspect.getsource(instr32.Instr32.push_es)
        + inspect.getsource(instr32.Instr32.pop_es)
        + inspect.getsource(instr32.Instr32.push_ss)
        + inspect.getsource(instr32.Instr32.pop_ss)
        + inspect.getsource(instr32.Instr32.push_ds)
        + inspect.getsource(instr32.Instr32.pop_ds)
        + inspect.getsource(instr32.Instr32.pushad)
        + inspect.getsource(instr32.Instr32.popad)
        + inspect.getsource(instr32.Instr32.ret)
    )

    assert "push_segment32(" in source
    assert "pop_segment32(" in source
    assert "push_all32(" in source
    assert "pop_all32(" in source
    assert "return_near32(" in source


def test_x86_16_instruction_core_uses_stack_helpers_for_register_flags_and_immediate_pushes():
    source = (
        inspect.getsource(instr16.Instr16.push_r16)
        + inspect.getsource(instr16.Instr16.pop_r16)
        + inspect.getsource(instr16.Instr16.push_imm16)
        + inspect.getsource(instr16.Instr16.push_imm8)
        + inspect.getsource(instr16.Instr16.pushf)
        + inspect.getsource(instr32.Instr32.push_r32)
        + inspect.getsource(instr32.Instr32.pop_r32)
        + inspect.getsource(instr32.Instr32.push_imm32)
        + inspect.getsource(instr32.Instr32.push_imm8)
        + inspect.getsource(instr32.Instr32.pushf)
        + inspect.getsource(instr32.Instr32.popf)
    )

    assert "push16_register(" in source
    assert "pop16_register(" in source
    assert "push_immediate16(" in source
    assert "push_immediate32(" in source
    assert "push_flags16(" in source
    assert "push_flags32(" in source
    assert "pop_flags32(" in source
    assert "push32_register(" in source
    assert "pop32_register(" in source


def test_x86_16_instruction_core_uses_stack_helpers_for_rm_push_and_pop_paths():
    source = inspect.getsource(instr16.Instr16.push_rm16) + inspect.getsource(instr16.Instr16.pop_rm16)

    assert "push_immediate16(" in source
    assert "pop16(" in source
    assert "self.emu.push16(" not in source
    assert "self.emu.pop16(" not in source


def test_x86_16_instruction_core_uses_stack_helpers_for_32bit_near_control_transfer():
    source = (
        inspect.getsource(instr32.Instr32.call_rel32)
        + inspect.getsource(instr32.Instr32.jmp_rel32)
        + inspect.getsource(instr32.Instr32.call_rm32)
        + inspect.getsource(instr32.Instr32.jmp_rm32)
        + inspect.getsource(instr32.Instr32.jo_rel32)
        + inspect.getsource(instr32.Instr32.jno_rel32)
        + inspect.getsource(instr32.Instr32.jb_rel32)
        + inspect.getsource(instr32.Instr32.jnb_rel32)
        + inspect.getsource(instr32.Instr32.jz_rel32)
        + inspect.getsource(instr32.Instr32.jnz_rel32)
        + inspect.getsource(instr32.Instr32.jbe_rel32)
        + inspect.getsource(instr32.Instr32.ja_rel32)
        + inspect.getsource(instr32.Instr32.js_rel32)
        + inspect.getsource(instr32.Instr32.jns_rel32)
        + inspect.getsource(instr32.Instr32.jp_rel32)
        + inspect.getsource(instr32.Instr32.jnp_rel32)
        + inspect.getsource(instr32.Instr32.jl_rel32)
        + inspect.getsource(instr32.Instr32.jnl_rel32)
        + inspect.getsource(instr32.Instr32.jle_rel32)
        + inspect.getsource(instr32.Instr32.jnle_rel32)
    )

    assert "emit_near_call32(" in source
    assert "emit_near_jump32(" in source
    assert "branch_rel32(" in source
    assert "near_relative_target32(" in source
    assert "self.emu.update_eip(" not in source


def test_x86_16_instruction_core_uses_addressing_helper_to_advance_32bit_instruction_pointer():
    source = inspect.getsource(instr32.Instr32.test_rm32_imm32)

    assert "advance_eip32(" in source
    assert "update_eip(" not in source


def test_x86_16_instruction_core_uses_stack_helpers_for_base_return_and_jump_control():
    source = (
        inspect.getsource(InstrBase.retf_imm16)
        + inspect.getsource(InstrBase.retf)
        + inspect.getsource(InstrBase.iret)
        + inspect.getsource(InstrBase.jmp)
    )

    assert "return_far16(" in source
    assert "return_interrupt16(" in source
    assert "branch_rel8(" in source
    assert "self.emu.v2p(" not in source


def test_x86_16_emu_runtime_uses_shared_far_frame_helpers_by_mode():
    source = inspect.getsource(emu_mod.EmuInstr.callf) + inspect.getsource(emu_mod.EmuInstr.retf) + inspect.getsource(emu_mod.EmuInstr.iret)

    assert "push_far_return_frame16(" in source
    assert "push_far_return_frame32(" in source
    assert "push_privilege_stack32(" in source
    assert "pop_far_return_frame16(" in source
    assert "pop_far_return_frame32(" in source
    assert "pop_interrupt_frame16(" in source
    assert "pop_interrupt_frame32(" in source


def test_x86_16_instruction_core_uses_stack_helpers_for_far_control_transfer():
    source = (
        inspect.getsource(instr16.Instr16.callf_ptr16_16)
        + inspect.getsource(instr16.Instr16.jmpf_ptr16_16)
        + inspect.getsource(instr16.Instr16.callf_m16_16)
        + inspect.getsource(instr16.Instr16.jmpf_m16_16)
        + inspect.getsource(instr32.Instr32.callf_ptr16_32)
        + inspect.getsource(instr32.Instr32.jmpf_ptr16_32)
        + inspect.getsource(instr32.Instr32.callf_m16_32)
        + inspect.getsource(instr32.Instr32.jmpf_m16_32)
    )

    assert "emit_far_call16(" in source
    assert "emit_far_jump16(" in source
    assert "emit_far_call32(" in source
    assert "emit_far_jump32(" in source
    assert "far_return_ip16(" in source
    assert "far_return_ip32(" in source


def test_x86_16_access_far_control_uses_shared_linear_address_helper():
    source = inspect.getsource(access.DataAccess.callf) + inspect.getsource(access.DataAccess.jmpf)

    assert "linear_address(" in source
    assert "self.v2p(" not in source


def test_x86_16_instruction_core_uses_stack_helpers_for_8bit_and_16bit_relative_branches():
    source = (
        inspect.getsource(instr16.Instr16.jcxz_rel8)
        + inspect.getsource(InstrBase.jo_rel8)
        + inspect.getsource(InstrBase.jno_rel8)
        + inspect.getsource(InstrBase.jb_rel8)
        + inspect.getsource(InstrBase.jnb_rel8)
        + inspect.getsource(InstrBase.jz_rel8)
        + inspect.getsource(InstrBase.jnz_rel8)
        + inspect.getsource(InstrBase.jbe_rel8)
        + inspect.getsource(InstrBase.ja_rel8)
        + inspect.getsource(InstrBase.js_rel8)
        + inspect.getsource(InstrBase.jns_rel8)
        + inspect.getsource(InstrBase.jp_rel8)
        + inspect.getsource(InstrBase.jnp_rel8)
        + inspect.getsource(InstrBase.jl_rel8)
        + inspect.getsource(InstrBase.jnl_rel8)
        + inspect.getsource(InstrBase.jle_rel8)
        + inspect.getsource(InstrBase.jnle_rel8)
        + inspect.getsource(instr16.Instr16.loop16)
        + inspect.getsource(instr16.Instr16.loop16e)
        + inspect.getsource(instr16.Instr16.loop16ne)
        + inspect.getsource(instr16.Instr16.jo_rel16)
        + inspect.getsource(instr16.Instr16.jno_rel16)
        + inspect.getsource(instr16.Instr16.jb_rel16)
        + inspect.getsource(instr16.Instr16.jnb_rel16)
        + inspect.getsource(instr16.Instr16.jz_rel16)
        + inspect.getsource(instr16.Instr16.jnz_rel16)
        + inspect.getsource(instr16.Instr16.jbe_rel16)
        + inspect.getsource(instr16.Instr16.ja_rel16)
        + inspect.getsource(instr16.Instr16.js_rel16)
        + inspect.getsource(instr16.Instr16.jns_rel16)
        + inspect.getsource(instr16.Instr16.jp_rel16)
        + inspect.getsource(instr16.Instr16.jnp_rel16)
        + inspect.getsource(instr16.Instr16.jl_rel16)
        + inspect.getsource(instr16.Instr16.jnl_rel16)
        + inspect.getsource(instr16.Instr16.jle_rel16)
        + inspect.getsource(instr16.Instr16.jnle_rel16)
    )

    assert "branch_rel8(" in source
    assert "branch_rel16(" in source
    assert "loop_rel8(" in source
    assert "self.emu.lifter_instruction.jump(" not in source


def test_x86_16_instruction_core_uses_byte_alu_immediate_helper_families():
    source = (
        inspect.getsource(InstrBase.add_al_imm8)
        + inspect.getsource(InstrBase.or_al_imm8)
        + inspect.getsource(InstrBase.and_al_imm8)
        + inspect.getsource(InstrBase.sub_al_imm8)
        + inspect.getsource(InstrBase.xor_al_imm8)
        + inspect.getsource(InstrBase.adc_al_imm8)
        + inspect.getsource(InstrBase.sbb_al_imm8)
        + inspect.getsource(InstrBase.cmp_al_imm8)
        + inspect.getsource(InstrBase.add_rm8_imm8)
        + inspect.getsource(InstrBase.or_rm8_imm8)
        + inspect.getsource(InstrBase.and_rm8_imm8)
        + inspect.getsource(InstrBase.sub_rm8_imm8)
        + inspect.getsource(InstrBase.xor_rm8_imm8)
        + inspect.getsource(InstrBase.adc_rm8_imm8)
        + inspect.getsource(InstrBase.sbb_rm8_imm8)
        + inspect.getsource(InstrBase.cmp_rm8_imm8)
    )

    assert "binary_operation(" in source
    assert "binary_operation_with_carry(" in source
    assert "compare_operation(" in source
    assert "_binary_al_imm8(" not in source
    assert "_binary_al_imm8_with_carry(" not in source
    assert "_compare_al_imm8(" not in source
    assert "_binary_rm8_imm8(" not in source
    assert "_binary_rm8_imm8_with_carry(" not in source
    assert "_compare_rm8_imm8(" not in source


def test_x86_16_instruction_core_uses_resolved_operand_load_store_helpers():
    source = (
        inspect.getsource(instr16.Instr16.xchg_r16_rm16)
        + inspect.getsource(InstrBase.xchg_r8_rm8)
        + inspect.getsource(InstrBase.esc)
    )

    assert "load_resolved_operand(" in source
    assert "store_resolved_operand(" in source
