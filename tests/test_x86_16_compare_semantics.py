from __future__ import annotations

import angr
import pyvex
from angr import options as o
from archinfo import ArchX86

from angr_platforms.X86_16.arch_86_16 import Arch86_16


def _run_one_instruction(arch, code: bytes, ax: int = 0x125A, di: int = 0x200):
    project = angr.load_shellcode(
        code,
        arch=arch,
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.ax = ax
    state.regs.es = 0
    try:
        state.regs.di = di
    except AttributeError:
        pass
    try:
        state.regs.edi = di
    except AttributeError:
        pass

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _run_one_instruction_with_flags(arch, code: bytes, ax: int, flags: int, dx: int | None = None):
    project = angr.load_shellcode(
        code,
        arch=arch,
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.ax = ax
    state.regs.flags = flags
    if dx is not None:
        try:
            state.regs.dx = dx
        except AttributeError:
            pass
        try:
            state.regs.edx = dx
        except AttributeError:
            pass

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _run_loop_instruction(arch, code: bytes, cx: int, flags: int = 0):
    project = angr.load_shellcode(
        code,
        arch=arch,
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.cx = cx
    state.regs.flags = flags
    try:
        state.regs.ecx = cx
    except AttributeError:
        pass

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _run_jcc_instruction(arch, code: bytes, *, cx: int = 0, flags: int = 0):
    project = angr.load_shellcode(
        code,
        arch=arch,
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.cx = cx
    state.regs.flags = flags
    try:
        state.regs.ecx = cx
    except AttributeError:
        pass

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _assert_same_jcc_addr(code16: bytes, code32: bytes, *, cx: int = 0, flags: int = 0):
    state32 = _run_jcc_instruction(ArchX86(), code32, cx=cx, flags=flags)
    state16 = _run_jcc_instruction(Arch86_16(), code16, cx=cx, flags=flags)
    assert state32.addr == state16.addr


def _assert_same_loop_addr(code16: bytes, code32: bytes, *, cx: int, flags: int = 0):
    state32 = _run_loop_instruction(ArchX86(), code32, cx=cx, flags=flags)
    state16 = _run_loop_instruction(Arch86_16(), code16, cx=cx, flags=flags)
    assert state32.addr - len(code32) == state16.addr - len(code16)
    assert state32.solver.eval(state32.regs.cx) == state16.solver.eval(state16.regs.cx)


def _run_one_instruction_with_regs(arch, code: bytes, regs: dict[str, int]):
    project = angr.load_shellcode(
        code,
        arch=arch,
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.ds = 0
    state.regs.es = 0
    state.regs.ss = 0
    for reg, value in regs.items():
        setattr(state.regs, reg, value)
        alias = {"cx": "ecx", "dx": "edx", "si": "esi", "di": "edi"}.get(reg)
        if alias is not None:
            try:
                setattr(state.regs, alias, value)
            except AttributeError:
                pass

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _run_xlat_instruction(arch, code: bytes, table: bytes, bx: int = 0x220, ax: int = 0x0005):
    project = angr.load_shellcode(
        code,
        arch=arch,
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.ds = 0
    state.regs.bx = bx
    state.regs.ax = ax
    try:
        state.regs.ebx = bx
    except AttributeError:
        pass
    state.memory.store(bx, table)

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _run_movs_instruction(arch, code: bytes, src: bytes, si: int = 0x220, di: int = 0x200, cx: int = 0):
    project = angr.load_shellcode(
        code,
        arch=arch,
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.ds = 0
    state.regs.es = 0
    state.regs.si = si
    state.regs.di = di
    state.regs.cx = cx
    try:
        state.regs.esi = si
        state.regs.edi = di
        state.regs.ecx = cx
    except AttributeError:
        pass
    state.memory.store(si, src)

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _assert_same_reg_effect_with_flags(
    code16: bytes,
    code32: bytes,
    *,
    regs: dict[str, int],
    compare_regs: tuple[str, ...],
    compare_flag_bits: tuple[int, ...] = (0, 6, 7, 11),
):
    state32 = _run_one_instruction_with_regs(ArchX86(), code32, regs)
    state16 = _run_one_instruction_with_regs(Arch86_16(), code16, regs)

    for reg in compare_regs:
        assert state32.solver.eval(getattr(state32.regs, reg)) == state16.solver.eval(getattr(state16.regs, reg))
    for bit in compare_flag_bits:
        assert state32.solver.eval(state32.regs.flags[bit]) == state16.solver.eval(state16.regs.flags[bit])


def _assert_same_store_effect(code16: bytes, code32: bytes, width: int, ax: int):
    state32 = _run_one_instruction(ArchX86(), code32, ax=ax)
    state16 = _run_one_instruction(Arch86_16(), code16, ax=ax)

    assert state32.solver.eval(state32.regs.di) == state16.solver.eval(state16.regs.di)
    assert state32.solver.eval(state32.memory.load(0x200, width, endness=state32.arch.memory_endness)) == (
        state16.solver.eval(state16.memory.load(0x200, width, endness=state16.arch.memory_endness))
    )


def _assert_same_load_effect(code16: bytes, code32: bytes, mem: bytes):
    state32 = _run_load_instruction(ArchX86(), code32, mem)
    state16 = _run_load_instruction(Arch86_16(), code16, mem)

    assert state32.solver.eval(state32.regs.ax) == state16.solver.eval(state16.regs.ax)
    assert state32.solver.eval(state32.regs.si) == state16.solver.eval(state16.regs.si)


def _run_load_instruction(arch, code: bytes, mem: bytes, si: int = 0x220):
    project = angr.load_shellcode(
        code,
        arch=arch,
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.ds = 0
    try:
        state.regs.si = si
    except AttributeError:
        pass
    try:
        state.regs.esi = si
    except AttributeError:
        pass
    state.memory.store(si, mem)

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _assert_same_scan_effect(code16: bytes, code32: bytes, width: int, ax: int, mem: bytes):
    state32 = _run_scan_instruction(ArchX86(), code32, ax=ax, mem=mem)
    state16 = _run_scan_instruction(Arch86_16(), code16, ax=ax, mem=mem)

    assert state32.solver.eval(state32.regs.di) == state16.solver.eval(state16.regs.di)
    for bit in (0, 6, 7, 11):
        assert state32.solver.eval(state32.regs.flags[bit]) == state16.solver.eval(state16.regs.flags[bit])


def _assert_same_cmps_effect(code16: bytes, code32: bytes, src: bytes, dst: bytes):
    state32 = _run_cmps_instruction(ArchX86(), code32, src=src, dst=dst)
    state16 = _run_cmps_instruction(Arch86_16(), code16, src=src, dst=dst)

    assert state32.solver.eval(state32.regs.si) == state16.solver.eval(state16.regs.si)
    assert state32.solver.eval(state32.regs.di) == state16.solver.eval(state16.regs.di)
    for bit in (0, 6, 7, 11):
        assert state32.solver.eval(state32.regs.flags[bit]) == state16.solver.eval(state16.regs.flags[bit])


def _run_scan_instruction(arch, code: bytes, ax: int, mem: bytes, di: int = 0x200):
    project = angr.load_shellcode(
        code,
        arch=arch,
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.ax = ax
    state.regs.es = 0
    try:
        state.regs.di = di
    except AttributeError:
        pass
    try:
        state.regs.edi = di
    except AttributeError:
        pass
    state.memory.store(di, mem)

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _run_cmps_instruction(arch, code: bytes, src: bytes, dst: bytes, si: int = 0x220, di: int = 0x200):
    project = angr.load_shellcode(
        code,
        arch=arch,
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.ds = 0
    state.regs.es = 0
    try:
        state.regs.si = si
        state.regs.di = di
    except AttributeError:
        pass
    try:
        state.regs.esi = si
        state.regs.edi = di
    except AttributeError:
        pass
    state.memory.store(si, src)
    state.memory.store(di, dst)

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _run_far_load_instruction(code: bytes, si: int = 0x220):
    project = angr.load_shellcode(
        code,
        arch=Arch86_16(),
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.si = si
    state.regs.ds = 0
    state.memory.store(si, b"\x34\x12\x78\x56")

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _run_iret_instruction(code: bytes, sp: int = 0x300):
    project = angr.load_shellcode(
        code,
        arch=Arch86_16(),
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.ss = 0
    state.regs.sp = sp
    state.memory.store(sp, b"\x78\x56\x34\x12\x01\x08")

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    block = project.factory.block(0x100, num_inst=1, insn_bytes=code)
    return simgr.active[0], block


def _run_control_flow_instruction(code: bytes, setup=None, sp: int = 0x300):
    project = angr.load_shellcode(
        code,
        arch=Arch86_16(),
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.ss = 0
    state.regs.cs = 0
    state.regs.sp = sp
    if setup is not None:
        setup(state)

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _run_stack_instruction(arch, code: bytes, regs: dict[str, int], stack: bytes = b"", sp: int = 0x300):
    project = angr.load_shellcode(
        code,
        arch=arch,
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.ss = 0
    state.regs.ds = 0
    state.regs.es = 0
    state.regs.sp = sp
    reg_aliases = {
        "ax": "eax",
        "bx": "ebx",
        "cx": "ecx",
        "dx": "edx",
        "bp": "ebp",
        "si": "esi",
        "di": "edi",
        "sp": "esp",
    }
    for reg, value in regs.items():
        setattr(state.regs, reg, value)
        alias = reg_aliases.get(reg)
        if alias is not None:
            try:
                setattr(state.regs, alias, value)
            except AttributeError:
                pass
    if stack:
        state.memory.store(sp, stack)

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _assert_same_stack_effect(code16: bytes, code32: bytes, *, regs: dict[str, int], stack: bytes = b"", sp: int = 0x300):
    state32 = _run_stack_instruction(ArchX86(), code32, regs, stack=stack, sp=sp)
    state16 = _run_stack_instruction(Arch86_16(), code16, regs, stack=stack, sp=sp)

    assert state32.solver.eval(state32.regs.sp) == state16.solver.eval(state16.regs.sp)
    for offset in range(0, max(2, len(stack)), 2):
        addr = sp - 2 + offset if not stack else sp + offset
        assert state32.solver.eval(state32.memory.load(addr, 2, endness=state32.arch.memory_endness)) == (
            state16.solver.eval(state16.memory.load(addr, 2, endness=state16.arch.memory_endness))
        )


def _run_pop_rm16_instruction(code: bytes, sp: int = 0x300, bx: int = 0x220):
    project = angr.load_shellcode(
        code,
        arch=Arch86_16(),
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.ss = 0
    state.regs.ds = 0
    state.regs.sp = sp
    state.regs.bx = bx
    state.memory.store(sp, b"\x34\x12")

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def test_stosb_matches_upstream_x86_vex_effect():
    _assert_same_store_effect(b"\xAA", b"\xAA", 1, ax=0x125A)


def test_stosw_matches_upstream_x86_vex_effect():
    _assert_same_store_effect(b"\xAB", b"\x66\xAB", 2, ax=0x3456)


def test_lodsb_matches_upstream_x86_vex_effect():
    _assert_same_load_effect(b"\xAC", b"\x67\xAC", b"\x78")


def test_lodsw_matches_upstream_x86_vex_effect():
    _assert_same_load_effect(b"\xAD", b"\x66\x67\xAD", b"\x78\x56")


def test_scasb_matches_upstream_x86_vex_effect():
    _assert_same_scan_effect(b"\xAE", b"\x67\xAE", 1, ax=0x1278, mem=b"\x78")


def test_scasw_matches_upstream_x86_vex_effect():
    _assert_same_scan_effect(b"\xAF", b"\x66\x67\xAF", 2, ax=0x5678, mem=b"\x78\x56")


def test_cmpsb_matches_upstream_x86_vex_effect():
    _assert_same_cmps_effect(b"\xA6", b"\x67\xA6", b"\x78", b"\x78")


def test_rcr_ax_1_matches_upstream_x86_vex_effect():
    state32 = _run_one_instruction_with_flags(ArchX86(), b"\x66\xD1\xD8", ax=0x8001, flags=1)
    state16 = _run_one_instruction_with_flags(Arch86_16(), b"\xD1\xD8", ax=0x8001, flags=1)

    assert state32.solver.eval(state32.regs.ax) == state16.solver.eval(state16.regs.ax)
    for bit in (0, 11):
        assert state32.solver.eval(state32.regs.flags[bit]) == state16.solver.eval(state16.regs.flags[bit])


def test_ror_al_1_matches_upstream_x86_vex_effect():
    state32 = _run_one_instruction_with_flags(ArchX86(), b"\xD0\xC8", ax=0x0081, flags=0)
    state16 = _run_one_instruction_with_flags(Arch86_16(), b"\xD0\xC8", ax=0x0081, flags=0)

    assert state32.solver.eval(state32.regs.ax) == state16.solver.eval(state16.regs.ax)


def test_adc_ax_imm16_matches_upstream_x86_vex_effect():
    state32 = _run_one_instruction_with_flags(ArchX86(), b"\x66\x15\x00\x00", ax=0x0000, flags=1)
    state16 = _run_one_instruction_with_flags(Arch86_16(), b"\x15\x00\x00", ax=0x0000, flags=1)

    assert state32.solver.eval(state32.regs.ax) == state16.solver.eval(state16.regs.ax)
    for bit in (0, 2, 6, 7, 11):
        assert state32.solver.eval(state32.regs.flags[bit]) == state16.solver.eval(state16.regs.flags[bit])


def test_add_ax_imm16_matches_upstream_x86_vex_effect():
    state32 = _run_one_instruction_with_flags(ArchX86(), b"\x66\x05\x01\x00", ax=0x00FF, flags=0)
    state16 = _run_one_instruction_with_flags(Arch86_16(), b"\x05\x01\x00", ax=0x00FF, flags=0)

    assert state32.solver.eval(state32.regs.ax) == state16.solver.eval(state16.regs.ax)
    for bit in (0, 2, 6, 7, 11):
        assert state32.solver.eval(state32.regs.flags[bit]) == state16.solver.eval(state16.regs.flags[bit])


def test_adc_bx_cx_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x11\xCB",
        b"\x66\x11\xCB",
        regs={"bx": 0x1234, "cx": 0x1111, "flags": 1},
        compare_regs=("bx",),
        compare_flag_bits=(0, 2, 6, 7, 11),
    )


def test_sbb_dx_imm8_matches_upstream_x86_vex_effect():
    state32 = _run_one_instruction_with_flags(ArchX86(), b"\x66\x83\xDA\x00", ax=0x0000, dx=0x1234, flags=1)
    state16 = _run_one_instruction_with_flags(Arch86_16(), b"\x83\xDA\x00", ax=0x0000, dx=0x1234, flags=1)

    assert state32.solver.eval(state32.regs.dx) == state16.solver.eval(state16.regs.dx)
    for bit in (0, 6, 7, 11):
        assert state32.solver.eval(state32.regs.flags[bit]) == state16.solver.eval(state16.regs.flags[bit])


def test_sbb_al_al_opcode_1a_matches_upstream_x86_vex_effect():
    state32 = _run_one_instruction_with_flags(ArchX86(), b"\x1A\xC0", ax=0x0050, flags=1)
    state16 = _run_one_instruction_with_flags(Arch86_16(), b"\x1A\xC0", ax=0x0050, flags=1)

    assert state32.solver.eval(state32.regs.ax) == state16.solver.eval(state16.regs.ax)
    for bit in (0, 6, 7, 11):
        assert state32.solver.eval(state32.regs.flags[bit]) == state16.solver.eval(state16.regs.flags[bit])


def test_sar_al_1_matches_upstream_x86_vex_effect():
    state32 = _run_one_instruction_with_flags(ArchX86(), b"\xD0\xF8", ax=0x80FF, flags=0)
    state16 = _run_one_instruction_with_flags(Arch86_16(), b"\xD0\xF8", ax=0x80FF, flags=0)

    assert state32.solver.eval(state32.regs.ax) == state16.solver.eval(state16.regs.ax)


def test_shl_bx_cl_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xD3\xE3",
        b"\x66\xD3\xE3",
        regs={"bx": 0x1234, "cx": 3, "flags": 0},
        compare_regs=("bx",),
        compare_flag_bits=(0, 6, 7),
    )


def test_shr_di_cl_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xD3\xEF",
        b"\x66\xD3\xEF",
        regs={"di": 0x9234, "cx": 3, "flags": 0},
        compare_regs=("di",),
        compare_flag_bits=(0, 6, 7),
    )


def test_rol_si_cl_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xD3\xC6",
        b"\x66\xD3\xC6",
        regs={"si": 0x9234, "cx": 3, "flags": 0},
        compare_regs=("si",),
        compare_flag_bits=(0,),
    )


def test_ror_si_cl_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xD3\xCE",
        b"\x66\xD3\xCE",
        regs={"si": 0x9234, "cx": 3, "flags": 0},
        compare_regs=("si",),
        compare_flag_bits=(0,),
    )


def test_rol_si_cl_masked_16_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xD3\xC6",
        b"\x66\xD3\xC6",
        regs={"si": 0x9234, "cx": 0x10, "flags": 0x0801},
        compare_regs=("si",),
        compare_flag_bits=(0, 11),
    )


def test_ror_si_cl_masked_16_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xD3\xCE",
        b"\x66\xD3\xCE",
        regs={"si": 0x9234, "cx": 0x10, "flags": 0x0801},
        compare_regs=("si",),
        compare_flag_bits=(0, 11),
    )


def test_rcl_si_cl_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xD3\xD6",
        b"\x66\xD3\xD6",
        regs={"si": 0x9234, "cx": 3, "flags": 1},
        compare_regs=("si",),
        compare_flag_bits=(0,),
    )


def test_rcr_si_cl_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xD3\xDE",
        b"\x66\xD3\xDE",
        regs={"si": 0x9234, "cx": 3, "flags": 1},
        compare_regs=("si",),
        compare_flag_bits=(0,),
    )


def test_cbw_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x98",
        b"\x66\x98",
        regs={"ax": 0x0081},
        compare_regs=("ax",),
        compare_flag_bits=(),
    )


def test_inc_ax_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x40",
        b"\x66\x40",
        regs={"ax": 0x7FFF, "flags": 0},
        compare_regs=("ax",),
        compare_flag_bits=(4, 6, 7, 11),
    )


def test_cwd_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x99",
        b"\x66\x99",
        regs={"ax": 0x8001, "dx": 0},
        compare_regs=("dx",),
        compare_flag_bits=(),
    )


def test_xchg_ax_cx_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x91",
        b"\x91",
        regs={"ax": 0x1234, "cx": 0xABCD},
        compare_regs=("ax", "cx"),
        compare_flag_bits=(),
    )


def test_xchg_di_mem_matches_upstream_x86_vex_effect():
    code16 = b"\x87\x3D"
    code32 = b"\x67\x66\x87\x3F"

    project32 = angr.load_shellcode(
        code32,
        arch=ArchX86(),
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state32 = project32.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state32.regs.ds = 0
    state32.regs.di = 0x220
    state32.regs.edi = 0x220
    state32.memory.store(0x220, b"\x78\x56")
    simgr32 = project32.factory.simgr(state32)
    simgr32.step(num_inst=1, insn_bytes=code32)
    state32 = simgr32.active[0]

    project16 = angr.load_shellcode(
        code16,
        arch=Arch86_16(),
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state16 = project16.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state16.regs.ds = 0
    state16.regs.di = 0x220
    state16.memory.store(0x220, b"\x78\x56")
    simgr16 = project16.factory.simgr(state16)
    simgr16.step(num_inst=1, insn_bytes=code16)
    state16 = simgr16.active[0]

    assert state32.solver.eval(state32.regs.di) == state16.solver.eval(state16.regs.di)
    assert state32.solver.eval(state32.memory.load(0x220, 2, endness=state32.arch.memory_endness)) == (
        state16.solver.eval(state16.memory.load(0x220, 2, endness=state16.arch.memory_endness))
    )


def test_test_ax_cx_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x85\xC8",
        b"\x66\x85\xC8",
        regs={"ax": 0x1234, "cx": 0x00F0, "flags": 0xFFFF},
        compare_regs=(),
        compare_flag_bits=(0, 4, 6, 7, 11),
    )


def test_sbb_ax_imm16_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x1D\xDE\xFD",
        b"\x66\x1D\xDE\xFD\x00\x00",
        regs={"ax": 0x7A3E, "flags": 0x00D3},
        compare_regs=("ax",),
        compare_flag_bits=(0, 2, 4, 6, 7, 11),
    )


def test_cmp_ax_imm16_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x3D\x00\x00",
        b"\x66\x3D\x00\x00\x00\x00",
        regs={"ax": 0x0233, "flags": 0x0412},
        compare_regs=(),
        compare_flag_bits=(0, 2, 4, 6, 7, 11),
    )


def test_or_ax_imm16_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x0D\x5B\xDF",
        b"\x66\x0D\x5B\xDF",
        regs={"ax": 0x2104, "flags": 0xFFFF},
        compare_regs=("ax",),
        compare_flag_bits=(0, 4, 6, 7, 11),
    )


def test_and_ax_imm16_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x25\x8D\x26",
        b"\x66\x25\x8D\x26",
        regs={"ax": 0xFFFF, "flags": 0xFFFF},
        compare_regs=("ax",),
        compare_flag_bits=(0, 4, 6, 7, 11),
    )


def test_xor_ax_imm16_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x35\x00\x00",
        b"\x66\x35\x00\x00",
        regs={"ax": 0x0000, "flags": 0xFFFF},
        compare_regs=("ax",),
        compare_flag_bits=(0, 4, 6, 7, 11),
    )


def test_xor_al_imm8_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x34\x96",
        b"\x34\x96",
        regs={"ax": 0x0082, "flags": 0xFFFF},
        compare_regs=("ax",),
        compare_flag_bits=(0, 4, 6, 7, 11),
    )


def test_imul_cx_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xF7\xE9",
        b"\x66\xF7\xE9",
        regs={"ax": 0xFFFE, "cx": 0xFFFC, "flags": 0},
        compare_regs=("ax", "dx"),
        compare_flag_bits=(0, 11),
    )


def test_imul_ax_bx_imm16_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x69\xC3\x76\x0F",
        b"\x66\x69\xC3\x76\x0F\x00\x00",
        regs={"ax": 0x0000, "bx": 0x81AB, "flags": 0},
        compare_regs=("ax",),
        compare_flag_bits=(0, 11),
    )


def test_imul_di_bx_imm8_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x6B\xFB\x40",
        b"\x66\x6B\xFB\x40",
        regs={"di": 0xB875, "bx": 0xFFC4, "flags": 0},
        compare_regs=("di",),
        compare_flag_bits=(0, 11),
    )


def test_mul_cl_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xF6\xE1",
        b"\xF6\xE1",
        regs={"ax": 0x00F3, "cx": 0x0003, "flags": 0},
        compare_regs=("ax",),
        compare_flag_bits=(0, 11),
    )


def test_mul_cx_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xF7\xE1",
        b"\x66\xF7\xE1",
        regs={"ax": 0x2B87, "cx": 0x8003, "flags": 0},
        compare_regs=("ax", "dx"),
        compare_flag_bits=(),
    )


def test_div_cx_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xF7\xF1",
        b"\x66\xF7\xF1",
        regs={"ax": 0x0000, "dx": 0x0001, "cx": 0x0003, "flags": 0},
        compare_regs=("ax", "dx"),
        compare_flag_bits=(),
    )


def test_idiv_cx_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xF7\xF9",
        b"\x66\xF7\xF9",
        regs={"ax": 0x0009, "dx": 0x0000, "cx": 0x0003, "flags": 0},
        compare_regs=("ax", "dx"),
        compare_flag_bits=(),
    )


def test_neg_bx_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xF7\xDB",
        b"\x66\xF7\xDB",
        regs={"bx": 0x1234, "flags": 0},
        compare_regs=("bx",),
    )


def test_not_bx_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xF7\xD3",
        b"\x66\xF7\xD3",
        regs={"bx": 0x1234, "flags": 0},
        compare_regs=("bx",),
        compare_flag_bits=(),
    )


def test_aaa_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x37",
        b"\x37",
        regs={"ax": 0x009B, "flags": 0},
        compare_regs=("ax",),
        compare_flag_bits=(0, 4),
    )


def test_aas_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x3F",
        b"\x3F",
        regs={"ax": 0x000B, "flags": 0},
        compare_regs=("ax",),
        compare_flag_bits=(0, 4),
    )


def test_daa_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x27",
        b"\x27",
        regs={"ax": 0x009B, "flags": 0},
        compare_regs=("ax",),
        compare_flag_bits=(0, 2, 4, 6, 7),
    )


def test_das_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x2F",
        b"\x2F",
        regs={"ax": 0x009B, "flags": 0},
        compare_regs=("ax",),
        compare_flag_bits=(0, 2, 4, 6, 7),
    )


def test_aam_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xD4\x0A",
        b"\xD4\x0A",
        regs={"ax": 0x0023, "flags": 0},
        compare_regs=("ax",),
        compare_flag_bits=(2, 6, 7),
    )


def test_aad_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xD5\x0A",
        b"\xD5\x0A",
        regs={"ax": 0x0205, "flags": 0},
        compare_regs=("ax",),
        compare_flag_bits=(2, 6, 7),
    )


def test_xlat_matches_upstream_x86_vex_effect():
    table = bytes(range(16))
    state32 = _run_xlat_instruction(ArchX86(), b"\xD7", table=table)
    state16 = _run_xlat_instruction(Arch86_16(), b"\xD7", table=table)

    assert state32.solver.eval(state32.regs.al) == state16.solver.eval(state16.regs.al)


def test_movsb_matches_upstream_x86_vex_effect():
    state32 = _run_movs_instruction(ArchX86(), b"\xA4", src=b"Z")
    state16 = _run_movs_instruction(Arch86_16(), b"\xA4", src=b"Z")

    assert state32.solver.eval(state32.memory.load(0x200, 1)) == state16.solver.eval(state16.memory.load(0x200, 1))
    assert state32.solver.eval(state32.regs.si) == state16.solver.eval(state16.regs.si)
    assert state32.solver.eval(state32.regs.di) == state16.solver.eval(state16.regs.di)


def test_movsw_matches_upstream_x86_vex_effect():
    state32 = _run_movs_instruction(ArchX86(), b"\x66\x67\xA5", src=b"\x34\x12")
    state16 = _run_movs_instruction(Arch86_16(), b"\xA5", src=b"\x34\x12")

    assert state32.solver.eval(state32.memory.load(0x200, 2, endness=state32.arch.memory_endness)) == (
        state16.solver.eval(state16.memory.load(0x200, 2, endness=state16.arch.memory_endness))
    )
    assert state32.solver.eval(state32.regs.si) == state16.solver.eval(state16.regs.si)
    assert state32.solver.eval(state32.regs.di) == state16.solver.eval(state16.regs.di)


def test_rep_movsb_matches_upstream_x86_vex_effect():
    state32 = _run_movs_instruction(ArchX86(), b"\xF3\xA4", src=b"ZQ", cx=2)
    state16 = _run_movs_instruction(Arch86_16(), b"\xF3\xA4", src=b"ZQ", cx=2)

    assert state32.addr == state16.addr
    assert state32.solver.eval(state32.memory.load(0x200, 1)) == state16.solver.eval(state16.memory.load(0x200, 1))
    assert state32.solver.eval(state32.regs.si) == state16.solver.eval(state16.regs.si)
    assert state32.solver.eval(state32.regs.di) == state16.solver.eval(state16.regs.di)
    assert state32.solver.eval(state32.regs.cx) == state16.solver.eval(state16.regs.cx)


def test_lahf_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x9F",
        b"\x9F",
        regs={"ax": 0x3400, "flags": 0x08D5},
        compare_regs=("ax",),
        compare_flag_bits=(),
    )


def test_sahf_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\x9E",
        b"\x9E",
        regs={"ax": 0xD500, "flags": 0x0800},
        compare_regs=(),
        compare_flag_bits=(0, 2, 4, 6, 7, 11),
    )


def test_cmc_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xF5",
        b"\xF5",
        regs={"flags": 0x0000},
        compare_regs=(),
        compare_flag_bits=(0,),
    )


def test_clc_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xF8",
        b"\xF8",
        regs={"flags": 0x0001},
        compare_regs=(),
        compare_flag_bits=(0,),
    )


def test_stc_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xF9",
        b"\xF9",
        regs={"flags": 0x0000},
        compare_regs=(),
        compare_flag_bits=(0,),
    )


def test_cli_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xFA",
        b"\xFA",
        regs={"flags": 0xFFFF},
        compare_regs=(),
        compare_flag_bits=(9,),
    )


def test_sti_matches_upstream_x86_vex_effect():
    state = _run_control_flow_instruction(b"\xFB")

    assert state.solver.eval(state.regs.flags[9]) == 1


def test_cld_matches_upstream_x86_vex_effect():
    _assert_same_reg_effect_with_flags(
        b"\xFC",
        b"\xFC",
        regs={"flags": 0xFFFF},
        compare_regs=(),
        compare_flag_bits=(10,),
    )


def test_std_matches_upstream_x86_vex_effect():
    state = _run_control_flow_instruction(b"\xFD")

    assert state.solver.eval(state.regs.flags[10]) == 1


def test_loop_rel8_matches_upstream_x86_vex_effect():
    _assert_same_loop_addr(b"\xE2\xF2", b"\x67\xE2\xF2", cx=2)


def test_cmpsw_matches_upstream_x86_vex_effect():
    _assert_same_cmps_effect(b"\xA7", b"\x66\x67\xA7", b"\x78\x56", b"\x78\x56")


def test_jz_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x74\x05", b"\x74\x05", flags=0x0040)


def test_jnz_rel8_not_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x75\x05", b"\x75\x05", flags=0x0040)


def test_jc_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x72\x05", b"\x72\x05", flags=0x0001)


def test_ja_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x77\x05", b"\x77\x05", flags=0x0000)


def test_jbe_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x76\x05", b"\x76\x05", flags=0x0001)


def test_jae_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x73\x05", b"\x73\x05", flags=0x0000)


def test_jb_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x72\x05", b"\x72\x05", flags=0x0001)


def test_jo_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x70\x05", b"\x70\x05", flags=0x0800)


def test_jno_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x71\x05", b"\x71\x05", flags=0x0000)


def test_js_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x78\x05", b"\x78\x05", flags=0x0080)


def test_jns_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x79\x05", b"\x79\x05", flags=0x0000)


def test_jp_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x7A\x05", b"\x7A\x05", flags=0x0004)


def test_jnp_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x7B\x05", b"\x7B\x05", flags=0x0000)


def test_jg_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x7F\x05", b"\x7F\x05", flags=0x0000)


def test_jge_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x7D\x05", b"\x7D\x05", flags=0x0000)


def test_jl_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x7C\x05", b"\x7C\x05", flags=0x0080)


def test_jle_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_jcc_addr(b"\x7E\x05", b"\x7E\x05", flags=0x0040)


def test_jcxz_rel8_taken_matches_upstream_x86_vex_effect():
    state32 = _run_jcc_instruction(ArchX86(), b"\x67\xE3\x05", cx=0)
    state16 = _run_jcc_instruction(Arch86_16(), b"\xE3\x05", cx=0)
    assert state32.addr - (0x100 + 3) == state16.addr - (0x100 + 2)


def test_loope_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_loop_addr(b"\xE1\x05", b"\x67\xE1\x05", cx=2, flags=0x0040)


def test_loopne_rel8_taken_matches_upstream_x86_vex_effect():
    _assert_same_loop_addr(b"\xE0\x05", b"\x67\xE0\x05", cx=2, flags=0x0000)


def test_les_loads_far_pointer_into_register_and_es():
    state = _run_far_load_instruction(b"\xC4\x04")

    assert state.solver.eval(state.regs.ax) == 0x1234
    assert state.solver.eval(state.regs.es) == 0x5678


def test_lds_loads_far_pointer_into_register_and_ds():
    state = _run_far_load_instruction(b"\xC5\x04")

    assert state.solver.eval(state.regs.ax) == 0x1234
    assert state.solver.eval(state.regs.ds) == 0x5678


def test_iret_restores_ip_cs_and_flags():
    state, block = _run_iret_instruction(b"\xCF")
    put_regs = {
        block.vex.arch.translate_register_name(stmt.offset)
        for stmt in block.vex.statements
        if isinstance(stmt, pyvex.stmt.Put)
    }

    assert state.addr == 0x79B8
    assert state.solver.eval(state.regs.cs) == 0x1234
    assert state.solver.eval(state.regs.sp) == 0x306
    assert state.solver.eval(state.regs.flags) == 0x0801
    assert block.vex.jumpkind == "Ijk_Ret"
    assert {"cs", "flags"} <= put_regs


def test_jmp_short_executes_to_branch_target():
    state = _run_control_flow_instruction(b"\xEB\x02")

    assert state.addr == 0x104
    assert state.solver.eval(state.regs.sp) == 0x300


def test_jmp_rm16_executes_to_register_target():
    state = _run_control_flow_instruction(b"\xFF\xE0", setup=lambda s: setattr(s.regs, "ax", 0x222))

    assert state.addr == 0x222
    assert state.solver.eval(state.regs.sp) == 0x300


def test_call_rm16_pushes_return_and_jumps():
    state = _run_control_flow_instruction(b"\xFF\xD0", setup=lambda s: setattr(s.regs, "ax", 0x222))

    assert state.addr == 0x222
    assert state.solver.eval(state.regs.sp) == 0x2FE
    assert state.solver.eval(state.memory.load(0x2FE, 2, endness=state.arch.memory_endness)) == 0x102


def test_jmpf_ptr16_16_executes_to_linear_alias():
    state = _run_control_flow_instruction(b"\xEA\x78\x56\x34\x12")

    assert state.addr == 0x79B8
    assert state.solver.eval(state.regs.cs) == 0x1234
    assert state.solver.eval(state.regs.sp) == 0x300


def test_callf_ptr16_16_pushes_return_frame_and_jumps():
    state = _run_control_flow_instruction(b"\x9A\x78\x56\x34\x12")

    assert state.addr == 0x79B8
    assert state.solver.eval(state.regs.cs) == 0x1234
    assert state.solver.eval(state.regs.sp) == 0x2FC
    assert state.solver.eval(state.memory.load(0x2FC, 2, endness=state.arch.memory_endness)) == 0x105
    assert state.solver.eval(state.memory.load(0x2FE, 2, endness=state.arch.memory_endness)) == 0x0000


def test_jmpf_m16_16_executes_to_linear_alias():
    state = _run_control_flow_instruction(
        b"\xFF\x2E\x20\x01",
        setup=lambda s: (setattr(s.regs, "ds", 0), s.memory.store(0x120, b"\x78\x56\x34\x12")),
    )

    assert state.addr == 0x79B8
    assert state.solver.eval(state.regs.cs) == 0x1234
    assert state.solver.eval(state.regs.sp) == 0x300


def test_callf_m16_16_pushes_return_frame_and_jumps():
    state = _run_control_flow_instruction(
        b"\xFF\x1E\x20\x01",
        setup=lambda s: (setattr(s.regs, "ds", 0), s.memory.store(0x120, b"\x78\x56\x34\x12")),
    )

    assert state.addr == 0x79B8
    assert state.solver.eval(state.regs.cs) == 0x1234
    assert state.solver.eval(state.regs.sp) == 0x2FC
    assert state.solver.eval(state.memory.load(0x2FC, 2, endness=state.arch.memory_endness)) == 0x104
    assert state.solver.eval(state.memory.load(0x2FE, 2, endness=state.arch.memory_endness)) == 0x0000


def test_ret_pops_target_and_advances_stack():
    state = _run_control_flow_instruction(b"\xC3", setup=lambda s: s.memory.store(0x300, b"\x78\x56"))

    assert state.addr == 0x5678
    assert state.solver.eval(state.regs.sp) == 0x302


def test_retn_imm16_pops_target_and_adjusts_stack():
    state = _run_control_flow_instruction(b"\xC2\x04\x00", setup=lambda s: s.memory.store(0x300, b"\x78\x56"))

    assert state.addr == 0x5678
    assert state.solver.eval(state.regs.sp) == 0x306


def test_retf_transfers_control_without_crashing():
    state = _run_control_flow_instruction(b"\xCB", setup=lambda s: s.memory.store(0x300, b"\x78\x56\x34\x12"))

    assert state.addr == 0x79B8
    assert state.solver.eval(state.regs.cs) == 0x1234
    assert state.solver.eval(state.regs.sp) == 0x304


def test_retf_imm16_transfers_control_without_crashing():
    state = _run_control_flow_instruction(b"\xCA\x04\x00", setup=lambda s: s.memory.store(0x300, b"\x78\x56\x34\x12"))

    assert state.addr == 0x79B8
    assert state.solver.eval(state.regs.cs) == 0x1234
    assert state.solver.eval(state.regs.sp) == 0x308


def test_into_falls_through_when_overflow_clear():
    state = _run_control_flow_instruction(b"\xCE")

    assert state.addr == 0x101


def test_into_branches_to_interrupt_vector_when_overflow_set():
    state = _run_control_flow_instruction(b"\xCE", setup=lambda s: setattr(s.regs, "flags", 0x0800))

    assert state.addr == 0xF004


def _assert_same_in_effect(code16: bytes, code32: bytes, *, regs: dict[str, int], expected_ax: int):
    state32 = _run_one_instruction_with_regs(ArchX86(), code32, regs)
    state16 = _run_one_instruction_with_regs(Arch86_16(), code16, regs)

    assert state32.solver.eval(state32.regs.ax) == expected_ax
    assert state16.solver.eval(state16.regs.ax) == expected_ax
    assert state32.addr == state16.addr
    assert state32.solver.eval(state32.regs.ip) == state16.solver.eval(state16.regs.ip)


def test_in_al_dx_matches_upstream_x86_vex_effect():
    _assert_same_in_effect(b"\xEC", b"\xEC", regs={"ax": 0x12AA, "dx": 0x0040}, expected_ax=0x12FF)


def test_in_al_imm8_matches_upstream_x86_vex_effect():
    _assert_same_in_effect(b"\xE4\x40", b"\xE4\x40", regs={"ax": 0x12AA}, expected_ax=0x12FF)


def test_insb_advances_di_and_writes_byte():
    state = _run_control_flow_instruction(
        b"\x6C",
        setup=lambda s: (setattr(s.regs, "es", 0), setattr(s.regs, "di", 0x200), setattr(s.regs, "dx", 0x40)),
    )

    assert state.solver.eval(state.regs.di) == 0x201
    assert state.solver.eval(state.memory.load(0x200, 1)) == 0xFF


def test_insw_advances_di_by_word():
    state = _run_control_flow_instruction(
        b"\x6D",
        setup=lambda s: (setattr(s.regs, "es", 0), setattr(s.regs, "di", 0x200), setattr(s.regs, "dx", 0x40)),
    )

    assert state.solver.eval(state.regs.di) == 0x202
    assert state.solver.eval(state.memory.load(0x200, 2, endness=state.arch.memory_endness)) == 0xFFFF


def test_outsb_advances_si():
    state = _run_control_flow_instruction(
        b"\x6E",
        setup=lambda s: (setattr(s.regs, "ds", 0), setattr(s.regs, "si", 0x220), setattr(s.regs, "dx", 0x40), s.memory.store(0x220, b"X")),
    )

    assert state.solver.eval(state.regs.si) == 0x221


def test_outsw_advances_si_by_word():
    state = _run_control_flow_instruction(
        b"\x6F",
        setup=lambda s: (
            setattr(s.regs, "ds", 0),
            setattr(s.regs, "si", 0x220),
            setattr(s.regs, "dx", 0x40),
            s.memory.store(0x220, b"\x34\x12"),
        ),
    )

    assert state.solver.eval(state.regs.si) == 0x222


def test_pop_rm16_writes_memory_and_advances_stack():
    state = _run_pop_rm16_instruction(b"\x8F\x07")

    assert state.solver.eval(state.memory.load(0x220, 2, endness=state.arch.memory_endness)) == 0x1234
    assert state.addr == 0x102


def test_pusha_pushes_all_registers_using_original_sp():
    state = _run_stack_instruction(
        Arch86_16(),
        b"\x60",
        {
            "ax": 0x1111,
            "cx": 0x2222,
            "dx": 0x3333,
            "bx": 0x4444,
            "bp": 0x5555,
            "si": 0x6666,
            "di": 0x7777,
        },
        sp=0x300,
    )

    assert state.solver.eval(state.regs.sp) == 0x2F0
    assert state.solver.eval(state.memory.load(0x2F0, 2, endness=state.arch.memory_endness)) == 0x7777
    assert state.solver.eval(state.memory.load(0x2F2, 2, endness=state.arch.memory_endness)) == 0x6666
    assert state.solver.eval(state.memory.load(0x2F4, 2, endness=state.arch.memory_endness)) == 0x5555
    assert state.solver.eval(state.memory.load(0x2F6, 2, endness=state.arch.memory_endness)) == 0x0300
    assert state.solver.eval(state.memory.load(0x2F8, 2, endness=state.arch.memory_endness)) == 0x4444
    assert state.solver.eval(state.memory.load(0x2FA, 2, endness=state.arch.memory_endness)) == 0x3333
    assert state.solver.eval(state.memory.load(0x2FC, 2, endness=state.arch.memory_endness)) == 0x2222
    assert state.solver.eval(state.memory.load(0x2FE, 2, endness=state.arch.memory_endness)) == 0x1111


def test_popa_restores_registers_and_discards_saved_sp_word():
    stack = b"\x11\x11\x22\x22\x33\x33\x44\x44\x55\x55\x66\x66\x77\x77\x88\x88"
    state = _run_stack_instruction(Arch86_16(), b"\x61", {}, stack=stack, sp=0x300)

    assert state.solver.eval(state.regs.di) == 0x1111
    assert state.solver.eval(state.regs.si) == 0x2222
    assert state.solver.eval(state.regs.bp) == 0x3333
    assert state.solver.eval(state.regs.bx) == 0x5555
    assert state.solver.eval(state.regs.dx) == 0x6666
    assert state.solver.eval(state.regs.cx) == 0x7777
    assert state.solver.eval(state.regs.ax) == 0x8888
    assert state.solver.eval(state.regs.sp) == 0x310


def test_pushf_pushes_current_flags_word():
    state = _run_stack_instruction(Arch86_16(), b"\x9C", {"flags": 0x08D5}, sp=0x300)

    assert state.solver.eval(state.regs.sp) == 0x2FE
    assert state.solver.eval(state.memory.load(0x2FE, 2, endness=state.arch.memory_endness)) == 0x08D5


def test_popf_restores_flag_bits_from_stack():
    stack = b"\xD5\x08"
    state16 = _run_stack_instruction(Arch86_16(), b"\x9D", {"flags": 0}, stack=stack, sp=0x300)

    assert state16.solver.eval(state16.regs.sp) == 0x302
    for bit in (0, 2, 4, 6, 7, 8, 9, 10, 11):
        assert state16.solver.eval(state16.regs.flags[bit]) == ((0x08D5 >> bit) & 1)


def test_push_sp_matches_upstream_x86_vex_effect():
    state32 = _run_stack_instruction(ArchX86(), b"\x66\x54", {"sp": 0x300}, sp=0x300)
    state16 = _run_stack_instruction(Arch86_16(), b"\x54", {"sp": 0x300}, sp=0x300)

    assert state32.solver.eval(state32.regs.sp) == state16.solver.eval(state16.regs.sp)
    assert state32.solver.eval(state32.memory.load(0x2FE, 2, endness=state32.arch.memory_endness)) == (
        state16.solver.eval(state16.memory.load(0x2FE, 2, endness=state16.arch.memory_endness))
    )


def test_push_ax_matches_upstream_x86_vex_effect():
    _assert_same_stack_effect(b"\x50", b"\x66\x50", regs={"ax": 0x1234}, sp=0x300)


def test_push_imm16_matches_upstream_x86_vex_effect():
    _assert_same_stack_effect(b"\x68\x78\x56", b"\x66\x68\x78\x56", regs={}, sp=0x300)


def test_push_imm8_sign_extended_matches_upstream_x86_vex_effect():
    _assert_same_stack_effect(b"\x6A\x80", b"\x66\x6A\x80", regs={}, sp=0x300)


def test_salc_sets_al_from_carry_flag():
    set_state = _run_one_instruction_with_flags(Arch86_16(), b"\xD6", ax=0x00AA, flags=0x0001)
    clear_state = _run_one_instruction_with_flags(Arch86_16(), b"\xD6", ax=0x00AA, flags=0x0000)

    assert set_state.solver.eval(set_state.regs.ax) == 0x00FF
    assert clear_state.solver.eval(clear_state.regs.ax) == 0x0000


def test_leave_restores_bp_and_releases_stack_frame():
    stack = b"\x34\x12"
    regs = {"bp": 0x300, "sp": 0x2F0}
    state16 = _run_stack_instruction(Arch86_16(), b"\xC9", regs, stack=stack, sp=0x300)

    assert state16.solver.eval(state16.regs.bp) == 0x1234
    assert state16.solver.eval(state16.regs.sp) == 0x302


def test_enter_allocates_simple_frame():
    state = _run_stack_instruction(Arch86_16(), b"\xC8\x04\x00\x00", {"bp": 0x280}, sp=0x300)

    assert state.solver.eval(state.regs.bp) == 0x2FE
    assert state.solver.eval(state.regs.sp) == 0x2FA
    assert state.solver.eval(state.memory.load(0x2FE, 2, endness=state.arch.memory_endness)) == 0x0280


def test_enter_level_one_pushes_frame_pointer_copy():
    state = _run_stack_instruction(Arch86_16(), b"\xC8\x04\x00\x01", {"bp": 0x280}, sp=0x300)

    assert state.solver.eval(state.regs.bp) == 0x2FE
    assert state.solver.eval(state.regs.sp) == 0x2F8
    assert state.solver.eval(state.memory.load(0x2FC, 2, endness=state.arch.memory_endness)) == 0x02FE
    assert state.solver.eval(state.memory.load(0x2FE, 2, endness=state.arch.memory_endness)) == 0x0280


def test_div_zero_block_lifts_without_python_attribute_error():
    project = angr.load_shellcode(
        b"\x31\xD2\xB8\x34\x12\x31\xC9\xF7\xF1",
        arch=Arch86_16(),
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )

    block = project.factory.block(0x100, num_inst=4)
    assert block.vex is not None
