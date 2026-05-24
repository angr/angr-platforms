from __future__ import annotations

from pathlib import Path

import angr
from angr import options as o

from angr_platforms.X86_16.arch_86_16 import Arch86_16

MATRIX_DIR = Path(__file__).resolve().parents[1] / "x16_samples"


def _com_project(name: str):
    return angr.Project(
        MATRIX_DIR / name,
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        simos="DOS",
    )


def _concreteish_entry_state(project: angr.Project):
    state = project.factory.entry_state(
        add_options={
            o.ZERO_FILL_UNCONSTRAINED_MEMORY,
            o.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )
    state.regs.sp = 0xFFFE
    return state


def _run_to_completion(project: angr.Project, max_steps: int = 16):
    simgr = project.factory.simgr(_concreteish_entry_state(project))

    for _ in range(max_steps):
        if simgr.deadended or not simgr.active:
            break

        state = simgr.active[0]
        if project.is_hooked(state.addr):
            simgr.step()
            continue

        data = project.loader.memory.load(state.addr, 16)
        insn = next(project.arch.capstone.disasm(bytes(data), state.addr, 1))
        simgr.step(size=insn.size)

    return simgr


def _run_plain_steps_to_completion(project: angr.Project, max_steps: int = 16):
    simgr = project.factory.simgr(_concreteish_entry_state(project))

    for _ in range(max_steps):
        if simgr.deadended or not simgr.active:
            break
        simgr.step()

    return simgr


def test_com_dos_sample_runs_to_dos_exit():
    project = _com_project("ICOMDO.COM")
    simgr = _run_to_completion(project)

    assert len(simgr.active) == 0
    assert len(simgr.deadended) == 1
    assert len(simgr.errored) == 0
    assert simgr.deadended[0].addr == 0


def test_com_bios_sample_runs_to_dos_exit():
    project = _com_project("ICOMBI.COM")
    simgr = _run_to_completion(project)

    assert len(simgr.active) == 0
    assert len(simgr.deadended) == 1
    assert len(simgr.errored) == 0
    assert simgr.deadended[0].addr == 0


def test_com_dos_sample_runs_to_dos_exit_with_plain_steps():
    project = _com_project("ICOMDO.COM")
    simgr = _run_plain_steps_to_completion(project)

    assert len(simgr.active) == 0
    assert len(simgr.deadended) == 1
    assert len(simgr.errored) == 0
    assert simgr.deadended[0].addr == 0


def test_com_bios_sample_runs_to_dos_exit_with_plain_steps():
    project = _com_project("ICOMBI.COM")
    simgr = _run_plain_steps_to_completion(project)

    assert len(simgr.active) == 0
    assert len(simgr.deadended) == 1
    assert len(simgr.errored) == 0
    assert simgr.deadended[0].addr == 0
