#!/usr/bin/env python3
""" test_tricore.py
A module for testing tricore lifter.
"""
import os
import unittest
import angr
import claripy
from angr_platforms.tricore import *  # pylint: disable=[wildcard-import, unused-wildcard-import]

TEST_PROGRAMS_BASE = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'test_programs', 'tricore'))


class TestTricoreLifter(unittest.TestCase):
    """ Class for testing tricore lifter. """

    def test_lifting_abs_instructions(self):
        print("Lifting (ABS format) ldmst 1000, e2", "-"*50)
        inst = b'e5020005'
        lifter = LifterTRICORE(ArchTRICORE(), 0)
        lifter.lift(inst)
        lifter.irsb.pp()
        self.assertEqual(lifter.irsb.arch.name, 'TRICORE')
        self.assertEqual(lifter.irsb.stmts_used, 14)

    def test_lifting_absb_instructions(self):
        print("\nLifting (ABSB format) st.t 0x1000, 1, 0", "-"*50)
        inst = b'D5010001'
        lifter = LifterTRICORE(ArchTRICORE(), 0)
        lifter.lift(inst)
        lifter.irsb.pp()
        self.assertEqual(lifter.irsb.arch.name, 'TRICORE')
        self.assertEqual(lifter.irsb.stmts_used, 21)


class TestAngrOnTricore(unittest.TestCase):
    """ Class for testing lifted instructions by angr analysis engine. """

    def test_angr_find_v1(self):
        print("\ntest_angr_find_v1()", "-"*100)
        test_file = os.path.join(TEST_PROGRAMS_BASE, '00_angr_find_v1.elf')
        proj = angr.Project(test_file, use_sim_procedures=True,
                                       load_options={'auto_load_libs': False,
                                                     'arch': "Tricore"})

        self.assertEqual(proj.arch.name, 'TRICORE')

        state = proj.factory.blank_state(addr=0xa1000486)

        proj.hook(0xa1000610, angr.SIM_PROCEDURES['libc']['puts']())
        proj.hook(0xa10061e0, angr.SIM_PROCEDURES['linux_kernel']['read']())

        ea = state.regs.sp + 15
        password = claripy.BVS('password', 8*8)
        state.memory.store(ea, password)

        state.regs.a4 = ea
        state.regs.a5 = 0xa1006885

        sm = proj.factory.simulation_manager(state)
        sm.explore(find=0xa1000498)

        self.assertEqual(sm.found[0].solver.eval(password, cast_to=bytes), b'PITUUQGD')


    def test_angr_find_v2(self):
        print("\ntest_angr_find_v2()", "-"*100)
        test_file = os.path.join(TEST_PROGRAMS_BASE, '00_angr_find_v2.elf')
        proj = angr.Project(test_file, use_sim_procedures=True,
                                       load_options={'auto_load_libs': False,
                                                     'arch': "Tricore"})

        self.assertEqual(proj.arch.name, 'TRICORE')

        state = proj.factory.blank_state(addr=0xa100047c)

        proj.hook(0xa1000610, angr.SIM_PROCEDURES['libc']['puts']())
        proj.hook(0xa10061e0, angr.SIM_PROCEDURES['linux_kernel']['read']())

        ea = state.regs.sp + 7
        password = claripy.BVS('password', 8*8)
        state.memory.store(ea, password)

        sm = proj.factory.simulation_manager(state)
        sm.explore(find=0xa100049a)

        self.assertEqual(sm.found[0].solver.eval(password, cast_to=bytes), b'PITUUQGD')


    def test_angr_avoid(self):
        print("\ntest_angr_avoid()", "-"*100)
        test_file = os.path.join(TEST_PROGRAMS_BASE, '01_angr_avoid.elf')
        proj = angr.Project(test_file, use_sim_procedures=True,
                                       load_options={'auto_load_libs': False,
                                                     'arch': "Tricore"})

        self.assertEqual(proj.arch.name, 'TRICORE')

        state = proj.factory.blank_state(addr=0xa1000536)

        proj.hook(0xa1000610, angr.SIM_PROCEDURES['libc']['puts']())
        proj.hook(0xa10061e0, angr.SIM_PROCEDURES['linux_kernel']['read']())
        proj.hook(0xa10006c8, angr.SIM_PROCEDURES['libc']['printf']())

        ea = state.regs.sp + 0x1c
        password = claripy.BVS('password', 8*8)
        state.memory.store(ea, password)

        state.regs.a4 = ea
        state.regs.a5 = 0xa1007c40

        sm = proj.factory.simulation_manager(state)
        sm.explore(find=0xa100048e, avoid=[0xa100045a, 0xa1000486])

        self.assertEqual(sm.found[0].solver.eval(password, cast_to=bytes), b'YDWDXNRJ')


    def test_angr_find_condition(self):
        print("\ntest_angr_find_condition()", "-"*100)
        test_file = os.path.join(TEST_PROGRAMS_BASE, '02_angr_find_condition.elf')
        proj = angr.Project(test_file, use_sim_procedures=True,
                                       load_options={'auto_load_libs': False,
                                                     'arch': "Tricore"})

        self.assertEqual(proj.arch.name, 'TRICORE')

        state = proj.factory.blank_state(addr=0xa10004c0)

        ea = state.regs.sp + 0x1c
        password = claripy.BVS('password', 8*8)
        state.memory.store(ea, password)

        state.regs.a4 = ea
        state.regs.a5 = 0xa1007b6e

        sm = proj.factory.simulation_manager(state)
        sm.explore(find=0xa10004d2, avoid=0xa1000418)

        self.assertEqual(sm.found[0].solver.eval(password, cast_to=bytes), b'RLAXEGIE')


    def test_angr_symbolic_registers(self):
        print("\ntest_angr_symbolic_registers()", "-"*100)
        test_file = os.path.join(TEST_PROGRAMS_BASE, '03_angr_symbolic_registers.elf')
        proj = angr.Project(test_file, use_sim_procedures=True,
                                       load_options={'auto_load_libs': False,
                                                     'arch': "Tricore"})

        self.assertEqual(proj.arch.name, 'TRICORE')

        state = proj.factory.blank_state(addr=0xa10005ae)

        d1 = claripy.BVS('d1', 8*4)
        d2 = claripy.BVS('d2', 8*4)
        d3 = claripy.BVS('d3', 8*4)
        state.regs.d1 = d1
        state.regs.d2 = d2
        state.regs.d3 = d3

        sm = proj.factory.simulation_manager(state)
        sm.explore(find=0xa10005dc)

        self.assertEqual(sm.found[0].solver.eval(d1), 363754123)
        self.assertEqual(sm.found[0].solver.eval(d2), 4072241450)
        self.assertEqual(sm.found[0].solver.eval(d3), 861621882)


    def test_angr_symbolic_stack(self):
        print("\ntest_angr_symbolic_stack()", "-"*100)
        test_file = os.path.join(TEST_PROGRAMS_BASE, '04_angr_symbolic_stack.elf')
        proj = angr.Project(test_file, use_sim_procedures=True,
                                       load_options={'auto_load_libs': False,
                                                     'arch': "Tricore"})

        self.assertEqual(proj.arch.name, 'TRICORE')

        state = proj.factory.blank_state(addr=0xa100044a)

        user_input0 = claripy.BVS('user_input0', 8*4)
        user_input1 = claripy.BVS('user_input1', 8*4)
        state.memory.store(state.regs.a10 + 8, user_input0)
        state.memory.store(state.regs.a10 + 12, user_input1)

        sm = proj.factory.simulation_manager(state)
        sm.explore(find=0xa1000490)

        print("user_input0:", sm.found[0].solver.eval(user_input0, cast_to=bytes))
        print("user_input1:", sm.found[0].solver.eval(user_input1, cast_to=bytes))


    def test_angr_symbolic_memory(self):
        print("\ntest_angr_symbolic_memory()", "-"*100)
        test_file = os.path.join(TEST_PROGRAMS_BASE, '05_angr_symbolic_memory.elf')
        proj = angr.Project(test_file, use_sim_procedures=True,
                                       load_options={'auto_load_libs': False,
                                                     'arch': "Tricore"})

        self.assertEqual(proj.arch.name, 'TRICORE')

        state = proj.factory.blank_state(addr=0xa10004c4)

        user_input0 = claripy.BVS('user_input0', 8*8)
        user_input1 = claripy.BVS('user_input1', 8*8)
        user_input2 = claripy.BVS('user_input2', 8*8)
        user_input3 = claripy.BVS('user_input3', 8*8)
        state.memory.store(0xa10088f0, user_input0)
        state.memory.store(0xa10088f8, user_input1)
        state.memory.store(0xa1008900, user_input2)
        state.memory.store(0xa1008908, user_input3)
        state.regs.a13 = 0xa10088f0

        sm = proj.factory.simulation_manager(state)
        sm.explore(find=0xa10004e4)

        self.assertEqual(sm.found[0].solver.eval(user_input0, cast_to=bytes), b'HKTDXLYM')
        self.assertEqual(sm.found[0].solver.eval(user_input1, cast_to=bytes), b'HLFIUHII')
        self.assertEqual(sm.found[0].solver.eval(user_input2, cast_to=bytes), b'GBZEJCWI')
        self.assertEqual(sm.found[0].solver.eval(user_input3, cast_to=bytes), b'JNPESTBA')


    def test_angr_symbolic_dynamic_memory(self):
        print("\ntest_angr_symbolic_dynamic_memory()", "-"*100)
        test_file = os.path.join(TEST_PROGRAMS_BASE, '06_angr_symbolic_dynamic_memory.elf')
        proj = angr.Project(test_file, use_sim_procedures=True,
                                       load_options={'auto_load_libs': False,
                                                     'arch': "Tricore"})

        self.assertEqual(proj.arch.name, 'TRICORE')

        state = proj.factory.blank_state(addr=0xa10004f2)

        user_input0 = claripy.BVS('user_input0', 8*8)
        user_input1 = claripy.BVS('user_input1', 8*8)

        state.memory.store(0xa100894c, 0x11111111)
        state.memory.store(0xa1008944, 0x22222222)

        state.memory.store(0x11111111, user_input0)
        state.memory.store(0x22222222, user_input1)

        state.regs.a14 = 0xa100894c
        state.regs.a13 = 0xa1008944

        sm = proj.factory.simulation_manager(state)
        sm.explore(find=0xa100052a, avoid=0xa1000522)

        self.assertEqual(sm.found[0].solver.eval(user_input0, cast_to=bytes), b'GZGVANZN')
        self.assertEqual(sm.found[0].solver.eval(user_input1, cast_to=bytes), b'NNUDCJOI')


    def test_angr_constraints(self):
        print("\ntest_angr_constraints()", "-"*100)
        test_file = os.path.join(TEST_PROGRAMS_BASE, '08_angr_constraints.elf')
        proj = angr.Project(test_file, use_sim_procedures=True,
                                       load_options={'auto_load_libs': False,
                                                     'arch': "Tricore"})

        self.assertEqual(proj.arch.name, 'TRICORE')

        password = claripy.BVS('password', 8*16)

        state = proj.factory.blank_state(addr=0xa10004d6)
        state.memory.store(0xa1008900, state.memory.load(0xa1007b8e, 16))
        state.regs.a15 = 0xa1008910
        state.memory.store(0xa1008910, password)

        for k in password.chop(bits=8):
            state.solver.add(k <= 0x5a)
            state.solver.add(k >= 0x41)

        sm = proj.factory.simulation_manager(state)
        sm.explore(find=0xa100050c, avoid=0xa1000422)

        self.assertEqual(sm.found[0].solver.eval(password, cast_to=bytes), b'MVBVLBBGPKISRMHL')


if __name__ == '__main__':
    unittest.main()
