import os
import unittest
import angr
import pyvex

from angr_platforms.bf import UberEngineWithBF


class TestBFEngine(unittest.TestCase):
    def test_hello(self):
        lifters = pyvex.lifting.lifters['BF']
        pyvex.lifting.lifters['BF'] = []
        try:
            hellobf = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_programs/bf/hello.bf'))
            p = angr.Project(hellobf, engine=UberEngineWithBF)
            entry = p.factory.entry_state()
            smgr = p.factory.simulation_manager(entry)
            smgr.explore()
            assert smgr.deadended[0].posix.dumps(1) == b'Hello World!\n'
        finally:
            # It's designed to only have "finally" block, no "except" blocks.
            # We want to make sure lifters['BF'] is restored after the test,
            # so that other code won't complain about it, while still being
            # able to detect any test failure in the "try" block
            pyvex.lifting.lifters['BF'] = lifters

    def test_1bytecrackme_good(self):
        lifters = pyvex.lifting.lifters['BF']
        pyvex.lifting.lifters['BF'] = []
        try:
            crackme = str(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                '../test_programs/bf/1bytecrackme-good.bf'))
            bad_states = lambda state: b"-" in state.posix.dumps(1)
            p = angr.Project(crackme, engine=UberEngineWithBF)
            p.arch.vex_arch = None  # force test with engine
            entry = p.factory.entry_state(remove_options={angr.options.LAZY_SOLVES})
            smgr = p.factory.simulation_manager(entry)
            smgr.run(until=lambda lsmgr: len(lsmgr.active) == 0)
            smgr.stash(from_stash="deadended", to_stash="bad", filter_func=bad_states)
            assert b"\n" == smgr.deadended[0].posix.dumps(0)
        finally:
            # "finally" block only, no "except" blocks. See `test_hello()`
            pyvex.lifting.lifters['BF'] = lifters


if __name__ == '__main__':
    unittest.main()