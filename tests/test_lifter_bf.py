import os
import unittest
import angr
import archinfo

from angr_platforms.bf import ArchBF, LifterBF


class TestBFLifter(unittest.TestCase):
    def test_lifter_bf(self):
        # import logging
        # logging.getLogger('pyvex').setLevel(logging.DEBUG)
        # logging.basicConfig()
        test1 = b'<>+-[].,'
        test2 = b'<>+-[].,'
        lifter = LifterBF(archinfo.arch_from_id('bf'), 0)
        lifter.lift(data=test1)
        lifter.irsb.pp()

        lifter = LifterBF(ArchBF(), 0)
        lifter.lift(data=test2)
        lifter.irsb.pp()

    def test_hello(self):
        hellobf = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_programs/bf/hello.bf'))
        p = angr.Project(hellobf)
        entry = p.factory.entry_state()
        smgr = p.factory.simulation_manager(entry)
        smgr.explore()
        assert smgr.deadended[0].posix.dumps(1) == b'Hello World!\n'

    def test_1bytecrackme_good(self):
        crackme = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_programs/bf/1bytecrackme-good.bf'))
        bad_states = lambda state: b"-" in state.posix.dumps(1)
        p = angr.Project(crackme)
        entry = p.factory.entry_state(remove_options={angr.options.LAZY_SOLVES})
        smgr = p.factory.simulation_manager(entry)
        smgr.run(until=lambda lsmgr: len(lsmgr.active) == 0)
        smgr.stash(from_stash="deadended", to_stash="bad", filter_func=bad_states)
        assert b"\n" == smgr.deadended[0].posix.dumps(0)


if __name__ == '__main__':
    unittest.main()