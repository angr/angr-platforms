#!/usr/bin/env python
import logging
import nose
import os
from angr_platforms.bf import *
import angr

def test_hello():
    hellobf = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_programs/bf/hello.bf'))
    p = angr.Project(hellobf)
    entry = p.factory.entry_state()
    smgr = p.factory.simulation_manager(entry)
    smgr.explore()
    nose.tools.assert_equals(smgr.deadended[0].posix.dumps(1), b'Hello World!\n')

def test_1bytecrackme_good():
    crackme = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_programs/bf/1bytecrackme-good.bf'))
    bad_states = lambda state: b"-" in state.posix.dumps(1)
    p = angr.Project(crackme)
    entry = p.factory.entry_state(remove_options={angr.options.LAZY_SOLVES})
    smgr = p.factory.simulation_manager(entry)
    smgr.run(until=lambda lsmgr: len(lsmgr.active) == 0)
    smgr.stash(from_stash="deadended", to_stash="bad", filter_func=bad_states)
    nose.tools.assert_equals(b"\n", smgr.deadended[0].posix.dumps(0))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    test_hello()
    test_1bytecrackme_good()

