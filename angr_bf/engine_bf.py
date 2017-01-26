import logging
from simuvex.engines import SimEngine
from simuvex import s_options as o
from simuvex.s_state import SimState
from .successors import SimSuccessors
l = logging.getLogger('simuvex.engines.SinEngineBF')


class SimEngineBF(SimEngine):
    """
    This is a SimEngine for executing BrainFuck.  Oh yeah, you're not hallucinating.
    :ivar callable check_failed: A callback that is called after _check() returns False.
    """

    def __init__(self, check_failed=None):
        self._check_failed = check_failed
        self.prog = prog

    def self._process(new_state, successors, *args, **kwargs):
        """
        :param state:
        :type state: SimState
        :param args:
        :param kwargs:
        :return:
        """

        ip =
        for inst in self.prog[ip:]
            # Step 0: Fetch
            inst = ""
            # Step 1: If it's a....
            if inst == '>':
                # Increment ptr
                pass
            elif inst == "<":
                # Decrement ptr
                pass
            elif inst == "-":
                # Decrement the byte at ptr in memory
                pass
            elif inst == "+":
                # Increment the byte at ptr in memory
                pass
            elif inst == ".":
                # Syscall: write byte at mem to stdout
                pass
            elif inst == ',':
                # Syscall: Write byte at mem to stdin
                pass
            elif inst == '[':
                # Jump to matching ] if value at ptr is 0
                break
            elif inst == ']':
                # Jump backward to matching [ if value at ptr is non-zero
                break

        successors = SimSuccessors(addr, state)
        return successors

    def _check(self, state, *args, **kwargs):
        """
        Check if this engine can be used for execution on the current state. A callback `check_failure` is called upon
        failed checks. Note that the execution can still fail even if check() returns True.

        :param simuvex.SimState state: The state with which to execute.
        :param args:                   Positional arguments that will be passed to process().
        :param kwargs:                 Keyword arguments that will be passed to process().
        :return:                       True if the state can be handled by the current engine, False otherwise.
        """
        return True
