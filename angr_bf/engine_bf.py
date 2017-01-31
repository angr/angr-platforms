import logging
from simuvex import SimValueError
from simuvex.engines import SimEngine
from simuvex import s_options as o
from simuvex.s_state import SimState
from simuvex.engines.successors import SimSuccessors
import claripy

l = logging.getLogger('simuvex.engines.SinEngineBF')


class SimEngineBF(SimEngine):
    """
    This is a SimEngine for executing BrainFuck.  Oh yeah, you're not hallucinating.
    :ivar callable check_failed: A callback that is called after _check() returns False.
    """

    def _process(self, state, successors, *args, **kwargs):
        """
        This function executes one "basic block" of BrainFuck.

        As input, we get the current state, which contains the value of the two registers (ip and ptr),
        and the program's code and data memory.
        We then perform a series of symbolic actions on this state, until the block ends, at which point we define
        its "successors" -- where execution can possibly go from here.
        The basic block ends when:
            1) A branch is reached.  The successors are the next instruction if the branch is taken,
            and the instruction if it is not.
            2) Input and Output.  We're modeling I/O as a system call, so this ends the block.
            3) ip points somewhere outside the program's memory.  In Brainfuck, this is the simple halting case.

        :param state:
        :type state: SimState
        :param args:
        :param kwargs:
        :return:
        """
        my_block = state.ip  # The start address of this basic block.  We'll need this later
        successors = SimSuccessors(my_block, state)  # All the places we can go from this block.
        while True:
            # Run through instructions, until we hit a branch.
            # Step 0: Fetch the next instruction
            # Because memory can be symbolic, but code in BrainFuck can't,
            # we just ask for a concrete value, and we'll get one.
            try:
                inst = chr(state.mem_concrete(state.ip,1))
            except SimValueError:
                # ...except if it IS symbolic.  That means we ran off the memory.
                # Drop the mic and go home.  We're done here.
                the_end = state.copy()
                successors.add_successor(the_end, state.ip, True, "Ijk_Exit", add_guard=True, exit_stmt_idx=-1,
                                         exit_ins_addr=state.ip, source=my_block)
                break
            # Step 1: Decode.  If it's a....
            if inst == '>':
                # Increment ptr
                state.regs.ptr = (state.regs.ptr + 1)
            elif inst == "<":
                state.regs.ptr = (state.regs.ptr - 1)
            elif inst == "-":
                # Decrement the byte at ptr in memory
                # NOTE: We're doing the "wrap-around" variation of BF
                state.memory.store(state.regs.ptr, (state.memory.load(state.regs.ptr) - 1) % 256, 1)
            elif inst == "+":
                # Increment the byte at ptr in memory
                state.memory.store(state.regs.ptr, (state.memory.load(state.regs.ptr) + 1) % 256, 1)
            elif inst == ".":
                # Syscall: write byte at mem to stdout
                newstate = state.copy()
                val_to_write = state.memory.load(state.regs.ptr)
                # TODO: Something about the syscall register 'inout'
                newstate.ip = state.ip + 1
                successors.add_successor(new_state, not_taken_state.ip, val_at_ptr != 0, "Ijk_Syscall",
                         add_guard=True, exit_stmt_idx=-1, exit_ins_addr=state.ip, source=my_block)
                break
            elif inst == ',':
                # Syscall: Write byte from stdin to cell at ptr
                newstate = state.copy()
                val_to_write = state.memory.load(state.regs.ptr)
                # TODO: Something about the syscall register 'inout'
                newstate.ip = state.ip + 1
                successors.add_successor(new_state, not_taken_state.ip, val_at_ptr != 0, "Ijk_Syscall",
                         add_guard=True, exit_stmt_idx=-1, exit_ins_addr=state.ip, source=my_block)
                break
            elif inst == '[':
                # Jump to matching ] if value at ptr is 0
                val_at_ptr = state.memory.load(state.regs.ptr, 1)
                # find the ].  This returns None if we don't find it (ran off the end)
                dest = state.mem.find(state.ip, ']', max_symbolic_bytes=0, default=None)
                taken_state = state.copy()
                taken_state.ip = dest
                not_taken_state = state.copy()
                not_taken_state.ip = state.ip + 1
                if not dest:
                    jk = "Ijk_Exit"
                else:
                    jk = "Ijk_Boring"
                successors.add_successor(taken_state, taken_state.ip, val_at_ptr == 0, jk, add_guard=True,
                                         exit_stmt_idx=-1, exit_ins_addr=state.ip, source=my_block)
                successors.add_successor(not_taken_state, not_taken_state.ip, val_at_ptr != 0, "Ijk_Boring",
                                         add_guard=True, exit_stmt_idx=-1, exit_ins_addr=state.ip, source=my_block)
            elif inst == ']':
                # Jump backward to matching [ if value at ptr is non-zero
                val_at_ptr = state.memory.load(state.regs.ptr, 1)
                # find the [, or the beginning.  If we go there, it's over.
                offset = -1
                while state.ip + offset > 0:
                    cell = chr(state.memory.load(state.ip + offset, 1))
                    if cell == "[":
                        break
                    offset -= 1
                taken_state = state.copy()
                taken_state.ip = state.ip + offset
                not_taken_state = state.copy()
                not_taken_state.ip = state.ip + 1
                successors.add_successor(taken_state, taken_state.ip, val_at_ptr != 0, "Ijk_Boring", add_guard=True,
                                         exit_stmt_idx=-1, exit_ins_addr=state.ip, source=my_block)
                successors.add_successor(not_taken_state, not_taken_state.ip, val_at_ptr == 0, "Ijk_Boring",
                                         add_guard=True, exit_stmt_idx=-1, exit_ins_addr=state.ip, source=my_block)
            # Step 3: Increment PC!
            state.ip += 1
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
        return not state.arch.name == 'BF'

