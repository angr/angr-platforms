import logging
import angr
import claripy

l = logging.getLogger(__name__)


class BFMixin(angr.engines.SuccessorsMixin):
    """
    This is a SimEngine mixin for executing BrainFuck.  Oh yeah, you're not hallucinating.
    """

    def _build_jump_table(self, state):
        jump_table = {}
        jstack = []
        addr = 0
        while True:
            try:
                inst = chr(state.mem_concrete(addr, 1))
            except angr.SimValueError:
                break
            except KeyError:
                break
            if inst == '[':
                jstack.append(addr)
            elif inst == ']':
                try:
                    src = jstack.pop()
                    dest = addr
                    jump_table.update({src: dest})
                    jump_table.update({dest: src})
                except IndexError:
                    raise ValueError("Extra ] at offset %d" % inst)
            addr += 1
        if jstack:
            raise ValueError("Unmatched [s at: " + ",".join(jstack))
        return jump_table

    def resolve_jump(self, state, addr):
        if not hasattr(state.scratch, 'jump_table'):
            state.scratch.jump_table = self._build_jump_table(state)
        try:
            return state.scratch.jump_table[addr]
        except KeyError:
            raise ValueError("There is no entry in the jump table at address %d" % addr)

    #def lift(self, addr=None, clemory=None, insn_bytes=None, size=None, arch=None, **kwargs):

    #    if addr is None:
    #        raise ValueError("addr must be specified.")

    #    if insn_bytes is None:
    #        if clemory is None:
    #            raise ValueError("clemory must be specified if insn_bytes is None.")
    #        insn_bytes = clemory.load(addr, size)
    #    else:
    #        size = len(insn_bytes)

    #    if arch is None:
    #        arch = archinfo.arch_from_id('bf')

    #    irsb = pyvex.lift(insn_bytes, addr, arch, max_bytes=size)
    #    return irsb

    def process_successors(self, successors, **kwargs):
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

        :param successors: The SimSuccessors for this block.  In other words, where the program can go from here, and
        under what circumstances
        :type successors: angr.SimSuccessors
        :param args:
        :param kwargs:
        :return:
        """
        state = self.state
        my_block = state.ip  # The start address of this basic block.  We'll need this later
        while True:
            # Run through instructions, until we hit a branch.
            # Step 0: Fetch the next instruction
            # Because memory can be symbolic, but code in BrainFuck can't,
            # we just ask for a concrete value, and we'll get one.
            try:
                inst = chr(state.mem_concrete(state.ip,1))
            except angr.SimValueError:
                # ...except if it IS symbolic.  That means we ran off the memory.
                # Drop the mic and go home.  We're done here.
                the_end = state.copy()
                successors.add_successor(the_end, state.ip, claripy.true, "Ijk_Exit", add_guard=False, exit_stmt_idx=-1,
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
                oldval = state.memory.load(state.regs.ptr, 1)
                newval = (oldval - 1)
                state.memory.store(state.regs.ptr, newval, 1)
            elif inst == "+":
                # Increment the byte at ptr in memory
                oldval = state.memory.load(state.regs.ptr, 1)
                newval = (oldval + 1)
                state.memory.store(state.regs.ptr, newval, 1)
            elif inst == ".":
                # Syscall: write byte at mem to stdout
                newstate = state.copy()
                newstate.regs.inout = 1  # Set this to 0 to cause a write syscall
                newstate.ip = state.ip + 1
                successors.add_successor(newstate, newstate.ip, claripy.true, "Ijk_Syscall",
                                         add_guard=False, exit_stmt_idx=-1, exit_ins_addr=state.ip, source=my_block)
                # Syscalls, even fake ones like this, end a basic block.
                break
            elif inst == ',':
                # Syscall: read byte from stdin to cell at ptr
                new_state = state.copy()
                new_state.regs.inout = 0  # This must be 0 when we do a syscall to get a read!
                new_state.ip = state.ip + 1
                successors.add_successor(new_state, new_state.ip, claripy.true, "Ijk_Syscall",
                                         add_guard=False, exit_stmt_idx=-1, exit_ins_addr=state.ip, source=my_block)
                # Syscalls, even fake ones like this, end the basic block
                break
            elif inst == '[':
                # Jump to matching ] if value at ptr is 0
                val_at_ptr = state.memory.load(state.regs.ptr, 1)
                # find the ].  This returns None if we don't find it (ran off the end)
                jk = "Ijk_Boring"
                dest = self.resolve_jump(state, state.solver.eval(state.ip))
                taken_state = state.copy()
                taken_state.ip = dest
                not_taken_state = state.copy()
                not_taken_state.ip = state.ip + 1

                successors.add_successor(taken_state, taken_state.ip, val_at_ptr == 0, jk, add_guard=True,
                                         exit_stmt_idx=-1, exit_ins_addr=state.ip, source=my_block)
                successors.add_successor(not_taken_state, not_taken_state.ip, val_at_ptr != 0, "Ijk_Boring",
                                         add_guard=True, exit_stmt_idx=-1, exit_ins_addr=state.ip, source=my_block)
                # This is a conditional, so this basic block is done!
                break
            elif inst == ']':
                # Jump backward to matching [ if value at ptr is non-zero
                val_at_ptr = state.memory.load(state.regs.ptr, 1)
                # find the [, or the beginning.  If we go there, it's over.
                jk = "Ijk_Boring"
                taken_state = state.copy()
                dest = self.resolve_jump(state, state.solver.eval(state.ip))
                taken_state.ip = dest
                not_taken_state = state.copy()
                not_taken_state.ip = state.ip + 1
                successors.add_successor(taken_state, taken_state.ip, val_at_ptr != 0, jk, add_guard=True,
                                         exit_stmt_idx=-1, exit_ins_addr=state.ip, source=my_block)
                successors.add_successor(not_taken_state, not_taken_state.ip, val_at_ptr == 0, "Ijk_Boring",
                                         add_guard=True, exit_stmt_idx=-1, exit_ins_addr=state.ip, source=my_block)
                # This is a conditional, so this basic block is done!
                break
            # Step 3: Increment PC!
            state.ip += 1

        # Step 4: Set this flag to tell the rest of angr that you finished processing the block
        successors.processed = True

        # TODO: HACK: FIXME: this just has to be here. This should not have to be here.
        successors.artifacts['irsb_size'] = state.ip - my_block
        successors.artifacts['irsb'] = None
        successors.artifacts['irsb_direct_next'] = True


class UberEngineWithBF(angr.engines.UberEngine, BFMixin):
    """
    This is a class that "mixes" together the standard symbolic execution stack and the brainfuck interpreter.
    Giving it to angr will do everything we want.
    """
    pass
