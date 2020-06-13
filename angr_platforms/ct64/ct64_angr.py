import angr
import claripy
import cle
import archinfo
import logging
import struct

from .ct64_engine import UberEngineWithCT64K

l = logging.getLogger('angr.ct64k')

def load_rom(rom):
    return angr.Project(rom, main_opts={'backend': CT64KBlob, 'arch': ArchCT64K(), 'base_addr': 0x1000, 'entry_point': 0x1000}, engine=UberEngineWithCT64K)

class ArchCT64K(archinfo.Arch):
    def __init__(self, endness=archinfo.Endness.BE):
        super(ArchCT64K, self).__init__(endness)

    name = 'CT64K'
    bits = 16
    byte_width = 16
    max_inst_bytes = 3
    ip_offset = 0
    sp_offset = 1
    bp_offset = 2
    initial_sp = 0x300
    sp_diff = 1

    register_names = {
            0: 'ip',
            1: 'sp',
            2: 'bp',
    }
    for i in range(3, 0x10):
        register_names[i] = 'sc%X' % i
    for i in range(0x10, 0x40):
        register_names[i] = 'r%X' % i
    for i in range(0x40, 0x100):
        register_names[i] = 's%X' % i

    registers = {n: (o, 1) for o, n in register_names.items()}

    # don't bother; we overwrite registers with memory anyway
    #default_register_values = [
    #    ( 'sp', 0x300, True, 'global' ),
    #    ( 'bp', 0x300, True, 'global' ),
    #    ( 'ip', 0x1000, True, 'global' )
    #]

class CT64KBlob(cle.backends.blob.Blob):
    def _load(self, file_offset, mem_addr, size):
        self.os = 'ct64k'
        self._binary_stream.seek(file_offset)
        string = self._binary_stream.read(size)
        memdata = list(struct.unpack('H'*(len(string)//2), string))
        self.memory.add_backer(mem_addr - self.linked_base, memdata)
        self._max_addr = max(len(memdata) + mem_addr, self._max_addr)
        self._min_addr = min(mem_addr, self._min_addr)

class SimCT64K(angr.SimOS):
    def __init__(self, project):
        self.peripherals = {
            0x200: (hard_200_rd, hard_200_wr),
            0x201: (hard_201_rd, hard_201_wr),
        }
        super(SimCT64K, self).__init__(project, 'ct64k')

    def configure_project(self):
        pass

    def state_blank(self, addr=None, **kwargs):
        if addr is None:
            addr = 0x1000

        permissions_backer = (True, {(0, 0xffff): 7})
        state = super(SimCT64K, self).state_blank(addr=addr, permissions_backer=permissions_backer, **kwargs)

        state.register_plugin('registers', state.memory)
        state.memory.id = 'reg'

        state.registers.store(0, addr, size=1)
        state.registers.store(1, state.arch.initial_sp, size=1)
        state.registers.store(2, state.arch.initial_sp, size=1)

        state.inspect.b('reg_read', action=self.hard_checker_rd, when=angr.BP_AFTER)
        state.inspect.b('reg_write', action=self.hard_checker_wr, when=angr.BP_AFTER)
        return state

    def state_entry(self, *args, **kwargs):
        state = self.state_blank(*args, **kwargs)
        state.memory.store(3, claripy.BVV(0, (0x200 - 3)*16))
        state.memory.store(0x300, claripy.BVV(0, (0x1000 - 0x300)*16))
        return state

    def _hard_checker(self, state, addr):
        crange = state.solver.And(addr >= 0x200, addr < 0x300)
        if not state.solver.satisfiable(extra_constraints=(crange,)):
            return None

        try:
            addr = state.solver.eval_one(addr)
        except angr.SimSolverError:
            l.warning("Address %s could touch peripherals but is multivalued", addr)
            return None

        try:
            return self.peripherals[addr]
        except KeyError:
            l.error("Touching unmapped peripheral address %#x", addr)
            return None

    def hard_checker_rd(self, state):
        p = self._hard_checker(state, state.inspect.reg_read_offset)
        if p is None:
            return
        state.inspect.reg_read_expr = p[0](state)

    def hard_checker_wr(self, state):
        p = self._hard_checker(state, state.inspect.reg_write_offset)
        if p is None:
            return
        p[1](state, state.inspect.reg_write_expr)

angr.calling_conventions.register_default_cc('CT64K', angr.calling_conventions.SimCCCdecl)
angr.simos.register_simos('ct64k', SimCT64K)

# output
def hard_200_rd(state):
    return state.solver.BVV(0, 16)

def hard_200_wr(state, v):
    state.posix.fd[1].write_data(v)

# input
def hard_201_rd(state):
    r = state.posix.fd[0].read_data(1)[0]
    state.solver.add(r < 0x100)
    return r

def hard_201_wr(state, v): # pylint: disable=unused-argument
    pass
