from angr.sim_procedure import SimProcedure


class X86DirtyIN(SimProcedure):
    """SimProcedure for x86g_dirtyhelper_IN used by the x86-16 lifter.

    Returns a deterministic default value when no port device is registered.
    Signature (size_bits, port)
    """

    def run(self, size, port=None):
        try:
            # size may be a claripy BV or a Python int
            if hasattr(size, 'concrete') or hasattr(size, 'size'):
                sz = int(self.state.solver.eval(size))
            else:
                sz = int(size)
        except Exception:
            sz = 32

        if sz == 8:
            return self.state.solver.BVV(0xFF, 8)
        if sz == 16:
            return self.state.solver.BVV(0xFFFF, 16)
        return self.state.solver.BVV(0xFFFFFFFF, 32)


class X86DirtyOUT(SimProcedure):
    """SimProcedure stub for x86g_dirtyhelper_OUT used by the x86-16 lifter.

    Signature (size_bits, port, value)
    This is a no-op when no port device is present.
    """

    def run(self, size, port, value):
        return None
