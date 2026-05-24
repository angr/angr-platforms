"""Runtime patch to override angr VEX dirty helpers for x86 IN/OUT.

This module performs a best-effort monkeypatch for the runtime dirty-helper
surface. Keeping it in a separate file keeps `__init__` small.
"""

from __future__ import annotations

import sys

import claripy

__all__ = ["apply_patch"]


def _default_in(state, portno, sz):
    try:
        szv = int(sz) if isinstance(sz, int) else int(state.solver.eval(sz))
    except Exception:
        szv = 32
    if szv == 8:
        return claripy.BVV(0xFF, 8), []
    if szv == 16:
        return claripy.BVV(0xFFFF, 16), []
    return claripy.BVV(0xFFFFFFFF, 32), []


def _default_out(state, portno, data, sz):
    return None, []


def apply_patch() -> int:
    try:
        import angr as _angr

        from . import simprocs_io as _simprocs_io

        _angr.SIM_PROCEDURES = getattr(_angr, "SIM_PROCEDURES", {})
        _arch_key = "X86_16"
        if _arch_key not in _angr.SIM_PROCEDURES:
            _angr.SIM_PROCEDURES[_arch_key] = {}
        _angr.SIM_PROCEDURES[_arch_key]["x86g_dirtyhelper_IN"] = _simprocs_io.X86DirtyIN
        _angr.SIM_PROCEDURES[_arch_key]["x86g_dirtyhelper_OUT"] = _simprocs_io.X86DirtyOUT
    except Exception:
        # Best-effort registration; if angr is absent or API differs, continue silently.
        pass

    try:
        # Patch angr's VEX dirty helpers for x86 to return deterministic defaults
        # when no PortIO device is present. This overrides the engine-level helpers
        # that otherwise emit symbolic IN_... values.
        import angr.engines.vex.heavy.dirty as _dirty

        def _patched_x86g_dirtyhelper_IN(state, portno, sz):
            try:
                szv = int(sz) if isinstance(sz, int) else int(state.solver.eval(sz))
            except Exception:
                szv = 32
            if szv == 8:
                return state.solver.BVV(0xFF, 8)
            if szv == 16:
                return state.solver.BVV(0xFFFF, 16)
            return state.solver.BVV(0xFFFFFFFF, 32)

        def _patched_x86g_dirtyhelper_OUT(state, portno, sz, val):
            return None

        _dirty.x86g_dirtyhelper_IN = _patched_x86g_dirtyhelper_IN
        _dirty.x86g_dirtyhelper_OUT = _patched_x86g_dirtyhelper_OUT
    except Exception:
        pass

    patched = 0
    for name, mod in list(sys.modules.items()):
        if not mod:
            continue
        try:
            if hasattr(mod, "x86g_dirtyhelper_IN"):
                setattr(mod, "x86g_dirtyhelper_IN", _default_in)
                patched += 1
            if hasattr(mod, "x86g_dirtyhelper_OUT"):
                setattr(mod, "x86g_dirtyhelper_OUT", _default_out)
                patched += 1
        except Exception:
            continue
    return patched


