from __future__ import annotations

import claripy
import networkx
from angr.analyses.reaching_definitions import rd_state as _rd_state
from angr.analyses.typehoon import simple_solver as _typehoon_simple_solver
from angr.analyses.typehoon import translator as _typehoon_translator

try:
    from angr.analyses.typehoon import lifter as _typehoon_lifter
except ImportError:
    _typehoon_lifter = None
from angr.analyses.typehoon.simple_solver import BASE_LATTICES, BottomType, Int, Int16, TopType
from angr.analyses.typehoon.typeconsts import Int16 as TCInt16
from angr.analyses.typehoon.typeconsts import Pointer
from angr.analyses.variable_recovery import variable_recovery_base as _variable_recovery_base
from angr.sim_type import (
    SimTypeBottom,
    SimTypePointer,
)

__all__ = ["apply_x86_16_typehoon_compatibility"]


def apply_x86_16_typehoon_compatibility() -> None:
    _orig_stack_addr_from_offset = _variable_recovery_base.VariableRecoveryStateBase.stack_addr_from_offset

    def _stack_addr_from_offset_8616(self, offset):
        if self.arch.bits == 16:
            return (offset + 0x7FFE) & 0xFFFF
        return _orig_stack_addr_from_offset(self, offset)

    if (
        getattr(_variable_recovery_base.VariableRecoveryStateBase.stack_addr_from_offset, "__name__", "")
        != "_stack_addr_from_offset_8616"
    ):
        _variable_recovery_base.VariableRecoveryStateBase.stack_addr_from_offset = _stack_addr_from_offset_8616

    _orig_initial_stack_pointer = _rd_state.ReachingDefinitionsState._initial_stack_pointer

    def _initial_stack_pointer_8616(self):
        if self.arch.bits == 16:
            return claripy.BVS("stack_base", 16, explicit_name=True)
        return _orig_initial_stack_pointer(self)

    if getattr(_rd_state.ReachingDefinitionsState._initial_stack_pointer, "__name__", "") != "_initial_stack_pointer_8616":
        _rd_state.ReachingDefinitionsState._initial_stack_pointer = _initial_stack_pointer_8616

    class Pointer16(Pointer, TCInt16):
        def __init__(self, basetype=None, name: str | None = None):
            Pointer.__init__(self, basetype, name=name)
            TCInt16.__init__(self, name=name)

        def __repr__(self, memo=None):
            bt = self.basetype.__repr__(memo=memo) if isinstance(self.basetype, TCInt16) else repr(self.basetype)
            name_str = f"{self.name}#" if self.name else ""
            return f"{name_str}ptr16({bt})"

    if not hasattr(_typehoon_simple_solver, "Pointer16"):
        _typehoon_simple_solver.Pointer16 = Pointer16
        _typehoon_simple_solver.Pointer16_ = Pointer16()
        _typehoon_simple_solver.PRIMITIVE_TYPES = set(_typehoon_simple_solver.PRIMITIVE_TYPES) | {
            _typehoon_simple_solver.Pointer16_
        }

    base_lattice_16 = networkx.DiGraph()
    base_lattice_16.add_edge(TopType(), Int())
    base_lattice_16.add_edge(Int(), Int16())
    base_lattice_16.add_edge(Int16(), _typehoon_simple_solver.Pointer16_)
    base_lattice_16.add_edge(_typehoon_simple_solver.Pointer16_, BottomType())
    BASE_LATTICES[16] = base_lattice_16

    def _pointer_class_16(self):
        if self.bits == 16:
            return Pointer16
        if self.bits == 32:
            return _typehoon_simple_solver.Pointer32
        if self.bits == 64:
            return _typehoon_simple_solver.Pointer64
        raise NotImplementedError(f"Unsupported bits {self.bits}")

    _typehoon_simple_solver.SimpleSolver._pointer_class = _pointer_class_16

    _orig_simple_solver_init = _typehoon_simple_solver.SimpleSolver.__init__

    def _simple_solver_init_8616(
        self,
        bits: int,
        constraints,
        typevars,
        constraint_set_degradation_threshold: int = 150,
        stackvar_max_sizes=None,
    ):
        if bits != 16:
            return _orig_simple_solver_init(
                self,
                bits,
                constraints,
                typevars,
                constraint_set_degradation_threshold=constraint_set_degradation_threshold,
                stackvar_max_sizes=stackvar_max_sizes,
            )

        self.bits = bits
        self._constraints = constraints
        self._typevars = typevars
        self.stackvar_max_sizes = stackvar_max_sizes if stackvar_max_sizes is not None else {}
        self._constraint_set_degradation_threshold = constraint_set_degradation_threshold
        self._base_lattice = BASE_LATTICES[bits]
        self._base_lattice_inverted = networkx.DiGraph()
        for src, dst in self._base_lattice.edges:
            self._base_lattice_inverted.add_edge(dst, src)

        self.processed_constraints_count = 0
        self.simplified_constraints_count = 0
        self.eqclass_constraints_count = []

        self._equivalence = _typehoon_simple_solver.defaultdict(dict)
        for func_tv in list(self._constraints):
            if self._constraints[func_tv]:
                self.processed_constraints_count += len(self._constraints[func_tv])
                self.preprocess(func_tv)
                self.simplified_constraints_count += len(self._constraints[func_tv])

        self._repr_tv_to_tvs = _typehoon_simple_solver.defaultdict(set)
        for tv, repr_tv in self._equivalence.items():
            self._repr_tv_to_tvs[repr_tv].add(tv)

        self.solution = {}
        for tv, sol in self._equivalence.items():
            if isinstance(tv, _typehoon_simple_solver.TypeVariable) and isinstance(sol, _typehoon_simple_solver.TypeConstant):
                self.solution[tv] = sol

        self._solution_cache = {}
        self.solve()
        for func_tv in list(self._constraints):
            self._convert_arrays(self._constraints[func_tv])

        for tv, tv_eq in self._equivalence.items():
            if tv not in self.solution and tv_eq in self.solution:
                self.solution[tv] = self.solution[tv_eq]

    if getattr(_typehoon_simple_solver.SimpleSolver.__init__, "__name__", "") != "_simple_solver_init_8616":
        _typehoon_simple_solver.SimpleSolver.__init__ = _simple_solver_init_8616

    def _translate_pointer16(self, tc):
        if isinstance(tc.basetype, _typehoon_translator.typeconsts.BottomType):
            internal = SimTypeBottom(label="void").with_arch(self.arch)
        else:
            internal = self._tc2simtype(tc.basetype)
        return SimTypePointer(internal).with_arch(self.arch)

    def _translate_simtype_pointer_16(self, st):
        base = self._simtype2tc(st.pts_to)
        if self.arch.bits == 16:
            return Pointer16(base)
        if self.arch.bits == 32:
            return _typehoon_translator.typeconsts.Pointer32(base)
        if self.arch.bits == 64:
            return _typehoon_translator.typeconsts.Pointer64(base)
        raise TypeError(f"Unsupported pointer size {self.arch.bits}")

    _typehoon_translator.TypeTranslator._translate_Pointer16 = _translate_pointer16
    _typehoon_translator.TypeTranslator._translate_SimTypePointer = _translate_simtype_pointer_16
    _typehoon_translator.TypeConstHandlers[Pointer16] = _typehoon_translator.TypeTranslator._translate_Pointer16
    _typehoon_translator.SimTypeHandlers[SimTypePointer] = _typehoon_translator.TypeTranslator._translate_SimTypePointer

    if _typehoon_lifter is not None:
        _orig_lifter_init = _typehoon_lifter.TypeLifter.__init__

        def _typelifter_init_16(self, bits: int):
            if bits not in (16, 32, 64):
                raise ValueError("TypeLifter only supports 16-bit, 32-bit, or 64-bit pointers.")
            self.bits = bits
            self.memo = {}

        def _lift_simtype_pointer_16(self, ty):
            if self.bits == 16:
                return Pointer16(self.lift(ty.pts_to))
            if self.bits == 32:
                return _typehoon_lifter.Pointer32(self.lift(ty.pts_to))
            if self.bits == 64:
                return _typehoon_lifter.Pointer64(self.lift(ty.pts_to))
            raise ValueError(f"Unsupported bits {self.bits}.")

        _typehoon_lifter.TypeLifter.__init__ = _typelifter_init_16
        _typehoon_lifter.TypeLifter._lift_SimTypePointer = _lift_simtype_pointer_16


