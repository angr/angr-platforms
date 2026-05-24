from __future__ import annotations

import logging

from angr import ailment
from angr.analyses.decompiler.return_maker import ReturnMaker
from angr.calling_conventions import SimComboArg, SimRegArg
from angr.sim_type import SimTypeBottom

__all__ = [
    "apply_x86_16_decompiler_return_compatibility",
    "describe_x86_16_decompiler_return_compatibility",
]

l = logging.getLogger(__name__)


def describe_x86_16_decompiler_return_compatibility():
    return ("ReturnMaker._handle_Return: SimComboArg support",)


def _make_return_register_expr_8616(self, stmt, reg_arg: SimRegArg):
    reg = self.arch.registers[reg_arg.reg_name]
    return ailment.Expr.Register(
        self._next_atom(),
        None,
        reg[0],
        reg_arg.size * self.arch.byte_width,
        reg_name=self.arch.translate_register_name(reg[0], reg_arg.size),
        ins_addr=stmt.tags["ins_addr"],
    )


def _make_return_combo_expr_8616(self, stmt, ret_val: SimComboArg):
    parts = []
    for loc in reversed(ret_val.locations):
        if not isinstance(loc, SimRegArg):
            return None
        parts.append(_make_return_register_expr_8616(self, stmt, loc))

    if not parts:
        return None

    expr = parts[0]
    for part in parts[1:]:
        expr = ailment.Expr.BinaryOp(
            self._next_atom(),
            "Concat",
            [expr, part],
            bits=getattr(expr, "bits", 0) + getattr(part, "bits", 0),
            ins_addr=stmt.tags["ins_addr"],
        )
    return expr


def apply_x86_16_decompiler_return_compatibility() -> None:
    _orig_handle_return = ReturnMaker._handle_Return

    def _handle_Return_8616(self, stmt_idx: int, stmt: ailment.Stmt.Return, block):  # pylint:disable=unused-argument
        if (
            block is not None
            and not stmt.ret_exprs
            and self.function.prototype is not None
            and self.function.prototype.returnty is not None
            and type(self.function.prototype.returnty) is not SimTypeBottom
        ):
            ret_val = self.function.calling_convention.return_val(self.function.prototype.returnty)
            ret_expr = None
            if isinstance(ret_val, SimRegArg):
                ret_expr = _make_return_register_expr_8616(self, stmt, ret_val)
            elif isinstance(ret_val, SimComboArg):
                ret_expr = _make_return_combo_expr_8616(self, stmt, ret_val)

            if ret_expr is None:
                return _orig_handle_return(self, stmt, block)

            new_stmt = stmt.copy()
            new_stmt.ret_exprs.append(ret_expr)

            new_statements = block.statements[::]
            new_statements[stmt_idx] = new_stmt
            self._new_block = block.copy(statements=new_statements)
            return None

        return _orig_handle_return(self, stmt, block)

    if getattr(ReturnMaker._handle_Return, "__name__", "") != "_handle_Return_8616":
        ReturnMaker._handle_Return = _handle_Return_8616



