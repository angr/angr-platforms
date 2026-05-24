from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, IntEnum, auto
import re

from .condition_ir import build_condition_ir_8616, harmonize_condition_args_8616, normalize_condition_op_8616
from .core import IRCondition, IRValue
from .regs import register_name_from_offset

__all__ = [
    "build_condition_from_binop",
    "expr_to_condition",
]


class _FlagBit(IntEnum):
    CF = 0x0001
    ZF = 0x0040
    SF = 0x0080
    OF = 0x0800


class _FlagPredicateKind(Enum):
    BIT_SET = auto()
    BIT_CLEAR = auto()
    BITS_EQUAL = auto()
    BITS_NOT_EQUAL = auto()
    AND = auto()
    OR = auto()


@dataclass(frozen=True, slots=True)
class _FlagPredicate:
    kind: _FlagPredicateKind
    bit: _FlagBit | None = None
    left_bit: _FlagBit | None = None
    right_bit: _FlagBit | None = None
    left: _FlagPredicate | None = None
    right: _FlagPredicate | None = None


_INVERT_CONDITION_OPS = {
    "eq": "ne",
    "ne": "eq",
    "zero": "nonzero",
    "nonzero": "zero",
    "ult": "uge",
    "uge": "ult",
    "ule": "ugt",
    "ugt": "ule",
    "slt": "sge",
    "sge": "slt",
    "sle": "sgt",
    "sgt": "sle",
}


def _zero_fold(cond_op: str, left: IRValue, right: IRValue) -> IRCondition | None:
    if cond_op not in {"eq", "ne"}:
        return None
    if right.const == 0:
        return build_condition_ir_8616("zero" if cond_op == "eq" else "nonzero", left, expr=("zero_fold",))
    if left.const == 0:
        return build_condition_ir_8616("zero" if cond_op == "eq" else "nonzero", right, expr=("zero_fold",))
    return None


def _compare_size_bytes(op: str) -> int:
    match = re.search(r"(\d+)(?:[SU])?$", op)
    if match is None:
        return 0
    bits = int(match.group(1))
    return 0 if bits <= 0 else max(1, bits // 8)


def build_condition_from_binop(op: str, left: IRValue, right: IRValue) -> IRCondition | None:
    folded = op.lower()
    left, right = harmonize_condition_args_8616(left, right, size=_compare_size_bytes(op))
    variants = {
        "cmpeq": "eq",
        "cmpne": "ne",
        "cmplt": "lt",
        "cmple": "le",
        "cmpgt": "gt",
        "cmpge": "ge",
        "cascmp": "eq",
    }
    for needle, cond_op in variants.items():
        if needle not in folded:
            continue
        zero_fold = _zero_fold(cond_op, left, right)
        if zero_fold is not None:
            return zero_fold
        if folded.endswith("s"):
            return build_condition_ir_8616(normalize_condition_op_8616(f"s{cond_op}"), left, right, expr=(op,))
        if folded.endswith("u"):
            return build_condition_ir_8616(normalize_condition_op_8616(f"u{cond_op}"), left, right, expr=(op,))
        return build_condition_ir_8616(normalize_condition_op_8616(cond_op), left, right, expr=(op,))
    return None


def _nonzero_condition(value: IRValue, *, source: str) -> IRCondition:
    return build_condition_ir_8616("nonzero", value, expr=(source,))


def _masked_nonzero_condition(left: IRValue, right: IRValue, *, source: str) -> IRCondition:
    return IRCondition(op="masked_nonzero", args=(left, right), expr=(source,))


def _const_value(expr) -> int | None:
    con = getattr(expr, "con", None)
    if con is None:
        return None
    value = getattr(con, "value", None)
    return None if value is None else int(value)


def _invert_condition(cond: IRCondition) -> IRCondition:
    inverted_op = _INVERT_CONDITION_OPS.get(cond.op)
    if inverted_op is not None:
        return build_condition_ir_8616(inverted_op, *cond.args, expr=cond.expr)
    if cond.op == "not" and len(cond.args) == 1 and isinstance(cond.args[0], IRCondition):
        return cond.args[0]
    if cond.op == "and" and len(cond.args) == 2 and all(isinstance(arg, IRCondition) for arg in cond.args):
        return build_condition_ir_8616(
            "or",
            _invert_condition(cond.args[0]),
            _invert_condition(cond.args[1]),
            expr=cond.expr,
        )
    if cond.op == "or" and len(cond.args) == 2 and all(isinstance(arg, IRCondition) for arg in cond.args):
        return build_condition_ir_8616(
            "and",
            _invert_condition(cond.args[0]),
            _invert_condition(cond.args[1]),
            expr=cond.expr,
        )
    return build_condition_ir_8616("not", cond, expr=cond.expr)


def _resolve_tmp_expr(expr, tmp_exprs: dict[int, object] | None, seen: set[int] | None = None):
    if getattr(expr, "tag", "") != "Iex_RdTmp" or tmp_exprs is None:
        return expr
    tmp_id = int(getattr(expr, "tmp"))
    if seen is None:
        seen = set()
    if tmp_id in seen:
        return expr
    resolved = tmp_exprs.get(tmp_id)
    if resolved is None:
        return expr
    seen.add(tmp_id)
    return _resolve_tmp_expr(resolved, tmp_exprs, seen)


def _is_flags_expr(expr, tmp_exprs: dict[int, object] | None) -> bool:
    resolved = _resolve_tmp_expr(expr, tmp_exprs)
    tag = getattr(resolved, "tag", "")
    if tag == "Iex_Get":
        return register_name_from_offset(int(getattr(resolved, "offset", -1))) == "flags"
    if tag == "Iex_Unop":
        args = tuple(getattr(resolved, "args", ()) or ())
        return bool(args) and _is_flags_expr(args[0], tmp_exprs)
    return False


def _flag_bit_from_mask(mask: int | None) -> _FlagBit | None:
    if mask is None:
        return None
    try:
        return _FlagBit(int(mask))
    except ValueError:
        return None


def _extract_flag_bit_expr(expr, tmp_exprs: dict[int, object] | None) -> _FlagBit | None:
    resolved = _resolve_tmp_expr(expr, tmp_exprs)
    if getattr(resolved, "tag", "") != "Iex_Binop":
        return None
    op = str(getattr(resolved, "op", "")).lower()
    if "and" not in op:
        return None
    args = tuple(getattr(resolved, "args", ()) or ())
    if len(args) != 2:
        return None
    left, right = args
    if _is_flags_expr(left, tmp_exprs):
        return _flag_bit_from_mask(_const_value(_resolve_tmp_expr(right, tmp_exprs)))
    if _is_flags_expr(right, tmp_exprs):
        return _flag_bit_from_mask(_const_value(_resolve_tmp_expr(left, tmp_exprs)))
    return None


def _extract_boolean_flag_test(expr, tmp_exprs: dict[int, object] | None) -> tuple[_FlagBit, bool] | None:
    resolved = _resolve_tmp_expr(expr, tmp_exprs)
    if getattr(resolved, "tag", "") != "Iex_Binop":
        return None
    op = str(getattr(resolved, "op", "")).lower()
    args = tuple(getattr(resolved, "args", ()) or ())
    if len(args) != 2:
        return None
    left, right = args
    left_bit = _extract_flag_bit_expr(left, tmp_exprs)
    right_bit = _extract_flag_bit_expr(right, tmp_exprs)
    left_const = _const_value(_resolve_tmp_expr(left, tmp_exprs))
    right_const = _const_value(_resolve_tmp_expr(right, tmp_exprs))
    if left_bit is not None and right_const == 0:
        return left_bit, "cmpne" in op
    if right_bit is not None and left_const == 0:
        return right_bit, "cmpne" in op
    return None


def _extract_masked_flag_pair_test(
    lhs,
    rhs,
    tmp_exprs: dict[int, object] | None,
) -> tuple[_FlagBit, _FlagBit] | None:
    left_bit = _extract_flag_bit_expr(lhs, tmp_exprs)
    right_bit = _extract_flag_bit_expr(rhs, tmp_exprs)
    if left_bit is None or right_bit is None:
        return None
    return left_bit, right_bit


def _invert_flag_predicate_8616(pred: _FlagPredicate) -> _FlagPredicate | None:
    if pred.kind == _FlagPredicateKind.BIT_SET:
        return _FlagPredicate(_FlagPredicateKind.BIT_CLEAR, bit=pred.bit)
    if pred.kind == _FlagPredicateKind.BIT_CLEAR:
        return _FlagPredicate(_FlagPredicateKind.BIT_SET, bit=pred.bit)
    if pred.kind == _FlagPredicateKind.BITS_EQUAL:
        return _FlagPredicate(
            _FlagPredicateKind.BITS_NOT_EQUAL,
            left_bit=pred.left_bit,
            right_bit=pred.right_bit,
        )
    if pred.kind == _FlagPredicateKind.BITS_NOT_EQUAL:
        return _FlagPredicate(
            _FlagPredicateKind.BITS_EQUAL,
            left_bit=pred.left_bit,
            right_bit=pred.right_bit,
        )
    if pred.kind == _FlagPredicateKind.AND and pred.left is not None and pred.right is not None:
        left_pred = _invert_flag_predicate_8616(pred.left)
        right_pred = _invert_flag_predicate_8616(pred.right)
        if left_pred is None or right_pred is None:
            return None
        return _FlagPredicate(_FlagPredicateKind.OR, left=left_pred, right=right_pred)
    if pred.kind == _FlagPredicateKind.OR and pred.left is not None and pred.right is not None:
        left_pred = _invert_flag_predicate_8616(pred.left)
        right_pred = _invert_flag_predicate_8616(pred.right)
        if left_pred is None or right_pred is None:
            return None
        return _FlagPredicate(_FlagPredicateKind.AND, left=left_pred, right=right_pred)
    return None


def _flag_predicate_from_expr(expr, tmp_exprs: dict[int, object] | None) -> _FlagPredicate | None:
    resolved = _resolve_tmp_expr(expr, tmp_exprs)
    tag = getattr(resolved, "tag", "")
    if tag == "Iex_Unop":
        op = str(getattr(resolved, "op", "")).lower()
        args = tuple(getattr(resolved, "args", ()) or ())
        if len(args) != 1:
            return None
        if "not" not in op:
            return None
        inner = _flag_predicate_from_expr(args[0], tmp_exprs)
        if inner is None:
            return None
        return _invert_flag_predicate_8616(inner)
    if tag == "Iex_Binop":
        op = str(getattr(resolved, "op", "")).lower()
        args = tuple(getattr(resolved, "args", ()) or ())
        if len(args) != 2:
            return None
        left, right = args
        flag_test = _extract_boolean_flag_test(resolved, tmp_exprs)
        if flag_test is not None:
            bit, is_set = flag_test
            return _FlagPredicate(_FlagPredicateKind.BIT_SET if is_set else _FlagPredicateKind.BIT_CLEAR, bit=bit)
        if "and" in op:
            left_pred = _flag_predicate_from_expr(left, tmp_exprs)
            right_pred = _flag_predicate_from_expr(right, tmp_exprs)
            if left_pred is not None and right_pred is not None:
                return _FlagPredicate(_FlagPredicateKind.AND, left=left_pred, right=right_pred)
        if "or" in op:
            left_pred = _flag_predicate_from_expr(left, tmp_exprs)
            right_pred = _flag_predicate_from_expr(right, tmp_exprs)
            if left_pred is not None and right_pred is not None:
                return _FlagPredicate(_FlagPredicateKind.OR, left=left_pred, right=right_pred)
        if "cmpeq" in op or "cmpne" in op:
            left_test = _extract_boolean_flag_test(left, tmp_exprs)
            right_test = _extract_boolean_flag_test(right, tmp_exprs)
            if left_test is not None and right_test is not None:
                left_bit, left_set = left_test
                right_bit, right_set = right_test
                same_truth = left_set == right_set
                if "cmpeq" in op:
                    return _FlagPredicate(
                        _FlagPredicateKind.BITS_EQUAL if same_truth else _FlagPredicateKind.BITS_NOT_EQUAL,
                        left_bit=left_bit,
                        right_bit=right_bit,
                    )
                return _FlagPredicate(
                    _FlagPredicateKind.BITS_NOT_EQUAL if same_truth else _FlagPredicateKind.BITS_EQUAL,
                    left_bit=left_bit,
                    right_bit=right_bit,
                )

            masked_bits = _extract_masked_flag_pair_test(left, right, tmp_exprs)
            if masked_bits is None:
                return None
            left_bit, right_bit = masked_bits
            if "cmpeq" in op:
                return _FlagPredicate(
                    _FlagPredicateKind.BITS_EQUAL,
                    left_bit=left_bit,
                    right_bit=right_bit,
                )
            return _FlagPredicate(
                _FlagPredicateKind.BITS_NOT_EQUAL,
                left_bit=left_bit,
                right_bit=right_bit,
            )
    return None


def _looks_like_flag_compare(cond: IRCondition) -> bool:
    for arg in cond.args:
        if not isinstance(arg, IRValue):
            continue
        if arg.space.name == "REG" and arg.name == "flags":
            return True
        if (arg.name or "").startswith("mask:flags"):
            return True
    return False


def _latest_nonflag_compare(conditions: dict[int, IRCondition]) -> IRCondition | None:
    for cond in reversed(tuple(conditions.values())):
        if cond.op not in {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"}:
            continue
        if len(cond.args) != 2:
            continue
        if _looks_like_flag_compare(cond):
            continue
        return cond
    return None


def _condition_op_from_flag_predicate(pred: _FlagPredicate) -> str | None:
    if pred.kind == _FlagPredicateKind.BIT_SET and pred.bit == _FlagBit.ZF:
        return "eq"
    if pred.kind == _FlagPredicateKind.BIT_CLEAR and pred.bit == _FlagBit.ZF:
        return "ne"
    if pred.kind == _FlagPredicateKind.BIT_SET and pred.bit == _FlagBit.CF:
        return "ult"
    if pred.kind == _FlagPredicateKind.BIT_CLEAR and pred.bit == _FlagBit.CF:
        return "uge"
    if pred.kind == _FlagPredicateKind.BITS_NOT_EQUAL and {pred.left_bit, pred.right_bit} == {_FlagBit.SF, _FlagBit.OF}:
        return "slt"
    if pred.kind == _FlagPredicateKind.BITS_EQUAL and {pred.left_bit, pred.right_bit} == {_FlagBit.SF, _FlagBit.OF}:
        return "sge"
    if pred.kind == _FlagPredicateKind.OR and pred.left is not None and pred.right is not None:
        if {
            (pred.left.kind, pred.left.bit),
            (pred.right.kind, pred.right.bit),
        } == {
            (_FlagPredicateKind.BIT_SET, _FlagBit.CF),
            (_FlagPredicateKind.BIT_SET, _FlagBit.ZF),
        }:
            return "ule"
        if {
            pred.left.kind,
            pred.right.kind,
        } == {_FlagPredicateKind.BIT_SET, _FlagPredicateKind.BITS_NOT_EQUAL}:
            bit_pred = pred.left if pred.left.kind == _FlagPredicateKind.BIT_SET else pred.right
            cmp_pred = pred.right if bit_pred is pred.left else pred.left
            if bit_pred.bit == _FlagBit.ZF and {cmp_pred.left_bit, cmp_pred.right_bit} == {_FlagBit.SF, _FlagBit.OF}:
                return "sle"
    if pred.kind == _FlagPredicateKind.AND and pred.left is not None and pred.right is not None:
        if {
            (pred.left.kind, pred.left.bit),
            (pred.right.kind, pred.right.bit),
        } == {
            (_FlagPredicateKind.BIT_CLEAR, _FlagBit.CF),
            (_FlagPredicateKind.BIT_CLEAR, _FlagBit.ZF),
        }:
            return "ugt"
        if {
            pred.left.kind,
            pred.right.kind,
        } == {_FlagPredicateKind.BIT_CLEAR, _FlagPredicateKind.BITS_EQUAL}:
            bit_pred = pred.left if pred.left.kind == _FlagPredicateKind.BIT_CLEAR else pred.right
            cmp_pred = pred.right if bit_pred is pred.left else pred.left
            if bit_pred.bit == _FlagBit.ZF and {cmp_pred.left_bit, cmp_pred.right_bit} == {_FlagBit.SF, _FlagBit.OF}:
                return "sgt"
    return None


def _flag_formula_condition(expr, conditions, tmp_exprs: dict[int, object] | None) -> IRCondition | None:
    pred = _flag_predicate_from_expr(expr, tmp_exprs)
    if pred is None:
        return None
    cond_op = _condition_op_from_flag_predicate(pred)
    if cond_op is None:
        return None
    compare = _latest_nonflag_compare(conditions)
    if compare is None:
        return None
    lhs, rhs = compare.args
    return build_condition_ir_8616(cond_op, lhs, rhs, expr=("flag_jcc_formula", cond_op))


def _try_expr_to_condition(expr, tmps, conditions, *, expr_to_value: Callable, tmp_exprs: dict[int, object] | None = None) -> IRCondition | None:
    tag = getattr(expr, "tag", "")
    if tag == "Iex_RdTmp":
        tmp_id = int(getattr(expr, "tmp"))
        cond = conditions.get(tmp_id)
        if cond is not None:
            return cond
        if tmp_exprs is not None and tmp_id in tmp_exprs:
            return _try_expr_to_condition(tmp_exprs[tmp_id], tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs)
        return None
    if tag == "Iex_Binop":
        formula_cond = _flag_formula_condition(expr, conditions, tmp_exprs)
        if formula_cond is not None:
            return formula_cond
        op = str(getattr(expr, "op", ""))
        args = tuple(getattr(expr, "args", ()) or ())
        if len(args) != 2:
            return None
        lowered = op.lower()
        if "and" in lowered:
            return _logical_condition("and", args[0], args[1], tmps, conditions, expr_to_value=expr_to_value, source=op, tmp_exprs=tmp_exprs)
        if "or" in lowered:
            return _logical_condition("or", args[0], args[1], tmps, conditions, expr_to_value=expr_to_value, source=op, tmp_exprs=tmp_exprs)
        left = expr_to_value(args[0], tmps, conditions)
        right = expr_to_value(args[1], tmps, conditions)
        return build_condition_from_binop(op, left, right)
    if tag == "Iex_ITE":
        cond_expr = getattr(expr, "cond", None)
        iftrue = getattr(expr, "iftrue", None)
        iffalse = getattr(expr, "iffalse", None)
        cond = _try_expr_to_condition(cond_expr, tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs)
        if cond is None:
            return None
        iftrue_const = _const_value(iftrue)
        iffalse_const = _const_value(iffalse)
        if (iftrue_const, iffalse_const) == (1, 0):
            return cond
        if (iftrue_const, iffalse_const) == (0, 1):
            return _invert_condition(cond)
    return None


def _logical_condition(op: str, lhs, rhs, tmps, conditions, *, expr_to_value: Callable, source: str, tmp_exprs: dict[int, object] | None = None) -> IRCondition | None:
    lhs_cond = _try_expr_to_condition(lhs, tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs)
    rhs_cond = _try_expr_to_condition(rhs, tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs)
    if lhs_cond is None or rhs_cond is None:
        return None
    return build_condition_ir_8616(op, lhs_cond, rhs_cond, expr=(source,))


def expr_to_condition(expr, tmps, conditions, *, expr_to_value: Callable, tmp_exprs: dict[int, object] | None = None) -> IRCondition:
    tag = getattr(expr, "tag", "")
    if tag == "Iex_RdTmp":
        tmp_id = int(getattr(expr, "tmp"))
        if tmp_id in conditions:
            return conditions[tmp_id]
        return _nonzero_condition(expr_to_value(expr, tmps, conditions), source=f"rdtmp:{tmp_id}")
    if tag == "Iex_Binop":
        op = str(getattr(expr, "op", ""))
        args = tuple(getattr(expr, "args", ()) or ())
        if len(args) == 2:
            formula_cond = _flag_formula_condition(expr, conditions, tmp_exprs)
            if formula_cond is not None:
                return formula_cond
            left = expr_to_value(args[0], tmps, conditions)
            right = expr_to_value(args[1], tmps, conditions)
            cond = build_condition_from_binop(op, left, right)
            if cond is not None:
                return cond
            logical = _try_expr_to_condition(expr, tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs)
            if logical is not None:
                return logical
            if "And" in op:
                return _masked_nonzero_condition(left, right, source=op)
    if tag == "Iex_ITE":
        cond = _try_expr_to_condition(expr, tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs)
        if cond is not None:
            return cond
    return _nonzero_condition(expr_to_value(expr, tmps, conditions), source=tag or "expr")
