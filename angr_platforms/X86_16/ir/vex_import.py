from __future__ import annotations

from typing import Any

from .core import (
    AddressStatus,
    IRAddress,
    IRAtom,
    IRBlock,
    IRCondition,
    IRFunctionArtifact,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from .vex_addressing import block_segment_hints, expr_to_address
from .vex_condition_lifting import build_condition_from_binop, expr_to_condition
from .regs import register_name_from_offset
from .ssa import build_x86_16_block_local_ssa
from .ssa_function import build_x86_16_function_ssa
from ..analysis.alias import storage_of
from ..analysis.stack_frame_ir import build_x86_16_ir_frame_access_artifact

__all__ = [
    "apply_x86_16_vex_ir_artifact",
    "build_x86_16_ir_function_artifact",
    "build_x86_16_ir_function_artifact_summary",
]


def _const(expr) -> int | None:
    con = getattr(expr, "con", None)
    return None if con is None else int(getattr(con, "value", 0))


def _int_size(expr, default: int = 2) -> int:
    size = getattr(getattr(expr, "result_size", None), "value", None)
    if size is None:
        size = getattr(expr, "ty", None)
    try:
        return int(size or default)
    except Exception:  # noqa: BLE001
        return default


def _expr_to_value(expr, tmps: dict[int, IRValue], conditions: dict[int, IRCondition]) -> IRValue:
    tag = getattr(expr, "tag", "")
    if tag == "Iex_RdTmp":
        tmp_id = int(getattr(expr, "tmp"))
        if tmp_id in tmps:
            return tmps[tmp_id]
        if tmp_id in conditions:
            return IRValue(MemSpace.TMP, name=f"cond_t{tmp_id}", size=1, expr=("condition_tmp",))
        return IRValue(MemSpace.TMP, name=f"t{tmp_id}")
    if tag == "Iex_Get":
        name = register_name_from_offset(int(getattr(expr, "offset", -1)))
        return IRValue(MemSpace.REG, name=name, size=_int_size(expr))
    if tag == "Iex_Const":
        return IRValue(MemSpace.CONST, const=_const(expr), size=_int_size(expr))
    if tag == "Iex_Unop":
        args = tuple(getattr(expr, "args", ()) or ())
        if not args:
            return IRValue(MemSpace.UNKNOWN, name=str(getattr(expr, "op", "unop")), expr=("empty_unop",))
        inner = _expr_to_value(args[0], tmps, conditions)
        return IRValue(
            inner.space,
            name=inner.name,
            offset=inner.offset,
            const=inner.const,
            size=inner.size,
            expr=(str(getattr(expr, "op", "unop")),),
        )
    if tag == "Iex_Binop":
        op = str(getattr(expr, "op", ""))
        args = tuple(getattr(expr, "args", ()) or ())
        if len(args) != 2:
            return IRValue(MemSpace.TMP, name=f"expr:{op}", expr=(op,))
        left = _expr_to_value(args[0], tmps, conditions)
        right = _expr_to_value(args[1], tmps, conditions)
        cond = build_condition_from_binop(op, left, right)
        if cond is not None:
            return IRValue(MemSpace.TMP, name=f"cond:{cond.op}", size=1, expr=(op,))
        if "Add" in op and left.space == MemSpace.REG and right.space == MemSpace.CONST and right.const is not None:
            return IRValue(left.space, name=left.name, offset=left.offset + int(right.const), size=left.size, expr=(op,))
        if "Sub" in op and left.space == MemSpace.REG and right.space == MemSpace.CONST and right.const is not None:
            return IRValue(left.space, name=left.name, offset=left.offset - int(right.const), size=left.size, expr=(op,))
        if "Add" in op and left.space == MemSpace.REG and right.space == MemSpace.REG and left.name and right.name:
            return IRValue(MemSpace.TMP, name=f"addr:{left.name}+{right.name}", size=left.size, expr=(op, left.name, right.name))
        if "And" in op:
            return IRValue(MemSpace.TMP, name=f"mask:{left.name or 'lhs'}", size=max(left.size, right.size), expr=(op,))
        return IRValue(MemSpace.TMP, name=f"expr:{op}", size=max(left.size, right.size), expr=(op,))
    if tag == "Iex_Load":
        addr = expr_to_address(
            getattr(expr, "addr", None),
            tmps,
            conditions,
            expr_to_value=_expr_to_value,
            size=_int_size(expr),
        )
        return IRValue(MemSpace.TMP, name="load", size=addr.size or _int_size(expr), expr=("load",))
    return IRValue(MemSpace.UNKNOWN, name=tag or "expr")

def _stmt_to_instr(stmt, tmps: dict[int, IRValue], conditions, *, segment_hints, tmp_exprs: dict[int, Any]) -> IRInstr | None:
    tag = getattr(stmt, "tag", "")
    if tag == "Ist_WrTmp":
        data = getattr(stmt, "data", None)
        tmp_id = int(getattr(stmt, "tmp"))
        data_tag = getattr(data, "tag", "")
        tmp_exprs[tmp_id] = data
        dst = IRValue(MemSpace.TMP, name=f"t{tmp_id}", size=_int_size(data))
        if data_tag == "Iex_Load":
            addr = expr_to_address(
                getattr(data, "addr", None),
                tmps,
                conditions,
                expr_to_value=_expr_to_value,
                size=_int_size(data),
                segment_hints=segment_hints,
            )
            tmps[tmp_id] = IRValue(MemSpace.TMP, name=f"load_t{tmp_id}", size=_int_size(data), expr=("load",))
            return IRInstr(op="LOAD", dst=dst, args=(addr,), size=_int_size(data))
        if data_tag == "Iex_Binop":
            op = str(getattr(data, "op", "BINOP"))
            args = tuple(getattr(data, "args", ()) or ())
            if len(args) == 2:
                left = _expr_to_value(args[0], tmps, conditions)
                right = _expr_to_value(args[1], tmps, conditions)
                if any(token in op for token in ("Cmp", "And", "Or")):
                    conditions[tmp_id] = expr_to_condition(
                        data,
                        tmps,
                        conditions,
                        expr_to_value=_expr_to_value,
                        tmp_exprs=tmp_exprs,
                    )
                else:
                    cond = build_condition_from_binop(op, left, right)
                    if cond is not None:
                        conditions[tmp_id] = cond
                tmps[tmp_id] = _expr_to_value(data, tmps, conditions)
                return IRInstr(op=op, dst=dst, args=(left, right), size=max(left.size, right.size))
        if data_tag == "Iex_ITE":
            cond = expr_to_condition(data, tmps, conditions, expr_to_value=_expr_to_value, tmp_exprs=tmp_exprs)
            if not (
                cond.op == "nonzero"
                and len(cond.args) == 1
                and isinstance(cond.args[0], IRValue)
                and cond.args[0].space == MemSpace.UNKNOWN
                and cond.args[0].name == "Iex_ITE"
            ):
                conditions[tmp_id] = cond
        value = _expr_to_value(data, tmps, conditions)
        tmps[tmp_id] = value
        return IRInstr(op="MOV", dst=dst, args=(value,), size=value.size)
    if tag == "Ist_Put":
        offset = int(getattr(stmt, "offset"))
        dst = IRValue(MemSpace.REG, name=register_name_from_offset(offset), size=2)
        src = _expr_to_value(getattr(stmt, "data", None), tmps, conditions)
        return IRInstr(op="MOV", dst=dst, args=(src,), size=dst.size)
    if tag == "Ist_Store":
        addr = expr_to_address(
            getattr(stmt, "addr", None),
            tmps,
            conditions,
            expr_to_value=_expr_to_value,
            size=_int_size(getattr(stmt, "data", None)),
            segment_hints=segment_hints,
        )
        data = _expr_to_value(getattr(stmt, "data", None), tmps, conditions)
        return IRInstr(op="STORE", dst=None, args=(addr, data), size=data.size)
    if tag == "Ist_Exit":
        cond = expr_to_condition(getattr(stmt, "guard", None), tmps, conditions, expr_to_value=_expr_to_value, tmp_exprs=tmp_exprs)
        target = _expr_to_value(getattr(stmt, "dst", None), tmps, conditions)
        return IRInstr(op="CJMP", dst=None, args=(cond, target), size=0)
    return None


def _block_to_ir(block) -> IRBlock:
    vex = getattr(block, "vex", None)
    addr = int(getattr(block, "addr", 0))
    if vex is None:
        return IRBlock(addr=addr, refusals=(IRRefusal("missing_vex", "block has no vex IR", addr),))
    tmps: dict[int, IRValue] = {}
    conditions = {}
    tmp_exprs: dict[int, Any] = {}
    instrs: list[IRInstr] = []
    refusals: list[IRRefusal] = []
    segment_hints = block_segment_hints(block)
    for stmt in tuple(getattr(vex, "statements", ()) or ()):
        instr = _stmt_to_instr(stmt, tmps, conditions, segment_hints=segment_hints, tmp_exprs=tmp_exprs)
        if instr is None:
            tag = getattr(stmt, "tag", "")
            if tag:
                refusals.append(IRRefusal("unsupported_stmt", f"unsupported VEX statement {tag}", addr))
            continue
        instrs.append(instr)
    successor_addrs: list[int] = []
    for stmt in tuple(getattr(vex, "statements", ()) or ()):
        if getattr(stmt, "tag", "") == "Ist_Exit":
            dst = getattr(stmt, "dst", None)
            const_dst = _const(dst)
            if const_dst is not None:
                successor_addrs.append(int(const_dst))
    vex_next = getattr(vex, "next", None)
    next_const = _const(vex_next)
    if next_const is not None:
        successor_addrs.append(int(next_const))
    return IRBlock(
        addr=addr,
        instrs=tuple(instrs),
        refusals=tuple(refusals),
        successor_addrs=tuple(sorted(dict.fromkeys(successor_addrs))),
    )


def build_x86_16_ir_function_artifact(project, function) -> IRFunctionArtifact:
    blocks: list[IRBlock] = []
    refusals: list[IRRefusal] = []
    for block_addr in tuple(sorted(getattr(function, "block_addrs_set", ()) or ())):
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception as ex:  # noqa: BLE001
            refusals.append(IRRefusal("block_decode_failed", str(ex), int(block_addr)))
            continue
        ir_block = _block_to_ir(block)
        blocks.append(ir_block)
        refusals.extend(ir_block.refusals)
    return IRFunctionArtifact(
        function_addr=int(getattr(function, "addr", 0)),
        blocks=tuple(blocks),
        refusals=tuple(refusals),
        summary=build_x86_16_ir_function_artifact_summary(
            IRFunctionArtifact(function_addr=int(getattr(function, "addr", 0)), blocks=tuple(blocks), refusals=tuple(refusals))
        ),
    )


def build_x86_16_ir_function_artifact_summary(artifact: IRFunctionArtifact) -> dict[str, object]:
    space_counts = {space.value: 0 for space in MemSpace}
    address_space_counts = {space.value: 0 for space in MemSpace}
    stable_address_space_counts = {space.value: 0 for space in MemSpace}
    address_status_counts = {status.value: 0 for status in AddressStatus}
    segment_origin_counts = {origin.value: 0 for origin in SegmentOrigin}
    condition_counts: dict[str, int] = {}
    ssa_binding_count = 0
    aliasable_values = 0

    def _record_condition_atom(cond: IRCondition) -> None:
        nonlocal aliasable_values
        condition_counts[cond.op] = condition_counts.get(cond.op, 0) + 1
        for item in cond.args:
            if isinstance(item, IRCondition):
                _record_condition_atom(item)
                continue
            space_counts[item.space.value] = space_counts.get(item.space.value, 0) + 1
            if storage_of(item) is not None:
                aliasable_values += 1

    for block in artifact.blocks:
        ssa_binding_count += len(build_x86_16_block_local_ssa(block).bindings)
        for instr in block.instrs:
            atoms: tuple[IRAtom, ...] = instr.args + (() if instr.dst is None else (instr.dst,))
            for atom in atoms:
                if isinstance(atom, IRCondition):
                    _record_condition_atom(atom)
                    continue
                space_counts[atom.space.value] = space_counts.get(atom.space.value, 0) + 1
                if isinstance(atom, IRAddress):
                    address_space_counts[atom.space.value] = address_space_counts.get(atom.space.value, 0) + 1
                    if atom.status == AddressStatus.STABLE:
                        stable_address_space_counts[atom.space.value] = stable_address_space_counts.get(atom.space.value, 0) + 1
                    address_status_counts[atom.status.value] = address_status_counts.get(atom.status.value, 0) + 1
                    segment_origin_counts[atom.segment_origin.value] = segment_origin_counts.get(atom.segment_origin.value, 0) + 1
                if storage_of(atom) is not None:
                    aliasable_values += 1
    frame = build_x86_16_ir_frame_access_artifact(artifact)
    return {
        "block_count": len(artifact.blocks),
        "instruction_count": sum(len(block.instrs) for block in artifact.blocks),
        "refusal_count": len(artifact.refusals),
        "space_counts": dict(sorted(space_counts.items())),
        "address_space_counts": dict(sorted(address_space_counts.items())),
        "stable_address_space_counts": dict(sorted(stable_address_space_counts.items())),
        "address_status_counts": dict(sorted(address_status_counts.items())),
        "segment_origin_counts": dict(sorted(segment_origin_counts.items())),
        "condition_counts": dict(sorted(condition_counts.items())),
        "aliasable_value_count": aliasable_values,
        "ssa_binding_count": ssa_binding_count,
        "frame_slot_count": len(frame.slots),
        "frame_refusal_count": len(frame.refusals),
    }


def apply_x86_16_vex_ir_artifact(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return False
    function = project.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        return False
    artifact = build_x86_16_ir_function_artifact(project, function)
    setattr(codegen, "_inertia_vex_ir_artifact", artifact)
    setattr(codegen, "_inertia_vex_ir_summary", artifact.summary)
    setattr(codegen, "_inertia_vex_ir_frame", build_x86_16_ir_frame_access_artifact(artifact))
    setattr(codegen, "_inertia_vex_ir_function_ssa", build_x86_16_function_ssa(artifact))
    info = getattr(function, "info", None)
    if isinstance(info, dict):
        info["x86_16_vex_ir_artifact"] = artifact.to_dict()
        info["x86_16_vex_ir_summary"] = dict(artifact.summary)
        info["x86_16_vex_ir_frame"] = getattr(codegen, "_inertia_vex_ir_frame").to_dict()
        info["x86_16_vex_ir_function_ssa"] = getattr(codegen, "_inertia_vex_ir_function_ssa").to_dict()
    return False
