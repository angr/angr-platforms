from __future__ import annotations

import logging
import os
import re

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CReturn,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import (
    SimTypeBottom,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)
from angr.utils.library import convert_cproto_to_py

try:
    from angr.analyses.typehoon import lifter as _typehoon_lifter
except ImportError:
    _typehoon_lifter = None
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .alias.alias_model import _stack_slot_identity_can_join, _stack_slot_identity_for_variable
from .analysis_helpers import preferred_known_helper_signature_decl
from .annotations import ANNOTATION_KEY, _source_decl_from_cod_source_lines, annotate_function
from .decompiler_postprocess_utils import (
    _c_constant_value_8616,
    _iter_c_nodes_deep_8616,
    _match_bp_stack_load_8616,
    _replace_c_children_8616,
    _structured_codegen_node_8616,
)


def _function_complexity_8616(project, function) -> tuple[int, int]:
    block_addrs = sorted(getattr(function, "block_addrs_set", ()) or ())
    byte_count = 0
    for block_addr in block_addrs:
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        byte_count += len(block.bytes)
    return len(block_addrs), byte_count


def _is_tiny_function_8616(project, function) -> bool:
    block_count, byte_count = _function_complexity_8616(project, function)
    return block_count <= 4 and byte_count <= 32


def _unwrap_synthetic_wide_return_8616(retval):
    if not isinstance(retval, CBinaryOp):
        return None

    candidates = []
    if retval.op == "Or":
        candidates.extend(((retval.lhs, retval.rhs), (retval.rhs, retval.lhs)))
    elif retval.op == "Concat":
        candidates.extend(((retval.lhs, retval.rhs),))
    else:
        return None

    for maybe_wide, maybe_low in candidates:
        if isinstance(maybe_wide, CBinaryOp):
            if maybe_wide.op == "Shl" and _c_constant_value_8616(maybe_wide.rhs) == 16:
                return maybe_low
            if maybe_wide.op == "Concat":
                return maybe_low

    return None


def _normalize_arg_names_8616(arg_names: tuple[str | None, ...] | list[str | None] | None, count: int) -> list[str | None]:
    normalized: list[str | None] = []
    used: set[str] = set()
    source = list(arg_names or ())
    for index in range(count):
        base_name = source[index] if index < len(source) else None
        if not isinstance(base_name, str) or not base_name:
            base_name = f"a{index}"
        candidate = base_name
        suffix_match = re.fullmatch(r"(?P<base>.+?)_(?P<suffix>\d+)", base_name)
        if suffix_match is not None:
            unsuffixed = suffix_match.group("base")
            if unsuffixed and unsuffixed not in used:
                candidate = unsuffixed
        suffix = 2
        while candidate in used:
            candidate = f"{base_name}_{suffix}"
            suffix += 1
        normalized.append(candidate)
        used.add(candidate)
    return normalized


def _known_helper_arg_names_8616(name: str | None) -> list[str] | None:
    if not isinstance(name, str) or not name:
        return None

    decl = preferred_known_helper_signature_decl(name)
    if decl is None:
        return None

    try:
        _, proto, _ = convert_cproto_to_py(decl)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "convert_cproto_to_py failed for decl=%r: %s",
            decl,
            ex,
        )
        return None

    if proto is None:
        return None

    arg_names = list(getattr(proto, "arg_names", None) or ())
    return arg_names or None


def _set_codegen_prototype_8616(codegen, prototype) -> None:
    functy_ok = False
    proto_ok = False
    try:
        codegen.cfunc.functy = prototype
        functy_ok = True
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "setting cfunc.functy failed for %#x: %s",
            getattr(codegen.cfunc, "addr", 0),
            ex,
        )
    try:
        codegen.cfunc.prototype = prototype
        proto_ok = True
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "setting cfunc.prototype failed for %#x: %s",
            getattr(codegen.cfunc, "addr", 0),
            ex,
        )
    if not functy_ok and not proto_ok:
        logging.getLogger(__name__).warning(
            "codegen prototype set failed for %#x (neither functy nor prototype attribute)",
            getattr(codegen.cfunc, "addr", 0),
        )


def _prune_return_address_stack_arguments_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    func_addr = getattr(codegen.cfunc, "addr", None)
    if func_addr is None:
        return False

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return False

    prototype = getattr(func, "prototype", None)
    annotations = getattr(func, "info", {}).get(ANNOTATION_KEY, {})
    stack_specs = annotations.get("stack_vars", {}) if isinstance(annotations, dict) else {}
    arg_list = list(getattr(codegen.cfunc, "arg_list", ()) or ())
    if prototype is None or not arg_list:
        return False

    kept_args = []
    changed = False
    for arg in arg_list:
        variable = getattr(arg, "variable", None)
        if isinstance(variable, SimStackVariable):
            identity = _stack_slot_identity_for_variable(variable)
            if (
                identity is not None
                and getattr(identity, "base", None) == "bp"
                and getattr(identity, "offset", None) in {0, 2}
                and getattr(identity, "offset", None) not in stack_specs
            ):
                changed = True
                continue
        kept_args.append(arg)

    if not changed:
        return False
    codegen.cfunc.arg_list = kept_args
    proto_args = list(getattr(prototype, "args", ()) or ())
    arg_types = []
    arg_names = []
    for index, arg in enumerate(kept_args):
        arg_type = getattr(arg, "variable_type", None)
        if arg_type is None and index < len(proto_args):
            arg_type = proto_args[index]
        arg_types.append(arg_type)
        variable = getattr(arg, "variable", None)
        arg_name = getattr(variable, "name", None)
        if isinstance(variable, SimStackVariable):
            offset = getattr(variable, "offset", None)
            if isinstance(offset, int) and offset > 0:
                spec = stack_specs.get(offset - 2)
                if isinstance(spec, str):
                    arg_name = spec
                elif isinstance(spec, dict):
                    spec_name = spec.get("name")
                    if isinstance(spec_name, str) and spec_name:
                        arg_name = spec_name
        if arg_name is not None:
            try:
                arg.name = arg_name
            except Exception:
                pass
            if variable is not None and getattr(variable, "name", None) != arg_name:
                variable.name = arg_name
            unified = getattr(arg, "unified_variable", None)
            if unified is not None and getattr(unified, "name", None) != arg_name:
                unified.name = arg_name
        arg_names.append(arg_name)

    new_proto = prototype.__class__(
        arg_types,
        prototype.returnty,
        arg_names=_normalize_arg_names_8616(arg_names, len(arg_types)),
        variadic=getattr(prototype, "variadic", False),
    ).with_arch(project.arch)
    func.prototype = new_proto
    func.is_prototype_guessed = False
    _set_codegen_prototype_8616(codegen, new_proto)
    return True


def _normalize_function_prototype_arg_names_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    func_addr = getattr(codegen.cfunc, "addr", None)
    if func_addr is None:
        return False

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return False

    prototype = getattr(func, "prototype", None)
    if prototype is None:
        return False

    arg_names = getattr(prototype, "arg_names", None)
    if arg_names is None:
        return False

    normalized = _normalize_arg_names_8616(arg_names, len(getattr(prototype, "args", ()) or ()))
    if list(arg_names) == normalized:
        return False

    new_proto = prototype.__class__(
        list(getattr(prototype, "args", ()) or ()),
        prototype.returnty,
        arg_names=normalized,
        variadic=getattr(prototype, "variadic", False),
    ).with_arch(project.arch)
    func.prototype = new_proto
    _set_codegen_prototype_8616(codegen, new_proto)
    return True


def _make_unique_identifier_8616(base: str, used: set[str]) -> str:
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _dedupe_codegen_variable_names_8616(codegen) -> bool:
    # Name dedup is readability-only. If it perturbs canonicalized semantics it must
    # not run in the correctness pipeline by default.
    if os.environ.get("INERTIA_ENABLE_NAME_DEDUP", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return False

    if getattr(codegen, "cfunc", None) is None:
        return False

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if not isinstance(variables_in_use, dict) and not isinstance(unified_locals, dict):
        return False

    def is_generic_name(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+|ir_\d+)", name) is not None

    def preferred_name(variable, cvar) -> str | None:
        candidates = [
            getattr(variable, "name", None),
            getattr(cvar, "name", None),
            getattr(getattr(cvar, "unified_variable", None), "name", None),
        ]
        for candidate in candidates:
            if isinstance(candidate, str) and candidate and not is_generic_name(candidate):
                return candidate
        for candidate in candidates:
            if isinstance(candidate, str) and candidate:
                return candidate
        return None

    def sort_key(item):
        variable, cvar = item
        variable_name = getattr(variable, "name", None)
        cvar_name = getattr(cvar, "name", None)
        variable_name_key = variable_name if isinstance(variable_name, str) else ""
        cvar_name_key = cvar_name if isinstance(cvar_name, str) else ""
        if isinstance(variable, SimStackVariable):
            offset = getattr(variable, "offset", 0)
            base_rank = 0 if isinstance(offset, int) and offset > 0 else 1
            return (
                0,
                base_rank,
                offset if isinstance(offset, int) else 0,
                getattr(variable, "size", 0) if isinstance(getattr(variable, "size", 0), int) else 0,
                variable_name_key,
            )
        if isinstance(variable, SimRegisterVariable):
            reg = getattr(variable, "reg", 0)
            return (
                1,
                reg if isinstance(reg, int) else 0,
                getattr(variable, "size", 0) if isinstance(getattr(variable, "size", 0), int) else 0,
                variable_name_key,
            )
        if isinstance(variable, SimMemoryVariable):
            addr = getattr(variable, "addr", 0)
            return (
                2,
                addr if isinstance(addr, int) else 0,
                getattr(variable, "size", 0) if isinstance(getattr(variable, "size", 0), int) else 0,
                variable_name_key,
            )
        return (3, variable_name_key, cvar_name_key)

    ordered_items = list(variables_in_use.items()) if isinstance(variables_in_use, dict) else []
    if isinstance(unified_locals, dict):
        for variable, cvars in unified_locals.items():
            if variable not in variables_in_use and cvars:
                ordered_items.append((variable, next(iter(cvars))[0]))

    ordered_items.sort(key=sort_key)

    used_names: set[str] = set()
    seen_variables: set[int] = set()
    changed = False

    def apply_name(variable, cvar, new_name: str) -> None:
        nonlocal changed
        if getattr(variable, "name", None) != new_name:
            variable.name = new_name
            changed = True
        if getattr(cvar, "name", None) != new_name:
            try:
                cvar.name = new_name
            except Exception:
                pass
            else:
                changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "name", None) != new_name:
            unified.name = new_name
            changed = True

    for variable, cvar in ordered_items:
        if id(variable) in seen_variables:
            continue
        seen_variables.add(id(variable))
        name = preferred_name(variable, cvar)
        if name is None:
            continue
        if name in used_names:
            name = _make_unique_identifier_8616(name, used_names)
        else:
            used_names.add(name)
        apply_name(variable, cvar, name)

    return changed


def _return_value_shape_8616(retval) -> str | None:
    if retval is None:
        return None
    if isinstance(retval, CFunctionCall) and getattr(retval, "callee_target", None) == "MK_FP":
        return "wide_fp"
    if isinstance(retval, CBinaryOp):
        if retval.op in {"Or", "Concat"}:
            for maybe_wide, maybe_low in ((retval.lhs, retval.rhs), (retval.rhs, retval.lhs)):
                if _c_constant_value_8616(maybe_low) == 0:
                    return _return_value_shape_8616(maybe_wide) or "wide_fp"
                if isinstance(maybe_wide, CBinaryOp):
                    if maybe_wide.op == "Shl" and _c_constant_value_8616(maybe_wide.rhs) == 16:
                        return "wide_fp"
                    if maybe_wide.op == "Concat":
                        return "wide_fp"
        return "scalar"
    if isinstance(retval, CConstant):
        return "scalar"
    if isinstance(retval, CVariable):
        return "scalar"
    if isinstance(retval, CTypeCast):
        return _return_value_shape_8616(retval.expr)
    if isinstance(retval, CUnaryOp):
        return "scalar" if retval.op in {"Neg", "Not", "Reference"} else None
    return "scalar"


def _stack_arg_has_pointer_evidence_8616(codegen, variable) -> bool:
    identity = _stack_slot_identity_for_variable(variable)
    if identity is None:
        return False

    statements = getattr(getattr(codegen, "cfunc", None), "statements", None)
    for stmt in getattr(statements, "statements", ()) or ():
        for node in _iter_c_nodes_deep_8616(stmt):
            if not isinstance(node, CUnaryOp) or node.op != "Dereference":
                continue
            for operand_node in _iter_c_nodes_deep_8616(node.operand):
                if not isinstance(operand_node, CVariable):
                    continue
                operand_var = getattr(operand_node, "variable", None)
                if _stack_slot_identity_for_variable(operand_var) == identity:
                    return True
    return False


def _source_return_shape_8616(source_return_lines) -> str | None:
    if not source_return_lines:
        return None

    found_value_return = False
    for line in source_return_lines:
        stripped = line.strip()
        if not stripped.startswith("return "):
            continue
        expr = stripped[len("return ") :].rstrip(";").strip()
        if not expr:
            continue
        if expr == "0":
            found_value_return = True
            continue
        found_value_return = True
        if "MK_FP(" in expr or re.search(r"<<\s*16\b", expr) is not None or "Concat(" in expr:
            return "wide_fp"

    if found_value_return:
        return "scalar"
    return None


def _promote_stack_prototype_from_bp_loads_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    func_addr = getattr(codegen.cfunc, "addr", None)
    if func_addr is None:
        return False

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return False

    prototype = getattr(func, "prototype", None)
    if prototype is None:
        return False
    current_proto = getattr(getattr(codegen, "cfunc", None), "functy", None) or prototype
    existing_args = list(getattr(codegen.cfunc, "arg_list", ()) or ())
    c_target = str(getattr(project, "_inertia_c_target", "portable-flat") or "portable-flat").strip().lower()
    promote_near_pointers = c_target != "portable-flat"

    annotations = {}
    info = getattr(func, "info", None)
    if isinstance(info, dict):
        maybe_annotations = info.get(ANNOTATION_KEY)
        if isinstance(maybe_annotations, dict):
            annotations = maybe_annotations
    source_pointer_flags: tuple[bool, ...] = ()
    source_lines = annotations.get("source_lines", ()) if isinstance(annotations, dict) else ()
    source_decl = _source_decl_from_cod_source_lines(source_lines) if source_lines else None
    if isinstance(source_decl, str) and source_decl:
        try:
            _, parsed_proto, _ = convert_cproto_to_py(source_decl)
        except Exception:
            parsed_proto = None
        else:
            if parsed_proto is not None:
                source_pointer_flags = tuple(
                    isinstance(arg, SimTypePointer)
                    for arg in (getattr(parsed_proto, "args", ()) or ())
                )

    stack_specs = annotations.get("stack_vars", {}) if isinstance(annotations, dict) else {}
    annotated_args = []
    if isinstance(stack_specs, dict):
        for offset, spec in sorted(stack_specs.items(), key=lambda item: item[0]):
            if not isinstance(offset, int) or offset <= 0:
                continue
            name = None
            if isinstance(spec, str):
                name = spec
            elif isinstance(spec, dict):
                spec_name = spec.get("name")
                if isinstance(spec_name, str) and spec_name:
                    name = spec_name
            annotated_args.append((offset, name))

    arg_names = list(getattr(prototype, "arg_names", None) or ())
    if annotated_args:
        target_arg_count = len(annotated_args)
        new_args = list(getattr(prototype, "args", ()) or ())
        if len(new_args) < target_arg_count:
            new_args.extend(
                SimTypeShort(False).with_arch(project.arch)
                for _ in range(target_arg_count - len(new_args))
            )
        elif len(new_args) > target_arg_count:
            new_args = new_args[:target_arg_count]

        desired_names = []
        for index in range(target_arg_count):
            annotated_name = annotated_args[index][1] if index < len(annotated_args) else None
            existing_name = arg_names[index] if index < len(arg_names) else None
            desired_names.append(annotated_name or existing_name)
        normalized_names = _normalize_arg_names_8616(desired_names, target_arg_count)

        stack_cvars_by_offset = {}
        for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            if isinstance(variable, SimStackVariable):
                stack_cvars_by_offset.setdefault(getattr(variable, "offset", None), cvar)
        pointer_promoted = False
        resolved_args = []
        for index in range(target_arg_count):
            annotated_offset = annotated_args[index][0] if index < len(annotated_args) else None
            if index < len(existing_args):
                resolved_arg = existing_args[index]
            else:
                resolved_arg = stack_cvars_by_offset.get(annotated_offset)
            resolved_args.append(resolved_arg)
            if resolved_arg is None:
                continue
            if not promote_near_pointers:
                continue
            if index < len(source_pointer_flags) and source_pointer_flags[index] is False:
                continue
            if not _stack_arg_has_pointer_evidence_8616(codegen, getattr(resolved_arg, "variable", None)):
                continue
            pointer_type = SimTypePointer(SimTypeShort(False))
            arch = getattr(getattr(codegen, "project", None), "arch", None)
            if arch is not None and hasattr(pointer_type, "with_arch"):
                pointer_type = pointer_type.with_arch(arch)
            if getattr(resolved_arg, "variable_type", None) != pointer_type:
                resolved_arg.variable_type = pointer_type
                pointer_promoted = True
            if new_args[index] != pointer_type:
                new_args[index] = pointer_type
                pointer_promoted = True

        if (
            pointer_promoted
            or target_arg_count > len(getattr(prototype, "args", ()) or ())
            or list(arg_names) != normalized_names
        ):
            new_proto = prototype.__class__(
                new_args,
                prototype.returnty,
                arg_names=normalized_names,
                variadic=getattr(prototype, "variadic", False),
            ).with_arch(project.arch)
            func.prototype = new_proto
            func.is_prototype_guessed = False
            _set_codegen_prototype_8616(codegen, new_proto)
            arg_list = getattr(codegen.cfunc, "arg_list", None)
            if isinstance(arg_list, list) and len(arg_list) > target_arg_count:
                codegen.cfunc.arg_list = arg_list[:target_arg_count]
            elif not arg_list and any(resolved_arg is not None for resolved_arg in resolved_args):
                codegen.cfunc.arg_list = [resolved_arg for resolved_arg in resolved_args if resolved_arg is not None]
            return True

    fallback_args = [
        arg
        for arg in existing_args
        if isinstance(getattr(arg, "variable", None), SimStackVariable)
    ]
    if fallback_args:
        target_arg_count = len(fallback_args)
        new_args = list(getattr(current_proto, "args", ()) or ())
        if len(new_args) < target_arg_count:
            new_args.extend(
                SimTypeShort(False).with_arch(project.arch)
                for _ in range(target_arg_count - len(new_args))
            )
        elif len(new_args) > target_arg_count:
            new_args = new_args[:target_arg_count]

        pointer_promoted = False
        for index, resolved_arg in enumerate(fallback_args):
            if not promote_near_pointers:
                continue
            if index < len(source_pointer_flags) and source_pointer_flags[index] is False:
                continue
            if not _stack_arg_has_pointer_evidence_8616(codegen, getattr(resolved_arg, "variable", None)):
                continue
            pointer_type = SimTypePointer(SimTypeShort(False))
            arch = getattr(getattr(codegen, "project", None), "arch", None)
            if arch is not None and hasattr(pointer_type, "with_arch"):
                pointer_type = pointer_type.with_arch(arch)
            if getattr(resolved_arg, "variable_type", None) != pointer_type:
                resolved_arg.variable_type = pointer_type
                pointer_promoted = True
            if index < len(new_args) and new_args[index] != pointer_type:
                new_args[index] = pointer_type
                pointer_promoted = True

        if pointer_promoted:
            desired_names = []
            for index in range(target_arg_count):
                if index < len(fallback_args):
                    desired_names.append(
                        getattr(getattr(fallback_args[index], "unified_variable", None), "name", None)
                        or fallback_args[index].name
                    )
                elif index < len(getattr(current_proto, "arg_names", ()) or ()):
                    desired_names.append(current_proto.arg_names[index])
                else:
                    desired_names.append(None)
            normalized_names = _normalize_arg_names_8616(desired_names, target_arg_count)
            new_proto = current_proto.__class__(
                new_args,
                current_proto.returnty,
                arg_names=normalized_names,
                variadic=getattr(current_proto, "variadic", False),
            )
            arch = getattr(getattr(codegen, "project", None), "arch", None)
            if arch is not None and hasattr(new_proto, "with_arch"):
                new_proto = new_proto.with_arch(arch)
            func.prototype = new_proto
            codegen.cfunc.functy = new_proto
            codegen.cfunc.arg_list = fallback_args
            return True

    for name in arg_names:
        if name is None:
            continue
        if not (isinstance(name, str) and len(name) > 1 and name[0] == "a" and name[1:].isdigit()):
            break
    else:
        if not getattr(codegen, "cfunc", None):
            return False

        stack_slots_by_offset = {}
        for variable, _cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            if not isinstance(variable, SimStackVariable):
                continue
            identity = _stack_slot_identity_for_variable(variable)
            if identity is not None:
                stack_slots_by_offset[getattr(variable, "offset", None)] = identity

        offsets = set()
        slot_identities = set()
        for stmt in getattr(codegen.cfunc.statements, "statements", ()) or ():
            if not isinstance(stmt, CReturn):
                continue
            retval = getattr(stmt, "retval", None)
            if retval is None:
                continue
            for node in _iter_c_nodes_deep_8616(retval):
                offset = _match_bp_stack_load_8616(node, project)
                if offset is not None and offset > 2:
                    offsets.add(offset)
                    slot_identity = stack_slots_by_offset.get(offset)
                    if slot_identity is not None:
                        slot_identities.add(slot_identity)

        if len(slot_identities) > 1:
            return False

        existing_args = list(getattr(prototype, "args", ()) or ())

        if offsets:
            target_arg_count = max(
                len(existing_args),
                max(((offset - 2) // 2) for offset in offsets),
            )
            if target_arg_count > len(existing_args):
                new_args = list(existing_args)
                new_args.extend(
                    SimTypeShort(False).with_arch(project.arch)
                    for _ in range(target_arg_count - len(existing_args))
                )
            else:
                new_args = list(existing_args)
            arg_names = _normalize_arg_names_8616(getattr(prototype, "arg_names", None), len(new_args))
        else:
            existing_names = getattr(prototype, "arg_names", None)
            arg_names = _normalize_arg_names_8616(existing_names, len(existing_args)) if existing_names is not None else None

        def has_wide_return_pattern() -> bool:
            for stmt in getattr(codegen.cfunc.statements, "statements", ()) or ():
                if not isinstance(stmt, CReturn):
                    continue
                retval = getattr(stmt, "retval", None)
                if not isinstance(retval, CBinaryOp) or retval.op != "Or":
                    continue
                for maybe_shl, maybe_other in ((retval.lhs, retval.rhs), (retval.rhs, retval.lhs)):
                    if not isinstance(maybe_shl, CBinaryOp) or maybe_shl.op != "Shl":
                        continue
                    if _c_constant_value_8616(maybe_shl.rhs) != 16:
                        continue
                    if isinstance(maybe_other, CVariable):
                        return True
            return False

        if offsets and target_arg_count > len(existing_args):
            new_proto = prototype.__class__(
                new_args,
                prototype.returnty,
                arg_names=arg_names,
                variadic=getattr(prototype, "variadic", False),
            ).with_arch(project.arch)
            func.prototype = new_proto
            func.is_prototype_guessed = False
            _set_codegen_prototype_8616(codegen, new_proto)
            return True

        if not isinstance(prototype.returnty, SimTypeLong) or not has_wide_return_pattern():
            return False

        wide_ty = SimTypeLong().with_arch(project.arch)
        new_proto = prototype.__class__(
            [wide_ty],
            wide_ty,
            arg_names=_normalize_arg_names_8616(getattr(prototype, "arg_names", None), 1),
            variadic=getattr(prototype, "variadic", False),
        ).with_arch(project.arch)
        func.prototype = new_proto
        func.is_prototype_guessed = False
        _set_codegen_prototype_8616(codegen, new_proto)
        return True


def _classify_return_shape_8616(project, codegen) -> bool:
    # Return-shape reclassification mutates function prototypes and can affect
    # observable memory/ABI behavior. Keep it opt-in until fully proven stable.
    if os.environ.get("INERTIA_ENABLE_RETURN_SHAPE_CLASSIFY", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return False

    if getattr(codegen, "cfunc", None) is None:
        return False

    func_addr = getattr(codegen.cfunc, "addr", None)
    if func_addr is None:
        return False

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return False

    prototype = getattr(func, "prototype", None)
    if prototype is None:
        return False

    source_return_lines: tuple[str, ...] = ()
    source_lines: tuple[str, ...] = ()
    info = getattr(func, "info", None)
    if isinstance(info, dict):
        annotations = info.get(ANNOTATION_KEY)
        if isinstance(annotations, dict):
            source_return_lines = tuple(annotations.get("source_return_lines", ()) or ())
            source_lines = tuple(annotations.get("source_lines", ()) or ())

    source_decl = _source_decl_from_cod_source_lines(source_lines) if source_lines else None
    source_decl_is_void = False
    if isinstance(source_decl, str) and source_decl:
        try:
            _, source_proto, _ = convert_cproto_to_py(source_decl)
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "source decl proto parsing failed decl=%r: %s",
                source_decl,
                ex,
            )
            source_proto = None
        source_decl_is_void = isinstance(getattr(source_proto, "returnty", None), SimTypeBottom)

    return_nodes = [node for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements) if isinstance(node, CReturn)]
    if not return_nodes:
        source_shape = _source_return_shape_8616(source_return_lines)
        if source_shape is None and not source_decl_is_void:
            return False
        return_nodes = []
    else:
        source_shape = _source_return_shape_8616(source_return_lines)

    tiny_function = _is_tiny_function_8616(project, func)
    changed = False
    value_returns = 0
    return_shapes: set[str] = set()

    for ret in return_nodes:
        retval = getattr(ret, "retval", None)
        if retval is None:
            continue
        value_returns += 1
        shape = _return_value_shape_8616(retval)
        replacement = _unwrap_synthetic_wide_return_8616(retval)
        if tiny_function and replacement is not None:
            ret.retval = None
            changed = True
            if shape is not None and shape != "wide_fp":
                return_shapes.add(shape)
            continue
        if shape is not None:
            return_shapes.add(shape)

    has_value_return = any(getattr(ret, "retval", None) is not None for ret in return_nodes)
    if not has_value_return and not return_nodes and source_shape is None and not source_decl_is_void:
        return changed

    if not has_value_return and source_shape is None:
        shape = "void"
    else:
        shape = "scalar_ax"

    info = getattr(func, "info", None)
    if isinstance(info, dict):
        return_info = info.setdefault("x86_16_return_shape", {})
        return_info["shape"] = shape
        return_info["tiny_function"] = tiny_function
        return_info["value_returns"] = value_returns

    new_returnty = None
    if shape == "void":
        new_returnty = SimTypeBottom(label="void")
    elif shape == "scalar_ax" and ((return_shapes and return_shapes <= {"scalar"}) or source_shape == "scalar"):
        if not isinstance(prototype.returnty, SimTypeShort):
            new_returnty = SimTypeShort(False)
    elif (return_shapes and return_shapes <= {"wide_fp"}) or source_shape == "wide_fp":
        if not isinstance(prototype.returnty, SimTypeLong):
            new_returnty = SimTypeLong()

    if new_returnty is None:
        return changed

    new_proto = prototype.__class__(
        list(getattr(prototype, "args", ()) or ()),
        new_returnty,
        arg_names=getattr(prototype, "arg_names", None),
        variadic=getattr(prototype, "variadic", False),
    ).with_arch(project.arch)
    func.prototype = new_proto
    func.is_prototype_guessed = False
    _set_codegen_prototype_8616(codegen, new_proto)
    return True


def _prune_void_function_return_values_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    func_addr = getattr(codegen.cfunc, "addr", None)
    if func_addr is None:
        return False

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return False

    prototype = getattr(func, "prototype", None)
    if prototype is None or type(getattr(prototype, "returnty", None)) is not SimTypeBottom:
        return False

    changed = False
    for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements):
        if not isinstance(node, CReturn):
            continue
        if getattr(node, "retval", None) is None:
            continue
        node.retval = None
        changed = True
    return changed

def _apply_annotations_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    func_addr = getattr(codegen.cfunc, "addr", None)
    if func_addr is None:
        return False

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return False

    changed = False
    helper_decl = preferred_known_helper_signature_decl(getattr(func, "name", None))
    if helper_decl is not None:
        annotate_function(project, func_addr, name=getattr(func, "name", None), c_decl=helper_decl)
        func = project.kb.functions.function(addr=func_addr, create=False)
        if func is None:
            return False
        if getattr(codegen, "cfunc", None) is not None and getattr(func, "prototype", None) is not None:
            codegen.cfunc.functy = func.prototype
            prototype_arg_names = tuple(getattr(func.prototype, "arg_names", ()) or ())
            if prototype_arg_names:
                for index, cvar in enumerate(getattr(codegen.cfunc, "arg_list", ()) or ()):
                    if index >= len(prototype_arg_names):
                        break
                    arg_name = prototype_arg_names[index]
                    if not isinstance(arg_name, str) or not arg_name:
                        continue
                    variable = getattr(cvar, "variable", None)
                    unified = getattr(cvar, "unified_variable", None)
                    if variable is not None and getattr(variable, "name", None) != arg_name:
                        variable.name = arg_name
                    if unified is not None and getattr(unified, "name", None) != arg_name:
                        unified.name = arg_name
                    if getattr(cvar, "name", None) != arg_name:
                        cvar.name = arg_name
        changed = True

    annotations = func.info.get(ANNOTATION_KEY)
    if not annotations:
        return False

    stack_specs = annotations.get("stack_vars", {})
    global_specs = annotations.get("global_vars", {})
    c_target = str(getattr(project, "_inertia_c_target", "portable-flat") or "portable-flat").strip().lower()
    promote_near_pointers = c_target != "portable-flat"

    def global_spec_for(addr: int):
        spec = global_specs.get(addr)
        if isinstance(spec, str):
            return spec, None
        if isinstance(spec, dict):
            name = spec.get("name")
            vartype = spec.get("type")
            if isinstance(name, str):
                return name, vartype
        return None, None

    arg_slot_identities = {
        _stack_slot_identity_for_variable(getattr(arg, "variable", None))
        for arg in getattr(codegen.cfunc, "arg_list", ()) or ()
        if isinstance(getattr(arg, "variable", None), SimStackVariable)
    }
    helper_arg_names = list(getattr(getattr(func, "prototype", None), "arg_names", ()) or ())
    helper_arg_offsets = sorted(offset for offset in stack_specs if isinstance(offset, int) and offset > 0)
    helper_arg_name_by_offset = {
        offset: helper_arg_names[index]
        for index, offset in enumerate(helper_arg_offsets)
        if index < len(helper_arg_names) and isinstance(helper_arg_names[index], str) and helper_arg_names[index]
    }
    stack_vars_by_offset = {}
    used_stack_names: set[str] = set()
    name_owner_offsets: dict[str, int] = {}
    exact_stack_candidates: dict[int, list[tuple[tuple[int, int, int, int, int], CVariable]]] = {}

    def _stack_name_is_generic(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(r"(?:arg_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)", name) is not None

    def _stack_candidate_score(variable, cvar, *, exact: bool) -> tuple[int, int, int, int, int]:
        identity = _stack_slot_identity_for_variable(variable)
        if identity is None:
            return (-1, -1, -1, -1, -1)
        variable_name = getattr(variable, "name", None)
        cvar_name = getattr(cvar, "name", None)
        unified_name = getattr(getattr(cvar, "unified_variable", None), "name", None)
        preferred_name = next(
            (name for name in (variable_name, cvar_name, unified_name) if isinstance(name, str) and name and not _stack_name_is_generic(name)),
            None,
        )
        is_arg_slot = 1 if identity in arg_slot_identities else 0
        has_preferred_name = 1 if preferred_name is not None else 0
        size = getattr(variable, "size", None)
        size_rank = -size if isinstance(size, int) else 0
        exact_rank = 1 if exact else 0
        return (exact_rank, is_arg_slot, has_preferred_name, size_rank, -getattr(variable, "offset", 0))

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if isinstance(variable, SimStackVariable):
            offset = getattr(variable, "offset", None)
            if not isinstance(offset, int):
                continue
            score = _stack_candidate_score(variable, cvar, exact=True)
            exact_stack_candidates.setdefault(offset, []).append((score, cvar))

    for offset, candidates in exact_stack_candidates.items():
        best_score, best_cvar = max(candidates, key=lambda item: item[0])
        stack_vars_by_offset[offset] = best_cvar

    materialized_stack_cvars: dict[int, CVariable] = {}

    def _stack_spec_for_offset(offset: int):
        spec = stack_specs.get(offset)
        if spec is None and isinstance(offset, int) and offset < 0:
            spec = stack_specs.get(offset + 2)
        return spec

    def _materialize_stack_cvar(offset: int, type_):
        existing = materialized_stack_cvars.get(offset)
        if existing is not None:
            return existing

        spec = _stack_spec_for_offset(offset)
        if spec is None:
            return None

        name = None
        spec_type = None
        if isinstance(spec, str):
            name = spec
        elif isinstance(spec, dict):
            spec_name = spec.get("name")
            if isinstance(spec_name, str) and spec_name:
                name = spec_name
            spec_type = spec.get("type")

        if name is None:
            return None

        size = max((getattr(type_, "size", None) or 8) // 8, 1)
        stack_var = SimStackVariable(offset, size, base="bp", name=name, region=func_addr)
        vartype = type_ if type_ is not None else spec_type
        cvar = CVariable(stack_var, variable_type=vartype, codegen=codegen)
        materialized_stack_cvars[offset] = cvar

        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            variables_in_use[stack_var] = cvar

        unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified_locals, dict):
            unified_locals[stack_var] = {(cvar, vartype if vartype is not None else getattr(cvar, "variable_type", None))}

        stack_vars_by_offset[offset] = cvar
        return cvar

    def resolve_stack_cvar(offset: int):
        direct = stack_vars_by_offset.get(offset)
        if direct is not None:
            return direct

        normalized_offset = offset - 2
        if normalized_offset != offset:
            direct = stack_vars_by_offset.get(normalized_offset)
            if direct is not None:
                return direct

        # Positive stack slots are arguments in the x86-16 calling
        # convention model we use here. If we have no exact materialization
        # yet, synthesize the slot rather than aliasing it to a covering local
        # variable. That keeps argument storage distinct from locals and avoids
        # collapsing different stack objects onto the same C variable name.
        if offset > 0:
            return _materialize_stack_cvar(offset, None)

        best = None
        best_size = None
        for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            if not isinstance(variable, SimStackVariable):
                continue
            base_offset = getattr(variable, "offset", None)
            size = getattr(variable, "size", None)
            if not isinstance(base_offset, int) or not isinstance(size, int):
                continue
            if base_offset <= offset < base_offset + size:
                if best is None or size < best_size:
                    best = cvar
                    best_size = size
        if best is not None:
            return best
        return _materialize_stack_cvar(offset, None)

    def sync_arg_list_from_annotations() -> bool:
        arg_offsets = [
            offset
            for offset in sorted(stack_specs)
            if isinstance(offset, int) and offset > 0
        ]
        if not arg_offsets:
            return False

        resolved_args = []
        for offset in arg_offsets:
            cvar = resolve_stack_cvar(offset)
            if isinstance(cvar, CVariable):
                resolved_args.append(cvar)

        if not resolved_args:
            return False

        current_proto = getattr(codegen.cfunc, "functy", None) or getattr(func, "prototype", None)
        if current_proto is None:
            return False

        existing_args = list(getattr(codegen.cfunc, "arg_list", ()) or ())
        target_arg_count = len(resolved_args)

        new_args = list(getattr(current_proto, "args", ()) or ())
        if len(new_args) < target_arg_count:
            new_args.extend(
                SimTypeShort(False).with_arch(getattr(getattr(codegen, "project", None), "arch", None))
                for _ in range(target_arg_count - len(new_args))
            )
        elif len(new_args) > target_arg_count:
            new_args = new_args[:target_arg_count]

        pointer_promoted = False
        for index, resolved_arg in enumerate(resolved_args):
            if not promote_near_pointers:
                continue
            if not _stack_arg_has_pointer_evidence_8616(codegen, getattr(resolved_arg, "variable", None)):
                continue
            pointer_type = SimTypePointer(SimTypeShort(False))
            arch = getattr(getattr(codegen, "project", None), "arch", None)
            if arch is not None and hasattr(pointer_type, "with_arch"):
                pointer_type = pointer_type.with_arch(arch)
            if getattr(resolved_arg, "variable_type", None) != pointer_type:
                resolved_arg.variable_type = pointer_type
                pointer_promoted = True
            if index < len(new_args) and new_args[index] != pointer_type:
                new_args[index] = pointer_type
                pointer_promoted = True

        desired_names = []
        for index in range(target_arg_count):
            if index < len(resolved_args):
                desired_names.append(getattr(getattr(resolved_args[index], "unified_variable", None), "name", None) or resolved_args[index].name)
            elif index < len(getattr(current_proto, "arg_names", ()) or ()):
                desired_names.append(current_proto.arg_names[index])
            else:
                desired_names.append(None)
        normalized_names = _normalize_arg_names_8616(desired_names, target_arg_count)

        if (
            len(existing_args) == target_arg_count
            and len(getattr(current_proto, "args", ()) or ()) == target_arg_count
            and list(getattr(current_proto, "arg_names", ()) or ()) == normalized_names
            and all(existing is resolved for existing, resolved in zip(existing_args, resolved_args))
            and not pointer_promoted
        ):
            return False

        new_proto = current_proto.__class__(
            new_args,
            current_proto.returnty,
            arg_names=normalized_names,
            variadic=getattr(current_proto, "variadic", False),
        )
        arch = getattr(getattr(codegen, "project", None), "arch", None)
        if arch is not None and hasattr(new_proto, "with_arch"):
            new_proto = new_proto.with_arch(arch)
        func.prototype = new_proto
        codegen.cfunc.functy = new_proto
        codegen.cfunc.arg_list = resolved_args
        return True

    def unique_stack_name(base_name: str | None) -> str | None:
        if not isinstance(base_name, str) or not base_name:
            return None
        candidate = base_name
        suffix = 2
        while candidate in used_stack_names:
            candidate = f"{base_name}_{suffix}"
            suffix += 1
        used_stack_names.add(candidate)
        return candidate

    def spec_name_for(variable):
        offset = getattr(variable, "offset", None)
        if isinstance(offset, int) and offset > 0:
            helper_name = helper_arg_name_by_offset.get(offset)
            if helper_name is not None:
                return helper_name, None
        spec = stack_specs.get(offset)
        if spec is None and isinstance(offset, int) and offset < 0:
            spec = stack_specs.get(offset + 2)
        if isinstance(spec, str):
            return spec, None
        if isinstance(spec, dict):
            return spec.get("name"), spec.get("type")
        return None, None

    stack_items = sorted(
        [
            (variable, cvar)
            for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items()
            if isinstance(variable, SimStackVariable)
        ],
        key=lambda item: (
            0 if isinstance(getattr(item[0], "offset", None), int) and getattr(item[0], "offset", 0) > 0 else 1,
            abs(getattr(item[0], "offset", 0)) if isinstance(getattr(item[0], "offset", None), int) else 0,
            getattr(item[0], "size", 0) if isinstance(getattr(item[0], "size", 0), int) else 0,
            getattr(item[0], "name", "") or "",
        ),
    )
    for variable, cvar in stack_items:
        name, vartype = spec_name_for(variable)
        if name is None:
            current = getattr(variable, "name", None)
            if current and not current.startswith(("arg_", "s_", "v")):
                name = current

        current_name = getattr(variable, "name", None)
        if isinstance(current_name, str) and current_name and current_name == name:
            used_stack_names.add(current_name)
            name_owner_offsets[current_name] = getattr(variable, "offset", 0) if isinstance(getattr(variable, "offset", None), int) else 0
            if getattr(variable, "name", None) != current_name:
                variable.name = current_name
                changed = True
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and getattr(unified, "name", None) != current_name:
                unified.name = current_name
                changed = True
            if getattr(cvar, "name", None) != current_name:
                try:
                    cvar.name = current_name
                except Exception:
                    pass
                else:
                    changed = True
            continue

        if name is not None and name in used_stack_names:
            owner_offset = name_owner_offsets.get(name)
            offset = getattr(variable, "offset", None)
            if owner_offset == offset:
                pass
            else:
                name = unique_stack_name(name)
                if name is not None:
                    name_owner_offsets[name] = offset if isinstance(offset, int) else 0
        else:
            name = unique_stack_name(name)
            if name is not None:
                offset = getattr(variable, "offset", None)
                name_owner_offsets[name] = offset if isinstance(offset, int) else 0

        if name is not None:
            target = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
            if target is not None and getattr(target, "name", None) != name:
                target.name = name
                changed = True
            if getattr(variable, "name", None) != name:
                variable.name = name
                changed = True

        if vartype is not None and getattr(cvar, "variable_type", None) != vartype:
            cvar.variable_type = vartype
            changed = True

    preferred_stack_cvars_by_identity: dict[object, CVariable] = {}
    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if not isinstance(variable, SimStackVariable):
            continue
        identity = _stack_slot_identity_for_variable(variable)
        if identity is None:
            continue
        current_best = preferred_stack_cvars_by_identity.get(identity)
        if current_best is None:
            preferred_stack_cvars_by_identity[identity] = cvar
            continue
        current_best_var = getattr(current_best, "variable", None)
        if not isinstance(current_best_var, SimStackVariable):
            preferred_stack_cvars_by_identity[identity] = cvar
            continue
        current_score = _stack_candidate_score(current_best_var, current_best, exact=True)
        new_score = _stack_candidate_score(variable, cvar, exact=True)
        if new_score > current_score:
            preferred_stack_cvars_by_identity[identity] = cvar

    def transform_stack_aliases(node):
        if not isinstance(node, CVariable):
            return node
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return node
        identity = _stack_slot_identity_for_variable(variable)
        if identity is None:
            return node
        preferred = preferred_stack_cvars_by_identity.get(identity)
        if preferred is None or preferred is node:
            return node
        return preferred

    if _replace_c_children_8616(codegen.cfunc.statements, transform_stack_aliases):
        changed = True

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if not isinstance(variable, SimMemoryVariable):
            continue
        name, vartype = global_spec_for(getattr(variable, "addr", None))
        if not isinstance(name, str):
            continue
        current = getattr(variable, "name", None)
        if current and not current.startswith(("g_", "field_")) and current != name:
            continue
        target = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
        if target is not None and getattr(target, "name", None) != name:
            target.name = name
            changed = True
        if getattr(variable, "name", None) != name:
            variable.name = name
            changed = True
        if vartype is not None and getattr(cvar, "variable_type", None) != vartype:
            cvar.variable_type = vartype
            changed = True

    def transform_globals(node):
        if not isinstance(node, CVariable):
            return node
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimMemoryVariable):
            return node
        name, vartype = global_spec_for(getattr(variable, "addr", None))
        if not isinstance(name, str):
            return node
        current = getattr(variable, "name", None)
        if current and not current.startswith(("g_", "field_")) and current != name:
            return node
        if getattr(variable, "name", None) != name:
            variable.name = name
            changed = True
        return CVariable(
            variable,
            variable_type=vartype if vartype is not None else getattr(node, "variable_type", None),
            codegen=codegen,
        )

    if _replace_c_children_8616(codegen.cfunc.statements, transform_globals):
        changed = True

    def transform(node):
        if not _structured_codegen_node_8616(node):
            return node

        direct_offset = _match_bp_stack_load_8616(node, project)
        if direct_offset is not None:
            type_ = getattr(node, "type", None)
            stack_cvar = resolve_stack_cvar(direct_offset)
            if stack_cvar is None:
                stack_cvar = _materialize_stack_cvar(direct_offset, type_)
            if stack_cvar is not None:
                return stack_cvar

        if isinstance(node, CBinaryOp) and node.op in {"Or", "Add"}:
            for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                low_offset = _match_bp_stack_load_8616(low_expr, project)
                if low_offset is None:
                    continue
                high_offset = _match_bp_stack_load_8616(high_expr, project)
                if high_offset != low_offset + 1:
                    continue
                low_cvar = stack_vars_by_offset.get(low_offset)
                high_cvar = stack_vars_by_offset.get(high_offset)
                if low_cvar is not None and high_cvar is not None:
                    low_var = getattr(low_cvar, "variable", None)
                    high_var = getattr(high_cvar, "variable", None)
                    if isinstance(low_var, SimStackVariable) and isinstance(high_var, SimStackVariable):
                        if not _stack_slot_identity_can_join(low_var, high_var):
                            continue
                cvar = low_cvar
                if cvar is not None:
                    return cvar
        return node

    if _replace_c_children_8616(codegen.cfunc.statements, transform):
        changed = True

    if sync_arg_list_from_annotations():
        changed = True

    return changed

def _prune_unused_unnamed_memory_declarations_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    used_variables: set[int] = set()
    for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements):
        if not isinstance(node, CVariable):
            continue
        variable = getattr(node, "variable", None)
        if variable is not None:
            used_variables.add(id(variable))
        unified = getattr(node, "unified_variable", None)
        if unified is not None:
            used_variables.add(id(unified))

    changed = False
    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable in list(variables_in_use):
            if not isinstance(variable, SimMemoryVariable):
                continue
            name = getattr(variable, "name", None)
            if not isinstance(name, str) or not name.startswith("g_"):
                continue
            if id(variable) in used_variables:
                continue
            cvar = variables_in_use[variable]
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and id(unified) in used_variables:
                continue
            del variables_in_use[variable]
            changed = True

    return changed

def _prune_unused_flag_assignments_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    flags_offset = project.arch.registers.get("flags", (None, None))[0]
    if flags_offset is None:
        return False

    used_registers: set[int] = set()
    used_variables: set[int] = set()

    def collect_reads(node, *, assignment_lhs: bool = False):
        if not _structured_codegen_node_8616(node):
            return
        if isinstance(node, CVariable) and not assignment_lhs:
            variable = getattr(node, "variable", None)
            if variable is not None:
                used_variables.add(id(variable))
                if isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) is not None:
                    used_registers.add(variable.reg)
            unified = getattr(node, "unified_variable", None)
            if unified is not None:
                used_variables.add(id(unified))
                if isinstance(unified, SimRegisterVariable) and getattr(unified, "reg", None) is not None:
                    used_registers.add(unified.reg)
            return

        for attr in ("rhs", "expr", "operand", "condition", "cond", "body", "iffalse", "iftrue", "callee_target", "else_node", "retval"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                collect_reads(child)
        lhs = getattr(node, "lhs", None)
        if _structured_codegen_node_8616(lhs):
            collect_reads(lhs, assignment_lhs=isinstance(node, CAssignment))
        for attr in ("args", "operands", "statements"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item):
                    collect_reads(item)
                elif isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem):
                            collect_reads(subitem)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for cond, body in pairs:
                if _structured_codegen_node_8616(cond):
                    collect_reads(cond)
                if _structured_codegen_node_8616(body):
                    collect_reads(body)

    collect_reads(codegen.cfunc.statements)

    changed = False

    def visit(node):
        nonlocal changed
        if isinstance(node, CStatements):
            new_statements = []
            for stmt in node.statements:
                visit(stmt)
                if isinstance(stmt, CAssignment) and isinstance(stmt.lhs, CVariable):
                    variable = getattr(stmt.lhs, "variable", None)
                    if (
                        isinstance(variable, SimRegisterVariable)
                        and getattr(variable, "reg", None) == flags_offset
                        and id(variable) not in used_variables
                        and getattr(variable, "reg", None) not in used_registers
                    ):
                        changed = True
                        continue
                new_statements.append(stmt)
            node.statements = new_statements

        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                visit(child)

        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _cond, body in pairs:
                if _structured_codegen_node_8616(body):
                    visit(body)

    visit(codegen.cfunc.statements)
    return changed

def _c_expr_uses_register_8616(node, reg_offset: int) -> bool:
    if not _structured_codegen_node_8616(node):
        return False
    if isinstance(node, CVariable):
        variable = getattr(node, "variable", None)
        return isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) == reg_offset

    for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond", "body", "iftrue", "iffalse", "callee_target", "else_node", "retval"):
        child = getattr(node, attr, None)
        if _structured_codegen_node_8616(child) and _c_expr_uses_register_8616(child, reg_offset):
            return True

    for attr in ("args", "operands", "statements"):
        seq = getattr(node, attr, None)
        if not seq:
            continue
        for item in seq:
            if _structured_codegen_node_8616(item) and _c_expr_uses_register_8616(item, reg_offset):
                return True
            if isinstance(item, tuple):
                for subitem in item:
                    if _structured_codegen_node_8616(subitem) and _c_expr_uses_register_8616(subitem, reg_offset):
                        return True

    pairs = getattr(node, "condition_and_nodes", None)
    if pairs:
        for cond, body in pairs:
            if _structured_codegen_node_8616(cond) and _c_expr_uses_register_8616(cond, reg_offset):
                return True
            if _structured_codegen_node_8616(body) and _c_expr_uses_register_8616(body, reg_offset):
                return True

    return False

def _stmt_reads_reg_before_write_8616(stmt, reg_offset: int) -> tuple[bool, bool]:
    if not _structured_codegen_node_8616(stmt):
        return False, False

    if isinstance(stmt, CAssignment):
        lhs = stmt.lhs
        writes = (
            isinstance(lhs, CVariable)
            and isinstance(getattr(lhs, "variable", None), SimRegisterVariable)
            and getattr(lhs.variable, "reg", None) == reg_offset
        )
        reads = _c_expr_uses_register_8616(stmt.rhs, reg_offset)
        return reads, writes

    if isinstance(stmt, CStatements):
        for substmt in stmt.statements:
            reads, writes = _stmt_reads_reg_before_write_8616(substmt, reg_offset)
            if reads:
                return True, writes
            if writes:
                return False, True
        return False, False

    if type(stmt).__name__ == "CIfElse":
        cond_nodes = getattr(stmt, "condition_and_nodes", None) or ()
        for cond, body in cond_nodes:
            if _c_expr_uses_register_8616(cond, reg_offset):
                return True, False
            reads, writes = _stmt_reads_reg_before_write_8616(body, reg_offset)
            if reads:
                return True, writes
        else_node = getattr(stmt, "else_node", None)
        if else_node is not None:
            reads, writes = _stmt_reads_reg_before_write_8616(else_node, reg_offset)
            if reads:
                return True, writes
        return False, False

    if type(stmt).__name__ == "CWhileLoop":
        cond = getattr(stmt, "condition", None)
        if _structured_codegen_node_8616(cond) and _c_expr_uses_register_8616(cond, reg_offset):
            return True, False
        body = getattr(stmt, "body", None)
        if body is not None:
            return _stmt_reads_reg_before_write_8616(body, reg_offset)
        return False, False

    return _c_expr_uses_register_8616(stmt, reg_offset), False

def _prune_overwritten_flag_assignments_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    flags_offset = project.arch.registers.get("flags", (None, None))[0]
    if flags_offset is None:
        return False

    changed = False

    def visit(node):
        nonlocal changed
        if isinstance(node, CStatements):
            new_statements = []
            statements = list(node.statements)
            for idx, stmt in enumerate(statements):
                remove = False
                if isinstance(stmt, CAssignment) and isinstance(stmt.lhs, CVariable):
                    variable = getattr(stmt.lhs, "variable", None)
                    if isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) == flags_offset:
                        remainder = CStatements(statements[idx + 1 :], codegen=codegen)
                        reads, _writes = _stmt_reads_reg_before_write_8616(remainder, flags_offset)
                        if not reads:
                            remove = True
                if not remove:
                    new_statements.append(stmt)
                    visit(stmt)
                else:
                    changed = True
            node.statements = new_statements
            return

        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                visit(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _cond, body in pairs:
                if _structured_codegen_node_8616(body):
                    visit(body)

    visit(codegen.cfunc.statements)
    return changed
