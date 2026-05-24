import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeBottom, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable

from angr_platforms.X86_16.annotations import ANNOTATION_KEY
from angr_platforms.X86_16.arch_86_16 import Arch86_16

REPO_ROOT = Path(__file__).resolve().parents[2]
DECOMPILE_PATH = REPO_ROOT / "decompile.py"

_spec = spec_from_file_location("decompile", DECOMPILE_PATH)
assert _spec is not None and _spec.loader is not None
_decompile = module_from_spec(_spec)
sys.modules[_spec.name] = _decompile
_spec.loader.exec_module(_decompile)

from angr_platforms.X86_16 import decompiler_postprocess as postprocess


class _FakePrototype:
    def __init__(self, args=None, returnty=None, *, arg_names=None, variadic=False):
        self.args = [SimTypeShort(False)] if args is None else list(args)
        self.returnty = SimTypeLong() if returnty is None else returnty
        self.arg_names = ("a0",) if arg_names is None else arg_names
        self.variadic = variadic

    def with_arch(self, _arch):
        try:
            self.returnty = self.returnty.with_arch(_arch)
        except Exception:
            pass
        self.args = [arg.with_arch(_arch) if hasattr(arg, "with_arch") else arg for arg in self.args]
        return self


def test_bp_stack_prototype_promotion_rejects_mixed_stack_regions(monkeypatch):
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1)
    project = SimpleNamespace(
        arch=SimpleNamespace(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: SimpleNamespace(
                    prototype=_FakePrototype(),
                    is_prototype_guessed=True,
                )
            )
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(statements=[]),
            variables_in_use={
                SimStackVariable(4, 1, base="bp", name="a0", region=0x1000): SimpleNamespace(),
                SimStackVariable(6, 1, base="bp", name="a1", region=0x2000): SimpleNamespace(),
            },
        )
    )
    ret0 = structured_c.CReturn(SimpleNamespace(), codegen=c_codegen)
    ret1 = structured_c.CReturn(SimpleNamespace(), codegen=c_codegen)
    codegen.cfunc.statements.statements = [ret0, ret1]

    fake_nodes = [object(), object()]
    monkeypatch.setattr(postprocess, "_iter_c_nodes_deep_8616", lambda _retval: iter(fake_nodes))
    monkeypatch.setattr(postprocess, "_match_bp_stack_load_8616", lambda node, _project: 4 if node is fake_nodes[0] else 6)

    assert not postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)


def test_bp_stack_prototype_promotion_uses_annotated_stack_vars():
    func = SimpleNamespace(
        prototype=_FakePrototype(
            args=[SimTypeShort(False)],
            arg_names=("funcNumber",),
            returnty=SimTypeShort(False),
        ),
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    4: {"name": "ovlLoadSegment"},
                    6: {"name": "funcNumber"},
                },
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=SimpleNamespace(statements=[]), variables_in_use={})
    )

    changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert changed is True
    assert len(func.prototype.args) == 2
    assert func.prototype.arg_names == ["ovlLoadSegment", "funcNumber"]


def test_bp_stack_prototype_promotion_preserves_pointer_evidence():
    stack_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    stack_cvar = structured_c.CVariable(stack_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    func = SimpleNamespace(
        prototype=_FakePrototype(
            args=[SimTypeShort(False)],
            arg_names=("s",),
            returnty=SimTypeShort(False),
        ),
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    4: {"name": "s"},
                },
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(
                statements=[
                    structured_c.CUnaryOp("Dereference", stack_cvar, codegen=c_codegen),
                ]
            ),
            variables_in_use={stack_var: stack_cvar},
        )
    )
    stack_cvar.codegen = codegen

    changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.args[0], SimTypePointer)
    assert "s *" in str(func.prototype.args[0]) or func.prototype.args[0].__class__.__name__ == "SimTypePointer"


def test_bp_stack_prototype_promotion_preserves_pointer_evidence_without_annotations():
    stack_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    stack_cvar = structured_c.CVariable(stack_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    func = SimpleNamespace(
        prototype=_FakePrototype(
            args=[SimTypeShort(False)],
            arg_names=("s",),
            returnty=SimTypeShort(False),
        ),
        is_prototype_guessed=True,
        info={ANNOTATION_KEY: {}},
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(
                statements=[
                    structured_c.CUnaryOp("Dereference", stack_cvar, codegen=c_codegen),
                ]
            ),
            variables_in_use={stack_var: stack_cvar},
            arg_list=[stack_cvar],
            functy=func.prototype,
        )
    )
    stack_cvar.codegen = codegen

    changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.args[0], SimTypePointer)
    assert codegen.cfunc.functy is func.prototype
    assert codegen.cfunc.arg_list == [stack_cvar]


def test_bp_stack_prototype_promotion_respects_scalar_source_decl_over_weak_pointer_promotion():
    stack_var = SimStackVariable(6, 2, base="bp", name="iRow2", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    stack_cvar = structured_c.CVariable(stack_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    func = SimpleNamespace(
        prototype=_FakePrototype(
            args=[SimTypeShort(False), SimTypeShort(False)],
            arg_names=("iRow1", "iRow2"),
            returnty=SimTypeBottom(),
        ),
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    4: {"name": "iRow1"},
                    6: {"name": "iRow2"},
                },
                "source_lines": (
                    "void SwapBars(int iRow1, int iRow2)",
                    "{",
                    "}",
                ),
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)),
    )
    codegen = SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(
                statements=[
                    structured_c.CUnaryOp("Dereference", stack_cvar, codegen=c_codegen),
                ]
            ),
            variables_in_use={stack_var: stack_cvar},
            arg_list=[None, stack_cvar],
            functy=func.prototype,
        )
    )
    stack_cvar.codegen = codegen

    postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert not isinstance(func.prototype.args[1], SimTypePointer)


def test_bp_stack_prototype_promotion_shrinks_overguessed_stack_arguments():
    prototype = _FakePrototype(
        args=[SimTypeShort(False), SimTypeShort(False)],
        arg_names=("s", "a1"),
        returnty=SimTypeShort(False),
    )
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    4: {"name": "s"},
                },
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(statements=[]),
            variables_in_use={},
            arg_list=["first", "second"],
            functy=prototype,
        )
    )

    changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert changed is True
    assert len(func.prototype.args) == 1
    assert func.prototype.arg_names == ["s"]
    assert codegen.cfunc.arg_list == ["first"]
    assert codegen.cfunc.functy is func.prototype


def test_bp_stack_prototype_promotion_counts_only_real_stack_arguments():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1)
    prototype = _FakePrototype(args=[], arg_names=(), returnty=SimTypeShort(False))
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=True, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=SimpleNamespace(statements=[]), variables_in_use={})
    )
    ret = structured_c.CReturn(SimpleNamespace(), codegen=c_codegen)
    codegen.cfunc.statements.statements = [ret]
    fake_node = object()

    def fake_iter(_retval):
        return iter([fake_node])

    original_iter = postprocess._iter_c_nodes_deep_8616
    original_match = postprocess._match_bp_stack_load_8616
    try:
        postprocess._iter_c_nodes_deep_8616 = fake_iter
        postprocess._match_bp_stack_load_8616 = lambda node, _project: 4 if node is fake_node else None

        changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)
    finally:
        postprocess._iter_c_nodes_deep_8616 = original_iter
        postprocess._match_bp_stack_load_8616 = original_match

    assert changed is True
    assert len(func.prototype.args) == 1
    assert func.prototype.arg_names == ["a0"]


def test_bp_stack_return_address_pruning_keeps_annotated_arguments():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    arg_var = SimStackVariable(2, 2, base="bp", name="segment", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    prototype = _FakePrototype(args=[SimTypeShort(False)], arg_names=("segment",), returnty=SimTypeShort(False))
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
        info={ANNOTATION_KEY: {"stack_vars": {2: {"name": "segment"}}}},
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, arg_list=[arg_cvar], statements=structured_c.CStatements([], codegen=c_codegen))
    )

    changed = postprocess._prune_return_address_stack_arguments_8616(project, codegen)

    assert changed is False
    assert codegen.cfunc.arg_list == [arg_cvar]
    assert func.prototype.arg_names == ("segment",)


def test_classify_return_shape_promotes_scalar_returns_from_void_prototypes():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    ret = structured_c.CReturn(
        structured_c.CConstant(0, SimTypeShort(False), codegen=c_codegen),
        codegen=c_codegen,
    )
    prototype = _FakePrototype(returnty=SimTypeBottom())
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=True, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([ret], codegen=c_codegen))
    )

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeShort)
    assert func.prototype.returnty.size == 16


def test_classify_return_shape_uses_source_return_lines_when_returns_are_missing():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    prototype = _FakePrototype(returnty=SimTypeBottom())
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "source_return_lines": ("return MK_FP(sreg.es, rout.x.bx);",),
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)),
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([], codegen=c_codegen)))

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeLong)
    assert func.prototype.returnty.size == 32


def test_classify_return_shape_uses_void_source_decl_when_returns_are_missing():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    prototype = _FakePrototype(args=[], arg_names=(), returnty=SimTypeShort(False))
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "source_lines": ("void ReInitBars()", "{", "}",),
                "source_return_lines": (),
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)),
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([], codegen=c_codegen)))

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeBottom)


def test_classify_return_shape_treats_explicit_void_returns_as_void():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    ret = structured_c.CReturn(None, codegen=c_codegen)
    prototype = _FakePrototype(args=[], arg_names=(), returnty=SimTypeShort(False))
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=True, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)),
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([ret], codegen=c_codegen)))

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeBottom)


def test_classify_return_shape_promotes_far_pointer_returns_from_void_prototypes():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    ret = structured_c.CReturn(
        structured_c.CFunctionCall(
            "MK_FP",
            None,
            [
                structured_c.CConstant(0x1234, SimTypeShort(False), codegen=c_codegen),
                structured_c.CConstant(0x20, SimTypeShort(False), codegen=c_codegen),
            ],
            codegen=c_codegen,
        ),
        codegen=c_codegen,
    )
    prototype = _FakePrototype(returnty=SimTypeBottom())
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=True, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([ret], codegen=c_codegen))
    )

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeLong)
    assert func.prototype.returnty.size == 32
