from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from inertia_decompiler.cli_access_object_hints import AccessTraitObjectHint
from inertia_decompiler.cli_access_object_hints import _build_stable_access_object_hints
from inertia_decompiler.cli_access_profiles import build_access_trait_evidence_profiles
from inertia_decompiler.cli_access_rewrite_artifact import (
    AccessRewriteArtifact,
    has_access_rewrite_artifact,
    load_access_rewrite_artifact,
)
from inertia_decompiler.cli_access_trait_rewrite import _attach_access_trait_field_names


def test_access_rewrite_artifact_loader_uses_cache_without_raw_traits():
    project = SimpleNamespace(
        _inertia_access_traits={0x4010: "invalid"},
        _inertia_access_rewrite_artifact_cache={
            0x4010: AccessRewriteArtifact(
                object_hints={
                    ("stack", "bp", -4): AccessTraitObjectHint(
                        base_key=("stack", "bp", -4),
                        kind="stack",
                        candidates=((0, 2, 1),),
                    )
                },
                refusal_reasons={},
            )
        },
    )

    artifact = load_access_rewrite_artifact(
        project,
        0x4010,
        build_access_trait_evidence_profiles=lambda _traits: {},
        build_stable_access_object_hints=lambda _traits: {},
    )

    assert artifact is not None
    assert has_access_rewrite_artifact(
        project,
        0x4010,
        build_access_trait_evidence_profiles=lambda _traits: {},
        build_stable_access_object_hints=lambda _traits: {},
    ) is True
    assert ("stack", "bp", -4) in artifact.object_hints


def test_attach_access_trait_field_names_uses_prebuilt_artifact_cache():
    variable = SimStackVariable(-4, 2, base="bp", name="v1", region=0x4010)
    codegen = SimpleNamespace(cstyle_null_cmp=False, next_idx=lambda _name: 0)
    cfunc = SimpleNamespace(addr=0x4010, statements=structured_c.CVariable(variable, codegen=codegen))
    codegen.cfunc = cfunc
    project = SimpleNamespace(
        _inertia_access_traits={0x4010: "invalid"},
        _inertia_access_rewrite_artifact_cache={
            0x4010: AccessRewriteArtifact(
                object_hints={
                    ("stack", "bp", -4): AccessTraitObjectHint(
                        base_key=("stack", "bp", -4),
                        kind="stack",
                        candidates=((0, 2, 1),),
                    )
                },
                refusal_reasons={},
            )
        },
    )

    changed = _attach_access_trait_field_names(
        project,
        codegen,
        should_attach_access_trait_names=lambda _codegen: True,
        load_access_rewrite_artifact=lambda current_project, function_addr: load_access_rewrite_artifact(
            current_project,
            function_addr,
            build_access_trait_evidence_profiles=lambda _traits: {},
            build_stable_access_object_hints=lambda _traits: {},
        ),
        stable_access_object_hint_for_key=lambda hints, base_key: hints.get(base_key),
        access_trait_variable_key=lambda current_variable: ("stack", "bp", current_variable.offset),
        stack_object_name=lambda offset: f"stack_{abs(offset):x}",
        access_trait_field_name=lambda offset, _size: f"field_{offset:x}",
        replace_c_children=lambda _root, _transform: False,
    )

    assert changed is True
    assert variable.name == "stack_4"
    assert getattr(codegen.cfunc.statements, "name", None) == "stack_4"


def test_access_rewrite_artifact_loader_preserves_storage_object_refusal_reason():
    project = SimpleNamespace(
        _inertia_access_traits={
            0x4010: {
                "base_const": {
                    ("ss", ("stack", "bp", -4), 4, 2, 1): 1,
                },
                "array_evidence": {
                    (("stack", "bp", -4), ("reg", 2), 2, 4, 2): 1,
                },
            }
        }
    )

    artifact = load_access_rewrite_artifact(
        project,
        0x4010,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        build_stable_access_object_hints=lambda traits: _build_stable_access_object_hints(
            traits,
            build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        ),
    )

    assert artifact is not None
    assert artifact.object_hints == {}
    assert artifact.refusal_reasons == {
        ("stack", "bp", -4): "mixed_or_unstable_evidence",
    }


def test_attach_access_trait_field_names_refuses_mixed_or_unstable_evidence():
    variable = SimStackVariable(-4, 2, base="bp", name="v1", region=0x4010)
    codegen = SimpleNamespace(cstyle_null_cmp=False, next_idx=lambda _name: 0)
    cfunc = SimpleNamespace(addr=0x4010, statements=structured_c.CVariable(variable, codegen=codegen))
    codegen.cfunc = cfunc
    project = SimpleNamespace(
        _inertia_access_traits={0x4010: "invalid"},
        _inertia_access_rewrite_artifact_cache={
            0x4010: AccessRewriteArtifact(
                object_hints={},
                refusal_reasons={
                    ("stack", "bp", -4): "mixed_or_unstable_evidence",
                },
            )
        },
    )

    changed = _attach_access_trait_field_names(
        project,
        codegen,
        should_attach_access_trait_names=lambda _codegen: True,
        load_access_rewrite_artifact=lambda current_project, function_addr: load_access_rewrite_artifact(
            current_project,
            function_addr,
            build_access_trait_evidence_profiles=lambda _traits: {},
            build_stable_access_object_hints=lambda _traits: {},
        ),
        stable_access_object_hint_for_key=lambda hints, base_key: hints.get(base_key),
        access_trait_variable_key=lambda current_variable: ("stack", "bp", current_variable.offset),
        stack_object_name=lambda offset: f"stack_{abs(offset):x}",
        access_trait_field_name=lambda offset, _size: f"field_{offset:x}",
        replace_c_children=lambda _root, _transform: False,
    )

    assert changed is False
    assert variable.name == "v1"
    assert getattr(codegen.cfunc.statements, "name", None) == "v1"
