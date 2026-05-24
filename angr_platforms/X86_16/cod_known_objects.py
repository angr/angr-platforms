from __future__ import annotations

import re
from collections import OrderedDict
from dataclasses import dataclass

from angr.sim_type import SimStruct, SimTypeChar, SimTypePointer, SimTypeShort, SimUnion


@dataclass(frozen=True)
class CODKnownObjectSpec:
    name: str
    type: object
    size: int
    field_names: tuple[str, ...]
    field_offsets: tuple[int, ...]
    field_widths: tuple[int, ...]
    packed: bool
    allowed_views: tuple[str, ...]
    segment_domain: str
    type_name: str


def _make_union_regs_type() -> SimUnion:
    word = SimTypeShort(False)
    byte = SimTypeChar()

    x_fields = OrderedDict(
        (
            ("ax", word),
            ("bx", word),
            ("cx", word),
            ("dx", word),
            ("si", word),
            ("di", word),
            ("cflag", word),
        )
    )
    h_fields = OrderedDict(
        (
            ("al", byte),
            ("ah", byte),
            ("bl", byte),
            ("bh", byte),
            ("cl", byte),
            ("ch", byte),
            ("dl", byte),
            ("dh", byte),
        )
    )
    return SimUnion(
        {
            "x": SimStruct(x_fields, name="x", pack=True),
            "h": SimStruct(h_fields, name="h", pack=True),
        },
        name="union REGS",
    )


def _make_sregs_type() -> SimStruct:
    word = SimTypeShort(False)
    return SimStruct(
        OrderedDict(
            (
                ("es", word),
                ("cs", word),
                ("ss", word),
                ("ds", word),
            )
        ),
        name="struct SREGS",
        pack=True,
    )


def _make_exe_load_params_type() -> SimStruct:
    word = SimTypeShort(False)
    fields = OrderedDict(
        (
            ("envSegment", word),
            ("cmdlineOffset", word),
            ("cmdlineSegment", word),
            ("fcb1Offset", word),
            ("fcb1Segment", word),
            ("fcb2Offset", word),
            ("fcb2Segment", word),
            ("sp", word),
            ("ss", word),
            ("ip", word),
            ("cs", word),
        )
    )
    return SimStruct(fields, name="struct ExeLoadParams", pack=True)


def _make_ovl_load_params_type() -> SimStruct:
    word = SimTypeShort(False)
    return SimStruct(
        OrderedDict((("segment", word), ("reloc", word))),
        name="struct OvlLoadParams",
        pack=True,
    )


def _make_ovl_header_type() -> SimTypePointer:
    word = SimTypeShort(False)
    header = SimStruct(
        OrderedDict((("code_segment", word), ("slot", word))),
        name="struct OvlHeader",
        pack=True,
    )
    return SimTypePointer(header)


def _make_slot_array_type() -> SimTypePointer:
    return SimTypePointer(SimTypeShort(False))


def _type_name(type_obj: object) -> str:
    return getattr(type_obj, "name", None) or type_obj.__class__.__name__


_KNOWN_COD_OBJECT_SPECS: dict[str, CODKnownObjectSpec] = {
    "rin": CODKnownObjectSpec(
        "rin",
        _make_union_regs_type(),
        14,
        ("x", "h"),
        (0, 0),
        (14, 8),
        True,
        ("x", "h"),
        "register",
        _type_name(_make_union_regs_type()),
    ),
    "rout": CODKnownObjectSpec(
        "rout",
        _make_union_regs_type(),
        14,
        ("x", "h"),
        (0, 0),
        (14, 8),
        True,
        ("x", "h"),
        "register",
        _type_name(_make_union_regs_type()),
    ),
    "sreg": CODKnownObjectSpec(
        "sreg",
        _make_sregs_type(),
        8,
        ("es", "cs", "ss", "ds"),
        (0, 2, 4, 6),
        (2, 2, 2, 2),
        True,
        (),
        "register",
        _type_name(_make_sregs_type()),
    ),
    "exeLoadParams": CODKnownObjectSpec(
        "exeLoadParams",
        _make_exe_load_params_type(),
        22,
        (
            "envSegment",
            "cmdlineOffset",
            "cmdlineSegment",
            "fcb1Offset",
            "fcb1Segment",
            "fcb2Offset",
            "fcb2Segment",
            "sp",
            "ss",
            "ip",
            "cs",
        ),
        (0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20),
        (2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2),
        True,
        (),
        "stack",
        _type_name(_make_exe_load_params_type()),
    ),
    "ovlLoadParams": CODKnownObjectSpec(
        "ovlLoadParams",
        _make_ovl_load_params_type(),
        4,
        ("segment", "reloc"),
        (0, 2),
        (2, 2),
        True,
        (),
        "global",
        _type_name(_make_ovl_load_params_type()),
    ),
    "ovlHeader": CODKnownObjectSpec(
        "ovlHeader",
        _make_ovl_header_type(),
        4,
        ("code_segment", "slot"),
        (0, 2),
        (2, 2),
        True,
        (),
        "global",
        _type_name(_make_ovl_header_type()),
    ),
    "slotArray": CODKnownObjectSpec(
        "slotArray",
        _make_slot_array_type(),
        2,
        (),
        (),
        (),
        False,
        (),
        "global",
        _type_name(_make_slot_array_type()),
    ),
}


def _sanitize_known_object_name(name: str | None) -> str | None:
    if not isinstance(name, str) or not name:
        return None
    name = name.lstrip("_")
    if name.startswith("$") and "_" in name:
        name = name.rsplit("_", 1)[-1]
    prefixed_match = re.match(r"^[A-Za-z]+\d+_(?P<rest>.+)$", name)
    if prefixed_match is not None:
        name = prefixed_match.group("rest")
    return name


def known_cod_object_spec(name: str | None) -> CODKnownObjectSpec | None:
    sanitized = _sanitize_known_object_name(name)
    if sanitized is None:
        return None
    return _KNOWN_COD_OBJECT_SPECS.get(sanitized)


def canonical_known_cod_object_name(name: str | None) -> str | None:
    spec = known_cod_object_spec(name)
    if spec is not None:
        return spec.name
    return _sanitize_known_object_name(name)


def known_cod_object_names() -> tuple[str, ...]:
    return tuple(_KNOWN_COD_OBJECT_SPECS)


def describe_x86_16_cod_known_objects() -> dict[str, object]:
    return {
        "count": len(_KNOWN_COD_OBJECT_SPECS),
        "names": known_cod_object_names(),
        "specs": tuple(
            {
                "name": spec.name,
                "size": spec.size,
                "field_names": spec.field_names,
                "field_offsets": spec.field_offsets,
                "field_widths": spec.field_widths,
                "packed": spec.packed,
                "allowed_views": spec.allowed_views,
                "segment_domain": spec.segment_domain,
                "type_name": spec.type_name,
                "type": spec.type,
            }
            for spec in _KNOWN_COD_OBJECT_SPECS.values()
        ),
    }



