from __future__ import annotations

from pathlib import Path

import decompile
from inertia_decompiler.default_signature_catalog import default_signature_catalog_path
from inertia_decompiler import sidecar_metadata


LIFE_EXE = Path(__file__).resolve().parents[2] / "LIFE.EXE"


def test_life_metadata_marks_amallocbrk_as_signature_matched():
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(
        LIFE_EXE,
        project,
        signature_catalog=default_signature_catalog_path(),
        allow_peer_exe=False,
    )

    assert metadata is not None
    assert 0x12BA3 in metadata.signature_code_addrs
    assert metadata.code_labels.get(0x12BA3) == "amallocbrk"


def test_life_metadata_marks_fcmp_and_catox_as_signature_matched():
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(
        LIFE_EXE,
        project,
        signature_catalog=default_signature_catalog_path(),
        allow_peer_exe=False,
    )

    assert metadata is not None
    assert 0x10FF6 in metadata.signature_code_addrs
    assert 0x1191A in metadata.signature_code_addrs
    assert metadata.code_labels.get(0x10FF6) == "fcmp"
    assert metadata.code_labels.get(0x1191A) == "catox"
