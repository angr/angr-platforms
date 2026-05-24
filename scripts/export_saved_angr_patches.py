#!/usr/bin/env python3
from __future__ import annotations

import argparse
import difflib
import json
import re
from pathlib import Path


def _sanitize_relpath(relpath: str) -> str:
    relpath = relpath.lstrip("/")
    relpath = relpath.replace("../", "up__/")
    return re.sub(r"[^A-Za-z0-9._/-]", "_", relpath)


def _saved_backup_path(saved_root: Path, relpath: str) -> Path:
    direct = (saved_root / relpath).resolve()
    if direct.exists():
        return direct

    trimmed = relpath
    while trimmed.startswith("../"):
        trimmed = trimmed[3:]
    fallback = (saved_root / trimmed).resolve()
    return fallback


def _read_text(path: Path) -> list[str]:
    return path.read_text().splitlines(keepends=True)


def export_patches(backup_dir: Path, site_packages_root: Path, label: str) -> list[Path]:
    manifest = json.loads((backup_dir / "patched_files_manifest.json").read_text())
    relpaths = manifest.get(label, [])
    saved_root = backup_dir / "patched_files" / label
    out_root = backup_dir / "patches" / label
    out_root.mkdir(parents=True, exist_ok=True)

    combined_lines: list[str] = []
    written: list[Path] = []

    for relpath in relpaths:
        old_path = (site_packages_root / relpath).resolve()
        new_path = _saved_backup_path(saved_root, relpath)
        if not new_path.exists():
            continue

        diff_lines = list(
            difflib.unified_diff(
                _read_text(old_path),
                _read_text(new_path),
                fromfile=str(old_path),
                tofile=str(new_path),
                n=3,
            )
        )
        if not diff_lines:
            continue

        patch_path = out_root / f"{_sanitize_relpath(relpath)}.patch"
        patch_path.parent.mkdir(parents=True, exist_ok=True)
        patch_path.write_text("".join(diff_lines))
        written.append(patch_path)
        combined_lines.extend(diff_lines)

    combined_path = backup_dir / "patches" / f"{label}-combined.patch"
    combined_path.parent.mkdir(parents=True, exist_ok=True)
    combined_path.write_text("".join(combined_lines))
    written.append(combined_path)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description="Export unified patch files from saved angr stack backups.")
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--site-packages-root", type=Path, required=True)
    parser.add_argument("--label", required=True, help="Manifest key, e.g. python3.12")
    args = parser.parse_args()

    written = export_patches(args.backup_dir, args.site_packages_root, args.label)
    for path in written:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
