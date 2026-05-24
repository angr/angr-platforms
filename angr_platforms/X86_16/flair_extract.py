from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from inertia_decompiler.signature_matching_policy import signature_matching_disabled


@dataclass(frozen=True)
class FlairStartupPattern:
    pat_path: str
    public_names: tuple[tuple[int, str], ...]
    compiler_tag: str | None
    library_tag: str | None


@dataclass(frozen=True)
class FlairSigLibrary:
    sig_path: str
    title: str
    os_types: str
    app_types: str
    file_types: str


_PUBLIC_NAME_RE = re.compile(r":(?P<offset>-?[0-9A-Fa-f]{4})\s+(?P<name>[A-Za-z_$?@][\w$?@]*)")
_TAG_RE = re.compile(r":(?P<key>[a-z])=(?P<value>[^:\s]+)")


def match_flair_startup_entry(
    entry_bytes: bytes,
    flair_root: Path,
    *,
    limit: int = 8,
) -> tuple[FlairStartupPattern, ...]:
    if signature_matching_disabled():
        return ()
    matches: list[FlairStartupPattern] = []
    for pat_path in sorted((flair_root / "startup").rglob("*.pat")):
        try:
            for line in pat_path.read_text(errors="ignore").splitlines():
                parsed = _parse_pat_line(line)
                if parsed is None:
                    continue
                pattern_bytes, public_names, tags = parsed
                if _pattern_matches(entry_bytes, pattern_bytes):
                    matches.append(
                        FlairStartupPattern(
                            pat_path=str(pat_path),
                            public_names=tuple(public_names),
                            compiler_tag=tags.get("c"),
                            library_tag=tags.get("s"),
                        )
                    )
                    if len(matches) >= limit:
                        return tuple(matches)
                    break
        except OSError:
            continue
    return tuple(matches)


def list_flair_sig_libraries(flair_root: Path) -> tuple[FlairSigLibrary, ...]:
    if signature_matching_disabled():
        return ()
    return _list_flair_sig_libraries_cached(str(flair_root))


@lru_cache(maxsize=2)
def _list_flair_sig_libraries_cached(flair_root: str) -> tuple[FlairSigLibrary, ...]:
    root = Path(flair_root)
    dumpsig = root / "bin" / "linux" / "dumpsig"
    if not dumpsig.exists():
        return ()
    libraries: list[FlairSigLibrary] = []
    for sig_path in sorted(root.rglob("*.sig")):
        try:
            proc = subprocess.run(
                [str(dumpsig), str(sig_path)],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode != 0:
            continue
        title = ""
        os_types = ""
        app_types = ""
        file_types = ""
        for line in proc.stdout.splitlines():
            if line.startswith("Signature     : "):
                title = line.split(":", 1)[1].strip()
            elif line.startswith("OS types      : "):
                os_types = line.split(":", 1)[1].strip()
            elif line.startswith("App types     : "):
                app_types = line.split(":", 1)[1].strip()
            elif line.startswith("File types    : "):
                file_types = line.split(":", 1)[1].strip()
            if title and os_types and app_types and file_types:
                break
        if title:
            libraries.append(
                FlairSigLibrary(
                    sig_path=str(sig_path),
                    title=title,
                    os_types=os_types,
                    app_types=app_types,
                    file_types=file_types,
                )
            )
    return tuple(libraries)


def _parse_pat_line(
    line: str,
) -> tuple[list[int | None], list[tuple[int, str]], dict[str, str]] | None:
    stripped = line.strip()
    if not stripped or stripped == "---":
        return None
    parts = stripped.split()
    if len(parts) < 4:
        return None
    pattern_text = parts[0]
    if len(pattern_text) < 64:
        return None
    pattern_bytes: list[int | None] = []
    for index in range(0, 64, 2):
        token = pattern_text[index : index + 2]
        pattern_bytes.append(None if token == ".." else int(token, 16))
    public_names = [(int(match.group("offset"), 16), match.group("name")) for match in _PUBLIC_NAME_RE.finditer(stripped)]
    tags = {match.group("key"): match.group("value") for match in _TAG_RE.finditer(stripped)}
    return pattern_bytes, public_names, tags


def _pattern_matches(entry_bytes: bytes, pattern_bytes: list[int | None]) -> bool:
    if len(entry_bytes) < len(pattern_bytes):
        return False
    for actual, expected in zip(entry_bytes, pattern_bytes):
        if expected is None:
            continue
        if actual != expected:
            return False
    return True
