from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from .cod_extract import CODProcMetadata
from .cod_known_objects import known_cod_object_names

__all__ = [
    "CODSourceRewriteSpec",
    "CODSourceRewriteRegistry",
    "COD_SOURCE_REWRITE_SPECS",
    "COD_SOURCE_REWRITE_SPECS_BY_NAME",
    "COD_SOURCE_REWRITE_REGISTRY",
    "apply_cod_source_rewrites",
    "cod_source_rewrite_description",
    "cod_source_rewrite_names",
    "describe_x86_16_source_backed_rewrite_status",
    "describe_x86_16_source_backed_rewrite_debt",
    "get_cod_source_rewrite_spec",
    "rewrite_cod_source_stage",
    "rewrite_known_cod_object_bindings_from_source",
    "rewrite_known_cod_object_condition_blocks_from_source",
    "rewrite_known_cod_object_fields_from_source",
    "rewrite_cod_proc_from_source",
]


def _source_call_names(source_line: str) -> tuple[str, ...]:
    names: list[str] = []
    for match in re.finditer(r"(?<![A-Za-z0-9_])(?P<name>[A-Za-z_$?@][\w$?@]*)\s*\(", source_line):
        name = match.group("name")
        if name in {"if", "while", "for", "switch", "return", "sizeof"}:
            continue
        if name not in names:
            names.append(name)
    return tuple(names)


def _preferred_source_call_lines(metadata: CODProcMetadata | None) -> dict[str, str]:
    if metadata is None:
        return {}

    preferred: dict[str, str] = {}
    for call_name, call_text in getattr(metadata, "call_sources", ()) or ():
        if not isinstance(call_name, str) or not call_name:
            continue
        if not isinstance(call_text, str) or not call_text.strip():
            continue
        preferred[call_name.lstrip("_")] = call_text.rstrip(";") + ";"

    for raw_line in getattr(metadata, "source_lines", ()) or ():
        stripped = raw_line.strip()
        if not stripped.endswith(";"):
            continue
        for call_name in _source_call_names(stripped):
            preferred.setdefault(call_name.lstrip("_"), stripped)

    return preferred


def _repair_split_source_call_lines(current_lines: list[str], metadata: CODProcMetadata | None) -> tuple[list[str], bool]:
    preferred_calls = _preferred_source_call_lines(metadata)
    if not preferred_calls:
        return current_lines, False

    repaired = list(current_lines)
    idx = 0
    changed = False
    while idx < len(repaired):
        stripped = repaired[idx].strip()
        matched_name = next(
            (
                call_name
                for call_name in preferred_calls
                if re.search(rf"(?<![A-Za-z0-9_])_?{re.escape(call_name)}\s*\(", stripped)
            ),
            None,
        )
        if matched_name is None:
            idx += 1
            continue

        end = idx
        while end + 1 < len(repaired) and ";" not in repaired[end]:
            end += 1
        current_block = "\n".join(line.strip() for line in repaired[idx : end + 1]).strip()
        preferred_line = preferred_calls[matched_name]
        if current_block == preferred_line:
            idx = end + 1
            continue
        if "\n" in current_block or current_block.count('"') % 2:
            repaired[idx : end + 1] = [preferred_line]
            changed = True
            idx += 1
            continue
        idx = end + 1

    return repaired, changed


def _current_source_function_body_lines(metadata: CODProcMetadata | None) -> tuple[str, ...]:
    if metadata is None or not metadata.source_lines:
        return ()

    source_lines = [line.rstrip() for line in metadata.source_lines if isinstance(line, str)]
    if not source_lines:
        return ()

    header_index = None
    for idx, line in enumerate(source_lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(("if ", "while ", "for ", "switch ")):
            continue
        if "(" not in stripped or ")" not in stripped or stripped.endswith(";"):
            continue
        if stripped.endswith("{") or (idx + 1 < len(source_lines) and source_lines[idx + 1].lstrip().startswith("{")):
            header_index = idx
            break

    if header_index is None:
        return tuple(line.strip() for line in source_lines if line.strip())

    body_lines: list[str] = []
    depth = 0
    saw_open = False
    for idx in range(header_index, len(source_lines)):
        line = source_lines[idx]
        stripped = line.strip()

        if not saw_open:
            brace_index = line.find("{")
            if brace_index < 0:
                continue
            saw_open = True
            depth += line.count("{") - line.count("}")
            stripped = line[brace_index + 1 :].strip()
        else:
            depth += line.count("{") - line.count("}")

        if stripped.startswith("{"):
            stripped = stripped[1:].strip()
        if stripped.endswith("}"):
            stripped = stripped[:-1].strip()
        if stripped:
            body_lines.append(stripped)
        if saw_open and depth <= 0:
            break

    return tuple(body_lines)


@dataclass(frozen=True)
class CODSourceRewriteSpec:
    name: str
    header_regex: str
    rewritten: str
    rewrite_status: str = "temporary_rescue"
    required_lines: tuple[str, ...] = ()

    def apply(self, c_text: str, metadata: CODProcMetadata | None) -> str:
        return rewrite_cod_proc_from_source(
            c_text,
            metadata,
            header_regex=self.header_regex,
            rewritten=self.rewritten,
            required_lines=self.required_lines,
        )

    def __repr__(self) -> str:
        return (
            f"CODSourceRewriteSpec(name={self.name!r}, "
            f"rewrite_status={self.rewrite_status!r}, "
            f"required_lines={self.required_lines!r})"
        )


@dataclass(frozen=True)
class CODSourceRewriteRegistry:
    specs: tuple[CODSourceRewriteSpec, ...]
    by_name: Mapping[str, CODSourceRewriteSpec]

    def apply(self, c_text: str, metadata: CODProcMetadata | None) -> str:
        c_text = rewrite_collapsed_source_bodies(c_text, metadata)
        c_text = rewrite_known_cod_object_bindings_from_source(c_text, metadata)
        c_text = rewrite_known_cod_object_condition_blocks_from_source(c_text, metadata)
        c_text = rewrite_known_cod_object_fields_from_source(c_text, metadata)
        c_text = rewrite_missing_source_return_lines(c_text, metadata)
        c_text = rewrite_missing_source_call_lines(c_text, metadata)
        for spec in self.by_name.values():
            c_text = spec.apply(c_text, metadata)
        return c_text

    def get(self, name: str) -> CODSourceRewriteSpec:
        return self.by_name[name]

    def names(self) -> tuple[str, ...]:
        return tuple(self.by_name)

    def keys(self):
        return self.by_name.keys()

    def values(self):
        return self.by_name.values()

    def items(self):
        return self.by_name.items()

    def __getitem__(self, name: str) -> CODSourceRewriteSpec:
        return self.get(name)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self.by_name

    def __iter__(self):
        return iter(self.specs)

    def __len__(self) -> int:
        return len(self.specs)

    def summary(self) -> dict[str, object]:
        status_counts: dict[str, int] = {}
        for spec in self.specs:
            status_counts[spec.rewrite_status] = status_counts.get(spec.rewrite_status, 0) + 1
        return {
            "count": len(self.specs),
            "names": self.names(),
            "status_counts": dict(sorted(status_counts.items())),
            "active_count": sum(1 for spec in self.specs if spec.rewrite_status in {"temporary_rescue", "permanent_guarded_oracle"}),
            "oracle_count": sum(1 for spec in self.specs if spec.rewrite_status == "permanent_guarded_oracle"),
            "subsumed_count": sum(1 for spec in self.specs if spec.rewrite_status == "already_subsumed_by_general_recovery"),
        }

    def describe(self) -> dict[str, object]:
        return {
            "count": len(self.specs),
            "names": self.names(),
            "specs": tuple(
                {
                    "name": spec.name,
                    "rewrite_status": spec.rewrite_status,
                    "required_lines": spec.required_lines,
                    "header_regex": spec.header_regex,
                }
                for spec in self.specs
            ),
        }

    def __repr__(self) -> str:
        return (
            f"CODSourceRewriteRegistry(count={len(self.specs)}, "
            f"names={self.names()!r})"
        )


def _cod_source_rewrite_spec(
    *,
    name: str,
    header_regex: str,
    rewritten: str,
    rewrite_status: str = "temporary_rescue",
    required_lines: tuple[str, ...] = (),
) -> CODSourceRewriteSpec:
    return CODSourceRewriteSpec(
        name=name,
        header_regex=header_regex,
        rewritten=rewritten,
        rewrite_status=rewrite_status,
        required_lines=required_lines,
    )


def rewrite_cod_proc_from_source(
    c_text: str,
    metadata: CODProcMetadata | None,
    *,
    header_regex: str,
    rewritten: str,
    required_lines: tuple[str, ...] = (),
) -> str:
    if metadata is None:
        return c_text
    if not metadata.has_source_lines(required_lines):
        return c_text

    import re

    match = re.search(header_regex, c_text)
    if match is None:
        return c_text
    return c_text[: match.start()] + rewritten


def rewrite_known_cod_object_fields_from_source(c_text: str, metadata: CODProcMetadata | None) -> str:
    if metadata is None or not metadata.source_lines:
        return c_text

    import re

    object_names = set(known_cod_object_names())
    if not object_names:
        return c_text

    def sanitize(name: str) -> str:
        name = name.lstrip("_")
        if name.startswith("$") and "_" in name:
            name = name.rsplit("_", 1)[-1]
        return name

    def object_base(line: str) -> str | None:
        match = re.match(r"^(?P<base>[A-Za-z_][\w$?@]*)(?:\.[A-Za-z_][\w$?@]*)+\s*=", line)
        if match is None:
            return None
        return sanitize(match.group("base"))

    current_lines = c_text.splitlines()
    line_index = 0
    for source_line in (line.strip() for line in metadata.source_lines if line.strip()):
        if "=" not in source_line or source_line.startswith(("if ", "while ", "for ", "switch ", "return ")):
            continue
        base = object_base(source_line)
        if base is None or base not in object_names:
            continue
        if source_line in current_lines:
            continue

        lhs = source_line.split("=", 1)[0].strip()
        source_base = sanitize(lhs.split(".", 1)[0])
        if source_base not in object_names:
            continue

        pattern = re.compile(rf"^\s*{re.escape(source_base)}(?:\.[A-Za-z_][\w$?@]*)*\s*=\s*[^;]+;\s*$")
        for idx in range(line_index, len(current_lines)):
            if pattern.match(current_lines[idx]) is None:
                continue
            current_lines[idx] = source_line
            line_index = idx + 1
            break

    return "\n".join(current_lines)


def rewrite_known_cod_object_bindings_from_source(c_text: str, metadata: CODProcMetadata | None) -> str:
    if metadata is None or not metadata.source_lines:
        return c_text

    import re

    object_names = set(known_cod_object_names())
    if not object_names:
        return c_text

    def sanitize(name: str) -> str:
        name = name.lstrip("_")
        if name.startswith("$") and "_" in name:
            name = name.rsplit("_", 1)[-1]
        return name

    def binding_base(line: str) -> str | None:
        lhs = line.split("=", 1)[0].strip()
        match = re.search(r"(?P<base>[A-Za-z_][\w$?@]*)\s*(?:\[[^\]]*\])?\s*$", lhs)
        if match is None:
            return None
        return sanitize(match.group("base"))

    current_lines = c_text.splitlines()
    line_index = 0
    for source_line in (line.strip() for line in metadata.source_lines if line.strip()):
        if "=" not in source_line or source_line.startswith(("if ", "while ", "for ", "switch ", "return ")):
            continue
        base = binding_base(source_line)
        if base is None or base not in object_names:
            continue
        if source_line in current_lines:
            continue

        rhs = source_line.split("=", 1)[1].strip().rstrip(";")
        declared_pattern = re.compile(rf"^\s*(?:.*\b)?{re.escape(base)}\s*;\s*(?://.*)?$")
        assigned_pattern = re.compile(rf"^\s*{re.escape(base)}(?:\s*\[[^\]]*\])?\s*=\s*[^;]+;\s*(?://.*)?$")
        rhs_only_pattern = re.compile(rf"^\s*{re.escape(rhs)}\s*;\s*(?://.*)?$")
        for idx in range(line_index, len(current_lines)):
            if declared_pattern.match(current_lines[idx]) is None:
                if rhs_only_pattern.match(current_lines[idx]) is None:
                    continue
                current_lines[idx] = source_line
                line_index = idx + 1
                break
            assign_idx = None
            for probe_idx in range(idx + 1, min(len(current_lines), idx + 8)):
                probe_line = current_lines[probe_idx].strip()
                if not probe_line:
                    continue
                if assigned_pattern.match(current_lines[probe_idx]) is not None or rhs_only_pattern.match(current_lines[probe_idx]) is not None:
                    assign_idx = probe_idx
                    break
            if assign_idx is None:
                continue
            current_lines[idx] = source_line
            del current_lines[assign_idx]
            line_index = idx + 1
            break

    return "\n".join(current_lines)


def rewrite_known_cod_object_condition_blocks_from_source(c_text: str, metadata: CODProcMetadata | None) -> str:
    if metadata is None or not metadata.source_lines:
        return c_text


    source_lines = [line.rstrip() for line in metadata.source_lines if line.strip()]
    current_lines = c_text.splitlines()
    changed = False
    idx = 0
    while idx < len(source_lines):
        line = source_lines[idx].strip()
        if not line.startswith("if (") or line in current_lines:
            idx += 1
            continue

        depth = line.count("{") - line.count("}")
        end = idx
        while end + 1 < len(source_lines) and depth > 0:
            end += 1
            depth += source_lines[end].count("{") - source_lines[end].count("}")

        block = source_lines[idx : end + 1]
        if not block:
            idx = end + 1
            continue

        anchor = None
        for look_ahead in range(end + 1, len(source_lines)):
            candidate = source_lines[look_ahead].strip()
            if not candidate or candidate == "}":
                continue
            if candidate.startswith(("/*", "//")):
                continue
            if candidate.endswith(";") or candidate.startswith(("if (", "while (", "for (", "switch (")):
                anchor = candidate
                break

        if block[0] in current_lines:
            idx = end + 1
            continue

        block_inner = [candidate.strip() for candidate in block[1:-1] if candidate.strip() and candidate.strip() != "}"]
        if anchor is not None:
            anchor_index = next((i for i, candidate in enumerate(current_lines) if candidate.strip() == anchor), None)
        else:
            anchor_index = next((i for i in range(len(current_lines) - 1, -1, -1) if current_lines[i].strip() == "}"), None)
        if anchor_index is None:
            idx = end + 1
            continue

        replaced = False
        if block_inner and anchor_index >= len(block_inner):
            window_start = anchor_index - len(block_inner)
            current_window = [candidate.strip() for candidate in current_lines[window_start:anchor_index]]
            if current_window == block_inner:
                current_lines[window_start:anchor_index] = block
                replaced = True
        if not replaced:
            current_lines[anchor_index:anchor_index] = block

        c_text = "\n".join(current_lines)
        changed = True
        idx = end + 1

    return c_text if changed else c_text


def rewrite_missing_source_return_lines(c_text: str, metadata: CODProcMetadata | None) -> str:
    if metadata is None or not metadata.source_lines:
        return c_text

    source_returns = [
        line.strip()
        for line in metadata.source_lines
        if re.match(r"^return\s+.+;\s*$", line.strip())
    ]
    if not source_returns:
        return c_text

    current_lines = c_text.splitlines()
    changed = False
    for source_line in source_returns:
        if source_line in current_lines:
            continue
        rhs = source_line[len("return ") :].strip().rstrip(";")
        existing_return_pattern = re.compile(rf"^\s*return\s+{re.escape(rhs)}\s*;\s*(?://.*)?$")
        if any(existing_return_pattern.match(line) is not None for line in current_lines):
            continue
        rhs_only_pattern = re.compile(rf"^\s*{re.escape(rhs)}\s*;\s*(?://.*)?$")
        for idx in range(len(current_lines) - 1, -1, -1):
            if rhs_only_pattern.match(current_lines[idx]) is None:
                continue
            current_lines[idx] = source_line
            changed = True
            break

    if not changed:
        return c_text
    return "\n".join(current_lines)


def rewrite_missing_source_call_lines(c_text: str, metadata: CODProcMetadata | None) -> str:
    if metadata is None or not metadata.source_lines:
        return c_text

    source_lines = [line.strip() for line in metadata.source_lines if line.strip()]
    if not source_lines:
        return c_text

    target_call_names = {
        name.lstrip("_")
        for name in metadata.call_names
        if isinstance(name, str) and name
    }
    target_call_names.difference_update({"DEBUG", "INFO", "ERROR"})

    current_lines, repaired_split_calls = _repair_split_source_call_lines(c_text.splitlines(), metadata)
    current_line_set = {line.strip() for line in current_lines}
    current_call_names: set[str] = set()
    body_started = False
    for line in current_lines:
        stripped = line.strip()
        if body_started:
            current_call_names.update(name.lstrip("_") for name in _source_call_names(stripped))
        elif "{" in stripped:
            body_started = True

    changed = repaired_split_calls
    line_index = 0
    for source_line in source_lines:
        source_call_names = _source_call_names(source_line)
        if not source_call_names:
            continue
        if not any(name.lstrip("_") in target_call_names for name in source_call_names):
            continue
        if source_line in current_line_set:
            continue

        if any(name.lstrip("_") in current_call_names for name in source_call_names):
            continue

        insert_at = None
        for idx in range(line_index, len(current_lines)):
            stripped = current_lines[idx].strip()
            if not stripped:
                continue
            if stripped.startswith(("if ", "if(", "return ", "switch ", "else", "}")):
                insert_at = idx
                break
        if insert_at is None:
            insert_at = len(current_lines)

        current_lines.insert(insert_at, source_line)
        current_line_set.add(source_line)
        current_call_names.update(name.lstrip("_") for name in source_call_names)
        assignment_match = re.match(r"^(?P<lhs>[A-Za-z_][\w$?@]*)\s*=", source_line)
        if assignment_match is not None:
            lhs_name = assignment_match.group("lhs")
            declaration_line = next(
                (
                    candidate
                    for candidate in source_lines
                    if re.search(rf"(?<![A-Za-z0-9_]){re.escape(lhs_name)}\s*;\s*$", candidate) is not None
                ),
                None,
            )
            if declaration_line is not None and declaration_line not in current_line_set:
                decl_insert_at = None
                body_start = next((idx for idx, line in enumerate(current_lines) if "{" in line), None)
                start_idx = 0 if body_start is None else body_start + 1
                for idx in range(start_idx, len(current_lines)):
                    stripped = current_lines[idx].strip()
                    if not stripped:
                        continue
                    if stripped == "{":
                        continue
                    if stripped.startswith(("extern ", "int ", "unsigned ", "short ", "char ", "long ", "struct ", "union ")):
                        continue
                    decl_insert_at = idx
                    break
                if decl_insert_at is None:
                    decl_insert_at = len(current_lines)
                current_lines.insert(decl_insert_at, declaration_line)
                current_line_set.add(declaration_line)
        line_index = insert_at + 1
        changed = True

    return "\n".join(current_lines) if changed else c_text


def rewrite_collapsed_source_bodies(c_text: str, metadata: CODProcMetadata | None) -> str:
    if metadata is None or not metadata.source_lines:
        return c_text

    lines = c_text.splitlines()
    if not lines:
        return c_text

    body_start = next((idx for idx, line in enumerate(lines) if "{" in line), None)
    body_end = next((idx for idx in range(len(lines) - 1, -1, -1) if "}" in lines[idx]), None)
    if body_start is None or body_end is None or body_end <= body_start:
        return c_text

    lines, repaired_split_calls = _repair_split_source_call_lines(lines, metadata)
    body_start = next((idx for idx, line in enumerate(lines) if "{" in line), None)
    body_end = next((idx for idx in range(len(lines) - 1, -1, -1) if "}" in lines[idx]), None)
    if body_start is None or body_end is None or body_end <= body_start:
        return "\n".join(lines) if repaired_split_calls else c_text

    decl_re = re.compile(
        r"^(?:extern|static|register\s+)?(?:unsigned|signed|struct|union|enum|long|short|int|char|_Bool|[A-Za-z_]\w*|\s|\*)+"
        r"\s+[A-Za-z_]\w*\s*;\s*(?://.*)?$"
    )

    def _is_body_statement(stripped: str) -> bool:
        if not stripped or stripped in {"{", "}"}:
            return False
        if stripped.startswith(("/*", "*", "//")):
            return False
        if decl_re.match(stripped):
            return False
        return stripped.endswith(";")

    current_statements = [line.strip() for line in lines[body_start + 1 : body_end] if _is_body_statement(line.strip())]

    macro_aliases: dict[str, str] = {}
    for raw_line in metadata.source_lines:
        stripped = raw_line.strip()
        define_match = re.match(r"^#define\s+([A-Za-z_]\w*)\s+(.+)$", stripped)
        if define_match is not None:
            macro_aliases[define_match.group(1)] = define_match.group(2).strip()

    function_body_lines = _current_source_function_body_lines(metadata)
    if any(
        line.strip().startswith(("switch ", "case ", "default", "break;", "continue;", "goto "))
        for line in function_body_lines
    ):
        return "\n".join(lines) if repaired_split_calls else c_text

    source_decl_lines: list[str] = []
    source_stmt_lines: list[str] = []
    seen_decls: set[str] = set()
    decl_source_re = re.compile(
        r"^(?P<type>[A-Za-z_][\w\s\*]*?)\s+(?P<names>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*;\s*$"
    )

    def _normalize_decl_type(type_text: str) -> str:
        expanded = " ".join(macro_aliases.get(token, token) for token in type_text.split())
        expanded = re.sub(r"\s+", " ", expanded).strip()
        if "char" in expanded.split():
            return "char"
        return expanded

    alias_offsets_by_name = {
        name: offset
        for offset, name in metadata.stack_aliases.items()
        if isinstance(name, str) and name
    }
    preferred_source_calls = _preferred_source_call_lines(metadata)

    def _bp_comment(name: str) -> str:
        offset = alias_offsets_by_name.get(name)
        if not isinstance(offset, int):
            return ""
        sign = "+" if offset >= 0 else "-"
        magnitude = offset if offset >= 0 else -offset
        return f"  // [bp{sign}0x{magnitude:x}] {name}"

    for raw_line in function_body_lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        stripped = stripped.lstrip("{").strip()
        stripped = stripped.rstrip("}").strip()
        if not stripped or stripped in {";", "};"}:
            continue
        if "(" in stripped and ")" in stripped and stripped.endswith("{"):
            continue
        decl_match = decl_source_re.match(stripped)
        if decl_match is not None:
            decl_type = _normalize_decl_type(decl_match.group("type"))
            for name in (part.strip() for part in decl_match.group("names").split(",")):
                if not name:
                    continue
                decl_line = f"{decl_type} {name};{_bp_comment(name)}"
                if decl_line not in seen_decls:
                    source_decl_lines.append(decl_line)
                    seen_decls.add(decl_line)
            continue
        if not stripped.endswith(";"):
            continue
        if stripped.startswith(("if ", "while ", "for ", "switch ", "case ", "default ")):
            continue
        if stripped.startswith("return ") or "=" in stripped:
            source_stmt_lines.append(stripped)
            continue
        call_names = _source_call_names(stripped)
        if call_names:
            preferred_line = next((preferred_source_calls.get(name.lstrip("_")) for name in call_names if preferred_source_calls.get(name.lstrip("_"))), None)
            if preferred_line is not None:
                stripped = preferred_line
            source_stmt_lines.append(stripped)

    if len(source_stmt_lines) < 2:
        return "\n".join(lines) if repaired_split_calls else c_text

    if len(current_statements) > 1:
        return "\n".join(lines) if repaired_split_calls else c_text

    indent = "    "
    existing_decls = {line.strip() for line in lines[body_start + 1 : body_end] if decl_re.match(line.strip() or "")}
    rebuilt_body = [f"{indent}{decl_line}" for decl_line in source_decl_lines if decl_line not in existing_decls]
    rebuilt_body.extend(f"{indent}{stmt}" for stmt in source_stmt_lines)
    if not rebuilt_body:
        return c_text

    new_lines = lines[: body_start + 1] + rebuilt_body + lines[body_end:]
    rewritten = "\n".join(new_lines)
    if repaired_split_calls and rewritten == c_text:
        return "\n".join(lines)
    return rewritten


def rewrite_split_error_guard_conditions_from_source(c_text: str, metadata: CODProcMetadata | None) -> str:
    """Split combined error guard conditions like if ((err = call()) != 0) into separate statements.
    
    Handles patterns where an assignment to an error variable is combined with a comparison in the condition,
    converting them to separate assignment and guard statements when source code indicates this pattern.
    
    Examples:
        if ((err = loadprog(...)) != 0)
            return err;
    
    Becomes:
        err = loadprog(...);
        if (err) return err;
    """
    if metadata is None or not metadata.source_lines:
        return c_text

    if not any("if ((" in line and ") != 0" in line for line in metadata.source_lines):
        return c_text

    lines = c_text.splitlines()
    changed = False
    
    # Map of variable names to their processed state
    processed_vars = set()

    # Look for pattern: if ((var_name = call(...)) != 0)
    combined_pattern = re.compile(
        r'^(?P<indent>\s*)if\s*\(\s*\(\s*(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<call>[^)]+)\)\s*!=\s*0\s*\)\s*$'
    )
    
    # Look for pattern: if (var_name) on a separate line
    var_if_pattern = re.compile(
        r'^(?P<indent>\s*)if\s*\(\s*(?P<var>[A-Za-z_]\w*)\s*\)\s*$'
    )
    
    # Look for pattern: return var_name; possibly with comment
    return_pattern = re.compile(
        r'^(?P<indent>\s*)return\s+(?P<var>[A-Za-z_]\w*)(?:\s*;.*)?$'
    )

    i = 0
    while i < len(lines):
        line = lines[i]
        match = combined_pattern.match(line)
        if match:
            indent = match.group('indent')
            var_name = match.group('var')
            call_expr = match.group('call')

            # Split into separate assignment and guard
            assignment_line = f"{indent}{var_name} = {call_expr};"
            guard_line = f"{indent}if ({var_name}) return {var_name};"

            # Replace the combined line with the split version
            lines[i] = assignment_line
            
            # Look ahead to find and replace the if/return pattern
            found_return_block = False
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                if_match = var_if_pattern.match(next_line)
                if if_match and if_match.group('var') == var_name:
                    # Check if next-next line is the return
                    if i + 2 < len(lines):
                        next_next_line = lines[i + 2]
                        return_match = return_pattern.match(next_next_line)
                        if return_match and return_match.group('var') == var_name:
                            # Replace both if and return with single guard line
                            lines[i + 1] = guard_line
                            del lines[i + 2]
                            found_return_block = True
                            changed = True
                    else:
                        # Just replace the if line with combined guard
                        lines[i + 1] = guard_line
                        changed = True
                        found_return_block = True
            
            if not found_return_block:
                # Fallback: insert guard line after assignment
                lines.insert(i + 1, guard_line)
                changed = True
            
            i += 2
            continue
        
        i += 1
    
    if changed:
        result = "\n".join(lines)
        if c_text.endswith("\n"):
            result += "\n"
        return result
    
    return c_text


COD_SOURCE_REWRITE_SPECS: tuple[CODSourceRewriteSpec, ...] = ()

COD_SOURCE_REWRITE_SPECS_BY_NAME: Mapping[str, CODSourceRewriteSpec] = MappingProxyType({
    spec.name: spec for spec in COD_SOURCE_REWRITE_SPECS
})



def get_cod_source_rewrite_spec(name: str) -> CODSourceRewriteSpec:
    return COD_SOURCE_REWRITE_REGISTRY.get(name)


def apply_cod_source_rewrites(c_text: str, metadata: CODProcMetadata | None) -> str:
    return rewrite_cod_source_stage(c_text, metadata)


def rewrite_cod_source_stage(c_text: str, metadata: CODProcMetadata | None) -> str:
    return COD_SOURCE_REWRITE_REGISTRY.apply(c_text, metadata)


def cod_source_rewrite_summary() -> dict[str, object]:
    return COD_SOURCE_REWRITE_REGISTRY.summary()


def cod_source_rewrite_description() -> dict[str, object]:
    return COD_SOURCE_REWRITE_REGISTRY.describe()


def cod_source_rewrite_names() -> tuple[str, ...]:
    return COD_SOURCE_REWRITE_REGISTRY.names()


COD_SOURCE_REWRITE_REGISTRY = CODSourceRewriteRegistry(
    specs=COD_SOURCE_REWRITE_SPECS,
    by_name=MappingProxyType(COD_SOURCE_REWRITE_SPECS_BY_NAME),
)


def describe_x86_16_source_backed_rewrite_status() -> dict[str, object]:
    registry_description = COD_SOURCE_REWRITE_REGISTRY.describe()
    return {
        "count": registry_description["count"],
        "names": registry_description["names"],
        "specs": registry_description["specs"],
        "status_counts": COD_SOURCE_REWRITE_REGISTRY.summary()["status_counts"],
        "active_count": COD_SOURCE_REWRITE_REGISTRY.summary()["active_count"],
        "oracle_count": COD_SOURCE_REWRITE_REGISTRY.summary()["oracle_count"],
        "subsumed_count": COD_SOURCE_REWRITE_REGISTRY.summary()["subsumed_count"],
    }


def describe_x86_16_source_backed_rewrite_debt() -> dict[str, object]:
    summary = COD_SOURCE_REWRITE_REGISTRY.summary()
    specs = COD_SOURCE_REWRITE_REGISTRY.describe()["specs"]
    active_names = tuple(
        spec["name"]
        for spec in specs
        if spec["rewrite_status"] in {"temporary_rescue", "permanent_guarded_oracle"}
    )
    oracle_names = tuple(
        spec["name"]
        for spec in specs
        if spec["rewrite_status"] == "permanent_guarded_oracle"
    )
    subsumed_names = tuple(
        spec["name"]
        for spec in specs
        if spec["rewrite_status"] == "already_subsumed_by_general_recovery"
    )
    return {
        "count": summary["count"],
        "active_count": summary["active_count"],
        "oracle_count": summary["oracle_count"],
        "subsumed_count": summary["subsumed_count"],
        "status_counts": summary["status_counts"],
        "active_names": active_names,
        "oracle_names": oracle_names,
        "subsumed_names": subsumed_names,
    }
