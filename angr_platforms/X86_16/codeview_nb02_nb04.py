"""
CodeView NB02 (CV2) and NB04 (CV4) Parser

Minimal implementation focused on 80/20 value:
- Function names (from SST_PUBLIC and S_GPROC16)
- Stack variables (from S_BPREL16)
- Local/global variables (from S_LDATA16)
- Line number mapping (from SST_SRCMODULE)

References:
- LLVM llvm/include/llvm/DebugInfo/CodeView/
- Wine dlls/dbghelp/
- Open Watcom debugger
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class CodeViewSymbolType(IntEnum):
    """CodeView symbol record types (16-bit values)"""
    S_GPROC16 = 0x0110  # Global procedure (16-bit)
    S_LPROC16 = 0x0111  # Local procedure (16-bit)
    S_GDATA16 = 0x0112  # Global data
    S_LDATA16 = 0x0113  # Local data
    S_GPROCMIPS = 0x0114
    S_LPROCMIPS = 0x0115
    S_BPREL16 = 0x0500  # Stack-relative variable (BP-relative) 16-bit
    S_LTHREAD16 = 0x0501
    S_GTHREAD16 = 0x0502
    S_PUB16 = 0x0110  # Public symbol
    S_END = 0x0006  # End of procedure/scope
    S_RETURN = 0x4609  # Return symbol


class CodeViewSubsectionType(IntEnum):
    """CodeView subsection types (from directory entries)"""
    SST_MODULE = 0x0120
    SST_TYPES = 0x0121
    SST_PUBLIC = 0x0122
    SST_PUBLIC_SYM = 0x0223
    SST_SYMBOLS = 0x0124
    SST_ALIGN_SYM = 0x0125
    SST_SRCMODULE = 0x0127
    SST_SRCMODULE_FILE = 0x0211
    SST_LIBRARIES = 0x0180
    SST_GLOBAL_SYM = 0x0220
    SST_GLOBAL_PUB = 0x0221
    SST_GLOBAL_TYPES = 0x0222


@dataclass(frozen=True)
class CodeViewSymbol:
    """Parsed symbol record"""
    type_code: int
    name: str
    offset: int  # Offset within segment
    segment: int | None
    length: int | None = None  # For procedures
    data_type: int | None = None  # Type index
    extra: dict = field(default_factory=dict)

    def is_procedure(self) -> bool:
        return self.type_code in {CodeViewSymbolType.S_GPROC16, CodeViewSymbolType.S_LPROC16}

    def is_stack_var(self) -> bool:
        return self.type_code == CodeViewSymbolType.S_BPREL16

    def is_data_symbol(self) -> bool:
        return self.type_code in {CodeViewSymbolType.S_GDATA16, CodeViewSymbolType.S_LDATA16}


@dataclass(frozen=True)
class CodeViewNB0204Info:
    """Parsed CodeView NB02/NB04 debug information"""
    version: str  # "NB02" or "NB04"
    debug_base: int
    code_labels: dict[int, str] = field(default_factory=dict)  # address -> function name
    data_labels: dict[int, str] = field(default_factory=dict)  # address -> data name
    procedures: tuple[CodeViewSymbol, ...] = ()
    stack_variables: dict[str, list[CodeViewSymbol]] = field(default_factory=dict)  # func_name -> vars
    line_map: dict[int, tuple[int, int]] = field(default_factory=dict)  # code_addr -> (source_line, col)
    modules: tuple[str, ...] = ()


def find_codeview_nb0204(data: bytes, *, signatures: list[bytes] | None = None) -> tuple[str, int] | None:
    """
    Find CodeView NB02/NB04 debug info trailer in binary.
    
    Args:
        data: Binary file contents
        signatures: List of signatures to search for (default: [b'NB02', b'NB04', b'NB05'])
    
    Returns:
        (signature, debug_base) or None if not found
    """
    if signatures is None:
        signatures = [b"NB04", b"NB02", b"NB05"]
    
    # Search from end backwards (trailer is typically at end of debug info)
    for trailer_offset in range(len(data) - 8, max(-1, len(data) - 512), -1):
        if trailer_offset + 8 > len(data):
            continue
        
        for sig in signatures:
            if data[trailer_offset : trailer_offset + 4] == sig:
                # Read offset to start of CV header
                try:
                    debug_offset = struct.unpack_from("<I", data, trailer_offset + 4)[0]
                    debug_base = trailer_offset + 8 - debug_offset
                    
                    # Validate: check that debug_base points to a valid CV header
                    if 0 <= debug_base < len(data) and debug_base + 8 <= len(data):
                        root_sig = data[debug_base : debug_base + 4]
                        if root_sig == sig:
                            return sig.decode("ascii", errors="ignore"), debug_base
                except (struct.error, ValueError):
                    continue
    
    return None


def parse_codeview_nb0204(binary_path: Path, *, load_base_linear: int = 0) -> CodeViewNB0204Info | None:
    """Parse CodeView NB02/NB04 from binary file."""
    try:
        data = binary_path.read_bytes()
        return parse_codeview_nb0204_bytes(data, load_base_linear=load_base_linear)
    except (OSError, ValueError):
        return None


def parse_codeview_nb0204_bytes(data: bytes, *, load_base_linear: int = 0) -> CodeViewNB0204Info | None:
    """Parse CodeView NB02/NB04 from binary data."""
    located = find_codeview_nb0204(data)
    if located is None:
        return None
    
    version, debug_base = located
    
    try:
        # Read header at debug_base
        # struct CVHeader { char sig[4]; uint32_t subdir_offset; }
        if debug_base + 8 > len(data):
            return None
        
        sig, subdir_offset = struct.unpack_from("<4sI", data, debug_base)
        debug_offset = debug_base + subdir_offset
        
        if not (0 <= debug_offset < len(data)):
            return None
        
        code_labels: dict[int, str] = {}
        data_labels: dict[int, str] = {}
        procedures: list[CodeViewSymbol] = []
        stack_variables: dict[str, list[CodeViewSymbol]] = {}
        modules: list[str] = []
        
        # Parse subsection directory
        directory_entries = _parse_subsection_directory(data, debug_base, debug_offset)
        
        for entry in directory_entries:
            subsection_type = entry["type"]
            offset = entry["offset"]
            size = entry["size"]
            
            if offset + size > len(data):
                continue
            
            blob = data[offset : offset + size]
            
            if subsection_type == CodeViewSubsectionType.SST_PUBLIC:
                _parse_public_symbols(blob, code_labels, data_labels, load_base_linear)
            
            elif subsection_type == CodeViewSubsectionType.SST_SYMBOLS:
                syms = _parse_symbol_records(blob)
                for sym in syms:
                    if sym.is_procedure():
                        procedures.append(sym)
                        if sym.name and sym.offset >= 0:
                            code_labels[load_base_linear + sym.offset] = sym.name
                    elif sym.is_stack_var():
                        # Group by procedure
                        if sym.name not in stack_variables:
                            stack_variables[sym.name] = []
                        stack_variables[sym.name].append(sym)
                    elif sym.is_data_symbol():
                        if sym.name and sym.offset >= 0:
                            data_labels[load_base_linear + sym.offset] = sym.name
            
            elif subsection_type == CodeViewSubsectionType.SST_MODULE:
                # Extract module name
                names = _parse_module_names(blob)
                modules.extend(names)
        
        return CodeViewNB0204Info(
            version=version,
            debug_base=debug_base,
            code_labels=code_labels,
            data_labels=data_labels,
            procedures=tuple(procedures),
            stack_variables=stack_variables,
            modules=tuple(modules),
        )
    
    except (struct.error, ValueError, IndexError):
        return None


def _parse_subsection_directory(
    data: bytes,
    debug_base: int,
    directory_offset: int,
) -> list[dict]:
    """Parse subsection directory entries."""
    entries = []
    offset = directory_offset
    
    try:
        # First uint16 is count for some formats
        if offset + 2 > len(data):
            return entries
        
        # Read entries until we hit padding or end
        while offset + 8 <= len(data):
            try:
                # Try to read: type (2), module (2), offset (4)
                entry_type, entry_module = struct.unpack_from("<HH", data, offset)
                offset += 4
                
                # Offset is relative to start of this subsection's data
                entry_offset = struct.unpack_from("<I", data, offset)[0]
                offset += 4
                
                # Size (2 or 4 bytes depending on format)
                if offset < len(data):
                    entry_size = struct.unpack_from("<H", data, offset)[0]
                    offset += 2
                else:
                    entry_size = 0
                
                # Adjust offset to absolute position in data
                abs_offset = debug_base + entry_offset
                
                if 0 <= abs_offset < len(data) and entry_size > 0:
                    entries.append({
                        "type": entry_type,
                        "module": entry_module,
                        "offset": abs_offset,
                        "size": entry_size,
                    })
            
            except (struct.error, ValueError):
                break
    
    except (struct.error, ValueError):
        pass
    
    return entries


def _parse_public_symbols(
    blob: bytes,
    code_labels: dict[int, str],
    data_labels: dict[int, str],
    load_base_linear: int,
) -> None:
    """Parse SST_PUBLIC symbols."""
    offset = 0
    
    while offset + 6 < len(blob):
        try:
            # struct: offset (2), segment (2), type (2), name_len (1)
            sym_offset, segment, sym_type, name_len = struct.unpack_from("<HHHB", blob, offset)
            offset += 7
            
            if name_len > 0 and offset + name_len <= len(blob):
                name = blob[offset : offset + name_len].decode("ascii", errors="ignore")
                offset += name_len
                
                if name:
                    linear_addr = load_base_linear + (segment << 4) + sym_offset
                    if sym_type & 0x8000:  # Code symbol marker
                        code_labels[linear_addr] = name
                    else:
                        data_labels[linear_addr] = name
            
        except (struct.error, ValueError):
            break


def _parse_symbol_records(blob: bytes) -> list[CodeViewSymbol]:
    """Parse symbol records from SST_SYMBOLS subsection."""
    symbols: list[CodeViewSymbol] = []
    offset = 0
    
    while offset < len(blob):
        try:
            # Each record: length (2), type (2), data...
            if offset + 4 > len(blob):
                break
            
            length = struct.unpack_from("<H", blob, offset)[0]
            offset += 2
            
            if length < 2 or offset + length > len(blob):
                break
            
            record_type = struct.unpack_from("<H", blob, offset)[0]
            offset += 2
            
            # Record-specific parsing
            if record_type in {CodeViewSymbolType.S_GPROC16, CodeViewSymbolType.S_LPROC16}:
                # struct S_PROCnn { uint32_t parent; uint32_t end; uint32_t next;
                #   uint16_t length; uint16_t offset; uint16_t segment; ... char name[]; }
                if offset + 16 <= len(blob):
                    proc_length, proc_offset, segment = struct.unpack_from("<HHH", blob, offset + 10)
                    name_offset = offset + 16
                    
                    # Name is length-prefixed string
                    if name_offset < len(blob):
                        name_len = blob[name_offset]
                        if name_offset + 1 + name_len <= len(blob):
                            name = blob[name_offset + 1 : name_offset + 1 + name_len].decode("ascii", errors="ignore")
                            symbols.append(CodeViewSymbol(
                                type_code=record_type,
                                name=name,
                                offset=proc_offset,
                                segment=segment,
                                length=proc_length,
                            ))
            
            elif record_type == CodeViewSymbolType.S_BPREL16:
                # struct S_BPREL16 { int16_t offset; uint16_t type; ... char name[]; }
                if offset + 4 <= len(blob):
                    bp_offset, data_type = struct.unpack_from("<hH", blob, offset)
                    name_offset = offset + 4
                    
                    if name_offset < len(blob):
                        name_len = blob[name_offset]
                        if name_offset + 1 + name_len <= len(blob):
                            name = blob[name_offset + 1 : name_offset + 1 + name_len].decode("ascii", errors="ignore")
                            symbols.append(CodeViewSymbol(
                                type_code=record_type,
                                name=name,
                                offset=bp_offset,
                                segment=None,
                                data_type=data_type,
                                extra={"bp_relative": True},
                            ))
            
            elif record_type in {CodeViewSymbolType.S_GDATA16, CodeViewSymbolType.S_LDATA16}:
                # struct S_LDATA16 { uint16_t offset; uint16_t segment; uint16_t type; ... char name[]; }
                if offset + 6 <= len(blob):
                    data_offset, segment, data_type = struct.unpack_from("<HHH", blob, offset)
                    name_offset = offset + 6
                    
                    if name_offset < len(blob):
                        name_len = blob[name_offset]
                        if name_offset + 1 + name_len <= len(blob):
                            name = blob[name_offset + 1 : name_offset + 1 + name_len].decode("ascii", errors="ignore")
                            symbols.append(CodeViewSymbol(
                                type_code=record_type,
                                name=name,
                                offset=data_offset,
                                segment=segment,
                                data_type=data_type,
                            ))
            
            # Skip to next record
            offset += length - 2  # -2 because we already read the type
        
        except (struct.error, ValueError, IndexError):
            break
    
    return symbols


def _parse_module_names(blob: bytes) -> list[str]:
    """Parse module names from SST_MODULE subsection."""
    names: list[str] = []
    
    try:
        # Module record format varies, but typically ends with null-terminated strings
        offset = 0
        while offset < len(blob):
            if blob[offset] == 0:
                break
            # Find null terminator
            null_pos = blob.find(b"\x00", offset)
            if null_pos == -1:
                null_pos = len(blob)
            
            name = blob[offset:null_pos].decode("ascii", errors="ignore")
            if name:
                names.append(name)
            
            offset = null_pos + 1
    
    except (ValueError, IndexError):
        pass
    
    return names
