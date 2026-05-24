"""
NE (New Executable) format parser for Windows/OS2 16-bit binaries.

This module works with the existing CLE DOSNE loader (load_dos_ne.py).
It extracts symbol information (function names, entry points) and uses
the loader's segment mappings to calculate correct linear addresses.

Reference: 
  - QLINK /FORMATS/NE/neexe.txt (NE format specification)
  - Open Watcom os2exe.c + wdtab.c (practical parsing reference)
  - angr_platforms/X86_16/load_dos_ne.py (existing NE loader integration point)

Extracts:
  - Function names from resident names table
  - Entry points (segment:offset) from entry table
  - Integrates with existing DOSNE loader for address calculation
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    import angr


class NETargetOS(IntEnum):
    """NE module target OS enum (offset 0x36)"""
    UNKNOWN = 0
    OS2 = 1
    WINDOWS = 2
    DOS4 = 3
    WIN386 = 4
    BOSS = 5


@dataclass
class NESegment:
    """NE segment table entry"""
    offset: int         # Offset in file (or flags for moveable)
    length: int         # Segment length
    flags: int          # Segment flags
    min_alloc: int      # Minimum allocation


@dataclass  
class NEEntryPoint:
    """NE entry point (from entry table + names table)
    
    Attributes:
        ordinal: Export ordinal number (1-based)
        name: Function name (from resident names table)
        segment: Segment index (1-based into segment table)
        offset: Offset within segment
        flags: Entry flags (exported, shared, etc.)
    """
    ordinal: int
    name: str
    segment: int
    offset: int
    flags: int = 0


@dataclass
class NEExeInfo:
    """Parsed NE executable header"""
    target_os: int                              # Target OS (0x36)
    entry_points: dict[int, str] = field(default_factory=dict)  # ordinal -> name
    entry_offsets: dict[str, tuple[int, int]] = field(default_factory=dict)  # name -> (seg, off)
    segments: list[NESegment] = field(default_factory=list)
    code_labels: dict[int, str] = field(default_factory=dict)  # linear addr -> name
    data_labels: dict[int, str] = field(default_factory=dict)


def find_ne_header(data: bytes) -> Optional[int]:
    """Find NE header offset from MZ (DOS) header.
    
    MZ header at offset 0x3C contains offset to new executable header.
    Returns byte offset to 'NE' signature, or None if not found.
    """
    if len(data) < 0x3E:
        return None
    
    if data[0:2] != b'MZ':
        return None
    
    try:
        ne_offset = struct.unpack_from('<H', data, 0x3C)[0]
        if ne_offset + 2 > len(data):
            return None
        
        if data[ne_offset:ne_offset+2] == b'NE':
            return ne_offset
    except (struct.error, IndexError):
        pass
    
    return None


def parse_ne_header(data: bytes, ne_offset: int) -> tuple[dict, int]:
    """Parse NE header structure.
    
    Returns:
        (header_dict, resident_names_offset): Header fields and offset to resident names table
    """
    try:
        header = {}
        # Read fixed portion of NE header (0x40 bytes minimum for older versions)
        if ne_offset + 0x40 > len(data):
            return {}, 0
        
        # Signature (already verified as 'NE')
        header['signature'] = data[ne_offset:ne_offset+2].decode('ascii', errors='ignore')
        header['link_major'] = data[ne_offset+0x02]
        header['link_minor'] = data[ne_offset+0x03]
        
        # Critical table offsets (relative to NE header base)
        header['entry_table_off'], header['entry_table_len'] = struct.unpack_from(
            '<HH', data, ne_offset + 0x04
        )
        header['file_load_crc'] = struct.unpack_from('<I', data, ne_offset + 0x08)[0]
        header['program_flags'] = data[ne_offset+0x0C]
        header['app_flags'] = data[ne_offset+0x0D]
        header['auto_data_seg'] = data[ne_offset+0x0E]
        header['heap_init'] = struct.unpack_from('<H', data, ne_offset + 0x10)[0]
        header['stack_init'] = struct.unpack_from('<H', data, ne_offset + 0x12)[0]
        header['entry_cs'], header['entry_ip'] = struct.unpack_from(
            '<HH', data, ne_offset + 0x14
        )
        header['entry_ss'], header['entry_sp'] = struct.unpack_from(
            '<HH', data, ne_offset + 0x18
        )
        header['seg_count'] = struct.unpack_from('<H', data, ne_offset + 0x1C)[0]
        header['module_refs'] = struct.unpack_from('<H', data, ne_offset + 0x1E)[0]
        header['nonres_names_len'] = struct.unpack_from('<H', data, ne_offset + 0x20)[0]
        header['segment_table_off'] = struct.unpack_from('<H', data, ne_offset + 0x22)[0]
        header['resource_table_off'] = struct.unpack_from('<H', data, ne_offset + 0x24)[0]
        header['resident_names_off'] = struct.unpack_from('<H', data, ne_offset + 0x26)[0]
        header['module_ref_off'] = struct.unpack_from('<H', data, ne_offset + 0x28)[0]
        header['import_names_off'] = struct.unpack_from('<H', data, ne_offset + 0x2A)[0]
        header['nonres_names_off'] = struct.unpack_from('<I', data, ne_offset + 0x2C)[0]
        header['moveable_entries'] = struct.unpack_from('<H', data, ne_offset + 0x30)[0]
        
        # Check for extended header (alignment shift, etc.)
        if ne_offset + 0x36 < len(data):
            header['align_shift'] = struct.unpack_from('<H', data, ne_offset + 0x32)[0]
            header['resource_entries'] = struct.unpack_from('<H', data, ne_offset + 0x34)[0]
            header['target_os'] = data[ne_offset+0x36]
        else:
            header['target_os'] = 0
        
        return header, ne_offset + header['resident_names_off']
    
    except (struct.error, IndexError):
        return {}, 0


def parse_ne_resident_names(data: bytes, offset: int, max_len: int) -> dict[int, str]:
    """Parse resident names table.
    
    Format: zero-terminated list of (length, name, ordinal) tuples
    Returns: {ordinal: name_string}
    """
    names = {}
    pos = offset
    end = offset + max_len
    
    try:
        while pos < end:
            if pos >= len(data):
                break
            
            name_len = data[pos]
            if name_len == 0:  # End marker
                break
            
            pos += 1
            if pos + name_len + 2 > len(data):
                break
            
            name = data[pos:pos+name_len].decode('ascii', errors='replace')
            pos += name_len
            
            ordinal = struct.unpack_from('<H', data, pos)[0]
            pos += 2
            
            if ordinal > 0:  # Skip padding entries
                names[ordinal] = name
    
    except (struct.error, IndexError, UnicodeDecodeError):
        pass
    
    return names


def parse_ne_segment_table(data: bytes, ne_offset: int, seg_table_off: int, 
                           seg_count: int) -> list[NESegment]:
    """Parse NE segment table.
    
    Each entry is 8 bytes (offset, length, flags, min_alloc)
    """
    segments = []
    pos = ne_offset + seg_table_off
    
    try:
        for _ in range(seg_count):
            if pos + 8 > len(data):
                break
            
            seg_offset, seg_length, seg_flags, min_alloc = struct.unpack_from(
                '<HHHH', data, pos
            )
            pos += 8
            
            segments.append(NESegment(
                offset=seg_offset,
                length=seg_length,
                flags=seg_flags,
                min_alloc=min_alloc
            ))
    
    except struct.error:
        pass
    
    return segments


def parse_ne_entry_table(data: bytes, ne_offset: int, entry_off: int, 
                         entry_len: int, ordinal_names: dict[int, str],
                         segments: list[NESegment]) -> dict[int, tuple[int, int]]:
    """Parse NE entry table to map ordinals to (segment, offset).
    
    NE entry table format (from Open Watcom exeos2.h):
    
    Bundle prefix (2 bytes):
      - count (uint8): number of entries in this bundle
      - type (uint8): 
        - 0x00: null bundle (no records)
        - 0xFF: movable segment records
        - 0x01-0xFE: fixed segment records for that segment number
    
    Movable records (6 bytes each, when type=0xFF):
      - info (1 byte): flags (bit 0: exported, bit 1: shared data)
      - reserved (2 bytes): must be 0x3FCD
      - entrynum (1 byte): segment number containing entry point
      - entry (2 bytes): offset within segment
    
    Fixed records (3 bytes each, when type=0x01-0xFE):
      - info (1 byte): flags
      - entry (2 bytes): offset within segment
      - Segment number is the type value
    
    Returns: {ordinal: (segment_index, offset_in_segment)}
    """
    offsets = {}
    pos = ne_offset + entry_off
    end = pos + entry_len
    ordinal = 1
    
    try:
        while pos < end and pos < len(data) - 2:
            # Bundle header: count, type
            bundle_count = data[pos]
            if bundle_count == 0:  # End of table
                break
            
            bundle_type = data[pos + 1]
            pos += 2
            
            if bundle_type == 0x00:
                # Type 0x00: null bundle (skip count entries)
                ordinal += bundle_count
                
            elif bundle_type == 0xFF:
                # Type 0xFF: movable entries (info, reserved, segment, offset)
                for _ in range(bundle_count):
                    if pos + 6 > len(data):
                        break
                    info = data[pos]
                    reserved = struct.unpack_from('<H', data, pos + 1)[0]
                    segment = data[pos + 3]
                    offset = struct.unpack_from('<H', data, pos + 4)[0]
                    
                    # Only add if we have a name for this ordinal
                    # and segment is valid (1-based index into segment table)
                    if ordinal in ordinal_names and 1 <= segment <= 255:
                        offsets[ordinal] = (segment, offset)
                    
                    ordinal += 1
                    pos += 6
                    
            else:
                # Fixed entry: segment embedded in type (0x01-0xFE)
                segment_num = bundle_type
                for _ in range(bundle_count):
                    if pos + 3 > len(data):
                        break
                    info = data[pos]
                    offset = struct.unpack_from('<H', data, pos + 1)[0]
                    
                    # Only add if we have a name for this ordinal
                    if ordinal in ordinal_names and 1 <= segment_num <= 255:
                        offsets[ordinal] = (segment_num, offset)
                    
                    ordinal += 1
                    pos += 3
    
    except (struct.error, IndexError):
        pass
    
    return offsets


def parse_ne_exe(
    binary_path: Path,
    load_base_linear: int = 0,
    project: Optional[angr.Project] = None,
) -> NEExeInfo:
    """Parse NE executable and extract debug information.
    
    Integrates with existing CLE DOSNE loader for accurate addressing.
    
    Args:
        binary_path: Path to NE .EXE file
        load_base_linear: Linear load base address (used if project unavailable)
        project: Optional angr project with loaded binary (provides loader info)
    
    Returns:
        NEExeInfo with extracted code/data labels using correct linear addresses
    """
    info = NEExeInfo(target_os=0)
    
    try:
        with open(binary_path, 'rb') as f:
            data = f.read()
    except (OSError, IOError):
        return info
    
    # Find NE header
    ne_offset = find_ne_header(data)
    if ne_offset is None:
        return info
    
    # Parse header
    header, resident_names_abs = parse_ne_header(data, ne_offset)
    if not header:
        return info
    
    info.target_os = header.get('target_os', 0)
    
    # Parse resident names table (function names)
    resident_names_offset = ne_offset + header.get('resident_names_off', 0)
    module_ref_offset = ne_offset + header.get('module_ref_off', 0)
    max_resident_len = module_ref_offset - resident_names_offset if module_ref_offset > resident_names_offset else 256
    
    ordinal_names = parse_ne_resident_names(data, resident_names_offset, max_resident_len)
    info.entry_points = ordinal_names
    
    # Parse segment table
    segments = parse_ne_segment_table(
        data, ne_offset,
        header.get('segment_table_off', 0),
        header.get('seg_count', 0)
    )
    info.segments = segments
    
    # Parse entry table to map ordinals to addresses
    ordinal_offsets = parse_ne_entry_table(
        data, ne_offset,
        header.get('entry_table_off', 0),
        header.get('entry_table_len', 0),
        ordinal_names,
        segments
    )
    
    # Calculate linear addresses from segment:offset
    # Use loader's segment mappings if available (CLE DOSNE loader)
    ne_segment_selectors = None
    if project is not None:
        try:
            main_obj = project.loader.main_object
            if hasattr(main_obj, 'ne_segment_selectors'):
                ne_segment_selectors = main_obj.ne_segment_selectors
        except (AttributeError, TypeError):
            pass
    
    for ordinal, (segment_num, offset) in ordinal_offsets.items():
        name = ordinal_names.get(ordinal, f"export_{ordinal}")
        
        # Calculate linear address using loader's mapping if available
        linear_addr = _calculate_ne_linear_addr(
            segment_num, offset, 
            load_base_linear=load_base_linear,
            ne_segment_selectors=ne_segment_selectors,
            segments=segments
        )
        
        if linear_addr is not None:
            info.entry_offsets[name] = (segment_num, offset)
            info.code_labels[linear_addr] = name
    
    return info


def _calculate_ne_linear_addr(
    segment_num: int,
    offset: int,
    load_base_linear: int = 0,
    ne_segment_selectors: Optional[dict[int, int]] = None,
    segments: Optional[list[NESegment]] = None,
) -> Optional[int]:
    """Calculate linear address from NE segment:offset using loader info if available.
    
    If the CLE DOSNE loader has already calculated segment selectors, use those.
    Otherwise fall back to parsing segment table from binary.
    
    Args:
        segment_num: NE segment number (1-based)
        offset: Offset within segment
        load_base_linear: Load base if using standalone calculation
        ne_segment_selectors: Segment selectors from CLE loader (segment_num -> selector)
        segments: Parsed segments from NE segment table (for fallback)
    
    Returns:
        Linear address, or None if calculation not possible
    """
    if ne_segment_selectors is not None and segment_num in ne_segment_selectors:
        # Use loader's selector mapping (most accurate)
        selector = ne_segment_selectors[segment_num]
        return (selector << 4) + offset
    
    # Fallback: use segment table directly if available
    if segments and 0 < segment_num <= len(segments):
        seg = segments[segment_num - 1]
        # NE segment table entry offset[0:2] is sector count
        # Real address = load_base + (sectors << alignment_shift) + offset
        # But without alignment_shift, we approximate:
        return load_base_linear + (seg.offset << 4) + offset
    
    return None


# Export the main function used by sidecar parsers
__all__ = ['parse_ne_exe', 'NEExeInfo']
