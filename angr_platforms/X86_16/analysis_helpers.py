from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass
from pathlib import Path

import claripy
from angr import SimProcedure

INTERRUPT_CORE_VECTOR_BASE = 0xFF000
INTERRUPT_CORE_VECTOR_COUNT = 0x100


KNOWN_HELPER_SIGNATURE_DECLS: dict[str, str] = {
    "aNchkstk": "void aNchkstk(void);",
    "__aNchkstk": "void __aNchkstk(void);",
    "_abort": "void _abort(void);",
    "_DEBUG": "int _DEBUG(const char *fmt, ...);",
    "_ERROR": "int _ERROR(const char *fmt, ...);",
    "_INFO": "int _INFO(const char *fmt, ...);",
    "_fflush": "int _fflush(FILE *f);",
    "_fprintf": "int _fprintf(FILE *f, const char *fmt, ...);",
    "_intdos": "int _intdos(union REGS *in, union REGS *out);",
    "_intdosx": "int _intdosx(union REGS *in, union REGS *out, struct SREGS *sreg);",
    "_dos_getProcessId": "unsigned short _dos_getProcessId(void);",
    "_dos_setProcessId": "int _dos_setProcessId(const unsigned short pid);",
    "intdos": "int intdos(union REGS *in, union REGS *out);",
    "intdosx": "int intdosx(union REGS *in, union REGS *out, struct SREGS *sreg);",
    "loadprog": "int loadprog(const char *file, unsigned short segment, unsigned short mode, const char *cmdline);",
    "clearRect": "void clearRect(void *dst, unsigned short left, unsigned short top, unsigned short right, unsigned short bottom);",
    "clock": "clock_t clock(void);",
    "settextrows": "int settextrows(int rows);",
    "clearscreen": "void clearscreen(int mode);",
    "displaycursor": "void displaycursor(int mode);",
    "setvideomode": "void setvideomode(int mode);",
    "settextcolor": "int settextcolor(int color);",
    "settextposition": "void settextposition(int row, int col);",
    "outtext": "int outtext(const char *text);",
    "exit": "void exit(int status);",
    "memset": "void *memset(void *dst, int ch, unsigned long count);",
    "inp": "unsigned char inp(unsigned short port);",
    "openFile": "int openFile(const char *path, unsigned short mode);",
    "_openFile": "int _openFile(const char *path, unsigned short mode);",
    "readchar": "unsigned char readchar(void);",
    "readcharat": "unsigned char readcharat(unsigned short rowcol);",
    "setcursorpos": "void setcursorpos(unsigned short rowcol);",
    "writecharat": "void writecharat(unsigned short rowcol, unsigned char ch);",
    "writestringat": "void writestringat(unsigned short rowcol, const char *s);",
    "dispdigit": "void dispdigit(unsigned char digit);",
    "dispnum": "void dispnum(unsigned short value);",
    "Swaps": "int Swaps(void *lhs, void *rhs);",
    "_Swaps": "int _Swaps(void *lhs, void *rhs);",
    "SwapBars": "int SwapBars(int iRow1, int iRow2);",
    "_SwapBars": "int _SwapBars(int iRow1, int iRow2);",
    "PercolateUp": "int PercolateUp(int i);",
    "_PercolateUp": "int _PercolateUp(int i);",
    "PercolateDown": "int PercolateDown(int i);",
    "_PercolateDown": "int _PercolateDown(int i);",
}


@dataclass(frozen=True)
class FarCallTarget:
    callsite_addr: int
    target_addr: int
    return_addr: int | None


@dataclass(frozen=True)
class CallTargetSeed:
    callsite_addr: int
    target_addr: int
    return_addr: int | None
    kind: str


@dataclass(frozen=True)
class InterruptCall:
    insn_addr: int
    vector: int = 0x21
    ah: int | None = None
    al: int | None = None
    ax: int | None = None
    bx: int | None = None
    cx: int | None = None
    dx: int | None = None
    si: int | None = None
    di: int | None = None
    bh: int | None = None
    bl: int | None = None
    ch: int | None = None
    cl: int | None = None
    dh: int | None = None
    dl: int | None = None
    ds: int | None = None
    es: int | None = None
    ss: int | None = None
    cs: int | None = None
    ah_expr: str | None = None
    al_expr: str | None = None
    ax_expr: str | None = None
    bx_expr: str | None = None
    cx_expr: str | None = None
    dx_expr: str | None = None
    si_expr: str | None = None
    di_expr: str | None = None
    bh_expr: str | None = None
    bl_expr: str | None = None
    ch_expr: str | None = None
    cl_expr: str | None = None
    dh_expr: str | None = None
    dl_expr: str | None = None
    ds_expr: str | None = None
    es_expr: str | None = None
    ss_expr: str | None = None
    cs_expr: str | None = None
    string_literal: str | None = None


DOSInt21Call = InterruptCall


@dataclass(frozen=True)
class InterruptServiceSpec:
    vector: int
    pseudo_name: str
    dos_name: str
    modern_name: str
    render_kind: str = "generic"
    default_output: str = "return"
    pseudo_decl: str | None = None
    dos_decl: str | None = None
    modern_decl: str | None = None


INT21_SERVICE_SPECS: dict[int, InterruptServiceSpec] = {
    0x09: InterruptServiceSpec(
        0x21,
        "dos_print_dollar_string",
        "_dos_print_dollar_string",
        "print_dos_string",
        "string_dollar",
        pseudo_decl="void dos_print_dollar_string(const char *s);",
        dos_decl="void _dos_print_dollar_string(const char far *s);",
        modern_decl="void print_dos_string(const char *s);",
    ),
    0x0E: InterruptServiceSpec(
        0x21,
        "dos_set_current_drive",
        "_dos_setdrive",
        "set_current_drive",
        "drive",
        pseudo_decl="int dos_set_current_drive(int drive);",
        dos_decl="int _dos_setdrive(unsigned char drive);",
        modern_decl="int set_current_drive(int drive);",
    ),
    0x25: InterruptServiceSpec(
        0x21,
        "dos_setvect",
        "_dos_setvect",
        "setvect",
        "setvect",
        pseudo_decl="void dos_setvect(int vector, void (*handler)(void));",
        dos_decl="void _dos_setvect(unsigned int interruptno, void (far *isr)(void));",
        modern_decl="void setvect(int interruptno, void (*isr)(void));",
    ),
    0x30: InterruptServiceSpec(
        0x21,
        "dos_get_version",
        "_dos_get_version",
        "get_dos_version",
        "zero_arg",
        pseudo_decl="int dos_get_version(void);",
        dos_decl="unsigned short _dos_get_version(void);",
        modern_decl="int get_dos_version(void);",
    ),
    0x35: InterruptServiceSpec(
        0x21,
        "dos_getvect",
        "_dos_getvect",
        "getvect",
        "getvect",
        pseudo_decl="void *dos_getvect(int vector);",
        dos_decl="void (far *_dos_getvect(unsigned int interruptno))(void);",
        modern_decl="void (*getvect(int interruptno))(void);",
    ),
    0x39: InterruptServiceSpec(
        0x21,
        "dos_mkdir",
        "_dos_mkdir",
        "mkdir",
        "path",
        pseudo_decl="int dos_mkdir(const char *path);",
        dos_decl="int _dos_mkdir(const char far *path);",
        modern_decl="int mkdir(const char *path);",
    ),
    0x3A: InterruptServiceSpec(
        0x21,
        "dos_rmdir",
        "_dos_rmdir",
        "rmdir",
        "path",
        pseudo_decl="int dos_rmdir(const char *path);",
        dos_decl="int _dos_rmdir(const char far *path);",
        modern_decl="int rmdir(const char *path);",
    ),
    0x3B: InterruptServiceSpec(
        0x21,
        "dos_chdir",
        "_dos_chdir",
        "chdir",
        "path",
        pseudo_decl="int dos_chdir(const char *path);",
        dos_decl="int _dos_chdir(const char far *path);",
        modern_decl="int chdir(const char *path);",
    ),
    0x3C: InterruptServiceSpec(
        0x21,
        "dos_creat",
        "_dos_creat",
        "creat",
        "path_attrs",
        pseudo_decl="int dos_creat(const char *path, int attrs);",
        dos_decl="int _dos_creat(const char far *path, unsigned short attrs);",
        modern_decl="int creat(const char *path, int attrs);",
    ),
    0x3D: InterruptServiceSpec(
        0x21,
        "dos_open",
        "_dos_open",
        "open",
        "path_mode",
        pseudo_decl="int dos_open(const char *path, int mode);",
        dos_decl="int _dos_open(const char far *path, unsigned char mode);",
        modern_decl="int open(const char *path, int oflag);",
    ),
    0x3E: InterruptServiceSpec(
        0x21,
        "dos_close",
        "_dos_close",
        "close",
        "handle",
        pseudo_decl="int dos_close(int handle);",
        dos_decl="int _dos_close(unsigned short handle);",
        modern_decl="int close(int fd);",
    ),
    0x3F: InterruptServiceSpec(
        0x21,
        "dos_read",
        "_dos_read",
        "read",
        "handle_buffer_count",
        pseudo_decl="int dos_read(int handle, void *buffer, unsigned int count);",
        dos_decl="int _dos_read(unsigned short handle, void far *buffer, unsigned short count);",
        modern_decl="int read(int fd, void *buf, unsigned int count);",
    ),
    0x40: InterruptServiceSpec(
        0x21,
        "dos_write",
        "_dos_write",
        "write",
        "handle_buffer_count",
        pseudo_decl="int dos_write(int handle, const void *buffer, unsigned int count);",
        dos_decl="int _dos_write(unsigned short handle, const void far *buffer, unsigned short count);",
        modern_decl="int write(int fd, const void *buf, unsigned int count);",
    ),
    0x41: InterruptServiceSpec(
        0x21,
        "dos_unlink",
        "_dos_unlink",
        "unlink",
        "path",
        pseudo_decl="int dos_unlink(const char *path);",
        dos_decl="int _dos_unlink(const char far *path);",
        modern_decl="int unlink(const char *path);",
    ),
    0x42: InterruptServiceSpec(
        0x21,
        "dos_seek",
        "_dos_seek",
        "lseek",
        "handle_seek",
        pseudo_decl="long dos_seek(int handle, long offset, int origin);",
        dos_decl="long _dos_seek(unsigned short handle, long offset, unsigned char origin);",
        modern_decl="long lseek(int fd, long offset, int whence);",
    ),
    0x47: InterruptServiceSpec(
        0x21,
        "dos_get_current_directory",
        "_dos_getcwd",
        "get_current_directory",
        "drive_buffer",
        pseudo_decl="int dos_get_current_directory(int drive, char *buffer);",
        dos_decl="int _dos_getcwd(unsigned char drive, char far *buffer);",
        modern_decl="int get_current_directory(int drive, char *buffer);",
    ),
    0x4A: InterruptServiceSpec(
        0x21,
        "dos_setblock",
        "_dos_setblock",
        "resize_dos_memory_block",
        "zero_arg",
        pseudo_decl="int dos_setblock(void);",
        dos_decl="int _dos_setblock(void);",
        modern_decl="int resize_dos_memory_block(void);",
    ),
    0x4C: InterruptServiceSpec(
        0x21,
        "dos_exit",
        "_dos_exit",
        "exit",
        "exit",
        pseudo_decl="void dos_exit(int status);",
        dos_decl="void _dos_exit(unsigned char status);",
        modern_decl="void exit(int status);",
    ),
}


INTERRUPT_SERVICE_SPECS: dict[int, InterruptServiceSpec] = {
    0x10: InterruptServiceSpec(
        0x10,
        "bios_int10_video",
        "_bios_int10_video",
        "_bios_int10_video",
        "wrapper",
        pseudo_decl="int bios_int10_video(unsigned int service);",
        dos_decl="int _bios_int10_video(unsigned int service);",
        modern_decl="int _bios_int10_video(unsigned int service);",
    ),
    0x11: InterruptServiceSpec(
        0x11,
        "bios_equiplist",
        "_bios_equiplist",
        "_bios_equiplist",
        "direct",
        pseudo_decl="int bios_equiplist(void);",
        dos_decl="int _bios_equiplist(void);",
        modern_decl="int _bios_equiplist(void);",
    ),
    0x12: InterruptServiceSpec(
        0x12,
        "bios_memsize",
        "_bios_memsize",
        "_bios_memsize",
        "direct",
        pseudo_decl="int bios_memsize(void);",
        dos_decl="int _bios_memsize(void);",
        modern_decl="int _bios_memsize(void);",
    ),
    0x13: InterruptServiceSpec(
        0x13,
        "bios_int13_disk",
        "_bios_disk",
        "_bios_disk",
        "wrapper",
        pseudo_decl="int bios_int13_disk(void);",
        dos_decl="int _bios_disk(void);",
        modern_decl="int _bios_disk(void);",
    ),
    0x14: InterruptServiceSpec(
        0x14,
        "bios_int14_serial",
        "_bios_serialcom",
        "_bios_serialcom",
        "wrapper",
        pseudo_decl="int bios_int14_serial(void);",
        dos_decl="int _bios_serialcom(void);",
        modern_decl="int _bios_serialcom(void);",
    ),
    0x15: InterruptServiceSpec(
        0x15,
        "bios_int15_system",
        "_bios_int15_system",
        "_bios_int15_system",
        "wrapper",
        pseudo_decl="int bios_int15_system(void);",
        dos_decl="int _bios_int15_system(void);",
        modern_decl="int _bios_int15_system(void);",
    ),
    0x16: InterruptServiceSpec(
        0x16,
        "bios_keybrd",
        "_bios_keybrd",
        "_bios_keybrd",
        "direct",
        pseudo_decl="unsigned bios_keybrd(unsigned keycmd);",
        dos_decl="unsigned _bios_keybrd(unsigned keycmd);",
        modern_decl="unsigned _bios_keybrd(unsigned keycmd);",
    ),
    0x17: InterruptServiceSpec(
        0x17,
        "bios_int17_printer",
        "_bios_printer",
        "_bios_printer",
        "wrapper",
        pseudo_decl="int bios_int17_printer(void);",
        dos_decl="int _bios_printer(void);",
        modern_decl="int _bios_printer(void);",
    ),
    0x1A: InterruptServiceSpec(
        0x1A,
        "bios_timeofday",
        "_bios_timeofday",
        "_bios_timeofday",
        "direct",
        pseudo_decl="int bios_timeofday(void);",
        dos_decl="int _bios_timeofday(void);",
        modern_decl="int _bios_timeofday(void);",
    ),
}


INTERRUPT_SERVICE_BASE_ADDR = 0xFE000
DOS_SERVICE_BASE_ADDR = INTERRUPT_SERVICE_BASE_ADDR


def _interrupt_service_key(call: InterruptCall) -> int:
    if call.vector == 0x21:
        return call.ah & 0xFF if call.ah is not None else 0
    return call.vector & 0xFF


def interrupt_service_addr(call: InterruptCall) -> int:
    return INTERRUPT_SERVICE_BASE_ADDR + _interrupt_service_key(call)


def interrupt_service_name(call: InterruptCall, api_style: str = "pseudo") -> str:
    spec = _interrupt_service_spec_for_call(call)
    if spec is not None:
        if api_style == "pseudo":
            return spec.pseudo_name
        if api_style in {"dos", "msc", "compiler"}:
            return spec.dos_name
        return spec.modern_name

    if call.vector == 0x21:
        spec = INT21_SERVICE_SPECS.get(call.ah or -1)
        if spec is not None:
            if api_style == "pseudo":
                return spec.pseudo_name
            if api_style in {"dos", "msc", "compiler"}:
                return spec.dos_name
            return spec.modern_name
        return "dos_int21"

    if call.vector == 0x10:
        return "bios_int10_video" if api_style == "pseudo" else "_bios_int10_video"
    if call.vector == 0x11:
        return "bios_equiplist" if api_style == "pseudo" else "_bios_equiplist"
    if call.vector == 0x12:
        return "bios_memsize" if api_style == "pseudo" else "_bios_memsize"
    if call.vector == 0x13:
        return "bios_int13_disk" if api_style == "pseudo" else "_bios_disk"
    if call.vector == 0x14:
        return "bios_int14_serial" if api_style == "pseudo" else "_bios_serialcom"
    if call.vector == 0x15:
        return "bios_int15_system" if api_style == "pseudo" else "_bios_int15_system"
    if call.vector == 0x16:
        return "bios_keybrd" if api_style == "pseudo" else "_bios_keybrd"
    if call.vector == 0x17:
        return "bios_int17_printer" if api_style == "pseudo" else "_bios_printer"
    if call.vector == 0x1A:
        return "bios_timeofday" if api_style == "pseudo" else "_bios_timeofday"
    return f"int{call.vector:02x}"


def dos_service_name(call: InterruptCall) -> str:
    return interrupt_service_name(call, "pseudo")


def _interrupt_service_name_for_helper(call: InterruptCall, api_style: str) -> str:
    if api_style in {"dos", "msc", "compiler"}:
        return interrupt_service_name(call, "dos")
    return interrupt_service_name(call, "pseudo")


def interrupt_service_spec(call: InterruptCall) -> InterruptServiceSpec | None:
    if call.vector == 0x21:
        return None
    return INTERRUPT_SERVICE_SPECS.get(call.vector)


def _interrupt_service_spec_for_call(call: InterruptCall) -> InterruptServiceSpec | None:
    if call.vector == 0x21:
        return INT21_SERVICE_SPECS.get(call.ah or -1)
    return INTERRUPT_SERVICE_SPECS.get(call.vector)


def dos_service_addr(call: InterruptCall) -> int:
    return interrupt_service_addr(call)


def ensure_interrupt_service_hook(project, call: InterruptCall) -> tuple[int, str]:
    addr = interrupt_service_addr(call)
    name = _interrupt_service_name_for_helper(call, "pseudo")

    if not project.is_hooked(addr):
        no_ret = call.vector == 0x21 and call.ah == 0x4C

        def _run(self):  # pylint:disable=unused-argument
            if no_ret:
                code = getattr(self.state.regs, "al", claripy.BVV(0, 8))
                self.exit(claripy.ZeroExt(8, code))
            return claripy.BVS(f"{name}_ax", 16, explicit_name=True)

        proc_cls = type(
            f"{name.title().replace('_', '')}Procedure",
            (SimProcedure,),
            {
                "display_name": name,
                "NO_RET": no_ret,
                "run": _run,
            },
        )
        project.hook(addr, proc_cls(), replace=True)

    return addr, name


def ensure_dos_service_hook(project, call: InterruptCall) -> tuple[int, str]:
    return ensure_interrupt_service_hook(project, call)


def patch_interrupt_service_call_sites(
    function,
    binary_path: Path | str | None = None,
    *,
    vectors: set[int] | None = None,
) -> bool:
    """
    Rewrite Function._call_sites for recoverable DOS and BIOS interrupt services.

    The decompiler needs these synthetic hooks so direct interrupt callsites can
    be rendered with the service-specific helper names recovered from the
    interrupt vector and register state.
    """

    project = function.project
    if project is None:
        return False

    changed = False
    for call in collect_interrupt_service_calls(function, binary_path, vectors=vectors):
        target_addr, name = ensure_interrupt_service_hook(project, call)
        return_addr = function.get_call_return(call.insn_addr)
        new = (target_addr, return_addr)
        old = function._call_sites.get(call.insn_addr)
        if old != new:
            function._call_sites[call.insn_addr] = new
            changed = True
        callee = project.kb.functions.function(addr=target_addr, create=True)
        if callee is not None:
            callee.name = name
            callee._init_prototype_and_calling_convention()

    return changed


def normalize_api_style(api_style: str) -> str:
    if api_style in {"pseudo", "service"}:
        return "pseudo"
    if api_style in {"dos", "msc", "compiler"}:
        return "dos"
    return api_style


def describe_x86_16_interrupt_api_surface() -> dict[str, object]:
    return {
        "dos": {
            "service_count": len(INT21_SERVICE_SPECS),
            "service_names": tuple(spec.modern_name for spec in INT21_SERVICE_SPECS.values()),
            "helper_names": tuple(spec.dos_name for spec in INT21_SERVICE_SPECS.values()),
        },
        "bios": {
            "service_count": len(INTERRUPT_SERVICE_SPECS),
            "service_names": tuple(spec.modern_name for spec in INTERRUPT_SERVICE_SPECS.values()),
            "helper_names": tuple(spec.dos_name for spec in INTERRUPT_SERVICE_SPECS.values()),
            "vectors": tuple(sorted(INTERRUPT_SERVICE_SPECS)),
        },
        "wrappers": {
            "kinds": ("int86", "int86x", "intdos", "intdosx"),
            "input_fields": ("inregs", "outregs", "sregs"),
            "result_paths": (
                "outregs.h.ah",
                "outregs.h.al",
                "outregs.x.ax",
                "outregs.x.bx",
                "outregs.x.cx",
                "outregs.x.dx",
                "sregs.es",
            ),
        },
    }


def describe_x86_16_interrupt_core_surface() -> dict[str, object]:
    return {
        "vector_base": INTERRUPT_CORE_VECTOR_BASE,
        "vector_count": INTERRUPT_CORE_VECTOR_COUNT,
        "hook_count": INTERRUPT_CORE_VECTOR_COUNT,
        "runtime_alias_base": 0x0000,
        "named_vectors": tuple(sorted(INTERRUPT_SERVICE_SPECS) + [0x20, 0x21, 0x25, 0x26, 0x27, 0x2F]),
        "control_transfer_policy": "int -> synthetic target -> SimOS hook",
        "low_level_helpers": (
            "interrupt_service_addr",
            "ensure_interrupt_service_hook",
            "ensure_dos_service_hook",
            "collect_interrupt_service_calls",
            "patch_interrupt_service_call_sites",
        ),
    }


def describe_x86_16_interrupt_lowering_boundary() -> dict[str, object]:
    return {
        "boundary_rule": "interrupt instruction semantics stay low-level; DOS/BIOS/MS-C lowering stays in analysis and rewrite helpers",
        "core_surface": describe_x86_16_interrupt_core_surface(),
        "api_surface": describe_x86_16_interrupt_api_surface(),
        "validated_by": (
            "tests/test_x86_16_milestone_report.py",
            "tests/test_x86_16_package_exports.py",
            "tests/test_x86_16_helper_modeling.py",
        ),
    }


def known_helper_signature_decl(name: str) -> str | None:
    return KNOWN_HELPER_SIGNATURE_DECLS.get(name)


def preferred_known_helper_signature_decl(name: str) -> str | None:
    if name in KNOWN_HELPER_SIGNATURE_DECLS:
        if not name.startswith("_"):
            underscored = f"_{name}"
            if underscored in KNOWN_HELPER_SIGNATURE_DECLS:
                return KNOWN_HELPER_SIGNATURE_DECLS[underscored]
        return KNOWN_HELPER_SIGNATURE_DECLS[name]
    if not name.startswith("_"):
        underscored = f"_{name}"
        if underscored in KNOWN_HELPER_SIGNATURE_DECLS:
            return KNOWN_HELPER_SIGNATURE_DECLS[underscored]
    stripped = name.lstrip("_")
    if stripped != name:
        return KNOWN_HELPER_SIGNATURE_DECLS.get(stripped)
    return None


def describe_x86_16_known_helper_signatures() -> dict[str, object]:
    return {
        "signature_count": len(KNOWN_HELPER_SIGNATURE_DECLS),
        "helper_names": tuple(sorted(KNOWN_HELPER_SIGNATURE_DECLS)),
        "declarations": tuple(sorted(KNOWN_HELPER_SIGNATURE_DECLS.values())),
    }


def infer_com_region(path: Path, *, base_addr: int, window: int, arch) -> tuple[int, int]:
    """
    Infer a bounded `.COM` code region by scanning until a likely terminator.

    This keeps tiny DOS stubs from decompiling their trailing strings as code.
    """

    data = path.read_bytes()
    end_limit = min(len(data), window)
    current = 0
    ah = None

    while current < end_limit:
        chunk = data[current : current + 16]
        insn = next(arch.capstone.disasm(chunk, base_addr + current, 1), None)
        if insn is None:
            break

        text = f"{insn.mnemonic} {insn.op_str}".strip().lower()
        if text.startswith("mov ah, "):
            ah = int(text.split(", ", 1)[1], 0)
        elif text.startswith("mov ax, "):
            ax = int(text.split(", ", 1)[1], 0)
            ah = (ax >> 8) & 0xFF

        current += insn.size

        if insn.mnemonic == "int":
            if insn.op_str.lower() == "0x20":
                break
            if insn.op_str.lower() == "0x21" and ah == 0x4C:
                break
            if insn.op_str.lower() == "0x27":
                break
        if insn.mnemonic in {"ret", "retf", "iret", "jmp"}:
            break

    return base_addr, base_addr + max(current, 1)


def _decode_com_ascii_string(binary_path: Path | None, dx: int | None, *, terminator: int) -> str | None:
    if binary_path is None or binary_path.suffix.lower() != ".com" or dx is None or dx < 0x100:
        return None
    try:
        data = binary_path.read_bytes()
    except OSError:
        return None

    start = dx - 0x100
    if start < 0 or start >= len(data):
        return None
    end = data.find(bytes([terminator]), start)
    if end == -1:
        return None
    raw = data[start:end]
    if not raw:
        return ""
    if any(byte < 0x20 or byte > 0x7E for byte in raw):
        return None
    text = raw.decode("ascii", errors="ignore")
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _coerce_path(binary_path: Path | str | None) -> Path | None:
    if binary_path is None or isinstance(binary_path, Path):
        return binary_path
    return Path(binary_path)


def decode_com_dollar_string(binary_path: Path | str | None, dx: int | None) -> str | None:
    binary_path = _coerce_path(binary_path)
    return _decode_com_ascii_string(binary_path, dx, terminator=ord("$"))


def decode_com_c_string(binary_path: Path | str | None, dx: int | None) -> str | None:
    binary_path = _coerce_path(binary_path)
    return _decode_com_ascii_string(binary_path, dx, terminator=0)


def _format_imm(value: int) -> str:
    if 0 <= value <= 9:
        return str(value)
    return f"0x{value:x}"


def _format_mem_operand(ins, operand) -> str:
    mem = getattr(operand, "mem", None)
    if mem is None:
        return "<mem>"

    pieces: list[str] = []
    base = getattr(mem, "base", 0)
    index = getattr(mem, "index", 0)
    disp = getattr(mem, "disp", 0)
    if base:
        pieces.append(ins.reg_name(base).lower())
    if index:
        pieces.append(ins.reg_name(index).lower())
    if disp:
        disp_text = hex(abs(disp)) if abs(disp) > 9 else str(abs(disp))
        if pieces:
            pieces.append(("+" if disp >= 0 else "-") + disp_text)
        else:
            pieces.append(("-" if disp < 0 else "") + disp_text)
    if not pieces:
        pieces.append("0")
    return "[" + "".join(pieces) + "]"


def _operand_expr(ins, operand) -> tuple[int | None, str | None]:
    if operand.type == 1:
        reg_name = ins.reg_name(operand.reg).lower()
        return None, reg_name
    if operand.type == 2:
        imm = operand.imm & 0xFFFF
        return imm, _format_imm(imm)
    if operand.type == 3:
        return None, _format_mem_operand(ins, operand)
    return None, None


def collect_interrupt_calls(
    function,
    binary_path: Path | str | None = None,
    *,
    vectors: set[int] | None = None,
) -> list[InterruptCall]:
    binary_path = _coerce_path(binary_path)
    project = function.project
    if project is None:
        return []

    calls: list[InterruptCall] = []
    regs: dict[str, tuple[int | None, str | None]] = {
        "ah": (None, None),
        "al": (None, None),
        "ax": (None, None),
        "bh": (None, None),
        "bl": (None, None),
        "bx": (None, None),
        "ch": (None, None),
        "cl": (None, None),
        "cx": (None, None),
        "dh": (None, None),
        "dl": (None, None),
        "dx": (None, None),
        "si": (None, None),
        "di": (None, None),
        "ds": (None, None),
        "es": (None, None),
        "ss": (None, None),
        "cs": (None, None),
    }

    def set_reg(reg_name: str, value: int | None, expr: str | None) -> None:
        regs[reg_name] = (value, expr)

        if reg_name in {"ax", "bx", "cx", "dx"}:
            if value is not None:
                high = (value >> 8) & 0xFF
                low = value & 0xFF
                regs[f"{reg_name[0]}h"] = (high, _format_imm(high))
                regs[f"{reg_name[0]}l"] = (low, _format_imm(low))
            else:
                regs[f"{reg_name[0]}h"] = (None, None)
                regs[f"{reg_name[0]}l"] = (None, None)
        elif reg_name in {"ah", "al"}:
            high, _ = regs["ah"]
            low, _ = regs["al"]
            if high is not None and low is not None:
                regs["ax"] = (((high & 0xFF) << 8) | (low & 0xFF), None)
            else:
                regs["ax"] = (None, None)
        elif reg_name in {"bh", "bl"}:
            high, _ = regs["bh"]
            low, _ = regs["bl"]
            if high is not None and low is not None:
                regs["bx"] = (((high & 0xFF) << 8) | (low & 0xFF), None)
            else:
                regs["bx"] = (None, None)
        elif reg_name in {"ch", "cl"}:
            high, _ = regs["ch"]
            low, _ = regs["cl"]
            if high is not None and low is not None:
                regs["cx"] = (((high & 0xFF) << 8) | (low & 0xFF), None)
            else:
                regs["cx"] = (None, None)
        elif reg_name in {"dh", "dl"}:
            high, _ = regs["dh"]
            low, _ = regs["dl"]
            if high is not None and low is not None:
                regs["dx"] = (((high & 0xFF) << 8) | (low & 0xFF), None)
            else:
                regs["dx"] = (None, None)

    for block_addr in sorted(getattr(function, "block_addrs_set", ())):
        block = project.factory.block(block_addr, opt_level=0)
        for ins in block.capstone.insns:
            operands = getattr(ins, "operands", ())
            if ins.mnemonic == "mov" and len(operands) == 2:
                dst, src = operands
                if dst.type == 1:
                    reg_name = ins.reg_name(dst.reg).lower()
                    if reg_name in regs:
                        value, expr = _operand_expr(ins, src)
                        set_reg(reg_name, value, expr)
            elif ins.mnemonic == "xor" and len(operands) == 2 and operands[0].type == 1 and operands[1].type == 1:
                dst_name = ins.reg_name(operands[0].reg).lower()
                src_name = ins.reg_name(operands[1].reg).lower()
                if dst_name == src_name and dst_name in regs:
                    set_reg(dst_name, 0, "0")
            elif ins.mnemonic == "int":
                vector_text = ins.op_str.lower().strip()
                try:
                    vector = int(vector_text, 0) & 0xFF
                except ValueError:
                    continue
                if vectors is not None and vector not in vectors:
                    continue

                ah, ah_expr = regs["ah"]
                al, al_expr = regs["al"]
                ax, ax_expr = regs["ax"]
                bh, bh_expr = regs["bh"]
                bl, bl_expr = regs["bl"]
                bx, bx_expr = regs["bx"]
                ch, ch_expr = regs["ch"]
                cl, cl_expr = regs["cl"]
                cx, cx_expr = regs["cx"]
                dh, dh_expr = regs["dh"]
                dl, dl_expr = regs["dl"]
                dx, dx_expr = regs["dx"]
                si, si_expr = regs["si"]
                di, di_expr = regs["di"]
                ds, ds_expr = regs["ds"]
                es, es_expr = regs["es"]
                ss, ss_expr = regs["ss"]
                cs, cs_expr = regs["cs"]
                path_literal = None
                if vector == 0x21 and ah in {0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x41}:
                    path_literal = decode_com_c_string(binary_path, dx)
                elif vector == 0x21 and ah == 0x09:
                    path_literal = decode_com_dollar_string(binary_path, dx)
                calls.append(
                    InterruptCall(
                        insn_addr=ins.address,
                        vector=vector,
                        ah=ah,
                        al=al,
                        ax=ax,
                        bh=bh,
                        bl=bl,
                        bx=bx,
                        ch=ch,
                        cl=cl,
                        cx=cx,
                        dh=dh,
                        dl=dl,
                        dx=dx,
                        si=si,
                        di=di,
                        ds=ds,
                        es=es,
                        ss=ss,
                        cs=cs,
                        ah_expr=ah_expr,
                        al_expr=al_expr,
                        ax_expr=ax_expr,
                        bh_expr=bh_expr,
                        bl_expr=bl_expr,
                        bx_expr=bx_expr,
                        ch_expr=ch_expr,
                        cl_expr=cl_expr,
                        cx_expr=cx_expr,
                        dh_expr=dh_expr,
                        dl_expr=dl_expr,
                        dx_expr=dx_expr,
                        si_expr=si_expr,
                        di_expr=di_expr,
                        ds_expr=ds_expr,
                        es_expr=es_expr,
                        ss_expr=ss_expr,
                        cs_expr=cs_expr,
                        string_literal=path_literal,
                    )
                )
                if vector == 0x21:
                    set_reg("dx", None, None)

    return calls


def collect_dos_int21_calls(function, binary_path: Path | str | None = None) -> list[DOSInt21Call]:
    return [call for call in collect_interrupt_calls(function, binary_path, vectors={0x21}) if call.vector == 0x21]


def collect_interrupt_service_calls(
    function,
    binary_path: Path | str | None = None,
    *,
    vectors: set[int] | None = None,
) -> list[InterruptCall]:
    return collect_interrupt_calls(function, binary_path, vectors=vectors)


def _dos_path_arg(call: DOSInt21Call, *, far_ptr: bool) -> str | None:
    if call.string_literal is not None:
        return f'"{call.string_literal}"'
    if call.dx is not None:
        cast = "const char far *" if far_ptr else "const char *"
        return f"({cast})0x{call.dx:x}"
    if call.dx_expr is not None:
        cast = "const char far *" if far_ptr else "const char *"
        return f"({cast}){call.dx_expr}"
    return None


def _dos_arg(value: int | None, expr: str | None) -> str | None:
    if value is not None:
        return _format_imm(value)
    return expr


def _dos_buffer_arg(call: DOSInt21Call, *, far_ptr: bool, const: bool) -> str | None:
    cast = "const void far *" if far_ptr and const else "void far *" if far_ptr else "const void *" if const else "void *"
    if call.dx is not None:
        return f"({cast})0x{call.dx:x}"
    if call.dx_expr is not None:
        return f"({cast}){call.dx_expr}"
    return None


def _dos_si_buffer_arg(call: DOSInt21Call, *, far_ptr: bool, const: bool) -> str | None:
    cast = "const char far *" if far_ptr and const else "char far *" if far_ptr else "const char *" if const else "char *"
    if call.si is not None:
        return f"({cast})0x{call.si:x}"
    if call.si_expr is not None:
        return f"({cast}){call.si_expr}"
    return None


def _dos_drive_arg(call: DOSInt21Call) -> str | None:
    if call.dl is not None:
        return _format_imm(call.dl)
    return call.dl_expr


def _dos_seek_offset_arg(call: DOSInt21Call) -> str:
    if call.cx is not None and call.dx is not None:
        return f"0x{(((call.cx & 0xFFFF) << 16) | (call.dx & 0xFFFF)):x}"
    high = _dos_arg(call.cx, call.cx_expr)
    low = _dos_arg(call.dx, call.dx_expr)
    if high is not None and low is not None:
        return f"MK_LONG({low}, {high})"
    if low is not None:
        return low
    return "0"


def _dos_vector_arg(call: DOSInt21Call) -> str | None:
    if call.al is not None:
        return _format_imm(call.al)
    return call.al_expr


def _dos_far_pointer_arg(call: DOSInt21Call) -> str | None:
    segment = _dos_arg(call.ds, call.ds_expr)
    offset = _dos_arg(call.dx, call.dx_expr)
    if segment is not None and offset is not None:
        return f"MK_FP({segment}, {offset})"
    if offset is not None:
        return offset
    return None


def _interrupt_service_decl(spec: InterruptServiceSpec, api_style: str) -> str:
    api_style = normalize_api_style(api_style)
    if api_style == "pseudo" and spec.pseudo_decl is not None:
        return spec.pseudo_decl
    if api_style == "dos" and spec.dos_decl is not None:
        return spec.dos_decl
    if api_style == "raw":
        return ""
    if spec.modern_decl is not None:
        return spec.modern_decl
    if api_style == "pseudo":
        return f"int {spec.pseudo_name}(void);"
    if api_style == "dos":
        return f"int {spec.dos_name}(void);"
    return f"int {spec.modern_name.lstrip('_')}(void);"


def render_dos_int21_call(call: DOSInt21Call, api_style: str) -> str:
    api_style = normalize_api_style(api_style)

    if api_style == "raw":
        return "dos_int21()"

    spec = INT21_SERVICE_SPECS.get(call.ah or -1)
    if spec is None:
        return "dos_int21()"

    name = interrupt_service_name(call, api_style)

    if spec.render_kind == "string_dollar":
        if api_style == "dos":
            if call.string_literal is not None:
                return f'_dos_print_dollar_string("{call.string_literal}")'
            if call.dx is None:
                return "_dos_print_dollar_string()"
            return f"_dos_print_dollar_string((const char far *)0x{call.dx:x})"
        if api_style == "pseudo":
            if call.string_literal is not None:
                return f'{name}("{call.string_literal}")'
            if call.dx is None:
                return f"{name}()"
            return f"{name}((const char *)0x{call.dx:x})"
        if call.string_literal is not None:
            return f'print_dos_string("{call.string_literal}")'
        if call.dx is None:
            return "print_dos_string()"
        return f"print_dos_string((const char *)0x{call.dx:x})"

    if spec.render_kind == "drive":
        drive = _dos_drive_arg(call) or "0"
        return f"{name}({drive})"

    if spec.render_kind == "path":
        path = _dos_path_arg(call, far_ptr=api_style == "dos") or "NULL"
        return f"{name}({path})"

    if spec.render_kind == "path_mode":
        path = _dos_path_arg(call, far_ptr=api_style == "dos") or "NULL"
        mode = _dos_arg(call.al, call.al_expr) or "0"
        return f"{name}({path}, {mode})"

    if spec.render_kind == "path_attrs":
        path = _dos_path_arg(call, far_ptr=api_style == "dos") or "NULL"
        attrs = _dos_arg(call.cx, call.cx_expr) or "0"
        return f"{name}({path}, {attrs})"

    if spec.render_kind == "handle":
        handle = _dos_arg(call.bx, call.bx_expr) or "0"
        return f"{name}({handle})"

    if spec.render_kind == "handle_buffer_count":
        handle = _dos_arg(call.bx, call.bx_expr) or "0"
        buffer = _dos_buffer_arg(call, far_ptr=api_style == "dos", const=call.ah == 0x40) or "NULL"
        count = _dos_arg(call.cx, call.cx_expr) or "0"
        return f"{name}({handle}, {buffer}, {count})"

    if spec.render_kind == "handle_seek":
        handle = _dos_arg(call.bx, call.bx_expr) or "0"
        offset = _dos_seek_offset_arg(call)
        origin = _dos_arg(call.al, call.al_expr) or "0"
        return f"{name}({handle}, {offset}, {origin})"

    if spec.render_kind == "drive_buffer":
        drive = _dos_drive_arg(call) or "0"
        buffer = _dos_si_buffer_arg(call, far_ptr=api_style == "dos", const=False) or "NULL"
        return f"{name}({drive}, {buffer})"

    if spec.render_kind == "setvect":
        vector = _dos_vector_arg(call) or "0"
        handler = _dos_far_pointer_arg(call) or "NULL"
        if api_style == "dos":
            return f"_dos_setvect({vector}, {handler})"
        if api_style == "pseudo":
            return f"{name}({vector}, {handler})"
        return f"setvect({vector}, {handler})"

    if spec.render_kind == "getvect":
        vector = _dos_vector_arg(call) or "0"
        if api_style == "dos":
            return f"_dos_getvect({vector})"
        if api_style == "pseudo":
            return f"{name}({vector})"
        return f"getvect({vector})"

    if spec.render_kind == "exit":
        exit_code = call.ax & 0xFF if call.ax is not None else 0
        return f"{name}({exit_code})"

    if spec.render_kind == "zero_arg":
        return f"{name}()"

    if spec.render_kind == "wrapper":
        return f"{name}()"

    if spec.render_kind == "setblock":
        return f"{name}()"

    if spec.render_kind == "get_version":
        return f"{name}()"

    return f"{name}()"


def _render_simple_interrupt_call(call: InterruptCall, api_style: str) -> str:
    api_style = normalize_api_style(api_style)
    spec = interrupt_service_spec(call)
    if spec is None:
        return render_dos_int21_call(call, api_style)
    if api_style == "raw":
        return f"int{call.vector:02x}()"

    if call.vector == 0x10 and spec.render_kind == "wrapper":
        if call.ah is not None:
            selector = _format_imm(call.ah)
            return f"{interrupt_service_name(call, api_style)}({selector})"
        extended = any(value is not None for value in (call.ds, call.es, call.ss, call.cs))
        if extended:
            return "int86x(0x10, &inregs, &outregs, &sregs)"
        return "int86(0x10, &inregs, &outregs)"

    name = interrupt_service_name(call, api_style)
    if call.vector == 0x16:
        selector = _dos_arg(call.ah, call.ah_expr)
        if selector is not None:
            return f"{name}({selector})"
        return f"{name}()"
    if call.vector == 0x10 and api_style in {"dos", "msc", "compiler"}:
        return f"{name}(0x10)"
    if call.vector == 0x13 and api_style == "pseudo":
        return f"{name}()"
    return f"{name}()"


def render_interrupt_call(call: InterruptCall, api_style: str) -> str:
    spec = interrupt_service_spec(call)
    if spec is None:
        return render_dos_int21_call(call, api_style)
    return _render_simple_interrupt_call(call, api_style)


def dos_helper_declarations(calls: list[DOSInt21Call], api_style: str) -> list[str]:
    api_style = normalize_api_style(api_style)
    if api_style == "raw":
        return []

    declarations: list[str] = []
    seen: set[str] = set()
    for call in calls:
        spec = _interrupt_service_spec_for_call(call)
        if spec is None:
            decl = "int dos_int21(void);"
        else:
            if spec.render_kind == "wrapper" and call.vector not in {0x21, 0x10}:
                continue
            if call.vector == 0x10 and call.ah is None:
                continue
            decl = _interrupt_service_decl(spec, api_style)
        if decl not in seen:
            seen.add(decl)
            declarations.append(decl)
    return declarations


def interrupt_service_declarations(calls: list[InterruptCall], api_style: str) -> list[str]:
    api_style = normalize_api_style(api_style)
    if api_style == "raw":
        return []

    declarations: list[str] = []
    seen: set[str] = set()
    for call in calls:
        spec = _interrupt_service_spec_for_call(call)
        if spec is None:
            decls = dos_helper_declarations([call], api_style)
            for decl in decls:
                if decl not in seen:
                    seen.add(decl)
                    declarations.append(decl)
            continue

        if spec.render_kind == "wrapper" and call.vector not in {0x21, 0x10}:
            continue
        if call.vector == 0x10 and call.ah is None:
            continue

        decl = _interrupt_service_decl(spec, api_style)
        if decl not in seen:
            seen.add(decl)
            declarations.append(decl)
    return declarations


def _absolute_mem_disp(operand) -> int | None:
    mem = getattr(operand, "mem", None)
    if mem is None:
        return None
    if getattr(mem, "base", 0) != 0 or getattr(mem, "index", 0) != 0:
        return None
    return getattr(mem, "disp", 0) & 0xFFFF


def _initial_cs_linear_base(project) -> int | None:
    initial_regs = getattr(project.loader.main_object, "initial_register_values", None)
    if not initial_regs:
        return None
    cs = initial_regs.get("cs")
    if cs is None:
        return None
    return (cs & 0xFFFF) << 4


def _canonical_code_linear_addr(project, addr: int | None) -> int | None:
    if not isinstance(addr, int):
        return None
    original_project = getattr(project, "_inertia_original_project", None)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if original_project is None or not isinstance(original_delta, int):
        return addr

    original_main = getattr(getattr(original_project, "loader", None), "main_object", None)
    original_base = getattr(original_main, "linked_base", None)
    if not isinstance(original_base, int):
        return addr
    if addr < original_base:
        return addr + original_delta
    return addr


def _neighbor_image_bounds(project) -> tuple[int | None, int | None]:
    candidate_projects = [getattr(project, "_inertia_original_project", None), project]
    for candidate_project in candidate_projects:
        main_object = getattr(getattr(candidate_project, "loader", None), "main_object", None)
        linked_base = getattr(main_object, "linked_base", None)
        max_addr = getattr(main_object, "max_addr", None)
        if isinstance(linked_base, int) and isinstance(max_addr, int):
            return linked_base, linked_base + max_addr + 1
    return None, None


def _direct_call_insn_from_block(project, block_addr: int):
    block = project.factory.block(block_addr, opt_level=0)
    insns = getattr(getattr(block, "capstone", None), "insns", ()) or ()
    if not insns:
        return None

    for insn in insns:
        if getattr(insn, "address", None) != block_addr:
            continue
        mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
        if mnemonic in {"call", "lcall"}:
            return insn

    last = insns[-1]
    mnemonic = str(getattr(last, "mnemonic", "") or "").lower()
    if mnemonic in {"call", "lcall"}:
        return last
    return None


def _resolve_direct_call_target_from_insn(project, insn) -> int | None:
    operands = getattr(getattr(insn, "insn", None), "operands", ()) or ()
    mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()

    if mnemonic == "lcall" and len(operands) == 2 and all(getattr(op, "type", None) == 2 for op in operands):
        seg = operands[0].imm & 0xFFFF
        off = operands[1].imm & 0xFFFF
        return _canonical_code_linear_addr(project, (seg << 4) + off)

    if mnemonic == "call" and len(operands) == 1 and getattr(operands[0], "type", None) == 2:
        return _canonical_code_linear_addr(project, operands[0].imm & 0xFFFF)

    return None


def resolve_direct_call_target_from_block(project, block_addr: int) -> int | None:
    """
    Recover a direct call target from a block-end call or a callsite inside a block.

    This is intentionally narrow and only handles the direct near/far forms
    that show up in our DOS samples. Indirect calls still return ``None``.
    """

    insn = _direct_call_insn_from_block(project, block_addr)
    if insn is None:
        return None
    return _resolve_direct_call_target_from_insn(project, insn)


def resolve_direct_jump_target_from_block(project, block_addr: int) -> int | None:
    """
    Recover a direct jump target from the last instruction in a block.

    This is used for tail-jump thunks that should seed neighbor recovery even
    when no explicit call edge exists.
    """

    block = project.factory.block(block_addr, opt_level=0)
    insns = getattr(block.capstone, "insns", ())
    if not insns:
        return None

    last = insns[-1]
    capstone_insn = getattr(last, "insn", None)
    operands = getattr(capstone_insn, "operands", ()) if capstone_insn is not None else ()

    if last.mnemonic == "ljmp" and len(operands) == 2 and all(op.type == 2 for op in operands):
        seg = operands[0].imm & 0xFFFF
        off = operands[1].imm & 0xFFFF
        return _canonical_code_linear_addr(project, (seg << 4) + off)

    if last.mnemonic == "jmp" and len(operands) == 1 and operands[0].type == 2:
        return _canonical_code_linear_addr(project, operands[0].imm & 0xFFFF)

    op_str = str(getattr(last, "op_str", "") or "").strip().lower()
    if last.mnemonic == "jmp" and op_str and "[" not in op_str:
        for token in op_str.replace(":", " ").split():
            try:
                return _canonical_code_linear_addr(project, int(token, 0) & 0xFFFF)
            except ValueError:
                continue

    return None


def patch_direct_call_sites(function) -> bool:
    """
    Recover direct near/far callsites from block ends when CFG left `_call_sites` empty.

    Rebased exact-region recovery for small 16-bit functions sometimes keeps the
    block boundaries but loses the function callsite inventory. Downstream
    callsite summaries and argument recovery consume `Function.get_call_sites()`,
    so patch the direct block-end calls back into `_call_sites` before later
    passes give up on call reasoning.
    """

    project = getattr(function, "project", None)
    if project is None or getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return False

    call_sites = getattr(function, "_call_sites", None)
    if not isinstance(call_sites, dict):
        return False
    if call_sites:
        return False

    changed = False
    for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        if not insns:
            continue
        for insn in insns:
            mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
            if mnemonic not in {"call", "lcall"}:
                continue
            callsite_addr = getattr(insn, "address", None)
            if not isinstance(callsite_addr, int):
                continue
            target_addr = _resolve_direct_call_target_from_insn(project, insn)
            if target_addr is None:
                target_addr = resolve_stored_near_call_target_from_function(function, callsite_addr)
            if target_addr is None:
                continue
            size = getattr(insn, "size", None)
            if not isinstance(size, int) or size <= 0:
                size = getattr(getattr(insn, "insn", None), "size", None)
            return_addr = None
            if isinstance(size, int) and size > 0:
                return_addr = callsite_addr + size
            current = call_sites.get(callsite_addr)
            recovered = (target_addr, return_addr)
            if current != recovered:
                call_sites[callsite_addr] = recovered
                changed = True
    return changed


def resolve_stored_near_call_target_from_function(function, callsite_addr: int) -> int | None:
    """
    Recover a near call target from a startup-built absolute pointer slot.

    This is intentionally narrow. It only handles patterns like:

        mov word ptr ss:[0x60], 0x01a2
        ...
        call word ptr [0x60]

    which appear in MSC startup code for real-mode DOS.
    """

    project = function.project
    if project is None:
        return None

    block = project.factory.block(callsite_addr, opt_level=0)
    insns = getattr(block.capstone, "insns", ())
    if not insns:
        return None
    last = insns[-1]
    capstone_insn = getattr(last, "insn", None)
    operands = getattr(capstone_insn, "operands", ()) if capstone_insn is not None else ()
    if last.mnemonic != "call" or len(operands) != 1 or operands[0].type != 3:
        return None

    slot_disp = _absolute_mem_disp(operands[0])
    if slot_disp is None:
        return None

    cs_base = _initial_cs_linear_base(project)
    if cs_base is None:
        return None

    prior_insns = []
    for addr in sorted(function.block_addrs_set):
        if addr >= callsite_addr:
            continue
        prior_block = project.factory.block(addr, opt_level=0)
        prior_insns.extend(getattr(prior_block.capstone, "insns", ()))

    for ins in reversed(prior_insns):
        if ins.address >= callsite_addr:
            continue
        opers = getattr(ins.insn, "operands", ())
        if ins.mnemonic != "mov" or len(opers) != 2:
            continue
        dst, src = opers
        if dst.type != 3 or src.type != 2:
            continue
        dst_disp = _absolute_mem_disp(dst)
        if dst_disp != slot_disp:
            continue
        return _canonical_code_linear_addr(project, cs_base + (src.imm & 0xFFFF))

    return None


def resolve_stored_near_jump_target_from_function(function, jump_addr: int) -> int | None:
    """
    Recover a near jump target from a startup-built absolute pointer slot.

    This mirrors ``resolve_stored_near_call_target_from_function`` for tail-jump
    thunks that end in ``jmp word ptr [slot]``.
    """

    project = function.project
    if project is None:
        return None

    block = project.factory.block(jump_addr, opt_level=0)
    insns = getattr(block.capstone, "insns", ())
    if not insns:
        return None
    last = insns[-1]
    capstone_insn = getattr(last, "insn", None)
    operands = getattr(capstone_insn, "operands", ()) if capstone_insn is not None else ()
    if last.mnemonic != "jmp" or len(operands) != 1 or operands[0].type != 3:
        return None

    slot_disp = _absolute_mem_disp(operands[0])
    if slot_disp is None:
        return None

    cs_base = _initial_cs_linear_base(project)
    if cs_base is None:
        return None

    prior_insns = []
    for addr in sorted(function.block_addrs_set):
        if addr >= jump_addr:
            continue
        prior_block = project.factory.block(addr, opt_level=0)
        prior_insns.extend(getattr(prior_block.capstone, "insns", ()))

    for ins in reversed(prior_insns):
        if ins.address >= jump_addr:
            continue
        opers = getattr(ins.insn, "operands", ())
        if ins.mnemonic != "mov" or len(opers) != 2:
            continue
        dst, src = opers
        if dst.type != 3 or src.type != 2:
            continue
        dst_disp = _absolute_mem_disp(dst)
        if dst_disp != slot_disp:
            continue
        return _canonical_code_linear_addr(project, cs_base + (src.imm & 0xFFFF))

    return None


def collect_direct_far_call_targets(function) -> list[FarCallTarget]:
    """
    Recover direct or startup-recoverable call targets directly from lifted blocks.

    angr's stock call-target recovery does not currently understand the x86-16
    `CS:IP` far-call pattern very well, so medium-model DOS startup code often
    ends up with `UnresolvableCallTarget` call edges even when the block itself
    is fully understood. This helper keeps the workaround small, explicit, and
    reusable for CLI tooling and tests.
    """

    if function.project is None or function.project.arch.name != "86_16":
        return []

    project = function.project
    recovered: list[FarCallTarget] = []

    for callsite_addr in sorted(function.get_call_sites()):
        target_addr = resolve_direct_call_target_from_block(project, callsite_addr)
        if target_addr is None:
            target_addr = resolve_stored_near_call_target_from_function(function, callsite_addr)
        # Real-mode far calls commonly land below 64 KiB once segment:offset is
        # linearized (for example 0x0114:0x0240 -> 0x1380). Only discard calls
        # we still failed to resolve, not low linear addresses.
        if target_addr is None:
            continue

        recovered.append(
            FarCallTarget(
                callsite_addr=callsite_addr,
                target_addr=target_addr,
                return_addr=function.get_call_return(callsite_addr),
            )
        )

    return recovered


def collect_neighbor_call_targets(function) -> list[CallTargetSeed]:
    """
    Recover direct x86-16 call neighbors from a function's traced call sites.

    We prefer targets already recorded by CFG when they stay inside the loaded
    image, then fall back to block-level decoding for direct near/far calls and
    the narrow startup pointer-slot recovery used by MSC-style startup code.
    """

    project = getattr(function, "project", None)
    if project is None or project.arch.name != "86_16":
        return []

    patch_direct_call_sites(function)

    linked_base, image_end = _neighbor_image_bounds(project)

    recovered: list[CallTargetSeed] = []
    seen: set[tuple[int, int]] = set()
    far_targets = {
        (target.callsite_addr, target.target_addr): target for target in collect_direct_far_call_targets(function)
    }

    for callsite_addr in sorted(function.get_call_sites()):
        target_addr = None
        kind = "existing"
        try:
            target_addr = function.get_call_target(callsite_addr)
        except Exception:
            target_addr = None
        if not isinstance(target_addr, int):
            target_addr = None
        if target_addr is not None and image_end is not None and not (linked_base <= target_addr < image_end):
            target_addr = None

        far_target = far_targets.get((callsite_addr, target_addr)) if target_addr is not None else None
        if far_target is not None:
            kind = "direct_far"
        elif target_addr is None:
            direct_target = resolve_direct_call_target_from_block(project, callsite_addr)
            if direct_target is not None:
                target_addr = direct_target
                kind = "direct_far" if (callsite_addr, direct_target) in far_targets else "direct_near"
            else:
                stored_target = resolve_stored_near_call_target_from_function(function, callsite_addr)
                if stored_target is not None:
                    target_addr = stored_target
                    kind = "stored_near"
        if target_addr is None:
            continue
        if image_end is not None and not (linked_base <= target_addr < image_end):
            continue
        key = (callsite_addr, target_addr)
        if key in seen:
            continue
        seen.add(key)
        recovered.append(
            CallTargetSeed(
                callsite_addr=callsite_addr,
                target_addr=target_addr,
                return_addr=function.get_call_return(callsite_addr),
                kind=kind,
            )
        )

    block_addrs = sorted(getattr(function, "block_addrs_set", ()))
    block_addr_set = set(block_addrs)
    for block_addr in block_addrs:
        jump_target = resolve_direct_jump_target_from_block(project, block_addr)
        kind = "tail_jump"
        if jump_target is None:
            jump_target = resolve_stored_near_jump_target_from_function(function, block_addr)
            if jump_target is not None:
                kind = "stored_tail_jump"
        if jump_target is None:
            continue
        if jump_target in block_addr_set or jump_target == function.addr:
            continue
        if image_end is not None and not (linked_base <= jump_target < image_end):
            continue
        key = (block_addr, jump_target)
        if key in seen:
            continue
        seen.add(key)
        recovered.append(
            CallTargetSeed(
                callsite_addr=block_addr,
                target_addr=jump_target,
                return_addr=None,
                kind=kind,
            )
        )

    return recovered


def patch_far_call_sites(function, far_targets: list[FarCallTarget]) -> bool:
    """
    Rewrite Function._call_sites for immediate far calls recovered from blocks.

    CFGFast currently leaves some x86-16 far callsites pointing at a bogus short
    target (for example `0x14`) even when the block disassembly clearly shows an
    immediate `seg:off` far call. The decompiler reads `Function.get_call_target()`
    from `_call_sites`, so patching those entries gives downstream analyses a
    much better callee address without needing to modify site-packages angr.
    """

    changed = False

    for target in far_targets:
        old = function._call_sites.get(target.callsite_addr)
        new = (target.target_addr, target.return_addr)
        if old != new:
            function._call_sites[target.callsite_addr] = new
            changed = True

    return changed


def patch_dos_int21_call_sites(function, binary_path: Path | str | None = None) -> bool:
    """
    Rewrite Function._call_sites for recoverable int 21h services.

    This gives the decompiler service-specific pseudo-callees instead of a
    single undifferentiated `dos_int21` hook at every site.
    """

    return patch_interrupt_service_call_sites(function, binary_path, vectors={0x21})


def seed_calling_conventions(cfg) -> None:
    def _is_stack_probe_helper_name(name: str | None) -> bool:
        if not isinstance(name, str):
            return False
        normalized = name.strip().lower().lstrip("_")
        return normalized in {"anchkstk", "analloca_probe"}

    for function in getattr(cfg, "functions", {}).values():
        try:
            function._init_prototype_and_calling_convention()
        except Exception as ex:
            logging.getLogger(__name__).debug("prototype init skipped: %s", ex)
            continue
        if _is_stack_probe_helper_name(getattr(function, "name", None)):
            with contextlib.suppress(Exception):
                function.returning = True


def extend_cfg_for_far_calls(project, function, *, entry_window: int, callee_window: int = 0x80):
    """
    Re-run CFG with direct far callees seeded as extra function starts.

    This keeps bounded DOS startup recovery focused on the functions actually
    reached by immediate far calls, instead of forcing a broad CFG window that
    quickly runs into unrelated unsupported instructions.
    """

    far_targets = collect_direct_far_call_targets(function)
    if not far_targets:
        return None

    patch_far_call_sites(function, far_targets)

    function_starts = [function.addr, *(target.target_addr for target in far_targets)]
    regions = [(function.addr, function.addr + entry_window)]
    regions.extend((target.target_addr, target.target_addr + callee_window) for target in far_targets)

    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=sorted(set(function_starts)),
        regions=regions,
        normalize=True,
        force_complete_scan=False,
    )
    seed_calling_conventions(cfg)
    all_targets = list(far_targets)
    if function.addr in cfg.functions:
        recovered_function = cfg.functions[function.addr]
        recovered_targets = collect_direct_far_call_targets(recovered_function)
        merged: dict[tuple[int, int], FarCallTarget] = {
            (target.callsite_addr, target.target_addr): target for target in far_targets
        }
        for target in recovered_targets:
            merged[(target.callsite_addr, target.target_addr)] = target
        all_targets = list(merged.values())
        patch_far_call_sites(recovered_function, all_targets)
    for target in all_targets:
        callee = cfg.kb.functions.function(addr=target.target_addr, create=True)
        if callee is not None:
            callee._init_prototype_and_calling_convention()
    seed_calling_conventions(cfg)
    return cfg


# ── Function discovery ranking ──


@dataclass(frozen=True)
class EntryScore:
    """Deterministic entry-point confidence score for function discovery ranking."""

    addr: int
    score: int
    source: str = ""


def score_entry_address_8616(
    addr: int,
    *,
    is_explicit_entry: bool = False,
    is_direct_call_target: bool = False,
    is_mz_relocation_target: bool = False,
    has_prologue_match: bool = False,
    is_interrupt_service: bool = False,
    is_known_wrapper: bool = False,
    source_hint: str = "",
) -> EntryScore:
    """Compute a deterministic entry score for function discovery ranking.

    Weighted signal combination with address ascending as tie-break.
    Higher score = stronger evidence this is a real function entry point.

    Signals:
        explicit_entry:         +100  (MZ/NE entry point, linker entry)
        direct_call_target:     +80   (called by another function)
        mz_relocation_target:   +60   (MZ relocation entry)
        prologue_match:         +40   (push bp / mov bp,sp pattern)
        interrupt_service:      +20   (interrupt vector target)
        known_wrapper:          -30   (runtime/compiler wrapper, e.g. __acrtused)

    Tie-break: address ascending (lower addr = earlier = higher priority).
    """
    score = 0
    if is_explicit_entry:
        score += 100
    if is_direct_call_target:
        score += 80
    if is_mz_relocation_target:
        score += 60
    if has_prologue_match:
        score += 40
    if is_interrupt_service:
        score += 20
    if is_known_wrapper:
        score -= 30

    return EntryScore(addr=addr, score=score, source=source_hint)


def rank_entry_addresses_8616(
    entries: list[tuple[int, dict[str, object]]],
) -> list[EntryScore]:
    """Sort entry addresses by discovery confidence score, descending.

    Each entry is (addr, signals_dict).  Signals dict may contain:
        explicit_entry, direct_call_target, mz_relocation_target,
        prologue_match, interrupt_service, known_wrapper, source.

    Tie-break: address ascending.
    """
    scored = [
        score_entry_address_8616(
            addr,
            is_explicit_entry=bool(signals.get("explicit_entry")),
            is_direct_call_target=bool(signals.get("direct_call_target")),
            is_mz_relocation_target=bool(signals.get("mz_relocation_target")),
            has_prologue_match=bool(signals.get("prologue_match")),
            is_interrupt_service=bool(signals.get("interrupt_service")),
            is_known_wrapper=bool(signals.get("known_wrapper")),
            source_hint=str(signals.get("source", "")),
        )
        for addr, signals in entries
    ]
    # Higher score first; tie-break by address ascending
    scored.sort(key=lambda e: (-e.score, e.addr))
    return scored


def extend_cfg_for_neighbor_calls(
    project,
    function,
    *,
    entry_window: int,
    callee_window: int = 0x80,
    max_targets: int = 8,
):
    """
    Re-run bounded CFG with nearby traced callees seeded as extra starts.

    This keeps 16-bit function recovery local: once we recover one function we
    immediately reuse its traced call neighbors instead of widening into a
    broader scan of unrelated code bytes.
    """

    neighbor_targets = collect_neighbor_call_targets(function)
    if not neighbor_targets:
        return None

    far_targets = collect_direct_far_call_targets(function)
    if far_targets:
        patch_far_call_sites(function, far_targets)

    unique_targets: list[CallTargetSeed] = []
    seen_targets: set[int] = {function.addr}
    for target in sorted(
        neighbor_targets,
        key=lambda item: (abs(item.target_addr - function.addr), item.callsite_addr, item.target_addr),
    ):
        if target.target_addr in seen_targets:
            continue
        seen_targets.add(target.target_addr)
        unique_targets.append(target)
        if len(unique_targets) >= max_targets:
            break
    if not unique_targets:
        return None

    function_starts = [function.addr, *(target.target_addr for target in unique_targets)]
    regions = [(function.addr, function.addr + entry_window)]
    regions.extend((target.target_addr, target.target_addr + callee_window) for target in unique_targets)

    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=sorted(set(function_starts)),
        regions=regions,
        normalize=True,
        force_complete_scan=False,
    )
    seed_calling_conventions(cfg)

    if function.addr in cfg.functions:
        recovered_function = cfg.functions[function.addr]
        recovered_far_targets = collect_direct_far_call_targets(recovered_function)
        if recovered_far_targets:
            patch_far_call_sites(recovered_function, recovered_far_targets)
    for target in unique_targets:
        callee = cfg.kb.functions.function(addr=target.target_addr, create=True)
        if callee is not None:
            callee._init_prototype_and_calling_convention()
    seed_calling_conventions(cfg)
    return cfg
