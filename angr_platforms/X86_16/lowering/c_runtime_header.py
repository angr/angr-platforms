from __future__ import annotations


def render_c_runtime_header_8616(target: str | None) -> str:
    normalized = str(target or "").strip().lower()
    if normalized == "msc-dos":
        return (
            "#include <dos.h>\n"
            "#include <stdint.h>\n"
            "\n"
            "typedef unsigned char  uint8_t;\n"
            "typedef unsigned short uint16_t;\n"
            "typedef unsigned long  uint32_t;\n"
            "\n"
            "#define SEG_PTR(seg, off)  MK_FP((seg), (off))\n"
            "#define SEG_U8(seg, off)   (*(uint8_t  far *)MK_FP((seg), (off)))\n"
            "#define SEG_U16(seg, off)  (*(uint16_t far *)MK_FP((seg), (off)))\n"
            "#define SEG_U32(seg, off)  (*(uint32_t far *)MK_FP((seg), (off)))\n"
        )
    if normalized == "portable-flat":
        return (
            "#include <stdbool.h>\n"
            "#include <stdint.h>\n"
            "\n"
            "typedef unsigned long clock_t;\n"
            "typedef long time_t;\n"
            "\n"
            "extern uint8_t inertia_memory[];\n"
            "\n"
            "#ifndef far\n"
            "#define far\n"
            "#endif\n"
            "\n"
            "#define SEG_LINEAR(seg, off) ((((uint32_t)(uintptr_t)(seg)) << 4) + ((uint16_t)(uintptr_t)(off)))\n"
            "#define MK_FP(seg, off)      (&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_PTR(seg, off)    (&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_U8(seg, off)     (*(uint8_t  *)&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_U16(seg, off)    (*(uint16_t *)&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_U32(seg, off)    (*(uint32_t *)&inertia_memory[SEG_LINEAR((seg), (off))])\n"
        )
    return ""


__all__ = ["render_c_runtime_header_8616"]
