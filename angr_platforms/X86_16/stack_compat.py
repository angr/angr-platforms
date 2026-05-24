from __future__ import annotations

from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions

__all__ = ["apply_x86_16_stack_compatibility"]


def apply_x86_16_stack_compatibility() -> None:
    _orig_stack_offset_to_stack_addr = LiveDefinitions.stack_offset_to_stack_addr

    def _stack_offset_to_stack_addr_8616(self, offset) -> int:
        if getattr(self.arch, "bits", None) == 16:
            return (0x7FFE + offset) & 0xFFFF
        return _orig_stack_offset_to_stack_addr(self, offset)

    if getattr(LiveDefinitions.stack_offset_to_stack_addr, "__name__", "") != "_stack_offset_to_stack_addr_8616":
        LiveDefinitions.stack_offset_to_stack_addr = _stack_offset_to_stack_addr_8616


