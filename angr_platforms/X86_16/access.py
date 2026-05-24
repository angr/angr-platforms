from pyvex.lifting.util import JumpKind
from pyvex.lifting.util.vex_helper import Type

ITY_I8 = Type.int_8
ITY_I16 = Type.int_16
ITY_I32 = Type.int_32

from .addressing_helpers import ResolvedMemoryOperand, linear_address, resolve_memory_operand_8616
from .hardware import Hardware
from .regs import reg16_t, sgreg_t
from .stack_helpers import pop16, pop32, push16, push32, push_far_return_frame16

# Constants for access modes
MODE_READ = 0
MODE_WRITE = 1
MODE_EXEC = 2

# Module-level fact cache — bridges ephemeral emulator → persistent pipeline.
# Key = function address (int), value = list of AliasStorageFacts/AliasFailure.
# Populated by _record_semantic_memory_access() during VEX lifting.
# Consumed by collect_semantic_alias_facts_from_project_8616().
_inertia_module_alias_fact_cache: dict[int, list[object]] = {}


class DataAccess(Hardware):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tlb = []  # Translation Lookaside Buffer
        self._inertia_last_resolved_operand = None
        self._inertia_resolved_operands = []

    def set_segment(self, reg, sel):
        self.set_gpreg(reg, sel)

    def get_segment(self, reg):
        return self.get_sgreg(reg)

    def convert_ss_vaddr(self, vaddr):
        _, off = self.convert_segoff2vexv(sgreg_t.SS, vaddr)
        ss = self.get_sgreg(sgreg_t.SS).cast_to(ITY_I32)
        return (ss << 4) + off

    def v2p(self, seg, off):
        sg, vaddr = self.convert_segoff2vexv(seg, off)
        return (sg << 4) + vaddr

    def convert_segoff2vexv(self, seg, vaddr):
        if isinstance(seg, sgreg_t):
            sg = self.get_sgreg(seg)
        elif isinstance(seg, int):
            sg = self.constant(seg, ITY_I16)
        else:
            sg = seg
        if not isinstance(vaddr, int):
            vaddr = vaddr.cast_to(ITY_I32)
        sg = sg.cast_to(ITY_I32)
        return sg, vaddr

    def _record_resolved_operand(self, operand: ResolvedMemoryOperand, mode: int) -> ResolvedMemoryOperand:
        self._inertia_last_resolved_operand = operand
        history = getattr(self, "_inertia_resolved_operands", None)
        if not isinstance(history, list):
            history = []
            self._inertia_resolved_operands = history
        history.append((mode, operand))
        self._record_semantic_memory_access(operand, mode)
        return operand

    def _record_semantic_memory_access(self, operand: ResolvedMemoryOperand, mode: int) -> None:
        """Record typed IR address for alias/type consumption.

        The execution path still uses operand.exec_linear (linear) for the actual
        read/write.  This log is consumed by the alias and type recovery layers.

        AGENTS rule #3: exec_linear is execution-only; assert_semantic_safe()
        blocks accidental leakage of linear IR into semantic layers.
        """
        from .ir.core import IRAddress

        # Hard block: no linear addresses in semantic logs
        operand.assert_semantic_safe()

        semantic_log = getattr(self, "_inertia_semantic_access_log", None)
        if not isinstance(semantic_log, list):
            semantic_log = []
            self._inertia_semantic_access_log = semantic_log

        addr = operand.ir_address()

        # Do NOT create alias facts here.
        # Lifting may only record semantic IR addresses.
        # Alias facts are produced after stack-frame normalization
        # in collect_normalized_semantic_alias_facts_from_project_8616().

        if isinstance(addr, IRAddress):
            semantic_log.append((mode, addr))
            # Write to canonical evidence_cache.
            #
            # During initial CFG construction, function context is unknown.
            # Record by BLOCK address (available from the emulator's lifter/irsb).
            # The collection phase (fact_transfer.py) migrates block→function
            # via migrate_block_accesses_to_function().
            #
            # When function context IS known (re-lift), record directly by function.
            from .semantics.evidence_cache import (
                get_current_function_addr,
                get_accesses_for_block,
                record_access,
                record_access_by_block,
            )
            func_addr = get_current_function_addr()
            if isinstance(func_addr, int):
                record_access(
                    function_addr=func_addr,
                    mode=mode,
                    addr=addr,
                )
            else:
                # No function context — record by block address.
                # The lifter sets _inertia_current_block_addr on the emulator
                # before lifting each block (lift_86_16.py line ~98/115).
                block_addr = getattr(self, "_inertia_current_block_addr", None)
                if isinstance(block_addr, int):
                    record_access_by_block(
                        block_addr=block_addr,
                        mode=mode,
                        addr=addr,
                    )
                else:
                    # No block address either — truly uncollected
                    _uncollected = getattr(self, "_inertia_uncollected_accesses", 0)
                    self._inertia_uncollected_accesses = _uncollected + 1

    def _resolve_memory_operand(self, seg, addr, width_bits: int, mode: int) -> ResolvedMemoryOperand:
        operand = self._resolved_segment_operand(seg, addr, width_bits)
        self._record_resolved_operand(operand, mode)
        return operand

    def _resolved_segment_operand(self, seg, addr, width_bits: int) -> ResolvedMemoryOperand:
        return resolve_memory_operand_8616(self, seg, addr, width_bits, address_bits=16)

    def search_tlb(self, vpn):
        if vpn + 1 > len(self.tlb) or self.tlb[vpn] is None:
            return None
        return self.tlb[vpn]

    def cache_tlb(self, vpn, pte):
        if vpn + 1 > len(self.tlb):
            self.tlb.extend([None] * (vpn + 1 - len(self.tlb)))
        self.tlb[vpn] = pte

    def push32(self, value):
        push32(self, value)

    def pop32(self):
        return pop32(self)

    def push16(self, value):
        push16(self, value)

    def pop16(self):
        return pop16(self)

    def read_mem32_seg(self, seg, addr):
        operand = self._resolve_memory_operand(seg, addr, 32, MODE_READ)
        return self.read_mem32(operand.exec_linear)

    def read_mem16_seg(self, seg, addr):
        operand = self._resolve_memory_operand(seg, addr, 16, MODE_READ)
        return self.read_mem16(operand.exec_linear)

    def read_mem8_seg(self, seg, addr):
        operand = self._resolve_memory_operand(seg, addr, 8, MODE_READ)
        return self.read_mem8(operand.exec_linear)

    def write_mem32_seg(self, seg, addr, value):
        operand = self._resolve_memory_operand(seg, addr, 32, MODE_WRITE)
        self.write_mem32(operand.exec_linear, value)

    def write_mem16_seg(self, seg, addr, value):
        operand = self._resolve_memory_operand(seg, addr, 16, MODE_WRITE)
        self.write_mem16(operand.exec_linear, value)

    def write_mem8_seg(self, seg, addr, value):
        operand = self._resolve_memory_operand(seg, addr, 8, MODE_WRITE)
        self.write_mem8(operand.exec_linear, value)

    def get_code8(self, offset):
        assert offset == 0
        return self.bitstream.read("uint:8")

    def get_code16(self, offset):
        assert offset == 0
        return self.bitstream.read("uintle:16")

    def get_code32(self, offset):
        assert offset == 0
        return self.bitstream.read("uintle:32")

    def get_data16(self, seg, addr):
        return self.read_mem16_seg(seg, addr)

    def get_data32(self, seg, addr):
        return self.read_mem32_seg(seg, addr)

    def get_data8(self, seg, addr):
        return self.read_mem8_seg(seg, addr)

    def put_data8(self, seg, addr, value):
        self.write_mem8_seg(seg, addr, value)

    def put_data16(self, seg, addr, value):
        self.write_mem16_seg(seg, addr, value)

    def put_data32(self, seg, addr, value):
        self.write_mem32_seg(seg, addr, value)

    def callf(self, seg, ip, return_ip=None):
        push_far_return_frame16(self, return_ip)
        self.set_sgreg(sgreg_t.CS, seg)
        self.set_gpreg(reg16_t.IP, ip)
        laddr = linear_address(self, seg, ip)
        self.lifter_instruction.jump(None, laddr, jumpkind=JumpKind.Call)

    def jmpf(self, seg, ip):
        self.set_sgreg(sgreg_t.CS, seg)
        self.set_gpreg(reg16_t.IP, ip)
        laddr = linear_address(self, seg, ip)
        self.lifter_instruction.jump(None, laddr, jumpkind=JumpKind.Boring)