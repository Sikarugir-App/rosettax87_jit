"""
Hex-Rays plugin for Rosetta JIT trace databases.

Resolves indirect calls through stub_branch_slot into direct calls
to jit_<x86_addr> functions, using the xrefs set up by the loader.

Installation:
  Symlink to <IDA>/plugins/
  e.g. /Applications/IDA Professional 9.3.app/Contents/MacOS/plugins/

Auto-activates when a Rosetta trace IDB is detected (rt_routines segment).
"""

import ida_idaapi
import ida_segment
import ida_name
import ida_xref
import ida_kernwin
import ida_ua
import ida_bytes
import ida_funcs


_STUB_NAMES = [
    "stub_branch_slot",
    "stub_indirect_jmp",
    "stub_indirect_call",
    "stub_indirect_jmp_dyld_stub",
    "stub_return_stack_miss",
]


def _find_stub_addrs():
    """Find stub addresses by name lookup."""
    if not ida_segment.get_segm_by_name("rt_routines"):
        return None

    addrs = set()
    for name in _STUB_NAMES:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        if ea != ida_idaapi.BADADDR:
            addrs.add(ea)
    return addrs if addrs else None


class RosettaHexraysPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    comment = "Rosetta JIT stub call resolver for Hex-Rays"
    help = ""
    wanted_name = "RosettaHexrays"
    wanted_hotkey = ""

    def init(self):
        try:
            import ida_hexrays
            if not ida_hexrays.init_hexrays_plugin():
                return ida_idaapi.PLUGIN_SKIP
        except ImportError:
            return ida_idaapi.PLUGIN_SKIP

        stub_addrs = _find_stub_addrs()
        if not stub_addrs:
            return ida_idaapi.PLUGIN_SKIP

        self._install(ida_hexrays, stub_addrs)
        return ida_idaapi.PLUGIN_KEEP

    def _install(self, ida_hexrays, stub_addrs):
        class _Resolver(ida_hexrays.optinsn_t):
            def __init__(self, addrs):
                ida_hexrays.optinsn_t.__init__(self)
                self.stub_addrs = addrs

            def func(self, blk, ins, optflags):
                changes = 0
                if ins.opcode in (ida_hexrays.m_call, ida_hexrays.m_icall):
                    changes += self._try_resolve(ins)
                if ins.l.t == ida_hexrays.mop_d and ins.l.d:
                    changes += self._try_resolve(ins.l.d)
                if ins.r.t == ida_hexrays.mop_d and ins.r.d:
                    changes += self._try_resolve(ins.r.d)
                if ins.d.t == ida_hexrays.mop_d and ins.d.d:
                    changes += self._try_resolve(ins.d.d)
                return changes

            def _try_resolve(self, call_ins):
                if call_ins.opcode != ida_hexrays.m_call:
                    return 0
                if call_ins.l.t != ida_hexrays.mop_v:
                    return 0
                if call_ins.l.g not in self.stub_addrs:
                    return 0
                target = self._find_jit_target(call_ins.ea)
                if target is None:
                    target = self._find_jit_target_from_mov(call_ins.ea)
                if target is None:
                    return 0
                call_ins.l.make_gvar(target)
                if call_ins.d.t == ida_hexrays.mop_f:
                    call_ins.d.f.callee = target
                return 1

            @staticmethod
            def _find_jit_target(ea):
                ref = ida_xref.get_first_cref_from(ea)
                while ref != ida_idaapi.BADADDR:
                    name = ida_name.get_name(ref)
                    if name and name.startswith("jit_"):
                        return ref
                    ref = ida_xref.get_next_cref_from(ea, ref)
                return None

            @staticmethod
            def _find_jit_target_from_mov(ea):
                """Scan backwards for MOV X22, #imm to find x86 target addr."""
                REG_X22 = 129 + 22
                scan = ea - 4
                func = ida_funcs.get_func(ea)
                limit = func.start_ea if func else ea - 64
                for _ in range(12):
                    if scan < limit:
                        return None
                    insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(insn, scan) == 0:
                        scan -= 4
                        continue
                    mnem = insn.get_canon_mnem()
                    if mnem in ("MOV", "MOVZ") and insn.ops[0].type == 1 \
                            and insn.ops[0].reg == REG_X22 and insn.ops[1].type == 5:
                        x86_target = insn.ops[1].value
                        jit_name = "jit_%X" % x86_target
                        jit_ea = ida_name.get_name_ea(0xFFFFFFFFFFFFFFFF, jit_name)
                        if jit_ea != 0xFFFFFFFFFFFFFFFF:
                            return jit_ea
                        return None
                    scan -= 4
                return None

        self.resolver = _Resolver(stub_addrs)
        self.resolver.install()
        ida_kernwin.msg("Rosetta Hex-Rays: stub call resolver active (%d stubs)\n"
                        % len(stub_addrs))

    def run(self, arg):
        pass

    def term(self):
        if hasattr(self, 'resolver'):
            self.resolver.remove()


def PLUGIN_ENTRY():
    return RosettaHexraysPlugin()
