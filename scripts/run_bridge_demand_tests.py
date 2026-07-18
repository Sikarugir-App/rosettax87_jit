#!/usr/bin/env python3
"""run_bridge_demand_tests.py — test the bridge-demand estimation model.

Branch-complete empirical coverage of X87Cache::gap_gpr_demand: for each
family, emits a raw x86-64 blob with one instruction per demand-model
branch (plus boundary values of every encodability predicate), translates it
through aotinvoke --demand (stock Rosetta paths: all ops/fusions disabled),
and joins each `gpr_demand actual=N est=M|refuse` row back to the variant
that produced it, in program order.

The blob is never executed — only translated — so variants need no valid
addresses or runtime semantics (that is test_bridge_pressure.c's job).

Verdicts (stricter than the fixture verifier, because intent is declared):
    FAIL   actual > est                      (potential underestimate)
    FAIL   est == refuse but expect numeric  (over-refusal / prefix bug)
    FAIL   est numeric but expect refuse     (guard-rail hole)
    FAIL   est - actual > 0 without an allow_slack annotation
    SLACK  est - actual > 0 with allow_slack (documented over-estimate)
    PASS   otherwise
Plus a branch-coverage summary: every `branch=` label must be hit >= 1 time.

Spec-completeness is reviewed by diffing MATRIX[family] against the audit's
per-shape table (WORKFLOW.md §3). Shapes that x86 cannot encode for the
family (noted in UNENCODABLE) stay analytic-only.

Usage:
    run_bridge_demand_tests.py               # run ALL families with a matrix
    run_bridge_demand_tests.py <family> ...  # run specific families
    run_bridge_demand_tests.py --list        # list families and variant counts
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
AOTINVOKE = REPO / "build" / "bin" / "aotinvoke"
OUTDIR = REPO / "build" / "bridge_matrix"

# run_tests.sh-style colors (suppressed when stdout is not a tty)
if sys.stdout.isatty():
    RED, GREEN, YELLOW, CYAN, BOLD, NC = (
        "\033[0;31m", "\033[0;32m", "\033[0;33m", "\033[0;36m", "\033[1m", "\033[0m")
else:
    RED = GREEN = YELLOW = CYAN = BOLD = NC = ""

ROW_RE = re.compile(
    r"^\s*([0-9a-f]+)\s+(\S+)\s+(.*?)\s*;\s*gpr_demand actual=(\d+) est=(\d+|refuse)\s*$"
)


@dataclass
class V:
    """One matrix variant: an instruction targeting one model branch."""
    asm: str
    branch: str
    expect: str = "auto"        # "auto" (est==actual) | "refuse"
    allow_slack: str = ""       # non-empty: documented over-estimate reason
    pad: bool = False           # joined against its IR row but NOT graded —
                                # used for flag consumers/killers that shape
                                # the flag_liveness of the PRECEDING variant


# ── generic shape generators (shared across families) ───────────────────────
# Access-size log2 by AT&T suffix; boundary displacements are derived from it.
SUFFIX_LOG2 = {"b": 0, "w": 1, "l": 2, "q": 3}
REG_BY_SUFFIX = {"b": "%dl", "w": "%dx", "l": "%edx", "q": "%rdx"}


def base_disp(mnem: str, suffix: str = "q", reg: str | None = None,
              store: bool = False) -> list[V]:
    """[base + disp] boundary sweep for one access size.

    Boundaries per ldst_disp_encodable: scaled unsigned imm12
    (disp>>log2 <= 0xFFF, exactly scaled), signed imm9 (-0x100..0xFF).
    """
    lg = SUFFIX_LOG2[suffix]
    scale = 1 << lg
    reg = reg or REG_BY_SUFFIX[suffix]
    cases = [
        (0,                "disp 0 (passthrough)"),
        (0xFF,             "imm9 max"),
        (-0x100,           "imm9 min"),
        (0xFFF * scale,    "scaled imm12 max"),
        (0x1000 * scale,   "scaled imm12 max + 1 (non-encodable)"),
        (-0x101,           "below imm9, negative (non-encodable)"),
        (0x12345,          "large non-encodable"),
    ]
    if scale > 1:
        cases.append((scale + 1, "unscaled/unaligned (imm9 if small)"))
    out = []
    for disp, why in cases:
        src, dst = (reg, f"{disp:#x}(%rax)") if store else (f"{disp:#x}(%rax)", reg)
        out.append(V(f"{mnem}{suffix} {src}, {dst}",
                     branch=f"prefetch base-only {suffix}: {why}"))
    return out


def sib(mnem: str, suffix: str = "q", reg: str | None = None,
        store: bool = False) -> list[V]:
    """[base + index*scale (+disp)] sweep: every scale x disp {0, small, large}."""
    lg = SUFFIX_LOG2[suffix]
    reg = reg or REG_BY_SUFFIX[suffix]
    out = []
    for sc in (1, 2, 4, 8):
        for disp, dtag in ((0, "disp 0"), (8, "small disp"), (0x12345, "large disp")):
            shift_note = "shift==size or 0" if (sc == 1 or sc == (1 << lg)) else "shift mismatch"
            mem = f"{disp:#x}(%rax,%rcx,{sc})" if disp else f"(%rax,%rcx,{sc})"
            src, dst = (reg, mem) if store else (mem, reg)
            out.append(V(f"{mnem}{suffix} {src}, {dst}",
                         branch=f"prefetch SIB {suffix}: scale {sc} ({shift_note}), {dtag}"))
    return out


def index_only(mnem: str, suffix: str = "q", reg: str | None = None) -> list[V]:
    reg = reg or REG_BY_SUFFIX[suffix]
    return [
        V(f"{mnem}{suffix} (,%rcx,1), {reg}",
          branch="index-only: scale 1, no disp (64-bit passthrough, exact 0)"),
        V(f"{mnem}{suffix} (,%rcx,4), {reg}",
          branch="index-only: shifted, no disp"),
        V(f"{mnem}{suffix} 0x100(,%rcx,8), {reg}",
          branch="index-only: shifted + disp (LABEL_77)"),
    ]


def rip_rel(mnem: str, suffix: str, src: str | None, dst: str | None,
            branch: str, slack: str = "") -> V:
    mem = "0x100(%rip)"
    a, b = (src, mem) if dst is None else (mem, dst)
    return V(f"{mnem}{suffix} {a}, {b}", branch=branch, allow_slack=slack)


ALIGN_SLACK = ("Immediate alignment is runtime-decided "
               "(operand_addr_is_aligned reads text_base_align_offset) — "
               "model folds to the unaligned worst case")

# ── per-family matrices ──────────────────────────────────────────────────────

MATRIX: dict[str, list[V]] = {}

# Shapes the family's audit models but x86 cannot encode for these opcodes —
# analytic-only, listed so the coverage report is explicit about them.
UNENCODABLE: dict[str, list[str]] = {}

MATRIX["mov-movnti"] = [
    # -- Register sources (translate_gpr, mov AUDIT addendum A) --
    V("movb %al, %cl",   branch="reg-src low8 -> reg passthrough (26744)"),
    V("movb %ah, %cl",   branch="reg-src high-byte alloc under XZR hint (26669)"),
    V("movb %al, %ch",   branch="reg-src low8 -> high8 dst (write bitfield, 0)"),
    V("movb %ah, %ch",   branch="reg-src high-byte -> high8 dst"),
    V("movw %ax, %bx",   branch="reg-src r16 passthrough"),
    V("movl %eax, %ecx", branch="reg-src r32 arch hint (26748/26744)"),
    V("movq %rax, %rcx", branch="reg-src r64 arch hint"),
    V("movq %r8, %r15",  branch="reg-src r64 high regs"),
    V("movb %cl, (%rax)",  branch="reg-src low8 -> mem store (read 0 + store enc 0)"),
    V("movb %ah, (%rax)",  branch="reg-src high-byte -> mem store (read 1)"),
    V("movnti %ecx, (%rdi)",        branch="movnti r32 store, enc disp"),
    V("movnti %rcx, 0x12345(%rsi,%rdx,8)", branch="movnti r64 store, SIB large disp"),

    # -- BranchOffset (plain immediate) sources --
    V("movb $0x42, %al",  branch="imm -> r8: XZR hint materialization (12010-12016 analog)"),
    V("movb $0x0, %al",   branch="imm 0 -> r8: XZR-value special (emit_load_immediate value==0)"),
    V("movw $0x1234, %ax", branch="r16 <- BranchOffset special path (emit_movn, 17819)"),
    V("movl $0xdeadbeef, %eax", branch="imm -> r32 arch hint absorbs"),
    V("movq $0x12345678, %rax", branch="imm -> r64 arch hint absorbs"),
    V("movq $0x0, -0x40(%rax)", branch="imm 0 -> mem enc (both sides 0)"),
    V("movq $0x2, (%rax)",      branch="imm -> mem enc (value temp held)"),
    V("movl $0x42, 0x12345(%rax)", branch="imm -> mem non-enc (value + addr temps)"),

    # -- MemRef loads, arch hint (prefetch_allocs sweep) --
    *base_disp("mov", "q"),
    *base_disp("mov", "b", reg="%dl"),
    *sib("mov", "q"),
    *sib("mov", "l", reg="%edx"),
    *index_only("mov", "q"),

    # -- MemRef loads, XZR hint (8/16-bit reg dst: value reg absorbs addr) --
    V("movw (%rax), %bx",          branch="mem -> r16: value reg doubles as addr hint (26449)"),
    V("movb 0x12345(%rax), %al",   branch="mem non-enc -> r8: value reg absorbs (23220 analog)"),
    V("movw 0x8(%rax,%rcx,2), %bx", branch="mem SIB -> r16: value reg absorbs"),

    # -- MemRef stores (prefetch_allocs, store direction) --
    *base_disp("mov", "q", store=True),
    *sib("mov", "q", store=True),

    # -- absolute (moffs) and RIP-relative --
    V("movl 0x12345678, %eax",  branch="absolute load (moffs/disp-only)"),
    V("movl %eax, 0x12345678",  branch="absolute store (moffs/disp-only)"),
    rip_rel("mov", "q", None, "%rcx",
            branch="RIP-relative load (Immediate src, 26583-26612)"),
    rip_rel("mov", "q", "%rcx", None,
            branch="RIP-relative store (Immediate dst, write peak 2)",
            slack=ALIGN_SLACK),
    V("movq $0x7, 0x100(%rip)",
      branch="imm -> RIP-relative store (imm held + write peak 2)",
      allow_slack=ALIGN_SLACK),

    # -- 32-bit addressing (ADDR32.md): every S32 MemRef costs exactly 1 on
    #    the XZR-hint paths; the value-absorb read stays 1 --
    V("movl (%esi), %eax",            branch="addr32 load base disp 0 (mov w,w zext, 26363-26376)"),
    V("movl 0x8(%esi), %eax",         branch="addr32 load base + small disp (no S64 fast path)"),
    V("movq 0x12345(%esi), %rdx",     branch="addr32 load base + non-encodable disp"),
    V("movl (%esi,%ecx,4), %eax",     branch="addr32 load SIB disp 0 (no reg-offset fast path)"),
    V("movq 0x8(%esi,%ecx,8), %rdx",  branch="addr32 load SIB + disp"),
    V("movl (,%ecx,4), %eax",         branch="addr32 load index-only"),
    V("movw (%esi), %bx",             branch="addr32 load -> r16 (value reg absorbs addr)"),
    V("movl %eax, (%esi)",            branch="addr32 store base disp 0"),
    V("movq %rdx, 0x12345(%esi,%ecx,8)", branch="addr32 store SIB + large disp"),
    V("movl $0x42, 0x8(%esi)",        branch="addr32 imm store (value temp + addr temp)"),

    # -- width cross: l-width boundary sweeps (arch-hint loads + XZR stores) --
    *base_disp("mov", "l", reg="%edx"),
    *base_disp("mov", "l", reg="%edx", store=True),
    *base_disp("mov", "w", reg="%bx", store=True),
    *sib("mov", "l", reg="%edx", store=True),
    V("movw 0x1ffe(%rax), %bx",  branch="w load scaled-imm12 max (value absorbs)"),
    V("movw (%rax,%rcx,2), %bx", branch="w load SIB shift==size (value absorbs)"),

    # -- index-only stores --
    V("movq %rcx, (,%rdx,4)",       branch="index-only store, shifted"),
    V("movq %rcx, 0x100(,%rdx,8)",  branch="index-only store + disp"),

    # -- movnti cross (store-only opcode, l/q) --
    V("movnti %ecx, 0x12345(%rax)",     branch="movnti l non-enc disp"),
    V("movnti %rcx, (%rax,%rdx,8)",     branch="movnti q SIB shift==size (0)"),
    V("movnti %ecx, (%rax,%rdx,8)",     branch="movnti l SIB shift mismatch (1)"),
    V("movnti %ecx, (%esi)",            branch="movnti addr32 (flat 1)"),

    # -- moffs widths + imm64 + sign-extended imm --
    V("movb 0x12345678, %al",           branch="moffs b load"),
    V("movabsq 0x112233445566, %rax",   branch="moffs q load (movabs 8-byte moffs)"),
    V("movabsq %rax, 0x112233445566",   branch="moffs q store"),
    V("movabsq $0x123456789abcdef0, %rax", branch="imm64 -> r64 (arch absorbs)"),
    V("movq $-0x1, %rax",               branch="sign-extended imm32 -> r64"),
    V("movb $0x42, %ah",                branch="imm -> high-byte dst (value temp + bitfield)"),
    V("movw $0x1234, 0x8(%rax)",        branch="imm -> mem w enc"),

    # -- REX low-byte corner (sil/dil encode where ah/bh would sit sans REX) --
    V("movb %sil, %dil",                branch="REX low-byte reg,reg (class 0, not high-byte)"),

    # -- RIP width cross --
    V("movl 0x100(%rip), %edx",         branch="RIP load l (arch hint)"),
    V("movw 0x100(%rip), %bx",          branch="RIP load w (XZR hint)"),
    V("movw %bx, 0x100(%rip)",          branch="RIP store w",
      allow_slack=ALIGN_SLACK),

    # -- must-refuse guard rails (common prefix) --
    V("movq %fs:0x0, %rax",  branch="refuse: FS segment override (policy)", expect="refuse"),
    V("movq %gs:0x28, %rax", branch="refuse: GS segment override (policy)", expect="refuse"),
    V("movl %fs:0x12345678, %eax",
      branch="refuse: segment-prefixed moffs (AbsMem +3 pad byte gate)",
      expect="refuse"),
]

MATRIX["lea"] = [
    V("leaq (%rax), %rdx",           branch="Case A base-only disp 0 (passthrough)"),
    V("leaq 0x10(%rax), %rdx",       branch="Case A base + ADD-encodable disp"),
    V("leaq 0x555000(%rax), %rdx",   branch="Case A base + shifted-imm12 disp"),
    V("leaq 0x12345(%rax), %rdx",    branch="Case A base + non-encodable disp (LABEL_87 transient)"),
    V("leaq (%rax,%rcx,4), %rdx",    branch="Case A SIB disp 0 (26161-26181, no alloc)"),
    V("leaq 0x8(%rax,%rcx,2), %rdx", branch="Case A SIB + encodable disp (LABEL_41 transient)"),
    V("leaq 0x12345(%rax,%rcx,8), %rdx", branch="Case A SIB + non-encodable disp"),
    V("leaq (,%rcx,4), %rdx",        branch="Case A index-only shifted, no disp"),
    V("leaq (,%rcx,1), %rdx",        branch="Case A index-only scale 1, no disp"),
    V("leaq 0x100(,%rcx,4), %rdx",   branch="Case A index-only + disp (LABEL_77 transient)"),
    V("leaq 0x1234, %rdx",           branch="Case A disp-only (emit_load_immediate)"),
    V("leaq 0x100(%rip), %rdx",      branch="Case A RIP-relative Immediate"),
    V("leaw (%rax,%rcx), %ax",       branch="Case B r16 dst: held dst temp, CA reuses it"),
    V("leaw 0x12345(%rax,%rcx,2), %bx", branch="Case B r16 dst + complex EA (still 1)"),
    # leal runs the is_64bit==0 paths (dst-size gate, 17711) — identical
    # costs under the non-XZR hint (ADDR32.md):
    V("leal (%rax), %edx",           branch="Case A 32-bit base disp 0 (mov into arch, 0)"),
    V("leal 0x10(%rax), %edx",       branch="Case A 32-bit base + encodable disp"),
    V("leal 0x12345(%rax), %edx",    branch="Case A 32-bit base + non-encodable disp (transient)"),
    V("leal (%rax,%rcx,4), %edx",    branch="Case A 32-bit SIB disp 0"),
    V("leal 0x12345(%rax,%rcx,8), %edx", branch="Case A 32-bit SIB + disp (transient)"),
    V("leal (,%rcx,4), %edx",        branch="Case A 32-bit index-only shifted"),
    V("leal (%esi,%ecx,2), %edx",    branch="Case A addr32 (0x67) SIB disp 0"),
    # -- disp_add_encodable boundary sweep (the predicate demand_lea calls) --
    V("leaq 0xfff(%rax), %rdx",      branch="disp imm12 max (encodable)"),
    V("leaq 0x1000(%rax), %rdx",     branch="disp shifted-imm12 min (encodable)"),
    V("leaq 0xfff000(%rax), %rdx",   branch="disp shifted-imm12 max (encodable)"),
    V("leaq 0x1001(%rax), %rdx",     branch="disp just past imm12, unaligned (non-enc)"),
    V("leaq -0x8(%rax), %rdx",       branch="negative encodable disp (SUB form)"),
    V("leaq -0x12345(%rax), %rdx",   branch="negative non-encodable disp"),
    # -- SIB scale sweep: lea encodes ANY scale at 0 (shifted-reg ADD lsl 0-4) --
    V("leaq (%rax,%rcx,1), %rdx",    branch="SIB scale 1 disp 0 (0)"),
    V("leaq (%rax,%rcx,2), %rdx",    branch="SIB scale 2 disp 0 (0)"),
    V("leaq (%rax,%rcx,8), %rdx",    branch="SIB scale 8 disp 0 (0)"),
    V("leaq 0x8(%rax,%rcx,1), %rdx", branch="SIB scale 1 + enc disp (transient)"),
    # -- Case B breadth (16-bit dst: held temp, CA reuses — all 1) --
    V("leaw (%rax), %ax",            branch="Case B base-only disp 0"),
    V("leaw 0x12345(%rax), %bx",     branch="Case B non-encodable disp"),
    V("leaw (,%rcx,4), %ax",         branch="Case B index-only"),
    V("leaw 0x1234, %bx",            branch="Case B disp-only"),
    V("leaw 0x100(%rip), %ax",       branch="Case B RIP Immediate (addend on top of held temp)"),
    # -- width x addressing combos --
    V("leal 0x100(%rip), %edx",      branch="Case A l-dst RIP Immediate"),
    V("leaq (%esi,%ecx,2), %rdx",    branch="q dst + addr32 (0x67) SIB"),
    V("leal 0x12345(%esi), %edx",    branch="l dst + addr32 non-enc disp"),
    V("leaq 0x0, %rdx",              branch="disp-only zero (emit_load_immediate 0)"),
    V("leaq 0x12345678, %rdx",       branch="disp-only large (into arch dst, 0)"),
    V("leaq %fs:0x10(%rax), %rdx",   branch="refuse: segment-prefixed lea (prefix gate)",
      expect="refuse"),
]

MATRIX["sse-mov-scalar"] = [
    V("movsd %xmm0, %xmm1",   branch="reg<->reg XMM (0 GPR, FPR-side only)"),
    V("movss %xmm8, %xmm15",  branch="reg<->reg XMM high regs"),
    # loads (read_xmm_operand_to_fpr -> prefetch, XZR hint)
    V("movsd (%rax), %xmm0",           branch="load base disp 0 (prefetch enc, 0)"),
    V("movsd -0x8(%rax), %xmm1",       branch="load base imm9 disp"),
    V("movsd 0x12345(%rax), %xmm2",    branch="load base non-encodable disp"),
    V("movsd (%rax,%rcx,8), %xmm3",    branch="load SIB shift==size (0)"),
    V("movsd (%rax,%rcx,4), %xmm4",    branch="load SIB shift mismatch (1)"),
    V("movss (%rax,%rcx,4), %xmm5",    branch="load SIB movss shift==size (0)"),
    V("movss 0x8(%rax,%rcx,4), %xmm6", branch="load SIB + disp (1)"),
    V("movsd 0x100(%rip), %xmm7",      branch="load RIP Immediate src (26929/26940)",
      allow_slack=ALIGN_SLACK),
    # stores (write_fpr_to_mem_operand -> prefetch, XZR hint)
    V("movsd %xmm0, (%rax)",             branch="store base disp 0 (prefetch enc, 0)"),
    V("movss %xmm1, -0x8(%rax)",         branch="store base imm9 disp"),
    V("movsd %xmm2, 0x12345(%rax)",      branch="store base non-encodable disp"),
    V("movsd %xmm3, (%rax,%rcx,8)",      branch="store SIB shift==size (0)"),
    V("movsd %xmm4, 0x12345(%rax,%rcx,8)", branch="store SIB large disp (1)"),
    V("movsd %xmm5, 0x100(%rip)",        branch="store RIP Immediate dst (27770/27781)",
      allow_slack=ALIGN_SLACK),
    # -- ldst_disp_encodable boundary sweeps per access size --
    V("movsd 0x7ff8(%rax), %xmm0",       branch="movsd load scaled-imm12 max (0xFFF*8)"),
    V("movsd 0x8000(%rax), %xmm1",       branch="movsd load scaled-imm12 max+1 (1)"),
    V("movsd -0x100(%rax), %xmm2",       branch="movsd load imm9 min"),
    V("movsd -0x101(%rax), %xmm3",       branch="movsd load below imm9 (1)"),
    V("movsd 0xc(%rax), %xmm4",          branch="movsd load unaligned small (imm9, 0)"),
    V("movss 0x3ffc(%rax), %xmm5",       branch="movss load scaled-imm12 max (0xFFF*4)"),
    V("movss 0x4000(%rax), %xmm6",       branch="movss load scaled-imm12 max+1 (1)"),
    V("movsd %xmm0, 0x7ff8(%rax)",       branch="movsd store scaled-imm12 max"),
    V("movsd %xmm1, 0x8000(%rax)",       branch="movsd store max+1 (1)"),
    # -- SIB scale completion (scale 1 = lsl 0, encodable for any size) --
    V("movsd (%rax,%rcx,1), %xmm0",      branch="movsd SIB scale 1 (lsl 0, 0)"),
    V("movsd (%rax,%rcx,2), %xmm1",      branch="movsd SIB scale 2 (mismatch, 1)"),
    V("movss (%rax,%rcx,1), %xmm2",      branch="movss SIB scale 1 (0)"),
    V("movss %xmm3, (%rax,%rcx,8)",      branch="movss store SIB scale 8 (mismatch, 1)"),
    # -- index-only (incl. the exact-0 scale-1 passthrough) --
    V("movsd (,%rcx,1), %xmm0",          branch="index-only scale 1 (passthrough, 0)"),
    V("movsd (,%rcx,8), %xmm1",          branch="index-only shifted (1)"),
    V("movsd %xmm2, 0x100(,%rcx,8)",     branch="index-only store + disp (1)"),
    # -- xmm8-15 with memory (REX.R/B) --
    V("movsd (%rax), %xmm12",            branch="load into xmm8-15 (REX.R)"),
    V("movss %xmm13, 0x8(%rax)",         branch="store from xmm8-15"),
    # -- VEX forms: operands decode as YMM-class -> the flush tail fires --
    V("vmovsd %xmm1, %xmm2, %xmm3",      branch="VEX reg,reg,reg (YMM class, flush 1)"),
    V("vmovss %xmm4, %xmm5, %xmm6",      branch="VEX movss reg,reg,reg (flush 1)"),
    V("vmovsd (%rax), %xmm0",            branch="VEX load enc (flush only, 1)"),
    V("vmovsd 0x12345(%rax), %xmm1",     branch="VEX load non-enc (addr held + flush, 2)"),
    V("vmovsd %xmm2, (%rax)",            branch="VEX store enc (early return, no flush, 0)"),
    V("vmovss 0x100(%rip), %xmm7",       branch="VEX RIP load (Immediate + flush)",
      allow_slack=ALIGN_SLACK),
    # -- 32-bit addressing (ADDR32.md): every S32 MemRef = 1 --
    V("movsd (%esi), %xmm0",             branch="addr32 load base disp 0 (1, no fast path)"),
    V("movsd 0x8(%esi,%ecx,8), %xmm1",   branch="addr32 load SIB + disp"),
    V("movss (%esi,%ecx,4), %xmm2",      branch="addr32 movss load SIB (flat 1)"),
    V("movss %xmm3, (%esi)",             branch="addr32 store base disp 0 (1)"),
    V("movsd %xmm4, 0x12345(%esi)",      branch="addr32 store non-encodable disp"),
    V("movsd %xmm5, (%esi,%ecx,2)",      branch="addr32 store SIB (flat 1)"),
    V("movsd %fs:0x10(%rax), %xmm0",     branch="refuse: segment override", expect="refuse"),
]
UNENCODABLE["sse-mov-scalar"] = [
    "AbsMem src/dst — moffs encodings exist only for mov (a0-a3)",
]

MATRIX["sse-arith"] = [
    # -- Register/XMM source (27607 translate_vector_low, 0 GPR) --
    V("addsd %xmm0, %xmm1",   branch="reg,reg sd (0)"),
    V("mulss %xmm8, %xmm15",  branch="reg,reg ss high regs (REX, 0)"),
    V("divsd %xmm1, %xmm2",   branch="reg,reg divsd (0)"),
    V("sqrtsd %xmm2, %xmm3",  branch="reg,reg sqrtsd (0)"),
    V("rsqrtss %xmm4, %xmm5", branch="reg,reg rsqrtss (0)"),
    V("rcpss %xmm6, %xmm7",   branch="reg,reg rcpss (0)"),
    # -- MemRef source (26956 prefetch XZR hint -> mov_prefetch_allocs) --
    # base + disp boundary sweep, sd (scale 8)
    V("addsd (%rax), %xmm0",         branch="sd load base disp 0 (0)"),
    V("subsd -0x8(%rax), %xmm1",     branch="sd load base imm9 disp (0)"),
    V("mulsd 0x12345(%rax), %xmm2",  branch="sd load non-encodable disp (1)"),
    V("divsd 0x7ff8(%rax), %xmm3",   branch="sd load scaled-imm12 max (0xFFF*8, 0)"),
    V("addsd 0x8000(%rax), %xmm4",   branch="sd load scaled-imm12 max+1 (1)"),
    V("sqrtsd -0x100(%rax), %xmm5",  branch="sd load imm9 min (0)"),
    V("sqrtsd -0x101(%rax), %xmm6",  branch="sd load below imm9 (1)"),
    V("addsd 0xc(%rax), %xmm7",      branch="sd load unaligned small (imm9, 0)"),
    # base + disp boundary sweep, ss (scale 4)
    V("addss (%rax), %xmm0",         branch="ss load base disp 0 (0)"),
    V("mulss 0x3ffc(%rax), %xmm1",   branch="ss load scaled-imm12 max (0xFFF*4, 0)"),
    V("subss 0x4000(%rax), %xmm2",   branch="ss load scaled-imm12 max+1 (1)"),
    V("rcpss -0x8(%rax), %xmm3",     branch="rcpss load imm9 disp (0)"),
    V("rsqrtss 0x12345(%rax), %xmm4", branch="rsqrtss load non-encodable disp (1)"),
    V("sqrtss (%rax), %xmm5",        branch="sqrtss load base disp 0 (0)"),
    # SIB
    V("addsd (%rax,%rcx,8), %xmm0",  branch="sd SIB shift==size (0)"),
    V("mulsd (%rax,%rcx,4), %xmm1",  branch="sd SIB shift mismatch (1)"),
    V("divsd (%rax,%rcx,1), %xmm2",  branch="sd SIB scale 1 (lsl 0, 0)"),
    V("sqrtsd 0x8(%rax,%rcx,8), %xmm3", branch="sd SIB + disp (1)"),
    V("rsqrtss (%rax,%rcx,4), %xmm4", branch="ss SIB shift==size (0)"),
    V("rcpss 0x8(%rax,%rcx,4), %xmm5", branch="ss SIB + disp (1)"),
    # index-only
    V("addsd (,%rcx,1), %xmm0",      branch="index-only scale 1 (passthrough, 0)"),
    V("mulsd (,%rcx,8), %xmm1",      branch="index-only shifted (1)"),
    V("subsd 0x100(,%rcx,8), %xmm2", branch="index-only + disp (1)"),
    # -- Immediate (RIP) source (26929 aligned / 26940 unaligned, fold 2) --
    V("addsd 0x100(%rip), %xmm0",    branch="sd RIP Immediate src (2)",
      allow_slack=ALIGN_SLACK),
    V("rsqrtss 0x100(%rip), %xmm1",  branch="rsqrtss RIP Immediate src (2)",
      allow_slack=ALIGN_SLACK),
    V("sqrtsd 0x100(%rip), %xmm2",   branch="sqrtsd RIP Immediate src (2)",
      allow_slack=ALIGN_SLACK),
    # -- VEX forms: dst decodes YMM-class -> writeback flush {1,0} fires --
    V("vaddsd %xmm1, %xmm2, %xmm3",  branch="VEX reg,reg,reg (flush, 1)"),
    V("vsqrtsd %xmm1, %xmm2, %xmm3", branch="VEX sqrtsd reg (flush, 1)"),
    V("vrsqrtss %xmm4, %xmm5, %xmm6", branch="VEX rsqrtss reg (flush, 1)"),
    V("vmulss (%rax), %xmm1, %xmm2", branch="VEX load enc (flush only, 1)"),
    V("vdivsd 0x12345(%rax), %xmm1, %xmm2",
      branch="VEX load non-enc (addr held + flush, max(1,1+1)=2)"),
    V("vaddss 0x100(%rip), %xmm1, %xmm2",
      branch="VEX RIP load (Immediate peak 2, flush inside)",
      allow_slack=ALIGN_SLACK),
    # -- 32-bit addressing (ADDR32.md): every S32 MemRef = 1 --
    V("addsd (%esi), %xmm0",         branch="addr32 sd base disp 0 (1, no fast path)"),
    V("mulss 0x8(%esi,%ecx,4), %xmm1", branch="addr32 ss SIB + disp (1)"),
    V("sqrtsd (%esi), %xmm2",        branch="addr32 sqrtsd base (1)"),
    V("rsqrtss (%esi,%ecx,4), %xmm3", branch="addr32 rsqrtss SIB (flat 1)"),
    V("divsd 0x12345(%esi), %xmm4",  branch="addr32 divsd non-enc disp (1)"),
    # -- guard rail --
    V("addsd %fs:0x10(%rax), %xmm0", branch="refuse: segment override",
      expect="refuse"),
]
UNENCODABLE["sse-arith"] = [
    "AbsMem src — moffs encodings exist only for mov (a0-a3)",
    "memory/Immediate DESTINATION — op xmm, xmm/mem only; dst is always an "
    "XMM register, so the YMM-dst flush rows are reachable only via VEX",
]

# Flag consumers/killers for the alu family: an OF consumer keeps the widest
# flag set live for the PRECEDING instruction; a fresh cmp kills it. Both are
# pad rows (joined, not graded).
OF_CONSUMER = V("cmovoq %r10, %r11", branch="pad: OF/flags consumer", pad=True)
FLAG_KILLER = V("cmpq %r10, %r11", branch="pad: flags killer (redefines)", pad=True)


def alu_cross() -> list[V]:
    """Full opcode x shape cross-product for the alu-binary family.

    The audit claims all six opcodes share one allocation skeleton; this
    sweep TESTS that claim empirically instead of assuming it (per-opcode
    imm-encodability classes and emit paths genuinely differ — the
    0x0f0f0f0f 32-bit bitmask port bug was opcode-class-specific). Every
    variant is followed by an OF consumer pad so flags stay live (the
    worst-case flag_liveness for any gated path).
    """
    rmw_ops = ("add", "sub", "and", "or", "xor")
    all_ops = rmw_ops + ("cmp",)
    out: list[V] = []

    def add(v: V) -> None:
        out.append(v)
        out.append(OF_CONSUMER)

    # reg,reg at every width
    regs = {"b": ("%al", "%cl"), "w": ("%ax", "%bx"),
            "l": ("%eax", "%ecx"), "q": ("%rax", "%rcx")}
    for op in all_ops:
        for sfx, (s, d) in regs.items():
            add(V(f"{op}{sfx} {s}, {d}", branch=f"cross {op}: reg,reg {sfx}"))

    # immediates: arith class (add/sub/cmp) vs logical class (and/or/xor)
    for op in ("add", "sub", "cmp"):
        for imm, tag in (("$0x8", "imm12 enc"), ("$0xfff000", "shifted-imm12 enc"),
                         ("$-0x8", "negated enc"), ("$0x12345", "non-enc")):
            add(V(f"{op}q {imm}, %rax", branch=f"cross {op}: arith {tag}"))
    for op in ("and", "or", "xor"):
        for imm, tag in (("$0xff", "bitmask enc"), ("$0x5", "non-bitmask"),
                         ("$0x12345", "non-bitmask large")):
            add(V(f"{op}q {imm}, %rax", branch=f"cross {op}: logical {tag} q"))
        add(V(f"{op}l $0xf0f0f0f, %eax",
              branch=f"cross {op}: logical 32-bit repeating bitmask"))

    # memory sources: shape sweep per opcode
    mem_shapes = [("(%rax)", "disp0"), ("0x8(%rax)", "enc disp"),
                  ("0x12345(%rax)", "non-enc disp"), ("(%rax,%rdx,8)", "SIB")]
    for op in all_ops:
        for mem, tag in mem_shapes:
            add(V(f"{op}q {mem}, %rcx", branch=f"cross {op}: mem src {tag}"))

    # RMW memory destinations (reg src) — cmp included (mem lhs, no writeback)
    for op in all_ops:
        for mem, tag in mem_shapes:
            add(V(f"{op}q %rcx, {mem}", branch=f"cross {op}: mem dst {tag}"))

    # imm -> mem RMW per encodability class
    for op in rmw_ops:
        enc = "$0xff" if op in ("and", "or", "xor") else "$0x8"
        add(V(f"{op}q {enc}, 0x8(%rax)", branch=f"cross {op}: imm-enc -> mem"))
        add(V(f"{op}q $0x12345, 0x8(%rax)", branch=f"cross {op}: imm-non-enc -> mem"))
    add(V("cmpq $0x8, 0x8(%rax)", branch="cross cmp: imm vs mem"))
    add(V("cmpq $0x12345, 0x8(%rax)", branch="cross cmp: non-enc imm vs mem"))

    # addr32 per opcode: RMW dst AND mem src for the five, src for cmp,
    # plus one SIB to confirm the flat-1 ADDR32 rule
    for op in rmw_ops:
        add(V(f"{op}l %ecx, 0x8(%esi)", branch=f"cross {op}: addr32 mem dst"))
        add(V(f"{op}l 0x8(%esi), %ecx", branch=f"cross {op}: addr32 mem src"))
    add(V("cmpl 0x8(%esi), %ecx", branch="cross cmp: addr32 mem src"))
    add(V("addl %ecx, (%esi,%edi,4)", branch="cross add: addr32 SIB dst (flat 1)"))

    # high-byte as RMW DESTINATION and both-high (op0 read of AH + writeback)
    for op in ("add", "or", "xor"):
        add(V(f"{op}b %al, %ah", branch=f"cross {op}: high-byte DST"))
    add(V("orb %ah, %ch", branch="cross or: high-byte src AND dst"))
    add(V("cmpb %ah, %al", branch="cross cmp: high-byte lhs, flags live"))

    # bitmask replication at 8/16/64-bit widths (the port-bug axis)
    add(V("andb $0xf0, %al", branch="cross and: 8-bit bitmask (contiguous run)"))
    add(V("xorb $0x55, %al", branch="cross xor: 8-bit repeating bitmask"))
    add(V("orw $0xf0f, %ax", branch="cross or: 16-bit repeating bitmask"))
    add(V("andw $0x1234, %ax", branch="cross and: 16-bit non-bitmask"))
    add(V("andq $0x55555555, %rax",
          branch="cross and: bitmask at 32 but NOT after sign-extend to 64"))

    # immediates on sub-32 destinations (imm + extend-read composition)
    add(V("addb $0x42, %al", branch="cross add: imm -> r8"))
    add(V("addw $0x1234, %bx", branch="cross add: imm -> r16"))
    add(V("subw $0x1234, %bx", branch="cross sub: imm -> r16"))
    add(V("cmpw $0x1234, %ax", branch="cross cmp: imm vs r16, flags live (flag temp)"))
    add(V("addl $0x12345678, %eax", branch="cross add: eax short-form imm32"))
    add(V("addq $0x0, %rax", branch="cross add: imm 0"))

    # store-side shape sweep: SIB scales + index-only + sub-64 mem widths
    for sc in (1, 2, 4):
        add(V(f"addq %rcx, (%rax,%rdx,{sc})",
              branch=f"cross add: mem dst SIB scale {sc}"))
    add(V("addq %rcx, 0x8(,%rdx,4)", branch="cross add: mem dst index-only"))
    add(V("subq (,%rdx,8), %rcx", branch="cross sub: mem src index-only"))
    add(V("addb %cl, (%rax)", branch="cross add: mem dst b width"))
    add(V("addw %bx, 0x8(%rax)", branch="cross add: mem dst w width"))
    add(V("addb (%rax), %cl", branch="cross add: mem src b width"))

    # RIP forms per opcode: src for all six, RMW dst refuses for all five
    for op in all_ops:
        add(V(f"{op}q 0x100(%rip), %rcx", branch=f"cross {op}: RIP Immediate src"))
    for op in rmw_ops:
        add(V(f"{op}q %rcx, 0x100(%rip)",
              branch=f"cross {op}: RIP Immediate RMW dst (total 5)"))
    # imm-src crosses on the Immediate dst: enc imm adds 0 events, non-enc 1
    add(V("addq $0x8, 0x100(%rip)", branch="cross add: enc imm -> RIP dst (total 5)"))
    add(V("addq $0x12345, 0x100(%rip)", branch="cross add: non-enc imm -> RIP dst (total 6)"))
    add(V("orq $0x12345, 0x100(%rip)", branch="cross or: non-bitmask imm -> RIP dst (total 6)"))

    # small-cmp flag-temp gate, flags DEAD side (killer pad follows)
    out.append(V("cmpb %al, %cl", branch="cross cmp: r8, flags dead (no flag temp)"))
    out.append(FLAG_KILLER)
    out.append(V("cmpw %ax, %bx", branch="cross cmp: r16, flags dead"))
    out.append(FLAG_KILLER)

    # LOCK guard rails for the remaining opcodes
    add(V("lock andq $0x1, (%rax)", branch="cross and: LOCK refuse", expect="refuse"))
    add(V("lock orq %rcx, (%rax)", branch="cross or: LOCK refuse", expect="refuse"))

    return out

# DRAFT — graded once demand_alu_binary lands (until then every row FAILs
# with unexpected-refuse, and alu-binary is not in --matrix-all-landed
# because STATUS.md doesn't list it as landed). allow_slack annotations are
# added at review against the audit's shape table.
MATRIX["alu-binary"] = [
    # -- reg,reg / reg,imm forms, flags live vs dead --
    V("addq %rax, %rcx",        branch="RMW reg,reg r64"), FLAG_KILLER,
    V("addq %rax, %rcx",        branch="RMW reg,reg r64, flags live"), OF_CONSUMER,
    V("subl %ecx, %edx",        branch="RMW reg,reg r32"), OF_CONSUMER,
    V("andq %r8, %r9",          branch="logical reg,reg r64"), OF_CONSUMER,
    V("xorl %eax, %eax",        branch="xor self-zero idiom"), OF_CONSUMER,
    V("orb %al, %cl",           branch="logical reg,reg r8"), OF_CONSUMER,
    V("addb %ah, %cl",          branch="RMW high-byte src"), OF_CONSUMER,
    V("addw %ax, %bx",          branch="RMW reg,reg r16"), OF_CONSUMER,
    V("addq $0x8, %rax",        branch="arith imm12-encodable"), OF_CONSUMER,
    V("addq $0x12345, %rax",    branch="arith imm non-encodable (materialize)"), OF_CONSUMER,
    V("andq $0xff, %rax",       branch="logical imm bitmask-encodable"), OF_CONSUMER,
    V("andq $0x12345, %rax",    branch="logical imm NOT bitmask-encodable"), OF_CONSUMER,
    V("xorl $0xf0f0f0f, %eax",  branch="logical imm r32"), OF_CONSUMER,
    # -- cmp (no writeback; flag path only) --
    V("cmpq %rax, %rcx",        branch="cmp reg,reg, flags live"), OF_CONSUMER,
    V("cmpq %rax, %rcx",        branch="cmp reg,reg, flags killed"), FLAG_KILLER,
    V("cmpq $0x8, %rax",        branch="cmp imm12"), OF_CONSUMER,
    V("cmpq $0x12345, %rax",    branch="cmp imm non-encodable"), OF_CONSUMER,
    V("cmpq 0x8(%rax), %rcx",   branch="cmp mem,reg (mem src)"), OF_CONSUMER,
    V("cmpq %rcx, 0x8(%rax)",   branch="cmp reg,mem (mem lhs)"), OF_CONSUMER,
    V("cmpq $0x7, 0x12345(%rax,%rdx,8)", branch="cmp imm,mem complex SIB"), OF_CONSUMER,
    # -- RMW memory destinations (read+modify+write one operand) --
    V("addq $0x1, (%rax)",      branch="RMW mem dst, base disp 0, imm"), OF_CONSUMER,
    V("addq %rcx, 0x8(%rax)",   branch="RMW mem dst, enc disp, reg src"), OF_CONSUMER,
    V("addq %rcx, 0x12345(%rax)", branch="RMW mem dst, non-enc disp"), OF_CONSUMER,
    V("xorq %rcx, (%rax,%rdx,8)", branch="RMW mem dst, SIB disp 0"), OF_CONSUMER,
    V("andl $0x7fffffff, 0x12345(%rax,%rdx,8)", branch="RMW mem dst, SIB + large disp, imm"), OF_CONSUMER,
    V("orw $0x100, 0x8(%rax)",  branch="RMW mem dst r16"), OF_CONSUMER,
    V("subb $0x1, (%rax)",      branch="RMW mem dst r8"), OF_CONSUMER,
    V("addq %rax, 0x100(%rip)", branch="RMW Immediate (RIP) dst: honest event "
      "total 5 (alloc 1 + read 2 + write 2; over-ceiling, callers reject)"), OF_CONSUMER,
    V("cmpq $0x1, 0x100(%rip)", branch="cmp Immediate (RIP) lhs (no writeback)"), OF_CONSUMER,
    # -- memory sources --
    V("addq (%rax), %rcx",      branch="mem src, base disp 0"), OF_CONSUMER,
    V("subq 0x12345(%rax,%rdx,4), %rcx", branch="mem src, complex SIB"), OF_CONSUMER,
    V("orq 0x100(%rip), %rcx",  branch="mem src, RIP Immediate"), OF_CONSUMER,
    # -- 32-bit addressing (ADDR32.md) --
    V("addl %eax, (%esi)",      branch="addr32 RMW mem dst"), OF_CONSUMER,
    V("cmpl (%esi), %ecx",      branch="addr32 cmp mem src"), OF_CONSUMER,
    V("addl $0x5, 0x8(%esi)",   branch="addr32 RMW imm, base+disp"), OF_CONSUMER,
    # -- guard rails --
    V("lock addq $0x1, (%rax)", branch="refuse: LOCK RMW (lockable_rmw gate)",
      expect="refuse"),
    V("lock xorq %rcx, (%rax)", branch="refuse: LOCK xor reg,mem", expect="refuse"),
    V("lock subl $0x1, (%rax)", branch="refuse: LOCK sub imm,mem", expect="refuse"),
    V("addq %fs:0x0, %rax",     branch="refuse: segment override", expect="refuse"),
    # -- full opcode x shape cross-product (tests the no-split claim) --
    *alu_cross(),
]

def movzx_cross() -> list[V]:
    """Opcode x src-width x dst-width x shape cross-product for the widening
    moves. No imm forms, no stores (dst is always a register); the shape
    axes are src kind (reg incl. high-byte / mem / RIP), src access width
    (drives SIB shift==size and disp scaling), dst width (16-bit dsts take
    the XZR-hint path), and addr_size."""
    out: list[V] = []
    # (mnemonic, src width suffix log2 key, dst reg, tag)
    forms = [
        ("movzbl", "b", "%edx", "zx b->l"), ("movzbq", "b", "%rdx", "zx b->q"),
        ("movzbw", "b", "%dx",  "zx b->w (16-bit dst)"),
        ("movzwl", "w", "%edx", "zx w->l"), ("movzwq", "w", "%rdx", "zx w->q"),
        ("movsbl", "b", "%edx", "sx b->l"), ("movsbq", "b", "%rdx", "sx b->q"),
        ("movsbw", "b", "%dx",  "sx b->w (16-bit dst)"),
        ("movswl", "w", "%edx", "sx w->l"), ("movswq", "w", "%rdx", "sx w->q"),
        ("movslq", "l", "%rdx", "sxd l->q"),
    ]
    # register sources: low byte/word, plus high-byte for the b-width forms
    src_reg = {"b": "%al", "w": "%ax", "l": "%eax"}
    for mnem, w, dst, tag in forms:
        out.append(V(f"{mnem} {src_reg[w]}, {dst}", branch=f"cross {tag}: reg src"))
        # AH cannot be encoded alongside REX, so high-byte sources exist
        # only for the b->w/l forms (q-width dsts need REX.W).
        if w == "b" and not dst.startswith("%r"):
            out.append(V(f"{mnem} %ah, {dst}", branch=f"cross {tag}: HIGH-BYTE src"))
    # memory sources: boundary sweep on a representative per src width +
    # SIB shift match/mismatch + index-only
    scale = {"b": 1, "w": 2, "l": 4}
    for mnem, w, dst, tag in (("movzbl", "b", "%edx", "zx b->l"),
                              ("movswq", "w", "%rdx", "sx w->q"),
                              ("movslq", "l", "%rdx", "sxd l->q")):
        sc = scale[w]
        for mem, mtag in ((f"(%rax)", "disp 0"), (f"0xff(%rax)", "imm9 max"),
                          (f"{0xFFF * sc:#x}(%rax)", "scaled imm12 max"),
                          ("0x12345(%rax)", "non-enc disp"),
                          (f"(%rax,%rcx,{sc})", "SIB shift==size"),
                          (f"(%rax,%rcx,8)", "SIB shift mismatch")
                          if sc != 8 else (f"(%rax,%rcx,4)", "SIB shift mismatch"),
                          (f"0x100(,%rcx,{sc})", "index-only + disp")):
            out.append(V(f"{mnem} {mem}, {dst}", branch=f"cross {tag}: mem {mtag}"))
    # 16-bit DESTINATION x memory: the scratch-hint path (held dst temp
    # doubles as the address hint) — a distinct model branch from the
    # arch-hint sweeps above
    out.append(V("movzbw (%rax), %dx", branch="cross zx b->w: mem disp 0 (scratch hint)"))
    out.append(V("movzbw 0x12345(%rax), %dx", branch="cross zx b->w: mem non-enc disp"))
    out.append(V("movsbw (%rax,%rcx,1), %dx", branch="cross sx b->w: mem SIB"))
    out.append(V("movzbw 0x100(%rip), %dx", branch="cross zx b->w: RIP Immediate src"))
    out.append(V("movzbw (%esi), %dx", branch="cross zx b->w: addr32"))

    # remaining shape corners on arch-hint forms
    out.append(V("movzbl -0x100(%rax), %edx", branch="cross zx: mem imm9 min"))
    out.append(V("movzbl 0x8(%rax,%rcx,1), %edx", branch="cross zx: SIB + disp"))
    out.append(V("movzbl (,%rcx,1), %edx",
                 branch="cross zx: index-only scale 1, no disp (exact 0)"))
    out.append(V("movzwl (,%rcx,2), %edx", branch="cross zx: index-only shifted, no disp"))

    # register-encoding corners
    out.append(V("movzbl %sil, %edx",
                 branch="cross zx: REX low-byte src (AH slot with REX)"))
    out.append(V("movzbl %r9b, %edx", branch="cross zx: r8-r15 byte src"))
    # raw 0x63 without REX.W: movsxd with a 32-bit dst (compilers never emit
    # this; decode-corner — modrm 0xd8 = ebx <- eax)
    out.append(V(".byte 0x63, 0xd8", branch="cross sxd: no-REX.W movsxd r32 dst"))

    # RIP + addr32 + guard rails
    out.append(V("movzbl 0x100(%rip), %edx", branch="cross zx: RIP Immediate src"))
    out.append(V("movswl 0x100(%rip), %edx", branch="cross sx w: RIP Immediate src"))
    out.append(V("movslq 0x100(%rip), %rdx", branch="cross sxd: RIP Immediate src"))
    out.append(V("movzbl (%esi), %edx", branch="cross zx: addr32 base"))
    out.append(V("movswl 0x8(%esi), %edx", branch="cross sx: addr32 base+disp"))
    out.append(V("movslq (%esi,%ecx,4), %rdx", branch="cross sxd: addr32 SIB"))
    out.append(V("movzbl %fs:0x10(%rax), %edx",
                 branch="refuse: segment override", expect="refuse"))
    return out


MATRIX["movzx-movsx-movsxd"] = movzx_cross()
UNENCODABLE["movzx-movsx-movsxd"] = [
    "immediate and store forms — the widening moves encode only reg<-reg "
    "and reg<-mem",
    "AbsMem operands — moffs encodings (a0-a3) exist only for mov; the "
    "audit's AbsMem row is analytic-only",
    "LOCK/REP prefixes — not valid encodings for 0F B6/B7/BE/BF/63",
]

UNENCODABLE["alu-binary"] = [
    "AbsMem operands — moffs encodings (a0-a3) exist only for mov; alu "
    "opcodes cannot produce AbsMem-kind operands",
    "REP (non-LOCK) prefixes — 0xF2/0xF3 on alu opcodes are not valid "
    "encodings; only LOCK (rep_prefix==1) is reachable and it is refused",
]

def shift_cross() -> list[V]:
    """Opcode x count-kind x dst-shape cross-product for the shift family.

    Axes: count kind (implicit-1 D1 form, imm8 C1 form at boundary values
    incl. the flag-preserving count 0, and CL D3 form), dst (reg widths incl.
    high-byte and r8-r15, mem RMW boundary sweep, absolute, RIP Immediate,
    addr32), and flag liveness (shifts define OF/CF/... only when count!=0;
    count==1 defines OF specially; rol/ror touch only OF/CF) — every variant
    gets OF+CF consumer pads, with killer rows for the flags-dead side."""
    ops = ("shl", "shr", "sar", "rol", "ror")
    out: list[V] = []
    # SF consumer: emit_nz_flags' S8/S16 temp is SF-gated (decomp 24659) —
    # OF/CF pads alone leave it dead (matrix reconciliation 2026-07-17).
    sf_pad = V("cmovsq %r10, %r11", branch="pad: SF consumer", pad=True)

    def add(v: V) -> None:
        out.append(v)
        out.append(OF_CONSUMER)
        out.append(CF_CONSUMER)

    def add_sf(v: V) -> None:
        out.append(v)
        out.append(OF_CONSUMER)
        out.append(CF_CONSUMER)
        out.append(sf_pad)

    regs = {"b": "%cl", "w": "%bx", "l": "%edx", "q": "%rdx"}
    # NB: %cl is the count register — use non-cl byte dst for b-width imm forms
    for op in ops:
        for sfx, r in regs.items():
            dst = "%dl" if sfx == "b" else r
            add(V(f"{op}{sfx} $0x3, {dst}", branch=f"cross {op}: imm count, reg {sfx}"))
        add(V(f"{op}q %rdx", branch=f"cross {op}: implicit-1 (D1) reg q"))
        add(V(f"{op}q %cl, %rdx", branch=f"cross {op}: CL count, reg q"))
        add(V(f"{op}l %cl, %edx", branch=f"cross {op}: CL count, reg l"))
    # count boundaries + the flag-preserving zero count
    add(V("shlq $0x0, %rdx", branch="cross shl: count 0 (flags preserved)"))
    add(V("shrq $0x3f, %rdx", branch="cross shr: count 63 (max q)"))
    add(V("shll $0x1f, %edx", branch="cross shl: count 31 (max l)"))
    add(V("sarq $0x1, %rdx", branch="cross sar: explicit $1 (OF-defined form)"))
    add(V("rorb $0x7, %dl", branch="cross ror: count 7 (max b)"))
    # SF-live rows: the nz temp fires only under SF liveness (S8/S16 +
    # shl/shr/sar; decomp 24659)
    add_sf(V("shlb $0x3, %dl", branch="cross shl: imm, reg b, SF live (nz temp)"))
    add_sf(V("shrw $0x3, %bx", branch="cross shr: imm, reg w, SF live (nz temp)"))
    add_sf(V("sarb %cl, %dl", branch="cross sar: CL, reg b, SF live"))
    add_sf(V("shll $0x3, %edx", branch="cross shl: imm, reg l, SF live (no nz temp ≥S32)"))
    add_sf(V("rolb $0x3, %dl", branch="cross rol: imm, reg b, SF live (rol has no nz)"))
    # count==1 rows: OF materialization is count-gated (31047/31679/30835) —
    # exercise it at narrow widths where it stacks on the extend read
    add(V("shlb $0x1, %dl", branch="cross shl: explicit $1, reg b (OF defined)"))
    add(V("shrb $0x1, %dl", branch="cross shr: explicit $1, reg b (OF defined)"))
    add_sf(V("shlb $0x1, %dl", branch="cross shl: $1, reg b, OF+CF+SF all live (worst)"))
    add(V("shrq $0x1, 0x12345(%rax)", branch="cross shr: $1, mem non-enc (OF + addr)"))
    # high-byte + REX corners
    add(V("shlb $0x3, %ah", branch="cross shl: high-byte dst"))
    add(V("sarb %cl, %ah", branch="cross sar: CL count, high-byte dst"))
    add(V("rolb $0x1, %ah", branch="cross rol: implicit-1 high-byte dst"))
    add(V("shrq $0x3, %r15", branch="cross shr: r8-r15 dst"))
    # flags-dead side per opcode (killer follows)
    for op in ops:
        out.append(V(f"{op}q $0x3, %rdx", branch=f"cross {op}: reg q, flags dead"))
        out.append(FLAG_KILLER)
    out.append(V("shlq %cl, %rdx", branch="cross shl: CL count, flags dead"))
    out.append(FLAG_KILLER)
    # mem RMW dst: full boundary sweep on shl, spot-checks per other opcode
    mem_shapes = [("(%rax)", "disp0"), ("0x8(%rax)", "enc disp"),
                  ("-0x100(%rax)", "imm9 min"), ("-0x101(%rax)", "below imm9"),
                  ("0x7ff8(%rax)", "scaled imm12 max"),
                  ("0x8000(%rax)", "scaled imm12 max+1"),
                  ("0x12345(%rax)", "non-enc disp"),
                  ("(%rax,%rdx,8)", "SIB shift==size"),
                  ("(%rax,%rdx,2)", "SIB shift mismatch"),
                  ("(,%rdx,1)", "index-only scale 1"),
                  ("0x100(,%rdx,8)", "index-only + disp")]
    for mem, tag in mem_shapes:
        add(V(f"shlq $0x3, {mem}", branch=f"cross shl: imm count, mem q {tag}"))
    for op in ("shr", "sar", "rol", "ror"):
        add(V(f"{op}q $0x3, (%rax)", branch=f"cross {op}: imm count, mem q disp0"))
        add(V(f"{op}q $0x3, 0x12345(%rax)", branch=f"cross {op}: imm count, mem q non-enc"))
        add(V(f"{op}q %cl, (%rax)", branch=f"cross {op}: CL count, mem q"))
    add(V("shlq %cl, 0x12345(%rax)", branch="cross shl: CL count, mem non-enc"))
    add(V("shlq (%rax)", branch="cross shl: implicit-1, mem q"))
    add(V("shrb $0x3, (%rax)", branch="cross shr: mem b width"))
    add(V("shlw $0x3, 0x1ffe(%rax)", branch="cross shl: mem w scaled imm12 max"))
    add(V("sarl $0x3, 0x4000(%rax)", branch="cross sar: mem l scaled imm12 max+1"))
    # absolute + RIP Immediate RMW dst + addr32 per opcode
    for op in ops:
        add(V(f"{op}q $0x3, 0x12345678", branch=f"cross {op}: absolute disp-only dst"))
        add(V(f"{op}q $0x3, 0x100(%rip)", branch=f"cross {op}: RIP Immediate RMW dst"))
        add(V(f"{op}l $0x3, (%esi)", branch=f"cross {op}: addr32 mem dst"))
    add(V("shll %cl, 0x8(%esi,%ecx,4)", branch="cross shl: CL count, addr32 SIB"))
    # guard rails
    add(V("shlq $0x3, %fs:0x8(%rax)", branch="refuse: segment override",
          expect="refuse"))
    return out


def cmov_cross() -> list[V]:
    """cc x src-shape x width cross-product for cmovcc.

    The cc axis splits parity (cmovp/cmovnp, cc 0xA/0xB — the inline 3-temp
    set-carry path, 15078-15101) from every other cc (translate_condition_code
    + emit_csel, 15109-15110). Source shapes drive read_operand_to_gpr(XZR);
    dst is always a Register (S16 dst = held alloc_dst temp). cmov consumes
    flags but writes none, so no liveness pads are needed."""
    out: list[V] = []
    # cc breadth on reg,reg: one- and two-flag ccs + both parity forms
    for cc in ("e", "ne", "a", "b", "s", "ge", "o"):
        out.append(V(f"cmov{cc}q %rax, %rcx", branch=f"cross cmov{cc}: reg q (csel path)"))
    for cc in ("p", "np"):
        out.append(V(f"cmov{cc}q %rax, %rcx", branch=f"cross cmov{cc}: reg q (parity 3-temp path)"))
    # widths (cmov has no 8-bit form): w dst takes the held alloc_dst temp
    for cc in ("e", "p"):
        out.append(V(f"cmov{cc}w %ax, %bx", branch=f"cross cmov{cc}: reg w (S16 dst temp)"))
        out.append(V(f"cmov{cc}l %eax, %ecx", branch=f"cross cmov{cc}: reg l"))
    out.append(V("cmovnpw %ax, %bx", branch="cross cmovnp: reg w (parity swap + S16 dst)"))
    out.append(V("cmoveq %r8, %r15", branch="cross cmove: r8-r15"))
    # mem src sweep, normal vs parity
    mem_shapes = [("(%rax)", "disp0"), ("0x8(%rax)", "enc disp"),
                  ("-0x100(%rax)", "imm9 min"), ("-0x101(%rax)", "below imm9"),
                  ("0x7ff8(%rax)", "scaled imm12 max"),
                  ("0x8000(%rax)", "scaled imm12 max+1"),
                  ("0x12345(%rax)", "non-enc disp"),
                  ("(%rax,%rdx,8)", "SIB shift==size"),
                  ("(%rax,%rdx,2)", "SIB shift mismatch"),
                  ("(,%rdx,1)", "index-only scale 1"),
                  ("0x100(,%rdx,8)", "index-only + disp")]
    for cc in ("e", "p"):
        for mem, tag in mem_shapes:
            out.append(V(f"cmov{cc}q {mem}, %rcx", branch=f"cross cmov{cc}: mem q {tag}"))
    # sub-64 access widths from memory (boundary scales by access size)
    out.append(V("cmovew 0x1ffe(%rax), %bx", branch="cross cmove: mem w scaled imm12 max"))
    out.append(V("cmovpl 0x4000(%rax), %ecx", branch="cross cmovp: mem l scaled imm12 max+1"))
    out.append(V("cmovpw (%rax), %bx",
                 branch="cross cmovp: mem w (S16 dst + parity, total 5)"))
    out.append(V("cmovnpw 0x8(%rax), %bx",
                 branch="cross cmovnp: mem w (parity swap, total 5)"))
    # absolute / RIP / addr32
    for cc in ("e", "p"):
        out.append(V(f"cmov{cc}q 0x12345678, %rcx", branch=f"cross cmov{cc}: absolute disp-only src"))
        out.append(V(f"cmov{cc}q 0x100(%rip), %rcx",
                     branch=f"cross cmov{cc}: RIP Immediate src"
                     + (" (parity total 5)" if cc == "p" else "")))
        out.append(V(f"cmov{cc}l (%esi), %ecx", branch=f"cross cmov{cc}: addr32 base"))
    out.append(V("cmovel 0x8(%esi,%ecx,4), %edx", branch="cross cmove: addr32 SIB + disp"))
    out.append(V("cmovpw 0x100(%rip), %bx",
                 branch="cross cmovp: RIP Imm src + S16 dst + parity (total 6)"))
    out.append(V("cmovpw 0x12345678, %bx",
                 branch="cross cmovp: absolute src + S16 dst + parity (total 5)"))
    # guard rails
    out.append(V("cmoveq %fs:0x8(%rax), %rcx", branch="refuse: segment override",
                 expect="refuse"))
    return out


# Reconciled against the audit's 20-row shape table at review (2026-07-17):
# refuse expectations added for the parity + S16-dst + temp-holding-src rows
# (audit rows 16/18/20). High-byte-src rows (3/4/13/14) are analytic-only.
MATRIX["cmovcc"] = cmov_cross()
UNENCODABLE["cmovcc"] = [
    "8-bit forms — cmovcc encodes only r16/r32/r64 (0F 4x /r); hence the "
    "audit's high-byte-source rows (3/4/13/14) are analytic-only",
    "immediate and store forms — src is r/m, dst is always a register",
]


# CF consumer: inc/dec PRESERVE guest CF (ARM adds/subs clobber C), so any
# CF-restore work is worst-cased by a following CF consumer. Pad row.
CF_CONSUMER = V("cmovbq %r10, %r11", branch="pad: CF consumer", pad=True)


def unary_cross() -> list[V]:
    """Full opcode x shape cross-product for the alu-unary family
    (inc/dec/neg/not — one-operand RMW, no imm/no reg-src forms).

    Axes: dst kind (reg incl. high-byte/REX-low-byte/r8-r15, mem, absolute,
    RIP), width bwlq, mem encodability boundaries per width, SIB shift
    match/mismatch, index-only, addr32, and flag liveness (inc/dec preserve
    CF and write OF..; not writes NO flags; neg writes all). Every variant is
    followed by an OF- and a CF-consumer pad so the widest flag set stays
    live; a killer-pad pair covers the flags-dead side for the CF-preserve
    gate."""
    ops = ("inc", "dec", "neg", "not")
    out: list[V] = []

    def add(v: V) -> None:
        out.append(v)
        out.append(OF_CONSUMER)
        out.append(CF_CONSUMER)

    # register dst at every width
    regs = {"b": "%cl", "w": "%bx", "l": "%ecx", "q": "%rcx"}
    for op in ops:
        for sfx, r in regs.items():
            add(V(f"{op}{sfx} {r}", branch=f"cross {op}: reg {sfx}"))
    # high-byte, REX low-byte, r8-r15
    for op in ops:
        add(V(f"{op}b %ah", branch=f"cross {op}: high-byte reg"))
    add(V("incb %sil", branch="cross inc: REX low-byte reg"))
    add(V("notq %r15", branch="cross not: r8-r15"))

    # flags-dead side (killer follows) for the CF-preserve/flag gates
    for op in ops:
        out.append(V(f"{op}q %rcx", branch=f"cross {op}: reg q, flags dead"))
        out.append(FLAG_KILLER)

    # memory dst shape sweep per opcode (q width)
    mem_shapes = [("(%rax)", "disp0"), ("0x8(%rax)", "enc disp"),
                  ("-0x100(%rax)", "imm9 min"), ("-0x101(%rax)", "below imm9"),
                  ("0x7ff8(%rax)", "scaled imm12 max"),
                  ("0x8000(%rax)", "scaled imm12 max+1"),
                  ("0x12345(%rax)", "non-enc disp"),
                  ("(%rax,%rdx,8)", "SIB shift==size"),
                  ("(%rax,%rdx,2)", "SIB shift mismatch"),
                  ("(,%rdx,1)", "index-only scale 1"),
                  ("0x100(,%rdx,8)", "index-only + disp")]
    for op in ops:
        for mem, tag in mem_shapes:
            add(V(f"{op}q {mem}", branch=f"cross {op}: mem q {tag}"))

    # sub-64 mem widths (boundaries scale by access size)
    for op in ops:
        add(V(f"{op}b (%rax)", branch=f"cross {op}: mem b disp0"))
        add(V(f"{op}w 0x1ffe(%rax)", branch=f"cross {op}: mem w scaled imm12 max"))
        add(V(f"{op}l 0x4000(%rax)", branch=f"cross {op}: mem l scaled imm12 max+1"))

    # absolute (disp-only) + RIP-relative dst per opcode. RIP Immediate RMW
    # dst totals 5 (neg/not) / 6 (inc/dec, CF live) — over the bridging
    # ceiling (callers won't bridge it) but priced honestly and graded exact.
    for op in ops:
        add(V(f"{op}q 0x12345678", branch=f"cross {op}: absolute disp-only dst"))
        add(V(f"{op}q 0x100(%rip)", branch=f"cross {op}: RIP Immediate RMW dst (total 5-6)"))

    # addr32 (every S32 MemRef; ADDR32.md)
    for op in ops:
        add(V(f"{op}l (%esi)", branch=f"cross {op}: addr32 base disp0"))
    add(V("incl 0x8(%esi,%ecx,4)", branch="cross inc: addr32 SIB + disp"))
    add(V("negl 0x12345(%esi)", branch="cross neg: addr32 non-enc disp"))

    # guard rails: LOCK RMW + segment override
    for op in ops:
        add(V(f"lock {op}q (%rax)", branch=f"cross {op}: LOCK refuse",
              expect="refuse"))
    add(V("incq %fs:0x8(%rax)", branch="refuse: segment override",
          expect="refuse"))
    return out


# Reconciled against the audit's shape table at review (WORKFLOW.md §3 step 7,
# 2026-07-17): the sweep caught the Immediate-kind (RIP) RMW dst underestimate
# (actual 5-6 vs est 4-5) — now priced honestly (5/6), rejected by callers.
MATRIX["alu-unary"] = unary_cross()

# DRAFT — graded once demand_shifts lands; reconciled against the audit's
# shape table at review (WORKFLOW.md §3 step 7). (Assigned here, after the
# CF_CONSUMER pad definition shift_cross uses.)
MATRIX["shifts"] = shift_cross()
UNENCODABLE["shifts"] = [
    "LOCK/REP prefixes — not valid encodings for C0/C1/D0-D3 shift groups",
    "count operands other than imm8/CL — the ISA has no other count form",
]
UNENCODABLE["alu-unary"] = [
    "immediate/register-source forms — inc/dec/neg/not encode exactly one "
    "r/m operand (FE-FF /0 /1, F6-F7 /2 /3)",
    "AbsMem moffs encodings (a0-a3) exist only for mov; the disp-only "
    "absolute variants here decode as whatever kind Rosetta assigns "
    "disp32-SIB addressing",
]

# Rosetta pair-fuses ADJACENT push/push and pop/pop into one translate_insn
# call (STP/LDP) — the second instruction gets no translation of its own and
# thus no gpr_demand row. Same-op variants are therefore separated by nop
# pads, and the pair path is covered by explicit two-instruction variants
# that produce ONE row.
NOP_PAD = V("nop", branch="pad: fusion separator", pad=True)

MATRIX["push-pop"] = [
    # -- push register (incl. the RSP alias and REX.B) --
    V("pushq %rax",            branch="push reg"), NOP_PAD,
    V("pushq %r12",            branch="push reg r8-r15 (REX.B)"), NOP_PAD,
    V("pushq %rsp",            branch="push RSP (dup_gpr_if_alias fires)"), NOP_PAD,
    V("pushw %ax",             branch="pushw r16 src (S16 bitfield-extract, 1)"), NOP_PAD,
    V("pushw %sp",             branch="pushw SP (S16 extract scratch, NO alias dup)"), NOP_PAD,
    # -- deliberate pairs: ONE translation covers both instructions --
    V("pushq %rax\n\tpushq %rcx", branch="push-pair (STP fusion, one translation)"),
    NOP_PAD,
    V("popq %rcx\n\tpopq %rax",   branch="pop-pair (LDP fusion, one translation)"),
    NOP_PAD,
    # -- push immediate (BranchOffset kinds) --
    V("pushq $0x8",            branch="push imm8 sign-extended"), NOP_PAD,
    V("pushq $0x12345",        branch="push imm32"), NOP_PAD,
    V("pushq $-0x1",           branch="push imm negative"), NOP_PAD,
    V("pushq $0x0",            branch="push imm 0 (emit_load_immediate XZR special)"), NOP_PAD,
    # -- push memory (full shape sweep) --
    V("pushq (%rax)",          branch="push mem base disp 0"), NOP_PAD,
    V("pushq 0x8(%rax)",       branch="push mem enc disp"), NOP_PAD,
    V("pushq 0x12345(%rax)",   branch="push mem non-enc disp"), NOP_PAD,
    V("pushq (%rax,%rcx,8)",   branch="push mem SIB shift==size"), NOP_PAD,
    V("pushq (%rax,%rcx,2)",   branch="push mem SIB shift mismatch"), NOP_PAD,
    V("pushq (,%rcx,1)",       branch="push mem index-only scale 1 (passthrough)"), NOP_PAD,
    V("pushq 0x100(,%rcx,8)",  branch="push mem index-only + disp"), NOP_PAD,
    V("pushq 0x100(%rip)",     branch="push RIP Immediate src"), NOP_PAD,
    V("pushq 0x12345678",      branch="push AbsMem src (disp-only absolute)"), NOP_PAD,
    V("pushq (%rsp)",          branch="push (%rsp) — SP-relative src + SP update"), NOP_PAD,
    V("pushq 0x8(%rsp)",       branch="push disp(%rsp)"), NOP_PAD,
    # -- pushw (S16): shares translate_pushd_pushw, size arg alloc-neutral --
    V("pushw $0x1234",         branch="pushw imm16"), NOP_PAD,
    V("pushw $0x0",            branch="pushw imm 0 (XZR special)"), NOP_PAD,
    V("pushw 0x8(%rax)",       branch="pushw m16 enc disp"), NOP_PAD,
    V("pushw 0x1ffe(%rax)",    branch="pushw m16 scaled imm12 max (0xFFF*2)"), NOP_PAD,
    V("pushw 0x12345(%rax)",   branch="pushw m16 non-enc disp (value absorbs, still 1)"), NOP_PAD,
    V("pushw (%rax,%rcx,2)",   branch="pushw m16 SIB shift==size"), NOP_PAD,
    V("pushw 0x100(%rip)",     branch="pushw RIP Immediate src"), NOP_PAD,
    # -- pop --
    V("popq %rax",             branch="pop reg"), NOP_PAD,
    V("popq %r12",             branch="pop reg r8-r15"), NOP_PAD,
    V("popq %rsp",             branch="pop RSP (alias)"), NOP_PAD,
    # -- popw (S16): shares translate_popd_popw; S16 reg dst takes the
    #    alloc_dst_gpr held-temp path; m16 boundaries scale by 2 --
    V("popw %ax",              branch="popw r16 dst (alloc_dst_gpr S16 held temp)"), NOP_PAD,
    V("popw %sp",              branch="popw SP (S16 dst temp, no v4==4 fixup)"), NOP_PAD,
    V("popw (%rax)",           branch="popw m16 base disp 0"), NOP_PAD,
    V("popw 0x1ffe(%rax)",     branch="popw m16 scaled imm12 max (enc)"), NOP_PAD,
    V("popw 0x2000(%rax)",     branch="popw m16 scaled imm12 max + 1 (non-enc)"), NOP_PAD,
    V("popw (%rax,%rcx,2)",    branch="popw m16 SIB shift==size"), NOP_PAD,
    V("popw (%rax,%rcx,8)",    branch="popw m16 SIB shift mismatch"), NOP_PAD,
    V("popw 0x100(%rip)",      branch="popw RIP Immediate dst"), NOP_PAD,
    V("popw 0x8(%esi)",        branch="popw addr32 mem"), NOP_PAD,
    V("popq (%rax)",           branch="pop mem base disp 0"), NOP_PAD,
    V("popq 0x12345(%rax)",    branch="pop mem non-enc disp"), NOP_PAD,
    # pop is the side where ldst_disp_encodable changes est (1 vs 2) —
    # sweep its boundaries explicitly
    V("popq -0x100(%rax)",     branch="pop mem imm9 min (enc)"), NOP_PAD,
    V("popq -0x101(%rax)",     branch="pop mem below imm9 (non-enc)"), NOP_PAD,
    V("popq 0x7ff8(%rax)",     branch="pop mem scaled imm12 max (enc)"), NOP_PAD,
    V("popq 0x8000(%rax)",     branch="pop mem scaled imm12 max + 1 (non-enc)"), NOP_PAD,
    V("popq (%rax,%rcx,8)",    branch="pop mem SIB shift==size"), NOP_PAD,
    V("popq (%rax,%rcx,2)",    branch="pop mem SIB shift mismatch"), NOP_PAD,
    V("popq (,%rcx,1)",        branch="pop mem index-only scale 1 (passthrough)"), NOP_PAD,
    V("popq 0x100(,%rcx,8)",   branch="pop mem index-only + disp"), NOP_PAD,
    V("popq 0x12345678",       branch="pop AbsMem dst (disp-only absolute)"), NOP_PAD,
    V("popq 0x100(%rip)",      branch="pop RIP Immediate dst"), NOP_PAD,
    V("popq (%rsp)",           branch="pop (%rsp) — SP-relative dst"), NOP_PAD,
    # -- addr32 (0x67 affects the explicit mem operand) --
    V("pushq (%esi)",          branch="push addr32 mem"), NOP_PAD,
    V("popq 0x8(%esi)",        branch="pop addr32 mem"), NOP_PAD,
    # -- guard rails --
    V("pushq %fs:0x10(%rax)",  branch="refuse: segment-override mem", expect="refuse"),
    V("pushq %fs",             branch="refuse: segment push (separate opcode)",
      expect="refuse"),
    V("popq %fs",              branch="refuse: segment pop (separate opcode)",
      expect="refuse"),
]
UNENCODABLE["push-pop"] = [
    "kOpcodeName_pushd/popd — 32-bit-mode decode variants; a 64-bit-decoded "
    "blob cannot produce them (in 64-bit mode push/pop are 64- or 16-bit). "
    "Their empirical coverage comes from runtime fixtures / future "
    "32-bit-mode decode support; the audit's traces are the authority.",
]

def setcc_cross() -> list[V]:
    """cc x dst-shape cross-product for setcc.

    operands[0] is the cc, operands[1] the r/m8 dst (same layout as cmovcc).
    alloc_dst_gpr always takes one first-free temp: every dst is S8 (Register
    size<=S16 branch 27416) and mem kinds hit the same alloc at 27412/LABEL_2.
    Unlike cmovcc, the parity ccs (0xA/0xB, 15349-15356) cost NOTHING extra —
    emit_read_carry_to_gpr / emit_set_and_clear_carry_from_gpr work entirely
    in the already-allocated dst gpr (24738-24750). setcc reads flags but
    writes none, so no liveness pads. Expected axis of variation is the
    write_gpr_to_operand dst kind (27643-27701): Register via
    write_gpr_result, MemRef via translate_prefetch_impl store, AbsMem /
    unaligned-Immediate via compute_operand_address(XZR) + freed str temp,
    aligned-Immediate via a freed adr temp."""
    out: list[V] = []
    # cc breadth on a plain low-byte reg dst: one- and two-flag ccs + both
    # parity forms (the fnstsw/test/setp idiom makes p/np the hot ccs)
    for cc in ("e", "ne", "a", "b", "s", "ge", "o", "p", "np"):
        tag = " (parity carry-helper path)" if cc in ("p", "np") else ""
        out.append(V(f"set{cc} %dl", branch=f"cross set{cc}: low-byte reg{tag}"))
    # register classes: REX low bytes, r8b-r15b, high-byte (no REX needed)
    out.append(V("sete %sil", branch="cross sete: REX low byte (sil)"))
    out.append(V("setp %bpl", branch="cross setp: REX low byte (bpl)"))
    out.append(V("sete %r15b", branch="cross sete: r15b"))
    out.append(V("sete %ah", branch="cross sete: high-byte dst (ah)"))
    out.append(V("setp %ch", branch="cross setp: high-byte dst (ch)"))
    out.append(V("setnp %bh", branch="cross setnp: high-byte dst (bh)"))
    # mem dst sweep (b-size boundaries), normal vs parity cc
    mem_shapes = [("(%rax)", "disp0"), ("0x8(%rax)", "enc disp"),
                  ("0xff(%rax)", "imm9 max"), ("-0x100(%rax)", "imm9 min"),
                  ("0xfff(%rax)", "scaled imm12 max (b: scale 1)"),
                  ("0x1000(%rax)", "scaled imm12 max+1"),
                  ("-0x101(%rax)", "below imm9"),
                  ("0x12345(%rax)", "large non-enc disp"),
                  ("(%rax,%rdx,1)", "SIB shift==size (b: scale 1)"),
                  ("(%rax,%rdx,4)", "SIB shift mismatch"),
                  ("0x8(%rax,%rdx,1)", "SIB + disp"),
                  ("(,%rdx,1)", "index-only scale 1"),
                  ("0x100(,%rdx,8)", "index-only shifted + disp")]
    for cc in ("e", "p"):
        for mem, tag in mem_shapes:
            out.append(V(f"set{cc} {mem}", branch=f"cross set{cc}: mem dst {tag}"))
    # absolute / RIP / addr32 dsts
    for cc in ("e", "p"):
        out.append(V(f"set{cc} 0x12345678", branch=f"cross set{cc}: absolute disp-only dst"))
        out.append(V(f"set{cc} 0x100(%rip)",
                     branch=f"cross set{cc}: RIP Immediate dst (exact 3 — "
                     "the worst-case alignment fold equals the measured "
                     "total-event count, no slack)"))
        out.append(V(f"set{cc} (%esi)", branch=f"cross set{cc}: addr32 base"))
    out.append(V("sete 0x8(%esi,%ecx,4)", branch="cross sete: addr32 SIB + disp"))
    out.append(V("setp 0x12345(%edi)", branch="cross setp: addr32 non-enc disp"))
    # guard rails
    out.append(V("sete %fs:0x8(%rax)", branch="refuse: segment override",
                 expect="refuse"))
    return out


# Reconciled against the audit's 6-row shape table at review (2026-07-17):
# 50/50 exact, zero slack. The precautionary allow_slack on the RIP-Immediate
# rows was removed — the unaligned worst-case fold (peak 2 in
# compute_operand_address + the held dst temp = 3) equals the measured
# total-event count exactly, so slack would only mask a future regression.
MATRIX["setcc"] = setcc_cross()
UNENCODABLE["setcc"] = [
    "non-8-bit forms — 0F 9x /r encodes only r/m8; no r16/r32/r64, "
    "immediate-source, or two-operand shapes exist",
]


def test_cross() -> list[V]:
    """Shape cross-product for test (cmp's no-writeback sibling).

    operands: r/m first, reg-or-imm second; both reads, no writeback; lowers
    to ANDS (emit_ands_imm in the closure → the and/or/xor bitmask-imm
    encodability class, incl. the 32-bit replication trap). test WRITES
    SF/ZF/PF and clears OF/CF, so pads: OF consumer (worst flag liveness),
    flags-killer (dead side), SF consumer for the narrow-width nz gate the
    shifts matrix taught us to sweep. The aliased `test r,r` VC6 idiom gets
    both width and liveness coverage."""
    out: list[V] = []

    def add(v: V) -> None:
        out.append(v)
        out.append(OF_CONSUMER)

    # reg,reg — aliased idiom at every width, live and dead flags
    for sfx, r in (("b", "%al"), ("w", "%ax"), ("l", "%eax"), ("q", "%rax")):
        add(V(f"test{sfx} {r}, {r}", branch=f"cross test: aliased reg {sfx}"))
        out.append(V(f"test{sfx} {r}, {r}",
                     branch=f"cross test: aliased reg {sfx}, flags dead"))
        out.append(FLAG_KILLER)
    # non-aliased reg,reg + high-byte on either/both sides
    add(V("testq %rax, %rcx", branch="cross test: reg,reg q non-aliased"))
    add(V("testl %edx, %esi", branch="cross test: reg,reg l non-aliased"))
    add(V("testb %ah, %cl", branch="cross test: high-byte lhs"))
    add(V("testb %al, %ch", branch="cross test: high-byte rhs"))
    add(V("testb %ah, %bh", branch="cross test: high-byte both"))
    # SF-only liveness on narrow widths (shifts lesson)
    out.append(V("testw %ax, %bx", branch="cross test: reg w, SF-only live"))
    out.append(V("cmovsq %r10, %r11", branch="pad: SF consumer", pad=True))
    out.append(V("testb %al, %cl", branch="cross test: reg b, SF-only live"))
    out.append(V("cmovsq %r10, %r11", branch="pad: SF consumer", pad=True))
    # reg,imm — bitmask encodability class (ANDS) incl. replication trap
    for imm, tag in (("$0xff", "bitmask enc"), ("$0x5", "non-bitmask small"),
                     ("$0x12345", "non-bitmask large")):
        add(V(f"testq {imm}, %rax", branch=f"cross test: imm q {tag}"))
    add(V("testl $0xf0f0f0f, %eax", branch="cross test: imm l 32-bit repeating bitmask"))
    add(V("testq $0x55555555, %rax",
          branch="cross test: bitmask at 32 but NOT after sign-extend to 64"))
    add(V("testb $0x80, %al", branch="cross test: imm b (the fild-idiom sign bit)"))
    add(V("testw $0xf0f, %ax", branch="cross test: imm w repeating bitmask"))
    add(V("testw $0x1234, %bx", branch="cross test: imm w non-bitmask"))
    # mem lhs with reg rhs — boundary sweep at q, widths at b/w
    for mem, tag in (("(%rax)", "disp0"), ("0x8(%rax)", "enc disp"),
                     ("0x7ff8(%rax)", "scaled imm12 max"),
                     ("0x8000(%rax)", "scaled imm12 max+1"),
                     ("-0x100(%rax)", "imm9 min"), ("-0x101(%rax)", "below imm9"),
                     ("0x12345(%rax)", "large non-enc"),
                     ("(%rax,%rdx,8)", "SIB shift==size"),
                     ("(%rax,%rdx,2)", "SIB shift mismatch"),
                     ("(,%rdx,1)", "index-only")):
        add(V(f"testq %rcx, {mem}", branch=f"cross test: mem q {tag}"))
    add(V("testb %cl, (%rax)", branch="cross test: mem b reg"))
    add(V("testw %bx, 0x8(%rax)", branch="cross test: mem w reg"))
    # mem lhs with imm rhs (the memory fild idiom: test byte ptr [..], 0x80)
    add(V("testb $0x80, 0x12345(%rax)", branch="cross test: m8,imm8 non-enc disp"))
    add(V("testl $0x7fffffff, 0x8(%rax)", branch="cross test: m32,imm32 enc disp"))
    add(V("testq $0x12345, (%rax,%rdx,8)", branch="cross test: m64,non-bitmask imm SIB"))
    # absolute / RIP / addr32
    add(V("testq %rcx, 0x12345678", branch="cross test: absolute disp-only lhs"))
    add(V("testq %rcx, 0x100(%rip)", branch="cross test: RIP Immediate lhs, reg rhs"))
    add(V("testl $0x5, 0x100(%rip)", branch="cross test: RIP Immediate lhs, imm rhs"))
    add(V("testl %ecx, (%esi)", branch="cross test: addr32 base"))
    add(V("testb $0x80, 0x8(%esi,%ecx,4)", branch="cross test: addr32 SIB + disp imm8"))
    add(V("testl %ecx, 0x12345(%edi)", branch="cross test: addr32 non-enc disp"))
    # guard rail
    add(V("testq %rcx, %fs:0x8(%rax)", branch="refuse: segment override",
          expect="refuse"))
    return out


# DRAFT (2026-07-17) — the fnstsw-adjacent test shape is excluded by the
# LOOKAHEAD guard, not by the demand model, so it does not appear here (the
# model prices it like any test; the guard simply never lets it bridge).
MATRIX["test"] = test_cross()
UNENCODABLE["test"] = [
    "reg rhs with mem lhs is the only mem form — F6/F7 /0 and 84/85 have no "
    "mem,mem or imm-lhs encodings",
]


def mul_imul_cross() -> list[V]:
    """Form x shape cross-product for mul/imul (one handler,
    translate_imul_mul 28964-29243).

    Three x86 form classes: one-operand widening (rDX:rAX dst — mul and
    imul), two-operand imul r,r/m, three-operand imul r,r/m,imm. Flag work
    is (OF|CF)-gated with a size dimension (29037/29052/29145), so every
    variant gets an OF consumer pad plus dead-side rows."""
    out: list[V] = []

    def add(v: V) -> None:
        out.append(v)
        out.append(OF_CONSUMER)

    # one-operand widening forms, both opcodes, every width, reg and mem
    for op in ("mul", "imul"):
        for sfx, r in (("b", "%cl"), ("w", "%bx"), ("l", "%ecx"), ("q", "%rcx")):
            add(V(f"{op}{sfx} {r}", branch=f"cross {op}: one-op reg {sfx}"))
            out.append(V(f"{op}{sfx} {r}",
                         branch=f"cross {op}: one-op reg {sfx}, flags dead"))
            out.append(FLAG_KILLER)
        add(V(f"{op}l 0x8(%rax)", branch=f"cross {op}: one-op mem l enc disp"))
        add(V(f"{op}q 0x12345(%rax)", branch=f"cross {op}: one-op mem q non-enc disp"))
        add(V(f"{op}w (%rax,%rdx,2)", branch=f"cross {op}: one-op mem w SIB"))
        add(V(f"{op}b (%rax)", branch=f"cross {op}: one-op mem b disp0"))
    add(V("mull (%esi)", branch="cross mul: one-op addr32 mem"))
    add(V("imulq 0x100(%rip)", branch="cross imul: one-op RIP Immediate"))
    # two-operand imul
    for sfx, (s, d) in (("w", ("%ax", "%bx")), ("l", ("%eax", "%ecx")),
                        ("q", ("%rax", "%rcx"))):
        add(V(f"imul{sfx} {s}, {d}", branch=f"cross imul: two-op reg {sfx}"))
        out.append(V(f"imul{sfx} {s}, {d}",
                     branch=f"cross imul: two-op reg {sfx}, flags dead"))
        out.append(FLAG_KILLER)
    add(V("imulq %rcx, %rcx", branch="cross imul: two-op aliased"))
    add(V("imull 0x8(%rax), %ecx", branch="cross imul: two-op mem enc disp"))
    add(V("imulq 0x12345(%rax,%rdx,4), %rcx", branch="cross imul: two-op mem SIB+disp"))
    add(V("imull (%esi), %ecx", branch="cross imul: two-op addr32 mem"))
    add(V("imulq 0x100(%rip), %rcx", branch="cross imul: two-op RIP Immediate"))
    # three-operand imul (imm forms — the common compiler-emitted imul r,imm)
    add(V("imulq $0x8, %rax, %rcx", branch="cross imul: three-op enc imm"))
    add(V("imull $0x8c, %ebx, %edi", branch="cross imul: three-op imm8-class idiom"))
    add(V("imulq $0x12345, %rax, %rcx", branch="cross imul: three-op non-enc imm"))
    add(V("imulw $0x1234, %ax, %bx", branch="cross imul: three-op w"))
    add(V("imull $0x12345678, 0x8(%rax), %ecx", branch="cross imul: three-op mem src"))
    add(V("imull $0x5, (%esi), %ecx", branch="cross imul: three-op addr32 mem src"))
    add(V("imulq $0x12345678, 0x1234d(%rsi,%rdx,8), %rbx",
          branch="cross imul: three-op mem SIB (gap_mul_imul fixture shape)"))
    # guard rail
    add(V("imulq %fs:0x8(%rax), %rcx", branch="refuse: segment override",
          expect="refuse"))
    return out


# DRAFT (2026-07-17) — expects reconciled against the audit at review.
MATRIX["mul-imul"] = mul_imul_cross()
UNENCODABLE["mul-imul"] = [
    "mul has only the one-operand widening form (F6/F7 /4); imul adds "
    "two-operand (0F AF) and three-operand (69/6B) forms — no imm form "
    "for mul, no mem dst for any form",
]


# extends: no explicit operands (implicit AL/AX/EAX/RAX and DX:AX/EDX:EAX),
# so the shape space is the opcode alone — no mem/addr_size/kind dimensions
# and no flag pads (none of the five reads or writes EFLAGS). cbw and cwd
# take an inline first-free alloc (15532/15631, held to the LABEL_705
# epilogue) = 1; cwde/cdqe/cdq emit one pre-computed raw word via LABEL_561
# (15896-15898) = 0. cqo joined the family 2026-07-17 (user decision;
# AUDIT.md addendum): Bucket B like cdq, case group 15569-15571, demand 0.
MATRIX["extends"] = [
    V("cbtw", branch="cbw: inline first-free alloc 15532 (demand 1)"),
    V("cwtl", branch="cwde: raw-word emit via LABEL_561 (demand 0)"),
    V("cltq", branch="cdqe: raw-word emit via LABEL_561 (demand 0)"),
    V("cwtd", branch="cwd: inline first-free alloc 15631 (demand 1)"),
    V("cltd", branch="cdq: raw-word emit via LABEL_561 (demand 0)"),
    V("cqto", branch="cqo: raw-word emit via LABEL_561 (demand 0; "
      "added to the family 2026-07-17, AUDIT.md addendum)"),
]
UNENCODABLE["extends"] = [
    "no operand-bearing forms exist — 98/99 (+66/REX.W) encode only the "
    "implicit-accumulator shapes; the six matrix rows are the whole space",
]

def adc_sbb_cross() -> list[V]:
    """Full opcode x shape cross-product for adc/sbb (alu_cross pattern).

    Both opcodes CONSUME CF and write the full flag set; the handlers gate
    work on flag_liveness per-bit including FLAG_AF and FLAG_PF_HI
    (translate_adc 20872/20873/20881/20897, translate_sbb 21955/21956/
    21969/21990, emit_flag_writeback 24770/24780) — so beyond the usual
    OF-consumer / flags-killer pads this matrix adds an AF+PF pad (lahf
    reads SF:ZF:AF:PF:CF) and a PF-only pad (cmovp), the axis no previous
    family exercised. Narrow widths (S8/S16) x flag gates are swept on the
    dead side too (the shifts lesson). Draft written pre-landing; expects
    reconciled against the audit's shape table at review."""
    out: list[V] = []

    def add(v: V) -> None:
        out.append(v)
        out.append(OF_CONSUMER)

    regs = {"b": ("%al", "%cl"), "w": ("%ax", "%bx"),
            "l": ("%eax", "%ecx"), "q": ("%rax", "%rcx")}
    af_pad = V("lahf", branch="pad: AF+PF consumer (lahf)", pad=True)
    pf_pad = V("cmovpq %r10, %r11", branch="pad: PF consumer", pad=True)

    for op in ("adc", "sbb"):
        # reg,reg at every width, flags live vs dead
        for sfx, (s, d) in regs.items():
            add(V(f"{op}{sfx} {s}, {d}", branch=f"cross {op}: reg,reg {sfx}"))
            out.append(V(f"{op}{sfx} {s}, {d}",
                         branch=f"cross {op}: reg,reg {sfx}, flags dead"))
            out.append(FLAG_KILLER)
        # single-bit liveness gates: CF-only (the adc/sbb chain case),
        # SF-only narrow, AF+PF, PF-only narrow
        out.append(V(f"{op}q %rax, %rcx", branch=f"cross {op}: reg q, CF-only live"))
        out.append(CF_CONSUMER)
        out.append(V(f"{op}w %ax, %bx", branch=f"cross {op}: reg w, SF-only live"))
        out.append(V("cmovsq %r10, %r11", branch="pad: SF consumer", pad=True))
        out.append(V(f"{op}b %al, %cl", branch=f"cross {op}: reg b, AF+PF live"))
        out.append(af_pad)
        out.append(V(f"{op}w %ax, %bx", branch=f"cross {op}: reg w, PF-only live"))
        out.append(pf_pad)
        # high-byte src / dst / both
        add(V(f"{op}b %ah, %cl", branch=f"cross {op}: high-byte src"))
        add(V(f"{op}b %al, %ah", branch=f"cross {op}: high-byte dst"))
        add(V(f"{op}b %ah, %ch", branch=f"cross {op}: high-byte src AND dst"))
        # immediates (arith imm12 class, like add/sub)
        for imm, tag in (("$0x8", "imm12 enc"), ("$0xfff000", "shifted-imm12 enc"),
                         ("$-0x8", "negated enc"), ("$0x12345", "non-enc")):
            add(V(f"{op}q {imm}, %rax", branch=f"cross {op}: arith {tag}"))
        add(V(f"{op}b $0x42, %al", branch=f"cross {op}: imm -> r8"))
        add(V(f"{op}w $0x1234, %bx", branch=f"cross {op}: imm -> r16"))
        # memory sources
        for mem, tag in (("(%rax)", "disp0"), ("0x8(%rax)", "enc disp"),
                         ("0x12345(%rax)", "non-enc disp"),
                         ("(%rax,%rdx,8)", "SIB")):
            add(V(f"{op}q {mem}, %rcx", branch=f"cross {op}: mem src {tag}"))
        add(V(f"{op}b (%rax), %cl", branch=f"cross {op}: mem src b width"))
        add(V(f"{op}q (,%rdx,8), %rcx", branch=f"cross {op}: mem src index-only"))
        # RMW memory destinations
        for mem, tag in (("(%rax)", "disp0"), ("0x8(%rax)", "enc disp"),
                         ("0x12345(%rax)", "non-enc disp"),
                         ("(%rax,%rdx,8)", "SIB disp0"),
                         ("0x8(%rax,%rdx,4)", "SIB + disp"),
                         ("0x8(,%rdx,4)", "index-only + disp")):
            add(V(f"{op}q %rcx, {mem}", branch=f"cross {op}: mem dst {tag}"))
        add(V(f"{op}b %cl, (%rax)", branch=f"cross {op}: mem dst b width"))
        add(V(f"{op}w %bx, 0x8(%rax)", branch=f"cross {op}: mem dst w width"))
        add(V(f"{op}q $0x8, 0x8(%rax)", branch=f"cross {op}: imm-enc -> mem"))
        add(V(f"{op}q $0x12345, 0x8(%rax)", branch=f"cross {op}: imm-non-enc -> mem"))
        # absolute / addr32
        add(V(f"{op}l %ecx, 0x8(%esi)", branch=f"cross {op}: addr32 mem dst"))
        add(V(f"{op}l 0x8(%esi), %ecx", branch=f"cross {op}: addr32 mem src"))
        add(V(f"{op}l %ecx, (%esi,%edi,4)", branch=f"cross {op}: addr32 SIB dst"))
        # RIP forms (the standing trap — price by total events)
        add(V(f"{op}q 0x100(%rip), %rcx", branch=f"cross {op}: RIP Immediate src"))
        add(V(f"{op}q %rcx, 0x100(%rip)", branch=f"cross {op}: RIP Immediate RMW dst"))
        # LOCK guard rail (lockable_rmw refuses LOCK+mem in the common prefix)
        add(V(f"lock {op}q %rcx, (%rax)", branch=f"refuse: LOCK {op} RMW",
              expect="refuse"))
    # idioms
    add(V("sbbl %eax, %eax", branch="idiom: sbb same-reg carry materialization"))
    add(V("sbbq %rax, %rax", branch="idiom: sbb same-reg q"))
    add(V("adcl $0x0, %eax", branch="idiom: adc 0 (carry fold)"))
    # segment-override guard rail
    add(V("adcq %fs:0x8(%rax), %rcx", branch="refuse: segment override",
          expect="refuse"))
    return out


# DRAFT (2026-07-17) — join-checked pre-landing; expects reconciled against
# the audit's shape table at review.
MATRIX["adc-sbb"] = adc_sbb_cross()
UNENCODABLE["adc-sbb"] = [
    "no non-RMW form — 10-1D / 80-83 /2,/3 always read AND write the dst; "
    "every encodable shape is covered by the reg/mem/imm/RIP sweeps",
]


MATRIX["nop-wait"] = [
    V("nop",                          branch="nop: no translate_insn case (default label)"),
    V("fwait",                        branch="wait/FWAIT: default label"),
    V("nopl (%rax)",                  branch="multi-byte nop with MemRef operand (still 0)"),
    V("nopw 0x12345(%rax,%rax,1)",    branch="long nop with complex SIB operand (still 0)"),
]

# ── blob build + run + join ──────────────────────────────────────────────────


def assemble(family: str, variants: list[V], outdir: Path) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    asm = outdir / f"{family}.s"
    obj = outdir / f"{family}.o"
    blob = outdir / f"{family}.bin"
    lines = [".text"]
    for v in variants:
        lines.append(f"\t{v.asm}")
    lines.append("\tret")  # terminate the block; skipped when joining
    asm.write_text("\n".join(lines) + "\n")
    subprocess.run(["/usr/bin/clang", "-arch", "x86_64", "-c",
                    str(asm), "-o", str(obj)], check=True)
    # Extract raw __TEXT,__text bytes via otool's hex dump.
    dump = subprocess.run(["/usr/bin/otool", "-t", str(obj)],
                          check=True, capture_output=True, text=True).stdout
    data = bytearray()
    for line in dump.splitlines():
        m = re.match(r"^[0-9a-f]{8,16}[ \t]+((?:[0-9a-f]{2}[ \t]*)+)$", line)
        if m:
            data.extend(int(b, 16) for b in m.group(1).split())
    if not data:
        raise SystemExit(f"no __text bytes extracted for {family}")
    blob.write_bytes(bytes(data))
    return blob


def translate(blob: Path) -> list[tuple[str, str, int, int | None]]:
    """Run aotinvoke; return rows as (op, operands, actual, est|None) in order."""
    if not AOTINVOKE.exists():
        raise SystemExit(f"{AOTINVOKE} missing — build first (cmake --build build)")
    env = dict(os.environ,
               ROSETTA_X87_DISABLE_ALL_OPS="1",
               ROSETTA_X87_DISABLE_ALL_FUSIONS="1")
    proc = subprocess.run([str(AOTINVOKE), str(blob), "/dev/null", "--demand"],
                          capture_output=True, text=True, env=env, cwd=REPO)
    if proc.returncode != 0:
        raise SystemExit(f"aotinvoke failed:\n{proc.stderr or proc.stdout}")
    rows = []
    for line in proc.stdout.splitlines():
        m = ROW_RE.match(line)
        if m:
            _, op, operands, actual, est = m.groups()
            rows.append((op, operands, int(actual),
                         None if est == "refuse" else int(est)))
    return rows


def run_matrix(family: str, verbose: bool = True) -> int:
    if family not in MATRIX:
        raise SystemExit(f"no matrix spec for '{family}' — known: "
                         f"{', '.join(sorted(MATRIX))}")
    variants = MATRIX[family]
    blob = assemble(family, variants, OUTDIR)
    rows = translate(blob)
    # Drop the trailing ret row(s); everything before must join 1:1.
    while rows and rows[-1][0] == "ret":
        rows.pop()
    if len(rows) != len(variants):
        for i, r in enumerate(rows):
            v = variants[i].asm if i < len(variants) else "<none>"
            print(f"  row {i}: {r[0]} {r[1]}   <- variant: {v}")
        raise SystemExit(
            f"{family}: {len(variants)} variants but {len(rows)} IR rows — "
            f"an instruction decoded unexpectedly; fix the spec/join first.")

    fails = slack = 0
    hit: dict[str, int] = {}
    if verbose:
        print(f"{'#':>3}  {'instruction':<40} {'act':>3} {'est':>6}  verdict  branch")
        print("─" * 118)
    fail_lines: list[str] = []
    for i, (v, (op, operands, actual, est)) in enumerate(zip(variants, rows)):
        if v.pad:
            if verbose:
                est_s = "refuse" if est is None else str(est)
                print(f"{i:>3}  {v.asm:<40} {actual:>3} {est_s:>6}  {'pad':<8} {v.branch}")
            continue
        hit[v.branch] = hit.get(v.branch, 0) + 1
        if v.expect == "refuse":
            verdict = "PASS" if est is None else "FAIL(should refuse)"
        elif est is None:
            verdict = "FAIL(unexpected refuse)"
        elif actual > est:
            verdict = "FAIL(underestimate)"
        elif est > actual:
            verdict = f"SLACK({est - actual})" if v.allow_slack \
                else "FAIL(undocumented slack)"
        else:
            verdict = "PASS"
        if verdict.startswith("FAIL"):
            fails += 1
        if verdict.startswith("SLACK"):
            slack += 1
        est_s = "refuse" if est is None else str(est)
        line = f"{i:>3}  {v.asm:<40} {actual:>3} {est_s:>6}  {{v}}  {v.branch}"
        if verdict.startswith("FAIL"):
            fail_lines.append(line.format(v=f"{RED}{verdict}{NC}"))
        if verbose:
            color = RED if verdict.startswith("FAIL") else \
                YELLOW if verdict.startswith("SLACK") else GREEN
            print(line.format(v=f"{color}{verdict}{NC}"))

    if verbose:
        print("─" * 118)
    status = f"{GREEN}PASS{NC}" if fails == 0 else f"{RED}FAIL{NC}"
    print(f"{status}  {family:<22} {len(variants)} variants, {len(hit)} branches, "
          f"{fails} FAIL, {slack} documented-slack")
    if not verbose:
        for line in fail_lines:
            print(f"      {line}")
    if verbose:
        for note in UNENCODABLE.get(family, []):
            print(f"  analytic-only (not x86-encodable here): {note}")
    return fails


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if args and args[0] == "--list":
        for fam, vs in MATRIX.items():
            print(f"{fam:24s} {len(vs)} variants")
        return 0

    if args:
        # Explicit families: full per-variant tables.
        fails = 0
        for fam in args:
            print(f"{BOLD}== matrix {fam} =={NC}")
            fails += run_matrix(fam, verbose=True)
            print()
        return 1 if fails else 0

    # Default: run every family with a matrix spec, run_tests.sh-style.
    print(f"{BOLD}=== bridge-demand estimation: all families ==={NC}")
    fails = failed_fams = 0
    for fam in sorted(MATRIX):
        f = run_matrix(fam, verbose=False)
        fails += f
        failed_fams += 1 if f else 0
    total = len(MATRIX)
    print("=" * 64)
    print(f"Results: {GREEN}{total - failed_fams} families passed{NC}, "
          f"{RED}{failed_fams} failed{NC} ({fails} failing rows) / {total} total")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
