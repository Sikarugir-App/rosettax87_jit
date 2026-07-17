/*
 * test_bridge_pressure.c — GPR-pressure fixtures for ROSETTA_X87_RUN_BRIDGE.
 *
 * With RUN_BRIDGE=1, a run-transparent integer instruction inside an active
 * x87 run is translated by Rosetta itself while the run's pinned cache GPRs
 * (3 fixed; +up to 3 more with BRIDGE_CARRY) stay excluded from the scratch
 * pool. Rosetta's translators for the heavier transparent ops — adc/sbb,
 * CL-count shifts, mul/imul, xchg m,r, cmp/setcc/cmov chains, push/pop m64,
 * SSE converts — need several temporaries for complex-SIB addresses, large
 * immediates and flag materialization. If demand exceeds the reduced pool,
 * Rosetta aborts at translation time with
 *     "no temporary GPR available to allocate".
 *
 * Every fixture here is one x87 run (fld/fmul … fadd/fstp) with a gap of at
 * most kMaxBridgeGap(=4) transparent instructions in their nastiest operand
 * shapes: [base + index*scale + disp32] with a non-imm12 displacement
 * (0x12345), imm32/imm64 immediates, memory destinations, CL counts. Each
 * fixture family is one function so inspect_function.sh can audit its
 * lowering (and its temp demand) in isolation:
 *
 *     scripts/inspect_function.sh build/bin/test_bridge_pressure \
 *         gap_adc_sbb --disable-all-ops --disable-all-fusions
 *
 * (Rosetta's temp allocator is lowest-free-bit-first, so the highest scratch
 * register x22..x29 appearing in the disassembly of an instruction reveals
 * its peak concurrent temp demand.)
 *
 * All fixtures self-check against C-computed expected values, so the same
 * binary is a correctness test in every run_tests.sh phase.
 *
 * Build: clang -arch x86_64 -O0 -g -o test_bridge_pressure test_bridge_pressure.c
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int failures = 0;

static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

static void check(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-52s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_u64(const char *name, uint64_t got, uint64_t expected) {
    if (got != expected) {
        printf("FAIL  %-52s  got=0x%llx  expected=0x%llx\n", name,
               (unsigned long long)got, (unsigned long long)expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* Shared arena so 0x12345(%rsi,%rdx,8) with rdx=2 lands at a valid slot:
 * arena + 0x12345 + 16. The displacement 0x12345 is deliberately not
 * ADD-imm12(-shifted) encodable, forcing address materialization temps. */
static uint8_t arena[0x14000];
#define SLOT(off) ((uint64_t *)(arena + 0x12345 + 16 + (off)))

/* ── adc/sbb m64,imm32 with complex SIB; CF defined by an in-gap cmp ───── */
__attribute__((noinline))
static double gap_adc_sbb(double a, double b, double c,
                          uint64_t *adc_out, uint64_t *sbb_out) {
    double r;
    *SLOT(0) = 1000;   /* adc target */
    *SLOT(8) = 5000;   /* sbb target */
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "movq $2, %%rdx\n"
        "movq $5, %%rcx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        /* gap 1: cmp defines CF=1 (5 < 9); adc m64 += imm32 + CF */
        "cmpq $9, %%rcx\n"
        "adcq $0x12345678, 0x12345(%%rsi,%%rdx,8)\n"
        "faddl %[c]\n"
        /* gap 2: CF=1 again; sbb m64 -= imm32 + CF */
        "cmpq $9, %%rcx\n"
        "sbbq $0x1234, 0x1234d(%%rsi,%%rdx,8)\n"
        "fstpl %[r]\n"
        : [r] "=m"(r)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(arena)
        : "rsi", "rdx", "rcx", "cc", "memory");
    *adc_out = *SLOT(0);
    *sbb_out = *SLOT(8);
    return r;
}

/* ── xchg r64,m64 (implicitly locked → exclusive-loop temps) ───────────── */
__attribute__((noinline))
static double gap_xchg_mem(double a, double b, double c,
                           uint64_t *reg_out, uint64_t *mem_out) {
    double r;
    uint64_t reg = 0;
    *SLOT(0) = 0x1111222233334444ull;
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "movq $2, %%rdx\n"
        "movq $0xAABBCCDD, %%rcx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        "xchgq %%rcx, 0x12345(%%rsi,%%rdx,8)\n"
        "faddl %[c]\n"
        "fstpl %[r]\n"
        "movq %%rcx, %[reg]\n"
        : [r] "=m"(r), [reg] "=&r"(reg)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(arena)
        : "rsi", "rdx", "rcx", "cc", "memory");
    *reg_out = reg;
    *mem_out = *SLOT(0);
    return r;
}

/* ── shl/sar m64,CL with complex SIB ───────────────────────────────────── */
__attribute__((noinline))
static double gap_shift_cl(double a, double b, double c,
                           uint64_t *shl_out, uint64_t *sar_out) {
    double r;
    *SLOT(0) = 0x1111;
    *SLOT(8) = (uint64_t)-4096;
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "movq $2, %%rdx\n"
        "movq $5, %%rcx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        "shlq %%cl, 0x12345(%%rsi,%%rdx,8)\n"
        "faddl %[c]\n"
        "sarq %%cl, 0x1234d(%%rsi,%%rdx,8)\n"
        "fstpl %[r]\n"
        : [r] "=m"(r)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(arena)
        : "rsi", "rdx", "rcx", "cc", "memory");
    *shl_out = *SLOT(0);
    *sar_out = *SLOT(8);
    return r;
}

/* ── mul m64 (RDX:RAX writers) and imul r64,m64,imm32 ──────────────────── */
__attribute__((noinline))
static double gap_mul_imul(double a, double b, double c,
                           uint64_t *lo_out, uint64_t *hi_out, uint64_t *imul_out) {
    double r;
    uint64_t lo = 0, hi = 0, im = 0;
    *SLOT(0) = 0x123456789ull;
    *SLOT(8) = 77;
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "movq $7, %%rax\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        "mulq 0x12355(%%rsi)\n"           /* RDX:RAX = 7 * SLOT(0) */
        "faddl %[c]\n"
        "movq %%rax, %%rcx\n"             /* save lo before rdx reuse below */
        "movq %%rdx, %%rdi\n"
        "movq $2, %%rdx\n"
        "imulq $0x12345678, 0x1234d(%%rsi,%%rdx,8), %%rbx\n"
        "fstpl %[r]\n"
        "movq %%rcx, %[lo]\n"
        "movq %%rdi, %[hi]\n"
        "movq %%rbx, %[im]\n"
        : [r] "=m"(r), [lo] "=&r"(lo), [hi] "=&r"(hi), [im] "=&r"(im)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(arena)
        : "rsi", "rdx", "rcx", "rdi", "rax", "rbx", "cc", "memory");
    *lo_out = lo;
    *hi_out = hi;
    *imul_out = im;
    return r;
}

/* ── cmp m64,imm32 + setcc m8 + cmovcc r64,m64 flag chain ──────────────── */
__attribute__((noinline))
static double gap_cmp_setcc_cmov(double a, double b, double c,
                                 uint64_t *set_out, uint64_t *cmov_out) {
    double r;
    uint64_t cm = 0;
    *SLOT(0) = 0x99999999ull;   /* > 0x12345678 → above → cmov taken */
    *((uint8_t *)SLOT(8)) = 0xFF;
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "movq $2, %%rdx\n"
        "movq $0xDEAD, %%rcx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        "cmpq $0x12345678, 0x12345(%%rsi,%%rdx,8)\n"
        "setbe 0x1234d(%%rsi,%%rdx,8)\n"
        "cmovaq 0x12345(%%rsi,%%rdx,8), %%rcx\n"
        "faddl %[c]\n"
        "fstpl %[r]\n"
        "movq %%rcx, %[cm]\n"
        : [r] "=m"(r), [cm] "=&r"(cm)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(arena)
        : "rsi", "rdx", "rcx", "cc", "memory");
    *set_out = *((uint8_t *)SLOT(8));
    *cmov_out = cm;
    return r;
}

/* ── test reg,reg / mem,imm8 / reg,imm32 shapes inside x87 gaps ────────── */
__attribute__((noinline))
static double gap_test_shapes(double a, double b, double c, uint64_t *fl_out) {
    double r;
    uint64_t fl = 0;
    *SLOT(0) = 0x80ull;   /* memory operand: bit 7 set → test m8,0x80 nonzero */
    *((uint8_t *)SLOT(8)) = 0xFF;
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "movq $2, %%rdx\n"
        "xorq %%rcx, %%rcx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        "testq %%rdx, %%rdx\n"                   /* reg,reg: rdx=2 → ZF=0 */
        "setne %%cl\n"
        "testb $0x80, 0x12345(%%rsi,%%rdx,8)\n"  /* m8,imm8: 0x80 → ZF=0 */
        "setne %%ch\n"
        "faddl %[c]\n"
        "testl $0x7fffffff, %%edx\n"             /* reg,imm32: 2 → ZF=0 */
        "setne 0x1234d(%%rsi,%%rdx,8)\n"
        "fstpl %[r]\n"
        "movq %%rcx, %[fl]\n"
        : [r] "=m"(r), [fl] "=&r"(fl)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(arena)
        : "rsi", "rdx", "rcx", "cc", "memory");
    *fl_out = (fl & 0xFFFF) | ((uint64_t)*((uint8_t *)SLOT(8)) << 16);
    return r;
}

/* ── push m64 / pop m64 (memory forms, balanced inside one gap) ────────── */
__attribute__((noinline))
static double gap_push_pop_mem(double a, double b, double c, uint64_t *pop_out) {
    double r;
    *SLOT(0) = 0x5566778899AABBCCull;
    *SLOT(8) = 0;
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "movq $2, %%rdx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        "pushq 0x12345(%%rsi,%%rdx,8)\n"
        "popq 0x1234d(%%rsi,%%rdx,8)\n"
        "faddl %[c]\n"
        "fstpl %[r]\n"
        : [r] "=m"(r)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(arena)
        : "rsi", "rdx", "cc", "memory");
    *pop_out = *SLOT(8);
    return r;
}

/* ── SSE scalar: movsd/addsd from complex SIB + cvttsd2si ──────────────── */
__attribute__((noinline))
static double gap_sse_cvt(double a, double b, double c, uint64_t *cvt_out) {
    double r;
    uint64_t cv = 0;
    double v1 = 100.75, v2 = 41.5;
    memcpy(SLOT(0), &v1, 8);
    memcpy(SLOT(8), &v2, 8);
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "movq $2, %%rdx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        "movsd 0x12345(%%rsi,%%rdx,8), %%xmm1\n"
        "addsd 0x1234d(%%rsi,%%rdx,8), %%xmm1\n"
        "cvttsd2si %%xmm1, %%rcx\n"
        "faddl %[c]\n"
        "fstpl %[r]\n"
        "movq %%rcx, %[cv]\n"
        : [r] "=m"(r), [cv] "=&r"(cv)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(arena)
        : "rsi", "rdx", "rcx", "xmm1", "cc", "memory");
    *cvt_out = cv;
    return r;
}

/* ── mov heavies: imm64, m64←r store, movzx from SIB mem, movnti ───────── */
__attribute__((noinline))
static double gap_mov_heavy(double a, double b, double c,
                            uint64_t *store_out, uint64_t *zx_out, uint64_t *nti_out) {
    double r;
    uint64_t zx = 0;
    *SLOT(0) = 0;
    *SLOT(8) = 0;
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "movq $2, %%rdx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        "movabsq $0x1122334455667788, %%rcx\n"
        "movq %%rcx, 0x12345(%%rsi,%%rdx,8)\n"
        "movzwl 0x12345(%%rsi,%%rdx,8), %%edi\n"
        "movnti %%rcx, 0x1234d(%%rsi,%%rdx,8)\n"
        "faddl %[c]\n"
        "fstpl %[r]\n"
        "movq %%rdi, %[zx]\n"
        : [r] "=m"(r), [zx] "=&r"(zx)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(arena)
        : "rsi", "rdx", "rcx", "rdi", "cc", "memory");
    *store_out = *SLOT(0);
    *zx_out = zx;
    *nti_out = *SLOT(8);
    return r;
}

/* ── mov shape corners: partial reg→reg, scale-encodable SIB ───────────────
 * Verifies the tightened mov demand model (verify_demand.py fixtures):
 *   movb %al,%cl / movw %ax,%bx      — 8/16-bit reg→reg passthrough (demand 0)
 *   movb %ah,%ch                     — high-byte source (demand 1)
 *   (%rsi,%rdx,8) / (%rsi,%rdx)      — SIB, disp 0, lsl 3 / lsl 0 (demand 0)
 *   (%rsi,%rdx,4)                    — SIB, lsl 2 ≠ access size (demand 1) */
__attribute__((noinline))
static double gap_mov_shapes(double a, double b, double c,
                             uint64_t *rcx_out, uint64_t *rbx_out,
                             uint64_t *ld8_out, uint64_t *ld1_out,
                             uint64_t *ld4_out, uint64_t *st_out,
                             uint64_t *zxh_out) {
    double r;
    uint8_t buf[64];
    for (int i = 0; i < 64; i++) buf[i] = (uint8_t)(0xC0 + i);
    uint64_t st_buf[3] = {0, 0, 0};
    uint64_t rcx = 0xAAAAAAAAAAAAAAAAull, rbx = 0xBBBBBBBBBBBBBBBBull;
    uint64_t ld8 = 0, ld1 = 0, ld4 = 0, zxh = 0;
    __asm__ volatile(
        "movq $0x1122334455667788, %%rax\n"
        "movq $2, %%rdx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        /* gap 1: partial-register reg→reg moves + high-byte widening */
        "movb %%al, %%cl\n"
        "movw %%ax, %%bx\n"
        "movb %%ah, %%ch\n"
        "movzbl %%ah, %%eax\n"
        "faddl %[c]\n"
        /* gap 2: SIB loads/store with scale 8 / 1 / 4, disp 0 */
        "movq (%%rsi,%%rdx,8), %%r8\n"
        "movq (%%rsi,%%rdx), %%r9\n"
        "movq (%%rsi,%%rdx,4), %%r10\n"
        "movq %%r8, (%%rdi,%%rdx,8)\n"
        "fstpl %[r]\n"
        "movq %%r8, %[ld8]\n"
        "movq %%r9, %[ld1]\n"
        "movq %%r10, %[ld4]\n"
        "movq %%rax, %[zxh]\n"
        : [r] "=m"(r), [ld8] "=m"(ld8), [ld1] "=m"(ld1), [ld4] "=m"(ld4),
          [zxh] "=m"(zxh), "+c"(rcx), "+b"(rbx)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), "S"(buf), "D"(st_buf)
        : "rax", "rdx", "r8", "r9", "r10", "cc", "memory");
    *rcx_out = rcx;
    *rbx_out = rbx;
    *ld8_out = ld8;
    *ld1_out = ld1;
    *ld4_out = ld4;
    *st_out = st_buf[2];
    *zxh_out = zxh;
    return r;
}

/* ── alu shape corners from the matrix findings (2026-07-17) ───────────────
 * verify_demand.py fixtures for the alu-binary family:
 *   addb %ah, %cl        — high-byte source (extract temp)
 *   orb  %al, %cl        — r8 logical reg,reg
 *   xorl %r10d, %r10d    — self-zero idiom
 *   subl $1, %r9d        — r32 imm12
 *   addq %rax, rip_var   — RIP-relative RMW dst: REFUSED (demand > 4) —
 *                          run breaks, correctness must still hold. */
static uint64_t alu_rip_var = 1000;
__attribute__((noinline))
static double gap_alu_reg_shapes(double a, double b, double c,
                                 uint64_t *rcx_out, uint64_t *r9_out,
                                 uint64_t *r10_out, uint64_t *rip_out) {
    double r;
    uint64_t rcx = 0xAAAAAAAAAAAAAAAAull, r9v = 0, r10v = 0x5555;
    alu_rip_var = 1000;
    __asm__ volatile(
        "movq $0x1122334455667788, %%rax\n"
        "movq $100, %%r9\n"
        "movq $0x5555, %%r10\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        /* gap 1: high-byte src, r8 logical, self-zero, r32 imm */
        "addb %%ah, %%cl\n"
        "orb  %%al, %%cl\n"
        "xorl %%r10d, %%r10d\n"
        "subl $1, %%r9d\n"
        "faddl %[c]\n"
        /* gap 2: RIP-relative RMW (refused shape — run must break cleanly) */
        "addq %%rax, %[rip_var]\n"
        "fstpl %[r]\n"
        "movq %%r9, %[r9o]\n"
        "movq %%r10, %[r10o]\n"
        : [r] "=m"(r), [r9o] "=m"(r9v), [r10o] "=m"(r10v),
          [rip_var] "+m"(alu_rip_var), "+c"(rcx)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c)
        : "rax", "r9", "r10", "cc", "memory");
    *rcx_out = rcx;
    *r9_out = r9v;
    *r10_out = r10v;
    *rip_out = alu_rip_var;
    return r;
}

/* ── lea shape corners: SIB disp 0 / non-encodable disp / 16-bit dst ──────
 * verify_demand.py fixtures for the lea family:
 *   leaq (%rsi,%rdx,8)          — SIB, disp 0, arch dst      (demand 0)
 *   leaq 0x12345(%rsi,%rdx,4)   — SIB, non-encodable disp    (demand 1)
 *   leaw (%rsi,%rdx), %ax       — 16-bit dst (Case B temp)   (demand 1) */
__attribute__((noinline))
static double gap_lea_shapes(double a, double b, double c,
                             uint64_t *sib_out, uint64_t *disp_out,
                             uint64_t *w_out) {
    double r;
    uint64_t v1 = 0, v2 = 0, v3 = 0;
    __asm__ volatile(
        "movq $2, %%rdx\n"
        "movq $0x8888, %%rax\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        "leaq (%%rsi,%%rdx,8), %%r8\n"
        "leaq 0x12345(%%rsi,%%rdx,4), %%r9\n"
        "leaw (%%rsi,%%rdx), %%ax\n"
        "faddl %[c]\n"
        "fstpl %[r]\n"
        "movq %%r8, %[v1]\n"
        "movq %%r9, %[v2]\n"
        "movq %%rax, %[v3]\n"
        : [r] "=m"(r), [v1] "=m"(v1), [v2] "=m"(v2), [v3] "=m"(v3)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), "S"(arena)
        : "rax", "rdx", "r8", "r9", "cc", "memory");
    *sib_out = v1;
    *disp_out = v2;
    *w_out = v3;
    return r;
}

/* ── unary RMW memory forms: neg/not/inc/dec on complex SIB ────────────── */
__attribute__((noinline))
static double gap_unary_rmw(double a, double b, double c, uint64_t *out) {
    double r;
    *SLOT(0) = 100;
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "movq $2, %%rdx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        "negq 0x12345(%%rsi,%%rdx,8)\n"
        "notq 0x12345(%%rsi,%%rdx,8)\n"
        "faddl %[c]\n"
        "incq 0x12345(%%rsi,%%rdx,8)\n"
        "decq 0x12345(%%rsi,%%rdx,8)\n"
        "decq 0x12345(%%rsi,%%rdx,8)\n"
        "fstpl %[r]\n"
        : [r] "=m"(r)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(arena)
        : "rsi", "rdx", "cc", "memory");
    *out = *SLOT(0);
    return r;
}

/* ── ALU m64,imm32 memory-destination forms: add/and/xor/or ────────────── */
__attribute__((noinline))
static double gap_alu_mem_imm(double a, double b, double c, uint64_t *out) {
    double r;
    *SLOT(0) = 0x1000;
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "movq $2, %%rdx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        "addq $0x12345678, 0x12345(%%rsi,%%rdx,8)\n"
        "xorq $0x0F0F0F0F, 0x12345(%%rsi,%%rdx,8)\n"
        "faddl %[c]\n"
        "andq $0x7FFFFFFF, 0x12345(%%rsi,%%rdx,8)\n"
        "orq  $0x100, 0x12345(%%rsi,%%rdx,8)\n"
        "fstpl %[r]\n"
        : [r] "=m"(r)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(arena)
        : "rsi", "rdx", "cc", "memory");
    *out = *SLOT(0);
    return r;
}

/* ── GS-segment mov (TLS read: %gs:0x0 = pthread self on darwin) ────────
 * Rosetta's compute_operand_address takes the GS/TLS fallback path here,
 * which FIXED-allocates pool slot 7 (x29) in addition to mask-scanned
 * temps — the most allocation-hungry addressing form. */
__attribute__((noinline))
static double gap_gs_seg(double a, double b, double c, uint64_t *tls_out) {
    double r;
    uint64_t tls = 0;
    __asm__ volatile(
        "fldl %[a]\n"
        "fmull %[b]\n"
        "movq %%gs:0x0, %%rcx\n"
        "faddl %[c]\n"
        "fstpl %[r]\n"
        "movq %%rcx, %[tls]\n"
        : [r] "=m"(r), [tls] "=&r"(tls)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c)
        : "rcx", "cc");
    *tls_out = tls;
    return r;
}

/* ── RIP-relative RMW: flag ops on a global (pc-relative address temps) ── */
static uint64_t g_rip_slot;
__attribute__((noinline))
static double gap_rip_rmw(double a, double b, double c, uint64_t *out) {
    double r;
    g_rip_slot = 0x1000;
    __asm__ volatile(
        "movq $5, %%rcx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        "cmpq $9, %%rcx\n"
        "adcq $0x12345678, %[gv]\n"
        "faddl %[c]\n"
        "xorq $0x0F0F0F0F, %[gv]\n"
        "fstpl %[r]\n"
        : [r] "=m"(r), [gv] "+m"(g_rip_slot)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c)
        : "rcx", "cc");
    *out = g_rip_slot;
    return r;
}

/* ── 16-bit RMW flag forms on complex SIB (partial-width merge temps) ──── */
__attribute__((noinline))
static double gap_rmw16(double a, double b, double c, uint64_t *out) {
    double r;
    *SLOT(0) = 0xFFFF1111ull;
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "movq $2, %%rdx\n"
        "movq $5, %%rcx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        "cmpq $9, %%rcx\n"
        "adcw $0x1234, 0x12345(%%rsi,%%rdx,8)\n"
        "faddl %[c]\n"
        "rolw %%cl, 0x12345(%%rsi,%%rdx,8)\n"
        "fstpl %[r]\n"
        : [r] "=m"(r)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(arena)
        : "rsi", "rdx", "rcx", "cc", "memory");
    *out = *SLOT(0);
    return r;
}

/* ── LOCK-prefixed RMW: atomics keep their base opcode (add/adc/xor), so
 * the transparent-op check accepts them, but Rosetta lowers them as an
 * ldaxr/stlxr exclusive loop — address + immediate + loaded value + result
 * + store-status live simultaneously: the highest temp demand of any
 * transparent shape. */
__attribute__((noinline))
static double gap_lock_rmw(double a, double b, double c, uint64_t *out) {
    double r;
    *SLOT(0) = 0x1000;
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "movq $2, %%rdx\n"
        "movq $5, %%rcx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        "lock addq $0x12345678, 0x12345(%%rsi,%%rdx,8)\n"
        "faddl %[c]\n"
        "cmpq $9, %%rcx\n"
        "lock adcq $0x1234, 0x12345(%%rsi,%%rdx,8)\n"
        "fstpl %[r]\n"
        : [r] "=m"(r)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(arena)
        : "rsi", "rdx", "rcx", "cc", "memory");
    *out = *SLOT(0);
    return r;
}

/* ── Maximum-pin gap (BRIDGE_CARRY): both x87 run segments use two bases
 * with 2+ foldable accesses each (→ 2 carried base GPRs) plus fistp (→ a
 * carried rounding-control GPR). Across the gap the cache then pins
 * fixed + carried bases + RC GPRs, leaving Rosetta as few as 2-3 temps for
 * the gap instruction — a cmp + lock adc gap (peak demand 4) exhausted the
 * pool and aborted translation before the demand-aware carried release. */
__attribute__((noinline))
static double gap_max_pins(double *arrA, double *arrB,
                           int *is_out /*[4]*/, uint64_t *lock_out) {
    double r;
    int i1 = 0, i2 = 0, i3 = 0, i4 = 0;
    *SLOT(0) = 0x1000;
    __asm__ volatile(
        "movq %[pa], %%rsi\n"
        "movq %[pb], %%rdi\n"
        "movq %[ar], %%r8\n"
        "movq $5, %%r9\n"
        "movq $2, %%rdx\n"
        /* segment 1: SIB bases (scratch ADDs → addr-cache slots) used twice
         * each, plus two fistps (→ RC cache GPR) */
        "fldl (%%rsi,%%rdx,8)\n"
        "faddl 8(%%rsi,%%rdx,8)\n"
        "fistpl %[i1]\n"
        "fldl (%%rdi,%%rdx,8)\n"
        "faddl 8(%%rdi,%%rdx,8)\n"
        "fistpl %[i2]\n"
        /* gap: cmp defines CF, then lock adc m64,imm32 with complex SIB —
         * peak demand 4 temps, the heaviest bridged shape measured */
        "cmpq $9, %%r9\n"
        "lock adcq $0x12345678, 0x12345(%%r8,%%rdx,8)\n"
        /* segment 2: same SIB bases + fistps again (reuse carried pins) */
        "fldl (%%rsi,%%rdx,8)\n"
        "faddl 8(%%rsi,%%rdx,8)\n"
        "fistpl %[i3]\n"
        "fldl (%%rdi,%%rdx,8)\n"
        "faddl 8(%%rdi,%%rdx,8)\n"
        "fistpl %[i4]\n"
        "fldl (%%rsi,%%rdx,8)\n"
        "fstpl %[r]\n"
        : [r] "=m"(r), [i1] "=m"(i1), [i2] "=m"(i2), [i3] "=m"(i3), [i4] "=m"(i4)
        : [pa] "r"(arrA), [pb] "r"(arrB), [ar] "r"(arena)
        : "rsi", "rdi", "rdx", "r8", "r9", "cc", "memory");
    is_out[0] = i1; is_out[1] = i2; is_out[2] = i3; is_out[3] = i4;
    *lock_out = *SLOT(0);
    return r;
}

/* ── Flag-live mul/imul m64 in a maximum-pin gap ───────────────────────────
 * mul m64 and imul r64,m64,imm32 with a complex SIB operand materialize OF/CF
 * via extra movn+csel temps, so their true peak first-free demand is 5 — one
 * over the 5-free post-carried-release floor's usable budget. gap_gpr_demand
 * refuses them (kMaxBridgeDemand+1), so this gap is NOT bridged: the run breaks
 * and Rosetta translates the mul/imul at a run boundary with all 8 scratch
 * GPRs free. Before the demand fix this shape aborted translation with
 * "no temporary GPR available to allocate". The x87 values (two segments,
 * carried pins on the first) and the mul/imul results must still be correct
 * across the (now split) run. */
__attribute__((noinline))
static double gap_mul_flags_maxpin(double *arrA, double *arrB,
                                   int *is_out /*[2]*/,
                                   uint64_t *mul_lo_out, uint64_t *imul_out) {
    double r;
    int i1 = 0, i2 = 0;
    uint64_t mul_lo = 0, im = 0;
    *SLOT(0) = 0x123456789ull;  /* mul target */
    *SLOT(8) = 77;              /* imul target */
    __asm__ volatile(
        "movq %[pa], %%rsi\n"
        "movq %[pb], %%rdi\n"
        "movq %[ar], %%r8\n"
        "movq $2, %%rdx\n"
        /* segment 1: two SIB bases used twice each + fistp (carried pins) */
        "fldl (%%rsi,%%rdx,8)\n"
        "faddl 8(%%rsi,%%rdx,8)\n"
        "fistpl %[i1]\n"
        "fldl (%%rdi,%%rdx,8)\n"
        "faddl 8(%%rdi,%%rdx,8)\n"
        "fistpl %[i2]\n"
        /* gap: flag-live mul m64 (RDX:RAX) then imul r64,m64,imm32 — the
         * demand-5 shapes refused by gap_gpr_demand. mul clobbers RDX with the
         * high product, so restore the SIB index (RDX=2) before imul and
         * segment 2. */
        "movq $7, %%rax\n"
        "mulq 0x12345(%%r8,%%rdx,8)\n"        /* RDX:RAX = 7 * SLOT(0) */
        "movq %%rax, %%rcx\n"                 /* save lo before rax reuse */
        "movq $2, %%rdx\n"                    /* restore SIB index after mul */
        "imulq $0x12345678, 0x1234d(%%r8,%%rdx,8), %%rbx\n"
        /* segment 2: reuse the same SIB bases */
        "fldl (%%rsi,%%rdx,8)\n"
        "fstpl %[r]\n"
        "movq %%rcx, %[mlo]\n"
        "movq %%rbx, %[im]\n"
        : [r] "=m"(r), [i1] "=m"(i1), [i2] "=m"(i2),
          [mlo] "=&r"(mul_lo), [im] "=&r"(im)
        : [pa] "r"(arrA), [pb] "r"(arrB), [ar] "r"(arena)
        : "rsi", "rdi", "rdx", "r8", "rax", "rcx", "rbx", "cc", "memory");
    is_out[0] = i1; is_out[1] = i2;
    *mul_lo_out = mul_lo;
    *imul_out = im;
    return r;
}

int main(void) {
    const double a = 3.0, b = 4.0, c = 2.5;
    const double x87_expected = a * b + c; /* 14.5 */

    {
        uint64_t adc = 0, sbb = 0;
        check("gap_adc_sbb: x87 result", gap_adc_sbb(a, b, c, &adc, &sbb),
              x87_expected);
        check_u64("gap_adc_sbb: adc m64,imm32 (+CF)", adc,
                  1000ull + 0x12345678ull + 1);
        check_u64("gap_adc_sbb: sbb m64,imm32 (-CF)", sbb,
                  5000ull - 0x1234ull - 1);
    }
    {
        uint64_t reg = 0, mem = 0;
        check("gap_xchg_mem: x87 result", gap_xchg_mem(a, b, c, &reg, &mem),
              x87_expected);
        check_u64("gap_xchg_mem: reg got old mem", reg, 0x1111222233334444ull);
        check_u64("gap_xchg_mem: mem got old reg", mem, 0xAABBCCDDull);
    }
    {
        uint64_t shl = 0, sar = 0;
        check("gap_shift_cl: x87 result", gap_shift_cl(a, b, c, &shl, &sar),
              x87_expected);
        check_u64("gap_shift_cl: shl m64,cl", shl, 0x1111ull << 5);
        check_u64("gap_shift_cl: sar m64,cl", sar, (uint64_t)(-4096ll >> 5));
    }
    {
        uint64_t lo = 0, hi = 0, im = 0;
        check("gap_mul_imul: x87 result",
              gap_mul_imul(a, b, c, &lo, &hi, &im), x87_expected);
        check_u64("gap_mul_imul: mul lo", lo, 7ull * 0x123456789ull);
        check_u64("gap_mul_imul: mul hi", hi, 0);
        check_u64("gap_mul_imul: imul r,m,imm32", im, 77ull * 0x12345678ull);
    }
    {
        uint64_t set = 0, cmov = 0;
        check("gap_cmp_setcc_cmov: x87 result",
              gap_cmp_setcc_cmov(a, b, c, &set, &cmov), x87_expected);
        check_u64("gap_cmp_setcc_cmov: setbe m8 (false)", set, 0);
        check_u64("gap_cmp_setcc_cmov: cmova taken", cmov, 0x99999999ull);
    }
    {
        uint64_t fl = 0;
        check("gap_test_shapes: x87 result",
              gap_test_shapes(a, b, c, &fl), x87_expected);
        check_u64("gap_test_shapes: test rr/mi/ri flags", fl, 0x10101ull);
    }
    {
        uint64_t pop = 0;
        check("gap_push_pop_mem: x87 result",
              gap_push_pop_mem(a, b, c, &pop), x87_expected);
        check_u64("gap_push_pop_mem: m64 roundtrip", pop, 0x5566778899AABBCCull);
    }
    {
        uint64_t cvt = 0;
        check("gap_sse_cvt: x87 result", gap_sse_cvt(a, b, c, &cvt),
              x87_expected);
        check_u64("gap_sse_cvt: addsd+cvttsd2si", cvt, 142); /* 100.75+41.5 */
    }
    {
        uint64_t store = 0, zx = 0, nti = 0;
        check("gap_mov_heavy: x87 result",
              gap_mov_heavy(a, b, c, &store, &zx, &nti), x87_expected);
        check_u64("gap_mov_heavy: m64 store", store, 0x1122334455667788ull);
        check_u64("gap_mov_heavy: movzwl from SIB", zx, 0x7788);
        check_u64("gap_mov_heavy: movnti", nti, 0x1122334455667788ull);
    }
    {
        uint64_t rcx = 0, rbx = 0, ld8 = 0, ld1 = 0, ld4 = 0, st = 0;
        uint64_t zxh = 0;
        check("gap_mov_shapes: x87 result",
              gap_mov_shapes(a, b, c, &rcx, &rbx, &ld8, &ld1, &ld4, &st, &zxh),
              x87_expected);
        check_u64("gap_mov_shapes: movzbl ah (high-byte widen)", zxh, 0x77);
        /* rax = 0x1122334455667788: al=0x88, ah=0x77, ax=0x7788 */
        check_u64("gap_mov_shapes: movb al,cl + movb ah,ch", rcx,
                  0xAAAAAAAAAAAA7788ull);
        check_u64("gap_mov_shapes: movw ax,bx", rbx, 0xBBBBBBBBBBBB7788ull);
        /* buf[i] = 0xC0+i, little-endian u64 reads */
        uint64_t e8 = 0, e1 = 0, e4 = 0;
        for (int i = 7; i >= 0; i--) e8 = (e8 << 8) | (0xC0u + 16 + i);
        for (int i = 7; i >= 0; i--) e1 = (e1 << 8) | (0xC0u + 2 + i);
        for (int i = 7; i >= 0; i--) e4 = (e4 << 8) | (0xC0u + 8 + i);
        check_u64("gap_mov_shapes: movq (rsi,rdx,8) lsl3", ld8, e8);
        check_u64("gap_mov_shapes: movq (rsi,rdx) lsl0", ld1, e1);
        check_u64("gap_mov_shapes: movq (rsi,rdx,4) lsl2", ld4, e4);
        check_u64("gap_mov_shapes: movq store (rdi,rdx,8)", st, e8);
    }
    {
        uint64_t rcx = 0, r9 = 0, r10 = 1, rip = 0;
        check("gap_alu_reg_shapes: x87 result",
              gap_alu_reg_shapes(a, b, c, &rcx, &r9, &r10, &rip),
              x87_expected);
        /* rax=0x1122334455667788: ah=0x77, al=0x88.
         * cl: 0xAA + 0x77 = 0x21 (carry out), then 0x21 | 0x88 = 0xA9 */
        check_u64("gap_alu_reg_shapes: addb ah + orb al", rcx,
                  0xAAAAAAAAAAAAAAA9ull);
        check_u64("gap_alu_reg_shapes: subl imm", r9, 99);
        check_u64("gap_alu_reg_shapes: xorl self-zero", r10, 0);
        check_u64("gap_alu_reg_shapes: RIP RMW add (refused, run break)",
                  rip, 1000ull + 0x1122334455667788ull);
    }
    {
        uint64_t sib = 0, disp = 0, w = 0;
        check("gap_lea_shapes: x87 result",
              gap_lea_shapes(a, b, c, &sib, &disp, &w), x87_expected);
        check_u64("gap_lea_shapes: leaq (rsi,rdx,8)", sib,
                  (uint64_t)arena + 16);
        check_u64("gap_lea_shapes: leaq 0x12345(rsi,rdx,4)", disp,
                  (uint64_t)arena + 0x12345 + 8);
        check_u64("gap_lea_shapes: leaw (rsi,rdx),ax", w,
                  (0x8888ull & ~0xFFFFull) |
                      (uint16_t)((uint64_t)arena + 2));
    }
    {
        uint64_t v = 0;
        check("gap_unary_rmw: x87 result", gap_unary_rmw(a, b, c, &v),
              x87_expected);
        /* 100 → neg → -100 → not → 99 → inc → 100 → dec dec → 98 */
        check_u64("gap_unary_rmw: neg/not/inc/dec chain", v, 98);
    }
    {
        uint64_t v = 0;
        check("gap_alu_mem_imm: x87 result", gap_alu_mem_imm(a, b, c, &v),
              x87_expected);
        uint64_t e = 0x1000;
        e += 0x12345678ull;
        e ^= 0x0F0F0F0Full;
        e &= 0x7FFFFFFFull;
        e |= 0x100ull;
        check_u64("gap_alu_mem_imm: add/xor/and/or m64,imm32", v, e);
    }

    {
        uint64_t tls = 0;
        check("gap_gs_seg: x87 result", gap_gs_seg(a, b, c, &tls), x87_expected);
        check_u64("gap_gs_seg: gs:0 nonzero", tls != 0, 1);
    }
    {
        uint64_t v = 0;
        check("gap_rip_rmw: x87 result", gap_rip_rmw(a, b, c, &v), x87_expected);
        uint64_t e = 0x1000;
        e += 0x12345678ull + 1; /* CF=1 from cmp */
        e ^= 0x0F0F0F0Full;
        check_u64("gap_rip_rmw: adc/xor rip-relative", v, e);
    }
    {
        uint64_t v = 0;
        check("gap_rmw16: x87 result", gap_rmw16(a, b, c, &v), x87_expected);
        uint16_t w = 0x1111;
        w = (uint16_t)(w + 0x1234 + 1); /* adcw, CF=1 */
        w = (uint16_t)((w << 5) | (w >> 11)); /* rolw 5 */
        uint64_t e = (0xFFFF1111ull & ~0xFFFFull) | w;
        check_u64("gap_rmw16: adcw/rolw m16", v, e);
    }

    {
        uint64_t v = 0;
        check("gap_lock_rmw: x87 result", gap_lock_rmw(a, b, c, &v),
              x87_expected);
        check_u64("gap_lock_rmw: lock add/adc m64,imm32", v,
                  0x1000ull + 0x12345678ull + 0x1234ull + 1);
    }

    {
        double arrA[4] = {0, 0, 1.25, 2.5};
        double arrB[4] = {0, 0, 10.0, 20.25};
        int is[4] = {0, 0, 0, 0};
        uint64_t lk = 0;
        check("gap_max_pins: final fld", gap_max_pins(arrA, arrB, is, &lk),
              1.25);
        check_u64("gap_max_pins: fistp A seg1", (uint64_t)is[0], 4);  /* 3.75 */
        check_u64("gap_max_pins: fistp B seg1", (uint64_t)is[1], 30); /* 30.25 */
        check_u64("gap_max_pins: fistp A seg2", (uint64_t)is[2], 4);
        check_u64("gap_max_pins: fistp B seg2", (uint64_t)is[3], 30);
        check_u64("gap_max_pins: lock adc in max-pin gap", lk,
                  0x1000ull + 0x12345678ull + 1);
    }

    {
        double arrA[4] = {0, 0, 1.25, 2.5};
        double arrB[4] = {0, 0, 10.0, 20.25};
        int is[2] = {0, 0};
        uint64_t mlo = 0, im = 0;
        check("gap_mul_flags_maxpin: final fld",
              gap_mul_flags_maxpin(arrA, arrB, is, &mlo, &im), 1.25);
        check_u64("gap_mul_flags_maxpin: fistp A seg1", (uint64_t)is[0], 4);
        check_u64("gap_mul_flags_maxpin: fistp B seg1", (uint64_t)is[1], 30);
        check_u64("gap_mul_flags_maxpin: mul m64 lo", mlo, 7ull * 0x123456789ull);
        check_u64("gap_mul_flags_maxpin: imul r,m,imm32", im, 77ull * 0x12345678ull);
    }

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
