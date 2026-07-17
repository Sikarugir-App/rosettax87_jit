/*
 * test_run_breaks.c — Fixture for item 01 Phase-0 run-break telemetry
 *                     (ROSETTA_X87_LOG_RUN_BREAKS).
 *
 * Each function is an x87 sequence deliberately split by a non-x87 integer
 * instruction (mov / lea), so that under ROSETTA_X87_LOG_RUN_BREAKS=1 the
 * loader emits "X87 run-break" telemetry lines. Phase 0 changes no codegen, so
 * these tests double as a regression guard: values AND store addresses must be
 * identical to the un-split baseline (i.e. the interleaved mov must not corrupt
 * the x87 result). Run with the env flag set to eyeball the log output.
 *
 * Cases:
 *   (a) mov to an unrelated register between two x87 ops
 *   (b) mov to a register used as the BASE of a later x87 memory operand
 *   (c) lea updating a register used as an earlier x87 base
 *   (d) mov eax colliding with the FSTSW-AX register
 *
 * Build: clang -arch x86_64 -O0 -g -o test_run_breaks test_run_breaks.c
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int failures = 0;
static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

static void check(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-55s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_long(const char *name, long got, long expected) {
    if (got != expected) {
        printf("FAIL  %-55s  got=%ld  expected=%ld\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* (a) fld / fmul / mov <unrelated reg> / fstp — the canonical split.
 *     ecx is not used by any x87 operand, so the result must be unaffected. */
static double split_mov_unrelated(double a, double b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"            /* ST(0) = a */
        "fmull %2\n"           /* ST(0) = a*b */
        "movl $12345, %%ecx\n" /* breaks the run; unrelated to x87 state */
        "fstpl %0\n"           /* store a*b */
        : "=m"(r)
        : "m"(a), "m"(b)
        : "ecx");
    return r;
}

/* (b) mov sets a register THEN used as base of a later x87 load.
 *     The x87 operand after the mov must observe the new register value. */
static double split_mov_writes_later_base(double a, double val_at_ptr) {
    double storage = val_at_ptr;
    double r;
    __asm__ volatile(
        "fldl %1\n"            /* ST(0) = a */
        "movq %3, %%rdx\n"     /* rdx = &storage; breaks the run */
        "faddl (%%rdx)\n"      /* ST(0) = a + storage — must use new rdx */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(a), "m"(storage), "r"(&storage)
        : "rdx");
    return r;
}

/* (c) lea recomputing a register used as an earlier x87 base, between two
 *     x87 accesses through it. */
static double split_lea_updates_base(double first, double second) {
    double buf[2];
    buf[0] = first;
    buf[1] = second;
    double r;
    __asm__ volatile(
        "movq %3, %%rsi\n"     /* rsi = &buf[0] */
        "fldl (%%rsi)\n"       /* ST(0) = buf[0] = first */
        "leaq 8(%%rsi), %%rsi\n" /* rsi = &buf[1]; breaks the run */
        "faddl (%%rsi)\n"      /* ST(0) = first + buf[1] */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(buf[0]), "m"(buf[1]), "r"(&buf[0])
        : "rsi");
    return r;
}

/* (d) mov eax between x87 ops, colliding with the FSTSW-AX register.
 *     eax is clobbered by our mov but the x87 compare/result must be intact. */
static double split_mov_eax(double a, double b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"            /* ST(0) = a */
        "fmull %2\n"           /* ST(0) = a*b */
        "movl $0, %%eax\n"     /* breaks run; touches AX (FSTSW dest reg) */
        "fstpl %0\n"           /* store a*b */
        : "=m"(r)
        : "m"(a), "m"(b)
        : "eax");
    return r;
}

/* (e) mov with a complex effective address (base+index*8+disp) between x87
 *     ops. Rosetta's translation of this mov needs an address-computation
 *     scratch register — the probe for whether Rosetta allocates honestly
 *     from free_gpr_mask: under ROSETTA_X87_RUN_BRIDGE=1 it must not clobber
 *     the pinned cache GPRs (base/TOP/st_base), or the fstp result and the
 *     loaded value go wrong. */
static double split_mov_complex_ea(double a, double b, double *picked_out) {
    double arr[4] = {0.0, 1.0, 2.0, 3.0};
    long idx = 2;
    double r;
    __asm__ volatile(
        "fldl %2\n"                /* ST(0) = a */
        "movq 8(%3,%4,8), %%rcx\n" /* rcx = bits of arr[idx+1]; complex EA */
        "fmull %5\n"               /* ST(0) = a*b */
        "fstpl %1\n"
        "movq %%rcx, %0\n"
        : "=m"(*picked_out), "=m"(r)
        : "m"(a), "r"(arr), "r"(idx), "m"(b)
        : "rcx");
    return r;
}

/* (f) SSE movsd between x87 ops — the dominant run breaker in mixed x87/SSE
 *     code (whitelist v2). Both the x87 result and the SSE-copied value must
 *     be intact. */
static double split_movsd_sse(double a, double b, double *sse_out) {
    double sse_src = 99.5;
    double r;
    __asm__ volatile(
        "fldl %2\n"              /* ST(0) = a */
        "movsd %3, %%xmm1\n"     /* SSE load — bridged under whitelist v2 */
        "fmull %4\n"             /* ST(0) = a*b */
        "movsd %%xmm1, %1\n"     /* SSE store — also bridged */
        "fstpl %0\n"
        : "=m"(r), "=m"(*sse_out)
        : "m"(a), "m"(sse_src), "m"(b)
        : "xmm1");
    return r;
}

/* (g) integer ALU (add/inc — flag definers) between x87 ops. */
static double split_alu(double a, double b, long *ctr_out) {
    long ctr = 5;
    double r;
    __asm__ volatile(
        "fldl %2\n"
        "addq $10, %1\n"         /* flag-defining ALU — bridged */
        "fmull %3\n"
        "incq %1\n"              /* bridged */
        "fstpl %0\n"
        : "=m"(r), "+r"(ctr)
        : "m"(a), "m"(b)
        : "cc");
    *ctr_out = ctr; /* 5 + 10 + 1 = 16 */
    return r;
}

/* (h) push/pop pair between x87 ops (guest RSP traffic mid-run). */
static double split_push_pop(double a, double b, long *rt_out) {
    double r;
    __asm__ volatile(
        "fldl %2\n"
        "pushq $42\n"            /* bridged */
        "fmull %3\n"
        "popq %%rcx\n"           /* bridged */
        "fstpl %0\n"
        "movq %%rcx, %1\n"
        : "=m"(r), "=m"(*rt_out)
        : "m"(a), "m"(b)
        : "rcx");
    return r;
}

/* (i) setcc between x87 ops, reading flags from a cmp BEFORE the run, with
 *     an fcomp in between — the x87 compare must save/restore guest NZCV so
 *     the bridged setcc still sees the cmp's flags (and the nzcv-dead elision
 *     must stay off: setcc is a reader). */
static double split_setcc_after_fcomp(double a, double b, long *flag_out) {
    unsigned char sc = 0;
    double r;
    __asm__ volatile(
        "cmpq $7, %3\n"          /* guest flags: 8 > 7 → above */
        "fldl %2\n"
        "fldl %4\n"
        "fcomp %%st(1)\n"        /* x87 compare — must not destroy guest NZCV */
        "seta %1\n"              /* bridged; must read the cmp's flags */
        "fmull %4\n"             /* ST(0) = a*b */
        "fstpl %0\n"
        : "=m"(r), "=m"(sc)
        : "m"(a), "r"(8L), "m"(b)
        : "cc");
    *flag_out = sc;
    return r;
}

/* (j) shift (internal-branch translation path) between x87 ops. */
static double split_shift(double a, double b, long *sh_out) {
    long v = 3;
    double r;
    __asm__ volatile(
        "fldl %2\n"
        "shlq $4, %1\n"          /* bridged; translation patches an internal branch */
        "fmull %3\n"
        "fstpl %0\n"
        : "=m"(r), "+r"(v)
        : "m"(a), "m"(b)
        : "cc");
    *sh_out = v; /* 3 << 4 = 48 */
    return r;
}

/* ─────────────────────────────────────────────────────────────────────────
 * Whitelist-v2 coverage: one fixture per opcode group in the audit-eligible
 * set (research/bridge_demand/families.py TRANSPARENT; the former
 * X87Cache::is_transparent). Gaps are kept ≤ kMaxBridgeGap (4) so the bridge
 * actually engages — x87 anchors (fld/fadd/fmul/fstp) every few instructions.
 * NOT coverable from a 64-bit fixture: pushd/popd (32-bit-mode encodings).
 * ───────────────────────────────────────────────────────────────────────── */

/* (k) mov-family: movzx / movsx / movsxd / movnti / nop. */
static double split_mov_ext(double a, double b, long *zx, long *sx, long *sxd, int *nti) {
    unsigned short u16 = 0xFFEE;
    int i32 = -7;
    long z = 0, s = 0, d = 0;
    double r;
    __asm__ volatile(
        "fldl %5\n"
        "movzwq %7, %0\n"        /* z = 0xFFEE (zero-extend) */
        "movswq %7, %1\n"        /* s = -18   (sign-extend) */
        "nop\n"
        "fmull %6\n"
        "movslq %8, %2\n"        /* d = -7    (movsxd) */
        "movl $77, %%ecx\n"
        "movnti %%ecx, %3\n"     /* non-temporal store */
        "fstpl %4\n"
        : "=&r"(z), "=&r"(s), "=&r"(d), "=m"(*nti), "=m"(r)
        : "m"(a), "m"(b), "m"(u16), "m"(i32)
        : "ecx");
    *zx = z; *sx = s; *sxd = d;
    return r;
}

/* (l) ALU chain: sub / and / or / xor / dec / neg / not / cmp / cmovcc. */
static double split_alu_chain(double a, double b, double c, long *v_out) {
    long v = 100;
    double r;
    __asm__ volatile(
        "fldl %2\n"
        "subq $20, %1\n"          /* 80 */
        "andq $0xF0, %1\n"        /* 80 */
        "orq $5, %1\n"            /* 85 */
        "faddl %3\n"
        "xorq $0xFF, %1\n"        /* 170 */
        "decq %1\n"               /* 169 */
        "negq %1\n"               /* -169 */
        "fmull %4\n"
        "notq %1\n"               /* 168 */
        "movq $555, %%rcx\n"
        "cmpq $200, %1\n"         /* 168 < 200 → CF=1 (below) */
        "cmovbq %%rcx, %1\n"      /* v = 555 */
        "fstpl %0\n"
        : "=m"(r), "+r"(v)
        : "m"(a), "m"(b), "m"(c)
        : "rcx", "cc");
    *v_out = v;
    return r;
}

/* (m) carry + multiply: cmp / adc / sbb / imul / bswap / mul. */
static double split_carry_mul(double a, double b, long *v_out, long *mul_out) {
    long v = 10;
    long mr = 0;
    double r;
    __asm__ volatile(
        "fldl %3\n"
        "cmpq $20, %1\n"          /* 10 - 20 borrows → CF=1 */
        "adcq $5, %1\n"           /* 10 + 5 + 1 = 16 */
        "sbbq $2, %1\n"           /* CF=0 after adc → 14 */
        "faddl %4\n"
        "imulq $3, %1, %1\n"      /* 42 */
        "bswapq %1\n"
        "bswapq %1\n"             /* byte-swap round-trip = identity */
        "fmull %4\n"
        "movq $7, %%rcx\n"
        "movq $6, %%rax\n"
        "mulq %%rcx\n"            /* rax = 42, rdx = 0 */
        "movq %%rax, %2\n"
        "fstpl %0\n"
        : "=m"(r), "+r"(v), "=&r"(mr)
        : "m"(a), "m"(b)
        : "rax", "rdx", "rcx", "cc");
    *v_out = v; *mul_out = mr;
    return r;
}

/* (o) sign-extension family: cbw / cwd / cwde / cdqe / cdq (rax/rdx chain). */
static double split_signext(double a, double b, long *rax_out, long *rdx_out) {
    long ra = 0, rd = 0;
    double r;
    __asm__ volatile(
        "fldl %3\n"
        "movq $0x80, %%rax\n"     /* al = 0x80 (-128) */
        "cbw\n"                   /* ax  = 0xFF80 */
        "cwd\n"                   /* dx  = 0xFFFF */
        "fmull %4\n"
        "cwde\n"                  /* eax = 0xFFFFFF80 */
        "cdqe\n"                  /* rax = -128 */
        "cdq\n"                   /* edx = 0xFFFFFFFF → rdx = 0xFFFFFFFF */
        "fstpl %0\n"
        "movq %%rax, %1\n"
        "movq %%rdx, %2\n"
        : "=m"(r), "=&r"(ra), "=&r"(rd)
        : "m"(a), "m"(b)
        : "rax", "rdx", "cc");
    *rax_out = ra; *rdx_out = rd;
    return r;
}

/* (p) remaining shifts/rotates: shr / sar / rol / ror. */
static double split_shift_rot(double a, double b, long *v_out) {
    long v = 256;
    double r;
    __asm__ volatile(
        "fldl %2\n"
        "shrq $2, %1\n"           /* 64 */
        "sarq $2, %1\n"           /* 16 */
        "fmull %3\n"
        "rolq $4, %1\n"           /* 256 */
        "rorq $4, %1\n"           /* 16 */
        "fstpl %0\n"
        : "=m"(r), "+r"(v)
        : "m"(a), "m"(b)
        : "cc");
    *v_out = v;
    return r;
}

/* (q) xchg: reg-reg and (implicitly locked) reg-mem forms. */
static double split_xchg(double a, double b, long *reg_out, long *mem_out) {
    long mem = 33;
    long rc = 0;
    double r;
    __asm__ volatile(
        "fldl %3\n"
        "movq $11, %%rcx\n"
        "movq $22, %%rdx\n"
        "xchgq %%rdx, %%rcx\n"    /* rcx = 22, rdx = 11 */
        "fmull %4\n"
        "xchgq %%rcx, %2\n"       /* locked form: rcx = 33, mem = 22 */
        "movq %%rcx, %1\n"
        "fstpl %0\n"
        : "=m"(r), "=&r"(rc), "+m"(mem)
        : "m"(a), "m"(b)
        : "rcx", "rdx");
    *reg_out = rc; *mem_out = mem;
    return r;
}

/* (r) SSE copy chain: movss / movaps / movups / movdqa / movdqu. */
static float split_sse_copy_chain(double a, double b, double *x87_out) {
    float f = 3.25f;
    float out = 0.0f;
    double r;
    __asm__ volatile(
        "fldl %2\n"
        "movss %4, %%xmm1\n"
        "movaps %%xmm1, %%xmm2\n"
        "movups %%xmm2, %%xmm3\n"
        "fmull %3\n"
        "movdqa %%xmm3, %%xmm4\n"
        "movdqu %%xmm4, %%xmm5\n"
        "movss %%xmm5, %1\n"
        "fstpl %0\n"
        : "=m"(r), "=m"(out)
        : "m"(a), "m"(b), "m"(f)
        : "xmm1", "xmm2", "xmm3", "xmm4", "xmm5");
    *x87_out = r;
    return out;
}

/* (s) SSE pd/zeroing family: movapd / movupd / xorps / xorpd / pxor. */
static double split_sse_pd_zero(double a, double b, double *copy_out, double *zero_out) {
    double d = 12.75;
    double cp = 0.0, z = 5.0;
    double r;
    __asm__ volatile(
        "fldl %3\n"
        "movsd %5, %%xmm1\n"
        "movapd %%xmm1, %%xmm2\n"
        "movupd %%xmm2, %%xmm3\n"
        "fmull %4\n"
        "xorps %%xmm4, %%xmm4\n"
        "xorpd %%xmm5, %%xmm5\n"
        "pxor %%xmm6, %%xmm6\n"
        "movsd %%xmm3, %1\n"
        "fstpl %0\n"
        "movsd %%xmm5, %2\n"
        : "=m"(r), "=m"(cp), "=m"(z)
        : "m"(a), "m"(b), "m"(d)
        : "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6");
    *copy_out = cp; *zero_out = z;
    return r;
}

/* (t) SSE movd / movq (GPR↔XMM both directions). */
static double split_sse_movd_movq(double a, double b, long *q_out, long *d_out) {
    long src = 0x1122334455667788L;
    long q = 0, dd = 0;
    double r;
    __asm__ volatile(
        "fldl %3\n"
        "movq %5, %%xmm1\n"       /* mem64 → xmm */
        "movq %%xmm1, %1\n"       /* xmm → r64 */
        "fmull %4\n"
        "movd %k1, %%xmm2\n"      /* r32 → xmm */
        "movd %%xmm2, %k2\n"      /* xmm → r32 (zero-extends) */
        "fstpl %0\n"
        : "=m"(r), "=&r"(q), "=&r"(dd)
        : "m"(a), "m"(b), "m"(src)
        : "xmm1", "xmm2");
    *q_out = q; *d_out = dd;
    return r;
}

/* (u) SSE f32 scalar arithmetic: addss / mulss / subss / divss. */
static float split_sse_f32_arith(double a, double b, double *x87_out) {
    float v8 = 8.0f, c2 = 2.0f, c3 = 3.0f, c5 = 5.0f;
    float out = 0.0f;
    double r;
    __asm__ volatile(
        "fldl %2\n"
        "movss %4, %%xmm1\n"
        "addss %5, %%xmm1\n"      /* 10 */
        "mulss %6, %%xmm1\n"      /* 30 */
        "fmull %3\n"
        "subss %7, %%xmm1\n"      /* 25 */
        "divss %7, %%xmm1\n"      /* 5 */
        "movss %%xmm1, %1\n"
        "fstpl %0\n"
        : "=m"(r), "=m"(out)
        : "m"(a), "m"(b), "m"(v8), "m"(c2), "m"(c3), "m"(c5)
        : "xmm1");
    *x87_out = r;
    return out;
}

/* (v) SSE f64 scalar arithmetic: addsd / mulsd / subsd / divsd. */
static double split_sse_f64_arith(double a, double b, double *x87_out) {
    double v9 = 9.0, c3 = 3.0, c2 = 2.0, c4 = 4.0, c5 = 5.0;
    double out = 0.0;
    double r;
    __asm__ volatile(
        "fldl %2\n"
        "movsd %4, %%xmm1\n"
        "addsd %5, %%xmm1\n"      /* 12 */
        "mulsd %6, %%xmm1\n"      /* 24 */
        "fmull %3\n"
        "subsd %7, %%xmm1\n"      /* 20 */
        "divsd %8, %%xmm1\n"      /* 4 */
        "movsd %%xmm1, %1\n"
        "fstpl %0\n"
        : "=m"(r), "=m"(out)
        : "m"(a), "m"(b), "m"(v9), "m"(c3), "m"(c2), "m"(c4), "m"(c5)
        : "xmm1");
    *x87_out = r;
    return out;
}

/* (w) SSE conversions: cvtsi2ss / cvtss2sd / cvttsd2si / cvtsi2sd /
 *     cvtsd2ss / cvttss2si / cvtsd2si / cvtss2si. */
static double split_sse_cvt(double a, double b, int *tt_sd, int *tt_ss, int *r_sd, int *r_ss) {
    int i7 = 7, i9 = 9;
    int o0 = 0, o1 = 0, o2 = 0, o3 = 0;
    double r;
    __asm__ volatile(
        "fldl %5\n"
        "cvtsi2ssl %7, %%xmm1\n"   /* 7.0f */
        "cvtss2sd %%xmm1, %%xmm2\n"/* 7.0  */
        "cvttsd2si %%xmm2, %0\n"   /* 7 (truncating) */
        "faddl %6\n"
        "cvtsi2sdl %8, %%xmm3\n"   /* 9.0 */
        "cvtsd2ss %%xmm3, %%xmm4\n"/* 9.0f */
        "cvttss2si %%xmm4, %1\n"   /* 9 (truncating) */
        "fmull %6\n"
        "cvtsd2si %%xmm3, %2\n"    /* 9 (rounding) */
        "cvtss2si %%xmm4, %3\n"    /* 9 (rounding) */
        "fstpl %4\n"
        : "=&r"(o0), "=&r"(o1), "=&r"(o2), "=&r"(o3), "=m"(r)
        : "m"(a), "m"(b), "m"(i7), "m"(i9)
        : "xmm1", "xmm2", "xmm3", "xmm4");
    *tt_sd = o0; *tt_ss = o1; *r_sd = o2; *r_ss = o3;
    return r;
}

/* (x) SSE flag-writing compares: ucomiss / comiss / ucomisd / comisd,
 *     each consumed by a bridged setcc. */
static double split_sse_comis(double a, double b, long *f1, long *f2, long *f3, long *f4) {
    float x3 = 3.0f, x2 = 2.0f;
    double d1 = 1.5, d9 = 9.5;
    unsigned char c1 = 0, c2v = 0, c3v = 0, c4v = 0;
    double r;
    __asm__ volatile(
        "fldl %5\n"
        "movss %7, %%xmm1\n"
        "ucomiss %8, %%xmm1\n"    /* 3 vs 2 → above */
        "seta %1\n"
        "faddl %6\n"
        "comiss %8, %%xmm1\n"
        "seta %2\n"
        "movsd %9, %%xmm2\n"
        "fmull %6\n"
        "ucomisd %10, %%xmm2\n"   /* 1.5 vs 9.5 → below */
        "setb %3\n"
        "comisd %10, %%xmm2\n"
        "setb %4\n"
        "fstpl %0\n"
        : "=m"(r), "=m"(c1), "=m"(c2v), "=m"(c3v), "=m"(c4v)
        : "m"(a), "m"(b), "m"(x3), "m"(x2), "m"(d1), "m"(d9)
        : "cc", "xmm1", "xmm2");
    *f1 = c1; *f2 = c2v; *f3 = c3v; *f4 = c4v;
    return r;
}

int main(void) {
    check("split_mov_unrelated: a*b intact across mov ecx",
          split_mov_unrelated(3.0, 4.0), 12.0);

    check("split_mov_writes_later_base: fadd uses new base",
          split_mov_writes_later_base(10.0, 2.5), 12.5);

    check("split_lea_updates_base: fadd uses lea'd base",
          split_lea_updates_base(1.5, 6.0), 7.5);

    check("split_mov_eax: a*b intact across mov eax",
          split_mov_eax(2.0, 8.0), 16.0);

    {
        double picked = 0.0;
        check("split_mov_complex_ea: a*b intact across complex-EA mov",
              split_mov_complex_ea(3.0, 7.0, &picked), 21.0);
        check("split_mov_complex_ea: complex-EA mov loaded arr[3]",
              picked, 3.0);
    }

    {
        double sse = 0.0;
        check("split_movsd_sse: a*b intact across SSE movsd",
              split_movsd_sse(3.5, 2.0, &sse), 7.0);
        check("split_movsd_sse: SSE round-trip value",
              sse, 99.5);
    }

    {
        long ctr = 0;
        check("split_alu: a*b intact across add/inc",
              split_alu(6.0, 7.0, &ctr), 42.0);
        if (ctr != 16) { printf("FAIL  split_alu: ctr=%ld expected 16\n", ctr); failures++; }
        else           { printf("PASS  split_alu: ctr==16\n"); }
    }

    {
        long rt = 0;
        check("split_push_pop: a*b intact across push/pop",
              split_push_pop(2.5, 4.0, &rt), 10.0);
        if (rt != 42) { printf("FAIL  split_push_pop: popped=%ld expected 42\n", rt); failures++; }
        else          { printf("PASS  split_push_pop: popped==42\n"); }
    }

    {
        long flag = -1;
        check("split_setcc_after_fcomp: a*b intact",
              split_setcc_after_fcomp(3.0, 5.0, &flag), 15.0);
        if (flag != 1) { printf("FAIL  split_setcc_after_fcomp: seta=%ld expected 1 (cmp flags survived fcomp)\n", flag); failures++; }
        else           { printf("PASS  split_setcc_after_fcomp: seta==1\n"); }
    }

    {
        long sh = 0;
        check("split_shift: a*b intact across shl",
              split_shift(1.5, 8.0, &sh), 12.0);
        if (sh != 48) { printf("FAIL  split_shift: v=%ld expected 48\n", sh); failures++; }
        else          { printf("PASS  split_shift: v==48\n"); }
    }

    {
        long zx = 0, sx = 0, sxd = 0;
        int nti = 0;
        check("split_mov_ext: a*b intact", split_mov_ext(3.0, 4.0, &zx, &sx, &sxd, &nti), 12.0);
        check_long("split_mov_ext: movzx", zx, 0xFFEE);
        check_long("split_mov_ext: movsx", sx, -18);
        check_long("split_mov_ext: movsxd", sxd, -7);
        check_long("split_mov_ext: movnti", nti, 77);
    }

    {
        long v = 0;
        check("split_alu_chain: (a+b)*c intact", split_alu_chain(2.0, 3.0, 4.0, &v), 20.0);
        check_long("split_alu_chain: sub/and/or/xor/dec/neg/not/cmov", v, 555);
    }

    {
        long v = 0, mr = 0;
        check("split_carry_mul: (a+b)*b intact", split_carry_mul(1.0, 2.0, &v, &mr), 6.0);
        check_long("split_carry_mul: cmp/adc/sbb/imul/bswap", v, 42);
        check_long("split_carry_mul: mul", mr, 42);
    }

    {
        long ra = 0, rd = 0;
        check("split_signext: a*b intact", split_signext(2.0, 4.5, &ra, &rd), 9.0);
        check_long("split_signext: cbw/cwde/cdqe", ra, -128);
        check_long("split_signext: cdq", rd, 0xFFFFFFFFL);
    }

    {
        long v = 0;
        check("split_shift_rot: a*b intact", split_shift_rot(5.0, 2.0, &v), 10.0);
        check_long("split_shift_rot: shr/sar/rol/ror", v, 16);
    }

    {
        long rc = 0, mem = 0;
        check("split_xchg: a*b intact", split_xchg(3.0, 3.0, &rc, &mem), 9.0);
        check_long("split_xchg: reg after locked xchg", rc, 33);
        check_long("split_xchg: mem after locked xchg", mem, 22);
    }

    {
        double x87 = 0.0;
        float out = split_sse_copy_chain(2.0, 8.0, &x87);
        check("split_sse_copy_chain: a*b intact", x87, 16.0);
        check("split_sse_copy_chain: movss/aps/ups/dqa/dqu round-trip", (double)out, 3.25);
    }

    {
        double cp = 0.0, z = 5.0;
        check("split_sse_pd_zero: a*b intact", split_sse_pd_zero(4.0, 2.5, &cp, &z), 10.0);
        check("split_sse_pd_zero: movapd/movupd copy", cp, 12.75);
        check("split_sse_pd_zero: xorpd zeroed", z, 0.0);
    }

    {
        long q = 0, dd = 0;
        check("split_sse_movd_movq: a*b intact", split_sse_movd_movq(6.0, 2.0, &q, &dd), 12.0);
        check_long("split_sse_movd_movq: movq round-trip", q, 0x1122334455667788L);
        check_long("split_sse_movd_movq: movd round-trip", dd, 0x55667788L);
    }

    {
        double x87 = 0.0;
        float out = split_sse_f32_arith(3.0, 7.0, &x87);
        check("split_sse_f32_arith: a*b intact", x87, 21.0);
        check("split_sse_f32_arith: addss/mulss/subss/divss", (double)out, 5.0);
    }

    {
        double x87 = 0.0;
        double out = split_sse_f64_arith(1.5, 4.0, &x87);
        check("split_sse_f64_arith: a*b intact", x87, 6.0);
        check("split_sse_f64_arith: addsd/mulsd/subsd/divsd", out, 4.0);
    }

    {
        int t1 = 0, t2 = 0, r1 = 0, r2 = 0;
        check("split_sse_cvt: (a+b)*b intact", split_sse_cvt(1.0, 2.0, &t1, &t2, &r1, &r2), 6.0);
        check_long("split_sse_cvt: cvtsi2ss/cvtss2sd/cvttsd2si", t1, 7);
        check_long("split_sse_cvt: cvtsi2sd/cvtsd2ss/cvttss2si", t2, 9);
        check_long("split_sse_cvt: cvtsd2si", r1, 9);
        check_long("split_sse_cvt: cvtss2si", r2, 9);
    }

    {
        long f1 = 0, f2 = 0, f3 = 0, f4 = 0;
        check("split_sse_comis: (a+b)*b intact",
              split_sse_comis(1.0, 3.0, &f1, &f2, &f3, &f4), 12.0);
        check_long("split_sse_comis: ucomiss+seta", f1, 1);
        check_long("split_sse_comis: comiss+seta", f2, 1);
        check_long("split_sse_comis: ucomisd+setb", f3, 1);
        check_long("split_sse_comis: comisd+setb", f4, 1);
    }

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
