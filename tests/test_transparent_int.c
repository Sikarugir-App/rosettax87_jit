/*
 * test_transparent_int.c — Fixtures for ROSETTA_X87_TRANSPARENT_INT (inlined
 * guest integer instructions inside IR runs).
 *
 * With the flag set, mov r,r / mov r32,imm / lea / movzx / movsx / movsxd /
 * nop are consumed by X87IR::build as Guest* nodes instead of splitting the
 * run — SSA values stay in FPRs across them and one Context (mem-CSE, const
 * dedup, base-address cache) spans the former gap. These fixtures target the
 * correctness obligations specific to inlining (test_run_breaks covers the
 * plain bridge):
 *
 *   (a) inlined mov r32,imm chain — values visible after the run, incl.
 *       negative imm zero-extension
 *   (b) inlined mov rewriting the BASE of a later fstp — store address
 *       must use the new register value
 *   (c) mem-CSE eviction: load / base-rewrite / load of the SAME operand
 *       text — second load must not reuse the first value
 *   (d) store-forwarding eviction: fstp (%r) / base-rewrite / fld (%r) —
 *       must reload, not forward the stored value
 *   (e) base-address-cache exclusion: >=2 foldable accesses through a base
 *       that an inlined mov rewrites mid-run
 *   (f) FSTSW AX then inlined mov reading AX — program order must hold
 *   (g) lea forms: 3-term with large disp (transient-GPR path), negative
 *       disp, 32-bit dst truncation
 *   (h) movzx/movsx register forms incl. an AH (high-byte) source
 *   (i) deep-stack x87 with interleaved guest movs (pressure model)
 *
 * All fixtures must produce identical results with the flag off (bridged or
 * split runs), so the same binary doubles as the A/B regression guard.
 *
 * Build: clang -arch x86_64 -O0 -g -o test_transparent_int test_transparent_int.c
 */
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int failures = 0;

/* Fault guard (pattern from test_decoder_arpl): a broken translation of an
 * inlined mov/lea corrupts an address and faults — recover, report FAIL, and
 * keep running the remaining fixtures instead of wedging the harness. */
static sigjmp_buf g_fault_env;

static void on_fault(int sig) { siglongjmp(g_fault_env, sig); }

static void install_fault_guard(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_fault;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}

/* Run the block with fault recovery; a fault counts as one failure.
 * Variadic so commas inside the block don't split macro arguments. */
#define GUARDED(name, ...)                                            \
    do {                                                              \
        int _sig = sigsetjmp(g_fault_env, 1);                         \
        if (_sig) {                                                   \
            printf("FAIL  %s: fault (signal %d)\n", name, _sig);      \
            failures++;                                               \
        } else                                                        \
            __VA_ARGS__                                               \
    } while (0)
static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

static void check(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-58s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_long(const char *name, long got, long expected) {
    if (got != expected) {
        printf("FAIL  %-58s  got=%ld  expected=%ld\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* (a) mov r32,imm chain inside a run; negative imm must zero-extend into the
 *     64-bit register (W-write semantics). */
static double inline_mov_imm_chain(double a, double b, long *pos_out, long *neg_out) {
    long p = 0, n = 0;
    double r;
    __asm__ volatile(
        "fldl %3\n"
        "movl $123456, %%ecx\n"       /* inlined GuestMovRI */
        "fmull %4\n"
        "movl $-5, %%edx\n"           /* negative imm: rdx = 0xFFFFFFFB */
        "fstpl %0\n"
        "movq %%rcx, %1\n"
        "movq %%rdx, %2\n"
        : "=m"(r), "=&r"(p), "=&r"(n)
        : "m"(a), "m"(b)
        : "rcx", "rdx");
    *pos_out = p; *neg_out = n;
    return r;
}

/* (b) inlined mov rewrites the base register of a LATER fstp — the store
 *     must land at the new address, not the run-entry value of the base. */
static double inline_mov_store_base(double a, double b) {
    double sink1 = 0.0, sink2 = 0.0;
    __asm__ volatile(
        "movq %2, %%rdx\n"     /* rdx = &sink1 (before the run) */
        "fldl %3\n"
        "fmull %4\n"
        "movq %5, %%rdx\n"     /* inlined: rdx = &sink2 */
        "fstpl (%%rdx)\n"      /* must store to sink2 */
        : "+m"(sink1), "+m"(sink2)
        : "r"(&sink1), "m"(a), "m"(b), "r"(&sink2)
        : "rdx");
    /* a*b must be in sink2; sink1 untouched. */
    if (as_u64(sink1) != as_u64(0.0)) {
        printf("FAIL  inline_mov_store_base: sink1 clobbered (%g)\n", sink1);
        failures++;
    } else {
        printf("PASS  inline_mov_store_base: sink1 untouched\n");
    }
    return sink2;
}

/* (c) mem-CSE eviction: two loads of the same operand text around an inlined
 *     base rewrite — the second load must read the NEW location. */
static double inline_cse_evict_load(double v1, double v2) {
    double slot1 = v1, slot2 = v2;
    double r;
    __asm__ volatile(
        "movq %1, %%rsi\n"
        "fldl (%%rsi)\n"       /* ST(0) = slot1; CSE caches (%rsi) */
        "movq %2, %%rsi\n"     /* inlined: rsi = &slot2 — must evict */
        "faddl (%%rsi)\n"      /* + slot2, same operand text */
        "fstpl %0\n"
        : "=m"(r)
        : "r"(&slot1), "r"(&slot2), "m"(slot1), "m"(slot2)
        : "rsi");
    return r;
}

/* (d) store-forwarding eviction: fstp through a base, rewrite the base,
 *     fld the same operand text — must reload from the new address, not
 *     forward the stored value. */
static double inline_cse_evict_store_fwd(double a, double preset) {
    double dst1 = 0.0, dst2 = preset;
    double r;
    __asm__ volatile(
        "movq %3, %%rdx\n"
        "fldl %5\n"
        "fstpl (%%rdx)\n"      /* dst1 = a; forwards a for (%rdx) */
        "movq %4, %%rdx\n"     /* inlined: rdx = &dst2 — must evict */
        "fldl (%%rdx)\n"       /* must load dst2 = preset, NOT a */
        "fstpl %0\n"
        : "=m"(r), "+m"(dst1), "+m"(dst2)
        : "r"(&dst1), "r"(&dst2), "m"(a)
        : "rdx");
    return r;
}

/* (e) base-address cache: four foldable f64 accesses through rsi, with an
 *     inlined mov rewriting rsi in the middle. Without the written-reg
 *     exclusion the cached base would serve the post-write accesses. */
static double inline_base_cache_rewrite(void) {
    double arrA[2] = {1.0, 2.0};
    double arrB[2] = {10.0, 20.0};
    double r;
    __asm__ volatile(
        "movq %1, %%rsi\n"
        "fldl (%%rsi)\n"        /* 1.0 */
        "faddl 8(%%rsi)\n"      /* +2.0 */
        "movq %2, %%rsi\n"      /* inlined: rsi = arrB */
        "faddl (%%rsi)\n"       /* +10.0 — must use arrB */
        "faddl 8(%%rsi)\n"      /* +20.0 */
        "fstpl %0\n"
        : "=m"(r)
        : "r"(arrA), "r"(arrB), "m"(arrA[0]), "m"(arrA[1]), "m"(arrB[0]), "m"(arrB[1])
        : "rsi");
    return r; /* 33.0 */
}

/* (f) FSTSW AX writes guest AX mid-run; a later inlined mov must read the
 *     written status word (program order across Guest nodes). Equal compare
 *     → C3 (0x4000) set, C0/C2 clear. */
static double inline_fstsw_then_mov(double x, long *cc_out) {
    long cc = 0;
    double r;
    __asm__ volatile(
        "fldl %2\n"
        "fldl %2\n"
        "fcompp\n"             /* x vs x → equal: C3=1 C2=0 C0=0 */
        "fnstsw %%ax\n"
        "movl %%eax, %%ecx\n"  /* inlined GuestMovRR reading AX */
        "andl $0x4500, %%ecx\n"
        "fldl %2\n"
        "fmull %2\n"
        "fstpl %0\n"
        "movq %%rcx, %1\n"
        : "=m"(r), "=&r"(cc)
        : "m"(x)
        : "rax", "rcx", "cc");
    *cc_out = cc;
    return r;
}

/* (g) lea forms: 3-term with a large (non-imm12) displacement — exercises
 *     the transient-GPR path — plus negative disp and 32-bit truncation. */
static double inline_lea_forms(long *big_out, long *neg_out, long *trunc_out) {
    double one = 1.5, two = 2.0;
    long big = 0, neg = 0, tr = 0;
    double r;
    __asm__ volatile(
        "movq $0x1000, %%rsi\n"
        "movq $2, %%rdx\n"
        "fldl %4\n"
        "leaq 0x123457(%%rsi,%%rdx,4), %%rcx\n"  /* 0x1000+8+0x123457 */
        "fmull %5\n"
        "leaq -16(%%rcx), %%rdi\n"               /* negative disp */
        "fstpl %0\n"
        "movq %%rcx, %1\n"
        "movq %%rdi, %2\n"
        /* 32-bit dst: upper bits of rcx must be zeroed by leal */
        "movq $-1, %%rcx\n"
        "leal 4(%%rsi), %%ecx\n"
        "movq %%rcx, %3\n"
        : "=m"(r), "=&r"(big), "=&r"(neg), "=&r"(tr)
        : "m"(one), "m"(two)
        : "rsi", "rdx", "rcx", "rdi");
    *big_out = big; *neg_out = neg; *trunc_out = tr;
    return r;
}

/* (h) movzx/movsx register forms, including an AH (high-byte) source. */
static double inline_movzx_movsx(long *zxb, long *sxb, long *zxh, long *sxw, long *ah_out) {
    double a = 3.0, b = 5.0;
    long z8 = 0, s8 = 0, z16 = 0, sw = 0, ah = 0;
    double r;
    __asm__ volatile(
        "movq $0x8899, %%rax\n"      /* al = 0x99, ah = 0x88 */
        "fldl %6\n"
        "movzbl %%al, %%ecx\n"       /* 0x99 */
        "movsbl %%al, %%edx\n"       /* -103 (0x99 sign-extended) */
        "fmull %7\n"
        "movzbl %%ah, %%esi\n"       /* 0x88 — high-byte source */
        "movzwl %%ax, %%edi\n"       /* 0x8899 */
        "fstpl %0\n"
        "movslq %%edx, %%rdx\n"      /* movsxd */
        "movq %%rcx, %1\n"
        "movq %%rdx, %2\n"
        "movq %%rdi, %3\n"
        "movq %%rdx, %4\n"
        "movq %%rsi, %5\n"
        : "=m"(r), "=&r"(z8), "=&r"(s8), "=&r"(z16), "=&r"(sw), "=&r"(ah)
        : "m"(a), "m"(b)
        : "rax", "rcx", "rdx", "rsi", "rdi");
    *zxb = z8; *sxb = s8; *zxh = z16; *sxw = sw; *ah_out = ah;
    return r;
}

/* (j) OPT-BC (ROSETTA_X87_BRIDGE_CARRY): fistp runs split by a non-inlinable
 *     SSE gap, with an fldcw changing the rounding mode between carried
 *     runs. The carried RC value must be invalidated when the fldcw goes
 *     through a non-IR path, and re-cached when it lands in-run — either
 *     way each fistp must honor the control word in force. */
static void carry_rc_fldcw(double v, int *near1, int *near2, int *trunc1, int *trunc2) {
    unsigned short cw_old = 0, cw_trunc = 0;
    int a = 0, b = 0, c = 0, d = 0;
    float f = 1.0f;
    __asm__ volatile(
        "fnstcw %4\n"
        "movzwl %4, %%ecx\n"
        "orl $0x0C00, %%ecx\n"        /* RC = truncate */
        "movw %%cx, %5\n"
        /* nearest-mode pair, split by movss */
        "fldl %6\n" "fistpl %0\n"
        "fldl %6\n" "fistpl %1\n"
        "movss %7, %%xmm1\n"
        /* switch to truncate between runs */
        "fldcw %5\n"
        "fldl %6\n" "fistpl %2\n"
        "movss %7, %%xmm1\n"
        "fldl %6\n" "fistpl %3\n"
        "fldcw %4\n"                  /* restore */
        : "=m"(a), "=m"(b), "=m"(c), "=m"(d), "+m"(cw_old), "+m"(cw_trunc)
        : "m"(v), "m"(f)
        : "ecx", "xmm1");
    *near1 = a; *near2 = b; *trunc1 = c; *trunc2 = d;
}

/* (i) deep x87 stack with guest movs interleaved — exercises the pressure
 *     models with Guest nodes present. */
static double inline_deep_stack(void) {
    double v[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "movl $1, %%ecx\n"
        "fldl %2\n"
        "fldl %3\n"
        "movl $2, %%edx\n"
        "fldl %4\n"
        "fldl %5\n"
        "leaq 8(%%rsp), %%rsi\n"
        "fldl %6\n"
        "faddp\n"              /* 5+6=11 */
        "movl $3, %%ecx\n"
        "faddp\n"              /* 4+11=15 */
        "faddp\n"              /* 3+15=18 */
        "faddp\n"              /* 2+18=20 */
        "faddp\n"              /* 1+20=21 */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(v[0]), "m"(v[1]), "m"(v[2]), "m"(v[3]), "m"(v[4]), "m"(v[5])
        : "rcx", "rdx", "rsi");
    return r; /* 21.0 */
}

int main(void) {
    install_fault_guard();

    GUARDED("inline_mov_imm_chain", {
        long p = 0, n = 0;
        check("inline_mov_imm_chain: a*b intact",
              inline_mov_imm_chain(3.0, 4.0, &p, &n), 12.0);
        check_long("inline_mov_imm_chain: imm value", p, 123456);
        check_long("inline_mov_imm_chain: negative imm zero-extends", n, 0xFFFFFFFBL);
    });

    GUARDED("inline_mov_store_base", {
        check("inline_mov_store_base: fstp lands at new base",
              inline_mov_store_base(2.5, 4.0), 10.0);
    });

    GUARDED("inline_cse_evict_load", {
        check("inline_cse_evict_load: second load sees new base",
              inline_cse_evict_load(1.25, 2.5), 3.75);
    });

    GUARDED("inline_cse_evict_store_fwd", {
        check("inline_cse_evict_store_fwd: reload not forwarded",
              inline_cse_evict_store_fwd(7.0, 42.5), 42.5);
    });

    GUARDED("inline_base_cache_rewrite", {
        check("inline_base_cache_rewrite: post-write accesses use new base",
              inline_base_cache_rewrite(), 33.0);
    });

    GUARDED("inline_fstsw_then_mov", {
        long cc = -1;
        check("inline_fstsw_then_mov: x*x intact",
              inline_fstsw_then_mov(3.0, &cc), 9.0);
        check_long("inline_fstsw_then_mov: mov saw status word (C3)", cc, 0x4000);
    });

    GUARDED("inline_lea_forms", {
        long big = 0, neg = 0, tr = 0;
        check("inline_lea_forms: a*b intact",
              inline_lea_forms(&big, &neg, &tr), 3.0);
        check_long("inline_lea_forms: 3-term large disp", big, 0x1000 + 8 + 0x123457);
        check_long("inline_lea_forms: negative disp", neg, 0x1000 + 8 + 0x123457 - 16);
        check_long("inline_lea_forms: leal zero-extends", tr, 0x1004);
    });

    GUARDED("inline_movzx_movsx", {
        long z8 = 0, s8 = 0, z16 = 0, sw = 0, ah = 0;
        check("inline_movzx_movsx: a*b intact",
              inline_movzx_movsx(&z8, &s8, &z16, &sw, &ah), 15.0);
        check_long("inline_movzx_movsx: movzbl", z8, 0x99);
        check_long("inline_movzx_movsx: movsbl+movsxd", s8, -103);
        check_long("inline_movzx_movsx: movzwl", z16, 0x8899);
        check_long("inline_movzx_movsx: movzbl from AH", ah, 0x88);
    });

    GUARDED("inline_deep_stack", {
        check("inline_deep_stack: sum with interleaved movs",
              inline_deep_stack(), 21.0);
    });

    GUARDED("carry_rc_fldcw", {
        int n1 = 0, n2 = 0, t1 = 0, t2 = 0;
        carry_rc_fldcw(3.7, &n1, &n2, &t1, &t2);
        check_long("carry_rc_fldcw: nearest before fldcw", n1, 4);
        check_long("carry_rc_fldcw: nearest across gap", n2, 4);
        check_long("carry_rc_fldcw: truncate after fldcw", t1, 3);
        check_long("carry_rc_fldcw: truncate across gap", t2, 3);
    });

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
