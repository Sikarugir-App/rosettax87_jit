/*
 * test_addr_fold.c — Tests for IR base-address caching + displacement folding.
 *
 * Covers: positive scaled displacements (LDR/STR imm12), negative
 * displacements (LDUR/STUR), two cached bases in one run, out-of-range
 * displacements (fallback path), unaligned displacements, mixed f32/f64
 * through one base, and the FSTSW/RAX-base exclusion.
 *
 * Build: clang -arch x86_64 -O0 -g -o test_addr_fold test_addr_fold.c
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

/* ==== dot product, two bases, positive scaled disps ==== */
static double dot3(const double *p, const double *q) {
    double out;
    __asm__ volatile(
        "fldl (%1)\n\t"
        "fmull (%2)\n\t"
        "fldl 8(%1)\n\t"
        "fmull 8(%2)\n\t"
        "faddp\n\t"
        "fldl 16(%1)\n\t"
        "fmull 16(%2)\n\t"
        "faddp\n\t"
        "fstpl %0\n"
        : "=m"(out) : "r"(p), "r"(q));
    return out;
}

/* ==== strided store fill through one base ==== */
static void fill4(double *p) {
    __asm__ volatile(
        "fldz\n\t fstpl (%0)\n\t"
        "fld1\n\t fstpl 8(%0)\n\t"
        "fldz\n\t fstpl 16(%0)\n\t"
        "fld1\n\t fstpl 24(%0)\n"
        : : "r"(p) : "memory");
}

/* ==== negative displacements through one base ==== */
static double neg_disp(const double *p_end) {
    double out;
    __asm__ volatile(
        "fldl -8(%1)\n\t"
        "faddl -16(%1)\n\t"
        "faddl -24(%1)\n\t"
        "fstpl %0\n"
        : "=m"(out) : "r"(p_end));
    return out;
}

/* ==== displacement beyond imm12 range: cached base + fallback access ==== */
static double big_disp(const double *p) {
    double out;
    __asm__ volatile(
        "fldl (%1)\n\t"
        "faddl 8(%1)\n\t"
        "faddl 32768(%1)\n\t"     /* 32768 > 32760 → per-access fallback */
        "fstpl %0\n"
        : "=m"(out) : "r"(p));
    return out;
}

/* ==== unaligned f64 displacements (disp % 8 != 0 → LDUR path) ==== */
static double unaligned_disp(const char *base) {
    double out;
    __asm__ volatile(
        "fldl 4(%1)\n\t"
        "faddl 20(%1)\n\t"
        "fstpl %0\n"
        : "=m"(out) : "r"(base));
    return out;
}

/* ==== mixed f32/f64 through the same base ==== */
static double mixed_sizes(const char *base) {
    double out;
    __asm__ volatile(
        "flds (%1)\n\t"           /* f32 at +0 */
        "faddl 8(%1)\n\t"         /* f64 at +8 */
        "fadds 4(%1)\n\t"         /* f32 at +4 */
        "fstpl %0\n"
        : "=m"(out) : "r"(base));
    return out;
}

/* ==== FSTSW in run: RAX-based operands must not use a cached base ==== */
static double fstsw_rax_base(const double *p, uint16_t *sw_out) {
    double out;
    uint16_t sw;
    __asm__ volatile(
        "movq %2, %%rax\n\t"
        "fldl (%%rax)\n\t"
        "faddl 8(%%rax)\n\t"
        "fnstsw %%ax\n\t"          /* clobbers AX — RAX-based caching unsafe */
        "movw %%ax, %1\n\t"
        "fstpl %0\n"
        : "=m"(out), "=m"(sw)
        : "r"(p)
        : "rax");
    *sw_out = sw;
    return out;
}

/* ==== addr cache + RC cache in one run (2 FISTPs → pool-slot GPR) ====
 * Base+index addressing forces the cached base into an allocated scratch
 * register (a plain 64-bit register base is used directly), reproducing
 * the pool-slot collision seen with 32-bit game code. */
static void addr_cache_with_rc_cache(const double *p, int32_t *i0, int32_t *i1) {
    __asm__ volatile(
        "fldl (%2,%3,8)\n\t"       /* 2.25 */
        "faddl 8(%2,%3,8)\n\t"     /* 5.75 — two same-key accesses → addr cache */
        "fldl 8(%2,%3,8)\n\t"      /* 3.5 on top */
        "fistpl %0\n\t"            /* two non-truncating int stores → RC cache */
        "fistpl %1\n"
        : "=m"(*i0), "=m"(*i1) : "r"(p), "r"((long)0));
}

/* ==== addr cache + FRNDINT (per-node pool-slot GPR) in one run ==== */
static double addr_cache_with_frndint(const double *p) {
    double out;
    __asm__ volatile(
        "fldl (%1,%2,8)\n\t"
        "faddl 8(%1,%2,8)\n\t"     /* two same-key accesses → addr cache */
        "frndint\n\t"
        "fstpl %0\n"
        : "=m"(out) : "r"(p), "r"((long)0));
    return out;
}

/* ==== many distinct bases: only 2 cached, rest fall back ==== */
static double three_bases(const double *p, const double *q, const double *r) {
    double out;
    __asm__ volatile(
        "fldl (%1)\n\t"
        "faddl 8(%1)\n\t"
        "faddl (%2)\n\t"
        "faddl 8(%2)\n\t"
        "faddl (%3)\n\t"
        "faddl 8(%3)\n\t"
        "fstpl %0\n"
        : "=m"(out) : "r"(p), "r"(q), "r"(r));
    return out;
}

int main(void) {
    {
        double a[3] = {1.0, 2.0, 3.0};
        double b[3] = {4.0, 5.0, 6.0};
        check("dot3 two bases", dot3(a, b), 1.0*4.0 + 2.0*5.0 + 3.0*6.0);
    }
    {
        double buf[4] = {9.0, 9.0, 9.0, 9.0};
        fill4(buf);
        check("fill4 [0]", buf[0], 0.0);
        check("fill4 [1]", buf[1], 1.0);
        check("fill4 [2]", buf[2], 0.0);
        check("fill4 [3]", buf[3], 1.0);
    }
    {
        double buf[3] = {10.0, 20.0, 30.0};
        check("negative disps", neg_disp(buf + 3), 30.0 + 20.0 + 10.0);
    }
    {
        static double big[4097];  /* 32776 bytes */
        big[0] = 1.5; big[1] = 2.5; big[4096] = 4.0;
        check("big disp fallback", big_disp(big), 1.5 + 2.5 + 4.0);
    }
    {
        char buf[32];
        double x = 3.25, y = 1.75;
        memcpy(buf + 4, &x, 8);
        memcpy(buf + 20, &y, 8);
        check("unaligned disps", unaligned_disp(buf), 3.25 + 1.75);
    }
    {
        char buf[16];
        float f0 = 0.5f, f1 = 0.25f;
        double d = 2.0;
        memcpy(buf + 0, &f0, 4);
        memcpy(buf + 4, &f1, 4);
        memcpy(buf + 8, &d, 8);
        check("mixed f32/f64 one base", mixed_sizes(buf), 0.5 + 2.0 + 0.25);
    }
    {
        double a[2] = {6.0, 7.0};
        uint16_t sw = 0xFFFF;
        check("fstsw + rax base", fstsw_rax_base(a, &sw), 13.0);
    }
    {
        double a[2] = {1.0, 2.0}, b[2] = {4.0, 8.0}, c[2] = {16.0, 32.0};
        check("three bases", three_bases(a, b, c), 63.0);
    }
    {
        double a[2] = {2.25, 3.5};
        int32_t i0 = -1, i1 = -1;
        addr_cache_with_rc_cache(a, &i0, &i1);
        check("addr+rc cache: fistp #1", (double)i0, 4.0);   /* 3.5 → 4 nearest */
        check("addr+rc cache: fistp #2", (double)i1, 6.0);   /* 5.75 → 6 */
    }
    {
        double a[2] = {1.25, 2.5};
        check("addr cache + frndint", addr_cache_with_frndint(a), 4.0);  /* 3.75 → 4 */
    }

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
