/*
 * test_keepalive.c — OPT-KA fixture (ROSETTA_X87_RUNTIME_KEEPALIVE).
 *
 * Each function sandwiches a runtime-routine transcendental (fsin/fcos/fptan/
 * fsincos/f2xm1/fscale/fyl2x/fyl2xp1/fpatan/fprem/fprem1/fxam) inside an x87
 * run so the pinned cache is live across the runtime BL. The sequences are
 * chosen to exercise every piece of deferred state the keepalive prologue must
 * flush (deferred push tags, FXCH permutation, dirty TOP) and the cached-TOP
 * adjustment for the pushing/popping helpers (fptan/fsincos push, fyl2x/
 * fyl2xp1/fpatan pop) — the x87 ops AFTER the transcendental keep using the
 * cached TOP/base, so any incoherence corrupts values or slots.
 *
 * Results are compared against libm with a small relative tolerance: the
 * runtime helpers (openlibm under the custom loader, Apple's under native
 * Rosetta) may differ from the host libm in the last ulps.
 *
 * Must pass with the feature off (default), on (env=1), under native Rosetta,
 * and under the custom runtime_loader.
 *
 * Build: clang -arch x86_64 -O0 -g -o test_keepalive test_keepalive.c
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check_tol(const char *name, double got, double expected) {
    double err = fabs(got - expected);
    double rel = err / (fabs(expected) > 1e-300 ? fabs(expected) : 1.0);
    if (rel > 1e-9 && err > 1e-12) {
        printf("FAIL  %-55s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_u16(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-55s  got=0x%04x  expected=0x%04x\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* fsin mid-run: the ops after the BL reuse the pinned base/TOP. */
static double sin_in_run(double a, double b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"   /* ST0=b */
        "fldl %2\n"   /* ST0=a ST1=b */
        "fsin\n"      /* ST0=sin(a) */
        "fmulp\n"     /* ST0=sin(a)*b */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(b), "m"(a));
    return r;
}

/* fcos with a deferred push pending at the BL (fld1 right before). */
static double cos_deferred_push(double a, double *st1_out) {
    double r;
    __asm__ volatile(
        "fldl %2\n"   /* ST0=a */
        "fld1\n"      /* deferred push; ST0=1.0 ST1=a */
        "fcos\n"      /* ST0=cos(1.0) */
        "fstpl %0\n"  /* r=cos(1.0) */
        "fstpl %1\n"  /* st1_out=a — wrong slot if tags/TOP were incoherent */
        : "=m"(r), "=m"(*st1_out)
        : "m"(a));
    return r;
}

/* FXCH permutation dirty at the BL — must be materialized first. */
static double fxch_before_sin(double a, double b, double *st1_out) {
    double r;
    __asm__ volatile(
        "fldl %2\n"      /* ST0=a */
        "fldl %3\n"      /* ST0=b ST1=a */
        "fxch %%st(1)\n" /* deferred perm: ST0=a ST1=b */
        "fsin\n"         /* ST0=sin(a) */
        "fstpl %0\n"
        "fstpl %1\n"     /* must be b */
        : "=m"(r), "=m"(*st1_out)
        : "m"(a), "m"(b));
    return r;
}

/* fptan pushes 1.0 — cached TOP must track the helper's push. */
static double ptan_in_run(double a, double *one_out) {
    double r;
    __asm__ volatile(
        "fldl %2\n"   /* ST0=a */
        "fptan\n"     /* ST0=1.0 ST1=tan(a) */
        "fstpl %1\n"  /* one_out=1.0 */
        "fstpl %0\n"  /* r=tan(a) */
        : "=m"(r), "=m"(*one_out)
        : "m"(a));
    return r;
}

/* fptan + faddp: post-BL arithmetic through the adjusted cached TOP. */
static double ptan_faddp(double a) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fptan\n"     /* ST0=1.0 ST1=tan(a) */
        "faddp\n"     /* ST0=tan(a)+1.0 */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(a));
    return r;
}

static double sincos_in_run(double a, double *sin_out) {
    double c;
    __asm__ volatile(
        "fldl %2\n"
        "fsincos\n"   /* ST0=cos(a) ST1=sin(a) */
        "fstpl %0\n"
        "fstpl %1\n"
        : "=m"(c), "=m"(*sin_out)
        : "m"(a));
    return c;
}

/* fyl2x pops — cached TOP must track the helper's pop. */
static double yl2x_fld1_faddp(double y, double x) {
    double r;
    __asm__ volatile(
        "fldl %1\n"   /* ST0=y */
        "fldl %2\n"   /* ST0=x ST1=y */
        "fyl2x\n"     /* ST0=y*log2(x) */
        "fld1\n"
        "faddp\n"     /* y*log2(x)+1 — uses cached TOP after the pop */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(y), "m"(x));
    return r;
}

static double yl2xp1_in_run(double y, double x) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fldl %2\n"
        "fyl2xp1\n"   /* ST0=y*log2(x+1) */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(y), "m"(x));
    return r;
}

static double patan_in_run(double y, double x) {
    double r;
    __asm__ volatile(
        "fldl %1\n"   /* ST0=y */
        "fldl %2\n"   /* ST0=x ST1=y */
        "fpatan\n"    /* ST0=atan2(y,x) */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(y), "m"(x));
    return r;
}

static double scale_in_run(double v, double e) {
    double r;
    __asm__ volatile(
        "fldl %1\n"      /* ST0=e */
        "fldl %2\n"      /* ST0=v ST1=e */
        "fscale\n"       /* ST0=v*2^trunc(e) */
        "fstpl %0\n"
        "fstp %%st(0)\n" /* drop e */
        : "=m"(r)
        : "m"(e), "m"(v));
    return r;
}

static double f2xm1_faddp(double x) {
    double r;
    __asm__ volatile(
        "fld1\n"      /* ST0=1 */
        "fldl %1\n"   /* ST0=x ST1=1 */
        "f2xm1\n"     /* ST0=2^x-1 */
        "faddp\n"     /* ST0=2^x */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(x));
    return r;
}

static double prem_in_run(double a, double b, double *b_out) {
    double r;
    __asm__ volatile(
        "fldl %3\n"   /* ST0=b */
        "fldl %2\n"   /* ST0=a ST1=b */
        "fprem\n"     /* ST0=fmod(a,b) */
        "fstpl %0\n"
        "fstpl %1\n"  /* b intact */
        : "=m"(r), "=m"(*b_out)
        : "m"(a), "m"(b));
    return r;
}

static double prem1_in_run(double a, double b, double *b_out) {
    double r;
    __asm__ volatile(
        "fldl %3\n"
        "fldl %2\n"
        "fprem1\n"    /* IEEE remainder(a,b) */
        "fstpl %0\n"
        "fstpl %1\n"
        : "=m"(r), "=m"(*b_out)
        : "m"(a), "m"(b));
    return r;
}

/* fxam mid-run: condition bits for a negative normal (C1|C2), value intact. */
static uint16_t xam_in_run(double a, double *val_out) {
    uint16_t sw;
    /* Memory-form fnstsw: the register form writes %ax, which the compiler
     * may also be using to address the other memory operands — and fstp
     * before fnstsw would clear C1. */
    __asm__ volatile(
        "fldl %2\n"
        "fxam\n"
        "fnstsw %0\n"
        "fstpl %1\n"
        : "=m"(sw), "=m"(*val_out)
        : "m"(a));
    return sw;
}

/* TOP integrity read straight from the status word after a pushing helper. */
static uint16_t top_after_ptan(double a) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fptan\n"
        "fnstsw %%ax\n"
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        : "=a"(sw)
        : "m"(a));
    return (uint16_t)((sw >> 11) & 7);
}

int main(void) {
    double t1 = 0.0, t2 = 0.0;

    check_tol("fsin in run: sin(0.5)*3", sin_in_run(0.5, 3.0), sin(0.5) * 3.0);

    check_tol("fcos deferred push: cos(1.0)", cos_deferred_push(0.75, &t1), cos(1.0));
    check_tol("fcos deferred push: ST1 slot intact", t1, 0.75);

    check_tol("fxch before fsin: sin(0.25)", fxch_before_sin(0.25, 8.0, &t1), sin(0.25));
    check_tol("fxch before fsin: ST1 slot intact", t1, 8.0);

    check_tol("fptan: tan(0.5)", ptan_in_run(0.5, &t1), tan(0.5));
    check_tol("fptan: pushed 1.0", t1, 1.0);
    check_tol("fptan+faddp: tan(0.3)+1", ptan_faddp(0.3), tan(0.3) + 1.0);

    check_tol("fsincos: cos(0.6)", sincos_in_run(0.6, &t1), cos(0.6));
    check_tol("fsincos: sin(0.6)", t1, sin(0.6));

    check_tol("fyl2x+fld1+faddp: 3*log2(8)+1", yl2x_fld1_faddp(3.0, 8.0),
              3.0 * log2(8.0) + 1.0);
    check_tol("fyl2xp1: 2*log2(1.25)", yl2xp1_in_run(2.0, 0.25), 2.0 * log2(1.25));

    check_tol("fpatan: atan2(1,2)", patan_in_run(1.0, 2.0), atan2(1.0, 2.0));

    check_tol("fscale: 1.5*2^3", scale_in_run(1.5, 3.0), 1.5 * 8.0);

    check_tol("f2xm1+faddp: 2^0.5", f2xm1_faddp(0.5), pow(2.0, 0.5));

    check_tol("fprem: fmod(7.5,2.0)", prem_in_run(7.5, 2.0, &t2), fmod(7.5, 2.0));
    check_tol("fprem: divisor intact", t2, 2.0);
    check_tol("fprem1: remainder(7.5,2.0)", prem1_in_run(7.5, 2.0, &t2),
              remainder(7.5, 2.0));
    check_tol("fprem1: divisor intact", t2, 2.0);

    {
        /* negative normal → C1 (sign) + C2 (normal); C0=C3=0 */
        uint16_t sw = xam_in_run(-2.5, &t1);
        check_u16("fxam: negative normal C3..C0", (uint16_t)(sw & 0x4700), 0x0600);
        check_tol("fxam: value intact", t1, -2.5);
    }

    check_u16("fptan: TOP after push", top_after_ptan(0.4), 6);

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
