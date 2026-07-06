/*
 * test_ir_deferred.c — IR pipeline entry with carried-in deferred cache state.
 *
 * The IR pipeline (X87IR::compile_run) can now fire mid-run with deferred
 * cache state pending: a deferred-FXCH perm map, deferred push/pop tag
 * updates, and a stale in-memory TOP (top_dirty).  These sequences force the
 * per-instruction translators to create that state first (via ops the IR
 * bails on: FCMOV without a prior FCOMI in the run, FSTP m80), then continue
 * with 3+ IR-compilable instructions so the IR must fold the carried state.
 *
 * Build: clang -arch x86_64 -O0 -g -o test_ir_deferred test_ir_deferred.c
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

static void check_u16(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-55s  got=0x%04x  expected=0x%04x\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* ==== Deferred FXCH perm carried into IR ====
 *
 * The two FLDs are lowered by the IR (it bails at the first FCMOVB — no
 * FCOMI before it in the run).  The FXCH is then followed by another FCMOVB,
 * so the IR attempt starting at the FXCH only consumes one instruction and
 * declines; the FXCH is translated per-instruction and defers a perm swap.
 * FCMOVB (CF=0 → no move) flushes tags/top but NOT the perm, so the
 * remaining FADD/FMUL/FSTP/FSTP run enters the IR with perm_dirty set.
 */
static void ir_after_deferred_fxch(double *out0, double *out1) {
    __asm__ volatile(
        "cmpl $1, %[one]\n"   /* CF=0, ZF=1 — FCMOVB won't move */
        "fldl %[a]\n"         /* ST(0)=3 */
        "fldl %[b]\n"         /* ST(0)=5, ST(1)=3 */
        "fcmovb %%st(1), %%st\n" /* CF=0: no-op; IR bails here */
        "fxch %%st(1)\n"      /* ST(0)=3, ST(1)=5  (deferred perm) */
        "fcmovb %%st(1), %%st\n" /* CF=0: no-op; keeps FXCH per-instruction */
        "faddl %[c]\n"        /* ST(0)=3+10=13 */
        "fmul %%st(1), %%st\n"/* ST(0)=13*5=65 */
        "fstpl %[o0]\n"       /* 65 */
        "fstpl %[o1]\n"       /* 5 */
        : [o0] "=m"(*out0), [o1] "=m"(*out1)
        : [a] "m"((double){3.0}), [b] "m"((double){5.0}),
          [c] "m"((double){10.0}), [one] "m"((int){1})
        : "cc");
}

/* ==== Deferred pop + stale TOP carried into IR ====
 *
 * The IR consumes the two FLDs, bails at FSTP m80 (S80 store).  The
 * per-instruction m80 path pops with a deferred tag update and leaves
 * top_dirty set.  The remaining FADD/FMULP/FSTP enters the IR with
 * deferred_pop_count=1 and top_dirty=1.
 */
static void ir_after_deferred_pop(double *out0, long double *out80) {
    __asm__ volatile(
        "fldl %[a]\n"         /* ST(0)=2 */
        "fldl %[b]\n"         /* ST(0)=7, ST(1)=2 */
        "fldl %[c]\n"         /* ST(0)=4, ST(1)=7, ST(2)=2 */
        "fstpt %[o80]\n"      /* store 4 as f80, pop (deferred pop tag) */
        "faddl %[d]\n"        /* ST(0)=7+1=8 */
        "fmulp %%st(1)\n"     /* ST(0)=2*8=16 */
        "fstpl %[o0]\n"       /* 16 */
        : [o0] "=m"(*out0), [o80] "=m"(*out80)
        : [a] "m"((double){2.0}), [b] "m"((double){7.0}),
          [c] "m"((double){4.0}), [d] "m"((double){1.0}));
}

/* ==== FSTSW inside IR with stale in-memory TOP ====
 *
 * After the per-instruction FSTP m80 leaves top_dirty=1, the IR run contains
 * FCOM + FNSTSW AX with no pops before the FSTSW (top_delta snapshot 0), so
 * the IR must patch the TOP field of the status word read from memory using
 * the live TOP register.  TOP after 3 pushes and 1 pop is 6 (bits [13:11]).
 */
static void ir_fstsw_stale_top(double *out0, uint16_t *sw, long double *out80) {
    uint16_t sw_local = 0;
    __asm__ volatile(
        "fldl %[a]\n"         /* ST(0)=9 */
        "fldl %[b]\n"         /* ST(0)=5, ST(1)=9 */
        "fldl %[c]\n"         /* ST(0)=1, ST(1)=5, ST(2)=9 */
        "fstpt %[o80]\n"      /* pop (deferred), top_dirty=1 */
        "fcom %%st(1)\n"      /* 5 vs 9 → less: C0=1 */
        "fnstsw %%ax\n"       /* AX = status word, TOP patched from register */
        "movw %%ax, %[sw]\n"
        "faddp %%st(1)\n"     /* ST(0)=9+5=14 */
        "fstpl %[o0]\n"
        : [o0] "=m"(*out0), [sw] "=m"(sw_local), [o80] "=m"(*out80)
        : [a] "m"((double){9.0}), [b] "m"((double){5.0}),
          [c] "m"((double){1.0})
        : "ax");
    *sw = sw_local;
}

int main(void) {
    double r0 = 0, r1 = 0;
    long double r80 = 0;

    ir_after_deferred_fxch(&r0, &r1);
    check("ir_after_deferred_fxch: ST(0)", r0, 65.0);
    check("ir_after_deferred_fxch: ST(1)", r1, 5.0);

    r0 = r1 = 0;
    ir_after_deferred_pop(&r0, &r80);
    check("ir_after_deferred_pop: result", r0, 16.0);
    check("ir_after_deferred_pop: m80 store", (double)r80, 4.0);

    r0 = 0; r80 = 0;
    uint16_t sw = 0;
    ir_fstsw_stale_top(&r0, &sw, &r80);
    check("ir_fstsw_stale_top: result", r0, 14.0);
    check("ir_fstsw_stale_top: m80 store", (double)r80, 1.0);
    /* C0=1 (bit 8, ST(0) < src), C2=C3=0.  The TOP field is deliberately not
     * asserted: native Rosetta switches x87 emulation modes in-process and
     * reports a flattened TOP=0 here, so an absolute TOP value is not a
     * portable expectation (the suite's native-vs-loader comparison still
     * covers the FStsw TOP-patch path). */
    check_u16("ir_fstsw_stale_top: status word CC", sw & 0x4500, 0x0100);

    if (failures == 0)
        printf("ALL PASS\n");
    else
        printf("%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
