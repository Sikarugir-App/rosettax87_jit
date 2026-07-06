/*
 * test_mem_cse.c — Tests for IR memory-load CSE and store→load forwarding.
 *
 * Covers: repeated loads of the same operand (CSE hit), FSTP/FST m64 followed
 * by FLD of the same operand (forwarding, incl. NaN bit-exactness), aliasing
 * stores through a different base register (must invalidate), FNSTCW writing
 * over a cached load's memory (must invalidate), integer store→load (no
 * forwarding — conversion isn't invertible), f32 store→load (no forwarding —
 * narrowing), integer load CSE, and CSE-table eviction with >4 operands.
 *
 * Build: clang -arch x86_64 -O0 -g -o test_mem_cse test_mem_cse.c
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

static void check_bits(const char *name, uint64_t got, uint64_t expected) {
    if (got != expected) {
        printf("FAIL  %-55s  got=%016llx  expected=%016llx\n", name,
               (unsigned long long)got, (unsigned long long)expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* ==== FLD m64 + FADD m64, same operand (basic load-CSE hit) ==== */
static double fld_fadd_same(void) {
    double a = 1.5, out;
    __asm__ volatile(
        "fldl %1\n"            /* ST(0) = 1.5 */
        "faddl %1\n"           /* ST(0) += same operand → CSE hit */
        "fstpl %0\n"
        : "=m"(out)
        : "m"(a));
    return out;                /* 3.0 */
}

/* ==== FLD m64 twice, same operand ==== */
static void fld_fld_same(double *o0, double *o1) {
    double a = 2.25;
    __asm__ volatile(
        "fldl %2\n"
        "fldl %2\n"            /* CSE hit */
        "fstpl %0\n"
        "fstpl %1\n"
        : "=m"(*o0), "=m"(*o1)
        : "m"(a));
}

/* ==== FILD m32 + FIADD m32, same operand (integer load CSE) ==== */
static double fild_fiadd_same(void) {
    int32_t v = 41;
    double out;
    __asm__ volatile(
        "fildl %1\n"           /* ST(0) = 41.0 */
        "fiaddl %1\n"          /* CSE hit on LoadI32 → 82.0 */
        "fstpl %0\n"
        : "=m"(out)
        : "m"(v));
    return out;                /* 82.0 */
}

/* ==== FSTP m64 + FLD m64, same operand (store→load forwarding) ==== */
static double fstp_fld_forward(void) {
    double tmp, out;
    __asm__ volatile(
        "fldl %2\n"            /* ST(0) = 12.5 */
        "fstpl %1\n"           /* tmp = 12.5, pop */
        "fldl %1\n"            /* forwarded from the store */
        "fmull %2\n"
        "fstpl %0\n"
        : "=m"(out), "=m"(tmp)
        : "m"((double){12.5}));
    return out;                /* 156.25 */
}

/* ==== FST m64 (no pop) + FMUL m64, same operand ==== */
static double fst_fmul_forward(void) {
    double tmp, out;
    __asm__ volatile(
        "fldl %2\n"            /* ST(0) = 7.5 */
        "fstl %1\n"            /* tmp = 7.5, no pop */
        "fmull %1\n"           /* forwarded → 56.25 */
        "fstpl %0\n"
        : "=m"(out), "=m"(tmp)
        : "m"((double){7.5}));
    return out;                /* 56.25 */
}

/* ==== NaN payload survives store→load forwarding bit-exactly ==== */
static uint64_t forward_nan_bits(void) {
    uint64_t nan_bits = 0x7FF8000012345678ULL;
    double a, tmp, out;
    memcpy(&a, &nan_bits, 8);
    __asm__ volatile(
        "fldl %2\n"
        "fstpl %1\n"
        "fldl %1\n"            /* forwarded value must keep the payload */
        "fstpl %0\n"
        : "=m"(out), "=m"(tmp)
        : "m"(a));
    return as_u64(out);
}

/* ==== Aliasing store through a different base register invalidates ==== */
static double alias_store_invalidates(void) {
    double buf = 1.0, out;
    double *q = &buf;
    __asm__ volatile(
        "fldl (%1)\n"          /* ST(0) = 1.0; caches load of (%1) */
        "fldl %3\n"            /* push 5.0 */
        "fstpl (%2)\n"         /* write 5.0 through a different register */
        "fldl (%1)\n"          /* must reload → 5.0, NOT the cached 1.0 */
        "faddp\n"              /* 5.0 + 1.0 = 6.0 */
        "fstpl %0\n"
        : "=m"(out)
        : "r"(&buf), "r"(q), "m"((double){5.0})
        : "memory");
    return out;                /* 6.0 */
}

/* ==== FNSTCW overwrites a cached load's memory → must invalidate ==== */
static uint64_t fnstcw_invalidates(uint64_t *expected) {
    double buf = 1.0, out;
    uint16_t cw;
    __asm__ volatile("fnstcw %0" : "=m"(cw));
    *expected = (as_u64(1.0) & ~0xFFFFULL) | cw;
    __asm__ volatile(
        "fldl %1\n"            /* caches load of buf (= 1.0) */
        "fnstcw %1\n"          /* overwrite buf's low 2 bytes with the CW */
        "fldl %1\n"            /* must observe the modified bits */
        "fstpl %0\n"
        "fstp %%st(0)\n"       /* discard the first load */
        : "=m"(out), "+m"(buf));
    return as_u64(out);
}

/* ==== FISTP m32 + FILD m32: no forwarding across the int conversion ==== */
static double fistp_fild_no_forward(void) {
    double third = 1.0 / 3.0, out;
    int32_t i;
    __asm__ volatile(
        "fldl %2\n"            /* ST(0) = 0.333… */
        "fistpl %1\n"          /* i = 0 (round to nearest) */
        "fildl %1\n"           /* must load the converted int, not 1/3 */
        "fstpl %0\n"
        : "=m"(out), "=m"(i)
        : "m"(third));
    return out;                /* 0.0 */
}

/* ==== FSTP m32 + FLD m32: no forwarding across the f32 narrowing ==== */
static double fstps_flds_no_forward(void) {
    double third = 1.0 / 3.0, out;
    float f;
    __asm__ volatile(
        "fldl %2\n"
        "fstps %1\n"           /* narrow to f32 */
        "flds %1\n"            /* must reload the rounded f32 */
        "fstpl %0\n"
        : "=m"(out), "=m"(f)
        : "m"(third));
    return out;                /* (double)(float)(1/3) */
}

/* ==== >4 distinct operands: table eviction still yields correct reloads ==== */
static double cse_eviction(void) {
    double a = 1.0, b = 2.0, c = 3.0, d = 4.0, e = 5.0, out;
    __asm__ volatile(
        "fldl %1\n"
        "faddl %2\n"
        "faddl %3\n"
        "faddl %4\n"
        "faddl %5\n"
        "faddl %1\n"           /* a likely evicted from the 4-slot table */
        "fstpl %0\n"
        : "=m"(out)
        : "m"(a), "m"(b), "m"(c), "m"(d), "m"(e));
    return out;                /* 16.0 */
}

int main(void) {
    check("fld+fadd same operand (load CSE)", fld_fadd_same(), 3.0);

    {
        double o0, o1;
        fld_fld_same(&o0, &o1);
        check("fld+fld same operand: ST(0)", o0, 2.25);
        check("fld+fld same operand: ST(1)", o1, 2.25);
    }

    check("fild+fiadd same operand (int load CSE)", fild_fiadd_same(), 82.0);
    check("fstp+fld same operand (forwarding)", fstp_fld_forward(), 156.25);
    check("fst+fmul same operand (forwarding)", fst_fmul_forward(), 56.25);

    check_bits("NaN payload through forwarding", forward_nan_bits(),
               0x7FF8000012345678ULL);

    check("aliasing store invalidates cached load", alias_store_invalidates(), 6.0);

    {
        uint64_t expected;
        uint64_t got = fnstcw_invalidates(&expected);
        check_bits("fnstcw invalidates cached load", got, expected);
    }

    check("fistp+fild: no forwarding across int conversion",
          fistp_fild_no_forward(), 0.0);
    check("fstps+flds: no forwarding across f32 narrowing",
          fstps_flds_no_forward(), (double)(float)(1.0 / 3.0));

    check("5 operands then reuse (table eviction)", cse_eviction(), 16.0);

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
