/*
 * test_f32_raw.c — Tests for first-class f32 IR (raw S-register accesses).
 *
 * Covers: f32 copy elision (fld m32 + fstp m32), f32 store→load forwarding,
 *         adjacent f32 loads/stores (LDP/STP S pairing through a shared
 *         base), f32 dot product with interleaved loads, narrow dedup
 *         (one value stored to several f32 slots), mixed f32/f64 traffic,
 *         and double-rounding correctness of forwarded f32 stores.
 *
 * Build: clang -arch x86_64 -O0 -g -o test_f32_raw test_f32_raw.c
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

/* ==== f32 copy: fld m32 + fstp m32 (no conversion should survive) ==== */
static float f32_copy(const float *src) {
    float dst;
    __asm__ volatile(
        "flds %1\n"            /* push f32 */
        "fstps %0\n"           /* store f32, pop */
        : "=m"(dst) : "m"(*src));
    return dst;
}

/* ==== f32 copy chain through two addresses ==== */
static void f32_copy_chain(const float *src, float *mid, float *dst) {
    __asm__ volatile(
        "flds %2\n"
        "fstps %0\n"           /* src → mid */
        "flds %0\n"            /* reload mid (forwarded) */
        "fstps %1\n"           /* → dst */
        : "=m"(*mid), "=m"(*dst) : "m"(*src));
}

/* ==== f32 store→load forwarding must keep the narrowed value ==== */
static double f32_store_reload_rounds(void) {
    float tmp;
    double r;
    double val = 1.0 / 3.0;    /* not representable in f32 */
    __asm__ volatile(
        "fldl %2\n"            /* full f64 precision */
        "fstps %1\n"           /* narrow to f32, store */
        "flds %1\n"            /* reload — must be the ROUNDED value */
        "fstpl %0\n"
        : "=m"(r), "=m"(tmp) : "m"(val));
    return r;
}

/* ==== forwarded f32 value feeding arithmetic ==== */
static double f32_store_reload_arith(void) {
    float tmp;
    double r;
    double val = 1.0 / 3.0;
    __asm__ volatile(
        "fldl %2\n"
        "fstps %1\n"           /* rounded to f32 */
        "flds %1\n"            /* forwarded reload */
        "fadd %%st(0), %%st(0)\n"
        "fstpl %0\n"
        : "=m"(r), "=m"(tmp) : "m"(val));
    return r;
}

/* ==== adjacent f32 loads through one base (LDP S candidate) ==== */
static float f32_vec2_sum(const float *v) {
    float r;
    __asm__ volatile(
        "flds (%1)\n"          /* v[0] */
        "flds 4(%1)\n"         /* v[1] — adjacent */
        "faddp\n"
        "fstps %0\n"
        : "=m"(r) : "r"(v));
    return r;
}

/* ==== adjacent f32 stores through one base (STP S candidate) ==== */
static void f32_vec2_fill(float *v, const float *a, const float *b) {
    __asm__ volatile(
        "flds %1\n"
        "fstps 4(%0)\n"        /* v[1] */
        "flds %2\n"
        "fstps (%0)\n"         /* v[0] — adjacent, descending */
        : : "r"(v), "m"(*a), "m"(*b) : "memory");
}

/* ==== zero-fill two adjacent f32 slots (narrow dedup + STP) ==== */
static void f32_zero_fill(float *v) {
    __asm__ volatile(
        "fldz\n"
        "fstps (%0)\n"
        "fldz\n"
        "fstps 4(%0)\n"
        : : "r"(v) : "memory");
}

/* ==== f32 dot product, interleaved loads (pairing across fmul) ==== */
static float f32_dot4(const float *a, const float *b) {
    float r;
    __asm__ volatile(
        "flds (%1)\n"
        "fmuls (%2)\n"
        "flds 4(%1)\n"
        "fmuls 4(%2)\n"
        "faddp\n"
        "flds 8(%1)\n"
        "fmuls 8(%2)\n"
        "faddp\n"
        "flds 12(%1)\n"
        "fmuls 12(%2)\n"
        "faddp\n"
        "fstps %0\n"
        : "=m"(r) : "r"(a), "r"(b));
    return r;
}

/* ==== one value stored to several f32 slots (narrow dedup) ==== */
static void f32_broadcast(float *v, const double *x) {
    __asm__ volatile(
        "fldl %1\n"
        "fsts (%0)\n"          /* non-popping stores share one narrow */
        "fsts 4(%0)\n"
        "fstps 8(%0)\n"
        : : "r"(v), "m"(*x) : "memory");
}

/* ==== mixed f32 load + f64 arithmetic + f32 store ==== */
static float f32_scale(const float *x, const double *k) {
    float r;
    __asm__ volatile(
        "flds %1\n"
        "fmull %2\n"
        "fstps %0\n"
        : "=m"(r) : "m"(*x), "m"(*k));
    return r;
}

/* ==== f32 load used twice: as copy source and as arithmetic input ==== */
static void f32_copy_and_square(const float *src, float *copy, float *sq) {
    __asm__ volatile(
        "flds %2\n"
        "fst %%st(0)\n"        /* keep value */
        "fsts %0\n"            /* raw copy */
        "fmul %%st(0), %%st(0)\n"
        "fstps %1\n"           /* rounded square */
        : "=m"(*copy), "=m"(*sq) : "m"(*src));
}

int main(void) {
    /* f32 copy elision */
    {
        float src = 0.1f;      /* inexact in binary — bits must round-trip */
        check("f32 copy: exact bit round-trip", (double)f32_copy(&src), (double)0.1f);
        float nan_src;
        uint32_t nan_bits = 0x7FC00001u;   /* quiet NaN with payload */
        memcpy(&nan_src, &nan_bits, 4);
        float nan_dst = f32_copy(&nan_src);
        uint32_t got_bits;
        memcpy(&got_bits, &nan_dst, 4);
        if (got_bits != nan_bits) {
            printf("FAIL  f32 copy: NaN payload preserved  got=%08x expected=%08x\n",
                   got_bits, nan_bits);
            failures++;
        } else {
            printf("PASS  f32 copy: NaN payload preserved\n");
        }
    }

    /* f32 copy chain */
    {
        float src = 2.5f, mid = 0, dst = 0;
        f32_copy_chain(&src, &mid, &dst);
        check("f32 copy chain: mid", (double)mid, 2.5);
        check("f32 copy chain: dst", (double)dst, 2.5);
    }

    /* store→load forwarding keeps rounding */
    check("f32 store-reload: rounded value",
          f32_store_reload_rounds(), (double)(float)(1.0 / 3.0));
    check("f32 store-reload: forwarded into arithmetic",
          f32_store_reload_arith(), 2.0 * (double)(float)(1.0 / 3.0));

    /* adjacent loads/stores */
    {
        float v[2] = {1.25f, 2.5f};
        check("f32 vec2 sum (LDP)", (double)f32_vec2_sum(v), 3.75);
    }
    {
        float v[2] = {-1, -1}, a = 7.5f, b = 8.25f;
        f32_vec2_fill(v, &a, &b);
        check("f32 vec2 fill (STP): v[0]", (double)v[0], 8.25);
        check("f32 vec2 fill (STP): v[1]", (double)v[1], 7.5);
    }
    {
        float v[2] = {-1, -1};
        f32_zero_fill(v);
        check("f32 zero fill: v[0]", (double)v[0], 0.0);
        check("f32 zero fill: v[1]", (double)v[1], 0.0);
    }

    /* dot product with interleaved loads */
    {
        float a[4] = {1, 2, 3, 4}, b[4] = {5, 6, 7, 8};
        check("f32 dot4", (double)f32_dot4(a, b), 70.0);
    }

    /* narrow dedup broadcast */
    {
        float v[3] = {0, 0, 0};
        double x = 1.0 / 3.0;
        f32_broadcast(v, &x);
        check("f32 broadcast: v[0]", (double)v[0], (double)(float)(1.0 / 3.0));
        check("f32 broadcast: v[1]", (double)v[1], (double)(float)(1.0 / 3.0));
        check("f32 broadcast: v[2]", (double)v[2], (double)(float)(1.0 / 3.0));
    }

    /* mixed width */
    {
        float x = 3.0f;
        double k = 1.0 / 3.0;
        check("f32 scale by f64", (double)f32_scale(&x, &k),
              (double)(float)(3.0 * (1.0 / 3.0)));
    }

    /* value used as both raw copy and f64 arithmetic input */
    {
        float src = 0.1f, copy = 0, sq = 0;
        f32_copy_and_square(&src, &copy, &sq);
        check("f32 copy+square: copy", (double)copy, (double)0.1f);
        check("f32 copy+square: square",
              (double)sq, (double)(float)((double)0.1f * (double)0.1f));
    }

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
