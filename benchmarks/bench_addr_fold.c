/*
 * bench_addr_fold.c -- Benchmark for IR base-address caching + disp folding.
 *
 * Kernels mirror the dominant game-profile patterns: dot products and
 * vector/matrix element traffic through one or two shared guest base
 * registers ([reg+disp]).  Without folding every access pays an address
 * ADD + scratch GPR before the LDR/STR; with folding the base register is
 * used directly with an immediate offset.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 2000000
#define RUNS  5

static double va[4] = {1.0, 2.0, 3.0, 4.0};
static double vb[4] = {0.5, 0.25, 2.0, 1.5};

/* dot4 through two pointer bases — the fld|fmul|fld|fmul|faddp shape. */
static clock_t bench_dot4_two_bases(void) {
    clock_t start = clock();
    volatile double r;
    const double *p = va, *q = vb;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl (%1)\n\t"
            "fmull (%2)\n\t"
            "fldl 8(%1)\n\t"
            "fmull 8(%2)\n\t"
            "faddp\n\t"
            "fldl 16(%1)\n\t"
            "fmull 16(%2)\n\t"
            "faddp\n\t"
            "fldl 24(%1)\n\t"
            "fmull 24(%2)\n\t"
            "faddp\n\t"
            "fstpl %0\n"
            : "=m"(r) : "r"(p), "r"(q));
    return clock() - start;
}

/* Strided store fill through one base — the fstp|fstp struct-fill shape. */
static clock_t bench_fill4_stride(void) {
    clock_t start = clock();
    double buf[4];
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldz\n\t fstpl (%0)\n\t"
            "fld1\n\t fstpl 8(%0)\n\t"
            "fldz\n\t fstpl 16(%0)\n\t"
            "fld1\n\t fstpl 24(%0)\n"
            : : "r"(buf) : "memory");
    return clock() - start;
}

/* Vector scale in place: load/mul/store per element through one base. */
static clock_t bench_scale4_inplace(void) {
    clock_t start = clock();
    double buf[4] = {1.0, 2.0, 3.0, 4.0};
    double s = 1.0000001;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl (%0)\n\t  fmull %1\n\t  fstpl (%0)\n\t"
            "fldl 8(%0)\n\t fmull %1\n\t  fstpl 8(%0)\n\t"
            "fldl 16(%0)\n\t fmull %1\n\t fstpl 16(%0)\n\t"
            "fldl 24(%0)\n\t fmull %1\n\t fstpl 24(%0)\n"
            : : "r"(buf), "m"(s) : "memory");
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"dot4_two_bases", bench_dot4_two_bases},
        {"fill4_stride",   bench_fill4_stride},
        {"scale4_inplace", bench_scale4_inplace},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %-20s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
