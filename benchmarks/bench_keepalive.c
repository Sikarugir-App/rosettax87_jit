/*
 * bench_keepalive.c -- OPT-KA: transcendentals embedded in x87 runs.
 *
 * Each shape sandwiches a runtime-routine transcendental between inline x87
 * work, the pattern OPT-KA (ROSETTA_X87_RUNTIME_KEEPALIVE=1) targets: with
 * keepalive off the run breaks at the transcendental and the cache
 * re-materializes cold after the BL; with it on the pins survive.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

/* sin inside an arithmetic run (game-typical: angle math around a trig call) */
static clock_t bench_sin_in_run(void) {
    clock_t start = clock();
    volatile double a = 0.5, b = 3.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"
            "fldl %2\n\t"
            "fsin\n\t"
            "fmulp\n\t"
            "fldl %1\n\t"
            "faddp\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(b), "m"(a));
    return clock() - start;
}

/* sin+cos of the same angle via two runs' worth of inline ops around BLs */
static clock_t bench_sincos_pair(void) {
    clock_t start = clock();
    volatile double a = 0.6;
    volatile double s, c;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %2\n\t"
            "fsincos\n\t"
            "fstpl %1\n\t"
            "fstpl %0\n"
            : "=m"(s), "=m"(c) : "m"(a));
    return clock() - start;
}

/* fptan with post-BL arithmetic through the cached TOP */
static clock_t bench_ptan_faddp(void) {
    clock_t start = clock();
    volatile double a = 0.3;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"
            "fptan\n\t"
            "faddp\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(a));
    return clock() - start;
}

/* fyl2x (pop) followed by inline arithmetic */
static clock_t bench_yl2x(void) {
    clock_t start = clock();
    volatile double y = 3.0, x = 8.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"
            "fldl %2\n\t"
            "fyl2x\n\t"
            "fld1\n\t"
            "faddp\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(y), "m"(x));
    return clock() - start;
}

/* fscale sandwiched in a longer inline run */
static clock_t bench_fscale(void) {
    clock_t start = clock();
    volatile double v = 1.5, e = 3.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"
            "fldl %2\n\t"
            "fscale\n\t"
            "fstpl %0\n\t"
            "fstp %%st(0)\n"
            : "=m"(r) : "m"(e), "m"(v));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"sin_in_run",  bench_sin_in_run},
        {"sincos_pair", bench_sincos_pair},
        {"ptan_faddp",  bench_ptan_faddp},
        {"yl2x",        bench_yl2x},
        {"fscale",      bench_fscale},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
