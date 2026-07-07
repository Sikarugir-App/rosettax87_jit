/*
 * bench_f32.c -- Benchmark for first-class f32 IR (raw S-register accesses).
 *
 * Kernels mirror the dominant f32 (dword) game-profile patterns: float
 * copies, float dot products, vector fills and store→reload traffic.
 * The decomposed IR elides widen/narrow FCVTs on pure copies, forwards
 * f32 stores to later reloads, and pairs adjacent S-register accesses
 * into LDP/STP.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 2000000
#define RUNS  5

static float fa[4] = {1.0f, 2.0f, 3.0f, 4.0f};
static float fb[4] = {0.5f, 0.25f, 2.0f, 1.5f};

/* f32 dot4 through two bases — flds|fmuls|flds|fmuls|faddp. */
static clock_t bench_dot4_f32(void) {
    clock_t start = clock();
    volatile float r;
    const float *p = fa, *q = fb;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "flds (%1)\n\t"
            "fmuls (%2)\n\t"
            "flds 4(%1)\n\t"
            "fmuls 4(%2)\n\t"
            "faddp\n\t"
            "flds 8(%1)\n\t"
            "fmuls 8(%2)\n\t"
            "faddp\n\t"
            "flds 12(%1)\n\t"
            "fmuls 12(%2)\n\t"
            "faddp\n\t"
            "fstps %0\n"
            : "=m"(r) : "r"(p), "r"(q));
    return clock() - start;
}

/* Pure float copies through one base pair — fld|fstp with no arithmetic. */
static clock_t bench_copy4_f32(void) {
    clock_t start = clock();
    float dst[4];
    const float *p = fa;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "flds (%1)\n\t   fstps (%0)\n\t"
            "flds 4(%1)\n\t  fstps 4(%0)\n\t"
            "flds 8(%1)\n\t  fstps 8(%0)\n\t"
            "flds 12(%1)\n\t fstps 12(%0)\n"
            : : "r"(dst), "r"(p) : "memory");
    return clock() - start;
}

/* Vector scale in place: f32 load / f64-const mul / f32 store. */
static clock_t bench_scale4_f32(void) {
    clock_t start = clock();
    float buf[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float s = 1.0000001f;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "flds (%0)\n\t   fmuls %1\n\t fstps (%0)\n\t"
            "flds 4(%0)\n\t  fmuls %1\n\t fstps 4(%0)\n\t"
            "flds 8(%0)\n\t  fmuls %1\n\t fstps 8(%0)\n\t"
            "flds 12(%0)\n\t fmuls %1\n\t fstps 12(%0)\n"
            : : "r"(buf), "m"(s) : "memory");
    return clock() - start;
}

/* Zero-fill four adjacent f32 slots — fldz|fstps chains. */
static clock_t bench_zero4_f32(void) {
    clock_t start = clock();
    float buf[4];
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldz\n\t fstps (%0)\n\t"
            "fldz\n\t fstps 4(%0)\n\t"
            "fldz\n\t fstps 8(%0)\n\t"
            "fldz\n\t fstps 12(%0)\n"
            : : "r"(buf) : "memory");
    return clock() - start;
}

/* f32 store then reload of the same slot — fstps|flds forwarding. */
static clock_t bench_store_reload_f32(void) {
    clock_t start = clock();
    float tmp;
    volatile float r;
    const float *p = fa;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "flds (%2)\n\t"
            "fmuls 4(%2)\n\t"
            "fstps %1\n\t"
            "flds %1\n\t"
            "fmuls 8(%2)\n\t"
            "fstps %0\n"
            : "=m"(r), "=m"(tmp) : "r"(p));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"dot4_f32",         bench_dot4_f32},
        {"copy4_f32",        bench_copy4_f32},
        {"scale4_f32",       bench_scale4_f32},
        {"zero4_f32",        bench_zero4_f32},
        {"store_reload_f32", bench_store_reload_f32},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %-20s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
