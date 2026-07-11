/*
 * bench_interleaved_mov.c -- Baseline for item 01 (run-transparent integers).
 *
 * The game's hot x87 profile is f32-dominant memory-arith chains
 * (fld|fmul / fmul|fstp) that real code interleaves with trivial integer
 * instructions (address math, loop counters). Each interleaved mov/lea
 * TODAY ends the x87 run: the first half pays the IR epilogue writeback and
 * the second half pays the full prologue (base ADD, TOP reload, ReadSt).
 *
 * This bench establishes a BEFORE baseline for that split pattern so a future
 * Phase 1 (ROSETTA_X87_RUN_BRIDGE) / Phase 2 (ROSETTA_X87_TRANSPARENT_INT) can
 * be measured against it. Phase 0 itself changes no codegen, so numbers here
 * should be flat vs. HEAD; they exist to be re-run after Phase 1/2.
 *
 * Run under ROSETTA_X87_LOG_RUN_BREAKS=1 to see the run-break telemetry these
 * patterns generate.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 2000000
#define RUNS  5

/* --------------------------------------------------------------------------
 * f32 compute split by a mov to an UNRELATED register.
 * Pattern: flds|fmuls|mov ecx|fstps, repeated — each mov ends a run.
 * -------------------------------------------------------------------------- */
static clock_t bench_f32_mov_unrelated(void) {
    clock_t start = clock();
    volatile float r;
    float a = 1.5f, b = 2.0f;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "flds %1\n\t fmuls %2\n\t movl $1, %%ecx\n\t fstps %0\n\t"
            "flds %1\n\t fmuls %2\n\t movl $2, %%ecx\n\t fstps %0\n\t"
            "flds %1\n\t fmuls %2\n\t movl $3, %%ecx\n\t fstps %0\n\t"
            "flds %1\n\t fmuls %2\n\t movl $4, %%ecx\n\t fstps %0\n\t"
            "flds %1\n\t fmuls %2\n\t movl $5, %%ecx\n\t fstps %0\n\t"
            "flds %1\n\t fmuls %2\n\t movl $6, %%ecx\n\t fstps %0\n\t"
            "flds %1\n\t fmuls %2\n\t movl $7, %%ecx\n\t fstps %0\n\t"
            "flds %1\n\t fmuls %2\n\t movl $8, %%ecx\n\t fstps %0\n\t"
            : "=m"(r) : "m"(a), "m"(b) : "ecx");
    return clock() - start;
}

/* --------------------------------------------------------------------------
 * f64 compute split by a mov to a register used as the BASE of the next
 * x87 memory operand (the harder correctness case for Phase 2).
 * -------------------------------------------------------------------------- */
static clock_t bench_f64_mov_base(void) {
    clock_t start = clock();
    volatile double r;
    double slot0 = 3.0, slot1 = 5.0;
    double *p0 = &slot0, *p1 = &slot1;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "movq %3, %%rdx\n\t fldl (%%rdx)\n\t"
            "movq %4, %%rdx\n\t faddl (%%rdx)\n\t"
            "movq %3, %%rdx\n\t fmull (%%rdx)\n\t"
            "movq %4, %%rdx\n\t fsubl (%%rdx)\n\t"
            "fstpl %0\n\t"
            : "=m"(r) : "m"(slot0), "m"(slot1), "r"(p0), "r"(p1)
            : "rdx");
    return clock() - start;
}

/* --------------------------------------------------------------------------
 * f32 compute split by lea (address recompute) between accumulation steps.
 * -------------------------------------------------------------------------- */
static clock_t bench_f32_lea_split(void) {
    clock_t start = clock();
    volatile float r;
    float buf[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float *base = buf;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "movq %1, %%rsi\n\t"
            "flds (%%rsi)\n\t"
            "leaq 4(%%rsi), %%rsi\n\t fadds (%%rsi)\n\t"
            "leaq 4(%%rsi), %%rsi\n\t fadds (%%rsi)\n\t"
            "leaq 4(%%rsi), %%rsi\n\t fadds (%%rsi)\n\t"
            "fstps %0\n\t"
            : "=m"(r) : "r"(base)
            : "rsi", "memory");
    return clock() - start;
}

/* --------------------------------------------------------------------------
 * f32 x87 compute split by SSE moves (whitelist v2) — the dominant breaker
 * in mixed x87/SSE game code per run-break telemetry (movss/movsd).
 * -------------------------------------------------------------------------- */
static clock_t bench_f32_sse_mix(void) {
    clock_t start = clock();
    volatile float r;
    volatile float s;
    float a = 1.5f, b = 2.0f;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "flds %2\n\t fmuls %3\n\t movss %2, %%xmm1\n\t fstps %0\n\t"
            "flds %2\n\t fmuls %3\n\t movss %%xmm1, %1\n\t fstps %0\n\t"
            "flds %2\n\t fmuls %3\n\t movss %2, %%xmm1\n\t fstps %0\n\t"
            "flds %2\n\t fmuls %3\n\t movss %%xmm1, %1\n\t fstps %0\n\t"
            "flds %2\n\t fmuls %3\n\t movss %2, %%xmm1\n\t fstps %0\n\t"
            "flds %2\n\t fmuls %3\n\t movss %%xmm1, %1\n\t fstps %0\n\t"
            "flds %2\n\t fmuls %3\n\t movss %2, %%xmm1\n\t fstps %0\n\t"
            "flds %2\n\t fmuls %3\n\t movss %%xmm1, %1\n\t fstps %0\n\t"
            : "=m"(r), "=m"(s) : "m"(a), "m"(b) : "xmm1");
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"f32_mov_unrelated", bench_f32_mov_unrelated},
        {"f64_mov_base",      bench_f64_mov_base},
        {"f32_lea_split",     bench_f32_lea_split},
        {"f32_sse_mix",       bench_f32_sse_mix},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %-20s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
