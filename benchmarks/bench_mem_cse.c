/*
 * bench_mem_cse.c -- Benchmark for IR memory-load CSE + store->load forwarding.
 *
 * The IR build dedups Load* nodes for identical memory operands within a run
 * and forwards StoreF64 values to later LoadF64s of the same operand.  Each
 * kernel packs many repeated-operand accesses into a single x87 run so the
 * saved address computations + LDRs accumulate per translated block.
 *
 * Compare against a runtime built without the CSE table to measure benefit.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 2000000
#define RUNS  5

/* --------------------------------------------------------------------------
 * Repeated load: FLD a + 8x FADD a in one run.
 * CSE collapses 9 loads of `a` (addr computation + LDR each) into 1.
 * -------------------------------------------------------------------------- */
static clock_t bench_repeat_add_8x(void) {
    clock_t start = clock();
    volatile double r;
    double a = 1.25;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"
            "faddl %1\n\t"
            "faddl %1\n\t"
            "faddl %1\n\t"
            "faddl %1\n\t"
            "faddl %1\n\t"
            "faddl %1\n\t"
            "faddl %1\n\t"
            "faddl %1\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(a));
    return clock() - start;
}

/* --------------------------------------------------------------------------
 * Horner polynomial of degree 4: x is re-read by every FMUL.
 * Classic compiled-FP pattern; CSE collapses 4 loads of x into 1.
 * -------------------------------------------------------------------------- */
static clock_t bench_horner_4(void) {
    clock_t start = clock();
    volatile double r;
    double x = 1.0009765625;
    double c4 = 3.0, c3 = -2.0, c2 = 5.0, c1 = -7.0, c0 = 11.0;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"          /* c4 */
            "fmull %2\n\t"         /* * x */
            "faddl %3\n\t"         /* + c3 */
            "fmull %2\n\t"         /* * x  -- CSE hit */
            "faddl %4\n\t"         /* + c2 */
            "fmull %2\n\t"         /* * x  -- CSE hit */
            "faddl %5\n\t"         /* + c1 */
            "fmull %2\n\t"         /* * x  -- CSE hit */
            "faddl %6\n\t"         /* + c0 */
            "fstpl %0\n"
            : "=m"(r)
            : "m"(c4), "m"(x), "m"(c3), "m"(c2), "m"(c1), "m"(c0));
    return clock() - start;
}

/* --------------------------------------------------------------------------
 * Store->reload chain: each intermediate is spilled and immediately
 * reloaded (x87 register-starved codegen pattern).  Forwarding removes
 * every reload (addr computation + LDR).
 * -------------------------------------------------------------------------- */
static clock_t bench_store_reload(void) {
    clock_t start = clock();
    double t = 0.0;
    double a = 1.5, b = 1.0625;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"
            "fmull %2\n\t"
            "fstpl %0\n\t"         /* spill intermediate */
            "fldl %0\n\t"          /* reload -- forwarded */
            "fmull %2\n\t"
            "fstpl %0\n\t"
            "fldl %0\n\t"          /* forwarded */
            "fmull %2\n\t"
            "fstpl %0\n\t"
            "fldl %0\n\t"          /* forwarded */
            "fmull %2\n\t"
            "fstpl %0\n"
            : "+m"(t) : "m"(a), "m"(b));
    return clock() - start;
}

/* --------------------------------------------------------------------------
 * Memory accumulator: acc += v[i] with acc kept in memory
 * (FLD acc / FADD vi / FSTP acc repeated).  Every FLD after the first
 * forwards from the preceding FSTP.
 * -------------------------------------------------------------------------- */
static clock_t bench_mem_accum(void) {
    clock_t start = clock();
    double acc = 0.0;
    double v0 = 0.25, v1 = 0.5, v2 = 0.75, v3 = 1.0;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %0\n\t  faddl %1\n\t  fstpl %0\n\t"
            "fldl %0\n\t  faddl %2\n\t  fstpl %0\n\t"   /* fld forwarded */
            "fldl %0\n\t  faddl %3\n\t  fstpl %0\n\t"   /* fld forwarded */
            "fldl %0\n\t  faddl %4\n\t  fstpl %0\n"     /* fld forwarded */
            : "+m"(acc) : "m"(v0), "m"(v1), "m"(v2), "m"(v3));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"repeat_add_8x", bench_repeat_add_8x},
        {"horner_4",      bench_horner_4},
        {"store_reload",  bench_store_reload},
        {"mem_accum",     bench_mem_accum},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %-20s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
