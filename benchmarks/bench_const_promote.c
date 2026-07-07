/*
 * bench_const_promote.c -- Benchmark for IR constant-load promotion.
 *
 * FP literals loaded through absolute addresses in a read-only page are
 * promoted to constants at translation time (FMOV imm8 / literal pool, no
 * runtime load); FDIV by a power-of-two constant becomes FMUL by the
 * reciprocal.  Compare against ROSETTA_X87_DISABLE_CONST_PROMOTE=1.
 *
 * Links with -pagezero_size 0x4000 so pages below 2 GB can be mapped
 * (absolute [disp32] x87 operands are hand-encoded).
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>

#define TIMES 2000000
#define RUNS  5

#define RO_BASE 0x40000000UL

static int setup_pages(void) {
    void *p = mmap((void *)RO_BASE, 0x4000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (p != (void *)RO_BASE) return 0;
    double *d = (double *)RO_BASE;
    d[0] = 2.0;               /* +0  imm8 */
    d[1] = 0.5;               /* +8  imm8 */
    d[2] = 1.0009765625;      /* +16 literal */
    d[3] = 0.9990234375;      /* +24 literal */
    d[4] = 8.0;               /* +32 pow2 divisor */
    d[5] = 4.0;               /* +40 pow2 divisor */
    d[6] = 8.0009765625;      /* +48 rescale to keep x in range */
    mprotect((void *)RO_BASE, 0x4000, PROT_READ);
    return 1;
}

/* Chain of multiplies by four RO constants (2 imm8, 2 literal). */
static clock_t bench_mul_const_chain(void) {
    clock_t start = clock();
    volatile double r;
    double x = 1.5;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            ".byte 0xDC,0x0C,0x25,0x00,0x00,0x00,0x40\n\t"  /* fmull [RO+0]  */
            ".byte 0xDC,0x0C,0x25,0x08,0x00,0x00,0x40\n\t"  /* fmull [RO+8]  */
            ".byte 0xDC,0x0C,0x25,0x10,0x00,0x00,0x40\n\t"  /* fmull [RO+16] */
            ".byte 0xDC,0x0C,0x25,0x18,0x00,0x00,0x40\n\t"  /* fmull [RO+24] */
            "fstpl %0\n"
            : "=m"(r) : "m"(x));
    return clock() - start;
}

/* Loop-carried divide chain: x = (x / 8) * 8.0009765625 each iteration.
 * The serial dependency exposes FDIV vs FMUL latency once the divide is
 * promoted to a reciprocal multiply. */
static clock_t bench_div_pow2_chain(void) {
    clock_t start = clock();
    double x = 1234.5;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %0\n\t"
            ".byte 0xDC,0x34,0x25,0x20,0x00,0x00,0x40\n\t"  /* fdivl [RO+32] */
            ".byte 0xDC,0x0C,0x25,0x30,0x00,0x00,0x40\n\t"  /* fmull [RO+48] */
            "fstpl %0\n"
            : "+m"(x));
    return clock() - start;
}

int main(void) {
    if (!setup_pages()) {
        printf("BENCH setup_failed 0\n");
        return 1;
    }
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"mul_const_chain", bench_mul_const_chain},
        {"div_pow2_chain",  bench_div_pow2_chain},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %-20s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
