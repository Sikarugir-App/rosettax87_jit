/*
 * test_addr32.c — 32-bit addressing (0x67 / addr_size==S32) bridge fixtures.
 *
 * 32-bit games address every memory operand with addr_size==S32; the bridge
 * demand model admits those shapes via the ADDR32 audit
 * (research/bridge_demand/ADDR32.md). These fixtures execute 0x67-prefixed
 * mov/movsd forms inside x87 runs against memory mapped below 4 GiB, so the
 * bridged path is exercised end-to-end with self-checked values.
 *
 * Built with -Wl,-pagezero_size,0x4000 so addresses < 4 GiB are mappable
 * (same pattern as test_const_promote.c); data lives at a MAP_FIXED block
 * at 0x40000000 and pointers round-trip through 32-bit registers unchanged.
 *
 * verify_demand.py fixtures: gap_addr32_mov, gap_addr32_movsd.
 *
 * Build: clang -arch x86_64 -O0 -g -Wl,-pagezero_size,0x4000 -o test_addr32 test_addr32.c
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static int failures = 0;

static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

static void check(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-52s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_u64(const char *name, uint64_t got, uint64_t expected) {
    if (got != expected) {
        printf("FAIL  %-52s  got=0x%llx  expected=0x%llx\n", name,
               (unsigned long long)got, (unsigned long long)expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

#define LOW_BASE 0x40000000UL

static uint64_t *low_block(void) {
    void *p = mmap((void *)LOW_BASE, 0x4000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (p == MAP_FAILED || (uintptr_t)p != LOW_BASE) {
        printf("FAIL  mmap below 4GiB (got %p) — pagezero not shrunk?\n", p);
        failures++;
        return NULL;
    }
    return (uint64_t *)p;
}

/* ── 0x67 movs (loads, store, SIB) inside x87 gaps ─────────────────────── */
__attribute__((noinline))
static double gap_addr32_mov(double a, double b, double c, uint64_t *lo,
                             uint64_t *ld_out, uint64_t *sib_out,
                             uint64_t *st_out) {
    double r;
    uint64_t ld = 0, sib = 0;
    lo[0] = 0x1111222233334444ull;
    lo[1] = 0x5555666677778888ull;
    lo[2] = 0xAAAABBBBCCCCDDDDull;
    lo[3] = 0;
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "movq $2, %%rdx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        /* gap 1: addr32 loads + store (base, base+disp) */
        "movq 0x8(%%esi), %%rcx\n"
        "movl (%%esi), %%r8d\n"
        "movq %%rcx, 0x18(%%esi)\n"
        "faddl %[c]\n"
        /* gap 2: addr32 SIB load */
        "movq (%%esi,%%edx,8), %%r9\n"
        "fstpl %[r]\n"
        "movq %%rcx, %[ld]\n"
        "movq %%r9, %[sib]\n"
        : [r] "=m"(r), [ld] "=m"(ld), [sib] "=m"(sib)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(lo)
        : "rsi", "rdx", "rcx", "r8", "r9", "cc", "memory");
    *ld_out = ld;
    *sib_out = sib;
    *st_out = lo[3];
    return r;
}

/* ── 0x67 alu RMW + cmp inside x87 gaps (alu-binary family) ────────────── */
__attribute__((noinline))
static double gap_addr32_alu(double a, double b, double c, uint64_t *lo,
                             uint64_t *rmw_out, uint64_t *reg_out) {
    double r;
    uint64_t reg = 0;
    lo[6] = 1000;
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "movq $7, %%rcx\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        /* gap: addr32 RMW mem dst + addr32 mem src + addr32 cmp */
        "addl $0x5, 0x30(%%esi)\n"
        "addq 0x30(%%esi), %%rcx\n"
        "cmpl (%%esi), %%ecx\n"
        "faddl %[c]\n"
        "fstpl %[r]\n"
        "movq %%rcx, %[reg]\n"
        : [r] "=m"(r), [reg] "=m"(reg)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(lo)
        : "rsi", "rcx", "cc", "memory");
    *rmw_out = lo[6];
    *reg_out = reg;
    return r;
}

/* ── 0x67 movsd load + store inside an x87 gap ─────────────────────────── */
__attribute__((noinline))
static double gap_addr32_movsd(double a, double b, double c, uint64_t *lo,
                               uint64_t *rt_out) {
    double r;
    lo[4] = as_u64(41.5);
    lo[5] = 0;
    __asm__ volatile(
        "movq %[p], %%rsi\n"
        "fldl %[a]\n"
        "fmull %[b]\n"
        /* gap: addr32 movsd round-trip (load + store) */
        "movsd 0x20(%%esi), %%xmm4\n"
        "movsd %%xmm4, 0x28(%%esi)\n"
        "faddl %[c]\n"
        "fstpl %[r]\n"
        : [r] "=m"(r)
        : [a] "m"(a), [b] "m"(b), [c] "m"(c), [p] "r"(lo)
        : "rsi", "xmm4", "cc", "memory");
    *rt_out = lo[5];
    return r;
}

int main(void) {
    const double a = 3.0, b = 4.0, c = 2.5;
    const double x87_expected = a * b + c; /* 14.5 */

    uint64_t *lo = low_block();
    if (!lo) {
        printf("\n%d failure(s)\n", failures);
        return 1;
    }

    {
        uint64_t ld = 0, sib = 0, st = 0;
        check("gap_addr32_mov: x87 result",
              gap_addr32_mov(a, b, c, lo, &ld, &sib, &st), x87_expected);
        check_u64("gap_addr32_mov: movq 0x8(%esi)", ld, 0x5555666677778888ull);
        check_u64("gap_addr32_mov: movq (%esi,%edx,8)", sib,
                  0xAAAABBBBCCCCDDDDull);
        check_u64("gap_addr32_mov: movq store 0x18(%esi)", st,
                  0x5555666677778888ull);
    }
    {
        uint64_t rt = 0;
        check("gap_addr32_movsd: x87 result",
              gap_addr32_movsd(a, b, c, lo, &rt), x87_expected);
        check_u64("gap_addr32_movsd: movsd round-trip", rt, as_u64(41.5));
    }
    {
        uint64_t rmw = 0, reg = 0;
        check("gap_addr32_alu: x87 result",
              gap_addr32_alu(a, b, c, lo, &rmw, &reg), x87_expected);
        check_u64("gap_addr32_alu: addl RMW 0x30(%esi)", rmw, 1005);
        check_u64("gap_addr32_alu: addq mem src", reg, 7 + 1005);
    }

    if (failures) {
        printf("\n%d failure(s)\n", failures);
        return 1;
    }
    printf("\nall passed\n");
    return 0;
}
