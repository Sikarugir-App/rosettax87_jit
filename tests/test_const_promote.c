/*
 * test_const_promote.c — Tests for IR constant-load promotion.
 *
 * 32-bit guests load FP literals through absolute addresses; the IR promotes
 * such loads to constants when the page is read-only. 64-bit test binaries
 * can't produce absolute x87 operands through the assembler (±2GB reach), so
 * the instructions are hand-encoded ([disp32] SIB form) against pages mmap'd
 * at a fixed low address — hence this binary links with a shrunken
 * __PAGEZERO (-pagezero_size 0x4000).
 *
 * Covers: promotion of f64/f32 loads from a read-only page (values must be
 * bit-exact), FDIV-by-power-of-two → FMUL-reciprocal, FCOM-vs-0.0 → FTST,
 * and the critical negative case: loads from a WRITABLE page must NOT be
 * promoted (value changes between calls must be observed).
 *
 * Build: clang -arch x86_64 -O0 -g -Wl,-pagezero_size,0x4000 -o ...
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

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

/* RO block at 0x40000000 (16 KB), RW block at 0x40004000. */
#define RO_BASE 0x40000000UL
#define RW_BASE 0x40004000UL

static const double kPi = 3.141592653589793;

static int setup_pages(void) {
    void *p = mmap((void *)RO_BASE, 0x8000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (p != (void *)RO_BASE) {
        printf("FAIL  mmap at %#lx returned %p\n", RO_BASE, p);
        return 0;
    }
    double *d = (double *)RO_BASE;
    d[0] = 2.5;   /* +0  — FMOV-imm8-representable */
    d[1] = kPi;   /* +8  — literal-pool constant  */
    d[2] = 8.0;   /* +16 — power-of-two divisor   */
    float f = 1.5f;
    memcpy((void *)(RO_BASE + 24), &f, 4);  /* +24 — f32 constant */
    d[4] = 0.0;   /* +32 — zero for FCOM→FTST     */
    *(double *)RW_BASE = 5.0;
    if (mprotect((void *)RO_BASE, 0x4000, PROT_READ) != 0) {
        printf("FAIL  mprotect\n");
        return 0;
    }
    return 1;
}

/* fldl [0x40000000] (2.5); fmull [0x40000008] (pi) — both promoted. */
static double mul_ro_consts(void) {
    double out;
    __asm__ volatile(
        ".byte 0xDD,0x04,0x25,0x00,0x00,0x00,0x40\n\t"  /* fldl  [RO+0]  */
        ".byte 0xDC,0x0C,0x25,0x08,0x00,0x00,0x40\n\t"  /* fmull [RO+8]  */
        "fstpl %0\n"
        : "=m"(out));
    return out;
}

/* x / 8.0 with the divisor in the RO page → FMUL by 0.125 (exact). */
static double div_by_ro_pow2(double x) {
    double out;
    __asm__ volatile(
        "fldl %1\n\t"
        ".byte 0xDC,0x34,0x25,0x10,0x00,0x00,0x40\n\t"  /* fdivl [RO+16] */
        "fstpl %0\n"
        : "=m"(out) : "m"(x));
    return out;
}

/* flds [RO+24] (1.5f) — f32 promotion widens at translate time. */
static double load_ro_f32(void) {
    double out;
    __asm__ volatile(
        ".byte 0xD9,0x04,0x25,0x18,0x00,0x00,0x40\n\t"  /* flds  [RO+24] */
        "faddl %1\n\t"
        "fstpl %0\n"
        : "=m"(out) : "m"((double){0.25}));
    return out;
}

/* fcompl [RO+32] (0.0) → FTst; returns masked CC bits. */
static uint16_t cmp_ro_zero(double x) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n\t"
        ".byte 0xDC,0x1C,0x25,0x20,0x00,0x00,0x40\n\t"  /* fcompl [RO+32] */
        "fnstsw %%ax\n\t"
        "andw $0x4500, %%ax\n\t"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(x) : "ax", "cc");
    return sw;
}

/* fldl [RW] — page is writable: must NOT be promoted, must see live value. */
static double load_rw(void) {
    double out;
    __asm__ volatile(
        ".byte 0xDD,0x04,0x25,0x00,0x40,0x00,0x40\n\t"  /* fldl [RW+0]  */
        "faddl %1\n\t"
        "fstpl %0\n"
        : "=m"(out) : "m"((double){1.0}));
    return out;
}

int main(void) {
    if (!setup_pages()) {
        printf("\n1 failure(s)\n");
        return 1;
    }

    check("mul of two RO consts (2.5 * pi)", mul_ro_consts(), 2.5 * kPi);
    check("div by RO power of two (7/8)", div_by_ro_pow2(7.0), 0.875);
    check("div by RO power of two (-3/8)", div_by_ro_pow2(-3.0), -0.375);
    check("f32 RO const widened (1.5 + 0.25)", load_ro_f32(), 1.75);

    {
        uint16_t gt = cmp_ro_zero(2.0);   /* ST(0) > 0 → 0x0000 */
        uint16_t lt = cmp_ro_zero(-2.0);  /* ST(0) < 0 → 0x0100 */
        uint16_t eq = cmp_ro_zero(0.0);   /* equal    → 0x4000 */
        check("fcom vs RO zero: greater", (double)gt, 0.0);
        check("fcom vs RO zero: less", (double)lt, (double)0x0100);
        check("fcom vs RO zero: equal", (double)eq, (double)0x4000);
    }

    /* Writable page: change the value between calls — a wrong promotion
     * would freeze the first value into the translated code. */
    check("RW load, first value", load_rw(), 6.0);
    *(volatile double *)RW_BASE = 42.0;
    check("RW load, after modification", load_rw(), 43.0);
    *(volatile double *)RW_BASE = -7.5;
    check("RW load, after second modification", load_rw(), -6.5);

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
