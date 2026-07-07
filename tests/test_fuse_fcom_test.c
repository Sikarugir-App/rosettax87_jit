/*
 * test_fuse_fcom_test.c -- validate the fcomp+fnstsw+test => FCMP+CSET+TST
 * fusion (ROSETTA_X87_FUSE_FCOM_TEST=1) and its bail conditions.
 *
 * Build:  clang -arch x86_64 -O0 -g -o test_fuse_fcom_test test_fuse_fcom_test.c
 *
 * Every function performs an x87 compare, reads the status word via
 * FNSTSW AX, masks the CC bits with TEST (or AND), and branches. Each is
 * exercised with operands producing all four compare outcomes (>, <, =,
 * unordered), so both the fused and unfused lowerings must produce identical
 * branch decisions. Cases that must NOT fuse (parity-flag consumer, AL mask,
 * AND variant, non-adjacent test) guard the fusion's bail conditions.
 *
 * Known accepted trade with fusion ON (not tested here, by design): after a
 * fused test, guest AX does NOT hold the status word. Real code never reads
 * it after the test; code that does must run with the flag off.
 */

#include <stdint.h>
#include <stdio.h>

static int failures = 0;

static void check_u8(const char *name, uint8_t got, uint8_t expected) {
    if (got != expected) {
        printf("FAIL  %-60s  got=%u  expected=%u\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static const double kNan = __builtin_nan("");

/* ── test ah, 0x41 ; jz  → taken iff ST(0) > src (ordered) ─────────────── */
static uint8_t gt_jz(double a, double b) {
    uint8_t r;
    __asm__ volatile (
        "fldl %1\n\t"
        "fcompl %2\n\t"
        "fnstsw %%ax\n\t"
        "testb $0x41, %%ah\n\t"
        "jz 1f\n\t"
        "movb $0, %0\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "movb $1, %0\n"
        "2:\n"
        : "=r"(r) : "m"(a), "m"(b) : "ax", "cc", "st");
    return r;
}

/* ── test ah, 0x41 ; jnz → taken iff below-or-equal-or-unordered ───────── */
static uint8_t be_jnz(double a, double b) {
    uint8_t r;
    __asm__ volatile (
        "fldl %1\n\t"
        "fcompl %2\n\t"
        "fnstsw %%ax\n\t"
        "testb $0x41, %%ah\n\t"
        "jnz 1f\n\t"
        "movb $0, %0\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "movb $1, %0\n"
        "2:\n"
        : "=r"(r) : "m"(a), "m"(b) : "ax", "cc", "st");
    return r;
}

/* ── test ah, 0x01 ; jnz → taken iff below-or-unordered (C0) ───────────── */
static uint8_t b_jnz(double a, double b) {
    uint8_t r;
    __asm__ volatile (
        "fldl %1\n\t"
        "fcompl %2\n\t"
        "fnstsw %%ax\n\t"
        "testb $0x01, %%ah\n\t"
        "jnz 1f\n\t"
        "movb $0, %0\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "movb $1, %0\n"
        "2:\n"
        : "=r"(r) : "m"(a), "m"(b) : "ax", "cc", "st");
    return r;
}

/* ── test ah, 0x45 ; jnz → taken iff NOT greater ───────────────────────── */
static uint8_t ngt_jnz(double a, double b) {
    uint8_t r;
    __asm__ volatile (
        "fldl %1\n\t"
        "fcompl %2\n\t"
        "fnstsw %%ax\n\t"
        "testb $0x45, %%ah\n\t"
        "jnz 1f\n\t"
        "movb $0, %0\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "movb $1, %0\n"
        "2:\n"
        : "=r"(r) : "m"(a), "m"(b) : "ax", "cc", "st");
    return r;
}

/* ── test ax, 0x4500 ; sete → 1 iff greater (ordered) ──────────────────── */
static uint8_t gt_sete_ax(double a, double b) {
    uint8_t r;
    __asm__ volatile (
        "fldl %1\n\t"
        "fcompl %2\n\t"
        "fnstsw %%ax\n\t"
        "testw $0x4500, %%ax\n\t"
        "sete %0\n"
        : "=r"(r) : "m"(a), "m"(b) : "ax", "cc", "st");
    return r;
}

/* ── MUST NOT FUSE: and ah, 0x45 writes AH (may be re-read, e.g. MSVC's
 *    and ah,0x45; cmp ah,0x40 multiway idiom) — only TEST fuses ─────────── */
static uint8_t gt_and_jz(double a, double b) {
    uint8_t r;
    __asm__ volatile (
        "fldl %1\n\t"
        "fcompl %2\n\t"
        "fnstsw %%ax\n\t"
        "andb $0x45, %%ah\n\t"
        "jz 1f\n\t"
        "movb $0, %0\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "movb $1, %0\n"
        "2:\n"
        : "=r"(r) : "m"(a), "m"(b) : "ax", "cc", "st");
    return r;
}

/* ── fucompp path: compare ST(0) vs ST(1), double pop ──────────────────── */
static uint8_t fucompp_be_jnz(double a, double b) {
    uint8_t r;
    __asm__ volatile (
        "fldl %2\n\t"          /* ST(1) = b */
        "fldl %1\n\t"          /* ST(0) = a */
        "fucompp\n\t"
        "fnstsw %%ax\n\t"
        "testb $0x41, %%ah\n\t"
        "jnz 1f\n\t"
        "movb $0, %0\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "movb $1, %0\n"
        "2:\n"
        : "=r"(r) : "m"(a), "m"(b) : "ax", "cc", "st");
    return r;
}

/* ── MUST NOT FUSE: test ah, 0x44 ; jp — the classic != idiom (reads PF) ─ */
/* taken iff equal-or-ordered-nonequal... concretely: PF = parity of AH&0x44:
 * gt/lt → 0x00 (PF=1, taken), eq → 0x40 (PF=0, not taken), unord → 0x44
 * (PF=1, taken).  I.e. "jp" here means NOT equal (unordered counts as neq). */
static uint8_t neq_jp(double a, double b) {
    uint8_t r;
    __asm__ volatile (
        "fldl %1\n\t"
        "fcompl %2\n\t"
        "fnstsw %%ax\n\t"
        "testb $0x44, %%ah\n\t"
        "jp 1f\n\t"
        "movb $0, %0\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "movb $1, %0\n"
        "2:\n"
        : "=r"(r) : "m"(a), "m"(b) : "ax", "cc", "st");
    return r;
}

/* ── MUST NOT FUSE: mask hits AL (exception bits), not the CC bits ───────
 * fnclex first: AL holds the sticky exception byte, which earlier NaN
 * compares set under native Rosetta (the custom runtime doesn't model it). */
static uint8_t al_mask_jz(double a, double b) {
    uint8_t r;
    __asm__ volatile (
        "fnclex\n\t"
        "fldl %1\n\t"
        "fcompl %2\n\t"
        "fnstsw %%ax\n\t"
        "testb $0x45, %%al\n\t"
        "jz 1f\n\t"
        "movb $0, %0\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "movb $1, %0\n"
        "2:\n"
        : "=r"(r) : "m"(a), "m"(b) : "ax", "cc", "st");
    return r;
}

/* ── MUST NOT FUSE: test not adjacent to fnstsw ────────────────────────── */
static uint8_t nonadjacent_gt_jz(double a, double b) {
    uint8_t r;
    uint32_t scratch;
    __asm__ volatile (
        "fldl %2\n\t"
        "fcompl %3\n\t"
        "fnstsw %%ax\n\t"
        "movl $7, %1\n\t"      /* flag-neutral filler between fnstsw and test */
        "testb $0x41, %%ah\n\t"
        "jz 1f\n\t"
        "movb $0, %0\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "movb $1, %0\n"
        "2:\n"
        : "=r"(r), "=r"(scratch) : "m"(a), "m"(b) : "ax", "cc", "st");
    return r;
}

/* ── AND consumer with AX read back afterward — AND never fuses, so the
 *    full status-word CC mask must round-trip through AX intact. ─────────── */
static uint16_t ax_readback(double a, double b) {
    uint16_t sw;
    __asm__ volatile (
        "fldl %1\n\t"
        "fcompl %2\n\t"
        "fnstsw %%ax\n\t"
        "andw $0x4500, %%ax\n\t"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(a), "m"(b) : "ax", "cc", "st");
    return sw;
}

int main(void) {
    /* gt_jz: taken (r=1) iff a > b ordered */
    check_u8("gt_jz  3>1", gt_jz(3.0, 1.0), 1);
    check_u8("gt_jz  1<3", gt_jz(1.0, 3.0), 0);
    check_u8("gt_jz  2=2", gt_jz(2.0, 2.0), 0);
    check_u8("gt_jz  nan", gt_jz(kNan, 1.0), 0);

    check_u8("be_jnz 3>1", be_jnz(3.0, 1.0), 0);
    check_u8("be_jnz 1<3", be_jnz(1.0, 3.0), 1);
    check_u8("be_jnz 2=2", be_jnz(2.0, 2.0), 1);
    check_u8("be_jnz nan", be_jnz(kNan, 1.0), 1);

    check_u8("b_jnz  3>1", b_jnz(3.0, 1.0), 0);
    check_u8("b_jnz  1<3", b_jnz(1.0, 3.0), 1);
    check_u8("b_jnz  2=2", b_jnz(2.0, 2.0), 0);
    check_u8("b_jnz  nan", b_jnz(kNan, 1.0), 1);

    check_u8("ngt_jnz 3>1", ngt_jnz(3.0, 1.0), 0);
    check_u8("ngt_jnz 1<3", ngt_jnz(1.0, 3.0), 1);
    check_u8("ngt_jnz 2=2", ngt_jnz(2.0, 2.0), 1);
    check_u8("ngt_jnz nan", ngt_jnz(kNan, 1.0), 1);

    check_u8("gt_sete_ax 3>1", gt_sete_ax(3.0, 1.0), 1);
    check_u8("gt_sete_ax 1<3", gt_sete_ax(1.0, 3.0), 0);
    check_u8("gt_sete_ax 2=2", gt_sete_ax(2.0, 2.0), 0);
    check_u8("gt_sete_ax nan", gt_sete_ax(kNan, 1.0), 0);

    check_u8("gt_and_jz 3>1", gt_and_jz(3.0, 1.0), 1);
    check_u8("gt_and_jz 1<3", gt_and_jz(1.0, 3.0), 0);
    check_u8("gt_and_jz 2=2", gt_and_jz(2.0, 2.0), 0);
    check_u8("gt_and_jz nan", gt_and_jz(kNan, 1.0), 0);

    check_u8("fucompp_be_jnz 3>1", fucompp_be_jnz(3.0, 1.0), 0);
    check_u8("fucompp_be_jnz 1<3", fucompp_be_jnz(1.0, 3.0), 1);
    check_u8("fucompp_be_jnz 2=2", fucompp_be_jnz(2.0, 2.0), 1);
    check_u8("fucompp_be_jnz nan", fucompp_be_jnz(kNan, 1.0), 1);

    check_u8("neq_jp 3>1", neq_jp(3.0, 1.0), 1);
    check_u8("neq_jp 1<3", neq_jp(1.0, 3.0), 1);
    check_u8("neq_jp 2=2", neq_jp(2.0, 2.0), 0);
    check_u8("neq_jp nan", neq_jp(kNan, 1.0), 1);

    /* AL holds exception bits — typically 0 after these compares → jz taken */
    check_u8("al_mask_jz 3>1", al_mask_jz(3.0, 1.0), 1);

    check_u8("nonadjacent_gt_jz 3>1", nonadjacent_gt_jz(3.0, 1.0), 1);
    check_u8("nonadjacent_gt_jz 1<3", nonadjacent_gt_jz(1.0, 3.0), 0);

    /* full CC readback through AX (AND consumer with AX read afterward) */
    check_u8("ax_readback 3>1", ax_readback(3.0, 1.0) == 0x0000, 1);
    check_u8("ax_readback 1<3", ax_readback(1.0, 3.0) == 0x0100, 1);
    check_u8("ax_readback 2=2", ax_readback(2.0, 2.0) == 0x4000, 1);
    check_u8("ax_readback nan", ax_readback(kNan, 1.0) == 0x4500, 1);

    if (failures == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("%d FAILURES\n", failures);
    return 1;
}
