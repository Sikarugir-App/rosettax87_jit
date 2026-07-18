/*
 * test_sse_whitelist.c — flag-neutral SSE instructions in the post-run
 * EFLAGS deadness scans.
 *
 * nzcv_dead_after_run may walk across SSE/SSE2 data movement (movss, movsd,
 * movaps, ...) and conversions when scanning for the instruction that
 * redefines EFLAGS after an x87 compare run.
 *
 * 1. Pre-run guest flags consumed after the run through SSE moves (setcc):
 *    the scan must stay conservative — the NZCV save/restore keeps the
 *    pre-run flags intact.
 * 2. Compare result read via FNSTSW AX + TEST with SSE moves interleaved:
 *    values must be correct whether or not the elision fires.
 *
 * Compile (x86_64 target, e.g. under Rosetta):
 *   clang -arch x86_64 -O0 -o test_sse_whitelist test_sse_whitelist.c
 */

#include <stdio.h>

static int failures = 0;

#define CHECK(name, cond, got)                                          \
    do {                                                                \
        if (cond) {                                                     \
            printf("PASS %s\n", name);                                  \
        } else {                                                        \
            printf("FAIL %s (got %d)\n", name, (int)(got));             \
            failures++;                                                 \
        }                                                               \
    } while (0)

static double vals[2] = {1.5, 2.5};
static float fsrc = 3.0f;

/* Pre-run CMP flags must survive the compare run + SSE moves: the scan
   sees setcc (a flag reader) and must keep the conservative NZCV pair. */
static int pre_flags_survive(int x) {
    int out;
    float tmp;
    unsigned short sw;
    __asm__ volatile(
        "cmpl   $7, %3\n\t"        /* pre-run flags: ZF iff x == 7 */
        "fldl   (%4)\n\t"
        "fcompl 8(%4)\n\t"         /* run: FCMP would clobber NZCV */
        "fnstsw %%ax\n\t"
        "movss  (%5), %%xmm0\n\t"  /* whitelisted SSE moves */
        "movss  %%xmm0, %2\n\t"
        "movw   %%ax, %1\n\t"
        "sete   %%al\n\t"          /* reads the PRE-RUN ZF */
        "movzbl %%al, %0\n\t"
        : "=r"(out), "=m"(sw), "=m"(tmp)
        : "r"(x), "r"(vals), "r"(&fsrc)
        : "ax", "xmm0", "cc", "memory");
    return out;
}

/* Compare result through FNSTSW AX + TEST with SSE moves between the
   fnstsw and the TEST definer — elision may fire; result must be exact. */
static int compare_through_sse(void) {
    int out;
    float tmp;
    __asm__ volatile(
        "fldl   (%2)\n\t"          /* 1.5 */
        "fcompl 8(%2)\n\t"         /* vs 2.5 → C0 (below) */
        "fnstsw %%ax\n\t"
        "movss  (%3), %%xmm0\n\t"
        "movss  %%xmm0, %1\n\t"
        "testb  $0x45, %%ah\n\t"   /* full-EFLAGS definer ends the scan */
        "setne  %%al\n\t"          /* C0|C2|C3 set → 1 (1.5 < 2.5) */
        "movzbl %%al, %0\n\t"
        : "=r"(out), "=m"(tmp)
        : "r"(vals), "r"(&fsrc)
        : "ax", "xmm0", "cc", "memory");
    return out;
}

int main(void) {
    CHECK("pre_flags_survive_eq", pre_flags_survive(7) == 1, pre_flags_survive(7));
    CHECK("pre_flags_survive_ne", pre_flags_survive(3) == 0, pre_flags_survive(3));
    CHECK("compare_through_sse", compare_through_sse() == 1, compare_through_sse());

    if (failures == 0)
        printf("ALL PASS (test_sse_whitelist)\n");
    return failures != 0;
}
