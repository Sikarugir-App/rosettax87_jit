/*
 * test_decoder_fcomp_st.c — exercise the non-canonical `DC D8` encoding of FCOMP ST(0).
 *
 * Background
 * ----------
 * `FCOMP ST(0)` has two valid encodings:
 *
 *     D8 D8    canonical  (what every assembler emits)
 *     DC D8    alternate  (accepted by real x87 hardware, but Rosetta's
 *                          instruction decoder does NOT recognise it)
 *
 * The `DC D0..DF` row is normally the memory / reversed-operand form, so the
 * register form `DC D8+i` is an undocumented alias. Real silicon executes it as
 * `FCOMP ST(i)`; Rosetta's `decode_opcode` returns "invalid" and the
 * instruction faults. A game in the wild ships this exact byte sequence
 * (.text:006FA876  DC D8  fcomp st), which is why we test it explicitly.
 *
 * Because no assembler will emit `DC D8`, the bytes are injected with `.byte`.
 *
 * Result convention (matches the other x87 tests): each test returns the masked
 * x87 status-word CC bits.
 *
 *   result & 0x4500
 *         bit 14 = C3   (equal / above-or-equal)
 *         bit 10 = C2   (unordered / parity)
 *         bit  8 = C0   (below / carry)
 *
 *   ST(0) = src   0x4000    (C3=1, C2=0, C0=0)
 *   Unordered     0x4500    (C3=1, C2=1, C0=1)
 *
 * Compile (x86_64, as the CMake harness does):
 *   clang -arch x86_64 -O0 -g -o test_decoder_fcomp_st test_decoder_fcomp_st.c && ./test_decoder_fcomp_st
 */

#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * SIGILL guard. The `DC D8` encoding is undecodable to native Rosetta, where it
 * raises an illegal-instruction trap rather than translating (and can wedge the
 * process). Install a SIGILL handler that jumps back out to the recovery point
 * in main(), so an unsupported environment reports SKIP instead of hanging. It
 * is transparent where `DC D8` is supported (runtime_loader) — no trap fires.
 * --------------------------------------------------------------------------- */
static sigjmp_buf g_ill_env;
static volatile sig_atomic_t g_ill_hit = 0;

static void on_sigill(int sig) {
    (void)sig;
    g_ill_hit = 1;
    siglongjmp(g_ill_env, 1);
}

static void install_sigill_guard(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigill;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGILL, &sa, NULL);
}

/* Read x87 status-word CC bits after a compare. */
#define READ_SW(var)                                   \
    uint16_t var;                                      \
    __asm__ volatile (                                 \
        "fnstsw %%ax\n"                                \
        "andw $0x4500, %%ax\n"                         \
        "movw %%ax, %0\n"                              \
        : "=m" (var) : : "ax"                          \
    )

/* ===========================================================================
 * FCOMP ST(0)  —  DC D8  —  compare ST(0) with ST(0), pop once.
 *
 * Comparing a finite value with itself is always "equal" (C3=1) => 0x4000.
 * After the pop the stack is empty, so no teardown is needed.
 * =========================================================================== */
static uint16_t test_fcomp_st0_dcd8_eq(void)
{
    double st0 = 2.0;
    __asm__ volatile (
        "fldl %0\n"              /* ST(0) = 2.0                              */
        ".byte 0xDC, 0xD8\n"     /* DC D8 = fcomp st(0): compare 2.0,2.0 pop */
        : : "m" (st0)
    );
    READ_SW(cc);
    return cc;
}

/* FCOMP ST(0)  DC D8  — NaN vs NaN — unordered — expected 0x4500 */
static uint16_t test_fcomp_st0_dcd8_un(void)
{
    double nan_val = __builtin_nan("");
    __asm__ volatile (
        "fldl %0\n"              /* ST(0) = NaN                              */
        ".byte 0xDC, 0xD8\n"     /* DC D8 = fcomp st(0): unordered, pop      */
        : : "m" (nan_val)
    );
    READ_SW(cc);
    return cc;
}

/* ===========================================================================
 * Test table and harness
 * =========================================================================== */
typedef struct {
    const char    *name;
    uint16_t     (*fn)(void);
    uint16_t       expected;
} TestCase;

int main(void)
{
    install_sigill_guard();

    /* If `DC D8` traps SIGILL (native Rosetta — no alias support), land here
     * instead of hanging, and report that the environment lacks it. */
    if (sigsetjmp(g_ill_env, 1)) {
        printf("SKIP  test_decoder_fcomp_st — DC D8 raised SIGILL: this environment does "
               "not decode the non-canonical FCOMP alias (run under runtime_loader).\n");
        return 0;
    }

    TestCase tests[] = {
        { "fcomp ST(0)    DC D8   EQ  2.0=2.0", test_fcomp_st0_dcd8_eq, 0x4000 },
        { "fcomp ST(0)    DC D8   UN  NaN,NaN", test_fcomp_st0_dcd8_un, 0x4500 },
    };

    int pass = 0, fail = 0;
    int n = (int)(sizeof(tests) / sizeof(tests[0]));
    for (int i = 0; i < n; i++) {
        uint16_t got = tests[i].fn();
        int ok = (got == tests[i].expected);
        printf("%s  got=0x%04x  expected=0x%04x  %s\n",
               tests[i].name, (unsigned)got, (unsigned)tests[i].expected,
               ok ? "PASS" : "FAIL");
        ok ? pass++ : fail++;
    }

    printf("\n%d/%d passed\n", pass, n);
    return fail ? 1 : 0;
}
