/*
 * test_ir_fpr_pressure.c — x87 run whose peak FPR liveness exceeds the
 * default 8-register scratch pool.
 *
 * Shape: 8 FLDs fill the stack (8 simultaneously live values), then an
 * FADD m64 needs a 9th live register — peak_live_fprs = 9 > 8, so in the
 * default config the 17-instruction run is declined (kFprPressure,
 * ROSETTA_X87_LOG_IR_DECLINES=1 shows error=2) and handled by the singular
 * path with the run cache active. With ROSETTA_X87_EXTENDED_FPR_SCRATCH=1
 * (peak 9 <= 16) the whole run lowers through the IR as one unit — 2.3x
 * faster (values must be bit-identical in both configs; run this test in
 * both).
 *
 * History: a prefix-retry (halve the run on pressure decline) was tried and
 * reverted — splitting the run broke deferred push/pop tag cancellation and
 * benched 16% slower than the decline path on exactly this shape.
 *
 * Build: clang -arch x86_64 -O0 -g -o test_ir_fpr_pressure test_ir_fpr_pressure.c
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int failures = 0;
static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

static void check(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-58s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* 8 pushes + fadd m64 + 8 popping stores.
 * After the pushes: ST(0)=m[7] … ST(7)=m[0].
 * faddl m8: ST(0) = m[7] + m8.
 * fstpl out[0..7] pops top-down: out[0]=m[7]+m8, out[k]=m[7-k] for k>=1. */
static void nine_live(const double *m, double m8, double *out) {
    __asm__ volatile(
        "fldl 0(%1)\n\t"
        "fldl 8(%1)\n\t"
        "fldl 16(%1)\n\t"
        "fldl 24(%1)\n\t"
        "fldl 32(%1)\n\t"
        "fldl 40(%1)\n\t"
        "fldl 48(%1)\n\t"
        "fldl 56(%1)\n\t"
        "faddl %2\n\t"
        "fstpl 0(%0)\n\t"
        "fstpl 8(%0)\n\t"
        "fstpl 16(%0)\n\t"
        "fstpl 24(%0)\n\t"
        "fstpl 32(%0)\n\t"
        "fstpl 40(%0)\n\t"
        "fstpl 48(%0)\n\t"
        "fstpl 56(%0)\n\t"
        :
        : "r"(out), "r"(m), "m"(m8)
        : "memory");
}

int main(void) {
    double m[8] = {1.5, -2.25, 3.0, 0.125, 1e10, -7.75, 0.5, 42.0};
    double m8 = 100.0;
    double out[8] = {0};

    nine_live(m, m8, out);

    check("nine_live: out[0] = m[7] + m8", out[0], m[7] + m8);
    for (int k = 1; k < 8; k++) {
        char name[64];
        snprintf(name, sizeof(name), "nine_live: out[%d] = m[%d]", k, 7 - k);
        check(name, out[k], m[7 - k]);
    }

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
