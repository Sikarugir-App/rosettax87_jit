/*
 * test_ir_gpr_pressure.c — game-shaped x87 runs that the IR pipeline used to
 * decline with kGprPressure.
 *
 * Root cause (fixed): on mid-run re-entry (after a prefix of a long run was
 * already IR-compiled, or after a per-instruction fallback) the x87 cache's
 * three pinned GPRs are excluded from free_gpr_mask, but peak_live_gprs()
 * still charged for them (pinned=4), double-counting 3 registers. Any
 * mid-run attempt containing an integer store, a compare, or a TOP-delta
 * epilogue was then declined and fell back to per-instruction translation.
 *
 * The sequences below are shaped after the WoW 1.12 sites that logged
 * error=3 (address in comment). transform_seq is deliberately longer than
 * the 64-node IR cap so the run splits and the tail is compiled on mid-run
 * re-entry — the exact previously-failing condition.
 *
 * Build: clang -arch x86_64 -O0 -o test_ir_gpr_pressure test_ir_gpr_pressure.c
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

static int failures = 0;

static uint32_t f32_bits(float f) { uint32_t u; memcpy(&u, &f, 4); return u; }

static void check_f32(const char *name, float got, float expected) {
    if (f32_bits(got) != f32_bits(expected)) {
        printf("FAIL  %-58s  got=%.9g (%08x)  expected=%.9g (%08x)\n", name,
               got, f32_bits(got), expected, f32_bits(expected));
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_i32(const char *name, int32_t got, int32_t expected) {
    if (got != expected) {
        printf("FAIL  %-58s  got=%d  expected=%d\n", name, (int)got, (int)expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* ── CGMinimapFrame::Render shape (0x4ecfcd) ────────────────────────────────
 * fmul mem / faddp / fstp / fld / fdiv / fst / fmul st,st(1) / fmul mem /
 * fadd mem / fstp / deep fstp-st pops. */
static void minimap_seq(float va, float vb, float vc, float m58,
                        float c1, float c2, float c3, float c4,
                        float *o0, float *o1, float *o2) {
    __asm__ volatile(
        "flds %[va]\n\t"          /* (A)                        */
        "flds %[vb]\n\t"          /* (B A)                      */
        "flds %[vc]\n\t"          /* (C B A)                    */
        "fmuls %[m58]\n\t"        /* (C*m B A)                  */
        "faddp\n\t"               /* (B+C*m A)                  */
        "fstps %[o0]\n\t"         /* (A)                        */
        "flds %[c1]\n\t"          /* (c1 A)                     */
        "fdivs %[c2]\n\t"         /* (D=c1/c2 A)                */
        "fsts %[o1]\n\t"          /* (D A)                      */
        "fmul %%st(1), %%st\n\t"  /* (D*A A)                    */
        "fmuls %[c3]\n\t"         /* (D*A*c3 A)                 */
        "fadds %[c4]\n\t"         /* (D*A*c3+c4 A)              */
        "fstps %[o2]\n\t"         /* (A)                        */
        "fstp %%st(0)\n"          /* ()                         */
        : [o0] "=m"(*o0), [o1] "=m"(*o1), [o2] "=m"(*o2)
        : [va] "m"(va), [vb] "m"(vb), [vc] "m"(vc), [m58] "m"(m58),
          [c1] "m"(c1), [c2] "m"(c2), [c3] "m"(c3), [c4] "m"(c4));
}

static void run_minimap(void) {
    float o0 = 0, o1 = 0, o2 = 0;
    const float va = 1.75f, vb = -2.5f, vc = 3.25f, m58 = 0.375f;
    const float c1 = 7.0f, c2 = 3.0f, c3 = -1.5f, c4 = 0.625f;
    minimap_seq(va, vb, vc, m58, c1, c2, c3, c4, &o0, &o1, &o2);

    const double D = (double)c1 / (double)c2;
    check_f32("minimap: b + c*m", o0, (float)((double)vb + (double)vc * m58));
    check_f32("minimap: c1/c2 (fst keeps f64)", o1, (float)D);
    check_f32("minimap: d*a*c3 + c4", o2, (float)(D * va * c3 + c4));
}

/* ── sqrt/div normalization shape (0x6da299) ────────────────────────────────
 * fld g; fmul g (same-address CSE); faddp; fsqrt; fdivp; then three
 * fld g / fmul st,st(1) / fstp g global rescales; fstp st. */
static float g0, g1, g2;

static void sqrt_div_seq(float x, float acc) {
    __asm__ volatile(
        "flds %[x]\n\t"           /* (X)                        */
        "flds %[acc]\n\t"         /* (acc X)                    */
        "flds %[g2]\n\t"          /* (g acc X)                  */
        "fmuls %[g2]\n\t"         /* (g*g acc X)                */
        "faddp\n\t"               /* (acc+g*g X)                */
        "fsqrt\n\t"               /* (s X)                      */
        "fdivrp\n\t"              /* (N=X/s; gas swaps the reversed
                                     register-form mnemonics)   */
        "flds %[g0]\n\t"          /* (g0 N)                     */
        "fmul %%st(1), %%st\n\t"  /* (g0*N N)                   */
        "fstps %[g0]\n\t"         /* (N)                        */
        "flds %[g1]\n\t"
        "fmul %%st(1), %%st\n\t"
        "fstps %[g1]\n\t"
        "flds %[g2]\n\t"
        "fmul %%st(1), %%st\n\t"
        "fstps %[g2]\n\t"
        "fstp %%st(0)\n"          /* ()                         */
        : [g0] "+m"(g0), [g1] "+m"(g1), [g2] "+m"(g2)
        : [x] "m"(x), [acc] "m"(acc));
}

static void run_sqrt_div(void) {
    g0 = 0.5f;
    g1 = -1.25f;
    g2 = 3.0f;
    const float x = 2.5f, acc = 7.0f;
    sqrt_div_seq(x, acc);

    const double N = (double)x / sqrt((double)acc + (double)3.0f * 3.0f);
    check_f32("sqrt_div: g0 * N", g0, (float)(0.5 * N));
    check_f32("sqrt_div: g1 * N", g1, (float)(-1.25 * N));
    check_f32("sqrt_div: g2 * N", g2, (float)(3.0 * N));
}

/* ── fistp quantization shape (0x6b9bce) ────────────────────────────────────
 * fsubp / fmul st,st(1) / f32 store / two fld+fmul+fsub+fistp rounds
 * (2 non-truncating int stores in one run → RC cache active). */
static void fistp_seq(float a, float b, float m, float s,
                      float *of, int32_t *i0, int32_t *i1) {
    __asm__ volatile(
        "flds %[a]\n\t"           /* (A)                        */
        "flds %[b]\n\t"           /* (B A)                      */
        "fsubrp\n\t"              /* (A-B; gas-reversed name)   */
        "flds %[m]\n\t"           /* (M A-B)                    */
        "fmul %%st(1), %%st\n\t"  /* (M*(A-B) A-B)              */
        "fstps %[of]\n\t"         /* (A-B)                      */
        "fmuls %[m]\n\t"          /* ((A-B)*M)                  */
        "fsubs %[s]\n\t"          /* ((A-B)*M-S)                */
        "fistpl %[i0]\n\t"        /* ()                         */
        "flds %[a]\n\t"
        "fmuls %[m]\n\t"
        "fsubs %[s]\n\t"
        "fistpl %[i1]\n"
        : [of] "=m"(*of), [i0] "=m"(*i0), [i1] "=m"(*i1)
        : [a] "m"(a), [b] "m"(b), [m] "m"(m), [s] "m"(s));
}

static void run_fistp(void) {
    float of = 0;
    int32_t i0 = 0, i1 = 0;
    const float a = 100.25f, b = 37.5f, m = 2.5f, s = 0.5f;
    fistp_seq(a, b, m, s, &of, &i0, &i1);

    const double diff = (double)a - (double)b;
    check_f32("fistp: m*(a-b)", of, (float)((double)m * diff));
    check_i32("fistp: rint((a-b)*m - s)", i0,
              (int32_t)nearbyint(diff * m - s));
    check_i32("fistp: rint(a*m - s)", i1,
              (int32_t)nearbyint((double)a * m - s));
}

/* ── fcom+fnstsw+test chain shape (0x60249b) ────────────────────────────────
 * dot product, f32 store-and-keep, compare against a limit, branch on
 * C0|C3 — the fcom/fnstsw/test tail after an arithmetic run. */
static int fcom_seq(float x0, float x1, float y0, float y1, float lim,
                    float *out) {
    int r;
    __asm__ volatile(
        "flds %[x0]\n\t"
        "fmuls %[y0]\n\t"
        "flds %[x1]\n\t"
        "fmuls %[y1]\n\t"
        "faddp\n\t"
        "fsts %[out]\n\t"
        "fcomps %[lim]\n\t"
        "fnstsw %%ax\n\t"
        "testb $0x41, %%ah\n\t"
        "setz %%al\n\t"           /* 1 iff dot > lim (C0=C3=0)  */
        "movzbl %%al, %[r]\n"
        : [r] "=r"(r), [out] "=m"(*out)
        : [x0] "m"(x0), [x1] "m"(x1), [y0] "m"(y0), [y1] "m"(y1),
          [lim] "m"(lim)
        : "ax", "cc");
    return r;
}

static void run_fcom(void) {
    float dot = 0;
    int gt = fcom_seq(3.0f, 4.0f, 2.0f, -1.5f, 0.0f, &dot);
    check_f32("fcom: dot value", dot, (float)(3.0 * 2.0 + 4.0 * -1.5));
    check_i32("fcom: dot > 0 is false", gt, 0);

    gt = fcom_seq(3.0f, 4.0f, 2.0f, 1.5f, 5.0f, &dot);
    check_f32("fcom: dot value (2)", dot, (float)(3.0 * 2.0 + 4.0 * 1.5));
    check_i32("fcom: dot > 5 is true", gt, 1);
}

/* ── long matrix-transform shape (0x7158d7) ─────────────────────────────────
 * Six fxch-flavored dot3 rows plus an fistp tail in ONE contiguous x87 run
 * (~65 instructions, well past the 64-node IR cap) — the run necessarily
 * splits, and the tail compiles on mid-run re-entry with the cache GPRs
 * pinned. Pre-fix, the tail was declined (error=3); now it must both lower
 * and stay correct. */
struct xform {
    float v[6];   /* ax ay az bx by bz — offsets 0..20   */
    float m[9];   /* offsets 24..56                       */
    float sub[6]; /* offsets 60..80                       */
    float o[6];   /* offsets 84..104                      */
    float s;      /* offset 108                           */
    int32_t iq;   /* offset 112                           */
};

static void transform_seq(struct xform *p) {
    /* One base register, explicit offsets — 28 separate "m" operands exceed
     * what clang's -O0 allocator will register-allocate for one asm. */
#define ROW(vx, vy, vz, c0, c1, c2, subi, oi)                                \
        "flds " vy "(%0)\n\t"      /* (Y)                       */           \
        "fmuls " c1 "(%0)\n\t"     /* (Y*c1)                    */           \
        "flds " vx "(%0)\n\t"      /* (X Y*c1)                  */           \
        "fmuls " c0 "(%0)\n\t"     /* (X*c0 Y*c1)               */           \
        "fxch %%st(1)\n\t"         /* (Y*c1 X*c0)               */           \
        "faddp\n\t"                /* (X*c0+Y*c1)               */           \
        "flds " vz "(%0)\n\t"                                                \
        "fmuls " c2 "(%0)\n\t"                                               \
        "faddp\n\t"                /* (dot3)                    */           \
        "fsubrs " subi "(%0)\n\t"  /* (sub - dot3)              */           \
        "fstps " oi "(%0)\n\t"
    __asm__ volatile(
        /*   vx    vy    vz    c0    c1    c2    sub    o      */
        ROW("0",  "4",  "8",  "24", "28", "32", "60",  "84")
        ROW("12", "16", "20", "24", "28", "32", "64",  "88")
        ROW("0",  "4",  "8",  "36", "40", "44", "68",  "92")
        ROW("12", "16", "20", "36", "40", "44", "72",  "96")
        ROW("0",  "4",  "8",  "48", "52", "56", "76",  "100")
        ROW("12", "16", "20", "48", "52", "56", "80",  "104")
        "flds 0(%0)\n\t"           /* ax                        */
        "fmuls 56(%0)\n\t"         /* * m[8]                    */
        "fsubs 108(%0)\n\t"        /* - s                       */
        "fistpl 112(%0)\n"         /* → iq                      */
        :
        : "r"(p)
        : "memory");
#undef ROW
}

static void run_transform(void) {
    struct xform p = {
        .v = {1.5f, -2.25f, 0.75f, -0.5f, 3.5f, 2.0f},
        .m = {0.25f, -1.5f, 2.75f, 3.0f, 0.125f, -0.625f, 1.25f, -2.0f, 0.5f},
        .sub = {10.0f, -4.0f, 2.5f, 0.0f, -7.5f, 1.0f},
        .o = {0},
        .s = 0.5f,
        .iq = 0,
    };
    transform_seq(&p);

    const char *names[6] = {
        "transform: row0 (a . m[0..2])", "transform: row1 (b . m[0..2])",
        "transform: row2 (a . m[3..5])", "transform: row3 (b . m[3..5])",
        "transform: row4 (a . m[6..8])", "transform: row5 (b . m[6..8])",
    };
    for (int r = 0; r < 6; r++) {
        const float *v = (r % 2 == 0) ? &p.v[0] : &p.v[3];
        const float *c = &p.m[(r / 2) * 3];
        const double dot = (double)v[0] * c[0] + (double)v[1] * c[1] +
                           (double)v[2] * c[2];
        check_f32(names[r], p.o[r], (float)((double)p.sub[r] - dot));
    }
    check_i32("transform: fistp tail", p.iq,
              (int32_t)nearbyint((double)p.v[0] * p.m[8] - 0.5));
}

int main(void) {
    run_minimap();
    run_sqrt_div();
    run_fistp();
    run_fcom();
    run_transform();

    if (failures) {
        printf("\n%d failure(s)\n", failures);
        return 1;
    }
    printf("\nAll tests passed.\n");
    return 0;
}
