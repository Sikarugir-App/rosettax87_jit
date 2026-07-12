/*
 * test_int_regbase.c — integer x87 memory ops through a register base with
 * ZERO displacement, e.g. `fiaddl (%rax)`.
 *
 * Regression test: for zero-disp base-only operands compute_operand_address
 * returns the guest base register itself, and the fiadd/fisub/fisubr/fimul/
 * fidiv/fidivr/ficom translators used to reuse the returned address register
 * as the load destination — clobbering the live guest base register with the
 * loaded integer value.  Each test checks BOTH the arithmetic result and that
 * the base register still holds the pointer afterwards.
 *
 * Compile (x86_64 target, e.g. under Rosetta):
 *   clang -arch x86_64 -O0 -o test_int_regbase test_int_regbase.c
 */

#include <stdint.h>
#include <stdio.h>

static int failures = 0;

#define CHECK(name, cond, got)                                          \
    do {                                                                \
        if (cond) {                                                     \
            printf("PASS %s\n", name);                                  \
        } else {                                                        \
            printf("FAIL %s (got %f)\n", name, (double)(got));          \
            failures++;                                                 \
        }                                                               \
    } while (0)

#define CHECK_BASE(name, base, ptr)                                     \
    do {                                                                \
        if ((base) == (uintptr_t)(ptr)) {                               \
            printf("PASS %s_base\n", name);                             \
        } else {                                                        \
            printf("FAIL %s_base (base clobbered: %lx != %lx)\n", name, \
                   (unsigned long)(base), (unsigned long)(uintptr_t)(ptr)); \
            failures++;                                                 \
        }                                                               \
    } while (0)

/* One m32int op through (%rax): st0 = 10.0 <op> *p, base returned in *base. */
#define INT_OP_M32(insn, p, res, base)                    \
    __asm__ volatile(                                     \
        "movq  %2, %%rax\n\t"                             \
        "fldl  %3\n\t"                                    \
        insn " (%%rax)\n\t"                               \
        "movq  %%rax, %0\n\t"                             \
        "fstpl %1\n\t"                                    \
        : "=r"(base), "=m"(res)                           \
        : "r"((uintptr_t)(p)), "m"(ten)                   \
        : "rax")

/* Same for the m16int forms (fiadds etc.). */
#define INT_OP_M16(insn, p, res, base)                    \
    __asm__ volatile(                                     \
        "movq  %2, %%rax\n\t"                             \
        "fldl  %3\n\t"                                    \
        insn " (%%rax)\n\t"                               \
        "movq  %%rax, %0\n\t"                             \
        "fstpl %1\n\t"                                    \
        : "=r"(base), "=m"(res)                           \
        : "r"((uintptr_t)(p)), "m"(ten)                   \
        : "rax")

static const double ten = 10.0;

int main(void) {
    int32_t i32 = 4;
    int16_t i16 = 4;
    double res;
    uintptr_t base;

    INT_OP_M32("fiaddl", &i32, res, base);
    CHECK("fiadd_m32_regbase", res == 14.0, res);
    CHECK_BASE("fiadd_m32_regbase", base, &i32);

    INT_OP_M32("fisubl", &i32, res, base);
    CHECK("fisub_m32_regbase", res == 6.0, res);
    CHECK_BASE("fisub_m32_regbase", base, &i32);

    INT_OP_M32("fisubrl", &i32, res, base);
    CHECK("fisubr_m32_regbase", res == -6.0, res);
    CHECK_BASE("fisubr_m32_regbase", base, &i32);

    INT_OP_M32("fimull", &i32, res, base);
    CHECK("fimul_m32_regbase", res == 40.0, res);
    CHECK_BASE("fimul_m32_regbase", base, &i32);

    INT_OP_M32("fidivl", &i32, res, base);
    CHECK("fidiv_m32_regbase", res == 2.5, res);
    CHECK_BASE("fidiv_m32_regbase", base, &i32);

    INT_OP_M32("fidivrl", &i32, res, base);
    CHECK("fidivr_m32_regbase", res == 0.4, res);
    CHECK_BASE("fidivr_m32_regbase", base, &i32);

    INT_OP_M16("fiadds", &i16, res, base);
    CHECK("fiadd_m16_regbase", res == 14.0, res);
    CHECK_BASE("fiadd_m16_regbase", base, &i16);

    INT_OP_M16("fidivs", &i16, res, base);
    CHECK("fidiv_m16_regbase", res == 2.5, res);
    CHECK_BASE("fidiv_m16_regbase", base, &i16);

    /* ficom: compare 10.0 with *p (4) → C0=0,C2=0,C3=0 (greater). Also pops
       via ficomp second round to cover both opcodes. */
    {
        uint16_t sw;
        __asm__ volatile(
            "movq   %2, %%rax\n\t"
            "fldl   %3\n\t"
            "ficoml (%%rax)\n\t"
            "fnstsw %%ax\n\t"          /* clobbers RAX on purpose AFTER ficom */
            "andw   $0x4500, %%ax\n\t"
            "movw   %%ax, %1\n\t"
            "movq   %%rax, %0\n\t"
            "fstp   %%st(0)\n\t"
            : "=r"(base), "=m"(sw)
            : "r"((uintptr_t)&i32), "m"(ten)
            : "rax");
        CHECK("ficom_m32_regbase", sw == 0x0000, (double)sw);
    }
    {
        uint16_t sw;
        int32_t big = 100;
        __asm__ volatile(
            "movq    %2, %%rax\n\t"
            "fldl    %3\n\t"
            "ficompl (%%rax)\n\t"
            "fnstsw  %%ax\n\t"
            "andw    $0x4500, %%ax\n\t"
            "movw    %%ax, %1\n\t"
            "movq    %%rax, %0\n\t"
            : "=r"(base), "=m"(sw)
            : "r"((uintptr_t)&big), "m"(ten)
            : "rax");
        CHECK("ficomp_m32_regbase", sw == 0x0100, (double)sw);  /* 10 < 100 → C0 */
    }

    /* IR-shaped variants: consecutive x87 runs (length >= 2) so the IR
       pipeline lowers the integer load/store nodes — zero-disp regbase must
       survive the disp-folding path there too. */
    {
        int32_t v32[2] = {4, 0};
        __asm__ volatile(
            "movq    %1, %%rax\n\t"
            "fildl   (%%rax)\n\t"
            "fildl   (%%rax)\n\t"
            "faddp\n\t"
            "fistpl  4(%%rax)\n\t"
            "movq    %%rax, %0\n\t"
            : "=r"(base)
            : "r"((uintptr_t)v32)
            : "rax", "memory");
        CHECK("fild_fistp_m32_ir_regbase", v32[1] == 8, (double)v32[1]);
        CHECK_BASE("fild_fistp_m32_ir_regbase", base, v32);
    }
    {
        int64_t v64[2] = {(1LL << 40) + 3, 0};
        __asm__ volatile(
            "movq    %1, %%rax\n\t"
            "fildll  (%%rax)\n\t"
            "fildll  (%%rax)\n\t"
            "faddp\n\t"
            "fistpll 8(%%rax)\n\t"
            "movq    %%rax, %0\n\t"
            : "=r"(base)
            : "r"((uintptr_t)v64)
            : "rax", "memory");
        CHECK("fild_fistp_m64_ir_regbase", v64[1] == 2 * ((1LL << 40) + 3),
              (double)v64[1]);
        CHECK_BASE("fild_fistp_m64_ir_regbase", base, v64);
    }
    {
        int16_t v16 = 4;
        int32_t out = 0;
        __asm__ volatile(
            "movq    %2, %%rax\n\t"
            "filds   (%%rax)\n\t"
            "filds   (%%rax)\n\t"
            "faddp\n\t"
            "fistpl  %1\n\t"
            "movq    %%rax, %0\n\t"
            : "=r"(base), "=m"(out)
            : "r"((uintptr_t)&v16)
            : "rax", "memory");
        CHECK("fild_m16_ir_regbase", out == 8, (double)out);
        CHECK_BASE("fild_m16_ir_regbase", base, &v16);
    }

    if (failures == 0)
        printf("ALL PASS (test_int_regbase)\n");
    return failures != 0;
}
