/*
 * test_run_breaks.c — Fixture for item 01 Phase-0 run-break telemetry
 *                     (ROSETTA_X87_LOG_RUN_BREAKS).
 *
 * Each function is an x87 sequence deliberately split by a non-x87 integer
 * instruction (mov / lea), so that under ROSETTA_X87_LOG_RUN_BREAKS=1 the
 * loader emits "X87 run-break" telemetry lines. Phase 0 changes no codegen, so
 * these tests double as a regression guard: values AND store addresses must be
 * identical to the un-split baseline (i.e. the interleaved mov must not corrupt
 * the x87 result). Run with the env flag set to eyeball the log output.
 *
 * Cases:
 *   (a) mov to an unrelated register between two x87 ops
 *   (b) mov to a register used as the BASE of a later x87 memory operand
 *   (c) lea updating a register used as an earlier x87 base
 *   (d) mov eax colliding with the FSTSW-AX register
 *
 * Build: clang -arch x86_64 -O0 -g -o test_run_breaks test_run_breaks.c
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

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

/* (a) fld / fmul / mov <unrelated reg> / fstp — the canonical split.
 *     ecx is not used by any x87 operand, so the result must be unaffected. */
static double split_mov_unrelated(double a, double b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"            /* ST(0) = a */
        "fmull %2\n"           /* ST(0) = a*b */
        "movl $12345, %%ecx\n" /* breaks the run; unrelated to x87 state */
        "fstpl %0\n"           /* store a*b */
        : "=m"(r)
        : "m"(a), "m"(b)
        : "ecx");
    return r;
}

/* (b) mov sets a register THEN used as base of a later x87 load.
 *     The x87 operand after the mov must observe the new register value. */
static double split_mov_writes_later_base(double a, double val_at_ptr) {
    double storage = val_at_ptr;
    double r;
    __asm__ volatile(
        "fldl %1\n"            /* ST(0) = a */
        "movq %3, %%rdx\n"     /* rdx = &storage; breaks the run */
        "faddl (%%rdx)\n"      /* ST(0) = a + storage — must use new rdx */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(a), "m"(storage), "r"(&storage)
        : "rdx");
    return r;
}

/* (c) lea recomputing a register used as an earlier x87 base, between two
 *     x87 accesses through it. */
static double split_lea_updates_base(double first, double second) {
    double buf[2];
    buf[0] = first;
    buf[1] = second;
    double r;
    __asm__ volatile(
        "movq %3, %%rsi\n"     /* rsi = &buf[0] */
        "fldl (%%rsi)\n"       /* ST(0) = buf[0] = first */
        "leaq 8(%%rsi), %%rsi\n" /* rsi = &buf[1]; breaks the run */
        "faddl (%%rsi)\n"      /* ST(0) = first + buf[1] */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(buf[0]), "m"(buf[1]), "r"(&buf[0])
        : "rsi");
    return r;
}

/* (d) mov eax between x87 ops, colliding with the FSTSW-AX register.
 *     eax is clobbered by our mov but the x87 compare/result must be intact. */
static double split_mov_eax(double a, double b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"            /* ST(0) = a */
        "fmull %2\n"           /* ST(0) = a*b */
        "movl $0, %%eax\n"     /* breaks run; touches AX (FSTSW dest reg) */
        "fstpl %0\n"           /* store a*b */
        : "=m"(r)
        : "m"(a), "m"(b)
        : "eax");
    return r;
}

/* (e) mov with a complex effective address (base+index*8+disp) between x87
 *     ops. Rosetta's translation of this mov needs an address-computation
 *     scratch register — the probe for whether Rosetta allocates honestly
 *     from free_gpr_mask: under ROSETTA_X87_RUN_BRIDGE=1 it must not clobber
 *     the pinned cache GPRs (base/TOP/st_base), or the fstp result and the
 *     loaded value go wrong. */
static double split_mov_complex_ea(double a, double b, double *picked_out) {
    double arr[4] = {0.0, 1.0, 2.0, 3.0};
    long idx = 2;
    double r;
    __asm__ volatile(
        "fldl %2\n"                /* ST(0) = a */
        "movq 8(%3,%4,8), %%rcx\n" /* rcx = bits of arr[idx+1]; complex EA */
        "fmull %5\n"               /* ST(0) = a*b */
        "fstpl %1\n"
        "movq %%rcx, %0\n"
        : "=m"(*picked_out), "=m"(r)
        : "m"(a), "r"(arr), "r"(idx), "m"(b)
        : "rcx");
    return r;
}

/* (f) SSE movsd between x87 ops — the dominant run breaker in mixed x87/SSE
 *     code (whitelist v2). Both the x87 result and the SSE-copied value must
 *     be intact. */
static double split_movsd_sse(double a, double b, double *sse_out) {
    double sse_src = 99.5;
    double r;
    __asm__ volatile(
        "fldl %2\n"              /* ST(0) = a */
        "movsd %3, %%xmm1\n"     /* SSE load — bridged under whitelist v2 */
        "fmull %4\n"             /* ST(0) = a*b */
        "movsd %%xmm1, %1\n"     /* SSE store — also bridged */
        "fstpl %0\n"
        : "=m"(r), "=m"(*sse_out)
        : "m"(a), "m"(sse_src), "m"(b)
        : "xmm1");
    return r;
}

/* (g) integer ALU (add/inc — flag definers) between x87 ops. */
static double split_alu(double a, double b, long *ctr_out) {
    long ctr = 5;
    double r;
    __asm__ volatile(
        "fldl %2\n"
        "addq $10, %1\n"         /* flag-defining ALU — bridged */
        "fmull %3\n"
        "incq %1\n"              /* bridged */
        "fstpl %0\n"
        : "=m"(r), "+r"(ctr)
        : "m"(a), "m"(b)
        : "cc");
    *ctr_out = ctr; /* 5 + 10 + 1 = 16 */
    return r;
}

/* (h) push/pop pair between x87 ops (guest RSP traffic mid-run). */
static double split_push_pop(double a, double b, long *rt_out) {
    double r;
    __asm__ volatile(
        "fldl %2\n"
        "pushq $42\n"            /* bridged */
        "fmull %3\n"
        "popq %%rcx\n"           /* bridged */
        "fstpl %0\n"
        "movq %%rcx, %1\n"
        : "=m"(r), "=m"(*rt_out)
        : "m"(a), "m"(b)
        : "rcx");
    return r;
}

/* (i) setcc between x87 ops, reading flags from a cmp BEFORE the run, with
 *     an fcomp in between — the x87 compare must save/restore guest NZCV so
 *     the bridged setcc still sees the cmp's flags (and the nzcv-dead elision
 *     must stay off: setcc is a reader). */
static double split_setcc_after_fcomp(double a, double b, long *flag_out) {
    unsigned char sc = 0;
    double r;
    __asm__ volatile(
        "cmpq $7, %3\n"          /* guest flags: 8 > 7 → above */
        "fldl %2\n"
        "fldl %4\n"
        "fcomp %%st(1)\n"        /* x87 compare — must not destroy guest NZCV */
        "seta %1\n"              /* bridged; must read the cmp's flags */
        "fmull %4\n"             /* ST(0) = a*b */
        "fstpl %0\n"
        : "=m"(r), "=m"(sc)
        : "m"(a), "r"(8L), "m"(b)
        : "cc");
    *flag_out = sc;
    return r;
}

/* (j) shift (internal-branch translation path) between x87 ops. */
static double split_shift(double a, double b, long *sh_out) {
    long v = 3;
    double r;
    __asm__ volatile(
        "fldl %2\n"
        "shlq $4, %1\n"          /* bridged; translation patches an internal branch */
        "fmull %3\n"
        "fstpl %0\n"
        : "=m"(r), "+r"(v)
        : "m"(a), "m"(b)
        : "cc");
    *sh_out = v; /* 3 << 4 = 48 */
    return r;
}

int main(void) {
    check("split_mov_unrelated: a*b intact across mov ecx",
          split_mov_unrelated(3.0, 4.0), 12.0);

    check("split_mov_writes_later_base: fadd uses new base",
          split_mov_writes_later_base(10.0, 2.5), 12.5);

    check("split_lea_updates_base: fadd uses lea'd base",
          split_lea_updates_base(1.5, 6.0), 7.5);

    check("split_mov_eax: a*b intact across mov eax",
          split_mov_eax(2.0, 8.0), 16.0);

    {
        double picked = 0.0;
        check("split_mov_complex_ea: a*b intact across complex-EA mov",
              split_mov_complex_ea(3.0, 7.0, &picked), 21.0);
        check("split_mov_complex_ea: complex-EA mov loaded arr[3]",
              picked, 3.0);
    }

    {
        double sse = 0.0;
        check("split_movsd_sse: a*b intact across SSE movsd",
              split_movsd_sse(3.5, 2.0, &sse), 7.0);
        check("split_movsd_sse: SSE round-trip value",
              sse, 99.5);
    }

    {
        long ctr = 0;
        check("split_alu: a*b intact across add/inc",
              split_alu(6.0, 7.0, &ctr), 42.0);
        if (ctr != 16) { printf("FAIL  split_alu: ctr=%ld expected 16\n", ctr); failures++; }
        else           { printf("PASS  split_alu: ctr==16\n"); }
    }

    {
        long rt = 0;
        check("split_push_pop: a*b intact across push/pop",
              split_push_pop(2.5, 4.0, &rt), 10.0);
        if (rt != 42) { printf("FAIL  split_push_pop: popped=%ld expected 42\n", rt); failures++; }
        else          { printf("PASS  split_push_pop: popped==42\n"); }
    }

    {
        long flag = -1;
        check("split_setcc_after_fcomp: a*b intact",
              split_setcc_after_fcomp(3.0, 5.0, &flag), 15.0);
        if (flag != 1) { printf("FAIL  split_setcc_after_fcomp: seta=%ld expected 1 (cmp flags survived fcomp)\n", flag); failures++; }
        else           { printf("PASS  split_setcc_after_fcomp: seta==1\n"); }
    }

    {
        long sh = 0;
        check("split_shift: a*b intact across shl",
              split_shift(1.5, 8.0, &sh), 12.0);
        if (sh != 48) { printf("FAIL  split_shift: v=%ld expected 48\n", sh); failures++; }
        else          { printf("PASS  split_shift: v==48\n"); }
    }

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
