#include "rosetta_core/X87IR.h"

namespace X87IR {

// ── Pass 0: Dead-compare elimination ────────────────────────────────────────
//
// FCmp/FTst's only architectural effect is writing C0/C2/C3 into status_word
// (exceptions are unmodeled). FStsw is the only IR node that reads
// status_word, and run end is the final observer. So a compare whose CC bits
// are overwritten by a later FCmp/FTst, with no FStsw in between, has no
// observable effect and can be killed outright — its FCMP, the NZCV
// save/restore, the CC pack, and the status_word RMW all disappear, and its
// value inputs may cascade dead in pass_dse.
//
// Backward scan: `overwritten` is true when a live FCmp/FTst lies below with
// no FStsw between it and the current node.

static void pass_dead_compares(Context& ctx) {
    bool overwritten = false;
    for (int i = ctx.num_nodes - 1; i >= 0; i--) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        if (n.op == Op::FStsw) {
            overwritten = false;
        } else if (n.op == Op::FCmp || n.op == Op::FTst) {
            if (overwritten)
                n.flags |= kDead;
            else
                overwritten = true;
        }
    }
}

// ── Pass 0.5: Constant arithmetic ───────────────────────────────────────────
//
// With constant-load promotion, FP literals surface as Const* nodes:
//   FDiv(x, ConstF64 = ±2^k) → FMul(x, ±2^-k)  — exact (reciprocal of a
//     normal power of two is a normal power of two); FDIV is ~3-4× the
//     latency of FMUL. Requires a single-use divisor (bits are rewritten
//     in place).
//   FCmp(x, ±0.0 const) → FTst(x)  — FCMP #0.0 compares -0 == +0, matching
//     FCOM semantics; drops the constant materialization.
// Runs before pass_dse so orphaned constants are reaped.

static void pass_const_arith(Context& ctx) {
    int16_t use_count[kMaxNodes] = {};
    for (int d = 0; d < 8; d++) {
        if (ctx.slot_val[d] >= 0 && ctx.slot_val[d] < ctx.num_nodes)
            use_count[ctx.slot_val[d]]++;
    }
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        for (int j = 0; j < 3; j++) {
            if (n.inputs[j] >= 0) use_count[n.inputs[j]]++;
        }
    }

    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;

        if (n.op == Op::FDiv) {
            int16_t c = n.inputs[1];
            if (c < 0 || c >= ctx.num_nodes) continue;
            auto& cn = ctx.nodes[c];
            if (cn.op != Op::ConstF64 || (cn.flags & kDead) || use_count[c] != 1)
                continue;
            const uint64_t b = cn.imm_bits;
            const uint64_t exp = (b >> 52) & 0x7FF;
            // ±2^k with both value and reciprocal normal.
            if ((b & 0x000FFFFFFFFFFFFFULL) == 0 && exp >= 1 && exp <= 2045) {
                cn.imm_bits = (b & 0x8000000000000000ULL) | ((2046 - exp) << 52);
                n.op = Op::FMul;
            }
        } else if (n.op == Op::FCmp) {
            int16_t c = n.inputs[1];
            if (c < 0 || c >= ctx.num_nodes) continue;
            auto& cn = ctx.nodes[c];
            if (cn.flags & kDead) continue;
            const bool is_zero = cn.op == Op::ConstZero ||
                                 (cn.op == Op::ConstF64 && (cn.imm_bits << 1) == 0);
            if (!is_zero) continue;
            n.op = Op::FTst;
            n.inputs[1] = -1;
            if (--use_count[c] == 0)
                cn.flags |= kDead;
        }
    }
}

// ── Pass 1: Dead Store Elimination ──────────────────────────────────────────
//
// Walk backward. A value node is dead if it has no live consumers (no other
// node references it in inputs[], and it's not in the final slot_val[]).
// Side-effect nodes (Store*, FCmp, FTst, FStsw) are never eliminated.

static void pass_dse(Context& ctx) {
    // Count uses for each node.
    int16_t use_count[kMaxNodes] = {};

    // Final stack values count as uses.
    for (int d = 0; d < 8; d++) {
        if (ctx.slot_val[d] >= 0 && ctx.slot_val[d] < ctx.num_nodes)
            use_count[ctx.slot_val[d]]++;
    }

    // Forward pass to count uses from non-dead nodes.
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        for (int j = 0; j < 3; j++) {
            if (n.inputs[j] >= 0)
                use_count[n.inputs[j]]++;
        }
    }

    // Backward pass: mark dead nodes (pure-value nodes with zero uses).
    for (int i = ctx.num_nodes - 1; i >= 0; i--) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;

        // Side-effect nodes are never dead.
        switch (n.op) {
            case Op::StoreF64: case Op::StoreF32:
            case Op::StoreI16: case Op::StoreI32: case Op::StoreI64:
            case Op::FCmp: case Op::FTst: case Op::FStsw: case Op::FComI:
            case Op::StoreCW: case Op::LoadCW:
                continue;
            default: break;
        }

        if (use_count[i] == 0) {
            n.flags |= kDead;
            // Decrement use counts for this node's inputs.
            for (int j = 0; j < 3; j++) {
                if (n.inputs[j] >= 0)
                    use_count[n.inputs[j]]--;
            }
        }
    }

    // Second backward pass to catch cascading dead nodes.
    for (int i = ctx.num_nodes - 1; i >= 0; i--) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        switch (n.op) {
            case Op::StoreF64: case Op::StoreF32:
            case Op::StoreI16: case Op::StoreI32: case Op::StoreI64:
            case Op::FCmp: case Op::FTst: case Op::FStsw: case Op::FComI:
            case Op::StoreCW: case Op::LoadCW:
                continue;
            default: break;
        }
        if (use_count[i] == 0) {
            n.flags |= kDead;
            for (int j = 0; j < 3; j++) {
                if (n.inputs[j] >= 0)
                    use_count[n.inputs[j]]--;
            }
        }
    }
}

// ── Pass 1.5: FNeg folding ──────────────────────────────────────────────────
//
// fchs is common in game FP code. Fold single-use FNeg nodes into their
// consumer (all rewrites are IEEE-exact — FSub(x,y) computes x + (-y)):
//   FAdd(x, FNeg(y)) → FSub(x, y)
//   FAdd(FNeg(x), y) → FSub(y, x)
//   FSub(x, FNeg(y)) → FAdd(x, y)
//   FNeg(FMul(a, b)) with single-use mul → FNMul(a, b)   (one FNMUL insn)
// Runs before pass_fma so the rewritten FAdd/FSub feed FMA detection.
// Note: FNMul diverges from FMUL+FNEG only in the sign bit of a NaN result
// (AArch64 propagates the input NaN unnegated) — same fidelity class as the
// FMA fusion's rounding difference, accepted.

static void pass_fneg_fold(Context& ctx) {
    int16_t use_count[kMaxNodes] = {};
    for (int d = 0; d < 8; d++) {
        if (ctx.slot_val[d] >= 0 && ctx.slot_val[d] < ctx.num_nodes)
            use_count[ctx.slot_val[d]]++;
    }
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        for (int j = 0; j < 3; j++) {
            if (n.inputs[j] >= 0) use_count[n.inputs[j]]++;
        }
    }

    auto single_use_op = [&](int16_t id, Op op) {
        return id >= 0 && id < ctx.num_nodes && ctx.nodes[id].op == op &&
               !(ctx.nodes[id].flags & kDead) && use_count[id] == 1;
    };

    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;

        if (n.op == Op::FAdd || n.op == Op::FSub) {
            int16_t in0 = n.inputs[0], in1 = n.inputs[1];
            if (single_use_op(in1, Op::FNeg)) {
                auto& neg = ctx.nodes[in1];
                n.op = (n.op == Op::FAdd) ? Op::FSub : Op::FAdd;
                n.inputs[1] = neg.inputs[0];
                neg.flags |= kDead;
                use_count[in1] = 0;
                if (neg.inputs[0] >= 0) use_count[neg.inputs[0]]++;
            } else if (n.op == Op::FAdd && single_use_op(in0, Op::FNeg)) {
                auto& neg = ctx.nodes[in0];
                n.op = Op::FSub;
                n.inputs[0] = in1;
                n.inputs[1] = neg.inputs[0];
                neg.flags |= kDead;
                use_count[in0] = 0;
                if (neg.inputs[0] >= 0) use_count[neg.inputs[0]]++;
            }
        } else if (n.op == Op::FNeg) {
            int16_t m = n.inputs[0];
            if (single_use_op(m, Op::FMul)) {
                auto& mul = ctx.nodes[m];
                n.op = Op::FNMul;
                n.inputs[0] = mul.inputs[0];
                n.inputs[1] = mul.inputs[1];
                mul.flags |= kDead;
                use_count[m] = 0;
                if (mul.inputs[0] >= 0) use_count[mul.inputs[0]]++;
                if (mul.inputs[1] >= 0) use_count[mul.inputs[1]]++;
            }
        }
    }
}

// ── Pass 2: FMA Detection ───────────────────────────────────────────────────
//
// Pattern: FMul(a, b) with exactly one use → FAdd(mul, c) or FAdd(c, mul)
//          → replace with FMAdd(a, b, c).
//
// Similarly:
//   FAdd(c, mul) where mul = FMul(a, b)  → FMAdd(a, b, c)  [c + a*b]
//   FSub(c, mul)                          → FMSub(a, b, c)  [c - a*b]
//   FSub(mul, c)                          → FNMSub(a, b, c) [a*b - c]

static void pass_fma(Context& ctx) {
    // Count uses first to find single-use FMul nodes.
    int16_t use_count[kMaxNodes] = {};
    for (int d = 0; d < 8; d++) {
        if (ctx.slot_val[d] >= 0 && ctx.slot_val[d] < ctx.num_nodes)
            use_count[ctx.slot_val[d]]++;
    }
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        for (int j = 0; j < 3; j++) {
            if (n.inputs[j] >= 0) use_count[n.inputs[j]]++;
        }
    }

    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        if (n.op != Op::FAdd && n.op != Op::FSub) continue;

        int16_t in0 = n.inputs[0];
        int16_t in1 = n.inputs[1];

        // Check if one input is a single-use FMul.
        auto try_fuse = [&](int mul_input_idx, int other_input_idx) -> bool {
            int16_t mul_id = (mul_input_idx == 0) ? in0 : in1;
            int16_t other_id = (other_input_idx == 0) ? in0 : in1;
            if (mul_id < 0 || mul_id >= ctx.num_nodes) return false;
            auto& mul_node = ctx.nodes[mul_id];
            if (mul_node.op != Op::FMul) return false;
            if (mul_node.flags & kDead) return false;
            if (use_count[mul_id] != 1) return false;

            // Determine FMA variant.
            Op fma_op;
            if (n.op == Op::FAdd) {
                fma_op = Op::FMAdd;  // c + a*b (or a*b + c, same thing)
            } else {
                // FSub
                if (mul_input_idx == 0) {
                    // FSub(mul, c) → a*b - c = FNMSub
                    fma_op = Op::FNMSub;
                } else {
                    // FSub(c, mul) → c - a*b = FMSub
                    fma_op = Op::FMSub;
                }
            }

            // Rewrite: n becomes FMA, mul becomes dead.
            n.op = fma_op;
            n.inputs[0] = mul_node.inputs[0];  // a
            n.inputs[1] = mul_node.inputs[1];  // b
            n.inputs[2] = other_id;            // c (addend)
            mul_node.flags |= kDead;
            use_count[mul_id] = 0;
            // Update use counts for the rewritten inputs.
            if (mul_node.inputs[0] >= 0) use_count[mul_node.inputs[0]]++;
            if (mul_node.inputs[1] >= 0) use_count[mul_node.inputs[1]]++;
            // other_id already had its use from the original node; no change needed.
            return true;
        };

        if (!try_fuse(0, 1))
            try_fuse(1, 0);
    }
}

// ── Pass 3: FCOM + FSTSW Fusion ─────────────────────────────────────────────
//
// If a FCmp/FTst node is immediately followed by a FStsw with no intervening
// CC-modifying node, mark both with kFcomFused. The lowering keeps packed CC
// in a GPR between the two nodes, avoiding one LDRH in FStsw.

static void pass_fcom_fstsw_fusion(Context& ctx) {
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        if (n.op != Op::FStsw) continue;

        int16_t fcmp_id = n.inputs[0];
        if (fcmp_id < 0 || fcmp_id >= ctx.num_nodes) continue;
        auto& fcmp_node = ctx.nodes[fcmp_id];
        if (fcmp_node.op != Op::FCmp && fcmp_node.op != Op::FTst) continue;

        // Check no intervening CC-modifying instruction between fcmp and fstsw.
        bool clean = true;
        for (int j = fcmp_id + 1; j < i; j++) {
            auto& between = ctx.nodes[j];
            if (between.flags & kDead) continue;
            if (between.op == Op::FCmp || between.op == Op::FTst) {
                clean = false;
                break;
            }
        }
        if (clean) {
            fcmp_node.flags |= kFcomFused;
            n.flags |= kFcomFused;
        }
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

void optimize(Context& ctx) {
    pass_dead_compares(ctx);
    pass_const_arith(ctx);
    pass_dse(ctx);
    pass_fneg_fold(ctx);
    pass_fma(ctx);
    pass_fcom_fstsw_fusion(ctx);
}

}  // namespace X87IR
