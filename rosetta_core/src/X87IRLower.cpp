#include "rosetta_core/X87IR.h"

#include <cstring>
#include <utility>

#include "rosetta_core/AssemblerHelpers.hpp"
#include "rosetta_core/IRInstr.h"
#include "rosetta_core/IROperand.h"
#include "rosetta_core/Opcode.h"
#include "rosetta_core/Register.h"
#include "rosetta_core/TranslationResult.h"
#include "rosetta_core/TranslatorHelpers.hpp"
#include "rosetta_core/TranslatorX87Helpers.hpp"
#include "rosetta_config/Config.h"
#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/X87Cache.h"
#include "rosetta_core/CoreLog.h"

// Internal helpers from TranslatorX87Internal.hpp that we need.
namespace TranslatorX87 {
inline auto x87_begin(TranslationResult& a1, AssemblerBuffer& buf) -> std::pair<int, int> {
    if (a1.x87_cache.run_remaining > 0 && a1.x87_cache.gprs_valid)
        return {a1.x87_cache.base_gpr, a1.x87_cache.top_gpr};
    const int Xbase = alloc_gpr(a1, 0);
    const int Wd_top = alloc_gpr(a1, 1);
    emit_x87_base(buf, a1, Xbase);
    emit_load_top(buf, a1, Xbase, Wd_top);
    if (a1.x87_cache.run_remaining > 0) {
        a1.x87_cache.base_gpr = static_cast<int8_t>(Xbase);
        a1.x87_cache.top_gpr = static_cast<int8_t>(Wd_top);
        const int Xst_base = alloc_gpr(a1, 6);
        emit_add_imm(buf, 1, 0, 0, 0, kX87RegFileOff, Xbase, Xst_base);
        a1.x87_cache.st_base_gpr = static_cast<int8_t>(Xst_base);
        a1.x87_cache.gprs_valid = 1;
    }
    return {Xbase, Wd_top};
}
inline int x87_get_st_base(TranslationResult& a1) {
    return a1.x87_cache.gprs_valid ? a1.x87_cache.st_base_gpr : -1;
}
}  // namespace TranslatorX87

namespace X87IR {

static constexpr int16_t kX87TagWordImm12 = kX87TagWordOff / 2;  // = 2

// ── FPR assignment ──────────────────────────────────────────────────────────

struct FPRState {
    int8_t node_fpr[kMaxNodes];      // D register for each node, or -1
    int16_t last_use[kMaxNodes];     // last node index that uses each node, or -1

    void compute_last_uses(const Context& ctx) {
        memset(last_use, -1, sizeof(last_use));
        memset(node_fpr, -1, sizeof(node_fpr));
        for (int i = 0; i < ctx.num_nodes; i++) {
            auto& n = ctx.nodes[i];
            if (n.flags & kDead) continue;
            for (int j = 0; j < 3; j++) {
                if (n.inputs[j] >= 0) last_use[n.inputs[j]] = static_cast<int16_t>(i);
            }
        }
        // Final stack values are live past all nodes.
        for (int d = 0; d < 8; d++) {
            int16_t val = ctx.slot_val[d];
            if (val >= 0 && val < ctx.num_nodes)
                last_use[val] = static_cast<int16_t>(ctx.num_nodes);
        }
    }

    // Free FPRs whose last use was node `i`.
    void free_dead_inputs(TranslationResult& result, const Node& n, int i) {
        for (int j = 0; j < 3; j++) {
            int16_t in = n.inputs[j];
            if (in >= 0 && last_use[in] == i && node_fpr[in] >= 0) {
                free_fpr(result, node_fpr[in]);
                node_fpr[in] = -1;
            }
        }
    }

    int get(int16_t node_id) const {
        if (node_id < 0 || node_id >= kMaxNodes) return -1;
        return node_fpr[node_id];
    }

    // Try to reuse an FPR from a dying input of node `i`.
    // Returns the FPR register number, or -1 if no reuse is possible.
    // On success, sets node_fpr[input] = -1 so free_dead_inputs skips it.
    // Caller MUST capture input FPRs via get() BEFORE calling this.
    int try_reuse_input(const Context& ctx, int i) {
        const auto& n = ctx.nodes[i];
        // Prefer inputs[0] (Dn, natural accumulator position)
        for (int pref = 0; pref < 3; pref++) {
            int16_t in = n.inputs[pref];
            if (in >= 0 && last_use[in] == i && node_fpr[in] >= 0) {
                int fpr = node_fpr[in];
                node_fpr[in] = -1;  // claimed — free_dead_inputs will skip
                return fpr;
            }
        }
        return -1;
    }
};

// ── Guest-flags deadness after the run ──────────────────────────────────────
//
// Host NZCV holds the guest's materialized EFLAGS; each FCmp/FTst wraps its
// FCMP in an MRS/MSR pair (or one hoisted pair per group) to preserve them.
// If the first flag-relevant guest instruction after the run fully redefines
// EFLAGS, the pre-run flags are dead and the save/restore can be skipped
// entirely — the dominant pattern is `fcomp; fnstsw ax; test/and ...; jcc`.
//
// Whitelist walk: only instructions that neither read nor write EFLAGS may
// sit between the run and the redefinition. Anything unknown — including
// reaching block end, since the terminator may be a JCC and Rosetta itself
// treats flags as live across RET/CALL — keeps the conservative pair.
static bool nzcv_dead_after_run(IRInstr* instr_array, int64_t num_instrs, int64_t end_idx) {
    for (int64_t i = end_idx; i < num_instrs; i++) {
        switch (instr_array[i].opcode()) {
            // Full EFLAGS definers (write SF/ZF/CF/OF/PF; AF at worst
            // architecturally undefined): pre-run flags die here.
            case kOpcodeName_and:
            case kOpcodeName_or:
            case kOpcodeName_xor:
            case kOpcodeName_test:
            case kOpcodeName_cmp:
            case kOpcodeName_add:
            case kOpcodeName_sub:
                return true;
            // Flag-neutral instructions (neither read nor write EFLAGS).
            case kOpcodeName_mov:
            case kOpcodeName_movzx:
            case kOpcodeName_movsx:
            case kOpcodeName_movsxd:
            case kOpcodeName_lea:
            case kOpcodeName_push:
            case kOpcodeName_pop:
            case kOpcodeName_nop:
                continue;
            default:
                return false;  // reader / partial definer / unknown
        }
    }
    return false;  // block end reached without a full redefinition
}

// ── Base-address cache ──────────────────────────────────────────────────────
//
// Game-profile data shows runs dominated by f32/f64 memory traffic through a
// shared guest base register ([reg+disp] locals, vectors, matrices).  Instead
// of emitting ADD Waddr, Wbase, #disp + LDR [Xaddr] per access, materialize
// the base once per run and fold each displacement into the LDR/STR immediate.
//
// Correctness: guest GPRs cannot change within a run (only x87 instructions;
// the one exception, FSTSW AX, is handled by excluding RAX-based operands
// when an FStsw is present).  Semantics note for 32-bit addressing: folding
// computes zext32(base) + disp instead of zext32(base + disp) — divergence
// only on 32-bit pointer wraparound, impossible for valid pointers with
// |disp| ≤ 32 KB.

static bool addr_operand_base_cacheable(const IROperand* op) {
    return op->kind == IROperandKind::MemRef && op->mem.seg_override == 0 &&
           (op->mem.mem_flags & 1) != 0;  // has_base
}

// Same address computation modulo displacement.
static bool addr_base_key_equal(const IROperand* a, const IROperand* b) {
    return a->mem.addr_size == b->mem.addr_size &&
           a->mem.mem_flags == b->mem.mem_flags &&
           a->mem.base_reg == b->mem.base_reg &&
           a->mem.index_reg == b->mem.index_reg &&
           a->mem.shift_amount == b->mem.shift_amount;
}

static bool addr_disp_foldable(const IROperand* op, bool is_f64) {
    const int64_t disp = op->mem.disp;
    const int scale = is_f64 ? 8 : 4;
    if (disp >= 0 && disp % scale == 0 && disp / scale <= 4095) return true;
    return disp >= -256 && disp <= 255;  // LDUR/STUR imm9
}

static bool addr_uses_rax(const IROperand* op) {
    if ((op->mem.mem_flags & 1) && (op->mem.base_reg & 0xF) == 0) return true;
    if ((op->mem.mem_flags & 2) && (op->mem.index_reg & 0xF) == 0) return true;
    return false;
}

// Pick up to 2 base keys with ≥2 foldable f32/f64 accesses each; store the
// representative node IDs in ctx.addr_cache_rep.  Returns the planned count.
// The caller (compile_run) degrades the plan to fit the GPR pool — each
// cached base pins exactly one extra GPR for the whole run.
static int plan_addr_cache(Context& ctx) {
    bool has_fstsw = false;
    for (int i = 0; i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        if (n.op == Op::FStsw) has_fstsw = true;
        // Any segment-override memory operand in the run disables the cache:
        // the GS/TLS fallback path fixed-allocates pool slot 7 (x29) mid-run,
        // which would assert if a cached base happens to hold it (and the FS/GS
        // paths also allocate more transient GPRs than the pressure model
        // attributes to a Load/Store node).
        switch (n.op) {
            case Op::LoadF64: case Op::LoadF32:
            case Op::LoadI16: case Op::LoadI32: case Op::LoadI64:
            case Op::StoreF64: case Op::StoreF32:
            case Op::StoreI16: case Op::StoreI32: case Op::StoreI64:
            case Op::StoreCW: case Op::LoadCW:
                if (n.mem_operand->kind == IROperandKind::MemRef &&
                    n.mem_operand->mem.seg_override != 0)
                    return 0;
                break;
            default:
                break;
        }
    }

    struct { int16_t node; int count; } keys[6];
    int nkeys = 0;
    for (int i = 0; i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        bool is_f64;
        switch (n.op) {
            case Op::LoadF64: case Op::StoreF64: is_f64 = true; break;
            case Op::LoadF32: case Op::StoreF32: is_f64 = false; break;
            default: continue;
        }
        const IROperand* mo = n.mem_operand;
        if (!addr_operand_base_cacheable(mo)) continue;
        if (has_fstsw && addr_uses_rax(mo)) continue;
        if (!addr_disp_foldable(mo, is_f64)) continue;
        int k = 0;
        for (; k < nkeys; k++) {
            if (addr_base_key_equal(ctx.nodes[keys[k].node].mem_operand, mo)) {
                keys[k].count++;
                break;
            }
        }
        if (k == nkeys && nkeys < 6) {
            keys[nkeys].node = static_cast<int16_t>(i);
            keys[nkeys].count = 1;
            nkeys++;
        }
    }

    int picked = 0;
    for (int round = 0; round < 2; round++) {
        int best = -1;
        for (int k = 0; k < nkeys; k++) {
            if (keys[k].count >= 2 && (best < 0 || keys[k].count > keys[best].count))
                best = k;
        }
        if (best < 0) break;
        ctx.addr_cache_rep[picked++] = keys[best].node;
        keys[best].count = 0;
    }
    return picked;
}

// ── RC preamble: load control_word and extract rounding-control bits ────────

static void emit_rc_preamble(AssemblerBuffer& buf, int Xbase, int Wd_out) {
    // LDRH Wd_out, [Xbase, #0]  — control_word is at offset 0x00
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/1, /*imm12=*/0, Xbase, Wd_out);
    // UBFX Wd_out, Wd_out, #10, #2  — extract RC field (bits 11:10)
    emit_bitfield(buf, /*is_64=*/0, /*UBFM*/2, /*N*/0, /*immr*/10, /*imms*/11, Wd_out, Wd_out);
}

// ── Rounding-mode dispatch for FISTP/FIST ──────────────────────────────────
//
// Reads control_word, extracts RC, then emits the shared binary TBNZ dispatch
// tree (or a single FCVTNS under fast_round).  Wd_rc is left holding the
// extracted RC value (the tree is non-destructive).

static void emit_rcmode_dispatch(AssemblerBuffer& buf, int Wd_int, int Dd_val,
                                  int is_64bit_int, int Xbase, int Wd_rc) {
    if (g_rosetta_config && g_rosetta_config->fast_round) {
        // Fast path: assume RC=0 (round-to-nearest).
        emit_fcvt_fp_to_int(buf, is_64bit_int, /*ftype=double*/ 1, /*rmode=FCVTNS*/ 0,
                            Wd_int, Dd_val);
    } else {
        emit_rc_preamble(buf, Xbase, Wd_rc);
        emit_x87_rc_dispatch_fcvt(buf, Wd_rc, Wd_int, Dd_val, is_64bit_int);
    }
}

// ── Main lowering ───────────────────────────────────────────────────────────

void lower(Context& ctx, TranslationResult* result) {
    auto& buf = result->insn_buf;

    // ── Preamble: acquire base, TOP, and st_base ────────────────────────────
    auto [Xbase, Wd_top] = TranslatorX87::x87_begin(*result, buf);
    int Xst_base = TranslatorX87::x87_get_st_base(*result);
    int Wd_tmp = alloc_gpr(*result, 2);

    // Carried-in deferred cache state (mid-run entry). The epilogue folds
    // these into its TOP/tag writeback; step 6 then clears the flags.
    const bool entry_top_dirty = result->x87_cache.top_dirty != 0;
    const int entry_push_count = result->x87_cache.deferred_push_count;
    const int entry_pop_count = result->x87_cache.deferred_pop_count;

    // ── TOP=0 specialization gate ───────────────────────────────────────────
    // In real code TOP is almost always 0 at run entry (balanced stack
    // discipline). When enough stack-slot traffic would become static, the
    // run is emitted twice behind a CBNZ guard: a specialized body where
    // every ST(i) physical index, tag mask and TOP value is a translate-time
    // constant (wrap included), and the generic body as fallback.
    int top0_benefit = 0;
    for (int i = 0; i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        // ReadSt at depth > 0: ADD+AND+LDR → LDR imm.
        if (n.op == Op::ReadSt && n.initial_depth > 0) top0_benefit += 2;
    }
    for (int d = 1; d < 8; d++) {
        // Epilogue store at depth > 0: ADD+AND+STR → STR imm.
        int16_t val = ctx.slot_val[d];
        if (val < 0 || val >= ctx.num_nodes) continue;
        if (ctx.nodes[val].op == Op::ReadSt &&
            ctx.nodes[val].initial_depth == d + ctx.top_delta)
            continue;  // epilogue skips this store anyway
        top0_benefit += 2;
    }
    // TOP update becomes MOVZ, tag batch masks become constants.
    if (ctx.top_delta != 0) top0_benefit += 3;
    const bool top0_specialize = top0_benefit >= 4;

    // ── Base-address cache: materialize planned guest bases ────────────────
    const int addr_n = ctx.addr_cache_n;
    IROperand* addr_rep[2] = {nullptr, nullptr};
    int addr_reg[2] = {-1, -1};
    bool addr_owned[2] = {false, false};
    for (int k = 0; k < addr_n; k++) {
        addr_rep[k] = ctx.nodes[ctx.addr_cache_rep[k]].mem_operand;
        IROperand base_op = *addr_rep[k];
        base_op.mem.disp = 0;
        addr_reg[k] = compute_operand_address(*result, true, &base_op, GPR::XZR);
        // The 64-bit no-disp path returns the guest register itself (nothing
        // allocated); only scratch-pool registers are ours to free.
        addr_owned[k] = ((kGprScratchMask >> addr_reg[k]) & 1u) != 0;
    }

    // Emit a Load*/Store* access through a cached base + immediate offset.
    // Returns false if the operand matches no cached base (or the disp fits
    // neither form) — caller falls back to compute_operand_address.
    auto emit_cached_access = [&](const Node& n, int size, int is_load, int Vt) -> bool {
        for (int k = 0; k < addr_n; k++) {
            if (!addr_base_key_equal(n.mem_operand, addr_rep[k])) continue;
            const int64_t disp = n.mem_operand->mem.disp;
            const int scale = (size == 3) ? 8 : 4;
            if (disp >= 0 && disp % scale == 0 && disp / scale <= 4095) {
                if (is_load)
                    emit_fldr_imm(buf, size, Vt, addr_reg[k],
                                  static_cast<int16_t>(disp / scale));
                else
                    emit_fstr_imm(buf, size, Vt, addr_reg[k],
                                  static_cast<int16_t>(disp / scale));
            } else if (disp >= -256 && disp <= 255) {
                emit_fldur_fstur(buf, size, is_load, static_cast<int16_t>(disp),
                                 addr_reg[k], Vt);
            } else {
                continue;
            }
            return true;
        }
        return false;
    };

    // ── LDP/STP pairing ─────────────────────────────────────────────────────
    // If node i (LoadF64/StoreF64) and the immediately-next live node are the
    // same op through the same cached base with displacements 8 apart, emit
    // one LDP/STP and skip the partner. Adjacency keeps this model-neutral:
    // both FPRs are simultaneously live at the partner node in the existing
    // pressure model anyway, and reordering two non-overlapping adjacent
    // accesses is safe. Returns the cached-base index for a pairable operand
    // (LDP/STP range: disp % 8 == 0, disp/8 ∈ [-64, 63]) or -1.
    auto pairable_key = [&](const Node& n) -> int {
        for (int k = 0; k < addr_n; k++) {
            if (!addr_base_key_equal(n.mem_operand, addr_rep[k])) continue;
            const int64_t disp = n.mem_operand->mem.disp;
            if (disp % 8 == 0 && disp >= -512 && disp <= 504) return k;
            return -1;
        }
        return -1;
    };
    // Returns the partner node ID for node i, or -1.
    auto find_pair = [&](int i) -> int {
        const auto& n = ctx.nodes[i];
        int j = i + 1;
        while (j < ctx.num_nodes && (ctx.nodes[j].flags & kDead)) j++;
        if (j >= ctx.num_nodes || ctx.nodes[j].op != n.op) return -1;
        const int k1 = pairable_key(n);
        if (k1 < 0 || k1 != pairable_key(ctx.nodes[j])) return -1;
        const int64_t d1 = n.mem_operand->mem.disp;
        const int64_t d2 = ctx.nodes[j].mem_operand->mem.disp;
        if (d2 != d1 + 8 && d2 != d1 - 8) return -1;
        return j;
    };

    // ── RC caching: hoist LDRH+UBFX when ≥2 RC consumers in a segment ────
    int Wd_rc_cached = -1;

    if (!(g_rosetta_config && g_rosetta_config->fast_round)) {
        int rc_count = 0;
        bool use_rc_cache = false;
        for (int i = 0; i < ctx.num_nodes; i++) {
            auto& n = ctx.nodes[i];
            if (n.flags & kDead) continue;
            if (n.op == Op::StoreCW) { continue; }
            bool is_rc = (n.op == Op::FRndInt) ||
                ((n.op == Op::StoreI16 || n.op == Op::StoreI32 || n.op == Op::StoreI64)
                 && !(n.flags & kTruncate));
            if (is_rc && ++rc_count >= 2) { use_rc_cache = true; break; }
        }
        if (use_rc_cache)
            // alloc_free_gpr, NOT alloc_gpr(pool 3): the addr cache may
            // already hold x25 (any scratch), and fixed-slot allocation
            // asserts on collision. The RC dispatch works from any register.
            Wd_rc_cached = alloc_free_gpr(*result);
    }

    // ── NZCV hoisting / elision around FCmp/FTst ────────────────────────────
    // Hoisting: instead of saving/restoring guest NZCV per compare, save once
    // before the first compare and restore once after the last.  Safe only
    // when no node legitimately writes/reads NZCV in between (FComI writes it
    // for the guest; FCSel reads it) — nothing else emitted by this pipeline
    // touches flags.
    // Elision (nzcv_skip): when compile_run proved the guest flags dead after
    // the run (ctx.nzcv_dead), drop the MRS/MSR pair entirely.
    int nzcv_first_cmp = -1, nzcv_last_cmp = -1;
    bool nzcv_hoist = false;
    bool nzcv_skip = false;
    {
        int cmp_count = 0;
        bool has_nzcv_user = false;
        for (int i = 0; i < ctx.num_nodes; i++) {
            auto& n = ctx.nodes[i];
            if (n.flags & kDead) continue;
            if (n.op == Op::FComI || n.op == Op::FCSel) { has_nzcv_user = true; break; }
            if (n.op == Op::FCmp || n.op == Op::FTst) {
                if (nzcv_first_cmp < 0) nzcv_first_cmp = i;
                nzcv_last_cmp = i;
                cmp_count++;
            }
        }
        nzcv_skip = ctx.nzcv_dead && !has_nzcv_user && cmp_count >= 1;
        nzcv_hoist = !nzcv_skip && !has_nzcv_user && cmp_count >= 2;
    }

    // ── Run body (node loop + x87-state epilogue) ───────────────────────────
    // Emitted once normally, or twice when TOP=0 specialization is active:
    // top_known = 0 makes every stack-slot physical index / tag mask / TOP
    // value a translate-time constant; top_known = -1 is the generic body.
    auto emit_body = [&](int top_known) {
    FPRState fprs;
    fprs.compute_last_uses(ctx);
    bool pair_done[kMaxNodes] = {};
    bool rc_cache_valid = false;
    int Wd_nzcv_saved = -1;
    const int final_top_known =
        (top_known >= 0) ? ((top_known + ctx.top_delta) & 7) : -1;

    // ── Emit each IR node ───────────────────────────────────────────────────
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        if (pair_done[i]) {
            // Access already emitted as half of an LDP/STP; only the FPR
            // lifetime bookkeeping remains.
            fprs.free_dead_inputs(*result, n, i);
            continue;
        }

        switch (n.op) {

        // ── Value nodes ─────────────────────────────────────────────────
        case Op::ReadSt: {
            int Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            if (top_known >= 0) {
                // Static physical slot: LDR Dd, [Xbase, #st_off].
                const int phys = (top_known + n.initial_depth) & 7;
                emit_fldr_imm(buf, 3, Dd, Xbase,
                              static_cast<int16_t>((kX87RegFileOff >> 3) + phys));
            } else {
                emit_load_st(buf, Xbase, Wd_top, n.initial_depth, Wd_tmp, Dd, Xst_base);
            }
            break;
        }
        case Op::LoadF64: {
            int Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            int j = find_pair(i);
            if (j >= 0) {
                int Dd2 = alloc_free_fpr(*result);
                fprs.node_fpr[j] = static_cast<int8_t>(Dd2);
                pair_done[j] = true;
                const int k = pairable_key(n);
                const int64_t d1 = n.mem_operand->mem.disp;
                const int64_t d2 = ctx.nodes[j].mem_operand->mem.disp;
                const int64_t lo = d1 < d2 ? d1 : d2;
                emit_fldp_fstp_d(buf, /*is_load=*/1, static_cast<int16_t>(lo / 8),
                                 addr_reg[k], d1 < d2 ? Dd : Dd2, d1 < d2 ? Dd2 : Dd);
                break;
            }
            if (!emit_cached_access(n, 3, /*is_load=*/1, Dd)) {
                int addr = compute_operand_address(*result, true, n.mem_operand, GPR::XZR);
                emit_fldr_imm(buf, 3, Dd, addr, 0);
                free_gpr(*result, addr);
            }
            break;
        }
        case Op::LoadF32: {
            int Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            if (!emit_cached_access(n, 2, /*is_load=*/1, Dd)) {
                int addr = compute_operand_address(*result, true, n.mem_operand, GPR::XZR);
                emit_fldr_imm(buf, 2, Dd, addr, 0);
                free_gpr(*result, addr);
            }
            emit_fcvt_s_to_d(buf, Dd, Dd);
            break;
        }
        case Op::LoadI16: {
            int Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            int addr = compute_operand_address(*result, true, n.mem_operand, GPR::XZR);
            int Wd_val = alloc_free_gpr(*result);
            // LDRSH Wd_val, [addr] — sign-extending load
            emit_ldrs(buf, /*is_64=*/0, /*size=S16*/1, Wd_val, addr);
            free_gpr(*result, addr);
            // SCVTF Dd, Wd_val
            emit_scvtf(buf, /*is_64_int=*/0, /*ftype=f64*/1, Dd, Wd_val);
            free_gpr(*result, Wd_val);
            break;
        }
        case Op::LoadI32: {
            int Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            int addr = compute_operand_address(*result, true, n.mem_operand, GPR::XZR);
            int Wd_val = alloc_free_gpr(*result);
            emit_ldr_imm(buf, /*size=S32*/2, Wd_val, addr, 0);
            free_gpr(*result, addr);
            // SCVTF W-form treats the 32-bit source as signed
            emit_scvtf(buf, /*is_64_int=*/0, /*ftype=f64*/1, Dd, Wd_val);
            free_gpr(*result, Wd_val);
            break;
        }
        case Op::LoadI64: {
            int Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            int addr = compute_operand_address(*result, true, n.mem_operand, GPR::XZR);
            int Xd_val = alloc_free_gpr(*result);
            emit_ldr_imm(buf, /*size=S64*/3, Xd_val, addr, 0);
            free_gpr(*result, addr);
            emit_scvtf_x_to_d(buf, Dd, Xd_val);
            free_gpr(*result, Xd_val);
            break;
        }
        case Op::ConstZero: {
            int Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_movi_d_zero(buf, Dd);
            break;
        }
        case Op::ConstOne: {
            int Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_fmov_d_one(buf, Dd);
            break;
        }
        case Op::ConstF64: {
            int Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            uint8_t imm8;
            if (f64_fmov_imm8(n.imm_bits, &imm8))
                emit_fmov_d_imm8(buf, Dd, imm8);
            else
                emit_ldr_literal_f64(buf, Dd, n.imm_bits);
            break;
        }

        // ── Binary arithmetic ───────────────────────────────────────────
        case Op::FAdd: {
            int Dn = fprs.get(n.inputs[0]), Dm = fprs.get(n.inputs[1]);
            int Dd = fprs.try_reuse_input(ctx, i);
            if (Dd < 0) Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_fadd_f64(buf, Dd, Dn, Dm);
            break;
        }
        case Op::FSub: {
            int Dn = fprs.get(n.inputs[0]), Dm = fprs.get(n.inputs[1]);
            int Dd = fprs.try_reuse_input(ctx, i);
            if (Dd < 0) Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_fsub_f64(buf, Dd, Dn, Dm);
            break;
        }
        case Op::FMul: {
            int Dn = fprs.get(n.inputs[0]), Dm = fprs.get(n.inputs[1]);
            int Dd = fprs.try_reuse_input(ctx, i);
            if (Dd < 0) Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_fmul_f64(buf, Dd, Dn, Dm);
            break;
        }
        case Op::FNMul: {
            int Dn = fprs.get(n.inputs[0]), Dm = fprs.get(n.inputs[1]);
            int Dd = fprs.try_reuse_input(ctx, i);
            if (Dd < 0) Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_fnmul_f64(buf, Dd, Dn, Dm);
            break;
        }
        case Op::FDiv: {
            int Dn = fprs.get(n.inputs[0]), Dm = fprs.get(n.inputs[1]);
            int Dd = fprs.try_reuse_input(ctx, i);
            if (Dd < 0) Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_fdiv_f64(buf, Dd, Dn, Dm);
            break;
        }

        // ── FMA ─────────────────────────────────────────────────────────
        case Op::FMAdd: {
            // FMADD Dd, Dn, Dm, Da → Da + Dn * Dm
            // inputs[0] = Dn, inputs[1] = Dm, inputs[2] = Da
            int Dn = fprs.get(n.inputs[0]), Dm = fprs.get(n.inputs[1]);
            int Da = fprs.get(n.inputs[2]);
            int Dd = fprs.try_reuse_input(ctx, i);
            if (Dd < 0) Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_fmadd_f64(buf, Dd, Dn, Dm, Da);
            break;
        }
        case Op::FMSub: {
            // FMSUB Dd, Dn, Dm, Da → Da - Dn * Dm
            int Dn = fprs.get(n.inputs[0]), Dm = fprs.get(n.inputs[1]);
            int Da = fprs.get(n.inputs[2]);
            int Dd = fprs.try_reuse_input(ctx, i);
            if (Dd < 0) Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_fmsub_f64(buf, Dd, Dn, Dm, Da);
            break;
        }
        case Op::FNMSub: {
            // FNMSUB Dd, Dn, Dm, Da → Dn * Dm - Da
            int Dn = fprs.get(n.inputs[0]), Dm = fprs.get(n.inputs[1]);
            int Da = fprs.get(n.inputs[2]);
            int Dd = fprs.try_reuse_input(ctx, i);
            if (Dd < 0) Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_fnmsub_f64(buf, Dd, Dn, Dm, Da);
            break;
        }

        // ── Unary ───────────────────────────────────────────────────────
        case Op::FNeg: {
            int Dn = fprs.get(n.inputs[0]);
            int Dd = fprs.try_reuse_input(ctx, i);
            if (Dd < 0) Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_fneg_f64(buf, Dd, Dn);
            break;
        }
        case Op::FAbs: {
            int Dn = fprs.get(n.inputs[0]);
            int Dd = fprs.try_reuse_input(ctx, i);
            if (Dd < 0) Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_fabs_f64(buf, Dd, Dn);
            break;
        }
        case Op::FSqrt: {
            int Dn = fprs.get(n.inputs[0]);
            int Dd = fprs.try_reuse_input(ctx, i);
            if (Dd < 0) Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_fsqrt_f64(buf, Dd, Dn);
            break;
        }
        case Op::FRndInt: {
            int Dn = fprs.get(n.inputs[0]);
            int Dd = fprs.try_reuse_input(ctx, i);
            if (Dd < 0) Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);

            if (g_rosetta_config && g_rosetta_config->fast_round) {
                // Fast path: RC=0 → FRINTN
                emit_fp_dp1(buf, /*type=*/1, /*FRINTN=*/8, Dd, Dn);
            } else if (Wd_rc_cached >= 0) {
                // RC caching: emit preamble on first use, then reuse cached RC.
                if (!rc_cache_valid) {
                    emit_rc_preamble(buf, Xbase, Wd_rc_cached);
                    rc_cache_valid = true;
                }
                emit_x87_rc_dispatch_frint(buf, Wd_rc_cached, Dd, Dn);
            } else {
                // alloc_free_gpr, NOT alloc_gpr(pool 3) — see RC cache above.
                int Wd_rc = alloc_free_gpr(*result);
                emit_rc_preamble(buf, Xbase, Wd_rc);
                emit_x87_rc_dispatch_frint(buf, Wd_rc, Dd, Dn);
                free_gpr(*result, Wd_rc);
            }
            break;
        }

        // ── Conditional select (FCMOV) ────────────────────────────────
        case Op::FCSel: {
            int Dn = fprs.get(n.inputs[0]);   // ST(0) — false arm
            int Dm = fprs.get(n.inputs[1]);   // ST(i) — true arm
            int Dd = fprs.try_reuse_input(ctx, i);
            if (Dd < 0) Dd = alloc_free_fpr(*result);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            int cond = static_cast<int>(n.imm_bits & 0xF);
            // FCSEL Dd, Dn_true, Dm_false, cond → Dd = cond ? Dn : Dm
            emit_fcsel_f64(buf, Dd, Dm, Dn, cond);
            break;
        }

        // ── Memory stores ───────────────────────────────────────────────
        case Op::StoreF64: {
            int Dd_val = fprs.get(n.inputs[0]);
            int j = find_pair(i);
            if (j >= 0) {
                // Both values are already computed (the partner's input must
                // precede this node — everything between i and j is dead).
                int Dd_val2 = fprs.get(ctx.nodes[j].inputs[0]);
                pair_done[j] = true;
                const int k = pairable_key(n);
                const int64_t d1 = n.mem_operand->mem.disp;
                const int64_t d2 = ctx.nodes[j].mem_operand->mem.disp;
                const int64_t lo = d1 < d2 ? d1 : d2;
                emit_fldp_fstp_d(buf, /*is_load=*/0, static_cast<int16_t>(lo / 8),
                                 addr_reg[k], d1 < d2 ? Dd_val : Dd_val2,
                                 d1 < d2 ? Dd_val2 : Dd_val);
                break;
            }
            if (!emit_cached_access(n, 3, /*is_load=*/0, Dd_val)) {
                int addr = compute_operand_address(*result, true, n.mem_operand, GPR::XZR);
                emit_fstr_imm(buf, 3, Dd_val, addr, 0);
                free_gpr(*result, addr);
            }
            break;
        }
        case Op::StoreF32: {
            // Narrow f64 → f32, then store.
            int Ds_tmp = alloc_free_fpr(*result);
            emit_fcvt_d_to_s(buf, Ds_tmp, fprs.get(n.inputs[0]));
            if (!emit_cached_access(n, 2, /*is_load=*/0, Ds_tmp)) {
                int addr = compute_operand_address(*result, true, n.mem_operand, GPR::XZR);
                emit_fstr_imm(buf, 2, Ds_tmp, addr, 0);
                free_gpr(*result, addr);
            }
            free_fpr(*result, Ds_tmp);
            break;
        }

        // ── Integer stores (FISTP/FIST/FISTTP) ──────────────────────────
        case Op::StoreI16:
        case Op::StoreI32:
        case Op::StoreI64: {
            int Dd_val = fprs.get(n.inputs[0]);
            int Wd_int = alloc_free_gpr(*result);
            int is_64bit_int = (n.op == Op::StoreI64) ? 1 : 0;
            int store_size = (n.op == Op::StoreI16) ? 1
                           : (n.op == Op::StoreI32) ? 2
                                                    : 3;

            if (n.flags & kTruncate) {
                // FISTTP: always truncate, single FCVTZS.
                emit_fcvt_fp_to_int(buf, is_64bit_int, /*ftype=double*/ 1,
                                    /*rmode=FCVTZS*/ 3, Wd_int, Dd_val);
            } else if (Wd_rc_cached >= 0) {
                // RC caching: emit preamble on first use, then reuse cached RC.
                if (!rc_cache_valid) {
                    emit_rc_preamble(buf, Xbase, Wd_rc_cached);
                    rc_cache_valid = true;
                }
                emit_x87_rc_dispatch_fcvt(buf, Wd_rc_cached, Wd_int, Dd_val,
                                           is_64bit_int);
            } else {
                // FISTP/FIST: respect rounding mode from control_word.
                emit_rcmode_dispatch(buf, Wd_int, Dd_val, is_64bit_int, Xbase, Wd_tmp);
            }

            int addr = compute_operand_address(*result, true, n.mem_operand, GPR::XZR);
            emit_str_imm(buf, store_size, Wd_int, addr, /*imm12=*/0);
            free_gpr(*result, addr);
            free_gpr(*result, Wd_int);
            break;
        }

        // ── Compare ─────────────────────────────────────────────────────
        case Op::FCmp: {
            int Wd_packed;
            if (nzcv_skip || nzcv_hoist) {
                if (nzcv_hoist && Wd_nzcv_saved < 0) {
                    Wd_nzcv_saved = alloc_free_gpr(*result);
                    emit_mrs_nzcv(buf, Wd_nzcv_saved);
                }
                emit_fcmp_f64(buf, fprs.get(n.inputs[0]), fprs.get(n.inputs[1]));

                Wd_packed = alloc_free_gpr(*result);
                emit_fcom_cc_pack_hoisted(buf, *result, Wd_packed);
                if (nzcv_hoist && i == nzcv_last_cmp) {
                    emit_msr_nzcv(buf, Wd_nzcv_saved);
                    free_gpr(*result, Wd_nzcv_saved);
                    Wd_nzcv_saved = -1;
                }
            } else {
                int Wd_save = alloc_free_gpr(*result);
                emit_mrs_nzcv(buf, Wd_save);
                emit_fcmp_f64(buf, fprs.get(n.inputs[0]), fprs.get(n.inputs[1]));

                Wd_packed = alloc_free_gpr(*result);
                emit_fcom_cc_pack(buf, *result, Wd_packed, Wd_save);
                // emit_fcom_cc_pack restores NZCV and frees Wd_save internally.
            }

            if (n.flags & kFcomFused) {
                // Fused: keep packed CC alive for FStsw to consume.
                // Store the GPR number in node_fpr[] (repurposed for GPR tracking).
                fprs.node_fpr[i] = static_cast<int8_t>(Wd_packed);
            } else {
                // Non-fused: write CC to status_word now.
                emit_fcom_cc_write_sw(buf, *result, Xbase, Wd_packed);
                free_gpr(*result, Wd_packed);
            }
            break;
        }
        case Op::FTst: {
            int Wd_packed;
            if (nzcv_skip || nzcv_hoist) {
                if (nzcv_hoist && Wd_nzcv_saved < 0) {
                    Wd_nzcv_saved = alloc_free_gpr(*result);
                    emit_mrs_nzcv(buf, Wd_nzcv_saved);
                }
                emit_fcmp_zero_f64(buf, fprs.get(n.inputs[0]));

                Wd_packed = alloc_free_gpr(*result);
                emit_fcom_cc_pack_hoisted(buf, *result, Wd_packed);
                if (nzcv_hoist && i == nzcv_last_cmp) {
                    emit_msr_nzcv(buf, Wd_nzcv_saved);
                    free_gpr(*result, Wd_nzcv_saved);
                    Wd_nzcv_saved = -1;
                }
            } else {
                int Wd_save = alloc_free_gpr(*result);
                emit_mrs_nzcv(buf, Wd_save);
                emit_fcmp_zero_f64(buf, fprs.get(n.inputs[0]));

                Wd_packed = alloc_free_gpr(*result);
                emit_fcom_cc_pack(buf, *result, Wd_packed, Wd_save);
            }

            if (n.flags & kFcomFused) {
                fprs.node_fpr[i] = static_cast<int8_t>(Wd_packed);
            } else {
                emit_fcom_cc_write_sw(buf, *result, Xbase, Wd_packed);
                free_gpr(*result, Wd_packed);
            }
            break;
        }

        // ── FCOMI / FCOMIP / FUCOMI / FUCOMIP ───────────────────────────
        case Op::FComI: {
            // Direct port of translate_fcomi: FCMP two FPRs, then pack and
            // write x86-compatible flags into NZCV. Does NOT touch status_word.
            int Dd_st0 = fprs.get(n.inputs[0]);
            int Dd_src = fprs.get(n.inputs[1]);

            emit_fcmp_f64(buf, Dd_st0, Dd_src);

            // Extract condition bits before any MSR clobbers NZCV.
            int Wd_z = alloc_free_gpr(*result);
            int Wd_v = alloc_free_gpr(*result);
            int Wd_c = alloc_free_gpr(*result);

            emit_cset(buf, /*is_64bit=*/0, /*EQ=*/0, Wd_z);   // 1 if equal
            emit_cset(buf, /*is_64bit=*/0, /*VS=*/6, Wd_v);   // 1 if unordered
            emit_cset(buf, /*is_64bit=*/0, /*CS=*/2, Wd_c);   // 1 if carry set

            // Z_new = Z | V  (equal or unordered → ZF)
            emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_v, 0, Wd_z, Wd_z);
            // C_new = C & !V  (carry clear for unordered → CF)
            emit_logical_shifted_reg(buf, 0, /*AND*/0, /*N=invert rhs*/1, /*LSL*/0, Wd_v, 0, Wd_c, Wd_c);

            // Pack NZCV: bit30=ZF, bit29=CF, bit28=V(PF for FCMOV), bit26=PF
            emit_bitfield(buf, /*is_64=*/0, /*UBFM=*/2, /*N=*/0,
                          /*immr=*/2, /*imms=*/1, Wd_z, Wd_z);
            emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_c, 29, Wd_z, Wd_z);
            emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_v, 28, Wd_z, Wd_z);
            emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_v, 26, Wd_z, Wd_z);

            emit_msr_nzcv(buf, Wd_z);

            free_gpr(*result, Wd_c);
            free_gpr(*result, Wd_v);
            free_gpr(*result, Wd_z);
            // Pop (for FCOMIP/FUCOMIP) is handled by the IR epilogue via top_delta.
            break;
        }

        // ── Control word ────────────────────────────────────────────────
        case Op::StoreCW: {
            // FLDCW: load u16 from memory, write to X87State.control_word.
            int addr = compute_operand_address(*result, true, n.mem_operand, GPR::XZR);
            int Wd_cw = alloc_free_gpr(*result);
            emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/1, /*imm12=*/0, addr, Wd_cw);
            free_gpr(*result, addr);
            // STRH Wd_cw, [Xbase, #0]  — control_word is at offset 0x00 → imm12=0
            emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/0, /*imm12=*/0, Xbase, Wd_cw);
            // Re-cache RC from the just-written control word.
            if (Wd_rc_cached >= 0) {
                // UBFX Wd_rc_cached, Wd_cw, #10, #2
                emit_bitfield(buf, 0, 2, 0, 10, 11, Wd_cw, Wd_rc_cached);
                rc_cache_valid = true;
            } else {
                rc_cache_valid = false;
            }
            free_gpr(*result, Wd_cw);
            break;
        }
        case Op::LoadCW: {
            // FNSTCW: read X87State.control_word, store u16 to memory.
            int Wd_cw = alloc_free_gpr(*result);
            // LDRH Wd_cw, [Xbase, #0]  — control_word is at offset 0x00 → imm12=0
            emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/1, /*imm12=*/0, Xbase, Wd_cw);
            int addr = compute_operand_address(*result, true, n.mem_operand, GPR::XZR);
            emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/0, /*imm12=*/0, addr, Wd_cw);
            free_gpr(*result, addr);
            free_gpr(*result, Wd_cw);
            break;
        }

        // ── FSTSW AX ───────────────────────────────────────────────────
        case Op::FStsw: {
            static constexpr int16_t kSwImm12 = kX87StatusWordOff / 2;  // = 1

            int Wd_sw;
            if (n.flags & kFcomFused) {
                // Fused: RMW status_word with the packed CC held from the
                // FCmp, keeping the merged value in a GPR — skips the LDRH
                // reload of the halfword just stored (a store→load hazard).
                int16_t fcmp_id = n.inputs[0];
                int Wd_packed = fprs.get(fcmp_id);

                Wd_sw = emit_fcom_cc_write_sw_keep(buf, *result, Xbase, Wd_packed);
                free_gpr(*result, Wd_packed);
                fprs.node_fpr[fcmp_id] = -1;
            } else {
                // Non-fused: load status_word (CC already written by FCmp).
                Wd_sw = alloc_free_gpr(*result);
                emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/1,
                                 kSwImm12, Xbase, Wd_sw);
            }
            {
                // Patch TOP if pops occurred before this FSTSW, or if the
                // in-memory TOP was already stale on entry (carried top_dirty).
                int16_t td = n.inputs[2];  // top_delta snapshot
                if (td != 0) {
                    if (top_known >= 0) {
                        const int k = (top_known + td) & 7;
                        int Wd_adj = alloc_free_gpr(*result);
                        emit_movn(buf, 0, /*MOVZ*/2, 0, (uint16_t)k, Wd_adj);
                        emit_bitfield(buf, 0, /*BFM*/1, 0, /*immr=*/21, /*imms=*/2,
                                      Wd_adj, Wd_sw);
                        free_gpr(*result, Wd_adj);
                    } else {
                        int Wd_adj = alloc_free_gpr(*result);
                        if (td < 0)
                            emit_add_imm(buf, 0, /*is_sub=*/1, 0, 0, -td, Wd_top, Wd_adj);
                        else
                            emit_add_imm(buf, 0, /*is_sub=*/0, 0, 0, td, Wd_top, Wd_adj);
                        emit_and_imm(buf, 0, Wd_adj, 0, 0, 2, Wd_adj);
                        // BFI Wd_sw, Wd_adj, #11, #3 — patch TOP field
                        emit_bitfield(buf, 0, /*BFM*/1, 0, /*immr=*/21, /*imms=*/2,
                                      Wd_adj, Wd_sw);
                        free_gpr(*result, Wd_adj);
                    }
                } else if (entry_top_dirty) {
                    // BFI Wd_sw, Wd_top, #11, #3 — memory TOP is stale;
                    // Wd_top already holds the correct masked value (which is
                    // the guard constant in the specialized body, so BFI from
                    // XZR clears the field when top_known == 0).
                    if (top_known == 0)
                        emit_bitfield(buf, 0, /*BFM*/1, 0, /*immr=*/21, /*imms=*/2,
                                      GPR::XZR, Wd_sw);
                    else
                        emit_bitfield(buf, 0, /*BFM*/1, 0, /*immr=*/21, /*imms=*/2,
                                      Wd_top, Wd_sw);
                }

                // BFI W_ax, Wd_sw, #0, #16 — write status_word into x86 AX
                int W_ax = n.inputs[1];  // destination register index (usually 0 = W0)
                emit_bitfield(buf, 0, /*BFM*/1, 0, /*immr=*/0, /*imms=*/15,
                              Wd_sw, W_ax);
                free_gpr(*result, Wd_sw);
            }
            break;
        }

        }  // switch

        // Free FPRs whose last use was this node.
        fprs.free_dead_inputs(*result, n, i);
    }

    // ── Epilogue: update x87 state ──────────────────────────────────────────

    // 1. Update TOP register.
    if (ctx.top_delta != 0) {
        if (top_known >= 0) {
            // Final TOP is a translate-time constant.
            emit_movn(buf, 0, /*MOVZ*/2, 0, (uint16_t)final_top_known, Wd_top);
        } else {
            if (ctx.top_delta < 0) {
                emit_add_imm(buf, 0, /*is_sub=*/1, 0, 0, -ctx.top_delta, Wd_top, Wd_top);
            } else {
                emit_add_imm(buf, 0, /*is_sub=*/0, 0, 0, ctx.top_delta, Wd_top, Wd_top);
            }
            emit_and_imm(buf, 0, Wd_top, 0, 0, 2, Wd_top);
        }
    }

    // 2. Store modified stack values.
    // At this point, Wd_top holds the FINAL top. slot_val[d] tells us what value
    // should be at logical depth d relative to the final TOP.
    for (int d = 0; d < 8; d++) {
        int16_t val = ctx.slot_val[d];
        if (val < 0) continue;  // initial slot, unchanged (no store needed)
        // Skip redundant write-back: if the value is a ReadSt loaded from the
        // same physical slot it would be stored to, the store is a no-op.
        if (ctx.nodes[val].op == Op::ReadSt &&
            ctx.nodes[val].initial_depth == d + ctx.top_delta)
            continue;
        int Dd = fprs.get(val);
        if (Dd < 0) continue;   // dead or already freed
        if (top_known >= 0) {
            const int phys = (final_top_known + d) & 7;
            emit_fstr_imm(buf, 3, Dd, Xbase,
                          static_cast<int16_t>((kX87RegFileOff >> 3) + phys));
        } else {
            emit_store_st(buf, Xbase, Wd_top, d, Wd_tmp, Dd, Xst_base);
        }
    }

    // 3. Write TOP to status_word if changed, or if it was already stale on
    //    entry (carried-in top_dirty from deferred pushes/pops).
    if (ctx.top_delta != 0 || entry_top_dirty) {
        emit_store_top(buf, Xbase, Wd_top, Wd_tmp);
    }

    // 4. Update tag word, folding in carried-in deferred push/pop tag updates
    //    (P pending set-valid, Q pending set-empty; P and Q never coexist).
    //    Relative to the FINAL top:
    //      valid slots:  V = max(0, P - top_delta)   at TOP .. TOP+V-1
    //      empty slots:  M = max(0, top_delta + Q - P) at TOP-M .. TOP-1
    //    With P = Q = 0 this reduces to the plain net push/pop cases.
    {
        const int set_valid = (entry_push_count - ctx.top_delta > 0)
                                  ? entry_push_count - ctx.top_delta : 0;
        const int set_empty = (ctx.top_delta + entry_pop_count - entry_push_count > 0)
                                  ? ctx.top_delta + entry_pop_count - entry_push_count : 0;
        if (set_valid > 0 || set_empty > 0) {
            int Wd_tmp2 = alloc_free_gpr(*result);
            int Wd_tagw = alloc_free_gpr(*result);
            if (top_known >= 0) {
                // Static slot positions → constant tag masks (wrap folded at
                // translate time): LDRH / MOVZ+ORR / MOVZ+BIC / STRH.
                emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/1,
                                 kX87TagWordImm12, Xbase, Wd_tagw);
                if (set_empty > 0) {
                    uint16_t mask = 0;
                    for (int k = 1; k <= set_empty; k++)
                        mask |= (uint16_t)(0x3u << (((final_top_known - k) & 7) * 2));
                    emit_movn(buf, 0, /*MOVZ*/2, 0, mask, Wd_tmp2);
                    emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, 0, Wd_tmp2, 0,
                                             Wd_tagw, Wd_tagw);
                }
                if (set_valid > 0) {
                    uint16_t mask = 0;
                    for (int k = 0; k < set_valid; k++)
                        mask |= (uint16_t)(0x3u << (((final_top_known + k) & 7) * 2));
                    emit_movn(buf, 0, /*MOVZ*/2, 0, mask, Wd_tmp2);
                    emit_logical_shifted_reg(buf, 0, /*AND*/0, /*N=BIC*/1, 0, Wd_tmp2,
                                             0, Wd_tagw, Wd_tagw);
                }
                emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/0,
                                 kX87TagWordImm12, Xbase, Wd_tagw);
            } else {
                if (set_empty > 0)
                    emit_x87_tag_set_empty_batch(buf, Xbase, Wd_top, Wd_tmp, Wd_tmp2,
                                                  Wd_tagw, set_empty);
                if (set_valid > 0)
                    emit_x87_tag_set_valid_batch(buf, Xbase, Wd_top, Wd_tmp, Wd_tmp2,
                                                  Wd_tagw, set_valid);
            }
            free_gpr(*result, Wd_tagw);
            free_gpr(*result, Wd_tmp2);
        }
    }

    // 5. Free all remaining FPRs held by node values.
    for (int i = 0; i < ctx.num_nodes; i++) {
        if (fprs.node_fpr[i] >= 0) {
            free_fpr(*result, fprs.node_fpr[i]);
            fprs.node_fpr[i] = -1;
        }
    }
    };  // emit_body

    // ── Emit the run: specialized (TOP==0) + generic behind a guard, or just
    //    the generic body. Branch offsets are patched after emission (the
    //    buffer may grow/move, so patch through buf.data at patch time).
    if (!top0_specialize) {
        emit_body(-1);
    } else {
        const uint32_t saved_gpr_mask = result->free_gpr_mask;
        const uint32_t saved_fpr_mask = result->free_fpr_mask;

        const uint64_t guard_off = buf.end;
        emit_cbz(buf, /*is_64bit=*/0, /*is_nz=*/1, Wd_top, /*imm19=*/0);  // CBNZ → generic
        emit_body(/*top_known=*/0);
        const uint64_t skip_off = buf.end;
        emit_b(buf, 0);                                                   // B → done
        // Patch the CBNZ to land on the generic body.
        buf.data[guard_off / 4] |=
            (((uint32_t)((buf.end - guard_off) / 4) & 0x7FFFF) << 5);

        // The specialized body is balanced, but restore allocation state
        // explicitly so the generic body starts from the identical pool.
        result->free_gpr_mask = saved_gpr_mask;
        result->free_fpr_mask = saved_fpr_mask;
        emit_body(/*top_known=*/-1);
        // Patch the skip branch to land after the generic body.
        buf.data[skip_off / 4] |= ((uint32_t)((buf.end - skip_off) / 4) & 0x3FFFFFF);
    }

    // 6. Clean up cache deferred state (we handled everything inline).
    result->x87_cache.top_dirty = 0;
    result->x87_cache.deferred_push_count = 0;
    result->x87_cache.deferred_pop_count = 0;
    result->x87_cache.reset_perm();

    // 7. Free scratch GPRs.
    for (int k = 0; k < addr_n; k++) {
        if (addr_owned[k])
            free_gpr(*result, addr_reg[k]);
    }
    if (Wd_rc_cached >= 0)
        free_gpr(*result, Wd_rc_cached);
    free_gpr(*result, Wd_tmp);

    // 8. If cache is about to expire (run_remaining will hit 0 after ticks),
    //    free the cache GPRs. Otherwise, leave them pinned for the next run.
    if (result->x87_cache.run_remaining <= ctx.consumed) {
        // Cache will be deactivated by tick(). Release GPRs now so they don't
        // stay allocated past the run.
        // (tick() resets gprs_valid=0 but doesn't free the mask bits.)
        // The caller (Translator.cpp) resets free_gpr_mask after ticking.
    }
}

// ── Peak GPR pressure query ──────────────────────────────────────────────────
//
// Returns the maximum number of scratch GPRs simultaneously in use during
// lowering (permanent + transient).  If this exceeds the available pool the
// caller should bail out to the ordinary per-instruction translation path.
//
// Permanent GPRs (held for the entire lower() duration):
//   - Xbase (pool 0), Wd_top (pool 1), Wd_tmp (pool 2), Xst_base (pool 6) = 4
//   - Wd_rc_cached (pool 3) when RC caching is active = +1
//
// Per-node transient GPR demand (mirrors the lowering code exactly):
//   - ReadSt, Const*, FAdd/FSub/FMul/FDiv, FMA*, FNeg/FAbs/FSqrt, FCSel: 0
//   - LoadF64, LoadF32, StoreF64, StoreF32: 1 (addr from compute_operand_address)
//   - LoadI16/I32/I64: 2 (addr + Wd_val)
//   - StoreI16/I32/I64: 2 (Wd_int + addr)
//   - FRndInt without RC cache: 1 (Wd_rc via alloc_gpr(3))
//   - FCmp/FTst: 4 peak inside emit_fcom_cc_pack (Wd_save + Wd_packed + Wd_cc + Wd_vs)
//     If kFcomFused, Wd_packed stays alive until consumed by FStsw.
//   - FComI: 3 (Wd_z + Wd_v + Wd_c)
//   - FStsw (fused): 2 (Wd_packed held from FCmp + Wd_sw_inner inside emit_fcom_cc_write_sw,
//     or Wd_sw + Wd_adj when top_delta != 0)
//   - FStsw (non-fused): 2 (Wd_sw + Wd_adj if top_delta != 0)
//   - StoreCW/LoadCW: 2 (addr + Wd_cw)
//   - Epilogue (top_delta != 0): 2 (Wd_tmp2 + Wd_tagw)
//
// Fused FCmp/FTst holds 1 GPR (Wd_packed) alive across nodes until FStsw.
// We track this as a "held" count that overlaps with per-node transient demand.
int peak_live_gprs(const Context& ctx, bool entry_deferred) {
    // Determine if RC caching will be active (same logic as lower()).
    bool rc_cache = false;
    if (!(g_rosetta_config && g_rosetta_config->fast_round)) {
        int rc_count = 0;
        for (int i = 0; i < ctx.num_nodes; i++) {
            const auto& n = ctx.nodes[i];
            if (n.flags & kDead) continue;
            if (n.op == Op::StoreCW) continue;
            bool is_rc = (n.op == Op::FRndInt) ||
                ((n.op == Op::StoreI16 || n.op == Op::StoreI32 || n.op == Op::StoreI64)
                 && !(n.flags & kTruncate));
            if (is_rc && ++rc_count >= 2) { rc_cache = true; break; }
        }
    }

    int pinned = 4;  // Xbase, Wd_top, Wd_tmp, Xst_base
    if (rc_cache) pinned++;  // Wd_rc_cached

    // NZCV hoisting/elision mirror (same predicates as lower()): when hoisting,
    // one GPR (Wd_nzcv_saved) is held from the first FCmp/FTst through the
    // last, and each compare no longer allocates a per-node Wd_save. When
    // eliding (nzcv_skip), compares cost 3 transient with nothing held.
    int nzcv_first_cmp = -1, nzcv_last_cmp = -1;
    bool nzcv_hoist = false;
    bool nzcv_skip = false;
    {
        int cmp_count = 0;
        bool has_nzcv_user = false;
        for (int i = 0; i < ctx.num_nodes; i++) {
            const auto& n = ctx.nodes[i];
            if (n.flags & kDead) continue;
            if (n.op == Op::FComI || n.op == Op::FCSel) { has_nzcv_user = true; break; }
            if (n.op == Op::FCmp || n.op == Op::FTst) {
                if (nzcv_first_cmp < 0) nzcv_first_cmp = i;
                nzcv_last_cmp = i;
                cmp_count++;
            }
        }
        nzcv_skip = ctx.nzcv_dead && !has_nzcv_user && cmp_count >= 1;
        nzcv_hoist = !nzcv_skip && !has_nzcv_user && cmp_count >= 2;
    }

    // Simulate GPR pressure across IR nodes.
    // "held" tracks GPRs held alive across node boundaries (fused FCmp→FStsw).
    int held = 0;
    int peak = pinned;  // at minimum, permanent GPRs

    for (int i = 0; i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;

        int transient = 0;  // per-node transient GPR demand

        switch (n.op) {
        // No transient GPRs
        case Op::ReadSt:
        case Op::ConstZero: case Op::ConstOne: case Op::ConstF64:
        case Op::FAdd: case Op::FSub: case Op::FMul: case Op::FDiv:
        case Op::FNMul:
        case Op::FMAdd: case Op::FMSub: case Op::FNMSub:
        case Op::FNeg: case Op::FAbs: case Op::FSqrt:
        case Op::FCSel:
            break;

        // 1 GPR: addr from compute_operand_address
        case Op::LoadF64: case Op::LoadF32:
        case Op::StoreF64: case Op::StoreF32:
            transient = 1;
            break;

        // 2 GPRs: addr + Wd_val
        case Op::LoadI16: case Op::LoadI32: case Op::LoadI64:
            transient = 2;
            break;

        // 2 GPRs: Wd_int + addr
        case Op::StoreI16: case Op::StoreI32: case Op::StoreI64:
            transient = 2;
            break;

        // FRndInt: 1 GPR if no RC cache (alloc_gpr(3) for Wd_rc), 0 with cache
        case Op::FRndInt:
            if (!rc_cache) transient = 1;
            break;

        // FCmp/FTst: 4 peak inside emit_fcom_cc_pack
        // (Wd_save + Wd_packed + Wd_cc + Wd_vs simultaneously live)
        // Hoisted: no per-node Wd_save (3 transient), but Wd_nzcv_saved is
        // held from the first compare through the last (held++ below).
        // If fused, Wd_packed stays alive after — but it is already part of
        // this node's transient count, so the held++ happens after node_total
        // below (adding it here would double-count it and spuriously bail
        // every fused single-compare run: 4 pinned + 4 + 1 = 9 > 8 pool).
        case Op::FCmp: case Op::FTst:
            if (nzcv_skip) {
                transient = 3;  // Wd_packed + Wd_cc + Wd_vs, no save
            } else if (nzcv_hoist) {
                transient = 3;
                if (i == nzcv_first_cmp) held++;  // Wd_nzcv_saved acquired
            } else {
                transient = 4;
            }
            break;

        // FComI: 3 GPRs (Wd_z + Wd_v + Wd_c)
        case Op::FComI:
            transient = 3;
            break;

        // FStsw: fused path holds Wd_packed (counted in held) + up to 2 more
        // Non-fused: up to 2 (Wd_sw + Wd_adj)
        case Op::FStsw:
            // Fused: emit_fcom_cc_write_sw_keep allocates Wd_sw while
            // Wd_packed (held) is still live, then Wd_packed is freed and
            // Wd_sw + possibly Wd_adj coexist → peak 2 alongside held-1.
            // Non-fused: max(Wd_sw+Wd_adj) = 2
            transient = 2;
            if (n.flags & kFcomFused) {
                // Wd_packed is released during this node
                held--;
            }
            break;

        // StoreCW/LoadCW: 2 GPRs (addr + Wd_cw)
        case Op::StoreCW: case Op::LoadCW:
            transient = 2;
            break;
        }

        int node_total = pinned + held + transient;
        if (node_total > peak) peak = node_total;

        // Fused FCmp/FTst: Wd_packed survives the node (until FStsw). It was
        // counted in this node's transient demand; from here on it's held.
        if ((n.op == Op::FCmp || n.op == Op::FTst) && (n.flags & kFcomFused))
            held++;

        // Wd_nzcv_saved is released at the end of the last compare node.
        if (nzcv_hoist && i == nzcv_last_cmp) held--;
    }

    // Epilogue: if top_delta != 0 (or carried-in deferred tag/top state must be
    // materialized), needs 2 more transient GPRs (Wd_tmp2 + Wd_tagw)
    if (ctx.top_delta != 0 || entry_deferred) {
        int epilogue_total = pinned + held + 2;
        if (epilogue_total > peak) peak = epilogue_total;
    }

    return peak;
}

// ── Peak FPR pressure query ──────────────────────────────────────────────────
//
// Simulates the liveness model used by the lowering pass and returns the
// maximum number of scratch FPRs simultaneously in use at any point.
//
// Rules (mirroring the lowering pass exactly):
//   - Value-producing nodes (ReadSt, Load*, Const*, FAdd, …) hold one FPR from
//     the point they are emitted until their last use is emitted.
//   - free_dead_inputs() fires at the end of each node, so the transient peak
//     *during* a node is: (currently live) + 1 for the new output, before dead
//     inputs are freed.  try_reuse_input() avoids the +1 by recycling a dying
//     input's FPR; we model it with the same claim order as lower().
//   - StoreF32 allocates one extra transient FPR (Ds_tmp) that is freed before
//     the node ends.  Model as a +1 spike.
//   - StoreI*, FCmp, FTst, FStsw produce no FPR output and need no extra FPRs.
//   - Dead (kDead) nodes are skipped.
int peak_live_fprs(const Context& ctx) {
    // Step 1: compute last_use[] — same as FPRState::compute_last_uses.
    int16_t last_use[kMaxNodes];
    memset(last_use, -1, sizeof(last_use));
    for (int i = 0; i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        for (int j = 0; j < 3; j++) {
            if (n.inputs[j] >= 0) last_use[n.inputs[j]] = static_cast<int16_t>(i);
        }
    }
    for (int d = 0; d < 8; d++) {
        int16_t val = ctx.slot_val[d];
        if (val >= 0 && val < ctx.num_nodes)
            last_use[val] = static_cast<int16_t>(ctx.num_nodes);
    }

    // Step 2: simulate FPR allocation order, tracking live count.
    // A node holds an FPR from instruction i (inclusive) to last_use[i]
    // (exclusive — freed at the end of the last-use instruction).
    // live[i] = number of nodes alive at the *start* of instruction i.
    int live = 0;
    int peak = 0;

    // Track which nodes are currently holding an FPR (bit vector over kMaxNodes).
    bool holding[kMaxNodes] = {};

    for (int i = 0; i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;

        // Allocate FPR for nodes that produce an FPR-bearing value.
        // Ops that call try_reuse_input() in lower() can recycle a dying
        // input's FPR for their output (net-zero live change); model that
        // with the exact same claim order (inputs[0..2], first dying wins).
        bool produces_fpr = false;
        bool can_reuse = false;
        switch (n.op) {
        case Op::ReadSt:
        case Op::LoadF64: case Op::LoadF32:
        case Op::LoadI16: case Op::LoadI32: case Op::LoadI64:
        case Op::ConstZero: case Op::ConstOne: case Op::ConstF64:
            produces_fpr = true;
            break;
        case Op::FAdd: case Op::FSub: case Op::FMul: case Op::FDiv:
        case Op::FNMul:
        case Op::FMAdd: case Op::FMSub: case Op::FNMSub:
        case Op::FNeg: case Op::FAbs: case Op::FSqrt: case Op::FRndInt:
        case Op::FCSel:
            produces_fpr = true;
            can_reuse = true;
            break;
        default:
            break;
        }

        if (produces_fpr) {
            bool reused = false;
            if (can_reuse) {
                for (int j = 0; j < 3; j++) {
                    int16_t in = n.inputs[j];
                    if (in >= 0 && last_use[in] == i && holding[in]) {
                        holding[in] = false;  // FPR claimed by this node's output
                        reused = true;
                        break;
                    }
                }
            }
            if (!reused) live++;
            holding[i] = true;
            if (live > peak) peak = live;
        }

        // StoreF32 allocates a transient Ds_tmp (fcvt d→s narrowing) that is
        // freed before the node finishes.  Model as a +1 spike on top of the
        // current live count.
        if (n.op == Op::StoreF32 && live + 1 > peak)
            peak = live + 1;

        // Free inputs whose last use is this node.
        for (int j = 0; j < 3; j++) {
            int16_t in = n.inputs[j];
            if (in >= 0 && last_use[in] == i && holding[in]) {
                holding[in] = false;
                live--;
            }
        }
    }

    return peak;
}

// ── Entry point ─────────────────────────────────────────────────────────────

int compile_run(TranslationResult* result, IRInstr* instr_array, int64_t num_instrs,
                int64_t start_idx, int run_length) {
    Context ctx;


    // Fold carried-in deferred-FXCH permutation into the initial slot map.
    const auto& cache = result->x87_cache;
    const int8_t* perm = cache.perm_dirty ? cache.perm : nullptr;

    // Constant-load promotion reads guest memory at translation time — only
    // sound in JIT mode, where the guest address space is this process.
    // Constant-load promotion reads guest memory at translation time. The
    // page-protection probe is only compiled into the ROSETTA_RUNTIME build,
    // which is always injected into a live guest process; elsewhere
    // range_is_readonly() is stubbed to false, so the flag is inert.
    const bool const_promote =
        !(g_rosetta_config && g_rosetta_config->disable_const_promote);

    if (!build(ctx, instr_array, num_instrs, start_idx, run_length, perm, const_promote))
        return 0;

    optimize(ctx);

    // Guest-flags deadness: scan the guest instructions after the consumed
    // run; if they fully redefine EFLAGS before any possible reader, the
    // FCmp/FTst NZCV save/restore is elided in lowering.
    ctx.nzcv_dead = nzcv_dead_after_run(instr_array, num_instrs,
                                        start_idx + ctx.consumed) ? 1 : 0;

    // Gate lowering on actual FPR pressure vs. available pool.
    uint32_t fpr_pool = result->free_fpr_mask;
    int available = 0;
    while (fpr_pool) { available++; fpr_pool &= fpr_pool - 1; }
    if (peak_live_fprs(ctx) > available) {
        return 0;
    }

    // Gate lowering on GPR pressure vs. available pool.
    {
        const bool entry_deferred = cache.top_dirty != 0 ||
                                    cache.deferred_push_count > 0 ||
                                    cache.deferred_pop_count > 0;
        uint32_t gpr_pool = result->free_gpr_mask;
        int gpr_available = 0;
        while (gpr_pool) { gpr_available++; gpr_pool &= gpr_pool - 1; }
        const int peak = peak_live_gprs(ctx, entry_deferred);
        if (peak > gpr_available) {
            return 0;
        }
        // Base-address cache: each cached base pins exactly one extra GPR for
        // the whole run (on top of every per-node total), so peak+N is exact.
        // Degrade the plan until it fits.
        int addr_n = plan_addr_cache(ctx);
        while (addr_n > 0 && peak + addr_n > gpr_available)
            addr_n--;
        ctx.addr_cache_n = static_cast<int8_t>(addr_n);
    }

    lower(ctx, result);

    return ctx.consumed;
}

}  // namespace X87IR
