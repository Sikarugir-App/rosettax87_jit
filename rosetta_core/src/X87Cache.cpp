#include "rosetta_core/X87Cache.h"

#include "rosetta_core/IRInstr.h"
#include "rosetta_core/Opcode.h"
#include "rosetta_config/Config.h"

// =============================================================================
// is_handled_x87 — returns true for opcodes that have a translate_* handler.
// Used by lookahead to determine consecutive x87 run lengths.
// =============================================================================

static bool is_handled_x87(uint16_t op) {
    switch (op) {
        case kOpcodeName_fldz:
        case kOpcodeName_fld1:
        case kOpcodeName_fldl2e:
        case kOpcodeName_fldl2t:
        case kOpcodeName_fldlg2:
        case kOpcodeName_fldln2:
        case kOpcodeName_fldpi:
        case kOpcodeName_fld:
        case kOpcodeName_fild:
        case kOpcodeName_fadd:
        case kOpcodeName_faddp:
        case kOpcodeName_fiadd:
        case kOpcodeName_fsub:
        case kOpcodeName_fsubr:
        case kOpcodeName_fsubp:
        case kOpcodeName_fsubrp:
        case kOpcodeName_fdiv:
        case kOpcodeName_fdivr:
        case kOpcodeName_fdivp:
        case kOpcodeName_fdivrp:
        case kOpcodeName_fmul:
        case kOpcodeName_fmulp:
        case kOpcodeName_fst:
        case kOpcodeName_fst_stack:
        case kOpcodeName_fstp:
        case kOpcodeName_fstp_stack:
        case kOpcodeName_fstsw:
        case kOpcodeName_fcom:
        case kOpcodeName_fcomp:
        case kOpcodeName_fcompp:
        case kOpcodeName_fucom:
        case kOpcodeName_fucomp:
        case kOpcodeName_fucompp:
        case kOpcodeName_fxch:
        case kOpcodeName_fchs:
        case kOpcodeName_fabs:
        case kOpcodeName_fsqrt:
        case kOpcodeName_fistp:
        case kOpcodeName_fisttp:
        case kOpcodeName_fidiv:
        case kOpcodeName_fimul:
        case kOpcodeName_fisub:
        case kOpcodeName_fidivr:
        case kOpcodeName_frndint:
        case kOpcodeName_fcomi:
        case kOpcodeName_fcomip:
        case kOpcodeName_fucomi:
        case kOpcodeName_fucomip:
        case kOpcodeName_ftst:
        case kOpcodeName_fist:
        case kOpcodeName_fisubr:
        case kOpcodeName_fcmovb:
        case kOpcodeName_fcmovbe:
        case kOpcodeName_fcmove:
        case kOpcodeName_fcmovnb:
        case kOpcodeName_fcmovnbe:
        case kOpcodeName_fcmovne:
        case kOpcodeName_fcmovu:
        case kOpcodeName_fcmovnu:
        case kOpcodeName_ficom:
        case kOpcodeName_ficomp:
        case kOpcodeName_fldcw:
        case kOpcodeName_fnstcw:
        case kOpcodeName_fnop:
            return true;
        default:
            return false;
    }
}

// =============================================================================
// X87Cache member functions
// =============================================================================

bool X87Cache::active() const {
    return run_remaining > 0;
}

void X87Cache::invalidate() {
    gprs_valid = 0;
    top_dirty = 0;
    deferred_push_count = 0;
    deferred_pop_count = 0;
    run_remaining = 0;
    reset_perm();
}

void X87Cache::invalidate(uint32_t& free_gpr_mask, uint32_t scratch_mask) {
    invalidate();
    free_gpr_mask = scratch_mask;
}

void X87Cache::set_run(int run_length) {
    if (run_length >= 2)
        run_remaining = static_cast<int16_t>(run_length);
}

void X87Cache::tick() {
    if (run_remaining > 0) {
        run_remaining--;
        if (run_remaining == 0) {
            gprs_valid = 0;
            top_dirty = 0;
            deferred_push_count = 0;
            deferred_pop_count = 0;
        }
    }
}

void X87Cache::reset_perm() {
    for (int i = 0; i < 8; i++)
        perm[i] = static_cast<int8_t>(i);
    perm_dirty = 0;
}

bool X87Cache::perm_is_identity() const {
    for (int i = 0; i < 8; i++)
        if (perm[i] != i) return false;
    return true;
}

uint32_t X87Cache::pinned_mask() const {
    uint32_t mask = 0;
    if (gprs_valid) {
        mask |= (1u << base_gpr);
        mask |= (1u << top_gpr);
        mask |= (1u << st_base_gpr);
    }
    return mask;
}

static OpcodeId opcode_to_id_local(uint16_t op) {
    using O = Opcode;
    using I = OpcodeId;
    switch (op) {
        case O::kOpcodeName_fldz:     return I::fldz;
        case O::kOpcodeName_fld1:     return I::fld1;
        case O::kOpcodeName_fldl2e:   return I::fldl2e;
        case O::kOpcodeName_fldl2t:   return I::fldl2t;
        case O::kOpcodeName_fldlg2:   return I::fldlg2;
        case O::kOpcodeName_fldln2:   return I::fldln2;
        case O::kOpcodeName_fldpi:    return I::fldpi;
        case O::kOpcodeName_fld:      return I::fld;
        case O::kOpcodeName_fild:     return I::fild;
        case O::kOpcodeName_fadd:     return I::fadd;
        case O::kOpcodeName_faddp:    return I::faddp;
        case O::kOpcodeName_fiadd:    return I::fiadd;
        case O::kOpcodeName_fsub:     return I::fsub;
        case O::kOpcodeName_fsubr:    return I::fsubr;
        case O::kOpcodeName_fsubp:    return I::fsubp;
        case O::kOpcodeName_fsubrp:   return I::fsubrp;
        case O::kOpcodeName_fdiv:     return I::fdiv;
        case O::kOpcodeName_fdivr:    return I::fdivr;
        case O::kOpcodeName_fdivp:    return I::fdivp;
        case O::kOpcodeName_fdivrp:   return I::fdivrp;
        case O::kOpcodeName_fmul:     return I::fmul;
        case O::kOpcodeName_fmulp:    return I::fmulp;
        case O::kOpcodeName_fst:      return I::fst;
        case O::kOpcodeName_fst_stack:    return I::fst_stack;
        case O::kOpcodeName_fstp:         return I::fstp;
        case O::kOpcodeName_fstp_stack:   return I::fstp_stack;
        case O::kOpcodeName_fstsw:    return I::fstsw;
        case O::kOpcodeName_fcom:     return I::fcom;
        case O::kOpcodeName_fcomp:    return I::fcomp;
        case O::kOpcodeName_fcompp:   return I::fcompp;
        case O::kOpcodeName_fucom:    return I::fucom;
        case O::kOpcodeName_fucomp:   return I::fucomp;
        case O::kOpcodeName_fucompp:  return I::fucompp;
        case O::kOpcodeName_fxch:     return I::fxch;
        case O::kOpcodeName_fchs:     return I::fchs;
        case O::kOpcodeName_fabs:     return I::fabs;
        case O::kOpcodeName_fsqrt:    return I::fsqrt;
        case O::kOpcodeName_fistp:    return I::fistp;
        case O::kOpcodeName_fisttp:   return I::fisttp;
        case O::kOpcodeName_fidiv:    return I::fidiv;
        case O::kOpcodeName_fimul:    return I::fimul;
        case O::kOpcodeName_fisub:    return I::fisub;
        case O::kOpcodeName_fidivr:   return I::fidivr;
        case O::kOpcodeName_frndint:  return I::frndint;
        case O::kOpcodeName_fcomi:    return I::fcomi;
        case O::kOpcodeName_fcomip:   return I::fcomip;
        case O::kOpcodeName_fucomi:   return I::fucomi;
        case O::kOpcodeName_fucomip:  return I::fucomip;
        case O::kOpcodeName_ftst:     return I::ftst;
        case O::kOpcodeName_fist:     return I::fist;
        case O::kOpcodeName_fisubr:   return I::fisubr;
        case O::kOpcodeName_fcmovb:   return I::fcmovb;
        case O::kOpcodeName_fcmovbe:  return I::fcmovbe;
        case O::kOpcodeName_fcmove:   return I::fcmove;
        case O::kOpcodeName_fcmovnb:  return I::fcmovnb;
        case O::kOpcodeName_fcmovnbe: return I::fcmovnbe;
        case O::kOpcodeName_fcmovne:  return I::fcmovne;
        case O::kOpcodeName_fcmovu:   return I::fcmovu;
        case O::kOpcodeName_fcmovnu:  return I::fcmovnu;
        case O::kOpcodeName_ficom:    return I::ficom;
        case O::kOpcodeName_ficomp:   return I::ficomp;
        default:                      return I::kCount;
    }
}

bool X87Cache::is_handled(uint16_t op) {
    return is_handled_x87(op);
}

// OPT-RB: instructions Rosetta may translate mid-run without invalidating the
// pinned base/TOP/st_base GPRs. Criteria: trivially self-contained, no x87
// side effects, no control flow. Kept deliberately minimal (v1); push/pop and
// flag definers are excluded on purpose.
bool X87Cache::is_transparent(uint16_t op) {
    switch (op) {
        case kOpcodeName_mov:
        case kOpcodeName_movzx:
        case kOpcodeName_movsx:
        case kOpcodeName_movsxd:
        case kOpcodeName_lea:
        case kOpcodeName_nop:
            return true;
        default:
            return false;
    }
}

static bool op_disabled_for_run(uint16_t op, uint64_t disabled_ops_mask) {
    if (!disabled_ops_mask)
        return false;
    const auto id = opcode_to_id_local(op);
    return id != OpcodeId::kCount &&
           ((disabled_ops_mask >> static_cast<int>(id)) & 1u);
}

int X87Cache::lookahead(IRInstr* instr_array, int64_t num_instrs, int64_t insn_idx,
                        uint64_t disabled_ops_mask, bool bridge) {
    int count = 0;
    int64_t i = insn_idx;
    for (;;) {
        // Consume a maximal group of handled, enabled x87 instructions.
        int group = 0;
        while (i < num_instrs && is_handled_x87(instr_array[i].opcode()) &&
               !op_disabled_for_run(instr_array[i].opcode(), disabled_ops_mask)) {
            i++;
            group++;
        }
        count += group;
        if (!bridge || count == 0)
            break;
        // OPT-RB: cross a short transparent gap, but only when another enabled
        // x87 instruction follows — a trailing gap is never counted, so a run
        // always ends on an x87 instruction (see header comment).
        int gap = 0;
        int64_t j = i;
        while (j < num_instrs && gap < kMaxBridgeGap &&
               is_transparent(instr_array[j].opcode())) {
            j++;
            gap++;
        }
        if (gap == 0 || j >= num_instrs ||
            !is_handled_x87(instr_array[j].opcode()) ||
            op_disabled_for_run(instr_array[j].opcode(), disabled_ops_mask))
            break;
        count += gap;
        i = j;
    }
    return count;
}
