#pragma once

#include <cstddef>
#include <cstdint>

#include "rosetta_core/IROperand.h"

// Bitmask for IRInstr::flag_liveness — records which x86 FLAGS are live
// (will be read before being overwritten) at this instruction.
//
// Computed by a backward dataflow pass in build_ir_module (source: FlagAnalysis.cpp):
//   1. Process IR blocks in reverse via a worklist
//   2. Walk instructions backward; look up each opcode in
//      x86_opcode_flag_effects[] (3 bytes per opcode: used, defined, special)
//   3. Store current liveness into insn->flag_liveness
//   4. Update:  liveness = (liveness & ~defined) | used
//   5. For cc-dependent instructions (jcc/cmovcc/setcc), flags_used comes
//      from x86_cc_flag_use_table[cc - 2]  (cc=0,1 use fallback 0x10 = OF)
//   6. Propagate changed entry-liveness to predecessor blocks until fixpoint
//
// Translators check individual bits to decide whether to emit flag-setting
// AArch64 variants (e.g. BICS vs BIC) or skip flag computation entirely.
enum FlagLiveness : uint8_t {
    FLAG_AF    = 0x02,  // bit 1   — auxiliary carry (AF)
    FLAG_PF_LO = 0x04,  // bit 2   — parity flag component
    FLAG_PF_HI = 0x08,  // bit 3   — parity flag component (also gates Z-flag codegen in emit_nz_flags)
    FLAG_PF    = 0x0C,  // bits 2+3 — both set when PF is live
    FLAG_OF    = 0x10,  // bit 4   — overflow (OF)
    FLAG_CF    = 0x20,  // bit 5   — carry (CF)
    FLAG_ZF    = 0x40,  // bit 6   — zero (ZF)
    FLAG_SF    = 0x80,  // bit 7   — sign (SF)
};

#pragma pack(push, 1)
struct IRInstr {
    uint32_t pc;
    uint16_t opcode_;
    uint8_t rep_prefix;
    uint8_t flag_liveness; // FlagLiveness bitmask — which x86 FLAGS are live here
    uint8_t _pad08;
    uint8_t rex_escape;
    uint8_t num_operands;
    uint8_t ir_kind;
    uint8_t ir_subkind;
    uint16_t aux_opcode;
    uint8_t _pad0F;

    IROperand operands[4];

    auto opcode() const -> uint16_t;

    auto set_opcode(uint16_t op) -> void;
};
#pragma pack(pop)

static_assert(sizeof(IRInstr) == 0x50, "IRInstr must be 0x50 bytes");
static_assert(offsetof(IRInstr, pc) == 0x00, "IRInstr::pc must be at offset 0x00");
static_assert(offsetof(IRInstr, opcode_) == 0x04, "IRInstr::opcode_ must be at offset 0x04");
static_assert(offsetof(IRInstr, rep_prefix) == 0x06, "IRInstr::rep_prefix must be at offset 0x06");
static_assert(offsetof(IRInstr, flag_liveness) == 0x07, "IRInstr::flag_liveness must be at offset 0x07");
static_assert(offsetof(IRInstr, _pad08) == 0x08, "IRInstr::_pad08 must be at offset 0x08");
static_assert(offsetof(IRInstr, rex_escape) == 0x09, "IRInstr::rex_escape must be at offset 0x09");
static_assert(offsetof(IRInstr, num_operands) == 0x0A, "IRInstr::num_operands must be at offset 0x0A");
static_assert(offsetof(IRInstr, ir_kind) == 0x0B, "IRInstr::ir_kind must be at offset 0x0B");
static_assert(offsetof(IRInstr, ir_subkind) == 0x0C, "IRInstr::ir_subkind must be at offset 0x0C");
static_assert(offsetof(IRInstr, aux_opcode) == 0x0D, "IRInstr::aux_opcode must be at offset 0x0D");
static_assert(offsetof(IRInstr, _pad0F) == 0x0F, "IRInstr::_pad0F must be at offset 0x0F");
static_assert(offsetof(IRInstr, operands) == 0x10, "IRInstr::operands must be at offset 0x10");
