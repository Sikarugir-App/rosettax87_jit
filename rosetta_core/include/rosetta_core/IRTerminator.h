#pragma once

#include <cstddef>
#include <cstdint>

#include "rosetta_core/IROperand.h"

struct IRBlock;

// Block terminator type — how control leaves an IR basic block.
// Values 0-18, stored in IRTerminator::kind and IRBlock::terminator.kind.
//
// Names confirmed via module_print format strings in libRosettaAot.dylib.
enum TerminatorKind : uint8_t {
    TK_JMP           = 0,   // direct jump          — emit_jmp_to_branch_target
    TK_JMP_IND       = 1,   // indirect jump / tail — emit_indirect_jmp_tail_call
    TK_DYLD_STUB     = 2,   // dyld stub thunk
    TK_FAR_JMP       = 3,   // far jump             — emit_far_jmp
    TK_JCC           = 4,   // conditional branch   — subkind = x86 condition code
    TK_CALL          = 5,   // near / direct call
    TK_CALL_IND      = 6,   // indirect call        — emit_indirect_jmp_or_call
    TK_FAR_CALL      = 7,   // far call             — emit_far_call
    TK_RET_NEAR      = 8,   // near return          — emit_ret_near
    TK_RET_NEAR_IMM  = 9,   // near return + imm    — emit_ret_near_imm
    TK_RET_FAR       = 10,  // far return           — emit_far_ret
    TK_RET_FAR_IMM   = 11,  // far return + imm     — emit_far_ret_imm
    TK_SYSCALL       = 12,  // SYSCALL              — emit_jmp_direct (fallthrough)
    TK_JCXZ          = 13,  // JCXZ/JECXZ/JRCXZ    — subkind = address size
    TK_LOOP          = 14,  // LOOP/LOOPE/LOOPNE    — subkind = x86 condition code
    TK_INVALID       = 15,  // invalid instruction  — emit_invalid
    TK_BAD_ACCESS    = 16,  // bad memory access    — emit_bad_access; subkind = BadAccessKind
    TK_INT_N         = 17,  // INT n                — emit_int_n; subkind = interrupt number
    TK_OPCODE_TERM   = 18,  // opcode-based term    — opcode = x86 opcode index into name table
};

// Branch target type — how a BranchTarget encodes the destination.
// Used in the IRBranchTarget variant (not IROperand) of IRTerminator's data union.
//
// Source names from assert strings:
//   ir::BranchTargetKind::BasicBlock      (0)
//   BranchTargetKind::PicAddress          (1)  — normal mode
//   BranchTargetKind::AbsoluteAddress     (1)  — single-step mode (alias)
//
// IDA decompiler shows these as IROperandKind values (Register, MemRef, etc.)
// when the union member hasn't been selected, because it defaults to IROperand.
enum BranchTargetKind : uint8_t {
    BasicBlock  = 0,  // value = IRBlock*; reads block->start_pc (+0x40)
    PicAddress  = 1,  // value = resolved address (AbsoluteAddress in single-step mode)
    PcRelative  = 2,  // value = pc_offset for emit_load_pc_relative_addr
    Trap        = 3,  // no branch; emits BRK #0xE (0xD42001C0)
};

struct IRBranchTargetBasicBlock {
 BranchTargetKind kind;
 IRBlock* block;
};

static_assert(sizeof(IRBranchTargetBasicBlock) == 0x10);
static_assert(offsetof(IRBranchTargetBasicBlock, kind) == 0x00);
static_assert(offsetof(IRBranchTargetBasicBlock, block) == 0x08);

struct IRBranchTargetPicAddress {
 BranchTargetKind kind;
 uint64_t pic_address;    
};

static_assert(sizeof(IRBranchTargetPicAddress) == 0x10);
static_assert(offsetof(IRBranchTargetPicAddress, kind) == 0x00);
static_assert(offsetof(IRBranchTargetPicAddress, pic_address) == 0x08);

struct IRBranchTargetPcRelative {
 BranchTargetKind kind;
 uint64_t pc_relative;    
};

static_assert(sizeof(IRBranchTargetPcRelative) == 0x10);
static_assert(offsetof(IRBranchTargetPcRelative, kind) == 0x00);
static_assert(offsetof(IRBranchTargetPcRelative, pc_relative) == 0x08);


struct IRBranchTargetTrap {
 BranchTargetKind kind;
 uint64_t trap;    
};

static_assert(sizeof(IRBranchTargetTrap) == 0x10);
static_assert(offsetof(IRBranchTargetTrap, kind) == 0x00);
static_assert(offsetof(IRBranchTargetTrap, trap) == 0x08);

union IRBranchTarget {
    IRBranchTargetBasicBlock block;
    IRBranchTargetPicAddress pic_address;
    IRBranchTargetPcRelative pc_relative;
    IRBranchTargetTrap trap;
};

static_assert(sizeof(IRBranchTarget) == 0x10, "IRBranchTarget must be 16 bytes");
static_assert(sizeof(IRBranchTarget) == sizeof(IROperand),
              "IRBranchTarget and IROperand must be the same size");

// BadAccessKind — subkind values for TK_BAD_ACCESS (kind 16).
// module_print prints "bad access: invalid address" or "bad access: bad protection".
enum BadAccessKind : uint8_t {
    BAK_INVALID_ADDRESS = 0,
    BAK_BAD_PROTECTION  = 1,
};

// IRTerminator — embedded in IRBlock at offset 0x10, 32 bytes.
//
// translate_block passes &block->terminator to emit_far_call, emit_far_jmp,
// emit_indirect_jmp_or_call, etc.  Those functions receive it typed as
// IRTerminator* (IDA currently shows IRInstr* due to a legacy cast).
//
// The 16-byte data field at +0x08 is a UNION of two different types,
// selected by the terminator kind:
//
//   IROperand:       JMP_IND, DYLD_STUB, FAR_JMP, CALL_IND, FAR_CALL
//   IRBranchTarget:  JMP, JCC, CALL, JCXZ, LOOP
//   raw block ptr:   SYSCALL (8-byte IRBlock* at +0x08, bit 0 = flag)
//   unused:          RET_*, INVALID, BAD_ACCESS, INT_N, OPCODE_TERM
//
// Field semantics vary by kind:
//   subkind (+0x01): condition code (JCC, LOOP), address size (JCXZ),
//                    BadAccessKind (BAD_ACCESS), interrupt number (INT_N)
//   opcode  (+0x02): x86 opcode index — same concept as IRInstr::opcode_
//                    (LOOP uses it to distinguish loop/loope/loopne/loopw/etc.)
//   extra   (+0x18): continuation IRBlock* for branching terminators
//                    (bit 0 = flag, e.g. TK_CALL stores return-continuation)

union IRTerminatorData // sizeof=0x10
{                                       // XREF: IRTerminator.data/r
    IROperand operand;
    IRBranchTarget target;
};
static_assert(sizeof(IRTerminatorData) == 0x10);

struct IRTerminator {
    TerminatorKind kind;     // +0x00
    uint8_t subkind;         // +0x01  overloaded per kind (see above)
    uint16_t opcode;         // +0x02  x86 opcode index (same concept as IRInstr::opcode_)
    uint32_t flags;          // +0x04
    IRTerminatorData data;   // +0x08
    IRBlock* extra;          // +0x18  continuation block ptr (bit 0 = flag)
};

static_assert(sizeof(IRTerminator) == 0x20, "IRTerminator must be 0x20 bytes");
static_assert(offsetof(IRTerminator, kind) == 0x00, "IRTerminator::kind must be at offset 0x00");
static_assert(offsetof(IRTerminator, subkind) == 0x01, "IRTerminator::subkind must be at offset 0x01");
static_assert(offsetof(IRTerminator, opcode) == 0x02, "IRTerminator::opcode must be at offset 0x02");
static_assert(offsetof(IRTerminator, flags) == 0x04, "IRTerminator::flags must be at offset 0x04");
static_assert(offsetof(IRTerminator, data) == 0x08, "IRTerminator::data must be at offset 0x08");
static_assert(offsetof(IRTerminator, extra) == 0x18, "IRTerminator::extra must be at offset 0x18");
