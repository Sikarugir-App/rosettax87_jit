#pragma once

#include <cstddef>
#include <cstdint>

#include "rosetta_core/IRInstr.h"
#include "rosetta_core/IRTerminator.h"

struct IRBlock {
    IRInstr* instrs;
    IRBlock** preds;
    IRTerminator terminator;
    uint32_t end_pc;
    uint32_t num_instrs;
    uint32_t num_preds;
    uint32_t block_index;
    uint32_t start_pc;
    uint32_t code_size;
    uint8_t live_flags_in;
    uint8_t flag_liveness;
    uint8_t is_sequential;
    uint8_t is_entry;
    uint32_t _pad4c;
};

static_assert(sizeof(IRBlock) == 0x50, "IRBlock must be 0x50 bytes");
static_assert(offsetof(IRBlock, instrs) == 0x00, "IRBlock::instrs must be at offset 0x00");
static_assert(offsetof(IRBlock, preds) == 0x08, "IRBlock::preds must be at offset 0x08");
static_assert(offsetof(IRBlock, terminator) == 0x10, "IRBlock::terminator must be at offset 0x10");
static_assert(offsetof(IRBlock, end_pc) == 0x30, "IRBlock::end_pc must be at offset 0x30");
static_assert(offsetof(IRBlock, num_instrs) == 0x34, "IRBlock::num_instrs must be at offset 0x34");
static_assert(offsetof(IRBlock, num_preds) == 0x38, "IRBlock::num_preds must be at offset 0x38");
static_assert(offsetof(IRBlock, block_index) == 0x3C, "IRBlock::block_index must be at offset 0x3C");
static_assert(offsetof(IRBlock, start_pc) == 0x40, "IRBlock::start_pc must be at offset 0x40");
static_assert(offsetof(IRBlock, code_size) == 0x44, "IRBlock::code_size must be at offset 0x44");
static_assert(offsetof(IRBlock, live_flags_in) == 0x48, "IRBlock::live_flags_in must be at offset 0x48");
static_assert(offsetof(IRBlock, flag_liveness) == 0x49, "IRBlock::flag_liveness must be at offset 0x49");
static_assert(offsetof(IRBlock, is_sequential) == 0x4A, "IRBlock::is_sequential must be at offset 0x4A");
static_assert(offsetof(IRBlock, is_entry) == 0x4B, "IRBlock::is_entry must be at offset 0x4B");
static_assert(offsetof(IRBlock, _pad4c) == 0x4C, "IRBlock::_pad4c must be at offset 0x4C");
