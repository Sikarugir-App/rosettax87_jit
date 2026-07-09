#pragma once

#include <cstdint>

// rosetta_loader writes these offsets into the library at runtime
struct Offsets {
    uint64_t init_library_rva;  // used to calculate base address of libRosettaRuntime from exports
                                // address
    uint64_t translate_insn_addr;
    uint64_t transaction_result_size_addr;
    uint64_t runtime_base;
    uint64_t rosettax87_base;
    uint64_t rosettax87_size;
    uint64_t classify_arm_pc_rva;  // classify_arm_pc offset within libRosettaRuntime
    uint64_t decode_opcode_rva;    // decode_opcode offset within libRosettaRuntime
};

static_assert(sizeof(Offsets) == 0x40, "Invalid size for Offsets");

extern Offsets kOffsets;
