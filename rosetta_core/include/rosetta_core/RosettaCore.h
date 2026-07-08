#pragma once

#include <cstdint>

struct RosettaCoreConfig {
    uint64_t  runtime_version;
    uintptr_t translate_insn_addr;
    uintptr_t transaction_result_size_addr;
    uintptr_t classify_arm_pc_addr;
    uintptr_t rosettax87_base;
    uintptr_t rosettax87_size;
};

void rosetta_core_init(const RosettaCoreConfig& config);

uint64_t rosetta_core_runtime_version();
