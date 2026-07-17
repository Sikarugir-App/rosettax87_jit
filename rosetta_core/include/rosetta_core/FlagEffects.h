#pragma once

#include <array>
#include <cstdint>

struct FlagEffectsEntry {
    uint8_t flags_used;
    uint8_t flags_defined;
    uint8_t special;
};

inline constexpr size_t kFlagEffectsCount = 118;
extern const std::array<FlagEffectsEntry, kFlagEffectsCount> x86_opcode_flag_effects;

void flags_to_string(char* buf, uint8_t flag_mask);
