#pragma once

#include <cstdint>

struct ThreadContextOffsets {
    uintptr_t runtime_pointers; // points to a function table
    uint32_t field_8;
    uint32_t field_C;
    uint32_t field_10;
    uint32_t x87_state_offset;
};
