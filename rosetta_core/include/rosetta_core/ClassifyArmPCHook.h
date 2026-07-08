#pragma once

#include <cstdint>

void init_classify_arm_pc_hook(uintptr_t classify_arm_pc_addr,
                               uintptr_t rosettax87_base,
                               uintptr_t rosettax87_size);
