#include "rosetta_core/ClassifyArmPCHook.h"

#include "rosetta_core/AbiInfo.h"
#include "rosetta_core/CoreLog.h"
#include "rosetta_core/hook.h"

// clang-format off
#include "rosetta_core/RuntimeLibC.h"
// clang-format on

using classify_arm_pc_t = void (*)(AbiInfo* result, unsigned int thread_port, uintptr_t port);

void hook_classify_arm_pc(AbiInfo* result, unsigned int thread_port, uintptr_t port);

classify_arm_pc_t original_classify_arm_pc = nullptr;
uintptr_t g_rosettax87_base = 0;
uintptr_t g_rosettax87_size = 0;

void init_classify_arm_pc_hook(uintptr_t classify_arm_pc_addr, uintptr_t rosettax87_base,
                               uintptr_t rosettax87_size) {
    g_rosettax87_base = rosettax87_base;
    g_rosettax87_size = rosettax87_size;

    // aotinvoke passes 0 (no runtime library to hook) -- nothing to install.
    if (classify_arm_pc_addr == 0) {
        return;
    }

    original_classify_arm_pc = reinterpret_cast<classify_arm_pc_t>(classify_arm_pc_addr);
    hook_install(reinterpret_cast<void*>(original_classify_arm_pc),
                 reinterpret_cast<void*>(hook_classify_arm_pc),
                 reinterpret_cast<void**>(&original_classify_arm_pc));
}

void hook_classify_arm_pc(AbiInfo* abil_info, unsigned int thread_port, uintptr_t pc) {
    original_classify_arm_pc(abil_info, thread_port, pc);

    if (abil_info->kind == AbiKind_Unknown) {
        if (pc >= g_rosettax87_base && pc <= g_rosettax87_base + g_rosettax87_size) {
            abil_info->kind = AbiKind_RuntimeRoutine;
        }
    }
}
