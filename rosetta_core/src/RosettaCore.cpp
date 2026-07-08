#include "rosetta_core/RosettaCore.h"

#include "rosetta_core/ClassifyArmPCHook.h"
#include "rosetta_core/CustomTranslationHook.h"

static uint64_t g_runtime_version = 0;

void rosetta_core_init(const RosettaCoreConfig& config) {
    g_runtime_version = config.runtime_version;
    init_custom_translation_hook(config.translate_insn_addr, config.transaction_result_size_addr);
    init_classify_arm_pc_hook(config.classify_arm_pc_addr, config.rosettax87_base, config.rosettax87_size);
}

uint64_t rosetta_core_runtime_version() {
    return g_runtime_version;
}
