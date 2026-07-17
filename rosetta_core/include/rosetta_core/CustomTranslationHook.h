#pragma once

#include <cstdint>
#include <functional>

struct IRBlock;
struct IRInstr;
struct TranslationResult;

struct CustomTranslationHook {
    std::function<void(TranslationResult* result, IRBlock* block, IRInstr* instr_array,
                       int64_t num_instrs, int64_t insn_idx)>
        before;

    std::function<void(TranslationResult* result, IRBlock* block, IRInstr* instr_array,
                       int64_t num_instrs, int64_t insn_idx, int64_t new_insn_idx)>
        after;
};

void init_custom_translation_hook(uintptr_t translate_insn_addr,
                                  uintptr_t transaction_result_size_addr,
                                  uintptr_t default_free_gpr_mask_addr,
                                  uintptr_t free_temporary_gpr_addr,
                                  const CustomTranslationHook* hook = nullptr);
