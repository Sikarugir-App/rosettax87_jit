#pragma once

#include <cstdint>

void init_custom_translation_hook(uintptr_t translate_insn_addr,
                                  uintptr_t transaction_result_size_addr);
