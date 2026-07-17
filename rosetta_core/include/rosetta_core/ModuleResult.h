#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "rosetta_core/IRModuleData.h"

struct IRBlock;
struct IRInstr;

struct ModuleResult {
    uint64_t alloc_handle;
    IRModuleData module_data;
};

// Optional per-item annotators for module_print. Each callback receives the item
// being printed and returns a short string that is appended inline to that item's
// row (after core's own content). An empty return value appends nothing. Either
// callback may be left unset.
struct ModulePrintHooks {
    // Called once per block; the return value is appended to the "BB_n" header row.
    std::function<std::string(const IRBlock&)> annotate_block;
    // Called once per instruction; the return value is appended to that
    // instruction's row. Receives the owning block and the instruction index so
    // callers can key into per-instruction side tables.
    std::function<std::string(const IRBlock&, const IRInstr&, uint32_t instr_idx)>
        annotate_instr;
};

void module_print(const ModuleResult* result,
                  const ModulePrintHooks* hooks = nullptr);
