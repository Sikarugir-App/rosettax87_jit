#pragma once

#include <cstdint>

// Loader-side view of the libRosettaRuntime __DATA,exports table, parsed from a
// file-on-disk image (fields are raw RVAs / packed values). NOTE: this is a
// DIFFERENT layout from rosetta_runtime's Export.h (which uses live pointers);
// the two are intentionally not merged.
struct Exports {
    uint64_t version;  // 0x16A0000000000
    uint64_t x87Exports;
    uint64_t x87ExportCount;
    uint64_t runtimeExports;
    uint64_t runtimeExportCount;
};

struct Export {
    uint64_t address;
    uint64_t name;
};
