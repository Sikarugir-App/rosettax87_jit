#pragma once

#include "rosetta_shared/Offsets.h"

// The loader writes the shared Offsets layout into this global (placed in its own
// __DATA,offsets section) at runtime; the runtime reads it. The struct layout lives
// in rosetta_shared/Offsets.h; only this runtime carries the global instance.
extern Offsets kOffsets;
