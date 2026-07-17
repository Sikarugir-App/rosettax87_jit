#pragma once

#include <cstddef>
#include <cstdint>

struct IRBlock;
struct IRInstr;

template <typename T>
struct RosettaVec {
    T* begin_;
    T* end_;
    T* end_cap_;

    T* begin() const { return begin_; }
    T* end()   const { return end_; }
    size_t size()  const { return static_cast<size_t>(end_ - begin_); }
    bool   empty() const { return begin_ == end_; }
    T& operator[](size_t i) const { return begin_[i]; }
};

static_assert(sizeof(RosettaVec<void*>) == 0x18);

using IRBlockVec = RosettaVec<IRBlock*>;
using IRInstrVec = RosettaVec<IRInstr>;

struct IRModuleData {
    uint64_t text_vmaddr_range;
    uint64_t max_pc_seen;
    IRBlockVec ir_blocks;
    IRInstrVec ir_instr;
    uint64_t field_40;
};
