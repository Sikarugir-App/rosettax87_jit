#include "rosetta_core/IRTerminator.h"

#include <cstdio>
#include <cstring>

#include "rosetta_core/IRBlock.h"
#include "rosetta_core/OpcodeCompatibility.h"

auto IRTerminator::opcode() const -> uint16_t {
    return opcode_host_to_internal(opcode_);
}
auto IRTerminator::set_opcode(uint16_t op) -> void {
    opcode_ = opcode_internal_to_host(op);
}

void branch_target_to_string(char* buf, IRBranchTarget target) {
    switch (target.block.kind) {
    case BasicBlock:
        snprintf(buf, 64, "BB_%u",
                 reinterpret_cast<IRBlock*>(target.block.block)->block_index);
        break;
    case PicAddress:
        snprintf(buf, 64, "0x%llx", target.pic_address.pic_address);
        break;
    case PcRelative:
        snprintf(buf, 64, "pic-address %lld",
                 static_cast<long long>(target.pc_relative.pc_relative));
        break;
    case Trap:
        strcpy(buf, "invalid pic-address");
        break;
    }
}
