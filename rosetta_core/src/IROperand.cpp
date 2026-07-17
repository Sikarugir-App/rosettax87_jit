#include "rosetta_core/IROperand.h"

#include <cstdio>
#include <cstring>

static const char* kConditionCodeNames[16] = {
    "o", "no", "b", "ae", "e", "ne", "be", "a",
    "s", "ns", "p", "np", "l", "ge", "le", "g",
};

const char* condition_code_to_string(uint8_t cc) {
    if (cc >= 16) return "??";
    return kConditionCodeNames[cc];
}

static const char* kSegmentRegisterNames[6] = {
    "ES", "CS", "SS", "DS", "FS", "GS",
};

static const char* kSegOverrideStrings[3] = {"", "fs:", "gs:"};

void IROperand_to_string(char* buf, IROperand operand) {
    switch (operand.kind) {
    case IROperandKind::Register:
        strlcpy(buf, register_to_string(operand.reg.reg), 64);
        return;

    case IROperandKind::MemRef: {
        const char* seg = "";
        if (operand.mem.seg_override <= 2)
            seg = kSegOverrideStrings[operand.mem.seg_override];

        const char* base = "";
        bool has_base = operand.mem.mem_flags & 1;
        if (has_base)
            base = register_to_string({operand.mem.base_reg});

        const char* sep1 = "";
        const char* idx = "";
        char scale_buf[4] = "";
        bool has_index = operand.mem.mem_flags & 2;
        if (has_index) {
            if (has_base) sep1 = " + ";
            idx = register_to_string({operand.mem.index_reg});
            if (operand.mem.shift_amount)
                snprintf(scale_buf, sizeof(scale_buf), "*%u",
                         1u << operand.mem.shift_amount);
        }

        const char* sep2 = "";
        char disp_buf[24] = "";
        bool need_disp = !has_base && !has_index;
        if (need_disp || operand.mem.disp) {
            int64_t d = operand.mem.disp;
            if (d < 0) {
                sep2 = (has_base || has_index) ? " - " : "-";
                snprintf(disp_buf, sizeof(disp_buf), "0x%llx",
                         (unsigned long long)(-d));
            } else {
                sep2 = (has_base || has_index) ? " + " : "";
                snprintf(disp_buf, sizeof(disp_buf), "0x%llx",
                         (unsigned long long)d);
            }
        }

        snprintf(buf, 64, "%s[%s%s%s%s%s%s]",
                 seg, base, sep1, idx, scale_buf, sep2, disp_buf);
        return;
    }

    case IROperandKind::AbsMem:
        snprintf(buf, 64, "[0x%llx]", (unsigned long long)operand.abs_mem.value);
        return;

    case IROperandKind::Immediate:
        snprintf(buf, 64, "[text base + 0x%llx]",
                 (unsigned long long)operand.imm.value);
        return;

    case IROperandKind::BranchOffset: {
        int64_t v = operand.branch.value;
        bool has_bit16 = *reinterpret_cast<uint16_t*>(&operand.kind) & 0x10000;
        if (has_bit16 || v >= 0) {
            snprintf(buf, 64, "0x%llx", (unsigned long long)v);
        } else {
            snprintf(buf, 64, "-0x%llx", (unsigned long long)(-v));
        }
        return;
    }

    case IROperandKind::ConditionCode:
        if ((operand.cc.cc & 0xF0) == 0)
            strlcpy(buf, kConditionCodeNames[operand.cc.cc & 0x0F], 64);
        else
            strlcpy(buf, "??", 64);
        return;

    case IROperandKind::SegmentRegister:
        if (operand.seg.seg_idx < 6)
            strlcpy(buf, kSegmentRegisterNames[operand.seg.seg_idx], 64);
        else
            strlcpy(buf, "???", 64);
        return;
    }
    buf[0] = '\0';
}
