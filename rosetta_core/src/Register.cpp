#include "rosetta_core/Register.h"

static const char* kGpr8Names[16] = {
    "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
};

static const char* kGpr8HiNames[4] = {"ah", "ch", "dh", "bh"};

static const char* kGpr16Names[16] = {
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
};

static const char* kGpr32Names[16] = {
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
};

static const char* kGpr64Names[16] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
};

static const char* kXmmNames[16] = {
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
    "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
};

static const char* kMmNames[8] = {
    "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7",
};

static const char* kStNames[8] = {
    "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
};

static const char* kYmmNames[16] = {
    "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
    "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",
};

const char* register_to_string(Register reg) {
    uint8_t cls = reg.value >> 4;
    uint8_t idx = reg.value & 0x0F;

    switch (cls) {
    case 0:  return kGpr8Names[idx];
    case 1:  return (idx < 4) ? kGpr8HiNames[idx] : "???";
    case 2:  return kGpr16Names[idx];
    case 3:  return kGpr32Names[idx];
    case 4:  return kGpr64Names[idx];
    case 5:  return kXmmNames[idx];
    case 6:  return kMmNames[idx & 0x07];
    case 7:  return kStNames[idx & 0x07];
    case 8:  return "rip";
    case 9:  return kYmmNames[idx];
    default: return "???";
    }
}
