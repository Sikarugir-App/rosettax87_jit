// Reverse-engineered from Rosetta 2's translator binary (TranslationCacheAbi.cpp,
// CodeFragmentMetadata.cpp). Produced by classify_arm_pc / abi_info_for_runtime /
// abi_info_for_runtime_routines_address; consumed by sa_tramp, guest_gpr_state_from_host_state.
//
// Confidence key:
//   [confirmed]  name taken verbatim from an ASSERT()/ERROR() string in the binary
//   [inferred]   name/purpose deduced from control flow and landmark symbols, not literal

#pragma once
#include <cstdint>

// AbiKind values 4-8, 0xA-0x10, 0x12 are best-effort inferences from control flow;
// treat those as a strong hypothesis, not verified ground truth.
enum AbiKind : uint8_t {
    AbiKind_Unknown          = 0x00, // [inferred] no code fragment found at all (tree empty / walk missed)
    AbiKind_None              = 0x01, // [inferred] classify_arm_pc called with a null PC
    AbiKind_NewThread         = 0x02, // [confirmed] ThreadContextSignals.cpp: "abi_info.kind == AbiKind::NewThread"
    AbiKind_TranslatedCode    = 0x03, // [confirmed] ThreadContextSignals.cpp / ThreadContextRegisterState.cpp:
                                       //             "abi_info.kind == AbiKind::TranslatedCode"
    AbiKind_Library           = 0x04, // [inferred] address resolved via rosetta::runtime::library::abi_for_address
    AbiKind_LibraryRoutine    = 0x05, // [inferred] same library path, different library::AbiKind subtype
    AbiKind_RuntimeRoutine    = 0x06, // [inferred] unlabeled runtime-routines sub-range
    AbiKind_ExitCall          = 0x07, // [inferred] bounded by `runtime_exit_ret`; restores x21 in sa_tramp
    AbiKind_Syscall           = 0x08, // [inferred] bounded by `runtime_syscall`
    AbiKind_Sigtramp          = 0x09, // [confirmed] TranslationCacheAbi.cpp: "abi_info.kind != AbiKind::Sigtramp"
                                       //             region starts exactly at `sa_tramp_handler`
    AbiKind_Unclassified      = 0x0A, // [inferred] in library range but library::abi_for_address returned 0
    AbiKind_ExitTrampoline0   = 0x0B, // [inferred] one of 6 sequential runtime-exit landmark regions;
    AbiKind_ExitTrampoline1   = 0x0C, //            exact per-instruction purpose not identified
    AbiKind_ExitTrampoline2   = 0x0D,
    AbiKind_ExitTrampoline3   = 0x0E,
    AbiKind_ExitTrampoline4   = 0x0F,
    AbiKind_ExitTrampoline5   = 0x10,
    AbiKind_Sigreturn         = 0x11, // [confirmed] ERROR("unexpectedly got a signal during sigreturn")
    AbiKind_ThreadRelated12   = 0x12, // [inferred] grouped with AbiKind_NewThread in sa_tramp's dispatch
};

// [inferred] value 1 confirmed as Syscall via guest_gpr_state_from_host_state's assert;
// 0 / 2 / 3 are unnamed placeholders.
enum InstructionOffsetKind : uint8_t {
    InstructionOffsetKind_0            = 0x0,
    InstructionOffsetKind_Syscall      = 0x1, // [confirmed] ThreadContextRegisterState.cpp:
                                               //   "instruction_extents.kind == InstructionOffsetKind::Syscall"
    InstructionOffsetKind_2            = 0x2,
    InstructionOffsetKind_BranchIsland = 0x3, // [inferred] loop-continuation value inside
                                               //            instruction_extents_for_arm_address
};

#pragma pack(push, 1)

// [confirmed as a group] field path "lr_abi_info.u.translated_code.instruction_extents.kind"
// appears verbatim in a ThreadContextRegisterState.cpp assert, confirming the `u` / `translated_code`
// / `instruction_extents` names and nesting.
struct InstructionExtents {
    InstructionOffsetKind kind;   // +0x00
    uint16_t              length; // +0x01 [confirmed] "offsets.x86_instruction_length.has_value()"
                                   //        (CodeFragmentMetadata.cpp) -- x86 instruction length in bytes
};
static_assert(sizeof(InstructionExtents) == 3, "InstructionExtents size mismatch");

// Populated by instruction_extents_for_arm_address (CodeFragmentMetadata.cpp) for
// AbiKind_TranslatedCode. Field names for x86_pc/arm_pc/arm_range_* are [inferred]
// from how they're computed; instruction_extents naming is [confirmed].
struct TranslatedCodePayload {
    uint64_t            x86_pc;           // +0x00 corresponding guest (x86) instruction address
    uint64_t            arm_pc;           // +0x08 resolved ARM pc (post branch-island indirection)
    uint64_t            arm_range_start;  // +0x10 start of the ARM instruction range for this x86 insn
    uint64_t            arm_range_end;    // +0x18 end of that ARM instruction range
    InstructionExtents  instruction_extents; // +0x20
};
static_assert(sizeof(TranslatedCodePayload) == 0x23, "TranslatedCodePayload size mismatch");

// The struct passed as classify_arm_pc's / abi_info_for_runtime's 1st argument (the "result" out-param).
// 48 bytes total, confirmed via classify_arm_pc's own local stack layout (6 qwords before its
// stack-cookie local).
struct AbiInfo {
    AbiKind kind;        // +0x00
    char    pad_01[7];   // +0x01 compiler padding to 8-byte union alignment
    union {               // +0x08 -- real field name is "u" (confirmed via the assert path above)
        uint64_t                raw_offset; // e.g. AbiKind_ExitCall: byte offset from a landmark symbol
        uint8_t                 subkind;    // e.g. AbiKind_NewThread/Sigtramp/ExitTrampolineN sub-case
        TranslatedCodePayload   translated_code; // valid when kind == AbiKind_TranslatedCode
    } u;
    char pad_2B[5];      // +0x2B trailing padding out to the full 0x30
};
static_assert(sizeof(AbiInfo) == 0x30, "AbiInfo size mismatch (expected 48 bytes)");

#pragma pack(pop)
