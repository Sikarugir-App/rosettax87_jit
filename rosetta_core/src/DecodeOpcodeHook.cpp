#include "rosetta_core/DecodeOpcodeHook.h"

#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/CoreLog.h"
#include "rosetta_core/Opcode.h"
#include "rosetta_core/OpcodeCompatibility.h"
#include "rosetta_core/hook.h"
#include "rosetta_config/Config.h"

// clang-format off
#include "rosetta_core/RuntimeLibC.h"
// clang-format on

// ---------------------------------------------------------------------------
// x86-64 decoder types, reverse-engineered from Rosetta's decode_opcode
// (Decoder.cpp). decode_opcode parses ONE instruction:
//
//   int decode_opcode(DecoderCtx* ctx, unsigned offset,
//                     DecodedInsn* out, uint8_t* out_len);
//   returns 0=ok, 1=invalid, 2=fault(truncated); *out_len = instruction length.
// ---------------------------------------------------------------------------

#pragma pack(push, 2)
struct x86_operand {  // sizeof=0x18
    uint8_t kind;
    uint8_t reg_class;
    uint8_t reg_num;
    uint8_t body[21];
};
#pragma pack(pop)
static_assert(sizeof(x86_operand) == 0x18, "x86_operand size");

#pragma pack(push, 2)
struct x86_opcode_desc {  // sizeof=0xC
    uint16_t mnemonic;
    uint8_t operands[8];
    uint8_t flags;
    uint8_t _b;
};
#pragma pack(pop)
static_assert(sizeof(x86_opcode_desc) == 0xC, "x86_opcode_desc size");

#pragma pack(push, 2)
struct DecodedInsn {  // sizeof=0x68
    uint16_t mnemonic;
    uint8_t pfx_group1;
    uint8_t vex_present;
    uint8_t _pad04[4];
    struct x86_operand operands[4];
};
#pragma pack(pop)
static_assert(sizeof(DecodedInsn) == 0x68, "DecodedInsn size");

#pragma pack(push, 2)
struct DecoderNode {  // sizeof=0x8
    uint16_t transition_base;
    uint16_t num_entries;
    uint32_t selector;
};
#pragma pack(pop)
static_assert(sizeof(DecoderNode) == 0x8, "DecoderNode size");

#pragma pack(push, 2)
struct DecoderCtx {  // sizeof=0x48
    uint8_t cpu_mode;
    uint8_t _pad01[7];
    const uint8_t* code_base;
    const uint8_t* code_end;
    const uint8_t* insn_start;
    const uint8_t* cursor;
    uint8_t fault;
    uint8_t pfx_group1;
    uint8_t seg_override;
    uint8_t pfx_66;
    uint8_t pfx_67;
    uint8_t rex_present;
    uint8_t rex_b;
    uint8_t rex_x;
    uint8_t rex_r;
    uint8_t rex_w;
    uint8_t vex_present;
    uint8_t vex_map;
    uint8_t vex_vvvv;
    uint8_t vex_l;
    uint8_t vex_pp;
    uint8_t _pad37;
    const struct x86_opcode_desc* opcode_desc;
    uint8_t modrm_valid;
    uint8_t modrm;
    uint8_t _pad42[6];
};
#pragma pack(pop)
static_assert(sizeof(DecoderCtx) == 0x48, "DecoderCtx size");

  typedef enum x86_decode_status {
      X86_DECODE_OK      = 0,  // instruction fully decoded; *out_len = instruction length
      X86_DECODE_INVALID = 1,  // complete but undecodable opcode (not in table); *out_len = 0
      X86_DECODE_FAULT   = 2,  // ran out of bytes: past code_end or >15-byte limit; *out_len = 
  } x86_decode_status;

using decode_opcode_t = x86_decode_status (*)(DecoderCtx* ctx, unsigned int offset, DecodedInsn* out,
                                uint8_t* out_len);

x86_decode_status hook_decode_opcode(DecoderCtx* ctx, unsigned int offset, DecodedInsn* out, uint8_t* out_len);

decode_opcode_t original_decode_opcode = nullptr;

void init_decode_opcode_hook(uintptr_t decode_opcode_addr) {
    // aotinvoke passes 0 (no runtime library to hook) -- nothing to install.
    if (decode_opcode_addr == 0) {
        return;
    }

    original_decode_opcode = reinterpret_cast<decode_opcode_t>(decode_opcode_addr);
    hook_install(reinterpret_cast<void*>(original_decode_opcode),
                 reinterpret_cast<void*>(hook_decode_opcode),
                 reinterpret_cast<void**>(&original_decode_opcode));
}

// ---------------------------------------------------------------------------
// Substitute-decode helper.
//
// Rosetta's decoder rejects some encodings we still need to translate (x87
// aliases; legacy-mode-only opcodes reassigned in 64-bit mode). For each, we
// copy the offending instruction into a private window, overwrite one or more
// opcode bytes with an encoding Rosetta *does* decode that has the SAME length
// and operand layout, and decode that instead. build_ir_module reads the
// operands and *out_len straight from the out-buffer and only uses the mnemonic
// as a bounded classifier, so a same-shape substitute yields a correct
// DecodedInsn; the caller then relabels the mnemonic as needed.
static x86_decode_status decode_substitute(DecoderCtx* ctx, const uint8_t* bytes, size_t n,
                                           DecodedInsn* out, uint8_t* out_len) {
    // 16 bytes covers the decoder's 15-byte max instruction length; the zero
    // tail is never read past the substitute's natural length but keeps code_end
    // safely beyond it.
    uint8_t buf[16] = {};
    if (n > sizeof(buf)) n = sizeof(buf);
    for (size_t i = 0; i < n; ++i) buf[i] = bytes[i];

    const uint8_t* saved_code_base = ctx->code_base;
    const uint8_t* saved_code_end = ctx->code_end;

    // The decoder only uses offset to form &code_base[offset], and reports
    // *out_len from cursor - insn_start, so the absolute address is irrelevant.
    ctx->code_base = buf;
    ctx->code_end = buf + sizeof(buf);

    x86_decode_status result = original_decode_opcode(ctx, 0, out, out_len);

    ctx->code_base = saved_code_base;
    ctx->code_end = saved_code_end;
    return result;
}

x86_decode_status hook_decode_opcode(DecoderCtx* ctx, unsigned int offset, DecodedInsn* out, uint8_t* out_len) {
    // Test-only: force the decoder into 32-bit mode. build_ir_module hard-wires
    // cpu_mode=0 (64-bit) in the AOT path, so legacy-only opcodes like ARPL (0x63,
    // which is MOVSXD in 64-bit) are otherwise unreachable via aotinvoke. Setting
    // it here per-instruction makes a 32-bit blob decode as 32-bit end-to-end.
    if (g_rosetta_config && g_rosetta_config->force_cpu_mode32) {
        ctx->cpu_mode = 1;
    }

    auto result = original_decode_opcode(ctx, offset, out, out_len);
    if (result != X86_DECODE_INVALID || *out_len != 0) {
        return result;
    }

    const uint8_t* insn = &ctx->code_base[offset];
    const size_t avail = static_cast<size_t>(ctx->code_end - insn);  // bytes still in range
    if (avail == 0) {
        return result;
    }

    // ── Non-canonical FCOMP ST(0): DC D8 → D8 D8 ────────────────────────────
    // Real x87 hardware treats DC D8 as an alias of the canonical D8 D8; Rosetta
    // only has the canonical form. Same instruction, same 2-byte length.
    if (avail >= 2 && insn[0] == 0xDC && insn[1] == 0xD8) {
        const uint8_t sub[2] = {0xD8, 0xD8};
        return decode_substitute(ctx, sub, sizeof(sub), out, out_len);
    }

    // ── Legacy-mode ARPL r/m16, r16 (opcode 0x63) ───────────────────────────
    // 0x63 has no entry in Rosetta's 64-bit-only tables (there it decodes as
    // MOVSXD), so any 0x63 that reaches INVALID is a 32-/16-bit ARPL. 0x63 shares
    // its exact ModRM/SIB/disp encoding with ADD r/m32,r32 (0x01): borrow ADD's
    // decode (identical length + operands — operand[0] = dest r/m, operand[1] =
    // src reg) and relabel it as our synthetic ARPL opcode. cpu_mode != 0 means
    // non-64-bit; the byte + INVALID gate is already conclusive on its own.
    if (insn[0] == 0x63 && ctx->cpu_mode != 0) {
        uint8_t sub[15];
        size_t n = avail < sizeof(sub) ? avail : sizeof(sub);
        for (size_t i = 0; i < n; ++i) sub[i] = insn[i];
        sub[0] = 0x01;  // ADD r/m32, r32 — same operand encoding as ARPL r/m16, r16

        result = decode_substitute(ctx, sub, n, out, out_len);
        if (result == X86_DECODE_OK) {
            // Relabel the borrowed ADD as ARPL. opcode_internal_to_host is
            // version-aware, so this stores the correct raw mnemonic into
            // build_ir_module -> IRInstr.opcode_, which IRInstr::opcode() then
            // maps back to kOpcodeName_arpl for the Translator.
            out->mnemonic = opcode_internal_to_host(kOpcodeName_arpl);
        }
        return result;
    }

    return result;
}
