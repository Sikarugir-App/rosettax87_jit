#pragma once

struct TranslationResult;
struct IRInstr;

// Translators for opcodes that Rosetta itself does not support and that this
// project adds on top of it. These are reached via the decode hook (see
// DecodeOpcodeHook.cpp), which relabels a borrowed, same-shape encoding as one
// of these synthetic opcodes. Unlike TranslatorX87 (the x87 FPU), these are
// general-purpose / legacy-mode instructions.
namespace TranslatorCustom {

// ARPL r/m16, r16 — legacy-mode-only opcode 0x63 (MOVSXD in 64-bit mode), which
// Rosetta cannot decode. The decode hook relabels a borrowed ADD as this opcode.
auto translate_arpl(TranslationResult* a1, IRInstr* a2) -> void;

};  // namespace TranslatorCustom
