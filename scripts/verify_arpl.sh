#!/usr/bin/env bash
#
# verify_arpl.sh — end-to-end check of the 32-bit ARPL (0x63 /r) path.
#
# ARPL only exists in 32-bit mode (0x63 is MOVSXD in 64-bit), and the AOT
# decoder hard-wires cpu_mode=0, so we force 32-bit decode with
# ROSETTA_FORCE_CPU_MODE32=1 and translate a `63 D0` (arpl eax,edx) blob through
# aotinvoke, then confirm the emitted AArch64 matches translate_arpl.
#
# Usage: bash scripts/verify_arpl.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AOT="$ROOT/build/bin/aotinvoke"
OBJDUMP="$(command -v aarch64-elf-objdump || command -v aarch64-linux-gnu-objdump || true)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

[[ -x "$AOT" ]] || { echo "FAIL  aotinvoke not built ($AOT)"; exit 1; }
[[ -n "$OBJDUMP" ]] || { echo "FAIL  aarch64-elf-objdump not on PATH"; exit 1; }

# arpl eax, edx ; ret
printf '\x63\xd0\xc3' > "$TMP/arpl.bin"

# 1. Sanity: at 64-bit it must decode as MOVSXD (proves the blob & baseline).
#    (Capture first — `grep -q` on a pipe would SIGPIPE aotinvoke and trip pipefail.)
V64="$("$AOT" "$TMP/arpl.bin" "$TMP/o64.bin" --verbose 2>&1 || true)"
if grep -qi 'movsxd' <<<"$V64"; then
    echo "PASS  64-bit: 63 D0 decodes as movsxd"
else
    echo "FAIL  64-bit: expected movsxd"; exit 1
fi

# 2. Force 32-bit: translate and confirm the ARPL lowering was emitted.
ROSETTA_FORCE_CPU_MODE32=1 "$AOT" "$TMP/arpl.bin" "$TMP/o32.bin" >/dev/null 2>&1
DIS="$("$OBJDUMP" -D -b binary -m aarch64 "$TMP/o32.bin" 2>/dev/null)"

# Expected core sequence (order matters): compare RPLs, set ZF, splice dst.RPL.
expect=(
  'ubfx	w24, w2, #0, #2'
  'mrs	x22, nzcv'
  'ubfx	w23, w0, #0, #2'
  'cmp	w23, w24'
  'cset	w25, cc'
  'bfi	w22, w25, #30, #1'
  'msr	nzcv, x22'
  'cbz	w25'
  'bfxil	w0, w24, #0, #2'
)
ok=1
for insn in "${expect[@]}"; do
    grep -qF "$insn" <<<"$DIS" || { echo "FAIL  32-bit: missing '$insn'"; ok=0; }
done

if [[ $ok -eq 1 ]]; then
    echo "PASS  32-bit: ARPL lowering emitted (decode-hook -> translate_arpl)"
    echo "================================================================"
    echo "Results: 2 passed, 0 failed"
else
    echo "---- full disassembly ----"; echo "$DIS" | sed -n '7,30p'
    exit 1
fi
