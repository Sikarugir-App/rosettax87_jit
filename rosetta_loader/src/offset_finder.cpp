#include "offset_finder.hpp"

#include <algorithm>
#include <charconv>
#include <optional>
#include <ranges>
#include <string_view>
#include <vector>

#include "macho_loader.hpp"
#include "types.h"

namespace {

auto findPattern(const std::vector<uint8_t>& haystack, std::string_view pattern, const char* name)
    -> std::optional<uint64_t> {
    struct PatternByte {
        uint8_t value;
        bool wildcard;
    };

    std::vector<PatternByte> parsed;

    for (auto token : std::views::split(pattern, ' ')) {
        std::string_view sv{token.begin(), token.end()};
        if (sv.empty())
            continue;
        if (sv[0] == '?') {
            parsed.push_back({0, true});
        } else {
            uint8_t val = 0;
            std::from_chars(sv.data(), sv.data() + sv.size(), val, 16);
            parsed.push_back({val, false});
        }
    }

    if (parsed.empty())
        return std::nullopt;

    auto it = std::search(
        haystack.begin(), haystack.end(), parsed.begin(), parsed.end(),
        [](uint8_t byte, const PatternByte& pat) { return pat.wildcard || byte == pat.value; });

    if (it != haystack.end())
        return static_cast<uint64_t>(std::distance(haystack.begin(), it));

    fprintf(stderr, "%s pattern not found.\n", name);
    return std::nullopt;
}

namespace aarch64 {

auto decodeAdrp(uint32_t insn, uint64_t pc) -> uint64_t {
    uint64_t immlo = (insn >> 29) & 0x3;
    uint64_t immhi = (insn >> 5) & 0x7FFFF;
    int64_t imm = static_cast<int64_t>((immhi << 2) | immlo) << 12;
    if (imm & (1ULL << 32))
        imm |= ~((1ULL << 33) - 1);
    return (pc & ~0xFFFULL) + imm;
}

auto decodeLdrbImm(uint32_t insn) -> uint64_t {
    return (insn >> 10) & 0xFFF;
}

auto decodeBl(uint32_t insn, uint64_t pc) -> uint64_t {
    int32_t imm26 = insn & 0x03FFFFFF;
    if (imm26 & (1 << 25))
        imm26 |= ~0x03FFFFFF;
    return pc + (static_cast<int64_t>(imm26) << 2);
}

}  // namespace aarch64

}  // anonymous namespace

auto OffsetFinder::scanRuntime() -> bool {
    MachoLoader loader;
    if (!loader.open("/usr/libexec/rosetta/runtime")) {
        fprintf(stderr, "Failed to open rosetta runtime Mach-O to determine offsets.\n");
        return false;
    }

    auto findExportsFetch = [&]() -> std::optional<uint64_t> {
        // LDR X2, [X19,#8]
        // LDR W3, [X19,#0x10]
        return findPattern(loader.buffer_, "62 06 40 F9 63 12 40 B9", "exportsFetch");
    };

    auto findSvcCall = [&]() -> std::optional<uint64_t> {
        // MOV X16, #197; SVC 0x80; CSET X1, CS; RET
        return findPattern(loader.buffer_, "B0 18 80 D2 01 10 00 D4 E1 37 9F 9A C0 03 5F D6",
                           "svcCall");
    };

    auto findDisableAot = [&]() -> std::optional<uint64_t> {
        // ADD X29, SP, #0x1D0; STR X4, [SP,#0x50]
        // (followed by ADRP+LDRB that encode g_disable_aot address)
        auto match = findPattern(loader.buffer_, "FD 43 07 91 E4 2B 00 F9", "disableAot");
        if (!match)
            return std::nullopt;
        uint64_t adrpOffset = *match + 8;
        uint32_t adrpInsn = *reinterpret_cast<uint32_t*>(&loader.buffer_[adrpOffset]);
        uint32_t ldrbInsn = *reinterpret_cast<uint32_t*>(&loader.buffer_[adrpOffset + 4]);
        return aarch64::decodeAdrp(adrpInsn, adrpOffset) + aarch64::decodeLdrbImm(ldrbInsn);
    };

    auto findClassifyArmPc = [&]() -> std::optional<uint64_t> {
        // LDR X2, [X26,#0x110]; LDR W1, [X25,#0x194]
        // ADD X0, SP, #imm; BL classify_arm_pc  <-- we decode the BL
        auto match = findPattern(loader.buffer_, "42 8B 40 F9 21 97 41 B9", "classifyArmPc");
        if (!match)
            return std::nullopt;
        uint64_t blOffset = *match + 0x0C;
        uint32_t blInsn = *reinterpret_cast<uint32_t*>(&loader.buffer_[blOffset]);
        return aarch64::decodeBl(blInsn, blOffset);
    };

    auto exportsFetch = findExportsFetch();
    auto svcCall = findSvcCall();
    auto disableAot = findDisableAot();
    auto classifyArmPc = findClassifyArmPc();

    if (!exportsFetch || !svcCall || !disableAot || !classifyArmPc)
        return false;

    offsetExportsFetch_ = *exportsFetch;
    offsetSvcCallEntry_ = *svcCall;
    offsetSvcCallRet_ = *svcCall + 0xC;
    offsetDisableAot_ = *disableAot;
    offsetClassifyArmPc_ = *classifyArmPc;

    return true;
}

auto OffsetFinder::scanLibRosettaRuntime() -> bool {
    MachoLoader loader;
    if (!loader.open("/Library/Apple/usr/libexec/oah/libRosettaRuntime")) {
        fprintf(stderr, "Failed to open libRosettaRuntime Mach-O to determine offsets.\n");
        return false;
    }

    auto findTransactionResultSize = [&]() -> std::optional<uint64_t> {
        // MOV W1, #0x268
        return findPattern(loader.buffer_, "01 4D 80 52", "transactionResultSize");
    };

    auto findTranslateInsn = [&]() -> std::optional<uint64_t> {
        // translate_insn function prologue
        return findPattern(loader.buffer_,
                           "FF 43 03 D1 FC 6F 07 A9 FA 67 08 A9 "
                           "F8 5F 09 A9 F6 57 0A A9 F4 4F 0B A9 "
                           "FD 7B 0C A9 FD 03 03 91 F3 03 00 AA",
                           "translateInsn");
    };

    auto findDecodeOpcode = [&]() -> std::optional<uint64_t> {
        auto match = findPattern(loader.buffer_, "E2 ? 08 91 E3 ? 08 91 E1 03 ? ?", "decodeOpcode");
        if (!match)
            return std::nullopt;
        uint64_t blOffset = *match + 0x0C;
        uint32_t blInsn = *reinterpret_cast<uint32_t*>(&loader.buffer_[blOffset]);
        return aarch64::decodeBl(blInsn, blOffset);
    };

    auto findInitLibrary = [&]() -> std::optional<uint64_t> {
        auto exportsSection = loader.getSection("__DATA", "exports");
        if (!exportsSection) {
            fprintf(stderr,
                    "initLibrary: __DATA.exports section not found in libRosettaRuntime.\n");
            return std::nullopt;
        }
        auto* exports = reinterpret_cast<Exports*>(loader.buffer_.data() + exportsSection->offset);
        auto x87ExportsRva = exports->x87Exports & 0xFFFFFFFF;
        return (*reinterpret_cast<uint64_t*>(loader.buffer_.data() + x87ExportsRva)) & 0xFFFFFFFF;
    };

    auto transactionResultSize = findTransactionResultSize();
    auto translateInsn = findTranslateInsn();
    auto decodeOpcode = findDecodeOpcode();
    auto initLibrary = findInitLibrary();

    if (!transactionResultSize || !translateInsn || !decodeOpcode || !initLibrary)
        return false;

    offsetTransactionResultSize_ = *transactionResultSize;
    offsetTranslateInsn_ = *translateInsn;
    offsetDecodeOpcode_ = *decodeOpcode;
    offsetInitLibrary_ = *initLibrary;

    return true;
}
