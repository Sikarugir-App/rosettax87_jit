#include "rosetta_core/ModuleResult.h"

#include <cstdio>
#include <string>

#include "rosetta_core/CoreLog.h"
#include "rosetta_core/FlagEffects.h"
#include "rosetta_core/IRBlock.h"
#include "rosetta_core/Opcode.h"

static const char* opcode_name(uint16_t index) {
    if (index >= kOpcodeNames.size()) return "???";
    return kOpcodeNames[index];
}

static IRBlock* terminator_extra_block(IRBlock* extra) {
    return reinterpret_cast<IRBlock*>(
        reinterpret_cast<uintptr_t>(extra) & ~uintptr_t(1));
}

void module_print(const ModuleResult* result, const ModulePrintHooks* hooks) {
    uint64_t text_base = result->module_data.text_vmaddr_range;

    for (IRBlock* block : result->module_data.ir_blocks) {
        {
            char hline[512];
            int hoff = snprintf(hline, sizeof(hline), "%-13llxBB_%u",
                                (unsigned long long)(text_base + block->start_pc),
                                block->block_index);
            if (hooks && hooks->annotate_block) {
                std::string extra = hooks->annotate_block(*block);
                if (!extra.empty())
                    snprintf(hline + hoff, sizeof(hline) - hoff, " %s",
                             extra.c_str());
            }
            CORE_LOG("%s", hline);
        }

        if (block->live_flags_in | block->flag_liveness) {
            char buf[64];
            flags_to_string(buf, block->flag_liveness);
            char buf2[64];
            flags_to_string(buf2, block->live_flags_in);
            CORE_LOG("%13sflags liveout %s, livein %s", "", buf, buf2);
        }

        if (block->num_preds) {
            char line[512];
            int off = snprintf(line, sizeof(line), "%13spreds    ", "");
            for (uint32_t p = 0; p < block->num_preds; p++) {
                if (p > 0)
                    off += snprintf(line + off, sizeof(line) - off, ",");
                off += snprintf(line + off, sizeof(line) - off, " BB_%u",
                                block->preds[p]->block_index);
            }
            CORE_LOG("%s", line);
        } else {
            CORE_LOG("%13spreds    ", "");
        }

        for (uint32_t i = 0; i < block->num_instrs; i++) {
            IRInstr& instr = block->instrs[i];

            char line[512];
            int off = snprintf(line, sizeof(line), "%-13llx%-10s",
                               (unsigned long long)(text_base + instr.pc),
                               opcode_name(instr.opcode()));

            for (uint8_t op = 0; op < instr.num_operands; op++) {
                if (op > 0)
                    off += snprintf(line + off, sizeof(line) - off, ", ");
                char obuf[64];
                IROperand_to_string(obuf, instr.operands[op]);
                off += snprintf(line + off, sizeof(line) - off, "%s", obuf);
            }

            if (instr.opcode() <= 117) {
                uint8_t def = x86_opcode_flag_effects[instr.opcode()].flags_defined
                              & instr.flag_liveness;
                if (def) {
                    char fbuf[64];
                    flags_to_string(fbuf, def);
                    off += snprintf(line + off, sizeof(line) - off, ", def %s",
                                    fbuf);
                }
            }

            if (hooks && hooks->annotate_instr) {
                std::string extra = hooks->annotate_instr(*block, instr, i);
                if (!extra.empty())
                    off += snprintf(line + off, sizeof(line) - off, "  %s",
                                    extra.c_str());
            }

            CORE_LOG("%s", line);
        }

        char tbuf[64];
        char line[512];
        int off = 0;

        if (block->is_entry & 1)
            off = snprintf(line, sizeof(line), "%-13llx",
                           (unsigned long long)(text_base + block->end_pc));
        else
            off = snprintf(line, sizeof(line), "%13s", "");

        switch (block->terminator.kind) {
        case TK_JMP:
            branch_target_to_string(tbuf, block->terminator.data.target);
            snprintf(line + off, sizeof(line) - off, "%-10s%s", "jmp", tbuf);
            break;

        case TK_JMP_IND:
        case TK_DYLD_STUB:
            IROperand_to_string(tbuf, block->terminator.data.operand);
            off += snprintf(line + off, sizeof(line) - off, "%-10s%s", "jmp",
                            tbuf);
            if (block->terminator.kind == TK_DYLD_STUB)
                snprintf(line + off, sizeof(line) - off, " (dyld stub %d)",
                         block->terminator.flags);
            break;

        case TK_FAR_JMP:
            IROperand_to_string(tbuf, block->terminator.data.operand);
            snprintf(line + off, sizeof(line) - off, "%-10s%s", "far jmp",
                     tbuf);
            break;

        case TK_JCC: {
            branch_target_to_string(tbuf, block->terminator.data.target);
            const char* cc = condition_code_to_string(block->terminator.subkind);
            IRBlock* ft = terminator_extra_block(block->terminator.extra);
            snprintf(line + off, sizeof(line) - off,
                     "%-10s%s, %s, fallthrough BB_%u", "jcc", cc, tbuf,
                     ft->block_index);
            break;
        }

        case TK_CALL:
            branch_target_to_string(tbuf, block->terminator.data.target);
            snprintf(line + off, sizeof(line) - off, "%-10s%s, return BB_%u",
                     "call", tbuf,
                     terminator_extra_block(block->terminator.extra)->block_index);
            break;

        case TK_CALL_IND:
            IROperand_to_string(tbuf, block->terminator.data.operand);
            snprintf(line + off, sizeof(line) - off, "%-10s%s, return BB_%u",
                     "call", tbuf,
                     terminator_extra_block(block->terminator.extra)->block_index);
            break;

        case TK_FAR_CALL:
            IROperand_to_string(tbuf, block->terminator.data.operand);
            snprintf(line + off, sizeof(line) - off, "%-10s%s, return BB_%u",
                     "far call", tbuf,
                     terminator_extra_block(block->terminator.extra)->block_index);
            break;

        case TK_RET_NEAR:
            snprintf(line + off, sizeof(line) - off, "ret");
            break;

        case TK_RET_NEAR_IMM:
            snprintf(line + off, sizeof(line) - off, "ret %hx",
                     block->terminator.opcode());
            break;

        case TK_RET_FAR:
            snprintf(line + off, sizeof(line) - off, "far ret");
            break;

        case TK_RET_FAR_IMM:
            snprintf(line + off, sizeof(line) - off, "far ret %hx",
                     block->terminator.opcode());
            break;

        case TK_SYSCALL: {
            IRBlock* ft = terminator_extra_block(
                reinterpret_cast<IRBlock*>(block->terminator.data.target.block.block));
            snprintf(line + off, sizeof(line) - off, "%-10sfallthrough BB_%u",
                     "syscall", ft->block_index);
            break;
        }

        case TK_JCXZ: {
            branch_target_to_string(tbuf, block->terminator.data.target);
            const char* name;
            switch (block->terminator.subkind) {
            case 2:  name = "jcxz";  break;
            case 1:  name = "jrcxz"; break;
            default: name = "jecxz"; break;
            }
            IRBlock* ft = terminator_extra_block(block->terminator.extra);
            snprintf(line + off, sizeof(line) - off,
                     "%-10s%s, fallthrough BB_%u", name, tbuf,
                     ft->block_index);
            break;
        }

        case TK_LOOP: {
            branch_target_to_string(tbuf, block->terminator.data.target);
            const char* name = opcode_name(block->terminator.opcode());
            const char* cc = condition_code_to_string(block->terminator.subkind);
            IRBlock* ft = terminator_extra_block(block->terminator.extra);
            snprintf(line + off, sizeof(line) - off,
                     "%-10s%s, %s, fallthrough BB_%u", name, cc, tbuf,
                     ft->block_index);
            break;
        }

        case TK_INVALID:
            snprintf(line + off, sizeof(line) - off, "invalid");
            break;

        case TK_BAD_ACCESS:
            if (block->terminator.subkind == BAK_BAD_PROTECTION)
                snprintf(line + off, sizeof(line) - off,
                         "bad access: bad protection");
            else
                snprintf(line + off, sizeof(line) - off,
                         "bad access: invalid address");
            break;

        case TK_INT_N:
            snprintf(line + off, sizeof(line) - off, "int %u",
                     block->terminator.subkind);
            break;

        case TK_OPCODE_TERM:
            snprintf(line + off, sizeof(line) - off, "%-10s",
                     opcode_name(block->terminator.opcode()));
            break;

        default:
            break;
        }

        CORE_LOG("%s", line);
        CORE_LOG("");
    }
}
