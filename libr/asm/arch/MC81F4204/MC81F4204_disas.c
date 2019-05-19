#include <r_asm.h>
#include <r_lib.h>
#include <string.h>

#include "MC81F4204_ops.h"
#include "MC81F4204_disas.h"

static const char *_MC81F4204_regs[] = {

};

int _MC81F4204_disas(ut64 pc, RAsmOp *op, const ut8 *buf, ut64 len) {
    int i = 0; // index of op in op array
    while (_MC81F4204_ops[i].string && _MC81F4204_ops[i].op != (buf[0] & _MC81F4204_ops[i].addr_mask)) {
        i++;
    } // search through array for current opcode

    if (_MC81F4204_ops[i].string) { // in op array
        const char* name = _MC81F4204_ops[i].string;
        ut8 oplen = _MC81F4204_ops[i].len;
        ut16 flag = _MC81F4204_ops[i].flag;
        char* disasm = 0;

        switch (oplen) {
        case 1:
            if (flag == INDEX_IN_OP) {
                // TODO this is not correct, refer to page 47 of manual
                disasm = r_str_newf(name, buf[0] > 4);
            } else {
                disasm = r_str_new(name);
            }
        case 2:
            if (len > 1) {
                if (flag == NO_FLAGS) {
                    disasm = r_str_newf(name, buf[1]);
                } else if (flag == REL_JMP) {
                    disasm = r_str_newf(name, rel_jmp_addr(pc + 2, buf[1]));
                } else if (flag == BYTE_BIT_POS) {
                    // TODO need to verify this, bit pos = BYTE >> 5
                    disasm = r_str_newf(name, buf[1] >> 5);
                } else if (flag == BIT_IN_OP) {
                    disasm = r_str_newf(name, buf[1], buf[0] >> 5);
                } else if (flag == BRANCH_BIT_IN_OP) {
                    disasm = r_str_newf(name, buf[0] >> 5, rel_jmp_addr(pc + 2, buf[1]));
                }
            } else {
                r_strbuf_set(&op->buf_asm, "truncated");
                return -1;
            }
            break;
        case 3:
            if (len > 2) {
                if (flag == NO_FLAGS) {
                    ut16 imm_addr = buf[2];
                    disasm = r_str_newf(name, buf[1] + (imm_addr << 8));
                } else if (flag == CMP_REL_JMP) {
                    disasm = r_str_newf(name, buf[1], rel_jmp_addr(pc + 3, buf[2]));
                } else if (flag == M_BIT_POS_B) {
                    ut16 imm_addr = buf[1] + ((buf[2] & 0x0F) << 8);
                 
                    // TODO need to verify this is how the bit are determined
                    // other address opcodes use H byte, L byte
                    if ((buf[2] & 0x10) == 0x10) {
                        disasm = r_str_newf(name, "~", imm_addr, buf[2] >> 5);
                    } else {
                        disasm = r_str_newf(name, "", imm_addr, buf[2] >> 5);
                    }
                } else if (flag == M_BIT_POS) {
                    ut16 imm_addr = buf[2] & 0x0F;
                 
                    // TODO need to verify this is how the bit are determined
                    // other address opcodes use H byte, L byte
                    disasm = r_str_newf(name, buf[1] + (imm_addr << 8), buf[2] >> 5);
                } else if (flag == BRANCH_BIT_IN_OP) { // TODO do not determine address, just put offset
                    disasm = r_str_newf(name, buf[1], buf[0] >> 5, rel_jmp_addr(pc + 2, buf[2]));
                } else if (flag == IMM_VALUE) {
                    disasm = r_str_newf(name, buf[2], buf[1]);
                }
            } else { 
                r_strbuf_set(&op->buf_asm, "truncated");
                return -1;
            }
            break;
        default:
            // shouldn't get here
            return 0;
        }
        //TODO Change control register to names
        r_strbuf_set(&op->buf_asm, disasm);
        free(disasm);

        return oplen;
    }

    // invalid opcode
    return 0;
}
    


















