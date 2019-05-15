#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include <MC81F4204_disas.h>

static int _disassemble(RAsm *a, RAsmOp *op, ut8 *buf, ut64 len) {
    int dlen = _MC81F4204_disas(a->pc, op, buf, len);
    if (dlen < 0) {
        dlen = 0;
    }
    op->size = dlen;
    return dlen;
}

RAsmPlugin r_asm_plugin_MC81F4204 = {
    .name = "MC81F4204",
    .desc = "disassembly for the microcontroller 81F4204",
    .arch = "MC81F4204",
    .bits = 8, // I think
    .init = NULL,
    .fini = NULL,
    .disassemble = &_disassemble,
    .modify = NULL,
    .assemble = NULL,
};

#ifndef CORELIB

struct r_lib_struct_t radare_plugin = {
    .type = R_LIB_TYPE_ASM,
    .data = &r_asm_plugin_MC81F40204
};

#endif


