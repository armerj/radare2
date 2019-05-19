#ifndef _MC81F4204_OPS_H
#define _MC81F4204_OPS_H

#include <r_types.h> // ?


static inline ut16 rel_jmp_addr(ut16 pc, ut8 offset) {
    if (offset < 0x80) {
        return pc + offset;
    }
    offset = 0 - offset;
    return pc - offset;
}

enum {
    OP_INVALID = 0,
    OP_ADC,
    OP_ADD,
    OP_AND,
    OP_ASL,
    OP_BBC,
    OP_BBS,
    OP_BCC,
    OP_BCS,
    OP_BEQ,
    OP_BIT,
    OP_BMI,
    OP_BNE,
    OP_BPL,
    OP_BRA,
    OP_BRK,
    OP_BVC,
    OP_BVS,
    OP_CALL,
    OP_CBNE,
    OP_CLR,
    OP_CLR1,
    OP_CMP,
    OP_COM,
    OP_DBNE,
    OP_DEC,
    OP_DI,
    OP_DIV,
    OP_EI,
    OP_EOR,
    OP_INC,
    OP_JMP,
    OP_LD,
    OP_LSR,
    OP_MUL,
    OP_NOP,
    OP_NOT,
    OP_OR,
    OP_PCALL,
    OP_POP,
    OP_PUSH,
    OP_RET,
    OP_RETI,
    OP_ROL,
    OP_ROR,
    OP_SBC,
    OP_SET,
    OP_SET1,
    OP_ST,
    OP_STOP,
    OP_SUB,
    OP_T,
    OP_TCLR,
    OP_TSET,
    OP_TST,
    OP_X,
    OP_XCN,
    OP_TCALL,
};

enum { 
    NO_MASK = 0xFF,
    BIT_MASK = 0x1F,
    TCALL_MASK = 0x0F,
};

enum {
    NO_FLAGS,
    DP_PLUS,
    M_BIT_POS, 
    M_BIT_POS_B, 
    BYTE_BIT_POS,
    REL_JMP,
    CMP_REL_JMP,
    BRANCH_BIT_IN_OP,
    BIT_IN_OP,
    INDEX_IN_OP,
    IMM_VALUE,
};

typedef struct {
    ut8 op;
    ut8 instr;
    char* string;
    ut8 len;
    ut16 flag;
    ut8 addr_mask
} _MC81F4204_op_t;

static _MC81F4204_op_t _MC81F4204_ops[] = {
    // RPR = RAM Page select Register, used with dp (direct page offset) to access memory
    // Memory Data = 0x0000 - 0x0FFF
    // upage = 0xFF00 - 0xFFFF
    // tcall = 0xFFC0 - 0xFFDF


    // Arithmetic and Logic
    // ADC
    {0x04, OP_ADC, "adc A, 0x%02x", 2, NO_FLAGS, NO_MASK},
    {0x05, OP_ADC, "adc A, [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK}, 
    {0x06, OP_ADC, "adc A, [rpr + 0x%02x + X]", 2, NO_FLAGS, NO_MASK},
    {0x07, OP_ADC, "adc A, [0x%04x]", 3, NO_FLAGS, NO_MASK},
    {0x15, OP_ADC, "adc A, [0x%04x] + Y", 3, NO_FLAGS, NO_MASK},
    {0x16, OP_ADC, "adc A, [ [rpr + 0x%02x + X] ]", 2, NO_FLAGS, NO_MASK},
    {0x17, OP_ADC, "adc A, [ [rpr + 0x%02x] ] + Y", 2, NO_FLAGS, NO_MASK},
    {0x14, OP_ADC, "adc A, [rpr + X]", 1, NO_FLAGS, NO_MASK},
    // AND
    {0x84, OP_AND, "and A, 0x%02x", 2, NO_FLAGS, NO_MASK},
    {0x85, OP_AND, "and A, [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK}, 
    {0x86, OP_AND, "and A, [rpr + 0x%02x + X]", 2, NO_FLAGS, NO_MASK},
    {0x87, OP_AND, "and A, [0x%04x]", 3, NO_FLAGS, NO_MASK},
    {0x95, OP_AND, "and A, [0x%04x] + Y", 3, NO_FLAGS, NO_MASK},
    {0x96, OP_AND, "and A, [ [rpr + 0x%02x + X] ]", 2, NO_FLAGS, NO_MASK},
    {0x97, OP_AND, "and A, [ [rpr + 0x%02x] ] + Y", 2, NO_FLAGS, NO_MASK},
    {0x94, OP_AND, "and A, X", 1, NO_FLAGS, NO_MASK},
    // ASL, possibly saves into same reg/mem location
    {0x08, OP_ASL, "asl A", 1, NO_FLAGS, NO_MASK},
    {0x09, OP_ASL, "asl [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    {0x19, OP_ASL, "asl [rpr + 0x%02x + X]", 2, NO_FLAGS, NO_MASK},
    {0x18, OP_ASL, "asl [0x%04x]", 3, NO_FLAGS, NO_MASK},
    // CMP, compare A with memory
    {0x44, OP_CMP, "cmp A, 0x%02x", 2, NO_FLAGS, NO_MASK},
    {0x45, OP_CMP, "cmp A, [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK}, 
    {0x46, OP_CMP, "cmp A, [rpr + 0x%02x + X]", 2, NO_FLAGS, NO_MASK},
    {0x47, OP_CMP, "cmp A, [0x%04x]", 3, NO_FLAGS, NO_MASK},
    {0x55, OP_CMP, "cmp A, [0x%04x] + Y", 3, NO_FLAGS, NO_MASK},
    {0x56, OP_CMP, "cmp A, [ [rpr + 0x%02x + X] ]", 2, NO_FLAGS, NO_MASK},
    {0x57, OP_CMP, "cmp A, [ [rpr + 0x%02x] ] + Y", 2, NO_FLAGS, NO_MASK},
    {0x54, OP_CMP, "cmp A, [rpr + X]", 1, NO_FLAGS, NO_MASK},
    // CMPX, compare X with memory
    {0x5e, OP_CMP, "cmp X, 0x%02x", 2, NO_FLAGS, NO_MASK},
    {0x6c, OP_CMP, "cmp X, [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    {0x7c, OP_CMP, "cmp X, [0x%04x]", 3, NO_FLAGS, NO_MASK},
    // CMPX, compare Y with memory
    {0x7e, OP_CMP, "cmp Y, 0x%02x", 2, NO_FLAGS, NO_MASK},
    {0x8c, OP_CMP, "cmp Y, [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    {0x9c, OP_CMP, "cmp Y, [0x%04x]", 3, NO_FLAGS, NO_MASK},
    // COM, 1's complement, saves back into dp
    {0x2c, OP_COM, "com [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    // DEC
    {0xa8, OP_DEC, "dec A", 1, NO_FLAGS, NO_MASK},
    {0xa9, OP_DEC, "dec [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    {0xb9, OP_DEC, "dec [rpr + 0x%02x + X]", 2, NO_FLAGS, NO_MASK},
    {0xb8, OP_DEC, "dec [0x%04x]", 3, NO_FLAGS, NO_MASK},
    {0xaf, OP_DEC, "dec X", 1, NO_FLAGS, NO_MASK},
    {0xbe, OP_DEC, "dec Y", 1, NO_FLAGS, NO_MASK},
    // DIV, YA/X, Q:A R:Y
    {0x9b, OP_DIV, "div", 1, NO_FLAGS, NO_MASK},
    //EOR
    {0xa4, OP_EOR, "eor A, 0x%02x", 2, NO_FLAGS, NO_MASK},
    {0xa5, OP_EOR, "eor A, [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK}, 
    {0xa6, OP_EOR, "eor A, [rpr + 0x%02x + X]", 2, NO_FLAGS, NO_MASK},
    {0xa7, OP_EOR, "eor A, [0x%04x]", 3, NO_FLAGS, NO_MASK},
    {0xb5, OP_EOR, "eor A, [0x%04x] + Y", 3, NO_FLAGS, NO_MASK},
    {0xb6, OP_EOR, "eor A, [ [rpr + 0x%02x + X] ]", 2, NO_FLAGS, NO_MASK},
    {0xb7, OP_EOR, "eor A, [ [rpr + 0x%02x] ] + Y", 2, NO_FLAGS, NO_MASK},
    {0xb4, OP_EOR, "eor A, [rpr + X]", 1, NO_FLAGS, NO_MASK},
    // INC
    {0x88, OP_INC, "inc A", 1, NO_FLAGS, NO_MASK},
    {0x89, OP_INC, "inc [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    {0x99, OP_INC, "inc [rpr + 0x%02x + X]", 2, NO_FLAGS, NO_MASK},
    {0x98, OP_INC, "inc [0x%04x]", 3, NO_FLAGS, NO_MASK},
    {0x8f, OP_INC, "inc X", 1, NO_FLAGS, NO_MASK},
    {0x9e, OP_INC, "inc Y", 1, NO_FLAGS, NO_MASK},   
    // LSR, manual 1.39 says shift left, but shows shift right
    {0x48, OP_LSR, "lsr A", 1, NO_FLAGS, NO_MASK},
    {0x49, OP_LSR, "lsr [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    {0x59, OP_LSR, "lsr [rpr + 0x%02x + X]", 2, NO_FLAGS, NO_MASK},
    {0x58, OP_LSR, "lsr [0x%04x]", 3, NO_FLAGS, NO_MASK},
    // MUL YA <- Y x A
    {0x5b, OP_MUL, "mul", 1, NO_FLAGS, NO_MASK},
    // OR
    {0x64, OP_OR, "or A, 0x%02x", 2, NO_FLAGS, NO_MASK},
    {0x65, OP_OR, "or A, [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK}, 
    {0x66, OP_OR, "or A, [rpr + 0x%02x + X]", 2, NO_FLAGS, NO_MASK},
    {0x67, OP_OR, "or A, [0x%04x]", 3, NO_FLAGS, NO_MASK},
    {0x75, OP_OR, "or A, [0x%04x] + Y", 3, NO_FLAGS, NO_MASK},
    {0x76, OP_OR, "or A, [ [rpr + 0x%02x + X] ]", 2, NO_FLAGS, NO_MASK},
    {0x77, OP_OR, "or A, [ [rpr + 0x%02x] ] + Y", 2, NO_FLAGS, NO_MASK},
    {0x74, OP_OR, "or A, [rpr + X]", 1, NO_FLAGS, NO_MASK},    
    // ROL, rotate left through carry
    {0x28, OP_ROL, "rol A", 1, NO_FLAGS, NO_MASK},
    {0x29, OP_ROL, "rol [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    {0x39, OP_ROL, "rol [rpr + 0x%02x + X]", 2, NO_FLAGS, NO_MASK},
    {0x38, OP_ROL, "rol [0x%04x]", 3, NO_FLAGS, NO_MASK},    
    // ROR, rotate right through carry
    {0x68, OP_ROR, "ror A", 1, NO_FLAGS, NO_MASK},
    {0x69, OP_ROR, "ror [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    {0x79, OP_ROR, "ror [rpr + 0x%02x + X]", 2, NO_FLAGS, NO_MASK},
    {0x78, OP_ROR, "ror [0x%04x]", 3, NO_FLAGS, NO_MASK},
    // SBC, subtract with carry
    {0x24, OP_SBC, "sbc A, 0x%02x", 2, NO_FLAGS, NO_MASK},
    {0x25, OP_SBC, "sbc A, [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK}, 
    {0x26, OP_SBC, "sbc A, [rpr + 0x%02x + X]", 2, NO_FLAGS, NO_MASK},
    {0x27, OP_SBC, "sbc A, [0x%04x]", 3, NO_FLAGS, NO_MASK},
    {0x35, OP_SBC, "sbc A, [0x%04x] + Y", 3, NO_FLAGS, NO_MASK},
    {0x36, OP_SBC, "sbc A, [ [rpr + 0x%02x + X] ]", 2, NO_FLAGS, NO_MASK},
    {0x37, OP_SBC, "sbc A, [ [rpr + 0x%02x] ] + Y", 2, NO_FLAGS, NO_MASK},
    {0x34, OP_SBC, "sbc A, [rpr + X]", 1, NO_FLAGS, NO_MASK}, 
    // TST, test memory for neg or zero
    {0x4c, OP_TST, "tst [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    // XCN, change nibbles in A, A7-A4 <-> A3-A0
    {0xce, OP_XCN, "xcn", 1, NO_FLAGS, NO_MASK},

    // Register and Memory Operations
    // LDA
    {0xc4, OP_LD, "ld A, 0x%02x", 2, NO_FLAGS, NO_MASK},
    {0xc5, OP_LD, "ld A, [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK}, 
    {0xc6, OP_LD, "ld A, [rpr + 0x%02x + X]", 2, NO_FLAGS, NO_MASK},
    {0xc7, OP_LD, "ld A, [0x%04x]", 3, NO_FLAGS, NO_MASK},
    {0xd5, OP_LD, "ld A, [0x%04x] + Y", 3, NO_FLAGS, NO_MASK},
    {0xd6, OP_LD, "ld A, [ [rpr + 0x%02x + X] ]", 2, NO_FLAGS, NO_MASK},
    {0xd7, OP_LD, "ld A, [ [rpr + 0x%02x] ] + Y", 2, NO_FLAGS, NO_MASK},
    {0xd4, OP_LD, "ld A, [rpr + X]", 1, NO_FLAGS, NO_MASK},
    {0xdb, OP_LD, "ld A, X + 1", 1, NO_FLAGS, NO_MASK},
    // LDM
    {0xe4, OP_LD, "ld [rpr + 0x%02x], 0x%02x", 3, IMM_VALUE, NO_MASK},
    // TODO 0xe4 verify, should be fixed
    // 0x00000485      e4200c         ld [rpr + 0xc20], 0xc20
    // Looks like #imm is before dp
    // Should be ld [rpr + 0x0c], 0x20
    // else if (pinName == PIN_R05) { PUR0 = byteClear(PUR0, 0x20); }
    // LDX
    {0x1e, OP_LD, "ld X, 0x%02x", 2, NO_FLAGS, NO_MASK},
    {0xcc, OP_LD, "ld X, [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK}, 
    {0xcd, OP_LD, "ld X, [ [rpr + 0x%02x] ] + Y", 2, NO_FLAGS, NO_MASK},
    {0xdc, OP_LD, "ld X, [0x%04x]", 3, NO_FLAGS, NO_MASK},
    // LDY
    {0x3e, OP_LD, "ld Y, 0x%02x", 2, NO_FLAGS, NO_MASK},
    {0xc9, OP_LD, "ld Y, [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK}, 
    {0xd9, OP_LD, "ld Y, [rpr + 0x%02x + X]", 2, NO_FLAGS, NO_MASK}, // manual 1.39 is wrong
    {0xd8, OP_LD, "ld Y, [0x%04x]", 3, NO_FLAGS, NO_MASK},
    // STA
    {0xe5, OP_ST, "st [rpr + 0x%02x], A", 2, NO_FLAGS, NO_MASK}, 
    {0xe6, OP_ST, "st [rpr + 0x%02x + X], A", 2, NO_FLAGS, NO_MASK},
    {0xe7, OP_ST, "st [0x%04x], A", 3, NO_FLAGS, NO_MASK},
    {0xf5, OP_ST, "st [0x%04x] + Y, A", 3, NO_FLAGS, NO_MASK},
    {0xf6, OP_ST, "st [ [rpr + 0x%02x + X] ], A", 2, NO_FLAGS, NO_MASK},
    {0xf7, OP_ST, "st [ [rpr + 0x%02x] ] + Y, A", 2, NO_FLAGS, NO_MASK},
    {0xf4, OP_ST, "st X, A", 1, NO_FLAGS, NO_MASK},
    {0xfb, OP_ST, "st X + 1, A", 1, NO_FLAGS, NO_MASK},
    // STX
    {0xec, OP_ST, "st [rpr + 0x%02x], X", 2, NO_FLAGS, NO_MASK}, 
    {0xed, OP_ST, "st [ [rpr + 0x%02x] ] + Y, X", 2, NO_FLAGS, NO_MASK},
    {0xfc, OP_ST, "st [0x%04x], X", 3, NO_FLAGS, NO_MASK},
    // STY
    {0xe9, OP_ST, "st [rpr + 0x%02x], Y", 2, NO_FLAGS, NO_MASK}, 
    {0xf9, OP_ST, "st [rpr + 0x%02x + X], Y", 2, NO_FLAGS, NO_MASK},
    {0xf8, OP_ST, "st [0x%04x], Y", 3, NO_FLAGS, NO_MASK},
    // Transfer between registers
    {0xe8, OP_T, "tax", 1, NO_FLAGS, NO_MASK}, // Transfer A into X
    {0x9f, OP_T, "tay", 1, NO_FLAGS, NO_MASK},
    {0xae, OP_T, "tspx", 1, NO_FLAGS, NO_MASK},
    {0xc8, OP_T, "txa", 1, NO_FLAGS, NO_MASK},
    {0x8e, OP_T, "txsp", 1, NO_FLAGS, NO_MASK},
    {0xbf, OP_T, "tya", 1, NO_FLAGS, NO_MASK},
    // Exchange between registers and memory
    {0xee, OP_X, "xax", 1, NO_FLAGS, NO_MASK}, // Exchange A and X
    {0xde, OP_X, "xay", 1, NO_FLAGS, NO_MASK},
    {0xbc, OP_X, "xma [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    {0xad, OP_X, "xma [rpr + 0x%02x + X]", 2, NO_FLAGS, NO_MASK},
    {0xbb, OP_X, "xma X", 1, NO_FLAGS, NO_MASK},
    {0xfe, OP_X, "xyx", 1, NO_FLAGS, NO_MASK},
    
    // 16-bit Manipulation
    {0x1d, OP_ADD, "addw YA, word [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    {0x5d, OP_CMP, "cmpw YA, word [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    {0xbd, OP_DEC, "decw word [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    {0x9d, OP_INC, "incw word [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    {0x7d, OP_LD, "ld YA, word [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},
    {0xdd, OP_ST, "st word [rpr + 0x%02x], YA", 2, NO_FLAGS, NO_MASK},
    {0x3d, OP_SUB, "subw YA, word [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK},

    // Bit Manipulation
    // other ops AND1B, EOR1B, LDCB, OR1B
    {0x8b, OP_AND, "and1 C, %s[0x%04x].%d", 3, M_BIT_POS_B, NO_MASK}, // TODO verify, I believe it is fixed
    // I beleive that the highest nibble is used to choose bit and determine AND1 or AND1B
    // 0xF000 & M = flags, likey 1110 is the mask for the bit, and 0001 is the mask for Not opertation

    {0x0c, OP_BIT, "bit [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK}, // Z <- A /\ M, N <- M7, V <- M6
    {0x1c, OP_BIT, "bit [0x%04x]", 3, NO_FLAGS, NO_MASK}, 
    {0x2b, OP_CLR, "clr A.%u", 2, BYTE_BIT_POS, NO_MASK},
    {0x20, OP_CLR, "clrc", 1, NO_FLAGS, NO_MASK},
    {0x40, OP_CLR, "clrg", 1, NO_FLAGS, NO_MASK}, 
    {0x80, OP_CLR, "clrv", 1, NO_FLAGS, NO_MASK},
    {0xab, OP_EOR, "eor1 C, %s[0x%04x].%d", 3, M_BIT_POS_B, NO_MASK},
 
    {0xcb, OP_LD, "ldc [0x%04x].%d", 3, M_BIT_POS, NO_MASK}, // should these be %02 not %04
    {0x4b, OP_NOT, "not1 [0x%04x].%d", 3, M_BIT_POS, NO_MASK},
    {0x6b, OP_OR, "or1 C, %s[0x%04x].%d", 3, M_BIT_POS_B, NO_MASK},
    {0x0b, OP_SET, "set A.%u", 2, BYTE_BIT_POS, NO_MASK},
    {0xa0, OP_SET, "setc", 1, NO_FLAGS, NO_MASK},
    {0xc0, OP_SET, "setg", 1, NO_FLAGS, NO_MASK},
    {0xeb, OP_ST, "st1 [0x%04x].%d, C", 3, M_BIT_POS, NO_MASK},
    {0x5c, OP_TCLR, "tclr [0x%04x]", 3, NO_FLAGS, NO_MASK}, // A - (M), (M) <- (M) \/ ~(A)
    {0x3c, OP_TSET, "tset [0x%04x]", 3, NO_FLAGS, NO_MASK}, // A - (M), (M) <- (M) \/ (A)

    // Branch and Jump
    {0x50, OP_BCC, "bcc [0x%04x]", 2, REL_JMP, NO_MASK}, // rel jump, need to get current position to determine jump to location
    {0xd0, OP_BCS, "bcs [0x%04x]", 2, REL_JMP, NO_MASK},
    {0xf0, OP_BEQ, "beq [0x%04x]", 2, REL_JMP, NO_MASK},
    {0x90, OP_BMI, "bmi [0x%04x]", 2, REL_JMP, NO_MASK},
    {0x70, OP_BNE, "bne [0x%04x]", 2, REL_JMP, NO_MASK},
    {0x10, OP_BPL, "bpl [0x%04x]", 2, REL_JMP, NO_MASK},
    {0x2f, OP_BRA, "bra [0x%04x]", 2, REL_JMP, NO_MASK},
    {0x30, OP_BVC, "bvc [0x%04x]", 2, REL_JMP, NO_MASK},
    {0xb0, OP_BVS, "bvs [0x%04x]", 2, REL_JMP, NO_MASK},

    // call
    {0x3b, OP_CALL, "call [0x%04x]", 3, NO_FLAGS, NO_MASK},
    {0x5f, OP_CALL, "call word [rpr + 0x%02x]", 2, NO_FLAGS, NO_MASK}, 

    // cmp and branch
    {0xfd, OP_CBNE, "cbne [rpr + 0x%02x], [0x%04x]", 3, CMP_REL_JMP, NO_MASK}, 
    {0x8d, OP_CBNE, "cbne [rpr + 0x%02x + X], [0x%04x]", 3, CMP_REL_JMP, NO_MASK}, 

    // dec and branch
    {0xac, OP_DBNE, "dbne [rpr + 0x%02x], [0x%04x]", 3, CMP_REL_JMP, NO_MASK}, 
    {0x7b, OP_DBNE, "dbne Y, [0x%04x]", 2, REL_JMP, NO_MASK},

    // JMP
    {0x1b, OP_JMP, "jmp [0x%04x]", 3, NO_FLAGS, NO_MASK}, 
    {0x1f, OP_JMP, "jmp [ [0x%04x] ]", 3, NO_FLAGS, NO_MASK}, 
    {0x3f, OP_JMP, "jmp [ [rpr + 0x%02x] ]", 2, NO_FLAGS, NO_MASK}, 

    // PCALL
    {0x4f, OP_PCALL, "pcall [upage + 0x%02x]", 2, NO_FLAGS, NO_MASK},

    // Control Operation and Etc
    {0x0f, OP_BRK, "brk", 1, NO_FLAGS, NO_MASK},
    {0x60, OP_DI, "di", 1, NO_FLAGS, NO_MASK},
    {0xe0, OP_EI, "ei", 1, NO_FLAGS, NO_MASK},
    {0xff, OP_NOP, "nop", 1, NO_FLAGS, NO_MASK},
    
    // POP
    {0x0d, OP_POP, "pop A", 1, NO_FLAGS, NO_MASK},
    {0x2d, OP_POP, "pop X", 1, NO_FLAGS, NO_MASK},
    {0x4d, OP_POP, "pop Y", 1, NO_FLAGS, NO_MASK},
    {0x6d, OP_POP, "pop PSW", 1, NO_FLAGS, NO_MASK},

    // PUSH
    {0x0e, OP_PUSH, "push A", 1, NO_FLAGS, NO_MASK},
    {0x2e, OP_PUSH, "push X", 1, NO_FLAGS, NO_MASK},
    {0x4e, OP_PUSH, "push Y", 1, NO_FLAGS, NO_MASK},
    {0x6e, OP_PUSH, "push PSW", 1, NO_FLAGS, NO_MASK},

    // RET
    {0x6f, OP_RET, "ret", 1, NO_FLAGS, NO_MASK},
    {0x7f, OP_RETI, "reti", 1, NO_FLAGS, NO_MASK}, 

    // STOP
    {0xef, OP_STOP, "stop", 1, NO_FLAGS, NO_MASK},

    // Opcodes with bit in opcode
    {0x01, OP_SET1, "set1 [rpr + 0x%02x].%d", 2, BIT_IN_OP, BIT_MASK},
    {0x11, OP_CLR1, "clr1 [rpr + 0x%02x].%d", 2, BIT_IN_OP, BIT_MASK},

    {0x02, OP_BBS, "bbs A.%d, [0x%04x]", 2, BRANCH_BIT_IN_OP, BIT_MASK},
    {0x03, OP_BBS, "bbs [rpr + 0x%02x].%d, [0x%04x]", 3, BRANCH_BIT_IN_OP, BIT_MASK},

    {0x12, OP_BBC, "bbc A.%d, [0x%04x]", 2, BRANCH_BIT_IN_OP, BIT_MASK},
    {0x13, OP_BBC, "bbc [rpr + 0x%02x].%d, [0x%04x]", 3, BRANCH_BIT_IN_OP, BIT_MASK},

    //TCALL
    {0x0a, OP_TCALL, "tcall %d", 1, INDEX_IN_OP, TCALL_MASK},
};

#endif














