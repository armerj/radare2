// Used 6502 analysis plugin as example https://github.com/radare/radare2/blob/master/libr/anal/p/anal_6502.c

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/MC81F4204/MC81F4204_ops.h" // TODO add cycles and mem type into op table


static inline ut16 rel_jmp_addr(ut16 pc, ut8 offset) {
    if (offset < 0x80) {
        return pc + offset;
    }
    offset = 0 - offset;
    return pc - offset;
}

static int set_reg_profile(RAnal *anal) {
	char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"gpr	x	.8	0	0\n"
		"gpr	ya	.16	1	0\n"
		"gpr	y	.8	1	0\n"
		"gpr	a	.8	2	0\n"
		"gpr	psw	.8	3	0\n"

		"gpr	flags	.8	4	0\n"
		"gpr	C	.1	.32	0\n"
		"gpr	Z	.1	.33	0\n"
		"gpr	I	.1	.34	0\n"
		"gpr	H	.1	.35	0\n"
		"gpr	B	.1	.36	0\n"
		"gpr	G	.1	.37	0\n"
		"gpr	V	.1	.38	0\n"
		"gpr	N	.1	.39	0\n"
		"gpr	sp	.8	4	0\n"
		"gpr	pc	.16	5	0\n"
		"gpr	pcl	.8	5	0\n"
		"gpr	pch	.8	6	0\n"
		"gpr	rpr	.8	7	0\n"
		"gpr	t	.8	8	0\n"; // temp register to make things easier
								  // TODO add memory register that we can store memory addresses into for ease of use, 8 and 16 bit
	return r_reg_set_profile_string (anal->reg, p);
}


static int esil_MC81F4204_init (RAnalEsil *esil) {
	if (esil->anal && esil->anal->reg) {		//initial values
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "pc", -1), 0x0000);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "sp", -1), 0xaf);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "a", -1), 0x00);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "x", -1), 0x00);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "y", -1), 0x00);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "psw", -1), 0x00);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "flags", -1), 0x00);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "rpr", -1), 0x00);
	}
	return true;
}

static char* _MC81F4204_mem_access[] = {
	"%s,", // immediate
	"rpr, 8, <<, %s, +, [1],", // dp
	"%s, x, +, 0xff, &, rpr, 8, <<, +, [1],", // dp + X
	"%s, [1],", // !abs
	"%s, y, +, [1],", //!abs + Y
	"", // [dp + X]
	"", // [dp] + Y
	"" // {X}
}

//********************* Move to asm ops table
typedef struct {
	ut8 op;
	ut8 len;
	ut8 cycles;
	ut8 memType;
} _MC81F4204_esil_t;

static _MC81F4204_esil_t _MC81F4204_esil[] = {
	// byte op, num of bytes, num of cycles, mem access type

	// ADC
	{0x04, 2, 2, 0},

}
//*********************

// from https://github.com/radare/radare2/blob/master/libr/anal/p/anal_6502.c
enum {  // TODO need H, and V
	_MC81F4204_FLAGS_C = (1 << 0),
	_MC81F4204_FLAGS_B = (1 << 1),
	_MC81F4204_FLAGS_Z = (1 << 2),
	_MC81F4204_FLAGS_N = (1 << 3),

	_MC81F4204_FLAGS_NZ = (_MC81F4204_FLAGS_Z | _MC81F4204_FLAGS_N),
	_MC81F4204_FLAGS_CNZ = (_MC81F4204_FLAGS_C | _MC81F4204_FLAGS_Z | _MC81F4204_FLAGS_N),
	_MC81F4204_FLAGS_BNZ = (_MC81F4204_FLAGS_B | _MC81F4204_FLAGS_Z | _MC81F4204_FLAGS_N),
};


static void _MC81F4204_anal_update_flags(RAnalOp *op, int flags) {
	/* FIXME: 9,$b instead of 8,$b to prevent the bug triggered by: A = 0 - 0xff - 1 */
	if (flags & _MC81F4204_FLAGS_B) {
		r_strbuf_append (&op->esil, ",9,$b,C,:=");
	}
	if (flags & _MC81F4204_FLAGS_C) {
		r_strbuf_append (&op->esil, ",7,$c,C,:=");
	}
	if (flags & _MC81F4204_FLAGS_Z) {
		r_strbuf_append (&op->esil, ",$z,Z,:=");
	}
	if (flags & _MC81F4204_FLAGS_N) {
		r_strbuf_append (&op->esil, ",$s,N,:=");
	}
}
// TODO update 


static int _MC81F4204_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	memset(op, '\0', sizeof(RAnalOp));
	op->size = 1;
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->id = data[0];
	int i = 0;
	r_strbuf_init(&op->esil);

	while (_MC81F4204_esil[i].op && _MC81F4204_esil[i].op != data[0]) {
		i++;
	} // search through array for current opcode esil data
	
	op->cycles = _MC81F4204_esil[i].cycles;
	op->size = _MC81F4204_esil[i].size;

	switch(data[0]) {
	case 0x00: // unvalid
		op->size = 1;
		op->type = R_ANAL_OP_TYPE_ILL;
		break;

	// ADC
	// $z, Z, =, a, 7, >>, N, =
	case 0x04:
	case 0x05:
	case 0x06:
	case 0x07:
	case 0x15:
	case 0x16:
	case 0x17:
	case 0x14:
		op->type = R_ANAL_OP_TYPE_ADD;
		
		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]); // Gets memory value
		r_strbuf_append(&op->esil, ""); // action and flag update
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_CNZ);
		break;

	// AND
	case 0x84:
	case 0x85:
	case 0x86:
	case 0x87:
	case 0x95:
	case 0x96:
	case 0x97:
	case 0x94:
		op->type = R_ANAL_OP_TYPE_AND;
		
		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append(&op->esil, "a, &=");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;

	// ASL 
	case 0x08:
		op->type = R_ANAL_OP_TYPE_ASL;

		r_strbuf_set (&op->esil,  "a, 1, <<=, 7");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_CNZ);
		break;
	case 0x09:
	case 0x19:
	case 0x18:
		op->type = R_ANAL_OP_TYPE_ASL;

		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append (&op->esil,  ", 1, <<=, 7");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_CNZ);
		break;

	// CMP, (A) - (M)
	case 0x44:
	case 0x45:
	case 0x46:
	case 0x47:
	case 0x55:
	case 0x56:
	case 0x57:
	case 0x54:
		op->type = R_ANAL_OP_TYPE_CMP;

		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append (&op->esil,  ", a, ==");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_BNZ); // B because we are subtracting
		break;

	//CMPX
	case 0x5E:
	case 0x6C:
	case 0x7C:
		op->type = R_ANAL_OP_TYPE_CMP;

		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append (&op->esil,  ", x, ==");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_BNZ); // B because we are subtracting
		break;

	//CMPY
	case 0x7E:
	case 0x8C:
	case 0x9C:
		op->type = R_ANAL_OP_TYPE_CMP;

		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append (&op->esil,  ", y, ==");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_BNZ); // B because we are subtracting
		break;

	// COM
	case 0x2C:
		// TODO op->type

		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append (&op->esil,  ", !=");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ); 
		break;
	
	// DEC
	case 0xA8:
	case 0xAF:
	case 0xBE:
		op->type = R_ANAL_OP_TYPE_STORE; // Not sure why it is store

		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append (&op->esil,  ", --="); // [1] I believe since we are sticking it back into memory, TODO check other switch cases. 
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;		
	case 0xA9:
	case 0xB9:
	case 0xB8:
		op->type = R_ANAL_OP_TYPE_STORE; // Not sure why it is store

		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append (&op->esil,  ", --=[1]"); // [1] I believe since we are sticking it back into memory, TODO check other switch cases. 
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ); 
		break;

	// DIV
	case 0x9B:
		op->type = R_ANAL_OP_TYPE_DIV; // TODO, need to check
		r_strbuf_set (&op->esil, "ya, x, %, t, =, ya, x, /, a, =");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NVHZ);
		r_strbuf_append (&op->esil,  "t, y, =");
		break;

	// EOR
	case 0xA4:
	case 0xA5:
	case 0xA6:
	case 0xA7:
	case 0xB5:
	case 0xB6:
	case 0xB7:
	case 0xB4:
		op->type = R_ANAL_OP_TYPE_XOR;

		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append (&op->esil,  ", a, ^="); 
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;

	// INC
	case 0x88:
	case 0x89:
	case 0x99:
	case 0x98:
	case 0x8F:
	case 0x9E:
		op->type = R_ANAL_OP_TYPE_STORE;
		
		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append (&op->esil,  ", ++=[1]"); // [1] I believe since we are sticking it back into memory, TODO check other switch cases. 
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ); 
		break;
	
	//LSR
	case 0x48:
		op->type = R_ANAL_OP_TYPE_SHR;

		r_strbuf_set (&op->esil,  "1,a,&,C,=,1,a,>>=");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZC); 
		break;
	case 0x49:
	case 0x59:
	case 0x58:
		op->type = R_ANAL_OP_TYPE_SHR;

		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append (&op->esil,  "t, =, 1, t , &, C, =, 1, t, >>="); // TODO need to check where it stores this
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZC); 
		break;

	// MUL
	case 0x5B:
		op->type = R_ANAL_OP_TYPE_MUL; // TODO check this

		r_strbuf_set (&op->esil,  "y, a, *, ya, =");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ); 
		break;

	// OR
	case 0x64:
	case 0x65:
	case 0x66:
	case 0x67:
	case 0x75:
	case 0x76:
	case 0x77:
	case 0x74:
		op->type = R_ANAL_OP_TYPE_OR;

		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append (&op->esil,  ", a, |="); 
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;		

	// ROL
	case 0x28:
	case 0x29:
	case 0x39:
	case 0x38:
		// TODO
	
	// ROR
	case 0x68:
	case 0x69:
	case 0x79:
	case 0x78:
		// TODO

	// SBC
	case 0x24:
	case 0x25:
	case 0x26:
	case 0x27:
	case 0x35:
	case 0x36:
	case 0x37:
	case 0x34:
		// TODO

	// TST
	case 0x4C:
		 // TODO  op->type = R_ANAL_OP_TYPE_OR;

		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append (&op->esil,  ", 0, -"); 
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;		

	// XCN, exchange nibbles in A
	case 0xCE:
		 // TODO  op->type =R_ANAL_OP_TYPE_OR;
		// TODO, t=a, a << 4, t >> 4, a += t

		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;		

	// LDA
	case 0xC4:
	case 0xC5:
	case 0xC6:
	case 0xC7:
	case 0xD5:
	case 0xD6:
	case 0xD7:
	case 0xD4:
		op->type = R_ANAL_OP_TYPE_LOAD;

		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append (&op->esil,  ", a, ="); 
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;	

	// LDM
	case 0xE4:
		op->type = R_ANAL_OP_TYPE_LOAD;

		r_strbuf_set (&op->esil, "%s, dp, =[1]", data[1]); // TODO fix dp
		break;	
		
	// LDX
	case 0x1E:
	case 0xCC:
	case 0xCD:
	case 0xDC:
		op->type = R_ANAL_OP_TYPE_LOAD;

		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append (&op->esil,  ", x, ="); 
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;	
		
	// LDY
	case 0x3E:
	case 0xC9:
	case 0xD9:
	case 0xD8:
		op->type = R_ANAL_OP_TYPE_LOAD;

		r_strbuf_set (&op->esil,  _MC81F4204_mem_access[_MC81F4204_esil[i].memType], data[1]);
		r_strbuf_append (&op->esil,  ", y, ="); 
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;	

	// STA
	case 0xE5:
	case 0xE6:
	case 0xE7:
	case 0xF5:
	case 0xF6:
	case 0xF7:
	case 0xF4:
	case 0xFB:
		op->type = R_ANAL_OP_TYPE_STORE;

		r_strbuf_set (&op->esil, "a, mem, =[1]", data[1]); // TODO fix mem
		break;	

	// STX
	case 0xEC:
	case 0xED:
	case 0xFC:
		op->type = R_ANAL_OP_TYPE_STORE;

		r_strbuf_set (&op->esil, "x, mem, =[1]", data[1]); // TODO fix mem
		break;	

	// STY
	case 0xE9:
	case 0xF9:
	case 0xF8:
		op->type = R_ANAL_OP_TYPE_STORE;

		r_strbuf_set (&op->esil, "y, mem, =[1]", data[1]); // TODO fix mem
		break;	

	// TAX transfer A to X
	case 0xE8:
		op->type = R_ANAL_OP_TYPE_MOV;

		r_strbuf_set (&op->esil, "a, x, =");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;	

	// TAY
	case 0xE8:
		op->type = R_ANAL_OP_TYPE_MOV;

		r_strbuf_set (&op->esil, "a, y, =");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;	

	// TSPX 
	case 0xE8:
		op->type = R_ANAL_OP_TYPE_MOV;

		r_strbuf_set (&op->esil, "sp, x, =");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;	

	// TXA 
	case 0xE8:
		op->type = R_ANAL_OP_TYPE_MOV;

		r_strbuf_set (&op->esil, "x, a, =");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;	

	// TXSP
	case 0xE8:
		op->type = R_ANAL_OP_TYPE_MOV;

		r_strbuf_set (&op->esil, "x, sp, =");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;	

	// TYA
	case 0xE8:
		op->type = R_ANAL_OP_TYPE_MOV;

		r_strbuf_set (&op->esil, "y, a, =");
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;	

	// XAX Exchange A and X
	case 0xE8:
		op->type = R_ANAL_OP_TYPE_MOV;

		r_strbuf_set (&op->esil, "a, t, =, x, a, =, t, x, =");
		break;	

	// XAY
	case 0xE8:
		op->type = R_ANAL_OP_TYPE_MOV;

		r_strbuf_set (&op->esil, "a, t, =, y, a, =, t, y, =");
		break;	

	// XMA
	case 0xBC:
	case 0xAD:
	case 0xBB:
		op->type = R_ANAL_OP_TYPE_MOV;

		r_strbuf_set (&op->esil, "a, t, =, mem, a, =, t,mem, ="); // TODO fix mem
		_MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;	

	// XYX
	case 0xE8:
		op->type = R_ANAL_OP_TYPE_MOV;

		r_strbuf_set (&op->esil, "x, t, =, y, x, =, t, y, =");
		break;	

	// ADDW 16bit opcode
	case 0x1D:
		op->type = R_ANAL_OP_TYPE_ADD;
		
		// TODO
		// FLAGS
		break;
		
	// CMPW
	case 0x5D:
		op->type = R_ANAL_OP_TYPE_CMP;

		// TODO
		// _MC81F4204_anal_update_flags(op, _6502_FLAGS_NZC);
		break;
		
	// DECW
	case 0xBD:
		op->type = R_ANAL_OP_TYPE_STORE;

		// TODO
		// _MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;
		
	// INCW
	case 0x9D:
		op->type = R_ANAL_OP_TYPE_STORE;

		// TODO
		// _MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;
		
	// LDYA
	case 0x7D:
		op->type = R_ANAL_OP_TYPE_LOAD;

		// TODO
		// _MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;
		
	// STYA
	case 0xDD:
		op->type = R_ANAL_OP_TYPE_STORE;

		// TODO
		break;
		
	// SUBW
	case 0x3D:
		op->type = R_ANAL_OP_TYPE_SUB;

		// TODO
		// FLAGS
		break;

	// AND1
	case 0x8B:
		op->type = R_ANAL_OP_TYPE_AND;
		// TODO function to determine M
		// TODO function to determine AND1 or AND1B

		break;

	// BIT
	case 0x0C:
	case 0x1C:
		op->type = R_ANAL_OP_TYPE_AND;
		// TODO function to determine M
		// TODO function to determine AND1 or AND1B

		break;

	// CLR1
	case 0x11:
	case 0x31:
	case 0x51:
	case 0x71:
	case 0x91:
	case 0xB1:
	case 0xD1:
	case 0xF1:
		op->type = R_ANAL_OP_TYPE_STORE;

		// TODO same as BIT
		break;

	// CLRA1
	case 0x2B:
		op->type = R_ANAL_OP_TYPE_STORE;

		// TODO same as BIT
		break;
	
	// CLRC
	case 0x20:
		op->type = R_ANAL_OP_TYPE_STORE;

		r_strbuf_set (&op->esil, "0, c, ="); 
		break;
	
	// CLRG
	case 0x20:
		op->type = R_ANAL_OP_TYPE_STORE;

		r_strbuf_set (&op->esil, "0, g, ="); 
		break;
	
	// CLRV
	case 0x20:
		op->type = R_ANAL_OP_TYPE_STORE;

		r_strbuf_set (&op->esil, "0, v, ="); 
		break;
	
	// EOR1
	case 0xAB:
		op->type = R_ANAL_OP_TYPE_XOR;
		// TODO function to determine M
		// TODO function to determine AND1 or AND1B

		break;

	// LDC
	case 0xCB:
		op->type = R_ANAL_OP_TYPE_LOAD;
		// TODO function to determine M
		// TODO function to determine AND1 or AND1B

		break;

	// NOT1
	case 0xCB:
		op->type = R_ANAL_OP_TYPE_STORE;
		// TODO function to determine M

		break;

	// OR1
	case 0x6B:
		op->type = R_ANAL_OP_TYPE_OR;
		// TODO function to determine M
		// TODO function to determine AND1 or AND1B

		break;

	// SET1
	case 0x01:
	case 0x21:
	case 0x41:
	case 0x61:
	case 0x81:
	case 0xA1:
	case 0xC1:
	case 0xE1:
		op->type = R_ANAL_OP_TYPE_STORE;

		// TODO same as BIT
		break;

	// SETC 
	case 0xA0:
		op->type = R_ANAL_OP_TYPE_STORE; // TODO 6502 has these as NOPs and updates flags

		r_strbuf_set (&op->esil, "1, c, ="); 
		break;
	
	// SETG
	case 0xC0:
		op->type = R_ANAL_OP_TYPE_STORE;

		r_strbuf_set (&op->esil, "1, g, ="); 
		break;

	// STC, Store C Flag
	case 0xEB:
		op->type = R_ANAL_OP_TYPE_STORE;
		// TODO function to determine M

		break;

	// TCLR1, Test and Clear bits with A
	case 0x5C:
		op->type = R_ANAL_OP_TYPE_CMP;
		// TODO

		// _MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;

	// TSET1
	case 0x3C:
		op->type = R_ANAL_OP_TYPE_CMP;
		// TODO

		// _MC81F4204_anal_update_flags(op, _6502_FLAGS_NZ);
		break;

	// BBC
	case 0x12:
	case 0x32:
	case 0x52:
	case 0x72:
	case 0x92:
	case 0xB2:
	case 0xD2:
	case 0xF2: 
	case 0x13:
	case 0x33:
	case 0x53:
	case 0x73:
	case 0x93:
	case 0xB3:
	case 0xD3:
	case 0xF3: 
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->fail = addr + op->size;
		
		// TODO jump code, do code for both A and dp
		break;

	// BBS
	case 0x02:
	case 0x22:
	case 0x42:
	case 0x62:
	case 0x82:
	case 0xA2:
	case 0xC2:
	case 0xE2:
	case 0x03:
	case 0x23:
	case 0x43:
	case 0x63:
	case 0x83:
	case 0xA3:
	case 0xC3:
	case 0xE3:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->fail = addr + op->size;
		
		// TODO jump code, do code for both A and dp
		break;

	// BCC
	case 0x50:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->fail = addr + op->size;
		
		// TODO jump code
		break;

	// BCS
	case 0xD0:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->fail = addr + op->size;
		
		// TODO jump code
		break;

	// BEQ
	case 0xF0:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->fail = addr + op->size;
		
		// TODO jump code
		break;

	// BMI
	case 0x90:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->fail = addr + op->size;
		
		// TODO jump code
		break;

	// BNE
	case 0x70:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->fail = addr + op->size;
		
		// TODO jump code
		break;

	// BPL
	case 0x10:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->fail = addr + op->size;
		
		// TODO jump code
		break;

	// BCC
	case 0x50:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->fail = addr + op->size;
		
		// TODO jump code
		break;

	// BRA, branch always
	case 0x2F:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		
		// TODO jump code
		break;

	// BVC
	case 0x30:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->fail = addr + op->size;
		
		// TODO jump code
		break;

	// BVS
	case 0xB0:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->fail = addr + op->size;
		
		// TODO jump code
		break;

	// CALL !abs
	case 0x3B:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 2;
		op->jump = (data[1] + (data[2] << 8);

		// TODO call code
		break;
		
	// CALL dp
	case 0x3B:
		op->type = R_ANAL_OP_TYPE_UCALL; // unknown call 
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 2;

		// TODO call code
		break;

	// CBNE, Compare and branch if not equal
	case 0xFD:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->fail = addr + op->size;
		
		// TODO jump code
		break;

	// DBNE, Decrement and branch if not equal
	case 0xAC:
	case 0x7B:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->fail = addr + op->size;
		
		// TODO jump code
		break;

	// JMP
	case 0x1B:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		
		// TODO jump code
		break;

	// JMP [mem]
	case 0x1F:
	case 0x3F:
		op->type = R_ANAL_OP_TYPE_UJMP; // unknown jump
		op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		
		// TODO jump code
		break;

	// PCALL
	case 0x1F:
	case 0x3F:
		op->type = R_ANAL_OP_TYPE_UCALL; // Change if able to determine how to read P call address
		//op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 2;
		
		// TODO jump code
		break;

	// TCALL
	case 0x1F:
	case 0x3F:
		op->type = R_ANAL_OP_TYPE_UCALL; // Change if able to determine how to read T call address
		//op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 2;
		
		// TODO jump code
		break;

	// BRK
	case 0x0F:
		op->type = R_ANAL_OP_TYPE_SWI; // Change if able to determine how to read from BRK vector
		//op->jump = rel_jmp_addr(addr + op->size, data[op->size - 1]);
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 2;
		
		// TODO jump code
		break;

	// DI
	case 0x60:
		op->type = R_ANAL_OP_TYPE_STORE: // Should these be NOPs
		
		r_strbuf_set (&op->esil, "0, i, ="); 
		break;

	// EI
	case 0xE0:
		op->type = R_ANAL_OP_TYPE_STORE:
		
		r_strbuf_set (&op->esil, "1, i, ="); 
		break;

	// NOP
	case 0xFF:
		op->type = R_ANAL_OP_TYPE_NOP:
		
		r_strbuf_set (&op->esil, "1, i, ="); 
		break;

	// POP
	case 0x0D:
		op->type = R_ANAL_OP_TYPE_POP;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -1;

		// TODO pop command
		break;

	case 0x2D:
		op->type = R_ANAL_OP_TYPE_POP;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -1;

		// TODO pop command
		break;

	case 0x4D:
		op->type = R_ANAL_OP_TYPE_POP;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -1;

		// TODO pop command
		break;

	case 0x6D:
		op->type = R_ANAL_OP_TYPE_POP;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -1;

		// TODO pop command
		break;

	// PUSH
	case 0x0E:
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 1;

		// TODO push command
		break;

	case 0x2E:
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 1;

		// TODO push command
		break;

	case 0x4E:
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 1;

		// TODO push command
		break;

	case 0x6E:
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 1;

		// TODO push command
		break;

	// RET
	case 0x6F:
		op->type = R_ANAL_OP_TYPE_RET;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -2;

		// TODO ret command
		break;

	// RETI
	case 0x7F:
		op->type = R_ANAL_OP_TYPE_RET; // TODO is there a return from interrupt
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -2;

		// TODO ret command
		break;

	// STOP
	case 0xEF:
		op->type = R_ANAL_OP_TYPE_NOP; // TODO is there a STOP
		break;
	}
	return op->size;
}

static int esil_MC81F4204_fini (RAnalEsil *esil) {
	return true;
}

RAnalPlugin r_anal_plugin_MC81F4204 = {
	.name = "MC81F4204",
	.desc = "MC81F4204 G810 Core analysis plugin",
	.license = "",
	.arch = "MC81F4204",
	.bits = 8,
	.op = &_MC81F4204_op,
	.set_reg_profile = &set_reg_profile,
	.esil = false, // change to true once all commands are complete
	//.esil_init = esil_6502_init,
	//.esil_fini = esil_6502_fini,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_MC81F4204,
	.version = R2_VERSION
};
