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


static int esil_MC81F4204_fini (RAnalEsil *esil) {
	return true;
}


RAnalPlugin r_anal_plugin_MC81F4204 = {
	.name = "MC81F4204",
	.desc = "ABOV MC81F4204",
	.license = "",
	.arch = "MC81F4204",
	.bits = 8,
	.op = &_MC81F4204_op,
	.set_reg_profile = &set_reg_profile,
	.esil = true,
	.esil_init = esil_MC81F4204_init,
	.esil_fini = esil_MC81F4204_fini,
};


#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_MC81F4204,
	.version = R2_VERSION
};
#endif


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

// from https://github.com/radare/radare2/blob/master/libr/anal/p/anal_6502.c
enum {  // TODO need H, and V
	_6502_FLAGS_C = (1 << 0),
	_6502_FLAGS_B = (1 << 1),
	_6502_FLAGS_Z = (1 << 2),
	_6502_FLAGS_N = (1 << 3),

	_6502_FLAGS_NZ = (_6502_FLAGS_Z | _6502_FLAGS_N),
	_6502_FLAGS_CNZ = (_6502_FLAGS_C | _6502_FLAGS_Z | _6502_FLAGS_N),
	_6502_FLAGS_BNZ = (_6502_FLAGS_B | _6502_FLAGS_Z | _6502_FLAGS_N),
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

	

}













