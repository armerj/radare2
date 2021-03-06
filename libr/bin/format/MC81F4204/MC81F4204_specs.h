#ifndef _MC81F4204_H
#define _MC81F4204_H

#define	ROM_SIZE	0x1000
#define	ROM_START_ADDRESS	0xF000

#define	RAM_START_ADDRESS	0x0000
#define	RAM_SIZE	0x010F

#define	RESET_VECTOR_ADDRESS_PHYSICAL	0x0FFE
#define MC81F4204_MAGIC "\x60\x1e\x00"


typedef struct {
	char* name;
	ut16 addr;
	ut16 size;
} _MC81F4204_symbol;

static _MC81F4204_symbol _MC81F4204_symbols_table[] = {
	{"RESET_VECTOR_START_ADDRESS", 0xFFFE, 2},
	{"IRQ_VECTOR_START_ADDRESS", 0xFFE0, 2},
	{"PCALL_START_ADDRESS", 0xFF00, 2},
	{"TCALL_0_ADDRESS", 0xFFDE, 2},
	{"TCALL_1_ADDRESS", 0xFFDC, 2},
	{"TCALL_2_ADDRESS", 0xFFDA, 2},
	{"TCALL_3_ADDRESS", 0xFFD8, 2},
	{"TCALL_4_ADDRESS", 0xFFD6, 2},
	{"TCALL_5_ADDRESS", 0xFFD4, 2},
	{"TCALL_6_ADDRESS", 0xFFD2, 2},
	{"TCALL_7_ADDRESS", 0xFFD0, 2},
	{"TCALL_8_ADDRESS", 0xFFCE, 2},
	{"TCALL_9_ADDRESS", 0xFFCC, 2},
	{"TCALL_10_ADDRESS", 0xFFCA, 2},
	{"TCALL_11_ADDRESS", 0xFFC8, 2},
	{"TCALL_12_ADDRESS", 0xFFC6, 2},
	{"TCALL_13_ADDRESS", 0xFFC4, 2},
	{"TCALL_14_ADDRESS", 0xFFC2, 2},
	{"TCALL_15_ADDRESS", 0xFFC0, 2}
};

typedef struct {
	char* name;
	ut16 paddr;
	ut16 size;
	ut16 vaddr;
	ut16 vsize;
} _MC81F4204_section;

static _MC81F4204_section _MC81F4204_sections_table[] = {
	{"ROM", 0x0, 0x0EFF, 0xF000, 0x0EFF},
	{"PCALL_TABLE", 0x0F00, 0xC0, 0xFF00, 0xC0},
	{"TCALL_TABLE", 0x0FC0, 0x20, 0xFFC0, 0x20},
	{"INTERRUPTS", 0x0FE0, 0x20, 0xFFE0, 0x20}
};

#endif
