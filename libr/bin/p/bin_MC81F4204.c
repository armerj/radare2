/* https://github.com/radare/radare2/blob/master/libr/bin/p/bin_nes.c as example */

#include <r_bin.h>
#include <r_lib.h>
#include "MC81F4204/MC81F4204_specs.h"

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = NULL;
	
	ret->file = strdup (bf->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("MC81F4204 Firmware");
	ret->arch = strdup ("MC81F4204");
	ret->bits = 8;
	ret->has_va = 1;
	return ret;
}

static void addsym(RList *ret, MC81F4204_symbol *symbol) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	if (!ptr) {
		return;
	}
	ptr->name = symbol->name;
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = size;
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
}

static RList* symbols(RBinFile *bf) { // make array and loop
	RList *ret = NULL;
	RBinSymbol *ptr;
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}

	for (ut8 i = 0; i <= 18; i++) {
		if (!(ptr = R_NEW0 (RBinSymbol))) {
			return ret;
		}

		ptr->name = MC81F4204_symbols_table[i]->name;
		ptr->paddr = ptr->vaddr = MC81F4204_symbols_table[i]->addr;
		ptr->size = MC81F4204_symbols_table[i]->size;
	}

	// TODO read beginning of firmware (Should we assume reset is 0xF000?), look for jump to main

	// addsym (ret, "MAIN", , 2);

	return ret;
}



static RList* sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	ines_hdr ihdr;
	memset (&ihdr, 0, INES_HDR_SIZE);
	
	if (!(ret = r_list_new ())) {
		return NULL;
	}


	for (ut8 i = 0; i <= 3; i++) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}

		ptr->name = MC81F4204_sections_table[i]->name;
		ptr->paddr = ptr->vaddr = MC81F4204_sections_table[i]->paddr;
		ptr->size = MC81F4204_sections_table[i]->size;
		ptr->vaddr = ptr->vaddr = MC81F4204_sections_table[i]->vaddr;
		ptr->vsize = MC81F4204_sections_table[i]->vsize;
		ptr->perm = R_PERM_RX;
		ptr->add = true;
		r_list_append (ret, ptr);
	}

	// read beginning of firmware, 
	// determine location of data and user code
	// create reset code section
	// create code section
	// create data section

	return ret;
}

static RList *mem(RBinFile *bf) {
	RList *ret;
	RBinMem *m, *n;

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;

	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}

	m->name = strdup ("RAM"); // Should probably split between, RAM lower, PPU, and upper
	m->addr = RAM_START_ADDRESS;
	m->size = RAM_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	return ret;
}

static RList* entries(RBinFile *bf) { 
	RList *ret;
	RBinAddr *ptr = NULL;
	ut16 *start_addr;
	memset (&start_addr, 0, 2);

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	if (!(ptr = R_NEW0 (RBinAddr))) {
		return ret;
	}

	r_buf_read_at (bf->buf, RESET_VECTOR_ADDRESS, &start_addr,2); // boot up code, may not necessarily be user code
	ptr->vaddr = (start_addr[1] << 8) | start_addr[0];
	ptr->paddr = ptr->vaddr - 0xF000;
	ptr->vaddr = start_addr;
	r_list_append (ret, ptr);
	return ret;
}

static ut64 baddr(RBinFile *bf) {
	// having this we make r2 -B work, otherwise it doesnt works :??
	return 0;
}

RBinPlugin r_bin_plugin_nes = {
	.name = "MC81F4204",
	.desc = "MC81F4204 firmware format",
	.license = "",
	.baddr = &baddr,
	.entries = &entries,
	.sections = sections,
	.symbols = &symbols,
	.info = &info,
	.mem = &mem,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_MC81F4204,
	.version = R2_VERSION
};
#endif