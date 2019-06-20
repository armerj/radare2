/* https://github.com/radare/radare2/blob/master/libr/bin/p/bin_nes.c as example */

#include <r_bin.h>
#include <r_lib.h>
#include "MC81F4204/MC81F4204_specs.h"


// **** copy
static bool check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || length < 3) {
		return false;
	}
	return (!memcmp (buf, MC81F4204_MAGIC, 3)); // maybe we should put both
}

static bool load_bytes(RBinFile *bf, void **bin_obj, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	return check_bytes (buf, sz);
}

static void *load_buffer(RBinFile *bf, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	ut64 tmpsz;
	const ut8 *tmp = r_buf_data (buf, &tmpsz);
	if (!check_bytes (tmp, tmpsz)) {
		return NULL;
	}
	return r_buf_new ();
}
// ****


static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = NULL;

    if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	
	ret->file = strdup (bf->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("MC81F4204 Firmware");
	ret->arch = strdup ("MC81F4204");
	ret->bits = 8;
	ret->has_va = 1;
	return ret;
}

static RList* symbols(RBinFile *bf) { // make array and loop
	RList *ret = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}

	for (ut8 i = 0; i <= 18; i++) {
	    RBinSymbol *ptr = NULL;
		if (!(ptr = R_NEW0 (RBinSymbol))) {
			return ret;
		}

		ptr->name = r_str_new(_MC81F4204_symbols_table[i].name);
		ptr->paddr = _MC81F4204_symbols_table[i].addr - 0xF000;
        ptr->vaddr = _MC81F4204_symbols_table[i].addr;
		ptr->size = _MC81F4204_symbols_table[i].size;

		r_list_append (ret, ptr);
	}

	// TODO read beginning of firmware (Should we assume reset is 0xF000?), look for jump to main

	// addsym (ret, "MAIN", , 2);

	return ret;
}



static RList* sections(RBinFile *bf) {
	RList *ret = NULL;
	
	if (!(ret = r_list_new ())) {
		return NULL;
	}


	for (ut8 i = 0; i <= 3; i++) {
	    RBinSection *ptr = NULL;
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}

		ptr->name = r_str_new(_MC81F4204_sections_table[i].name);
		ptr->paddr = _MC81F4204_sections_table[i].paddr;
		ptr->size = _MC81F4204_sections_table[i].size;
		ptr->vaddr = _MC81F4204_sections_table[i].vaddr;
		ptr->vsize = _MC81F4204_sections_table[i].vsize;
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
	RBinMem *m;

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
	ut16 start_addr;
	memset (&start_addr, 0, 2);

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	if (!(ptr = R_NEW0 (RBinAddr))) {
		return ret;
	}

	r_buf_read_at (bf->buf, RESET_VECTOR_ADDRESS_PHYSICAL, (ut8*)&start_addr,2); // boot up code, may not necessarily be user code
	ptr->vaddr = start_addr;
	ptr->paddr = start_addr - 0xF000;
	r_list_append (ret, ptr);

	return ret;
}

static ut64 baddr(RBinFile *bf) {
	// having this we make r2 -B work, otherwise it doesnt works :??
	return 0;
}

RBinPlugin r_bin_plugin_MC81F4204 = {
	.name = "MC81F4204",
	.desc = "MC81F4204 firmware format",
	.license = "",
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.load_bytes = &load_bytes,
	.load_buffer = &load_buffer,
	.check_bytes = &check_bytes,
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
