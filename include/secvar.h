// SPDX-License-Identifier: Apache-2.0
/* Copyright 2019 IBM Corp. */

#ifndef _SECVAR_DRIVER_
#define _SECVAR_DRIVER_

#include <stdint.h>

struct secvar;

struct secvar_storage_driver {
	int (*load_bank)(struct list_head *bank, int section);
	int (*write_bank)(struct list_head *bank, int section);
	int (*store_init)(void);
	void (*lock)(void);
	uint64_t max_var_size;
};

struct secvar_backend_driver {
	int (*pre_process)(struct list_head *variable_bank,
			   struct list_head *update_bank);   // Perform any pre-processing stuff (e.g. determine secure boot state)
	int (*process)(struct list_head *variable_bank,
		       struct list_head *update_bank);       // Process all updates
	int (*post_process)(struct list_head *variable_bank,
			    struct list_head *update_bank);  // Perform any post-processing stuff (e.g. derive/update variables)
	int (*validate)(struct secvar *var);		     // Validate a single variable, return boolean
	const char *compatible;				     // String to use for compatible in secvar node
};

extern struct secvar_storage_driver secboot_tpm_driver;

int secvar_main(struct secvar_storage_driver, struct secvar_backend_driver);

#endif
