// SPDX-License-Identifier: Apache-2.0
/* Copyright 2019 IBM Corp. */
#include <opal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <device.h>
#include <ccan/endian/endian.h>
#include <mbedtls/error.h>
#include "edk2-compat-process.h"
#include "edk2-compat-clear-keys.h"
#include "../secvar.h"

int clear_all_os_keys(void)
{
	struct secvar_node *node;

	node = find_secvar("PK", 3, &variable_bank);
	update_variable_in_bank(node->var, NULL, 0);

	node = find_secvar("KEK", 4, &variable_bank);
	update_variable_in_bank(node->var, NULL, 0);

	node = find_secvar("db", 3, &variable_bank);
	update_variable_in_bank(node->var, NULL, 0);

	node = find_secvar("dbx", 4, &variable_bank);
	update_variable_in_bank(node->var, NULL, 0);

	return 0;
}

bool is_physical_presence_asserted(void)
{
	struct dt_node *secureboot;

	secureboot = dt_find_by_path(dt_root, "ibm,secureboot");
	if (!secureboot)
		return false;

	if (dt_find_property(secureboot, "clear-os-keys")
			|| dt_find_property(secureboot, "clear-all-keys")
			|| dt_find_property(secureboot, "clear-mfg-keys"))
		return true;

	return false;
}
