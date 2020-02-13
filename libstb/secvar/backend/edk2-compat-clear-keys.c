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

int reset_keystore(void)
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

//	node = find_secvar("TS", 3, &variable_bank);
//	update_variable_in_bank(node->var, NULL, 0);

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

int add_hw_key_hash(void)
{
	struct secvar_node *node;
	uint32_t hw_key_hash_size;
	const char *hw_key_hash;
	struct dt_node *secureboot;

	secureboot = dt_find_by_path(dt_root, "ibm,secureboot");
	if (!secureboot)
		return false;

	hw_key_hash_size = dt_prop_get_u32(secureboot, "hw-key-hash-size");

	hw_key_hash = dt_prop_get(secureboot, "hw-key-hash");

	if (!hw_key_hash)
		return OPAL_PERMISSION;

	node = new_secvar("HWKH", 5, hw_key_hash,
			hw_key_hash_size, SECVAR_FLAG_PRIORITY);
	list_add_tail(&variable_bank, &node->link);

	return OPAL_SUCCESS;
}

int delete_hw_key_hash(void)
{
	struct secvar_node *node;
	int rc;

	node = find_secvar("HWKH", 5, &variable_bank);
	if (!node)
		return OPAL_SUCCESS;

	rc = update_variable_in_bank(node->var, NULL, 0);
	return rc;
}

int verify_hw_key_hash(void)
{
	const char *hw_key_hash;
	struct dt_node *secureboot;
	struct secvar_node *node;

	secureboot = dt_find_by_path(dt_root, "ibm,secureboot");
	if (!secureboot)
		return OPAL_INTERNAL_ERROR;

	hw_key_hash = dt_prop_get(secureboot, "hw-key-hash");

	if (!hw_key_hash)
		return OPAL_INTERNAL_ERROR;

	/* This value is from the protected storage */
	node = find_secvar("HWKH", 5, &variable_bank);
	if (!node)
		return OPAL_PERMISSION;

	if (memcmp(hw_key_hash, node->var->data, node->var->data_size) != 0)
		return OPAL_PERMISSION;

	return OPAL_SUCCESS;
}

