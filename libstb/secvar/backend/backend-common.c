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
#include "backend-common.h"
#include "../secvar.h"

bool setup_mode;

int add_to_variable_bank(struct secvar *secvar, const char *data, uint64_t dsize)
{
	struct secvar_node *node;

	node = find_secvar(secvar->key, secvar->key_len, &variable_bank);
	if (!node)
		return OPAL_INTERNAL_ERROR;

	/* Reallocate the data memory, if there is change in data size */
	if (node->size < dsize)
		if (realloc_secvar(node, dsize))
			return OPAL_NO_MEM;

	if (dsize && data)
		memcpy(node->var->data, data, dsize);
	node->var->data_size = dsize;

	/* Clear the volatile bit only if updated with positive data size */
	if (dsize)
		node->flags &= ~SECVAR_FLAG_VOLATILE;

	/* Is it required to be set everytime ? */
	if ((!strncmp(secvar->key, "PK", 3))
		node->flags |= SECVAR_FLAG_PRIORITY;

	return 0;
}

int clear_all_os_keys(void)
{
        struct secvar_node *node;

        node = find_secvar("PK", 3, &variable_bank);
        add_to_variable_bank(node->var, NULL, 0);

        node = find_secvar("KEK", 4, &variable_bank);
        add_to_variable_bank(node->var, NULL, 0);

        node = find_secvar("db", 3, &variable_bank);
        add_to_variable_bank(node->var, NULL, 0);

        node = find_secvar("dbx", 4, &variable_bank);
        add_to_variable_bank(node->var, NULL, 0);

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
