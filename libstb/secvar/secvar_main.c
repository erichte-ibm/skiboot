// SPDX-License-Identifier: Apache-2.0
/* Copyright 2019 IBM Corp. */

#ifndef pr_fmt
#define pr_fmt(fmt) "SECVAR: " fmt
#endif

#include <stdlib.h>
#include <string.h>
#include <skiboot.h>
#include <opal.h>
#include <device.h>
#include "secvar.h"

struct list_head variable_bank;
struct list_head update_bank;

int secvar_enabled = 0;	// Set to 1 if secvar is supported
int secvar_ready = 0;	// Set to 1 when base secvar inits correctly

// To be filled in by platform.secvar_init
struct secvar_storage_driver secvar_storage = {0};
struct secvar_backend_driver secvar_backend = {0};

// TODO: handle this better
struct dt_node *secvar_node;

int probe_secvar(void)
{
	struct dt_node *sb_node;
	struct dt_property *sb_compat;

	if (!platform.secvar_init)
		return 0;

	sb_node = dt_find_by_path(dt_root, "/ibm,secureboot/");
	if (!sb_node)
		return 1;

	// TODO: create if doesn't exist?
	sb_compat = (struct dt_property*) dt_find_property(sb_node, "compatible");
	if (!sb_compat)
		return 2;

	strcpy(sb_compat->prop, "ibm,secureboot-v3");

	return 0;
}

int secvar_set_secure_mode(uint64_t val)
{
	struct dt_property *node;

	if (!secvar_node)
		return -1;

	node = (struct dt_property *) dt_find_property(secvar_node, "secure-mode");
	if (!node)
		return -2;

	memcpy(node->prop, &val, sizeof(uint64_t));

	return 0;
}

static void secvar_init_devnode(void)
{
	struct dt_node *sb_root;

	sb_root = dt_find_by_path(dt_root, "/ibm,secureboot/");

	secvar_node = dt_new(sb_root, "secvar");

	dt_add_property_string(secvar_node, "compatible", secvar_backend.compatible);
	dt_add_property_u64(secvar_node, "secure-mode", 0);
}

static void secvar_set_status(const char *status)
{
	struct dt_property *stat_prop;
	if (!secvar_node)
		return; // Fail boot?

	stat_prop = (struct dt_property *) dt_find_property(secvar_node, "compatible");

	if (stat_prop)
		strcpy(stat_prop->prop, "ibm,secureboot-v3");
	else
		dt_add_property_string(secvar_node, "status", status);
		// Fail boot if not successful?
}

int secvar_main(struct secvar_storage_driver storage_driver,
               struct secvar_backend_driver backend_driver)
{
	int rc = OPAL_UNSUPPORTED;

	secvar_storage = storage_driver;
	secvar_backend = backend_driver;

	secvar_init_devnode();

	secvar_enabled = 1;

	list_head_init(&variable_bank);
	list_head_init(&update_bank);

	rc = secvar_storage.store_init();
	if (rc)
		goto fail;


	rc = secvar_storage.load_bank(&variable_bank, SECVAR_VARIABLE_BANK);
	if (rc)
		goto fail;

	rc = secvar_storage.load_bank(&update_bank, SECVAR_UPDATE_BANK);
	if (rc)
		goto fail;

	// At this point, base secvar is functional. Rest is up to the backend
	secvar_ready = 1;

	if (secvar_backend.pre_process)
		rc = secvar_backend.pre_process();

	// Process is required, error if it doesn't exist
	if (!secvar_backend.process)
		goto out;

	rc = secvar_backend.process();
	if (rc == OPAL_SUCCESS) {
		dt_add_property(secvar_node, "update-status", &rc, sizeof(rc));
		// TODO: Should being unable to write be a secvar/status = "fail"?
		rc = secvar_storage.write_bank(&variable_bank, SECVAR_VARIABLE_BANK);
		if (rc)
			goto out;

		rc = secvar_storage.write_bank(&update_bank, SECVAR_UPDATE_BANK);
		if (rc)
			goto out;
	}
	else
		dt_add_property(secvar_node, "update-status", &rc, sizeof(rc));

	// Last point of possible base secvar failure
	secvar_set_status("okay");

	if (secvar_backend.post_process)
		rc = secvar_backend.post_process();
	if (rc)
		goto out;

	return OPAL_SUCCESS;
fail:
	secvar_set_status("fail");
out:
	printf("Secure Variables Status %04x\n", rc);
	return rc;
}
