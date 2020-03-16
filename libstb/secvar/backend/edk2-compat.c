// SPDX-License-Identifier: Apache-2.0
/* Copyright 2019 IBM Corp. */
#ifndef pr_fmt
#define pr_fmt(fmt) "EDK2_COMPAT: " fmt
#endif

#include <opal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <skiboot.h>
#include <ccan/endian/endian.h>
#include <mbedtls/error.h>
#include "libstb/crypto/pkcs7/pkcs7.h"
#include "edk2.h"
#include "../secvar.h"
#include "edk2-compat-process.h"
#include "edk2-compat-reset.h"

struct list_head staging_bank;

/*
 * Initializes supported variables as empty if not loaded from
 * storage. Variables are initialized as volatile if not found.
 * Updates should clear this flag.
 * Returns OPAL Error if anything fails in initialization
 */
static int edk2_compat_pre_process(void)
{
	struct secvar_node *pkvar;
	struct secvar_node *kekvar;
	struct secvar_node *dbvar;
	struct secvar_node *dbxvar;
	struct secvar_node *tsvar;

	pkvar = find_secvar("PK", 3, &variable_bank);
	if (!pkvar) {
		pkvar = new_secvar("PK", 3, NULL, 0, SECVAR_FLAG_VOLATILE
				| SECVAR_FLAG_PRIORITY);
		if (!pkvar)
			return OPAL_NO_MEM;

		list_add_tail(&variable_bank, &pkvar->link);
	}
	if (pkvar->var->data_size == 0)
		setup_mode = true;
	else
		setup_mode = false;

	kekvar = find_secvar("KEK", 4, &variable_bank);
	if (!kekvar) {
		kekvar = new_secvar("KEK", 4, NULL, 0, SECVAR_FLAG_VOLATILE);
		if (!kekvar)
			return OPAL_NO_MEM;

		list_add_tail(&variable_bank, &kekvar->link);
	}

	dbvar = find_secvar("db", 3, &variable_bank);
	if (!dbvar) {
		dbvar = new_secvar("db", 3, NULL, 0, SECVAR_FLAG_VOLATILE);
		if (!dbvar)
			return OPAL_NO_MEM;

		list_add_tail(&variable_bank, &dbvar->link);
	}

	dbxvar = find_secvar("dbx", 4, &variable_bank);
	if (!dbxvar) {
		dbxvar = new_secvar("dbx", 4, NULL, 0, SECVAR_FLAG_VOLATILE);
		if (!dbxvar)
			return OPAL_NO_MEM;

		list_add_tail(&variable_bank, &dbxvar->link);
	}

	/* Should only ever happen on first boot */
	tsvar = find_secvar("TS", 3, &variable_bank);
	if (!tsvar) {
		tsvar = alloc_secvar(sizeof(struct efi_time) * 4);
		if (!tsvar)
			return OPAL_NO_MEM;

		memcpy(tsvar->var->key, "TS", 3);
		tsvar->var->key_len = 3;
		tsvar->var->data_size = sizeof(struct efi_time) * 4;
		memset(tsvar->var->data, 0, tsvar->var->data_size);
		list_add_tail(&variable_bank, &tsvar->link);
	}

	return OPAL_SUCCESS;
};

static int edk2_compat_process(void)
{
	struct secvar_node *node = NULL;
	struct secvar_node *tmp = NULL;
	struct efi_time timestamp;
	char *newesl = NULL;
	int neweslsize;
	int rc = 0;

	prlog(PR_INFO, "Setup mode = %d\n", setup_mode);

	/* Check if physical presence is asserted */
	if (is_physical_presence_asserted()) {
		prlog(PR_INFO, "Physical presence asserted to clear OS Secure boot keys\n");
		rc = reset_keystore();
		if (rc)
			goto cleanup;
		setup_mode = true;
		goto cleanup;
	}

	/* Check HW-KEY-HASH */
	if (!setup_mode) {
		rc = verify_hw_key_hash();
		if (rc != OPAL_SUCCESS) {
			rc = reset_keystore();
			if (rc)
				goto cleanup;
			setup_mode = true;
			goto cleanup;
		}
	}

	/* Return early if we have no updates to process */
	if (list_empty(&update_bank)) {
		return OPAL_EMPTY;
	}

	/* Perform a deep copy of the active bank to perform changes on.
	 * Swap them at then end if processing succeeds */
	list_head_init(&staging_bank);

	/* Loop through each command in the update bank.
	 * If any command fails, it just loops out of the update bank.
	 * It should also clear the update bank.
	 */
	list_for_each(&update_bank, node, link) {

		/* Submitted data is auth_2 descriptor + new ESL data
		 * Extract the auth_2 2 descriptor
		 */
		prlog(PR_INFO, "update for %s\n", node->var->key);

		rc = process_update(node, &newesl, &neweslsize, &timestamp);
		if (rc)
			break;

		/*
		 * If reached here means, signature is verified so update the
		 * value in the variable bank
		 */
		rc = update_variable_in_bank(node->var, newesl, neweslsize);
		if (rc)
			break;

		free(newesl);
		/* Update the TS variable with the new timestamp */
		rc = update_timestamp(node->var->key, &timestamp);
		if (rc)
			break;

		/* If the PK is updated, update the secure boot state of the
		 * system at the end of processing */
		if (key_equals(node->var->key, "PK")) {
			if(neweslsize == 0)
				setup_mode = true;
			else 
				setup_mode = false;
			prlog(PR_DEBUG, "setup mode is %d\n", setup_mode);
		}
	}

	if (rc == 0) {
		list_for_each(&staging_bank, node, link) {
			tmp = find_secvar(node->var->key, node->var->key_len, &variable_bank);
			if (tmp->var->data_size < node->var->data_size)
				if (realloc_secvar(tmp, node->var->data_size))
					return OPAL_NO_MEM;

			if (node->var->data_size && node->var->data)
				memcpy(tmp->var->data, node->var->data, node->var->data_size);

			tmp->var->data_size = node->var->data_size;
			tmp->flags = node->flags;
        	}
	}

cleanup:
	/* For any failure in processing update queue, we clear the update bank
	 * and return failure */
	clear_bank_list(&update_bank);

	return rc;
}

static int edk2_compat_post_process(void)
{
	struct secvar_node *hwvar;
	if (!setup_mode) {
		secvar_set_secure_mode();
		prlog(PR_INFO, "Enforcing OS secure mode\n");
		/* HW KEY HASH is no more needed after this point. It is already
		 * visible to userspace via device-tree, so exposing via sysfs is
		 * just a duplication. Remove it from in-memory copy. */
		hwvar = find_secvar("HWKH", 5, &variable_bank);
		if (!hwvar)
			return OPAL_INTERNAL_ERROR;
		list_del(&hwvar->link);
		dealloc_secvar(hwvar);
	}

	return OPAL_SUCCESS;
}

static int edk2_compat_validate(struct secvar *var)
{

	/* Checks if the update is for supported
	 * Non-volatile secure variables */
	if (!key_equals(var->key, "PK")
			&& !key_equals(var->key, "KEK")
			&& !key_equals(var->key, "db")
			&& !key_equals(var->key, "dbx"))
		return OPAL_PARAMETER;

	/* Check that signature type is PKCS7 */
	if (!is_pkcs7_sig_format(var->data))
		return OPAL_PARAMETER;

	return OPAL_SUCCESS;
};

struct secvar_backend_driver edk2_compatible_v1 = {
	.pre_process = edk2_compat_pre_process,
	.process = edk2_compat_process,
	.post_process = edk2_compat_post_process,
	.validate = edk2_compat_validate,
	.compatible = "ibm,edk2-compat-v1",
};
