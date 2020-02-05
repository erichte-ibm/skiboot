// SPDX-License-Identifier: Apache-2.0
/* Copyright 2019 IBM Corp. */
#ifndef pr_fmt
#define pr_fmt(fmt) "SECBOOT_TPM: " fmt
#endif

#include <stdlib.h>
#include <skiboot.h>
#include <opal.h>
#include <mbedtls/sha256.h>
#include "../secvar.h"
#include "secboot_tpm.h"
#include <tssskiboot.h>
#include <ibmtss/TPM_Types.h>

#define CYCLE_BIT(b) (b^0x1)

// Because mbedtls doesn't define this?
#define SHA256_DIGEST_LENGTH	32

#define SECBOOT_TPM_MAX_VAR_SIZE	8192

struct secboot *secboot_image = NULL;
struct tpmnv *tpmnv_image = NULL;

extern struct tpmnv_ops_s tpmnv_ops;

const size_t tpmnv_size = 1024;

static void calc_bank_hash(char *target_hash, char *source_buf, uint64_t size)
{
	mbedtls_sha256_context ctx;

	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_update_ret(&ctx, source_buf, size);
	mbedtls_sha256_finish_ret(&ctx, target_hash);
}

/* Reformat the TPMNV space */
static int tpmnv_format(void)
{
	memset(tpmnv_image, 0x00, tpmnv_size);

	tpmnv_image->header.magic_number = SECBOOT_MAGIC_NUMBER;
	tpmnv_image->header.magic_number = SECBOOT_VERSION;

	/* Counts as first write to the TPM NV, as required by fresh NV indices */
	return tpmnv_ops.write(SECBOOT_TPMNV_INDEX, tpmnv_image, tpmnv_size, 0);
}

/* Reformat the secboot PNOR space */
static int secboot_format(void)
{
	int rc;

	if (!platform.secboot_write)
		return OPAL_UNSUPPORTED;

	memset(secboot_image, 0x00, sizeof(struct secboot));

	secboot_image->header.magic_number = SECBOOT_MAGIC_NUMBER;
	secboot_image->header.version = SECBOOT_VERSION;

	/* Write the hash of the empty bank to the tpm so loads work in the future */
	calc_bank_hash(tpmnv_image->bank_hash[0], secboot_image->bank[0], SECBOOT_VARIABLE_BANK_SIZE);
	rc = tpmnv_ops.write(SECBOOT_TPMNV_INDEX, tpmnv_image->bank_hash[0], SHA256_DIGEST_SIZE, offsetof(struct tpmnv, bank_hash[0]));

	if (rc)
		return rc;

	return platform.secboot_write(0, secboot_image, sizeof(struct secboot));
}

/* Flattens a linked-list bank into a contiguous buffer for writing */
static int secboot_serialize_bank(struct list_head *bank, char *target, size_t target_size, int flags)
{
	struct secvar_node *node;
	char *tmp = target;
	int complete_priority = 0;

	if (!bank)
		return OPAL_INTERNAL_ERROR;
	if (!target)
		return OPAL_INTERNAL_ERROR;

	list_for_each(bank, node, link) {
		if (node->flags != flags)
			continue;

		/* Bail early if we are out of storage space */
		if ((target - tmp) + sizeof(struct secvar) + node->var->data_size > target_size) {
			return OPAL_EMPTY;
		}

		/* We only have space for one priority variable in TPMNV space,
		 *  so accept the first one, and bail if we attempt to continue looping. */
		if (complete_priority) {
			prlog(PR_ERR, "This driver only supports one priority variable, and more than one was given.");
			return OPAL_INTERNAL_ERROR;
		}

		/* Priority variable is packs the key tightly to save space */
		if (flags == SECVAR_FLAG_PRIORITY) {
			memcpy(target, &node->var->key_len, sizeof(node->var->key_len));
			target += sizeof(node->var->key_len);
			memcpy(target, &node->var->data_size, sizeof(node->var->data_size));
			target += sizeof(node->var->data_size);
			memcpy(target, node->var->key, node->var->key_len);
			target += node->var->key_len;
			memcpy(target, node->var->data, node->var->data_size);

			complete_priority = 1;
			continue;
		}

		memcpy(target, node->var, sizeof(struct secvar) + node->var->data_size);

		target += sizeof(struct secvar) + node->var->data_size;
	}

	return OPAL_SUCCESS;
}


static int secboot_load_from_pnor(struct list_head *bank, char *source, size_t max_size)
{
	char *src;
	struct secvar_node *tmp;
	struct secvar *hdr;

	src = source;

	while (src < (source + max_size)) {
		/* Load in the header first to get the size, and check if we are at the end */
		/* Banks are zeroized after each write, thus key_len == 0 indicates end of the list */
		hdr = (struct secvar *) src;
		if (hdr->key_len == 0) {
			break;
		}
		else if (hdr->key_len > SECVAR_MAX_KEY_LEN) {
			prlog(PR_ERR, "Attempted to load a key larger than max, len = %llu\n", hdr->key_len);
			return OPAL_INTERNAL_ERROR;
		}

		if (hdr->data_size > SECBOOT_TPM_MAX_VAR_SIZE) {
			prlog(PR_ERR, "Attempted to load a data payload larger than max, "
				      "size = %llu\n", hdr->data_size);
			return OPAL_INTERNAL_ERROR;
		}

		tmp = alloc_secvar(hdr->data_size);
		if (!tmp) {
			prlog(PR_ERR, "Could not allocate memory for loading secvar from image\n");
			return OPAL_NO_MEM;
		}

		memcpy(tmp->var, src, sizeof(struct secvar) + hdr->data_size);

		list_add_tail(bank, &tmp->link);
		src += sizeof(struct secvar) + hdr->data_size;
	}

	return OPAL_SUCCESS;
}


/* Helper for the variable-bank specific writing logic */
static int secboot_tpm_write_variable_bank(struct list_head *bank)
{
	int rc;
	uint64_t bit;

	bit = CYCLE_BIT(tpmnv_image->active_bit);
	// TODO: Write better offset calculation
	rc = secboot_serialize_bank(bank, tpmnv_image->priority_var, tpmnv_size - offsetof(struct tpmnv, priority_var), SECVAR_FLAG_PRIORITY);
	if (rc)
		goto out;

	rc = tpmnv_ops.write(SECBOOT_TPMNV_INDEX, tpmnv_image->priority_var, tpmnv_size - offsetof(struct tpmnv, priority_var), offsetof(struct tpmnv, priority_var));

	/* Calculate the bank hash, and write to TPM NV */
	rc = secboot_serialize_bank(bank, secboot_image->bank[bit], SECBOOT_VARIABLE_BANK_SIZE, 0);
	if (rc)
		goto out;

	calc_bank_hash(tpmnv_image->bank_hash[bit], secboot_image->bank[bit], SECBOOT_VARIABLE_BANK_SIZE);
	// TODO: write an auto-offset calculator
	rc = tpmnv_ops.write(SECBOOT_TPMNV_INDEX, tpmnv_image->bank_hash[bit], SHA256_DIGEST_LENGTH, ((char *) &tpmnv_image->bank_hash[bit] - (char *) tpmnv_image));
	if (rc)
		goto out;

	/* Write new variable bank to pnor */
	rc = platform.secboot_write(0, secboot_image, sizeof(struct secboot));
	if (rc)
		goto out;

	/* Flip the bit, and write to TPM NV */
	tpmnv_image->active_bit = bit;
	rc = tpmnv_ops.write(SECBOOT_TPMNV_INDEX, &tpmnv_image->active_bit, sizeof(tpmnv_image->active_bit), offsetof(struct tpmnv, active_bit));
out:

	return rc;
}

static int secboot_tpm_write_bank(struct list_head *bank, int section)
{
	int rc;

	switch(section) {
		case SECVAR_VARIABLE_BANK:
			rc = secboot_tpm_write_variable_bank(bank);
			break;
		case SECVAR_UPDATE_BANK:
			memset(secboot_image->update, 0, SECBOOT_UPDATE_BANK_SIZE);
			rc = secboot_serialize_bank(bank, secboot_image->update, SECBOOT_UPDATE_BANK_SIZE, 0);
			if (rc)
				break;

			rc = platform.secboot_write(0, secboot_image, sizeof(struct secboot));
			break;
		default:
			rc = OPAL_HARDWARE;
	}

	return rc;
}


static int secboot_tpm_load_variable_bank(struct list_head *bank)
{
	char bank_hash[SHA256_DIGEST_LENGTH];
	uint64_t bit = tpmnv_image->active_bit;
	struct secvar *tmp;
	struct secvar_node *node;

	/* Check the hash of the bank we loaded from PNOR versus the expected hash in TPM NV */
	calc_bank_hash(bank_hash, secboot_image->bank[bit], SECBOOT_VARIABLE_BANK_SIZE);
	if (memcmp(bank_hash, tpmnv_image->bank_hash[bit], SHA256_DIGEST_LENGTH))
		return OPAL_PERMISSION; /* Tampered pnor space detected, abandon ship */

	/* Temporary cast to check sizes */
	tmp = (struct secvar *) tpmnv_image->priority_var;
	/* Sanity check our potential priority variable */
	/* Should be zeroes if nonexistent */
	if ((tmp->key_len > SECVAR_MAX_KEY_LEN)
	     || (tmp->data_size > SECBOOT_TPM_MAX_VAR_SIZE)) {
		prlog(PR_ERR, "TPM NV Priority variable has impossible sizes, probably internal bug. "
			      "len = %llu, size = %llu\n", tmp->key_len, tmp->data_size);
		return OPAL_INTERNAL_ERROR;
	}
	/* Check if we have a priority variable to load */
	if (tmp->key_len != 0) {
		node = alloc_secvar(tmp->data_size);
		if (!node)
			return OPAL_NO_MEM;

		node->var->key_len = tmp->key_len;
		node->var->data_size = tmp->data_size;
		node->flags |= SECVAR_FLAG_PRIORITY;

		memcpy(node->var->key, tpmnv_image->priority_var + offsetof(struct secvar, key), tmp->key_len);
		memcpy(node->var->data, tpmnv_image->priority_var + offsetof(struct secvar, key) + tmp->key_len, tmp->data_size);

		list_add_tail(bank, &node->link);
	}

	return secboot_load_from_pnor(bank, secboot_image->bank[bit], SECBOOT_VARIABLE_BANK_SIZE);
}


static int secboot_tpm_load_bank(struct list_head *bank, int section)
{
	switch(section) {
		case SECVAR_VARIABLE_BANK:
			return secboot_tpm_load_variable_bank(bank);
		case SECVAR_UPDATE_BANK:
			return secboot_load_from_pnor(bank, secboot_image->update, SECBOOT_UPDATE_BANK_SIZE);
		default:
			return OPAL_HARDWARE;
	}

	return OPAL_HARDWARE;
}


static int secboot_tpm_store_init(void)
{
	int rc;
	unsigned secboot_size;
	int tpm_first_init = 0;

	if (secboot_image)
		return OPAL_SUCCESS;

	if (!platform.secboot_info)
		return OPAL_UNSUPPORTED;

	prlog(PR_DEBUG, "Initializing for pnor+tpm based platform\n");

	tpmnv_image = zalloc(tpmnv_size);
	if (!tpmnv_image)
		return OPAL_NO_MEM;

	/* Read from the TPM NV index, define it if it doesn't exist */
	rc = tpmnv_ops.read(SECBOOT_TPMNV_INDEX, tpmnv_image, tpmnv_size, 0);
	if (rc == TPM_RC_NV_UNINITIALIZED) {
		rc = tpmnv_ops.definespace(SECBOOT_TPMNV_INDEX, 'p', 'p', tpmnv_size);
		if (rc)

		/* Defining the index invokes a full reformat */
		tpm_first_init = 1;
	}
	else if (rc) {
		return rc;
	}

	/* Trigger a reformat if for some reason the NV index was cleared */
	if (tpmnv_image->header.magic_number != SECBOOT_MAGIC_NUMBER) {
		tpm_first_init = 1;
	}

	rc = platform.secboot_info(&secboot_size);
	if (rc) {
		prlog(PR_ERR, "error %d retrieving keystore info\n", rc);
		goto error;
	}
	if (sizeof(struct secboot) > secboot_size) {
		prlog(PR_ERR, "secboot partition %d KB too small. min=%ld\n",
		      secboot_size >> 10, sizeof(struct secboot));
		rc = OPAL_RESOURCE;
		goto error;
	}

	secboot_image = memalign(0x1000, sizeof(struct secboot));
	if (!secboot_image) {
		prlog(PR_ERR, "Failed to allocate space for the secboot image\n");
		free(tpmnv_image);
		rc = OPAL_NO_MEM;
		goto error;
	}

	/* Read in the PNOR data, bank hash is checked on call to .load_bank() */
	rc = platform.secboot_read(secboot_image, 0, sizeof(struct secboot));
	if (rc) {
		prlog(PR_ERR, "failed to read the secboot partition, rc=%d\n", rc);
		goto error;
	}

	if (tpm_first_init) {
		prlog(PR_INFO, "Initializing and formatting TPMNV space and SECBOOT partition\n");
		rc = tpmnv_format();
		if (rc)
			goto error;

		rc = secboot_format();
		if (rc)
			goto error;
	}
	/* Determine if we need to reformat just secboot*/
	else if (secboot_image->header.magic_number != SECBOOT_MAGIC_NUMBER) {
		prlog(PR_INFO, "SECBOOT partiton was empty or altered, formatting\n");
		rc = secboot_format();
		if (rc) {
			prlog(PR_ERR, "Failed to format secboot!\n");
			goto error;
		}
	}

	return OPAL_SUCCESS;

error:
	free(secboot_image);
	secboot_image = NULL;
	free(tpmnv_image);
	tpmnv_image = NULL;

	return rc;
}


static void secboot_tpm_lock(void)
{
	// TODO: lock the bank here
}

struct secvar_storage_driver secboot_tpm_driver = {
	.load_bank = secboot_tpm_load_bank,
	.write_bank = secboot_tpm_write_bank,
	.store_init = secboot_tpm_store_init,
	.lock = secboot_tpm_lock,
	.max_var_size = SECBOOT_TPM_MAX_VAR_SIZE,
};
