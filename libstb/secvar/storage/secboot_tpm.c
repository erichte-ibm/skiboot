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
struct tpmnv_vars *tpmnv_vars_image = NULL;
struct tpmnv_control *tpmnv_control_image = NULL;

extern struct tpmnv_ops_s tpmnv_ops;

const size_t tpmnv_vars_size = 1024;

/* Calculate a SHA256 hash over the supplied buffer */
static int calc_bank_hash(char *target_hash, char *source_buf, uint64_t size)
{
	mbedtls_sha256_context ctx;
	int rc;

	mbedtls_sha256_init(&ctx);

	rc = mbedtls_sha256_update_ret(&ctx, source_buf, size);
	if (rc)
		goto out;

	mbedtls_sha256_finish_ret(&ctx, target_hash);
	if (rc)
		goto out;

out:
	mbedtls_sha256_free(&ctx);
	return rc;
}

/* Reformat the TPMNV space */
static int tpmnv_format(void)
{
	int rc;

	memset(tpmnv_vars_image, 0x00, tpmnv_vars_size);
	memset(tpmnv_control_image, 0x00, sizeof(struct tpmnv_control));

	tpmnv_vars_image->header.magic_number = SECBOOT_MAGIC_NUMBER;
	tpmnv_vars_image->header.magic_number = SECBOOT_VERSION;
	tpmnv_control_image->header.magic_number = SECBOOT_MAGIC_NUMBER;
	tpmnv_control_image->header.magic_number = SECBOOT_VERSION;

	/* Counts as first write to the TPM NV, as required by fresh NV indices */
	rc = tpmnv_ops.write(SECBOOT_TPMNV_VARS_INDEX, tpmnv_vars_image, tpmnv_vars_size, 0);
	if (rc)
		return rc;

	return tpmnv_ops.write(SECBOOT_TPMNV_CONTROL_INDEX, tpmnv_control_image, sizeof(struct tpmnv_control), 0);
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
	rc = calc_bank_hash(tpmnv_control_image->bank_hash[0], secboot_image->bank[0], SECBOOT_VARIABLE_BANK_SIZE);
	if (rc)
		return rc;

	rc = tpmnv_ops.write(SECBOOT_TPMNV_CONTROL_INDEX, tpmnv_control_image->bank_hash[0], SHA256_DIGEST_SIZE, offsetof(struct tpmnv_control, bank_hash[0]));
	if (rc)
		return rc;

	return platform.secboot_write(0, secboot_image, sizeof(struct secboot));
}


/* Serialize one priority variable using a tighter packing scheme */
/* Returns the advanced target pointer */
static char *secboot_serialize_priority(char *target, struct secvar_node *node, char *end)
{
	if ((target + node->var->key_len + node->var->data_size + offsetof(struct secvar, key))	> end)
		return NULL;

	memcpy(target, &node->var->key_len, sizeof(node->var->key_len));
	target += sizeof(node->var->key_len);
	memcpy(target, &node->var->data_size, sizeof(node->var->data_size));
	target += sizeof(node->var->data_size);
	memcpy(target, node->var->key, node->var->key_len);
	target += node->var->key_len;
	memcpy(target, node->var->data, node->var->data_size);

	return target;
}


/* Flattens a linked-list bank into a contiguous buffer for writing */
static int secboot_serialize_bank(struct list_head *bank, char *target, size_t target_size, int flags)
{
	struct secvar_node *node;
	char *tmp = target;
	char *end = target + target_size;

	if (!bank)
		return OPAL_INTERNAL_ERROR;
	if (!target)
		return OPAL_INTERNAL_ERROR;

	list_for_each(bank, node, link) {
		if (node->flags != flags)
			continue;

		/* Priority variable has a different packing scheme */
		if (flags == SECVAR_FLAG_PRIORITY) {
			target = secboot_serialize_priority(target, node, end);
			if (!target)
				return OPAL_EMPTY;
			continue;
		}

		/* Bail early if we are out of storage space */
		if ((target - tmp) + sizeof(struct secvar) + node->var->data_size > target_size) {
			return OPAL_EMPTY;
		}

		memcpy(target, node->var, sizeof(struct secvar) + node->var->data_size);

		target += sizeof(struct secvar) + node->var->data_size;
	}

	return OPAL_SUCCESS;
}

/* Loads in a flattened list of variables from a buffer into a linked list */
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

	bit = CYCLE_BIT(tpmnv_control_image->active_bit);
	rc = secboot_serialize_bank(bank, tpmnv_vars_image->vars, tpmnv_vars_size - sizeof(struct tpmnv_vars), SECVAR_FLAG_PRIORITY);
	if (rc)
		goto out;

	rc = tpmnv_ops.write(SECBOOT_TPMNV_VARS_INDEX, tpmnv_vars_image, tpmnv_vars_size, 0);

	/* Calculate the bank hash, and write to TPM NV */
	rc = secboot_serialize_bank(bank, secboot_image->bank[bit], SECBOOT_VARIABLE_BANK_SIZE, 0);
	if (rc)
		goto out;

	rc = calc_bank_hash(tpmnv_control_image->bank_hash[bit], secboot_image->bank[bit], SECBOOT_VARIABLE_BANK_SIZE);
	if (rc) goto out;

	rc = tpmnv_ops.write(SECBOOT_TPMNV_CONTROL_INDEX, tpmnv_control_image->bank_hash[bit], SHA256_DIGEST_LENGTH, offsetof(struct tpmnv_control, bank_hash[bit]));
	if (rc)
		goto out;

	/* Write new variable bank to pnor */
	rc = platform.secboot_write(0, secboot_image, sizeof(struct secboot));
	if (rc)
		goto out;

	/* Flip the bit, and write to TPM NV */
	tpmnv_control_image->active_bit = bit;
	rc = tpmnv_ops.write(SECBOOT_TPMNV_CONTROL_INDEX, &tpmnv_control_image->active_bit, sizeof(tpmnv_control_image->active_bit), offsetof(struct tpmnv_control, active_bit));
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

/* Priority variables stored in TPMNV have to be packed tighter to make the most
 * out of the small amount of space available */
static int secboot_tpm_load_from_tpmnv(struct list_head *bank)
{
	struct secvar *hdr;
	struct secvar_node *node;
	char *cur;
	char *end;

	cur = tpmnv_vars_image->vars;
	end = ((char *) tpmnv_vars_image) + tpmnv_vars_size;

	while (cur < end) {
		/* Ensure there is enough space to even check for another var header */
		if ((end - cur) < offsetof(struct secvar, key))
			break;

		/* Temporary cast to check sizes in the header */
		hdr = (struct secvar *) cur;

		/* Check if we have a priority variable to load */
		/* Should be zeroes if nonexistent */
		if ((hdr->key_len == 0) && (hdr->data_size == 0))
			break;

		/* Sanity check our potential priority variables */
		if ((hdr->key_len > SECVAR_MAX_KEY_LEN)
		     || (hdr->data_size > SECBOOT_TPM_MAX_VAR_SIZE)) {
			prlog(PR_ERR, "TPM NV Priority variable has impossible sizes, probably internal bug. "
				      "len = %llu, size = %llu\n", hdr->key_len, hdr->data_size);
			return OPAL_INTERNAL_ERROR;
		}

		/* Advance cur over the two size values */
		cur += sizeof(hdr->key_len);
		cur += sizeof(hdr->data_size);

		/* Ensure the expected key/data size doesn't exceed the remaining buffer */
		if ((end - cur) < (hdr->data_size + hdr->key_len))
			return OPAL_INTERNAL_ERROR;

		node = alloc_secvar(hdr->data_size);
		if (!node)
			return OPAL_NO_MEM;

		node->var->key_len = hdr->key_len;
		node->var->data_size = hdr->data_size;
		node->flags |= SECVAR_FLAG_PRIORITY;

		memcpy(node->var->key, cur, hdr->key_len);
		cur += hdr->key_len;
		memcpy(node->var->data, cur, hdr->data_size);
		cur += hdr->data_size;

		list_add_tail(bank, &node->link);
	}

	return OPAL_SUCCESS;
}

static int secboot_tpm_load_variable_bank(struct list_head *bank)
{
	char bank_hash[SHA256_DIGEST_LENGTH];
	uint64_t bit = tpmnv_control_image->active_bit;
	int rc;

	/* Check the hash of the bank we loaded from PNOR versus the expected hash in TPM NV */
	rc = calc_bank_hash(bank_hash, secboot_image->bank[bit], SECBOOT_VARIABLE_BANK_SIZE);
	if (rc)
		return rc;

	if (memcmp(bank_hash, tpmnv_control_image->bank_hash[bit], SHA256_DIGEST_LENGTH))
		return OPAL_PERMISSION; /* Tampered pnor space detected, abandon ship */

	rc = secboot_tpm_load_from_tpmnv(bank);
	if (rc)
		return rc;

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

static int secboot_tpm_init_tpmnv(int *tpm_first_init)
{
	int rc;

	if (!tpm_first_init)
		return OPAL_INTERNAL_ERROR;

	tpmnv_vars_image = zalloc(tpmnv_vars_size);
	if (!tpmnv_vars_image)
		return OPAL_NO_MEM;
	tpmnv_control_image = zalloc(sizeof(struct tpmnv_control));
	if (!tpmnv_control_image)
		return OPAL_NO_MEM;

	// TODO use getcap

	/* Read from each TPM NV index, define it if it doesn't exist */
	/* Defining the index invokes a full reformat */
	rc = tpmnv_ops.read(SECBOOT_TPMNV_VARS_INDEX, tpmnv_vars_image, tpmnv_vars_size, 0);
	if (rc == TPM_RC_NV_UNINITIALIZED) {
		rc = tpmnv_ops.definespace(SECBOOT_TPMNV_VARS_INDEX, 'p', 'p', tpmnv_vars_size);
		if (rc)
			return rc;

		*tpm_first_init = 1;
		goto out;
	} else if (rc)
		return rc;

	rc = tpmnv_ops.read(SECBOOT_TPMNV_CONTROL_INDEX, tpmnv_control_image, sizeof(struct tpmnv_control), 0);
	if (rc == TPM_RC_NV_UNINITIALIZED) {
		rc = tpmnv_ops.definespace(SECBOOT_TPMNV_VARS_INDEX, 'p', 'p', sizeof(struct tpmnv_control));
		if (rc)
			return rc;

		*tpm_first_init = 1;
		goto out;
	} else if (rc)
		return rc;

	/* Trigger a reformat if for some reason the NV index was cleared */
	if (tpmnv_vars_image->header.magic_number != SECBOOT_MAGIC_NUMBER)
		*tpm_first_init = 1;
	if (tpmnv_control_image->header.magic_number != SECBOOT_MAGIC_NUMBER)
		*tpm_first_init = 1;

out:
	return OPAL_SUCCESS;
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

	/* Allocate and load data from the TPM NV indices,
	 * define them if they are not already. */
	rc = secboot_tpm_init_tpmnv(&tpm_first_init);
	if (rc)
		goto error;

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
		rc = OPAL_NO_MEM;
		goto error;
	}

	/* Read in the PNOR data, bank hash is checked on call to .load_bank() */
	rc = platform.secboot_read(secboot_image, 0, sizeof(struct secboot));
	if (rc) {
		prlog(PR_ERR, "failed to read the secboot partition, rc=%d\n", rc);
		goto error;
	}

	/* TPM needs to be formatted, also reformat SECBOOT with it */
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
	free(tpmnv_vars_image);
	tpmnv_vars_image = NULL;
	free(tpmnv_control_image);
	tpmnv_control_image = NULL;

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
