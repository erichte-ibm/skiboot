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
#include "../secvar_tpmnv.h"
#include "secboot_tpm.h"

//#define CYCLE_BIT(b) (((((b-1)%SECBOOT_VARIABLE_BANK_NUM)+1)%SECBOOT_VARIABLE_BANK_NUM)+1)
#define CYCLE_BIT(b) (b^0x1)

#define TPMNV_ID_ACTIVE_BIT	0x53414242 // SABB
#define TPMNV_ID_HASH_BANK_0	0x53484230 // SHB0
#define TPMNV_ID_HASH_BANK_1	0x53484231 // SHB1

#define GET_HASH_BANK_ID(bit) ((bit)?TPMNV_ID_HASH_BANK_1:TPMNV_ID_HASH_BANK_0)

// Because mbedtls doesn't define this?
#define SHA256_DIGEST_LENGTH	32

struct secboot *secboot_image;

static void calc_bank_hash(char *target_hash, char *source_buf, uint64_t size)
{
	mbedtls_sha256_context ctx;

	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_update_ret(&ctx, source_buf, size);
	mbedtls_sha256_finish_ret(&ctx, target_hash);
}

static int secboot_format(void)
{
	char bank_hash[SHA256_DIGEST_LENGTH];

	if (!platform.secboot_write)
		return OPAL_UNSUPPORTED;

	memset(secboot_image, 0x00, sizeof(struct secboot));

	secboot_image->header.magic_number = SECBOOT_MAGIC_NUMBER;
	secboot_image->header.version = SECBOOT_VERSION;

	// Write the empty hash to the tpm so loads work in the future
	calc_bank_hash(bank_hash, secboot_image->bank[0], SECBOOT_VARIABLE_BANK_SIZE);
	secvar_tpmnv_write(TPMNV_ID_HASH_BANK_0, bank_hash, SHA256_DIGEST_LENGTH, 0);

	return platform.secboot_write(0, secboot_image, sizeof(struct secboot));
}

// Flattens a linked-list bank into a contiguous buffer for writing
static int secboot_serialize_bank(struct list_head *bank, char *target, size_t target_size, int flags)
{
	struct secvar_node *node;
	char *tmp = target;

	if (!bank)
		return OPAL_INTERNAL_ERROR;
	if (!target)
		return OPAL_INTERNAL_ERROR;

	list_for_each(bank, node, link) {
		if (node->flags != flags)
			continue;

		// Bail early if we are out of storage space
		if ((target - tmp) + sizeof(struct secvar) + node->var->data_size > target_size) {
			return OPAL_EMPTY;
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
		// Load in the header first to get the size, and check if we are at the end
		hdr = (struct secvar *) src;
		if (hdr->key_len == 0) {
			break;
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


static int secboot_tpm_write_bank(struct list_head *bank, int section)
{
	int rc;
	uint64_t bit;
	char bank_hash[SHA256_DIGEST_LENGTH];

	switch(section) {
		case SECVAR_VARIABLE_BANK:
			// Get the current bit and flip it
			secvar_tpmnv_read(TPMNV_ID_ACTIVE_BIT, &bit, sizeof(bit), 0);
			bit = CYCLE_BIT(bit);

			// Calculate the bank hash, and write to TPM NV
			rc = secboot_serialize_bank(bank, secboot_image->bank[bit], SECBOOT_VARIABLE_BANK_SIZE, 0);
			if (rc)
				break;

			calc_bank_hash(bank_hash, secboot_image->bank[bit], SECBOOT_VARIABLE_BANK_SIZE);
			rc = secvar_tpmnv_write(GET_HASH_BANK_ID(bit), bank_hash, SHA256_DIGEST_LENGTH, 0);
			if (rc)
				break;

			// Write new variable bank to pnor
			rc = platform.secboot_write(0, secboot_image, sizeof(struct secboot));
			if (rc)
				break;

			// Flip the bit, and write to TPM NV
			rc = secvar_tpmnv_write(TPMNV_ID_ACTIVE_BIT, &bit, sizeof(bit), 0);
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
	char tpm_bank_hash[SHA256_DIGEST_LENGTH];
	uint64_t bit;

	secvar_tpmnv_read(TPMNV_ID_ACTIVE_BIT, &bit, sizeof(bit), 0);
	secvar_tpmnv_read(GET_HASH_BANK_ID(bit), tpm_bank_hash, SHA256_DIGEST_LENGTH, 0);

	calc_bank_hash(bank_hash, secboot_image->bank[bit], SECBOOT_VARIABLE_BANK_SIZE);
	if (memcmp(bank_hash, tpm_bank_hash, SHA256_DIGEST_LENGTH))
		return OPAL_PERMISSION; // Tampered pnor space detected, abandon ship

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

	// Already initialized
	if (secboot_image)
		return OPAL_SUCCESS;

	if (!platform.secboot_info)
		return OPAL_UNSUPPORTED;

	prlog(PR_DEBUG, "Initializing for pnor+tpm based platform\n");

	rc = secvar_tpmnv_alloc(TPMNV_ID_ACTIVE_BIT, sizeof(uint64_t));
	rc |= secvar_tpmnv_alloc(TPMNV_ID_HASH_BANK_0, SHA256_DIGEST_LENGTH);
	rc |= secvar_tpmnv_alloc(TPMNV_ID_HASH_BANK_1, SHA256_DIGEST_LENGTH);
	if (rc) {
		prlog(PR_ERR, "unable to alloc or find the tpmnv space\n");
		return rc;
	}

	rc = platform.secboot_info(&secboot_size);
	if (rc) {
		prlog(PR_ERR, "error %d retrieving keystore info\n", rc);
		return rc;
	}
	if (sizeof(struct secboot) > secboot_size) {
		prlog(PR_ERR, "secboot partition %d KB too small. min=%ld\n",
		      secboot_size >> 10, sizeof(struct secboot));
		return OPAL_RESOURCE;
	}

	secboot_image = memalign(0x1000, sizeof(struct secboot));
	if (!secboot_image) {
		prlog(PR_ERR, "Failed to allocate space for the secboot image\n");
		return OPAL_NO_MEM;
	}

	/* Read it in */
	rc = platform.secboot_read(secboot_image, 0, sizeof(struct secboot));
	if (rc) {
		prlog(PR_ERR, "failed to read the secboot partition, rc=%d\n", rc);
		goto out_free;
	}

	if ((secboot_image->header.magic_number != SECBOOT_MAGIC_NUMBER)
	     || tpm_first_init ) {
		prlog(PR_INFO, "Formatting secboot partition...\n");
		rc = secboot_format();
		if (rc) {
			prlog(PR_ERR, "Failed to format secboot!\n");
			goto out_free;
		}
	}

	return OPAL_SUCCESS;

out_free:
	if (secboot_image) {
		free(secboot_image);
		secboot_image = NULL;
	}

	return rc;
}

struct secvar_storage_driver secboot_tpm_driver = {
	.load_bank = secboot_tpm_load_bank,
	.write_bank = secboot_tpm_write_bank,
	.store_init = secboot_tpm_store_init,
	.max_var_size = 8192,
};
