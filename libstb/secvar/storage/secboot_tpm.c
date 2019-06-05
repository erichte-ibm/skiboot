/* Copyright 2019 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef pr_fmt
#define pr_fmt(fmt) "SECBOOT_P9: " fmt
#endif

#include <stdlib.h>
#include <skiboot.h>
#include <opal.h>
#include <mbedtls/sha256.h>
#include "../secvar.h"
#include "../secvar_tpmnv.h"

//#define CYCLE_BIT(b) (((((b-1)%SECBOOT_VARIABLE_BANK_NUM)+1)%SECBOOT_VARIABLE_BANK_NUM)+1)
#define CYCLE_BIT(b) (b^0x1)

// Arbitrarily defined via RNG
#define TPMNV_ID_ACTIVE_BIT	0x97faf1e2
#define TPMNV_ID_HASH_BANK_0	0x7c579c31
#define TPMNV_ID_HASH_BANK_1	0x9a296ce0

#define GET_HASH_BANK_ID(bit) ((bit)?TPMNV_ID_HASH_BANK_1:TPMNV_ID_HASH_BANK_0)

// TODO: Determine reasonable values for these, or have platform set it?
#define SECBOOT_VARIABLE_BANK_SIZE	32000
#define SECBOOT_UPDATE_BANK_SIZE	32000

#define SECBOOT_VARIABLE_BANK_NUM	2

// Because mbedtls doesn't define this?
#define SHA256_DIGEST_LENGTH	32


/* 0x5053424b = "PSBK" or Power Secure Boot Keystore */
#define SECBOOT_MAGIC_NUMBER	0x5053424b
#define SECBOOT_VERSION		1

struct secboot_header {
	uint32_t magic_number;
	uint8_t version;
	uint8_t reserved[3];	// Fix alignment
} __packed;


struct secboot {
	struct secboot_header header;
	char bank[SECBOOT_VARIABLE_BANK_NUM][SECBOOT_VARIABLE_BANK_SIZE];
	char update[SECBOOT_UPDATE_BANK_SIZE];
} __packed;
#define _secboot_header_ // TODO: delete this with tss, move to header if long term

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
		return -1;

	memset(secboot_image, 0x00, sizeof(struct secboot));

	secboot_image->header.magic_number = SECBOOT_MAGIC_NUMBER;
	secboot_image->header.version = SECBOOT_VERSION;

	// Write the empty hash to the tpm so loads work in the future
	calc_bank_hash(bank_hash, secboot_image->bank[0], SECBOOT_VARIABLE_BANK_SIZE);
	secvar_tpmnv_write(TPMNV_ID_HASH_BANK_0, bank_hash, SHA256_DIGEST_LENGTH, 0);

	return platform.secboot_write(0, secboot_image, sizeof(struct secboot));
}


static int secboot_serialize_bank(struct list_head *bank, char *target, size_t target_size, int flags)
{
	struct secvar_node *node;
	char *tmp = target;

	if (!bank)
		return -1;
	if (!target)
		return -1;

	list_for_each(bank, node, link) {
		if (node->flags != flags)
			continue;

		// Bail early if we are out of storage space
		if ((target - tmp) + sizeof(struct secvar) + node->var->data_size > target_size) {
			return -1;
		}
		
		memcpy(target, node->var, sizeof(struct secvar) + node->var->data_size);

		target += sizeof(struct secvar) + node->var->data_size;
	}

	return 0;
}


static int secboot_write_to_pnor(struct list_head *bank, char *target, size_t max_size)
{
	if (!platform.secboot_write) {
		prlog(PR_ERR, "Failed to write: platform.secboot_write not set\n");
		return -1;
	}

	memset(target, 0, max_size);

	return secboot_serialize_bank(bank, target, max_size, 0);
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
			return -1;
		}

		memcpy(tmp->var, src, sizeof(struct secvar) + hdr->data_size);

		list_add_tail(bank, &tmp->link);
		src += sizeof(struct secvar) + hdr->data_size;
	}

	return 0;
}


static int secboot_tpm_write_bank(struct list_head *bank, int section)
{
	int rc;
	uint64_t bit;
	char bank_hash[SHA256_DIGEST_LENGTH];

	secvar_tpmnv_read(TPMNV_ID_ACTIVE_BIT, &bit, sizeof(bit), 0);

	bit = CYCLE_BIT(bit);

	switch(section) {
		case SECVAR_VARIABLE_BANK:
			// Calculate the bank hash, and write to TPM NV
			rc = secboot_serialize_bank(bank, secboot_image->bank[bit], SECBOOT_VARIABLE_BANK_SIZE, 0);
			calc_bank_hash(bank_hash, secboot_image->bank[bit], SECBOOT_VARIABLE_BANK_SIZE);
			rc = secvar_tpmnv_write(GET_HASH_BANK_ID(bit), bank_hash, SHA256_DIGEST_LENGTH, 0);

			// Write new variable bank to pnor
			rc = platform.secboot_write(0, secboot_image, sizeof(struct secboot));

			// Flip the bit, and write to TPM NV
			rc = secvar_tpmnv_write(TPMNV_ID_ACTIVE_BIT, &bit, sizeof(bit), 0);
			break;
		case SECVAR_UPDATE_BANK:
			rc = secboot_write_to_pnor(bank, secboot_image->update, SECBOOT_UPDATE_BANK_SIZE);
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
		return 0;

	if (!platform.secboot_info)
		return -1;

	prlog(PR_DEBUG, "Initializing for pnor+tpm based platform\n");

	rc = secvar_tpmnv_alloc(TPMNV_ID_ACTIVE_BIT, sizeof(uint64_t));
	rc |= secvar_tpmnv_alloc(TPMNV_ID_HASH_BANK_0, SHA256_DIGEST_LENGTH);
	rc |= secvar_tpmnv_alloc(TPMNV_ID_HASH_BANK_1, SHA256_DIGEST_LENGTH);
	if (rc) {
		prlog(PR_ERR, "unable to alloc or find the tpmnv space\n");
		return -1;
	}

	rc = platform.secboot_info(&secboot_size);
	if (rc) {
		prlog(PR_ERR, "error %d retrieving keystore info\n", rc);
		return -1;
	}
	if (sizeof(struct secboot) > secboot_size) {
		prlog(PR_ERR, "secboot partition %d KB too small. min=%ld\n",
		      secboot_size >> 10, sizeof(struct secboot));
		return -1;
	}

	secboot_image = memalign(0x1000, sizeof(struct secboot));
	if (!secboot_image) {
		prlog(PR_ERR, "Failed to allocate space for the secboot image\n");
		return -1;
	}

	/* Read it in */
	rc = platform.secboot_read(secboot_image, 0, sizeof(struct secboot));
	if (rc) {
		prlog(PR_ERR, "failed to read the secboot partition, rc=%d\n", rc);
		goto out_free;
	}

	if (secboot_image->header.magic_number != SECBOOT_MAGIC_NUMBER) {
		prlog(PR_INFO, "Formatting secboot partition...\n");
		rc = secboot_format();
		if (rc) {
			prlog(PR_ERR, "Failed to format secboot!\n");
			goto out_free;
		}
	}

	return 0;

out_free:
	if (secboot_image) {
		free(secboot_image);
		secboot_image = NULL;
	}

	return -1;
}

struct secvar_storage_driver secboot_tpm_driver = {
	.load_bank = secboot_tpm_load_bank,
	.write_bank = secboot_tpm_write_bank,
	.store_init = secboot_tpm_store_init,
	.max_var_size = 4096,	// Arbitrary, probably could be larger
};
