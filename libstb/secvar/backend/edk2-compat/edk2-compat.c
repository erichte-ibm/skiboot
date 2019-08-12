/*
 * Copyright (c) 2006 - 2015, Intel Corporation. All rights reserved. This
 * program and the accompanying materials are licensed and made available
 * under the terms and conditions of the 2-Clause BSD License which
 * accompanies this distribution.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * Some of the concepts in this file are derived from the edk2-staging[1] repo
 * of tianocore reference implementation
 * [1] https://github.com/tianocore/edk2-staging
 * Copyright 2019 IBM Corp.
 */

#include <opal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <ccan/endian/endian.h>
#include "libstb/crypto/pkcs7/pkcs7.h"
#include "edk2.h"
#include "opal-api.h"
#include "../../secvar.h"
#include "../../secvar_devtree.h"
#include "../../secvar_tpmnv.h"

#define TPMNV_ID_EDK2_PK	0xd1e81f2c

static int esl_get_cert_size(unsigned char *buf)
{
	EFI_SIGNATURE_LIST list;
	uint32_t sigsize;

	memcpy(&list, buf, sizeof(EFI_SIGNATURE_LIST));

	sigsize = le32_to_cpu(list.SignatureListSize) - sizeof(list)
		- le32_to_cpu(list.SignatureHeaderSize);

	return sigsize;
}

static int esl_get_cert(unsigned char *buf, unsigned char *cert)
{
	int sig_data_offset;
	int size;
	EFI_SIGNATURE_LIST list;

	memcpy(&list, buf, sizeof(EFI_SIGNATURE_LIST));

	sig_data_offset = sizeof(list.SignatureType)
		+ sizeof(list.SignatureListSize)
		+ sizeof(list.SignatureHeaderSize)
		+ sizeof(list.SignatureSize)
		+ le32_to_cpu(list.SignatureHeaderSize)
		+ 16 * sizeof(uint8_t);

	size = le32_to_cpu(list.SignatureSize) - sizeof(EFI_SIGNATURE_LIST);
	memcpy(cert, buf + sig_data_offset, size);

	return 0;
}


/*
 * PK needs to be stored in the TPMNV space if on p9
 * We store it using the form <u64:esl size><esl data>, the
 * extra secvar headers are unnecessary
 */
static int edk2_p9_load_pk(void)
{
	struct secvar_node *pkvar;
	uint64_t size;
	int rc;

	// Ensure it exists
	rc = secvar_tpmnv_alloc(TPMNV_ID_EDK2_PK, -1);

	// Peek to get the size
	rc = secvar_tpmnv_read(TPMNV_ID_EDK2_PK, &size, sizeof(size), 0);
	if (OPAL_EMPTY)
		return 0;
	else if (rc)
		return -1;

	if (size > secvar_storage.max_var_size)
		return OPAL_RESOURCE;

	pkvar = alloc_secvar(size);
	pkvar->var->data_size = size;
	pkvar->flags |= SECVAR_FLAG_VOLATILE;

	rc = secvar_tpmnv_read(TPMNV_ID_EDK2_PK, pkvar->var->data, pkvar->var->data_size, sizeof(pkvar->var->data_size));
	if (rc)
		return -1;

	list_add_tail(&variable_bank, &pkvar->link);
}

static int edk2_p9_write_pk(void)
{
	char *tmp;
	int32_t tmpsize;
	struct secvar_node *pkvar;

	pkvar = find_secvar("PK", 3, &variable_bank);

	// Should not happen
	if (!pkvar)
		return OPAL_INTERNAL_ERROR;

	// Reset the pk flag to volatile on p9
	pkvar->flags |= SECVAR_FLAG_VOLATILE;

	tmpsize = secvar_tpmnv_size(TPMNV_ID_EDK2_PK);
	if (!tmpsize)
		return OPAL_RESOURCE;
	if (tmpsize < pkvar->var->data_size + sizeof(pkvar->var->data_size))
		return OPAL_RESOURCE;

	tmp = zalloc(tmpsize);

	memcpy(tmp, &pkvar->var->data_size, sizeof(pkvar->var->data_size));
	tmp += sizeof(pkvar->var->data_size);
	memcpy(tmp, pkvar->var->data, pkvar->var->data_size);

	return secvar_tpmnv_write(TPMNV_ID_EDK2_PK, tmp, tmpsize, 0);
}

/**
 * Initializes supported variables as empty if not loaded from
 * storage. Variables are initialized as volatile if not found.
 * Updates should clear this flag.
 *
 * Returns OPAL Error if anything fails in initialization
 */
static int edk2_compat_pre_process(void)
{
	struct secvar_node *pkvar;
	struct secvar_node *kekvar;
	struct secvar_node *dbvar;

	// If we are on p9, we need to load the PK from TPM NV space
	if (proc_gen == proc_gen_p9)
		edk2_p9_load_pk();

	pkvar = find_secvar((char *)"PK", 3, &variable_bank);
	if (!pkvar) {
		pkvar = alloc_secvar(0);
		if (!pkvar)
			return OPAL_NO_MEM;

		memcpy(pkvar->var->key, "PK", 3);
		pkvar->var->key_len = 3;
		pkvar->flags |= SECVAR_FLAG_VOLATILE;
		list_add_tail(&variable_bank, &pkvar->link);
	}

	kekvar = find_secvar((char *)"KEK", 4, &variable_bank);
	if (!kekvar) {
		kekvar = alloc_secvar(0);
		if (!kekvar)
			return OPAL_NO_MEM;

		memcpy(kekvar->var->key, "KEK", 4);
		kekvar->var->key_len = 4;
		kekvar->flags |= SECVAR_FLAG_VOLATILE;
		list_add_tail(&variable_bank, &kekvar->link);
	}

	dbvar = find_secvar((char *)"db", 3, &variable_bank);
	if (!dbvar) {
		dbvar = alloc_secvar(0);
		if (!dbvar)
			return OPAL_NO_MEM;

		memcpy(dbvar->var->key, "db", 3);
		dbvar->var->key_len = 3;
		dbvar->flags |= SECVAR_FLAG_VOLATILE;
		list_add_tail(&variable_bank, &dbvar->link);
	}


	return OPAL_SUCCESS;
};

/**
 * Extracts size of the PKCS7 signed data embedded in the
 * struct Authentication Descriptor 2 Header
 */
static int get_pkcs7_len(struct efi_variable_authentication_2 *auth)
{
	uint32_t dw_length = le32_to_cpu(auth->auth_info.hdr.dw_length);
	int size;

	size = dw_length - (sizeof(auth->auth_info.hdr.dw_length)
			+ sizeof(auth->auth_info.hdr.w_revision)
			+ sizeof(auth->auth_info.hdr.w_certificate_type)
			+ sizeof(auth->auth_info.cert_type));

	return size;
}

/**
 * The data submitted by the user is
 * auth_descriptor_2 + new ESL data
 * This function returns the size of the auth_descriptor_2
 */
static int get_auth_buffer_size(void *data)
{
	struct efi_variable_authentication_2 *auth;
	uint64_t auth_buffer_size;
	int len = 0;

	auth = (struct efi_variable_authentication_2 *)data;

	len = get_pkcs7_len(auth);

	auth_buffer_size = sizeof(struct efi_time)
		+ sizeof(u32)
		+ sizeof(u16)
		+ sizeof(u16)
		+ sizeof(uuid_t)
		+ len;

	return auth_buffer_size;
}

/**
 * Returns true if we are in Setup Mode
 *
 * Setup Mode is active if we have no PK.
 * Otherwise, we are in deployed mode.
 */
static int is_setup_mode(void)
{
	struct secvar_node *setup;

	setup = find_secvar((char *)"PK", 3, &variable_bank);

	// Not sure why this wouldn't exist
	if (!setup)
		return 1;

	return !setup->var->data_size;
}

/**
 * Update the variable with the new value.
 */
static int add_to_variable_bank(struct secvar *secvar, void *data, uint64_t dsize)
{
	struct secvar_node *node;

	node = find_secvar(secvar->key, secvar->key_len, &variable_bank);
	if (!node)
		return OPAL_INTERNAL_ERROR;

	// Expand the secvar allocated memory if needed
	if (node->size < dsize)
		if (realloc_secvar(node, dsize))
			return OPAL_NO_MEM;

	node->var->data_size = dsize;
	memcpy(node->var->data, data, dsize);
	node->flags &= ~SECVAR_FLAG_VOLATILE; // Clear the volatile bit when updated

	return 0;
}

/**
 * Verifies the PKCS7 signature on the signed data.
 */
static int verify_update(void *auth_buffer, unsigned char *newcert,
		uint64_t new_data_size, struct secvar *avar)
{
	struct efi_variable_authentication_2 *auth;
	struct mbedtls_pkcs7 *pkcs7;
	int len = 0;
	int signing_cert_size = 0;
	unsigned char *signing_cert;
	unsigned char *x509_buf;
	mbedtls_x509_crt x509;
	int rc = 0;

	auth = auth_buffer;

	len  = get_pkcs7_len(auth);

	pkcs7 = malloc(sizeof(struct mbedtls_pkcs7));
	mbedtls_pkcs7_init(pkcs7);

	rc = mbedtls_pkcs7_parse_der(
			(const unsigned char *)auth->auth_info.cert_data,
			(const unsigned int)len, pkcs7);

	signing_cert_size = esl_get_cert_size(avar->data);
	signing_cert = zalloc(signing_cert_size);
	esl_get_cert(avar->data, signing_cert);

	mbedtls_x509_crt_init(&x509);
	rc = mbedtls_x509_crt_parse(&x509, signing_cert, signing_cert_size);
	if(rc) {
		prlog(PR_INFO, "X509 certificate parsing failed %04x\n", rc);
		return rc;
	}

	x509_buf = zalloc(2048);
	mbedtls_x509_crt_info(x509_buf, 2048, "CRT:", &x509);

	rc = mbedtls_pkcs7_signed_data_verify(pkcs7, &x509, newcert, new_data_size);

	free(pkcs7);

	return rc;
}

static char *utf8_to_ucs2(const char *key, const char keylen)
{
	int i;
	char *str;
	str = malloc(keylen * 2);

	for (i = 0; i < keylen*2; key++) {
		str[i++] = *key;
		str[i++] = '\0';
	}
	return str;
}

/**
 * Create the single buffer (name, vendor guid, attributes,timestamp and
 * newdata) which was originally signed by the user
 */
static int concatenate_data_tobehashed( unsigned char *key, unsigned char *new_data,
		uint64_t new_data_size,
		unsigned char **buffer,
		uint64_t *buffer_size)
{
	unsigned char *tbh_buffer;
	int tbh_buffer_size;
	struct efi_time timestamp;
	int size = 0;
	int varlen = 0;
	char *wkey;
	uint32_t attr = 0x00000000;
	//uuid_t guid = PLATFORM_SECVAR_ID;
	char guid[16] = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,0x07, 0x08, 0x09};
	//uuid_t guid = UUID_INIT(0x11111111, 0x2222, 0x3333, 0x44, 0x44, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);

	memset(&timestamp, 0, sizeof(struct efi_time));

	// Convert utf8 name to ucs2 width
	varlen = strlen(key) * 2;
	wkey = utf8_to_ucs2(key, strlen(key)+1);

	/**
	 * Hash is generated on:
	 * variablename || vendorguid || attributes || timestamp || newcontent
	 */

	tbh_buffer_size = sizeof(struct efi_time) + varlen  + UUID_SIZE + sizeof(attr) + new_data_size;

	tbh_buffer = malloc(tbh_buffer_size);

	memcpy(tbh_buffer + size, wkey, varlen);
	size = size + varlen;
	memcpy(tbh_buffer + size, &guid, sizeof(guid));
	size = size + sizeof(guid);
	memcpy(tbh_buffer + size, &attr, sizeof(attr));
	size = size + sizeof(attr);
	memcpy(tbh_buffer + size, &timestamp , sizeof(struct efi_time));
	size = size + sizeof(struct efi_time);
	memcpy(tbh_buffer + size, new_data, new_data_size);
	size = size + new_data_size;

	*buffer = malloc(size);
	memcpy(*buffer, tbh_buffer, size);
	*buffer_size = size;

	free(wkey);

	return 0;
}

static int edk2_compat_process(void)
{
	unsigned char *auth_buffer;
	uint64_t auth_buffer_size;
	uint64_t new_data_size = 0;
	unsigned char *dbcert = NULL;
	struct secvar_node *anode = NULL;
	struct secvar_node *node = NULL;
	unsigned char *tbhbuffer;
	uint64_t tbhbuffersize;
	int rc;
	int pk_updated = 0;
	bool setupmode = is_setup_mode();

	prlog(PR_DEBUG, "Setup mode = %d\n", setupmode);

	/* Loop through each command in the update bank.
	 * If any command fails, it just loops out of the update bank.
	 * It should also clear the update bank.
	 */
	list_for_each(&update_bank, node, link) {

		/* Submitted data is auth_descriptor_2 + new ESL data
		 * Extract the size of auth_descriptor_2
		 */
		auth_buffer_size = get_auth_buffer_size(node->var->data);
		auth_buffer = zalloc(auth_buffer_size);
		memcpy(auth_buffer, node->var->data, auth_buffer_size);

		if (node->var->data_size < auth_buffer_size) {
			rc = OPAL_PARAMETER;
			goto out;
		}

		/* Calculate the size of new ESL data */
		new_data_size = node->var->data_size - auth_buffer_size;
		dbcert = zalloc(new_data_size);
		memcpy(dbcert, node->var->data + auth_buffer_size, new_data_size);

		if (!setupmode) {

			/* If the update is for PK, verify it with existing PK */
			if (memcmp(node->var->key,"PK",node->var->key_len) == 0) {
				anode = find_secvar((char *)"PK", 3,
						    &variable_bank);
				if (anode && (anode->var->data_size == 0)) {
					rc = -1;
					goto out;
				}
			}

			/* If the update is for KEK/DB, verify it with PK */
			if ((memcmp(node->var->key,"KEK", node->var->key_len) == 0)
					|| (memcmp(node->var->key, "db",
						   node->var->key_len) == 0)) {
				anode = find_secvar((char *)"PK", 3,
						    &variable_bank);
				if ((anode && (anode->var->data_size == 0))
						&& (memcmp(node->var->key,
							   "KEK",
							   node->var->key_len) == 0)) {
					prlog(PR_INFO, "validation of %s failed\n", node->var->key);
					rc = -1;
					goto out;
				}
			}

			/* If the update is for db, and previous verification
			 * via PK fails, check if it is signed by any of the
			 * KEKs
			 */
			if (memcmp(node->var->key, "db",
				   node->var->key_len) == 0) {
				anode = find_secvar((char *)"KEK", 4,
						    &variable_bank);
				if (anode && (anode->var->data_size == 0)) {
					prlog(PR_INFO, "validation of %s failed\n", node->var->key);
					rc = -1;
					goto out;
				}
			}

			/* Create the buffer on which signature was generated */
			rc = concatenate_data_tobehashed(node->var->key,
							 dbcert,
							 new_data_size,
							 &tbhbuffer,
							 &tbhbuffersize);

			/* Verify the signature */
			rc = verify_update(auth_buffer, tbhbuffer,
					   tbhbuffersize, anode->var);
			if (rc)
				goto out;

		}

		/*
		 * If reached here means, signature is verified so update the
		 * value in the variable bank
		 */
		add_to_variable_bank(node->var, dbcert, new_data_size);

		/* If the PK is updated, update the secure boot state of the
		 * system at the end of processing */
		if (memcmp(node->var->key, "PK",
			   node->var->key_len) == 0) {
			pk_updated = 1;
		}
	}

	if (pk_updated) {
		secvar_set_secure_mode();

		// Store the updated pk in TPMNV on p9 to be safe
		if (proc_gen == proc_gen_p9)
			edk2_p9_write_pk();
	}

out:
	clear_bank_list(&update_bank);

	return rc;
}


static int edk2_compat_validate(struct secvar *var)
{

	//Checks if the update is for supported
	//Non-volatile secure variales
	if (memcmp(var->key, "PK", 3) == 0)
		return 1;
	if (memcmp(var->key, "KEK", 4) == 0)
		return 1;
	if (memcmp(var->key, "db", 3) == 0)
		return 1;

	//Some more checks needs to be added:
	// - check guid
	// - check auth struct
	// - possibly check signature? can't add but can validate

	return 0;
};

struct secvar_backend_driver edk2_compatible_v1 = {
	.pre_process = edk2_compat_pre_process,
	.process = edk2_compat_process,
	.validate = edk2_compat_validate,
	.compatible = "ibm,edk2-compat-v1",
};
