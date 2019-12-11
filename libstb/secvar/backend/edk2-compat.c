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
#include <ccan/endian/endian.h>
#include "libstb/crypto/pkcs7/pkcs7.h"
#include "edk2.h"
#include "opal-api.h"
#include "../secvar.h"
#include "../secvar_devtree.h"
#include "../secvar_tpmnv.h"
#include <mbedtls/error.h>

#define TPMNV_ID_EDK2_PK	0x4532504b // E2PK

static bool setup_mode;

struct efi_time *timestamp_list;

/*
 * Converts utf8 string to ucs2
 */
static char *utf8_to_ucs2(const char *key, const char keylen)
{
	int i;
	char *str;
	str = zalloc(keylen * 2);

	for (i = 0; i < keylen*2; key++) {
		str[i++] = *key;
		str[i++] = '\0';
	}
	return str;
}

/*
 * Returns true if key1 = key2
 */
static bool key_equals(const char *key1, const char *key2)
{
	if (memcmp(key1, key2, strlen(key2)+1) == 0)
		return true;

	return false;
}

/**
 * Returns the authority that can sign the given key update
 */
static void get_key_authority(const char *ret[3], const char *key)
{
	int i = 0;

	memset(ret, 0, sizeof(char *) * 3);
	if (key_equals(key, "PK"))
		ret[i++] = "PK";
	if (key_equals(key, "KEK"))
		ret[i++] = "PK";
	if (key_equals(key, "db") || key_equals(key, "dbx")) {
		ret[i++] = "KEK";
		ret[i++] = "PK";
	}
	ret[i] = NULL;
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
	if (rc == OPAL_EMPTY)
		return 0;
	else if (rc)
		return -1;

	if (size > secvar_storage.max_var_size)
		return OPAL_RESOURCE;

	pkvar = alloc_secvar(size);
	memcpy(pkvar->var->key, "PK", 3);
	pkvar->var->key_len = 3;
	pkvar->var->data_size = size;
	pkvar->flags |= SECVAR_FLAG_VOLATILE;

	rc = secvar_tpmnv_read(TPMNV_ID_EDK2_PK, pkvar->var->data, pkvar->var->data_size, sizeof(pkvar->var->data_size));
	if (rc)
		return rc;

	list_add_tail(&variable_bank, &pkvar->link);

	return OPAL_SUCCESS;
}

/*
 * Writes the PK to the TPM.
 */
static int edk2_p9_write_pk(void)
{
	char *tmp;
	int32_t tmpsize;
	struct secvar_node *pkvar;
	int rc;

	pkvar = find_secvar("PK", 3, &variable_bank);

	// Should not happen
	if (!pkvar)
		return OPAL_INTERNAL_ERROR;

	// Reset the pk flag to volatile on p9
	pkvar->flags |= SECVAR_FLAG_VOLATILE;

	tmpsize = secvar_tpmnv_size(TPMNV_ID_EDK2_PK);
	if (tmpsize < 0) {
		prlog(PR_ERR, "TPMNV space for PK was not allocated properly\n");
		return OPAL_RESOURCE;
	}
	if (tmpsize < pkvar->var->data_size + sizeof(pkvar->var->data_size)) {
		prlog(PR_ERR, "TPMNV PK space is insufficient, %d < %llu\n", tmpsize,
			// Cast needed because x86 compiler complains building the test
			(long long unsigned) pkvar->var->data_size + sizeof(pkvar->var->data_size));
		return OPAL_RESOURCE;
	}

	tmp = zalloc(tmpsize);
	if (!tmp)
		return OPAL_NO_MEM;

	memcpy(tmp, &pkvar->var->data_size, sizeof(pkvar->var->data_size));
	memcpy(tmp + sizeof(pkvar->var->data_size),
		pkvar->var->data,
		pkvar->var->data_size);

	tmpsize = pkvar->var->data_size + sizeof(pkvar->var->data_size);

	rc = secvar_tpmnv_write(TPMNV_ID_EDK2_PK, tmp, tmpsize, 0);

	free(tmp);

	return rc;
}

/*
 * Returns the size of the certificate contained in the ESL.
 */
static int get_esl_cert_size(char *buf)
{
	EFI_SIGNATURE_LIST list;
	uint32_t sigsize;

	memcpy(&list, buf, sizeof(EFI_SIGNATURE_LIST));

	sigsize = le32_to_cpu(list.SignatureListSize) - sizeof(list)
		- le32_to_cpu(list.SignatureHeaderSize);

	return sigsize;
}

/*
 * Copies the certificate from the ESL into cert buffer.
 */
static int get_esl_cert(char *buf, char **cert)
{
	int sig_data_offset;
	int size;
	EFI_SIGNATURE_LIST list;

	memset(&list, 0, sizeof(EFI_SIGNATURE_LIST));
	memcpy(&list, buf, sizeof(EFI_SIGNATURE_LIST));

	sig_data_offset = sizeof(list.SignatureType)
		+ sizeof(list.SignatureListSize)
		+ sizeof(list.SignatureHeaderSize)
		+ sizeof(list.SignatureSize)
		+ le32_to_cpu(list.SignatureHeaderSize)
		+ 16 * sizeof(uint8_t);

	size = le32_to_cpu(list.SignatureSize) - sizeof(EFI_SIGNATURE_LIST);
	memcpy(*cert, buf + sig_data_offset, size);

	return 0;
}

/*
 * Extracts size of the PKCS7 signed data embedded in the
 * struct Authentication 2 Descriptor Header.
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

/*
 * Return the timestamp from the Authentication 2 Descriptor.
 */
static int get_timestamp_from_auth(char *data, struct efi_time **timestamp)
{
	*timestamp = (struct efi_time *) data;

	return 0;
}

/*
 * This function outputs the Authentication 2 Descriptor in the
 * auth_buffer and returns the size of the buffer.
 */
static int get_auth_descriptor2(void *data, char **auth_buffer)
{
	struct efi_variable_authentication_2 *auth = data;
	uint64_t auth_buffer_size;
	int len;

	if (!auth_buffer)
		return OPAL_PARAMETER;

	len = get_pkcs7_len(auth);
	if (len < 0)
		return OPAL_NO_MEM;

	auth_buffer_size = sizeof(auth->timestamp) + sizeof(auth->auth_info.hdr)
			   + sizeof(auth->auth_info.cert_type) + len;

	*auth_buffer = zalloc(auth_buffer_size);
	if (!(*auth_buffer))
		return OPAL_NO_MEM;

	memcpy(*auth_buffer, data, auth_buffer_size);

	return auth_buffer_size;
}

/*
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
	struct secvar_node *dbxvar;
	struct secvar_node *tsvar;

	// If we are on p9, we need to store the PK in write-lockable
	//  TPMNV space, as we determine our secure mode based on if this
	//  variable exists.
	// NOTE: Activation of this behavior is subject to change in a later
	//  patch version, ideally the platform should be able to configure
	//  whether it wants this extra protection, or to instead store
	//  everything via the storage driver.
	if (proc_gen == proc_gen_p9)
		edk2_p9_load_pk();

	pkvar = find_secvar("PK", 3, &variable_bank);
	if (!pkvar) {
		pkvar = alloc_secvar(0);
		if (!pkvar)
			return OPAL_NO_MEM;

		memcpy(pkvar->var->key, "PK", 3);
		pkvar->var->key_len = 3;
		pkvar->flags |= SECVAR_FLAG_VOLATILE;
		list_add_tail(&variable_bank, &pkvar->link);
	}

	kekvar = find_secvar("KEK", 4, &variable_bank);
	if (!kekvar) {
		kekvar = alloc_secvar(0);
		if (!kekvar)
			return OPAL_NO_MEM;

		memcpy(kekvar->var->key, "KEK", 4);
		kekvar->var->key_len = 4;
		kekvar->flags |= SECVAR_FLAG_VOLATILE;
		list_add_tail(&variable_bank, &kekvar->link);
	}

	dbvar = find_secvar("db", 3, &variable_bank);
	if (!dbvar) {
		dbvar = alloc_secvar(0);
		if (!dbvar)
			return OPAL_NO_MEM;

		memcpy(dbvar->var->key, "db", 3);
		dbvar->var->key_len = 3;
		dbvar->flags |= SECVAR_FLAG_VOLATILE;
		list_add_tail(&variable_bank, &dbvar->link);
	}

	dbxvar = find_secvar("dbx", 4, &variable_bank);
	if (!dbxvar) {
		dbxvar = alloc_secvar(0);
		if (!dbxvar)
			return OPAL_NO_MEM;

		memcpy(dbxvar->var->key, "dbx", 4);
		dbxvar->var->key_len = 4;
		dbxvar->flags |= SECVAR_FLAG_VOLATILE;
		list_add_tail(&variable_bank, &dbxvar->link);
	}

	tsvar = find_secvar("TS", 3, &variable_bank);
	// Should only ever happen on first boot
	if (!tsvar) {
		tsvar = alloc_secvar(sizeof(struct efi_time) * 4);
		if (!tsvar)
			return OPAL_NO_MEM;

		memcpy(tsvar->var->key, "TS", 3);
		tsvar->var->key_len = 3;
		list_add_tail(&variable_bank, &tsvar->link);
	}
	timestamp_list = (struct efi_time *) tsvar->var->data;

	return OPAL_SUCCESS;
};

/**
 * Returns true if we are in Setup Mode
 *
 * Setup Mode is active if we have no PK.
 * Otherwise, we are in user mode.
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

static int check_timestamp(char *key, struct efi_time *timestamp)
{
	struct efi_time *prev;
	int off;

	if (!strncmp(key, "PK", 3))
		off = 0;
	else if (!strncmp(key, "KEK", 4))
		off = 1;
	else if (!strncmp(key, "db", 3))
		off = 2;
	else if (!strncmp(key, "dbx", 4))
		off = 3;
	else
		return OPAL_PERMISSION;	// unexpected variable name?

	prev = &timestamp_list[off];

	// Compare timestamps
	// NOTE: this doesn't work, but this comparison is gonna be tedious
	//  WHY do they have to be 128-bits total
	//  64-bit UNIX timestamps are PERFECTLY FINE
	//  WHHYYYYYYY
	if (*((uint64_t *) prev) <= *((uint64_t *) timestamp)) // this MIGHT work well enough
		return OPAL_PERMISSION;

	// Update the TS variable with the new timestamp
	memcpy(prev, timestamp, sizeof(struct efi_time));

	return OPAL_SUCCESS;
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

/*
 * Verify the PKCS7 signature on the signed data.
 */
static int verify_signature(void *auth_buffer, char *newcert,
		uint64_t new_data_size, struct secvar *avar)
{
	struct efi_variable_authentication_2 *auth;
	mbedtls_pkcs7 *pkcs7;
	mbedtls_x509_crt x509;
	char *checkpkcs7cert;
	char *signing_cert;
	char *x509_buf;
	int len;
	int signing_cert_size;
	int rc;
	char *errbuf;

	auth = auth_buffer;


	len  = get_pkcs7_len(auth);

	pkcs7 = malloc(sizeof(struct mbedtls_pkcs7));
	mbedtls_pkcs7_init(pkcs7);

	rc = mbedtls_pkcs7_parse_der(
			(const unsigned char *)auth->auth_info.cert_data,
			(const unsigned int)len, pkcs7);
	if (rc) {
		prlog(PR_ERR, "Parsing pkcs7 failed %04x\n", rc);
		goto pkcs7out;
	}

	checkpkcs7cert = zalloc(2048);
	mbedtls_x509_crt_info(checkpkcs7cert, 2048, "CRT:", &(pkcs7->signed_data.certs));	
	prlog(PR_DEBUG, "%s \n", checkpkcs7cert);
	free(checkpkcs7cert);

	prlog(PR_INFO, "Load the signing certificate from the keystore");

	signing_cert_size = get_esl_cert_size(avar->data);
	signing_cert = zalloc(signing_cert_size);
	get_esl_cert(avar->data, &signing_cert);

	mbedtls_x509_crt_init(&x509);
	rc = mbedtls_x509_crt_parse(&x509, signing_cert, signing_cert_size);
	if(rc) {
		prlog(PR_INFO, "X509 certificate parsing failed %04x\n", rc);
		goto signout;
	}

	x509_buf = zalloc(2048);
	mbedtls_x509_crt_info(x509_buf, 2048, "CRT:", &x509);
	prlog(PR_INFO, "%s \n", x509_buf);
	free(x509_buf);

	rc = mbedtls_pkcs7_signed_data_verify(pkcs7, &x509, newcert, new_data_size);

	if (rc) {
		errbuf = zalloc(1024);
		mbedtls_strerror(rc, errbuf, 1024);
		prlog(PR_INFO, "Signature Verification failed %02x %s\n", rc, errbuf);
		free(errbuf);
		goto signout;
	}

	prlog(PR_INFO, "Signature Verification passed\n");

signout:
	free(signing_cert);

pkcs7out:
	free(pkcs7);

	return rc;
}


/**
 * Create the single buffer
 * name || vendor guid || attributes || timestamp || newcontent 
 * which is submitted as signed by the user.
 */
static int get_data_to_verify(char *key, char *new_data,
		uint64_t new_data_size,
		char **buffer,
		uint64_t *buffer_size, struct efi_time *timestamp)
{
	le32 attr = cpu_to_le32(SECVAR_ATTRIBUTES);
	int size = 0;
	int varlen;
	char *wkey;
	uuid_t guid;

	if (key_equals(key, "PK")
	    || key_equals(key, "KEK"))
		guid = EFI_GLOBAL_VARIABLE_GUID;

	if (key_equals(key, "db")
	    || key_equals(key, "dbx"))
		guid = EFI_IMAGE_SECURITY_DATABASE_GUID;
		
	// Convert utf8 name to ucs2 width
	varlen = strlen(key) * 2;
	wkey = utf8_to_ucs2(key, strlen(key));

	// Prepare the single buffer
	*buffer_size = varlen + UUID_SIZE + sizeof(attr)
		       + sizeof(struct efi_time) + new_data_size;
	*buffer = zalloc(*buffer_size);

	memcpy(*buffer + size, wkey, varlen);
	size = size + varlen;
	memcpy(*buffer + size, &guid, sizeof(guid));
	size = size + sizeof(guid);
	memcpy(*buffer + size, &attr, sizeof(attr));
	size = size + sizeof(attr);
	memcpy(*buffer + size, timestamp , sizeof(struct efi_time));
	size = size + sizeof(struct efi_time);

	memcpy(*buffer + size, new_data, new_data_size);
	size = size + new_data_size;

	free(wkey);

	return 0;
}

static int edk2_compat_process(void)
{
	char *auth_buffer = NULL;
	uint64_t auth_buffer_size = 0;
	struct efi_time *timestamp = NULL;
	const char *key_authority[3];
	char *newesl = NULL;
	uint64_t new_data_size = 0;
	char *tbhbuffer = NULL;
	uint64_t tbhbuffersize = 0;
	struct secvar_node *anode = NULL;
	struct secvar_node *node = NULL;
	int rc = 0;
	int pk_updated = 0;
	int i;

	setup_mode = is_setup_mode();

	prlog(PR_INFO, "Setup mode = %d\n", setup_mode);

	/* Loop through each command in the update bank.
	 * If any command fails, it just loops out of the update bank.
	 * It should also clear the update bank.
	 */
	list_for_each(&update_bank, node, link) {

		/* Submitted data is auth_2 descriptor + new ESL data
		 * Extract the auth_2 2 descriptor
		 */
		prlog(PR_INFO, "update for %s\n", node->var->key);
		auth_buffer_size = get_auth_descriptor2(node->var->data, &auth_buffer);
		if (auth_buffer_size <= 0)
			return OPAL_PARAMETER;

		if (node->var->data_size < auth_buffer_size) {
			rc = OPAL_PARAMETER;
			goto out;
		}

		rc = get_timestamp_from_auth(auth_buffer, &timestamp);
		if (rc < 0)
			goto out;	

		rc = check_timestamp(node->var->key, timestamp);
		if (rc)
			goto out;

		/* Calculate the size of new ESL data */
		new_data_size = node->var->data_size - auth_buffer_size;
		newesl = zalloc(new_data_size);
		memcpy(newesl, node->var->data + auth_buffer_size, new_data_size);

		if (!setup_mode) {
			/* Prepare the data to be verified */
			rc = get_data_to_verify(node->var->key, newesl,
						new_data_size, &tbhbuffer,
						&tbhbuffersize, timestamp);
		
			/* Get the authority to verify the signature */
			get_key_authority(key_authority, node->var->key);
			i = 0;

			/* Try for all the authorities that are allowed to sign.
			 * For eg. db/dbx can be signed by both PK or KEK
			 */
			while (key_authority[i] != NULL) {
				prlog(PR_DEBUG, "key is %s\n", node->var->key);
				prlog(PR_DEBUG, "key authority is %s\n", key_authority[i]);
				anode = find_secvar(key_authority[i], strlen(key_authority[i]) + 1,
						    &variable_bank);
				if (!anode) {
					rc = OPAL_PERMISSION;
					goto out;
				}
				if (anode->var->data_size == 0) {
					rc = OPAL_PERMISSION;
					goto out;
				}

				/* Verify the signature */
				rc = verify_signature(auth_buffer, tbhbuffer,
						      tbhbuffersize, anode->var);

				/* Break if signature verification is successful */
				if (!rc)
					break;
				i++;
			}
		}

		if (rc)
			goto out;

		/*
		 * If reached here means, signature is verified so update the
		 * value in the variable bank
		 */
		add_to_variable_bank(node->var, newesl, new_data_size);

		/* If the PK is updated, update the secure boot state of the
		 * system at the end of processing */
		if (key_equals(node->var->key, "PK")) {
			pk_updated = 1;
			setup_mode = 0;
		}
	}

	if (pk_updated) {
		// Store the updated pk in TPMNV on p9
		if (proc_gen == proc_gen_p9) {
			rc = edk2_p9_write_pk();
			prlog(PR_INFO, "edk2_p9_write rc=%d\n", rc);
		}
	}

out:
	if (auth_buffer)
		free(auth_buffer);
	if (newesl)
		free(newesl);
	if (tbhbuffer)
		free(tbhbuffer);

	clear_bank_list(&update_bank);

	return rc;
}

static int edk2_compat_post_process(void)
{
	if (!setup_mode) {
		secvar_set_secure_mode();
		prlog(PR_INFO, "Enforcing OS secure mode\n");
	}

	return 0;
}

static int edk2_compat_validate(struct secvar *var)
{

	//Checks if the update is for supported
	//Non-volatile secure variales
	if (key_equals(var->key, "PK")
	    || key_equals(var->key, "KEK")
	    || key_equals(var->key, "db")
	    || key_equals(var->key, "dbx"))
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
	.post_process = edk2_compat_post_process,
	.validate = edk2_compat_validate,
	.compatible = "ibm,edk2-compat-v1",
};
