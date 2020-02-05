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
#include <mbedtls/error.h>
#include <device.h>
#include "libstb/crypto/pkcs7/pkcs7.h"
#include "edk2.h"
#include "opal-api.h"
#include "../secvar.h"
#include "../secvar_devtree.h"

static bool setup_mode;

/* Converts utf8 string to ucs2 */
static char *utf8_to_ucs2(const char *key, size_t keylen)
{
	int i;
	char *str;

	str = zalloc(keylen * 2);
	if (!str)
		return NULL;

	for (i = 0; i < keylen*2; key++) {
		str[i++] = *key;
		str[i++] = '\0';
	}

	return str;
}

/* Returns true if key1 = key2 */
static bool key_equals(const char *key1, const char *key2)
{
	if (!strncmp(key1, key2, strlen(key1)))
		return true;

	return false;
}

/**
 * Returns the authority that can sign the given key update
 */
static void get_key_authority(const char *ret[3], const char *key)
{
	int i = 0;

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

/* Returns the size of the complete ESL. */
static int get_esl_signature_list_size(char *buf, size_t buflen)
{
	EFI_SIGNATURE_LIST list;

	if (buflen < sizeof(EFI_SIGNATURE_LIST))
		return OPAL_PARAMETER;

	memcpy(&list, buf, sizeof(EFI_SIGNATURE_LIST));

	prlog(PR_DEBUG, "size of signature list size is %u\n", le32_to_cpu(list.SignatureListSize));

	return le32_to_cpu(list.SignatureListSize);
}

/* Copies the certificate from the ESL into cert buffer and returns the size
 * of the certificate
 */
static int get_esl_cert(char *buf, size_t buflen, char **cert)
{
	int sig_data_offset;
	size_t size;
	EFI_SIGNATURE_LIST list;

	if (buflen < sizeof(EFI_SIGNATURE_LIST))
		return OPAL_PARAMETER;

	memcpy(&list, buf, sizeof(EFI_SIGNATURE_LIST));

	size = le32_to_cpu(list.SignatureSize) - sizeof(uuid_t);
	if (!size) {
		return OPAL_PERMISSION;
	}

	if (!cert)
		return OPAL_PARAMETER;
	*cert = zalloc(size);
	if (!(*cert))
		return OPAL_NO_MEM;

	prlog(PR_DEBUG,"size of signature list size is %u\n", le32_to_cpu(list.SignatureListSize));
	prlog(PR_DEBUG, "size of signature header size is %u\n", le32_to_cpu(list.SignatureHeaderSize));
	prlog(PR_DEBUG, "size of signature size is %u\n", le32_to_cpu(list.SignatureSize));

	sig_data_offset = sizeof(list) + le32_to_cpu(list.SignatureHeaderSize) + 16 * sizeof(uint8_t);
	
	memcpy(*cert, buf + sig_data_offset, size);

	return size;
}

/* Extracts size of the PKCS7 signed data embedded in the
 * struct Authentication 2 Descriptor Header.
 */
static int get_pkcs7_len(struct efi_variable_authentication_2 *auth)
{
	uint32_t dw_length; 
	size_t size;

	if (!auth)
		return OPAL_PARAMETER;
	
	dw_length = le32_to_cpu(auth->auth_info.hdr.dw_length);
	size = dw_length - (sizeof(auth->auth_info.hdr.dw_length)
			+ sizeof(auth->auth_info.hdr.w_revision)
			+ sizeof(auth->auth_info.hdr.w_certificate_type)
			+ sizeof(auth->auth_info.cert_type));

	return size;
}

/* This function outputs the Authentication 2 Descriptor in the
 * auth_buffer and returns the size of the buffer.
 */
static int get_auth_descriptor2(void *buf, size_t buflen, char **auth_buffer)
{
	struct efi_variable_authentication_2 *auth = NULL;
	size_t auth_buffer_size;
	int len;

	if (buflen < sizeof(struct efi_variable_authentication_2))
			return OPAL_PARAMETER;

	auth = buf;

	len = get_pkcs7_len(auth);

	/* We need PKCS7 data else there is no signature */
	if (len <= 0)
		return OPAL_PARAMETER;

	if (!auth_buffer)
		return OPAL_PARAMETER;

	auth_buffer_size = sizeof(auth->timestamp) + sizeof(auth->auth_info.hdr)
			   + sizeof(auth->auth_info.cert_type) + len;

	if (auth_buffer_size <= 0)
		return OPAL_PARAMETER;

	*auth_buffer = zalloc(auth_buffer_size);
	if (!(*auth_buffer))
		return OPAL_NO_MEM;

	memcpy(*auth_buffer, buf, auth_buffer_size);

	return auth_buffer_size;
}

/* Check that PK has single ESL */
static bool is_single_pk(char *data, size_t data_size)
{
	char *auth_buffer = NULL;
	char *newesl = NULL;
	int auth_buffer_size;
	int new_data_size;
	int esllistsize;

	/* Calculate the size of the authentication buffer */
	auth_buffer_size = get_auth_descriptor2(data, data_size, &auth_buffer);
	free(auth_buffer);
	if (auth_buffer_size <= 0)
		return false;

	/* Calculate the size of new ESL data */
	new_data_size = data_size - auth_buffer_size;
	if (!new_data_size)
		return true;

	newesl = zalloc(new_data_size);
	/* If there is an error in allocation, we cannot say anything about
	 * the data so do not validate it
	 */ 
	if (!newesl)
		return false;

	memcpy(newesl, data + auth_buffer_size, new_data_size);

	esllistsize = get_esl_signature_list_size(newesl, new_data_size);
	free(newesl);
	/* If there is failure in parsing the new data, we cannot say anything
	 * about the data so do not validate it
	 */ 
	if (esllistsize <= 0)
		return false;

	/* Here check if the new data is actually bigger than a single
	 * certificate
	 */
	if (new_data_size > esllistsize)
		return false;

	return true;
}

/*
 * Initializes supported variables as empty if not loaded from
 * storage. Variables are initialized as volatile if not found.
 * Updates should clear this flag.
ec*
 * Returns OPAL Error if anything fails in initialization
 */
static int edk2_compat_pre_process(void)
{
	struct secvar_node *pkvar;
	struct secvar_node *kekvar;
	struct secvar_node *dbvar;
	struct secvar_node *dbxvar;
	struct secvar_node *tsvar;
	char timestamp[sizeof(struct efi_time) * 4];

	pkvar = find_secvar("PK", 3, &variable_bank);
	if (!pkvar) {
		pkvar = new_secvar("PK", 3, NULL, 0);
		if (!pkvar)
			return OPAL_NO_MEM;

		/* Do I still need to set the flag, if yes can this
		 * also be passed as function parameter as suggested
		 * by Stefan */
		pkvar->flags |= SECVAR_FLAG_VOLATILE;
		list_add_tail(&variable_bank, &pkvar->link);
	}
	if (pkvar->var->data_size == 0)
		setup_mode = true;
	else
		setup_mode = false;

	kekvar = find_secvar("KEK", 4, &variable_bank);
	if (!kekvar) {
		kekvar = new_secvar("KEK", 4, NULL, 0);
		if (!kekvar)
			return OPAL_NO_MEM;

		kekvar->flags |= SECVAR_FLAG_VOLATILE;
		list_add_tail(&variable_bank, &kekvar->link);
	}

	dbvar = find_secvar("db", 3, &variable_bank);
	if (!dbvar) {
		dbvar = new_secvar("db", 3, NULL, 0);
		if (!dbvar)
			return OPAL_NO_MEM;

		dbvar->flags |= SECVAR_FLAG_VOLATILE;
		list_add_tail(&variable_bank, &dbvar->link);
	}

	dbxvar = find_secvar("dbx", 4, &variable_bank);
	if (!dbxvar) {
		dbxvar = new_secvar("dbx", 4, NULL, 0);
		if (!dbxvar)
			return OPAL_NO_MEM;

		dbxvar->flags |= SECVAR_FLAG_VOLATILE;
		list_add_tail(&variable_bank, &dbxvar->link);
	}

	/* Should only ever happen on first boot */
	tsvar = find_secvar("TS", 3, &variable_bank);
	if (!tsvar) {
		//How to pass the empty data here ?
		memset(timestamp, 0, sizeof(timestamp));
		tsvar = new_secvar("TS", 3, timestamp, sizeof(struct efi_time) * 4);
		if (!tsvar)
			return OPAL_NO_MEM;

		list_add_tail(&variable_bank, &tsvar->link);
		/* Is any flag needed here ? */
		//tsvar->flags |= SECVAR_FLAG_VOLATILE;
	}

	return OPAL_SUCCESS;
};

/* Update the variable with the new value. */
static int add_to_variable_bank(struct secvar *secvar, void *data, uint64_t dsize)
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
	/* Clear the volatile bit when updated */
	node->flags &= ~SECVAR_FLAG_VOLATILE;

	if ((!strncmp(secvar->key, "PK", 3))
	     || (!strncmp(secvar->key, "HWKEYHASH", 9)))
		node->flags |= SECVAR_FLAG_PRIORITY;

	return 0;
}

static struct efi_time *get_last_timestamp(const char *key)
{
	struct secvar_node *node;
	char *timestamp_list;
	u8 off;

	node = find_secvar("TS", 3, &variable_bank);

	/* We cannot find Timestamp variable, did someone tamper it ? */
	if (!node)
		return NULL;

	if (!strncmp(key, "PK", 3))
		off = 0;
	else if (!strncmp(key, "KEK", 4))
		off = 1;
	else if (!strncmp(key, "db", 3))
		off = 2;
	else if (!strncmp(key, "dbx", 4))
		off = 3;
	else
		return NULL;	// unexpected variable name?

	timestamp_list = node->var->data;
	if (!timestamp_list)
		return NULL;

	return &((struct efi_time *)timestamp_list)[off];
}

// Update the TS variable with the new timestamp
static int update_timestamp(char *key, struct efi_time *timestamp)
{
	struct efi_time *prev;

	prev = get_last_timestamp(key);
	if (prev == NULL)
		return OPAL_PARAMETER;

	memcpy(prev, timestamp, sizeof(struct efi_time));

	prlog(PR_DEBUG, "updated prev year is %d month %d day %d\n",
	       le16_to_cpu(prev->year), prev->month, prev->day);

	return OPAL_SUCCESS;
}

static int check_timestamp(char *key, struct efi_time *timestamp)
{
	struct efi_time *prev;

	prev = get_last_timestamp(key);
	if (prev == NULL)
		return OPAL_PARAMETER;

	printf("timestamp year is %d month %d day %d\n", le16_to_cpu(timestamp->year), timestamp->month, timestamp->day);
	printf("prev year is %d month %d day %d\n", le16_to_cpu(prev->year), prev->month, prev->day);
	if (le16_to_cpu(timestamp->year) > le16_to_cpu(prev->year))
		return OPAL_SUCCESS;
	if (le16_to_cpu(timestamp->year) < le16_to_cpu(prev->year))
		return OPAL_PERMISSION;

	if (timestamp->month > prev->month)
		return OPAL_SUCCESS;
	if (timestamp->month < prev->month)
		return OPAL_PERMISSION;

	if (timestamp->day > prev->day)
		return OPAL_SUCCESS;
	if (timestamp->day < prev->day)
		return OPAL_PERMISSION;

	if (timestamp->hour > prev->hour)
		return OPAL_SUCCESS;
	if (timestamp->hour < prev->hour)
		return OPAL_PERMISSION;

	if (timestamp->minute > prev->minute)
		return OPAL_SUCCESS;
	if (timestamp->minute < prev->minute)
		return OPAL_PERMISSION;

	if (timestamp->second > prev->second)
		return OPAL_SUCCESS;

	/* Time less than or equal to is considered as replay*/
	if (timestamp->second <= prev->second)
		return OPAL_PERMISSION;

	/* nanosecond, timezone, daylight and pad2 are meant to be zero */

	return OPAL_SUCCESS;
}

static int get_pkcs7(struct efi_variable_authentication_2 *auth, mbedtls_pkcs7 **pkcs7)
{
	char *checkpkcs7cert = NULL;
	int len;
	int rc;

	len = get_pkcs7_len(auth);
	if (len <= 0)
		return OPAL_PARAMETER;		

	if (!pkcs7)
		return OPAL_PARAMETER;

	*pkcs7 = malloc(sizeof(struct mbedtls_pkcs7));
	if (!(*pkcs7))
		return OPAL_NO_MEM;

	mbedtls_pkcs7_init(*pkcs7);
	rc = mbedtls_pkcs7_parse_der(
			(const unsigned char *)auth->auth_info.cert_data,
			(const unsigned int)len, *pkcs7);
	if (rc) {
		prlog(PR_ERR, "Parsing pkcs7 failed %04x\n", rc);
		mbedtls_pkcs7_free(*pkcs7);
		return rc;
	}

	checkpkcs7cert = zalloc(2048);
	if (!checkpkcs7cert) {
		mbedtls_pkcs7_free(*pkcs7);
		return OPAL_NO_MEM;
	}

	rc = mbedtls_x509_crt_info(checkpkcs7cert, 2048, "CRT:", &((*pkcs7)->signed_data.certs));	
	if (rc)
		rc = OPAL_PARAMETER;
	else
		prlog(PR_DEBUG, "%s \n", checkpkcs7cert);

	free(checkpkcs7cert);
	mbedtls_pkcs7_free(*pkcs7);

	return OPAL_SUCCESS;
}

/*
 * Verify the PKCS7 signature on the signed data.
 */
static int verify_signature(void *auth_buffer, char *newcert,
		uint64_t new_data_size, struct secvar *avar)
{
	struct efi_variable_authentication_2 *auth = NULL;
	mbedtls_pkcs7 *pkcs7 = NULL;
	mbedtls_x509_crt x509;
	char *signing_cert = NULL;
	char *x509_buf = NULL;
	int signing_cert_size;
	int rc;
	char *errbuf;
	int eslvarsize;
	int eslsize;
	int offset = 0;

	if (!auth_buffer)
		return OPAL_PARAMETER;

	auth = auth_buffer;

	/* Extract the pkcs7 from the auth structure */
	rc  = get_pkcs7(auth, &pkcs7);
	/* Failure to parse pkcs7 implies bad command */
	if (rc < 0)
		return OPAL_PARAMETER;		

	prlog(PR_INFO, "Load the signing certificate from the keystore");

	eslvarsize = avar->data_size;

	/* Variable is not empty */
	while (eslvarsize > 0) {
		prlog(PR_INFO, "esl var size size is %d offset is %d\n", eslvarsize, offset);
		if (eslvarsize < sizeof(EFI_SIGNATURE_LIST))
			break;

		/* Calculate the size of the ESL */
		eslsize = get_esl_signature_list_size(avar->data + offset, eslvarsize);
		/* If could not extract the size */
		if (eslsize <= 0)
			break;

		/* Extract the certificate from the ESL */
		signing_cert_size = get_esl_cert(avar->data + offset, eslvarsize, &signing_cert);
		if (signing_cert_size <= 0)
			return OPAL_PARAMETER;

		mbedtls_x509_crt_init(&x509);
		rc = mbedtls_x509_crt_parse(&x509, signing_cert, signing_cert_size);

		/* If failure in parsing the certificate, try next */
		if(rc) {
			prlog(PR_INFO, "X509 certificate parsing failed %04x\n", rc);
			goto next;
		}

		x509_buf = zalloc(2048);
		rc = mbedtls_x509_crt_info(x509_buf, 2048, "CRT:", &x509);

		/* If failure in reading the certificate, try next */
		if (rc < 0)
			goto next;

		prlog(PR_INFO, "%s \n", x509_buf);
		free(x509_buf);

		/* Verify the signature */
		rc = mbedtls_pkcs7_signed_data_verify(pkcs7, &x509, newcert, new_data_size);

		/* If you find a signing certificate, you are done */
		if (rc == 0) {
			prlog(PR_INFO, "Signature Verification passed\n");
			break;
		}

		errbuf = zalloc(1024);
		mbedtls_strerror(rc, errbuf, 1024);
		prlog(PR_INFO, "Signature Verification failed %02x %s\n", rc, errbuf);
		free(errbuf);

next:
		/* Look for the next ESL */
		offset = offset + eslsize;
		eslvarsize = eslvarsize - eslsize;
		mbedtls_x509_crt_free(&x509);
		free(signing_cert);

	}

	mbedtls_x509_crt_free(&x509);
	free(signing_cert);
	mbedtls_pkcs7_free(pkcs7);
	free(pkcs7);

	return rc;
}


/**
 * Create the single buffer
 * name || vendor guid || attributes || timestamp || newcontent 
 * which is submitted as signed by the user.
 * Returns number of bytes in the new buffer, else negative error
 * code.
 */
static int get_data_to_verify(char *key, char *new_data,
		size_t new_data_size,
		char **buffer,
		size_t *buffer_size, struct efi_time *timestamp)
{
	le32 attr = cpu_to_le32(SECVAR_ATTRIBUTES);
	size_t offset = 0;
	size_t varlen;
	char *wkey;
	uuid_t guid;

	if (key_equals(key, "PK")
	    || key_equals(key, "KEK"))
		guid = EFI_GLOBAL_VARIABLE_GUID;
	else if (key_equals(key, "db")
	    || key_equals(key, "dbx"))
		guid = EFI_IMAGE_SECURITY_DATABASE_GUID;
		
	// Convert utf8 name to ucs2 width
	varlen = strlen(key) * 2;
	wkey = utf8_to_ucs2(key, strlen(key));

	// Prepare the single buffer
	*buffer_size = varlen + UUID_SIZE + sizeof(attr)
		       + sizeof(struct efi_time) + new_data_size;
	*buffer = zalloc(*buffer_size);
	if (!*buffer)
		return OPAL_NO_MEM;

	memcpy(*buffer + offset, wkey, varlen);
	offset = offset + varlen;
	memcpy(*buffer + offset, &guid, sizeof(guid));
	offset = offset + sizeof(guid);
	memcpy(*buffer + offset, &attr, sizeof(attr));
	offset = offset + sizeof(attr);
	memcpy(*buffer + offset, timestamp , sizeof(struct efi_time));
	offset = offset + sizeof(struct efi_time);

	memcpy(*buffer + offset, new_data, new_data_size);
	offset = offset + new_data_size;

	free(wkey);

	return offset;
}

static int clear_all_os_keys(void)
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

/* Check if physical presence is asserted */
static bool is_physical_presence_asserted(void)
{
        struct dt_node *secureboot;

        secureboot = dt_find_by_path(dt_root, "ibm,secureboot");
        if (!secureboot)
                return false;

        if (dt_find_property(secureboot, "clear-os-pk")
            || dt_find_property(secureboot, "clear-all-keys")
            || dt_find_property(secureboot, "clear-mfg-keys"))
                return true;

        return false;
}

/* Compares the hw-key-hash from device tree to the value stored in
 * the TPM to ensure it is not modified */
static int verify_hw_key_hash(void)
{
	const char *hw_key_hash;
        struct dt_node *secureboot;
	struct secvar_node *node;

        secureboot = dt_find_by_path(dt_root, "ibm,secureboot");
        if (!secureboot)
                return false;

	hw_key_hash = dt_prop_get(secureboot, "hw-key-hash");

	if (!hw_key_hash)
		return OPAL_PERMISSION;

	/* This value is from TPM */
	node = find_secvar("HWKEYHASH", 9, &variable_bank);
	if (!node)
		return OPAL_PERMISSION;

	if (memcmp(hw_key_hash, node->var->data, node->var->data_size) != 0)
		return OPAL_PERMISSION;

	return OPAL_SUCCESS;
}

/* Adds hw-key-hash */
static int add_hw_key_hash(void)
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

	node = find_secvar("HWKEYHASH", 9, &variable_bank);
	if (!node) {
		node = new_secvar("HWKEYHASH", 9, (char *)hw_key_hash, hw_key_hash_size);
		list_add_tail(&variable_bank, &node->link);
		return OPAL_SUCCESS;
	}

	/* Either HWKEYHASH should be created for the first time or
	 * be zero data size */
	if (node && node->var->data_size)
		return OPAL_PERMISSION;

	node->var->data_size = 9;
	memcpy(node->var->data, hw_key_hash, hw_key_hash_size);

	return OPAL_SUCCESS;
}

/* Delete hw-key-hash */
static int delete_hw_key_hash(void)
{
	struct secvar_node *node;
	int rc;

	node = find_secvar("HWKEYHASH", 9, &variable_bank);
	if (!node)
		return OPAL_SUCCESS;

	rc = add_to_variable_bank(node->var, NULL, 0);
	return rc;
}

static int edk2_compat_process(void)
{
	char *auth_buffer = NULL;
	size_t auth_buffer_size = 0;
	struct efi_time *timestamp = NULL;
	const char *key_authority[3];
	char *newesl = NULL;
	size_t new_data_size = 0;
	char *tbhbuffer = NULL;
	size_t tbhbuffersize = 0;
	struct secvar_node *anode = NULL;
	struct secvar_node *node = NULL;
	int rc = 0;
	int i;

	prlog(PR_INFO, "Setup mode = %d\n", setup_mode);

	/* Check if physical presence is asserted */
	if (is_physical_presence_asserted()) {
		prlog(PR_INFO, "Physical presence asserted to clear OS Secure boot keys\n");
		clear_all_os_keys();
		setup_mode = true;
	}

	/* Check HW-KEY-HASH */
	if (!setup_mode) {
		rc = verify_hw_key_hash();
		if (rc < 0) {
			node = find_secvar("PK", 3, &variable_bank);
			if (node)
				add_to_variable_bank(node->var, NULL, 0);
		}
	}

	/* Loop through each command in the update bank.
	 * If any command fails, it just loops out of the update bank.
	 * It should also clear the update bank.
	 */
	list_for_each(&update_bank, node, link) {

		/* Submitted data is auth_2 descriptor + new ESL data
		 * Extract the auth_2 2 descriptor
		 */
 		printf("setup mode is %d\n", setup_mode);		
		prlog(PR_INFO, "update for %s\n", node->var->key);
		auth_buffer_size = get_auth_descriptor2(node->var->data,
							node->var->data_size,
							&auth_buffer);
		if ((auth_buffer_size <= 0)
		     || (node->var->data_size < auth_buffer_size)) {
			rc = OPAL_PARAMETER;
			goto out;
		}

		timestamp = (struct efi_time *)auth_buffer;

		rc = check_timestamp(node->var->key, timestamp);
		/* Failure implies probably an older command being resubmitted */
		if (rc)
			goto out;

		/* Calculate the size of new ESL data */
		new_data_size = node->var->data_size - auth_buffer_size;
		if (new_data_size <= 0) {
			rc = OPAL_PARAMETER;
			goto out;
		}
		newesl = zalloc(new_data_size);
		if (!newesl) {
			rc = OPAL_NO_MEM;
			goto out;
		}
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
				if (!anode || !anode->var->data_size) {
					i++;
					continue;
				}

				/* Verify the signature */
				rc = verify_signature(auth_buffer, tbhbuffer,
						      tbhbuffersize, anode->var);

				/* Break if signature verification is successful */
				if (rc == 0)
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
		rc = add_to_variable_bank(node->var, newesl, new_data_size);
		if (rc)
			goto out;
		// Update the TS variable with the new timestamp
		rc = update_timestamp(node->var->key, timestamp);
		if (rc)
			goto out;

		/* If the PK is updated, update the secure boot state of the
		 * system at the end of processing */
		if (key_equals(node->var->key, "PK")) {
			if(new_data_size == 0) {
				setup_mode = true;
				rc = delete_hw_key_hash();
				if (rc < 0)
					return OPAL_INTERNAL_ERROR;
			} else {
				setup_mode = false;
				rc = add_hw_key_hash();
				if (rc < 0)
					return OPAL_INTERNAL_ERROR;
			}
			printf("setup mode is %d\n", setup_mode);
		}
	}

out:
	free(auth_buffer);
	free(newesl);
	free(tbhbuffer);
	clear_bank_list(&update_bank);

	return rc;
}

static int edk2_compat_post_process(void)
{
	printf("setup mode is %d\n", setup_mode);
	if (!setup_mode) {
		secvar_set_secure_mode();
		prlog(PR_INFO, "Enforcing OS secure mode\n");
	}

	return OPAL_SUCCESS;
}

static bool is_pkcs7_sig_format(void *data)
{
	struct efi_variable_authentication_2 *auth = data;
	uuid_t pkcs7_guid = EFI_CERT_TYPE_PKCS7_GUID;

	if(!(memcmp(&auth->auth_info.cert_type, &pkcs7_guid, 16) == 0))
		return false;

	return true;
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

	/* PK update should contain single ESL. */
	if (key_equals(var->key, "PK")) {
		printf("check if single PK\n");
		if (!is_single_pk(var->data, var->data_size)) {
			printf("not single pk\n");
			return OPAL_PARAMETER;
		}
	}

	/* Check that signature type is PKCS7 */
	if (!is_pkcs7_sig_format(var->data))
		return OPAL_PARAMETER;

	//Some more checks needs to be added:
	// - check guid
	// - check auth struct
	// - possibly check signature? can't add but can validate

	return OPAL_SUCCESS;
};

struct secvar_backend_driver edk2_compatible_v1 = {
	.pre_process = edk2_compat_pre_process,
	.process = edk2_compat_process,
	.post_process = edk2_compat_post_process,
	.validate = edk2_compat_validate,
	.compatible = "ibm,edk2-compat-v1",
};
