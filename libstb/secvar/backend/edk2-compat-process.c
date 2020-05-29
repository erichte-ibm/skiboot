// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */
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
#include <assert.h>
#include "libstb/crypto/pkcs7/pkcs7.h"
#include "edk2.h"
#include "../secvar.h"
#include "edk2-compat-process.h"

bool setup_mode;

int update_variable_in_bank(struct secvar *secvar, const char *data,
			    uint64_t dsize, struct list_head *bank)
{
	struct secvar_node *node;

	node = find_secvar(secvar->key, secvar->key_len, bank);
	if (!node)
		return OPAL_EMPTY;

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
	else
		node->flags |= SECVAR_FLAG_VOLATILE;

        /* Is it required to be set everytime ? */
	if ((!strncmp(secvar->key, "PK", 3))
	     || (!strncmp(secvar->key, "HWKH", 5)))
		node->flags |= SECVAR_FLAG_PRIORITY;

	return 0;
}

/* Expand char to wide character size */
static char *char_to_wchar(const char *key, size_t keylen)
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

/* Returns the authority that can sign the given key update */
static void get_key_authority(const char *ret[3], const char *key)
{
	int i = 0;

	if (key_equals(key, "PK")) {
		ret[i++] = "PK";
	} else if (key_equals(key, "KEK")) {
		ret[i++] = "PK";
	} else if (key_equals(key, "db") || key_equals(key, "dbx")) {
		ret[i++] = "KEK";
		ret[i++] = "PK";
	}

	ret[i] = NULL;
}

static EFI_SIGNATURE_LIST* get_esl_signature_list(const char *buf, size_t buflen)
{
	EFI_SIGNATURE_LIST *list = NULL;

	if (buflen < sizeof(EFI_SIGNATURE_LIST) || !buf)
		return NULL;

	list = (EFI_SIGNATURE_LIST *)buf;

	return list;
}

/* Returns the size of the complete ESL. */
static int32_t get_esl_signature_list_size(const char *buf, size_t buflen)
{
	EFI_SIGNATURE_LIST *list = get_esl_signature_list(buf, buflen);

	if (!list)
		return OPAL_PARAMETER;

	prlog(PR_DEBUG, "size of signature list size is %u\n",
			le32_to_cpu(list->SignatureListSize));

	return le32_to_cpu(list->SignatureListSize);
}

/* Copies the certificate from the ESL into cert buffer and returns the size
 * of the certificate
 */
static int get_esl_cert(const char *buf, size_t buflen, char **cert)
{
	size_t sig_data_offset;
	size_t size;
	EFI_SIGNATURE_LIST *list = get_esl_signature_list(buf, buflen);

	if (!list)
		return OPAL_PARAMETER;

	assert(cert != NULL);

	size = le32_to_cpu(list->SignatureSize) - sizeof(uuid_t);

	prlog(PR_DEBUG,"size of signature list size is %u\n",
			le32_to_cpu(list->SignatureListSize));
	prlog(PR_DEBUG, "size of signature header size is %u\n",
			le32_to_cpu(list->SignatureHeaderSize));
	prlog(PR_DEBUG, "size of signature size is %u\n",
			le32_to_cpu(list->SignatureSize));

	sig_data_offset = sizeof(EFI_SIGNATURE_LIST) + le32_to_cpu(list->SignatureHeaderSize)
		+ 16 * sizeof(uint8_t);
	if (sig_data_offset > buflen)
		return OPAL_PARAMETER;

	*cert = zalloc(size);
	if (!(*cert))
		return OPAL_NO_MEM;

	memcpy(*cert, buf + sig_data_offset, size);

	return size;
}

/* Extracts size of the PKCS7 signed data embedded in the
 * struct Authentication 2 Descriptor Header.
 */
static int get_pkcs7_len(const struct efi_variable_authentication_2 *auth)
{
	uint32_t dw_length;
	size_t size;

	assert(auth != NULL);

	dw_length = le32_to_cpu(auth->auth_info.hdr.dw_length);
	size = dw_length - (sizeof(auth->auth_info.hdr.dw_length)
			+ sizeof(auth->auth_info.hdr.w_revision)
			+ sizeof(auth->auth_info.hdr.w_certificate_type)
			+ sizeof(auth->auth_info.cert_type));

	return size;
}

int get_auth_descriptor2(const void *buf, size_t buflen, char **auth_buffer)
{
	const struct efi_variable_authentication_2 *auth = buf;
	int auth_buffer_size;
	int len;

	if (buflen < sizeof(struct efi_variable_authentication_2)
	    || !buf)
			return OPAL_PARAMETER;

	assert(auth_buffer != NULL);

	len = get_pkcs7_len(auth);

	/* We need PKCS7 data else there is no signature */
	if (len <= 0)
		return OPAL_PARAMETER;

	auth_buffer_size = sizeof(auth->timestamp) + sizeof(auth->auth_info.hdr)
			   + sizeof(auth->auth_info.cert_type) + len;

	*auth_buffer = zalloc(auth_buffer_size);
	if (!(*auth_buffer))
		return OPAL_NO_MEM;

	/* Extracts the auth descriptor from data excluding new ESL data */
	memcpy(*auth_buffer, buf, auth_buffer_size);

	return auth_buffer_size;
}

int validate_esl_list(char *key, char *esl, size_t size)
{
	int count = 0;
	int signing_cert_size;
	char *signing_cert = NULL;
	mbedtls_x509_crt x509;
	char *x509_buf = NULL;
	int eslvarsize = size;
	int eslsize;
	int rc = OPAL_SUCCESS;
	int offset = 0;

	while (eslvarsize > 0) {
		prlog(PR_DEBUG, "esl var size size is %d offset is %d\n", eslvarsize, offset);
		if (eslvarsize < sizeof(EFI_SIGNATURE_LIST))
			break;

		/* Calculate the size of the ESL */
		eslsize = get_esl_signature_list_size(esl, eslvarsize);
		/* If could not extract the size */
		if (eslsize <= 0) {
			prlog(PR_ERR, "Invalid size of the ESL\n");
			rc = OPAL_PARAMETER;
			break;
		}

		signing_cert_size = get_esl_cert(esl, eslvarsize, &signing_cert);
		if (signing_cert_size < 0) {
			rc = signing_cert_size;
			break;
		}

		mbedtls_x509_crt_init(&x509);
		rc = mbedtls_x509_crt_parse(&x509, signing_cert, signing_cert_size);

		/* If failure in parsing the certificate, exit */
		if(rc) {
			prlog(PR_INFO, "X509 certificate parsing failed %04x\n", rc);
			rc = OPAL_PARAMETER;
			break;
		}

		x509_buf = zalloc(CERT_BUFFER_SIZE);
		rc = mbedtls_x509_crt_info(x509_buf, CERT_BUFFER_SIZE, "CRT:", &x509);
		prlog(PR_INFO, "%s ", x509_buf);

		/* If failure in reading the certificate, exit */
		if (rc < 0) {
			prlog(PR_INFO, "Failed to show X509 certificate info %04x\n", rc);
			rc = OPAL_PARAMETER;
			free(x509_buf);
			break;
		}
		rc = 0;

		free(x509_buf);
		x509_buf = NULL;
		count++;

		/* Look for the next ESL */
		offset = offset + eslsize;
		eslvarsize = eslvarsize - eslsize;
		mbedtls_x509_crt_free(&x509);
		free(signing_cert);
		/* Since we are going to allocate again in the next iteration */
		signing_cert = NULL;
	}

	if (rc == OPAL_SUCCESS) {
		if (key_equals(key, "PK") && (count > 1)) {
			prlog(PR_ERR, "PK can only be one\n");
			rc = OPAL_PARAMETER;
		} else {
			rc = count;
		}
	}

	prlog(PR_INFO, "Total ESLs are %d\n", rc);
	return rc;
}

/* Get the timestamp for the last update of the give key */
static struct efi_time *get_last_timestamp(const char *key, char *last_timestamp)
{
	struct efi_time *timestamp = (struct efi_time*)last_timestamp;

	if (!last_timestamp)
		return NULL;

	if (!strncmp(key, "PK", 3))
		return &timestamp[0];
	else if (!strncmp(key, "KEK", 4))
		return &timestamp[1];
	else if (!strncmp(key, "db", 3))
		return &timestamp[2];
	else if (!strncmp(key, "dbx", 4))
		return &timestamp[3];
	else
		return NULL;

}

int update_timestamp(const char *key, const struct efi_time *timestamp, char *last_timestamp)
{
	struct efi_time *prev;

	prev = get_last_timestamp(key, last_timestamp);
	if (prev == NULL)
		return OPAL_INTERNAL_ERROR;

	memcpy(prev, timestamp, sizeof(struct efi_time));

	prlog(PR_DEBUG, "updated prev year is %d month %d day %d\n",
			le16_to_cpu(prev->year), prev->month, prev->day);

	return OPAL_SUCCESS;
}

static uint64_t* unpack_timestamp(const struct efi_time *timestamp)
{
	void *val;

	u16 year = le32_to_cpu(timestamp->year);

	val = zalloc(sizeof(uint64_t));
	if (!val)
		return NULL;

	/* pad1, nanosecond, timezone, daylight and pad2 are meant to be zero */
	memcpy(val, &(timestamp->pad1), 1);
	memcpy(val+1, &(timestamp->second), 1);
	memcpy(val+2, &(timestamp->minute), 1);
	memcpy(val+3, &(timestamp->hour), 1);
	memcpy(val+4, &(timestamp->day), 1);
	memcpy(val+5, &(timestamp->month), 1);
	memcpy(val+6, &year, 2);

	prlog(PR_DEBUG, "val is %llx\n", ((uint64_t*)val));
	return ((uint64_t*)val);
}

int check_timestamp(const char *key, const struct efi_time *timestamp,
		    char *last_timestamp)
{
	struct efi_time *prev;
	uint64_t *new = NULL;
	uint64_t *last = NULL;


	prev = get_last_timestamp(key, last_timestamp);
	if (prev == NULL)
		return OPAL_INTERNAL_ERROR;

	prlog(PR_DEBUG, "timestamp year is %d month %d day %d\n",
			le16_to_cpu(timestamp->year), timestamp->month,
			timestamp->day);
	prlog(PR_DEBUG, "prev year is %d month %d day %d\n",
			le16_to_cpu(prev->year), prev->month, prev->day);

	new = unpack_timestamp(timestamp);
	last = unpack_timestamp(prev);
	if (!new || !last)
		return OPAL_NO_MEM;

	if (*new > *last)
		return OPAL_SUCCESS;

	return OPAL_PERMISSION;
}

/* Extract PKCS7 from the authentication header */
static int get_pkcs7(const struct efi_variable_authentication_2 *auth,
		     mbedtls_pkcs7 **pkcs7)
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
	rc = mbedtls_pkcs7_parse_der( auth->auth_info.cert_data, len, *pkcs7);
	if (rc) {
		prlog(PR_ERR, "Parsing pkcs7 failed %04x\n", rc);
		mbedtls_pkcs7_free(*pkcs7);
		return rc;
	}

	checkpkcs7cert = zalloc(CERT_BUFFER_SIZE);
	if (!checkpkcs7cert) {
		mbedtls_pkcs7_free(*pkcs7);
		return OPAL_NO_MEM;
	}

	rc = mbedtls_x509_crt_info(checkpkcs7cert, CERT_BUFFER_SIZE, "CRT:",
			&((*pkcs7)->signed_data.certs));
	if (rc < 0) {
		prlog(PR_ERR, "Failed to parse the certificate in PKCS7 structure\n");
		rc = OPAL_PARAMETER;
	} else {
		rc = OPAL_SUCCESS;
		prlog(PR_DEBUG, "%s \n", checkpkcs7cert);
	}

	free(checkpkcs7cert);
	mbedtls_pkcs7_free(*pkcs7);

	return rc;
}

/* Verify the PKCS7 signature on the signed data. */
static int verify_signature(const struct efi_variable_authentication_2 *auth,
			    const char *newcert, const size_t new_data_size,
			    const struct secvar *avar)
{
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

	if (!auth)
		return OPAL_PARAMETER;

	/* Extract the pkcs7 from the auth structure */
	rc  = get_pkcs7(auth, &pkcs7);
	/* Failure to parse pkcs7 implies bad input. */
	if (rc != OPAL_SUCCESS)
		return OPAL_PARAMETER;

	prlog(PR_INFO, "Load the signing certificate from the keystore");

	eslvarsize = avar->data_size;

	/* Variable is not empty */
	while (eslvarsize > 0) {
		prlog(PR_DEBUG, "esl var size size is %d offset is %d\n", eslvarsize, offset);
		if (eslvarsize < sizeof(EFI_SIGNATURE_LIST))
			break;

		/* Calculate the size of the ESL */
		eslsize = get_esl_signature_list_size(avar->data + offset, eslvarsize);
		/* If could not extract the size */
		if (eslsize <= 0) {
			rc = OPAL_PARAMETER;
			break;
		}

		/* Extract the certificate from the ESL */
		signing_cert_size = get_esl_cert(avar->data + offset,
						 eslvarsize, &signing_cert);
		if (signing_cert_size < 0) {
			rc = signing_cert_size;
			break;
		}

		mbedtls_x509_crt_init(&x509);
		rc = mbedtls_x509_crt_parse(&x509, signing_cert, signing_cert_size);

		/* This should not happen, unless something corrupted in PNOR */
		if(rc) {
			prlog(PR_INFO, "X509 certificate parsing failed %04x\n", rc);
			rc = OPAL_INTERNAL_ERROR;
			break;
		}

		x509_buf = zalloc(CERT_BUFFER_SIZE);
		rc = mbedtls_x509_crt_info(x509_buf, CERT_BUFFER_SIZE, "CRT:", &x509);

		/* This should not happen, unless something corrupted in PNOR */
		if (rc < 0) {
			free(x509_buf);
			rc = OPAL_INTERNAL_ERROR;
			break;
		}

		prlog(PR_INFO, "%s \n", x509_buf);
		free(x509_buf);
		x509_buf = NULL;

		/* Verify the signature */
		rc = mbedtls_pkcs7_signed_data_verify(pkcs7, &x509, newcert,
						      new_data_size);

		/* If you find a signing certificate, you are done */
		if (rc == 0) {
			prlog(PR_INFO, "Signature Verification passed\n");
			mbedtls_x509_crt_free(&x509);
			break;
		}

		errbuf = zalloc(MBEDTLS_ERR_BUFFER_SIZE);
		mbedtls_strerror(rc, errbuf, MBEDTLS_ERR_BUFFER_SIZE);
		prlog(PR_INFO, "Signature Verification failed %02x %s\n",
				rc, errbuf);
		free(errbuf);

		/* Look for the next ESL */
		offset = offset + eslsize;
		eslvarsize = eslvarsize - eslsize;
		mbedtls_x509_crt_free(&x509);
		free(signing_cert);
		/* Since we are going to allocate again in the next iteration */
		signing_cert = NULL;

	}

	free(signing_cert);
	mbedtls_pkcs7_free(pkcs7);
	free(pkcs7);

	return rc;
}

/* Create the single buffer
 * name || vendor guid || attributes || timestamp || newcontent
 * which is submitted as signed by the user.
 * Returns number of bytes in the new buffer, else negative error
 * code.
 */
static int get_data_to_verify(char *key, char *new_data, size_t new_data_size,
			      char **buffer, size_t *buffer_size,
			      struct efi_time *timestamp)
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
	else
		return OPAL_INTERNAL_ERROR;

	/* Expand char name to wide character width */
	varlen = strlen(key) * 2;
	wkey = char_to_wchar(key, strlen(key));

	/* Prepare the single buffer */
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

bool is_pkcs7_sig_format(void *data)
{
	struct efi_variable_authentication_2 *auth = data;
	uuid_t pkcs7_guid = EFI_CERT_TYPE_PKCS7_GUID;

	if(!(memcmp(&auth->auth_info.cert_type, &pkcs7_guid, 16) == 0))
		return false;

	return true;
}

int process_update(struct secvar_node *update, char **newesl,
		   int *new_data_size, struct efi_time *timestamp,
		   struct list_head *bank, char *last_timestamp)
{
	struct efi_variable_authentication_2 *auth = NULL;
	char *auth_buffer = NULL;
	int auth_buffer_size = 0;
	const char *key_authority[3];
	char *tbhbuffer = NULL;
	size_t tbhbuffersize = 0;
	struct secvar_node *anode = NULL;
	int rc = 0;
	int i;

	/* We need to split data into authentication descriptor and new ESL */
	auth_buffer_size = get_auth_descriptor2(update->var->data,
						update->var->data_size,
						&auth_buffer);
	if ((auth_buffer_size < 0)
	     || (update->var->data_size < auth_buffer_size)) {
		prlog(PR_ERR, "Invalid auth buffer size\n");
		rc = auth_buffer_size;
		goto out;
	}

	auth = (struct efi_variable_authentication_2 *)auth_buffer;

	if (!timestamp) {
		rc = OPAL_INTERNAL_ERROR;
		goto out;
	}

	memcpy(timestamp, auth_buffer, sizeof(struct efi_time));

	rc = check_timestamp(update->var->key, timestamp, last_timestamp);
	/* Failure implies probably an older command being resubmitted */
	if (rc != OPAL_SUCCESS) {
		prlog(PR_INFO, "Timestamp verification failed for key %s\n", update->var->key);
		goto out;
	}

	/* Calculate the size of new ESL data */
	*new_data_size = update->var->data_size - auth_buffer_size;
	if (*new_data_size < 0) {
		prlog(PR_ERR, "Invalid new ESL (new data content) size\n");
		rc = OPAL_PARAMETER;
		goto out;
	}
	*newesl = zalloc(*new_data_size);
	if (!(*newesl)) {
		rc = OPAL_NO_MEM;
		goto out;
	}
	memcpy(*newesl, update->var->data + auth_buffer_size, *new_data_size);

	/* Validate the new ESL is in right format */
	rc = validate_esl_list(update->var->key, *newesl, *new_data_size);
	if (rc < 0) {
		prlog(PR_ERR, "ESL validation failed for key %s with error %04x\n",
		      update->var->key, rc);
		goto out;
	}

	if (setup_mode) {
		rc = OPAL_SUCCESS;
		goto out;
	}

	/* Prepare the data to be verified */
	rc = get_data_to_verify(update->var->key, *newesl, *new_data_size,
				&tbhbuffer, &tbhbuffersize, timestamp);

	/* Get the authority to verify the signature */
	get_key_authority(key_authority, update->var->key);
	i = 0;

	/* Try for all the authorities that are allowed to sign.
	 * For eg. db/dbx can be signed by both PK or KEK
	 */
	while (key_authority[i] != NULL) {
		prlog(PR_DEBUG, "key is %s\n", update->var->key);
		prlog(PR_DEBUG, "key authority is %s\n", key_authority[i]);
		anode = find_secvar(key_authority[i], strlen(key_authority[i]) + 1,
				    bank);
		if (!anode || !anode->var->data_size) {
			i++;
			continue;
		}

		/* Verify the signature */
		rc = verify_signature(auth, tbhbuffer, tbhbuffersize,
				      anode->var);

		/* Break if signature verification is successful */
		if (rc == OPAL_SUCCESS)
			break;
		i++;
	}

out:
	free(auth_buffer);
	free(tbhbuffer);

	return rc;
}
