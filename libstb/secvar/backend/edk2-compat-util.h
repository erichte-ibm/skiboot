// SPDX-License-Identifier: Apache-2.0
/* Copyright 2019 IBM Corp. */

#ifndef __SECVAR_EDK2_COMAPT__
#define __SECVAR_EDK2_COMAPT__

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

extern bool setup_mode;

/* Converts utf8 string to ucs2 */
char *utf8_to_ucs2(const char *key, size_t keylen);

/* Returns true if key1 = key2 */
bool key_equals(const char *key1, const char *key2);

/* Returns the authority that can sign the given key update */
void get_key_authority(const char *ret[3], const char *key);

/* Returns the size of the complete ESL. */
int get_esl_signature_list_size(char *buf, size_t buflen);

/* Copies the certificate from the ESL into cert buffer and returns the size
 * of the certificate
 */
int get_esl_cert(char *buf, size_t buflen, char **cert);

/* Extracts size of the PKCS7 signed data embedded in the
 * struct Authentication 2 Descriptor Header.
 */
int get_pkcs7_len(struct efi_variable_authentication_2 *auth);

/* This function outputs the Authentication 2 Descriptor in the
 * auth_buffer and returns the size of the buffer.
 */
int get_auth_descriptor2(void *buf, size_t buflen, char **auth_buffer);

/* Check that PK has single ESL */
bool is_single_pk(char *data, size_t data_size);

/* Get the timestamp for the last update of the give key */ 
struct efi_time *get_last_timestamp(const char *key);

/* Update the TS variable with the new timestamp */
int update_timestamp(char *key, struct efi_time *timestamp);

/* Check the new timestamp against the timestamp last update was done */
int check_timestamp(char *key, struct efi_time *timestamp);

/* Extract PKCS7 from the authentication header */
int get_pkcs7(struct efi_variable_authentication_2 *auth, mbedtls_pkcs7 **pkcs7);

/* Verify the PKCS7 signature on the signed data. */
int verify_signature(void *auth_buffer, char *newcert,
			    uint64_t new_data_size, struct secvar *avar);

/* Verify the PKCS7 signature on the signed data. */
int process_single_update(struct secvar *auth);

/* Create the single buffer
 * name || vendor guid || attributes || timestamp || newcontent 
 * which is submitted as signed by the user.
 * Returns number of bytes in the new buffer, else negative error
 * code.
 */
int get_data_to_verify(char *key, char *new_data,
		size_t new_data_size,
		char **buffer,
		size_t *buffer_size, struct efi_time *timestamp);

/* Check the GUID of the data type */
bool is_pkcs7_sig_format(void *data);

/* Process the update */
int process_update(struct secvar_node *update, char **newesl, int *neweslsize,
		   struct efi_time *timestamp);

#endif
