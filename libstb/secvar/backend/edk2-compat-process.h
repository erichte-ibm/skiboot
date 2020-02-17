// SPDX-License-Identifier: Apache-2.0
/* Copyright 2019 IBM Corp. */

#ifndef __SECVAR_EDK2_COMPAT_PROCESS__
#define __SECVAR_EDK2_COMPAT_PROCESS__

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

#define CERT_BUFFER_SIZE        2048
#define MBEDTLS_ERR_BUFFER_SIZE 1024

#define EDK2_MAX_KEY_LEN        SECVAR_MAX_KEY_LEN
#define key_equals(a,b) (!strncmp(a, b, EDK2_MAX_KEY_LEN))

extern bool setup_mode;

/* Update the variable in the variable bank with the new value. */
int update_variable_in_bank(struct secvar *secvar, const char *data,
			    uint64_t dsize);

/* This function outputs the Authentication 2 Descriptor in the
 * auth_buffer and returns the size of the buffer. Please refer to
 * edk2.h for details on Authentication 2 Descriptor
 */
int get_auth_descriptor2(void *buf, size_t buflen, char **auth_buffer);

/* Check the format of the ESL */
int validate_esl_list(char *key, char *esl, size_t size);

/* Update the TS variable with the new timestamp */
int update_timestamp(char *key, struct efi_time *timestamp);

/* Check the new timestamp against the timestamp last update was done */
int check_timestamp(char *key, struct efi_time *timestamp);

/* Check the GUID of the data type */
bool is_pkcs7_sig_format(void *data);

/* Process the update */
int process_update(struct secvar_node *update, char **newesl, int *neweslsize,
		   struct efi_time *timestamp);

#endif
