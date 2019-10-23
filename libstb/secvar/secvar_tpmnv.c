// SPDX-License-Identifier: Apache-2.0
/* Copyright 2019 IBM Corp. */
#ifndef pr_fmt
#define pr_fmt(fmt) "SECVAR_TPMNV: " fmt
#endif

#include <opal.h>
#include <skiboot.h>
#include <string.h>
#include "secvar_tpmnv.h"
//#include <tssskiboot.h>

#define TPM_SECVAR_NV_INDEX	0x01c10191
#define TPM_SECVAR_MAGIC_NUM	0x53544e56

struct tpm_nv_id {
	uint32_t id;
	uint32_t size;
	char data[0];
} __packed;

struct tpm_nv {
	uint32_t magic_num;
	uint32_t version;
	struct tpm_nv_id vars[0];
} __packed;

int tpm_ready = 0;
int tpm_first_init = 0;
struct tpm_nv *tpm_image;
size_t tpm_nv_size = 0;

// These are borrowed from secboot_tpm.c for the temporary, pnor-based
// TPM NV storage backing. They should be removed when this file uses
// the actual TPM and TSS
#define SECBOOT_VARIABLE_BANK_SIZE      32000
#define SECBOOT_UPDATE_BANK_SIZE        32000
#define SECBOOT_VARIABLE_BANK_NUM       2
#ifndef _secboot_header_ // stupid fix for the test, delete with the rest
struct secboot_header {
        uint32_t magic_number;
        uint8_t version;
        uint8_t reserved[3];    // Fix alignment
} __packed;
struct secboot {
        struct secboot_header header;
        char bank[SECBOOT_VARIABLE_BANK_NUM][SECBOOT_VARIABLE_BANK_SIZE];
        char update[SECBOOT_UPDATE_BANK_SIZE];
} __packed;
#endif

// This function should be replaced with logic that performs the initial
// TPM NV Index definition, and any first-write logic
static int secvar_tpmnv_format(void)
{
	memset(tpm_image, 0, sizeof(tpm_nv_size));

	// TSS_NV_Define_Space()

	tpm_image->magic_num = TPM_SECVAR_MAGIC_NUM;
	tpm_image->version = 1;

	tpm_first_init = 1;

	return platform.secboot_write(sizeof(struct secboot), tpm_image, tpm_nv_size);
}


static int secvar_tpmnv_init(void)
{
	if (tpm_ready)
		return OPAL_SUCCESS;

	// Check here if TPM NV Index is defined
	//   if not, call secvar_tpmnv_format() here

	// Using the minimum defined by the spec for now
	// This value should probably be determined by tss_get_capatibility
	tpm_nv_size = 1024;

	tpm_image = malloc(tpm_nv_size);
	if (!tpm_image)
		return OPAL_NO_MEM;

	// Use pnor space for now, stored after the secboot pnor sections
	// NOTE: This file should never reference secboot in the future
	// Replace with TSS_NV_Read()
	if (platform.secboot_read(tpm_image, sizeof(struct secboot), tpm_nv_size))
		return OPAL_HARDWARE;
	if (tpm_image->magic_num != TPM_SECVAR_MAGIC_NUM)
		if(secvar_tpmnv_format())
			return OPAL_HARDWARE;
	tpm_ready = 1;

	return OPAL_SUCCESS;
}


static struct tpm_nv_id *find_tpmnv_id(uint32_t id)
{
	struct tpm_nv_id *tmp;
	char *cur, *end;

	cur = (char *) tpm_image->vars;
	end = ((char *) tpm_image) + tpm_nv_size;
	while (cur < end) {
		tmp = (struct tpm_nv_id *) cur;
		if (tmp->id == 0)
			return NULL;
		if (tmp->id == id)
			return tmp;
	     cur += sizeof(struct tpm_nv_id) + tmp->size;
	}

	return NULL;
}


// "Allocate" space within the secvar tpm
int secvar_tpmnv_alloc(uint32_t id, int32_t size)
{
	struct tpm_nv_id *tmp;
	char *cur;
	char *end;

	if (secvar_tpmnv_init())
		return OPAL_RESOURCE;

	cur = (char *) tpm_image->vars;
	end = ((char *) tpm_image) + tpm_nv_size;
	while (cur < end) {
		tmp = (struct tpm_nv_id *) cur;
		if (tmp->id == 0)
			goto allocate;
		if (tmp->id == id)
			return OPAL_SUCCESS; // Already allocated

	     cur += sizeof(struct tpm_nv_id) + tmp->size;
	}
	// We ran out of space...
	return OPAL_EMPTY;

allocate:
	tmp->id = id;

	// Special case: size of -1 gives remaining space
	if (size == -1)
		tmp->size = end - tmp->data;
	else
		tmp->size = size;

	return OPAL_SUCCESS;
}


int secvar_tpmnv_read(uint32_t id, void *buf, size_t size, size_t off)
{
	struct tpm_nv_id *var;

	if (secvar_tpmnv_init())
		return OPAL_RESOURCE;

	var = find_tpmnv_id(id);
	if (!var)
		return OPAL_EMPTY;

	size = MIN(size, var->size);
	memcpy(buf, var->data + off, size);

	return 0;
}


int secvar_tpmnv_write(uint32_t id, void *buf, size_t size, size_t off)
{
	struct tpm_nv_id *var;

	if (secvar_tpmnv_init())
		return OPAL_RESOURCE;

	var = find_tpmnv_id(id);
	if (!var)
		return OPAL_EMPTY;

	size = MIN(size, var->size);
	memcpy(var->data, buf + off, size);

	// Replace with:
	// TSS_NV_Write(TPM_SECVAR_NV_INDEX, var->data, size + sizeof(struct tpm_nv_id), tpm_image - var)
	return platform.secboot_write(sizeof(struct secboot), tpm_image, tpm_nv_size);
}

int secvar_tpmnv_size(uint32_t id)
{
	struct tpm_nv_id *var;

	if (secvar_tpmnv_init())
		return OPAL_RESOURCE;

	var = find_tpmnv_id(id);
	if (!var)
		return 0;
	return var->size;
}
