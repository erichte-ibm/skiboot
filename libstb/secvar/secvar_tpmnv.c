// SPDX-License-Identifier: Apache-2.0
/* Copyright 2019 IBM Corp. */
#ifndef pr_fmt
#define pr_fmt(fmt) "SECVAR_TPMNV: " fmt
#endif

#include <opal.h>
#include <skiboot.h>
#include <string.h>
#include <tssskiboot.h>
#include "secvar_tpmnv.h"

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

// Values set by a platform to enable TPMNV simulation mode
// NOT INTENDED FOR PRODUCTION USE
int tpm_fake_nv = 0;			// Use fake NV mode using pnor
uint64_t tpm_fake_nv_offset = 0;	// Offset into SECBOOT pnor to use
uint64_t tpm_fake_nv_max_size = 0;

static TPM_RC TSS_Fake_Read(TPMI_RH_NV_INDEX nvIndex, void *buf, size_t bufsize, uint64_t off)
{
	(void) nvIndex;
	(void) off;
	return platform.secboot_read(buf, tpm_fake_nv_offset, bufsize);
}

static TPM_RC TSS_Fake_Write(TPMI_RH_NV_INDEX nvIndex, void *buf, size_t bufsize, uint64_t off)
{
	(void) nvIndex;
	(void) off;
	return platform.secboot_write(tpm_fake_nv_offset, buf, bufsize);
}

static int TSS_Fake_Define_Space(TPMI_RH_NV_INDEX nvIndex, const char hierarchy,
			const char hierarchy_authorization,
			uint16_t dataSize)
{
	(void) nvIndex;
	(void) hierarchy;
	(void) hierarchy_authorization;
	(void) dataSize;
	return 0;
}

struct tpmnv_ops_s {
	TPM_RC (*tss_nv_read)(TPMI_RH_NV_INDEX, void*, size_t, uint64_t);
	TPM_RC (*tss_nv_write)(TPMI_RH_NV_INDEX, void*, size_t, uint64_t);
	int (*tss_nv_define_space)(TPMI_RH_NV_INDEX, const char, const char, uint16_t);
};

struct tpmnv_ops_s TSS_tpmnv_ops = {
	.tss_nv_read = TSS_NV_Read,
	.tss_nv_write = TSS_NV_Write,
	.tss_nv_define_space = TSS_NV_Define_Space,
};

struct tpmnv_ops_s Fake_tpmnv_ops = {
	.tss_nv_read = TSS_Fake_Read,
	.tss_nv_write = TSS_Fake_Write,
	.tss_nv_define_space = TSS_Fake_Define_Space,
};

struct tpmnv_ops_s *tpmnv_ops = &TSS_tpmnv_ops;

// This function should be replaced with logic that performs the initial
// TPM NV Index definition, and any first-write logic
static int secvar_tpmnv_format(void)
{
	memset(tpm_image, 0, sizeof(tpm_nv_size));

	// TSS_NV_Define_Space()

	tpm_image->magic_num = TPM_SECVAR_MAGIC_NUM;
	tpm_image->version = 1;

	tpm_first_init = 1;

	return tpmnv_ops->tss_nv_write(TPM_SECVAR_NV_INDEX, tpm_image, tpm_nv_size, 0);
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

	if (tpm_fake_nv)
		tpmnv_ops = &Fake_tpmnv_ops;

	tpmnv_ops->tss_nv_read(TPM_SECVAR_NV_INDEX, tpm_image, tpm_nv_size, 0);

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

	return tpmnv_ops->tss_nv_write(TPM_SECVAR_NV_INDEX, tpm_image, tpm_nv_size, 0);
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
