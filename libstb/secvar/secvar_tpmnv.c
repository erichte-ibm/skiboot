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
int tpm_error = 0;
int tpm_first_init = 0;
struct tpm_nv *tpm_image;
size_t tpm_nv_size = 0;

// Values set by a platform to enable TPMNV simulation mode
// NOT INTENDED FOR PRODUCTION USE
int tpm_fake_nv = 0;			// Use fake NV mode using pnor
uint64_t tpm_fake_nv_offset = 0;	// Offset into SECBOOT pnor to use
uint64_t tpm_fake_nv_max_size = 0;

static int TSS_Fake_Read(uint32_t nvIndex, void *buf, size_t bufsize, uint64_t off)
{
	(void) nvIndex;
	(void) off;
	return platform.secboot_read(buf, tpm_fake_nv_offset, bufsize);
}

static int TSS_Fake_Write(uint32_t nvIndex, void *buf, size_t bufsize, uint64_t off)
{
	(void) nvIndex;
	(void) off;
	return platform.secboot_write(tpm_fake_nv_offset, buf, bufsize);
}

static int TSS_Fake_Define_Space(uint32_t nvIndex, const char hierarchy,
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
	int (*tss_nv_read)(uint32_t, void*, size_t, uint64_t);
	int (*tss_nv_write)(uint32_t, void*, size_t, uint64_t);
	int (*tss_nv_define_space)(uint32_t, const char, const char, uint16_t);
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
	int rc;

	memset(tpm_image, 0, tpm_nv_size);

	// TODO: Determine the proper auths
	rc = tpmnv_ops->tss_nv_define_space(TPM_SECVAR_NV_INDEX, 'p', 'p', tpm_nv_size);
	if (rc) {
		prlog(PR_INFO, "Failed to define NV index, rc = %d\n", rc);
		return rc;
	}

	tpm_image->magic_num = TPM_SECVAR_MAGIC_NUM;
	tpm_image->version = 1;

	tpm_first_init = 1;

	return tpmnv_ops->tss_nv_write(TPM_SECVAR_NV_INDEX, tpm_image, tpm_nv_size, 0);
}


static int secvar_tpmnv_init(void)
{
	int rc;

	if (tpm_ready)
		return OPAL_SUCCESS;
	if (tpm_error)
		return OPAL_HARDWARE;

	prlog(PR_INFO, "Initializing TPMNV space...\n");

	// Check here if TPM NV Index is defined
	//   if not, call secvar_tpmnv_format() here

	// Using the minimum defined by the spec for now
	// This value should probably be determined by tss_get_capatibility
	tpm_nv_size = 1024;

	tpm_image = malloc(tpm_nv_size);
	if (!tpm_image) {
		tpm_error = 1;
		return OPAL_NO_MEM;
	}

	if (tpm_fake_nv) {
		prlog(PR_INFO, "Enabling fake TPM NV mode\n");
		tpmnv_ops = &Fake_tpmnv_ops;
	}

	prlog(PR_INFO, "Reading in from TPM NV...\n");
	rc = tpmnv_ops->tss_nv_read(TPM_SECVAR_NV_INDEX, tpm_image, tpm_nv_size, 0);
	if (rc == TPM_RC_NV_UNINITIALIZED) {
		rc = secvar_tpmnv_format();
		if (rc) {
			prlog(PR_ERR, "Failed to format tpmnv space, rc = %d\n", rc);
			tpm_error = 1;
			return OPAL_HARDWARE;
		}
	}
	else if (rc) {
		prlog(PR_ERR, "Failed to read from NV index, rc = %d\n", rc);
		tpm_error = 1;
		return OPAL_HARDWARE;
	}

	if (tpm_image->magic_num != TPM_SECVAR_MAGIC_NUM) {
		prlog(PR_INFO, "Magic num mismatch, reformatting NV space...\n");
		rc = secvar_tpmnv_format();
		if (rc) {
			prlog(PR_INFO, "Failed to format tpmnv space, rc = %d\n", rc);
			tpm_error = 1;
			return OPAL_HARDWARE;
		}
	}
	prlog(PR_INFO, "TPMNV space initialized successfully\n");
	tpm_ready = 1;

	return OPAL_SUCCESS;
}


static struct tpm_nv_id *find_tpmnv_id(uint32_t id)
{
	struct tpm_nv_id *tmp;
	char *cur, *end;

	cur = (char *) tpm_image->vars;
	end = ((char *) tpm_image) + tpm_nv_size;
	while (cur + sizeof(struct tpm_nv_id) < end) {
		tmp = (struct tpm_nv_id *) cur;
		if (tmp->id == 0)
			return NULL;
		if (tmp->id == id)
			goto out;

		cur += sizeof(struct tpm_nv_id) + tmp->size;
	}

	return NULL;
out:
	if (end < sizeof(struct tpm_nv_id) + tmp->size + cur) {
		// This should not happen
		prlog(PR_ERR, "BUG: NV id size overflow, id=%u, size=%u, end=%p\n",
		      id, tmp->size, end);
		return NULL;
	}

	return tmp;
}


// "Allocate" space within the secvar tpm
int secvar_tpmnv_alloc(uint32_t id, int32_t size)
{
	struct tpm_nv_id *tmp;
	char *cur;
	char *end;

	if (secvar_tpmnv_init())
		return OPAL_RESOURCE;
	if (size < -1)
		return OPAL_PARAMETER;

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
	// Ensure we have enough space for the allocation
	if ((end - cur) < size + sizeof(struct tpm_nv_id))
		return OPAL_EMPTY;

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

	if (!tpm_ready)
		return OPAL_RESOURCE;
	if (tpm_error)
		return OPAL_HARDWARE;

	var = find_tpmnv_id(id);
	if (!var)
		return OPAL_EMPTY;

	if (var->size < off)
		return OPAL_PARAMETER;

	size = MIN(size, var->size - off);
	memcpy(buf, var->data + off, size);

	return OPAL_SUCCESS;
}


int secvar_tpmnv_write(uint32_t id, void *buf, size_t size, size_t off)
{
	struct tpm_nv_id *var;

	if (!tpm_ready)
		return OPAL_RESOURCE;
	if (tpm_error)
		return OPAL_HARDWARE;

	var = find_tpmnv_id(id);
	if (!var)
		return OPAL_EMPTY;

	if (var->size < off)
		return OPAL_PARAMETER;

	size = MIN(size, var->size - off);
	memcpy(var->data, buf + off, size);

	return tpmnv_ops->tss_nv_write(TPM_SECVAR_NV_INDEX, tpm_image, tpm_nv_size, 0);
}

uint32_t secvar_tpmnv_size(uint32_t id)
{
	struct tpm_nv_id *var;

	if (!tpm_ready)
		return OPAL_RESOURCE;
	if (tpm_error)
		return OPAL_HARDWARE;

	var = find_tpmnv_id(id);
	if (!var)
		return 0;
	return var->size;
}
