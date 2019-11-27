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
};

struct tpm_nv {
	uint32_t magic_num;
	uint32_t version;
	struct tpm_nv_id vars[0];
};

int tpm_ready = 0;
int tpm_first_init = 0;
struct tpm_nv *tpm_image;
size_t tpm_nv_size = 0;

// These are borrowed from secboot_tpm.c, for the temporary, pnor-based
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

// This function should probably be replaced with TPM NV index reserving
// and first-write logic.
static int secvar_tpmnv_format(void)
{
	memset(tpm_image, 0, sizeof(tpm_nv_size));

	tpm_image->magic_num = TPM_SECVAR_MAGIC_NUM;
	tpm_image->version = 1;

	tpm_first_init = 1;

	return platform.secboot_write(sizeof(struct secboot), tpm_image, tpm_nv_size);
}


static int secvar_tpmnv_init(void)
{
	if (tpm_ready)
		return OPAL_SUCCESS;

	// Check if defined, if so, load
	// and set tpm_nv_size
	// TSS_NV_Define_Space
	// TSS_NV_Read

	tpm_nv_size = 1024;

	tpm_image = malloc(tpm_nv_size);
	if (!tpm_image)
		return OPAL_NO_MEM;

	// TEMP use pnor space for now, stored after the secboot sections
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
	struct tpm_nv_id *cur;

	for (cur = tpm_image->vars;
	     (char *) cur < ((char *) tpm_image) + tpm_nv_size;
	     cur += sizeof(struct tpm_nv_id) + cur->size) {
		if (cur->id == 0)
			return NULL;
		if (cur->id == id)
			return cur;
	}

	return NULL;
}


// "Allocate" space within the secvar tpm
int secvar_tpmnv_alloc(uint32_t id, int32_t size)
{
	struct tpm_nv_id *cur;
	char *end;

	if (secvar_tpmnv_init())
		return OPAL_RESOURCE;

	cur = tpm_image->vars;
	end = ((char *) tpm_image) + tpm_nv_size;
	while ((char *) cur < end) {
		if (cur->id == 0)
			goto allocate;
		if (cur->id == id)
			return OPAL_SUCCESS; // Already allocated

	     cur += sizeof(struct tpm_nv_id) + cur->size;
	}
	// We ran out of space...
	return OPAL_EMPTY;

allocate:
	cur->id = id;

	// Special case: size of -1 gives remaining space
	if (size == -1)
		cur->size = end - cur->data;
	else
		cur->size = size;

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
	memcpy(buf + off, var->data, size);

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
	// TSS_NV_Write(TPM_SECVAR_NV_INDEX, var->data, size + sizeof(struct tpm_nv_id), tpm_image - var)

	platform.secboot_write(sizeof(struct secboot), tpm_image, tpm_nv_size);
	return 0;
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
