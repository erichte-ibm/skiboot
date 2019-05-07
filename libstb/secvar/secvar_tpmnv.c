#include <skiboot.h>
#include <string.h>
#include "secvar_tpmnv.h"
//#include <tssskiboot.h>

#define TPM_SECVAR_NV_INDEX	0x01c10191

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
struct tpm_nv *tpm_image;
size_t tpm_nv_size = 0;

// Here just for size purposes, delete when using TSS
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


static int secvar_tpmnv_init(void)
{
	if (tpm_ready)
		return 0;

	// Check if defined, if so, load
	// and set tpm_nv_size
	// TSS_NV_Define_Space
	// TSS_NV_Read

	tpm_nv_size = 1024;

	tpm_image = zalloc(tpm_nv_size);
	if (!tpm_image)
		return -1;

	// TEMP use pnor space for now, stored after the secboot sections
	if (platform.secboot_read(tpm_image, sizeof(struct secboot), tpm_nv_size))
		return -1;

	tpm_ready = 1;

	return 0;
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

	if (!tpm_ready && secvar_tpmnv_init())
		return -1;

	for (cur = tpm_image->vars;
	     (char *) cur < ((char *) tpm_image) + tpm_nv_size;
	     cur += sizeof(struct tpm_nv_id) + cur->size) {
		if (cur->id == 0)
			goto allocate;
		if (cur->id == id)
			return 0; // Already allocated
	}

allocate:
	// Special case: size of -1 gives remaining space
	if (size == -1) {
		cur->id = id;
		cur->size = tpm_nv_size - (cur - tpm_image->vars);
	}

	if ((((char *) cur) + size) - (char *) tpm_image > tpm_nv_size) 
		return -2;

	cur->id = id;
	cur->size = size;

	return 0;
}


int secvar_tpmnv_read(uint32_t id, void *buf, size_t size, size_t off)
{
	struct tpm_nv_id *var;

	if (!tpm_ready && secvar_tpmnv_init())
		return -1;

	var = find_tpmnv_id(id);
	if (!var)
		return -1;
	
	size = MIN(size, var->size);
	memcpy(buf + off, var->data, size);

	return 0;
}


int secvar_tpmnv_write(uint32_t id, void *buf, size_t size, size_t off)
{
	struct tpm_nv_id *var;

	if (!tpm_ready && secvar_tpmnv_init())
		return -1;

	var = find_tpmnv_id(id);
	if (!var)
		return -1;

	size = MIN(size, var->size);
	memcpy(var->data, buf + off, size);
	// TSS_NV_Write(TPM_SECVAR_NV_INDEX, var->data, size + sizeof(struct tpm_nv_id), tpm_image - var)

	platform.secboot_write(sizeof(struct secboot), tpm_image, tpm_nv_size);
	return 0;
}

uint32_t secvar_tpmnv_size(uint32_t id)
{
	struct tpm_nv_id *var;

	if (!tpm_ready && secvar_tpmnv_init())
		return -1;

	var = find_tpmnv_id(id);
	if (!var)
		return 0;
	return var->size;
}