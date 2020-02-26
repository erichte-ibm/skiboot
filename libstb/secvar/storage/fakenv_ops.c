#include <skiboot.h>
#include "secboot_tpm.h"

static size_t fakenv_offset = sizeof(struct secboot);

static int fakenv_read(TPMI_RH_NV_INDEX nvIndex, void *buf,
                     size_t bufsize,  uint16_t off)
{
	(void) nvIndex;
	(void) off;
	return platform.secboot_read(buf, fakenv_offset, bufsize);
}

static int fakenv_write(TPMI_RH_NV_INDEX nvIndex, void *buf,
                      size_t bufsize, uint16_t off)
{
	(void) nvIndex;
	(void) off;
	return platform.secboot_write(fakenv_offset, buf, bufsize);
}

static int fakenv_definespace(TPMI_RH_NV_INDEX nvIndex, uint16_t dataSize)
{
	(void) nvIndex;
	(void) dataSize;
	return 0;
}

static int fakenv_writelock(TPMI_RH_NV_INDEX nvIndex)
{
	(void) nvIndex;
	return 0;
}

struct tpmnv_ops_s tpmnv_ops = {
	.read = fakenv_read,
	.write = fakenv_write,
	.writelock = fakenv_writelock,
	.definespace = fakenv_definespace,
};
