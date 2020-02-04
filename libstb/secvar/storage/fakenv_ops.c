#include <skiboot.h>
#include "secboot_tpm.h"

static size_t fakenv_offset = sizeof(struct secboot);

static int fakenv_read(uint32_t nvIndex, void *buf, size_t bufsize, uint64_t off)
{
	(void) nvIndex;
	(void) off;
	return platform.secboot_read(buf, fakenv_offset, bufsize);
}

static int fakenv_write(uint32_t nvIndex, void *buf, size_t bufsize, uint64_t off)
{
	(void) nvIndex;
	(void) off;
	return platform.secboot_write(fakenv_offset, buf, bufsize);
}

static int fakenv_definespace(uint32_t nvIndex, const char hierarchy,
			const char hierarchy_authorization,
			uint16_t dataSize)
{
	(void) nvIndex;
	(void) hierarchy;
	(void) hierarchy_authorization;
	(void) dataSize;
	return 0;
}

static int fakenv_writelock(uint32_t nvIndex)
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
