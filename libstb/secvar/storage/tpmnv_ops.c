#include <tssskiboot.h>
#include "secboot_tpm.h"

struct tpmnv_ops_s tpmnv_ops = {
	.read = TSS_NV_Read,
	.write = TSS_NV_Write,
	.writelock = TSS_NV_WriteLock,
	.definespace = TSS_NV_Define_Space
};

