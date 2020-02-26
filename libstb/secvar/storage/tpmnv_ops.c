#include <tssskiboot.h>
#include "secboot_tpm.h"

struct tpmnv_ops_s tpmnv_ops = {
	.read = tss_nv_read,
	.write = tss_nv_write,
	.writelock = tss_nv_write_lock,
	.definespace = tss_nv_define_space
};

