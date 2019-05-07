#ifndef _SECVAR_TPMNV_H_
#define _SECVAR_TPMNV_H_
#include <stdint.h>

int secvar_tpmnv_alloc(uint32_t id, int32_t size);
int secvar_tpmnv_read(uint32_t id, void *buf, size_t size, size_t off);
int secvar_tpmnv_write(uint32_t id, void *buf, size_t size, size_t off);
uint32_t secvar_tpmnv_size(uint32_t id);

#endif
