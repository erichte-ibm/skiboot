#ifndef _SECVAR_DEVTREE_H_
#define _SECVAR_DEVTREE_H_

int secvar_set_secure_mode(void);
void secvar_init_devnode(void);

void secvar_set_status(const char *status);
void secvar_set_update_status(uint64_t val);

void secvar_dt_backend_set_prop_string(const char *prop, const char *val);
void secvar_dt_backend_set_prop_u64(const char *prop, uint64_t val);
void secvar_dt_storage_set_prop_string(const char *prop, const char *val);
void secvar_dt_storage_set_prop_u64(const char *prop, uint64_t val);

#endif
