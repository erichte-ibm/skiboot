#include <device.h>
#include <string.h>
#include "secvar.h"
#include "secvar_devtree.h"

struct dt_node *secvar_node;
struct dt_node *secvar_backend_node;
struct dt_node *secvar_storage_node;

int secvar_set_secure_mode(void)
{
	struct dt_property *prop;

	if (!secvar_node)
		return -1;

	prop = (struct dt_property *) dt_find_property(secvar_node, "os-secure-enforcing");
	if (prop)
		return 0;

	prop = dt_add_property(secvar_node, "os-secure-enforcing", 0, 0);
	if (!prop)
		return -2;

	return 0;
}

void secvar_init_devnode(void)
{
	struct dt_node *sb_root;

	sb_root = dt_find_by_path(dt_root, "/ibm,opal/");

	secvar_node = dt_new(sb_root, "secvar");

	dt_add_property_string(secvar_node, "compatible", "ibm,secvar-v1");

	secvar_backend_node = dt_new(secvar_node, "backend");
	secvar_storage_node = dt_new(secvar_node, "storage");

	dt_add_property_string(secvar_backend_node, "compatible", secvar_backend.compatible);
	dt_add_property_string(secvar_storage_node, "compatible", secvar_storage.compatible);

	dt_add_property_u64(secvar_storage_node, "max-var-size", secvar_storage.max_var_size);
}

void secvar_set_status(const char *status)
{
	struct dt_property *stat_prop;
	if (!secvar_node)
		return; // Fail boot?

	stat_prop = (struct dt_property *) dt_find_property(secvar_node, "status");

	if (stat_prop)
		strcpy(stat_prop->prop, status);
	else
		dt_add_property_string(secvar_node, "status", status);
		// Fail boot if not successful?
}


void secvar_set_update_status(uint64_t val)
{
	struct dt_property *stat_prop;
	if (!secvar_node)
		return; // Fail boot?

	stat_prop = (struct dt_property *) dt_find_property(secvar_backend_node, "update-status");

	if (stat_prop)
		memcpy(stat_prop->prop, &val, sizeof(val));
	else
		dt_add_property(secvar_backend_node, "update-status", &val, sizeof(val));
}


void secvar_dt_backend_set_prop_string(const char *prop, const char *val)
{
	struct dt_property *p;

	if (!secvar_backend_node)
		return;

	p = (struct dt_property *) dt_find_property(secvar_backend_node, prop);

	if (p)
		memcpy(p->prop, val, strlen(val));
	else
		dt_add_property_string(secvar_backend_node, prop, val);
}

void secvar_dt_backend_set_prop_u64(const char *prop, uint64_t val)
{
	struct dt_property *p;

	if (!secvar_backend_node)
		return;

	p = (struct dt_property *) dt_find_property(secvar_backend_node, prop);

	if (p)
		memcpy(p->prop, &val, sizeof(val));
	else
		dt_add_property_u64(secvar_backend_node, prop, val);
}

void secvar_dt_storage_set_prop_string(const char *prop, const char *val)
{
	struct dt_property *p;

	if (!secvar_storage_node)
		return;

	p = (struct dt_property *) dt_find_property(secvar_storage_node, prop);

	if (p)
		memcpy(p->prop, val, strlen(val));
	else
		dt_add_property_string(secvar_backend_node, prop, val);
}

void secvar_dt_storage_set_prop_u64(const char *prop, uint64_t val)
{
	struct dt_property *p;

	if (!secvar_storage_node)
		return;

	p = (struct dt_property *) dt_find_property(secvar_storage_node, prop);

	if (p)
		memcpy(p->prop, &val, sizeof(val));
	else
		dt_add_property_u64(secvar_backend_node, prop, val);
}
