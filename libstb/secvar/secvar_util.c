// SPDX-License-Identifier: Apache-2.0
/* Copyright 2019 IBM Corp. */

#ifndef pr_fmt
#define pr_fmt(fmt) "SECVAR: " fmt
#endif

#include <stdlib.h>
#include <string.h>
#include <skiboot.h>
#include <opal.h>
#include "secvar.h"

void clear_bank_list(struct list_head *bank)
{
	struct secvar_node *node, *next;

	if (!bank)
		return;

	list_for_each_safe(bank, node, next, link) {
		list_del(&node->link);
		dealloc_secvar(node);
	}
}

struct secvar_node *alloc_secvar(uint64_t size)
{
	struct secvar_node *ret;

	ret = zalloc(sizeof(struct secvar_node));
	if (!ret)
		return NULL;

	ret->var = zalloc(sizeof(struct secvar) + size);
	if (!ret->var) {
		free(ret);
		return NULL;
	}

	ret->size = size;

	return ret;
}


struct secvar_node *new_secvar(char *key, uint64_t key_len,
			       char *data, uint64_t data_size,
			       uint64_t flags)
{
	struct secvar_node *ret;

	if (!key)
		return NULL;
	if ((!key_len) || (key_len > SECVAR_MAX_KEY_LEN))
		return NULL;
	if ((!data) && (data_size))
		return NULL;

	ret = alloc_secvar(data_size);
	if (!ret)
		return NULL;

	ret->var->key_len = key_len;
	ret->var->data_size = data_size;
	memcpy(ret->var->key, key, key_len);
	ret->flags = flags;

	if (data)
		memcpy(ret->var->data, data, data_size);

	return ret;
}

int realloc_secvar(struct secvar_node *node, uint64_t size)
{
	void *tmp;

	if (node->size >= size)
		return 0;

	tmp = zalloc(sizeof(struct secvar) + size);
	if (!tmp)
		return -1;

	memcpy(tmp, node->var, sizeof(struct secvar) + node->size);
	free(node->var);
	node->var = tmp;

	return 0;
}

void dealloc_secvar(struct secvar_node *node)
{
	if (!node)
		return;

	free(node->var);
	free(node);
}

struct secvar_node *find_secvar(const char *key, uint64_t key_len, struct list_head *bank)
{
	struct secvar_node *node = NULL;

	list_for_each(bank, node, link) {
		// Prevent matching shorter key subsets / bail early
		if (key_len != node->var->key_len)
			continue;
		if (!memcmp(key, node->var->key, key_len))
			return node;
	}

	return NULL;
}

int is_key_empty(const char *key, uint64_t key_len)
{
	int i;
	for (i = 0; i < key_len; i++) {
		if (key[i] != 0)
			return 0;
	}

	return 1;
}

int list_length(struct list_head *bank)
{
	int ret = 0;
	struct secvar_node *node;

	list_for_each(bank, node, link)
		ret++;

	return ret;
}
