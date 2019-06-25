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

		if (node->var) {
			free(node->var);
		}

		free(node);
	}
}

struct secvar_node *find_secvar(const char *key, uint64_t key_len, struct list_head *bank)
{
	struct secvar_node *node = NULL;

	list_for_each(bank, node, link) {
		// Prevent matching shorter key subsets / bail early
		if (key_len != node->var->key_len)
			continue;
		if (!memcmp(key, node->var->key, key_len)) {
			return node;
		}
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

	list_for_each(bank, node, link) {
		ret++;
	}

	return ret;
}
