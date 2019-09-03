/* Copyright 2019 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "secvar_api_test.c"

const char *secvar_test_name = "getvar";

// Run tests on the less obvious features of secvar_get
// Includes:
//  - Partial reads
//  - Size queries (NULL buffer)
//int run_test_helper(uint64_t bank_enum)
int run_test(void)
{
	int64_t rc;

	uint64_t size = 4;
	char *temp = zalloc(100);
	char key[1024] = {0};

	struct secvar_node *node = zalloc(sizeof(struct secvar_node));
	struct secvar *var = zalloc(sizeof(struct secvar) + 1024); // over-allocate for now, this should be rewritten
	size_t data_size = sizeof("foobar");
	char *data = zalloc(data_size);
	uint64_t key_len = 4;
	memcpy(data, "foobar", data_size);

	memcpy(key, "test", 4);

	// List should be empty at start
	rc = secvar_get(key, key_len, data, &data_size);
	ASSERT(rc == OPAL_EMPTY);
	ASSERT(list_length(&variable_bank) == 0);

	// Manually add variables, and check get_variable call
	var->key_len = key_len;
	memcpy(var->key, key, key_len);
	var->data_size = data_size;
	memcpy(var->data, data, data_size);

	node->var = var;
	list_add_tail(&variable_bank, &node->link);

	ASSERT(list_length(&variable_bank) == 1);

	// TEST ONLY DATA
	// Test actual variable get
	size = data_size;
	rc = secvar_get(key, key_len, temp, &size);
	ASSERT(rc == OPAL_SUCCESS);
	ASSERT(0 == memcmp("foobar", var->data, size));

	// Test buffer too small
	size = data_size / 2;
	memset(temp, 0, 100);
	rc = secvar_get(key, key_len, temp, &size);
	ASSERT(rc == OPAL_PARTIAL);

	size = 0;
	rc = secvar_get(key, key_len, temp, &size);
	ASSERT(rc == OPAL_PARTIAL);
	ASSERT(size == data_size);

	// Test size query w/ no data
	size = 0;
	rc = secvar_get(key, key_len, NULL, &size);
	ASSERT(rc == OPAL_SUCCESS);
	ASSERT(size == data_size);

	/**** Error/Bad param cases ****/
	// NULL key
	rc = secvar_get(NULL, key_len, data, &data_size);
	ASSERT(rc == OPAL_PARAMETER);
	// zero key_len
	rc = secvar_get(key, 0, data, &data_size);
	ASSERT(rc == OPAL_PARAMETER);
	// NULL size, valid data
	rc = secvar_get(key, key_len, data, NULL);
	ASSERT(rc == OPAL_PARAMETER);

	secvar_enabled = 0;
	rc = secvar_get(key, key_len, data, &data_size);
	ASSERT(rc == OPAL_UNSUPPORTED);
	secvar_enabled = 1;

	secvar_ready = 0;
	rc = secvar_get(key, key_len, data, &data_size);
	ASSERT(rc == OPAL_RESOURCE);
	secvar_ready = 1;

	list_del(&node->link);

	free(data);
	free(temp);

	return 0;
}
