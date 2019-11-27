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
#include "secvar_common_test.c"
#include "../backend/edk2-compat.c"
#include "../secvar_util.c"
#include "../secvar_tpmnv.c"
#include "../../crypto/pkcs7/pkcs7.c"
#include <platform.h>
#include "edk2_test_data.h"

const char *secvar_test_name = "edk2-compat";

struct platform platform;


#define ARBITRARY_SECBOOT_SIZE 128000
char *secboot_buffer;
static int secboot_read(void *dst, uint32_t src, uint32_t len)
{
	memcpy(dst, secboot_buffer + src, len);
	return 0;
}

static int secboot_write(uint32_t dst, void *src, uint32_t len)
{
	memcpy(secboot_buffer + dst, src, len);
	return 0;
}

int secvar_set_secure_mode(void) { return 0; };

int run_test()
{
	int rc = -1;
	struct secvar_node *tmp;
	int keksize;
	int dbsize;

	// Check pre-process creates the empty variables
	ASSERT(0 == list_length(&variable_bank));
	rc = edk2_compat_pre_process();
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(4 == list_length(&variable_bank));

	// Add PK to update and .process()
	printf("Add PK");
	tmp = alloc_secvar(PK_auth_len);
	memcpy(tmp->var->key, "PK", 3);
	tmp->var->key_len = 3;
	memcpy(tmp->var->data, PK_auth, PK_auth_len);
	tmp->var->data_size = PK_auth_len;
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(4 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("PK", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->var->data_size);
	ASSERT(PK_auth_len > tmp->var->data_size); // esl should be smaller without auth
	ASSERT(!is_setup_mode());

	// Add db, should fail with no KEK
	printf("Add db");
	dbsize = sizeof(DB_auth);
	tmp = alloc_secvar(dbsize);
	memcpy(tmp->var->key, "db", 3);
	tmp->var->key_len = 3;
	memcpy(tmp->var->data, DB_auth, dbsize);
	tmp->var->data_size = dbsize;
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(4 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("db", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 == tmp->var->data_size); // Should still be empty

	printf("Add KEK");
	// Add valid KEK, .process(), should succeed

	tmp = alloc_secvar(ValidKEK_auth_len);
	memcpy(tmp->var->key, "KEK", 4);
	tmp->var->key_len = 4;
	memcpy(tmp->var->data, ValidKEK_auth, ValidKEK_auth_len);
	tmp->var->data_size = ValidKEK_auth_len;
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(4 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->var->data_size);

	// Add db, .process(), should succeed
	printf("Add db again\n");
	dbsize = sizeof(DB_auth);
	tmp = alloc_secvar(dbsize);
	memcpy(tmp->var->key, "db", 3);
	tmp->var->key_len = 3;
	memcpy(tmp->var->data, DB_auth, dbsize);
	tmp->var->data_size = dbsize;
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(4 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("db", 3, &variable_bank);
	printf("tmp is %s\n", tmp->var->key);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->var->data_size);

	// Add invalid KEK, .process(), should fail
	printf("Add invalid KEK\n");
	keksize = sizeof(InvalidKEK_auth);
	tmp = alloc_secvar(keksize);
	memcpy(tmp->var->key, "KEK", 4);
	tmp->var->key_len = 4;
	memcpy(tmp->var->data, InvalidKEK_auth, keksize);
	tmp->var->data_size = keksize;
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(4 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->var->data_size);

	// Add ill formatted KEK, .process(), should fail
	printf("Add invalid KEK\n");
	keksize = sizeof(IllformatKEK_auth);
	tmp = alloc_secvar(keksize);
	memcpy(tmp->var->key, "KEK", 4);
	tmp->var->key_len = 4;
	memcpy(tmp->var->data, IllformatKEK_auth, keksize);
	tmp->var->data_size = keksize;
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(4 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->var->data_size);

	return 0;
}

int main(void)
{
	int rc;

	list_head_init(&variable_bank);
	list_head_init(&update_bank);

	// Run as a generic platform using whatever storage
	proc_gen = 0;
	rc = run_test();

	clear_bank_list(&variable_bank);
	clear_bank_list(&update_bank);
	ASSERT(0 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	printf("PASSED FIRST TEST\n");

	// Run as "p9" and use the TPM for pk
	// TODO: Change to TSS stubs when this matters
	platform.secboot_read = secboot_read;
	platform.secboot_write = secboot_write;
	secboot_buffer = zalloc(ARBITRARY_SECBOOT_SIZE);

	proc_gen = proc_gen_p9;
	rc = run_test();

	free(secboot_buffer);
	clear_bank_list(&variable_bank);
	clear_bank_list(&update_bank);

	return rc;
}
