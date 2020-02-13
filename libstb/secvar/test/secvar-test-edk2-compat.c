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
#include "../backend/edk2-compat-process.c"
#include "../secvar_util.c"
#define MBEDTLS_PKCS7_USE_C
#include "../../crypto/pkcs7/pkcs7.c"
#include "./data/edk2_test_data.h"
#include "./data/PK1.h"
#include "./data/noPK.h"
#include "./data/KEK.h"
#include "./data/multipleKEK.h"
#include "./data/multipleDB.h"
#include "./data/multiplePK.h"

int reset_keystore(void) { return 0; }
bool is_physical_presence_asserted(void) { return 0; }
int add_hw_key_hash(void) { return 0; }
int delete_hw_key_hash(void) { return 0; }
int verify_hw_key_hash(void) { return 0; }

const char *secvar_test_name = "edk2-compat";

int secvar_set_secure_mode(void) { return 0; };

int run_test()
{
	int rc = -1;
	struct secvar_node *tmp;
	int keksize;
	int dbsize;
	struct secvar_node *ts;
	ts = alloc_secvar(sizeof(struct secvar) + 64);
        memcpy(ts->var->key, "TS", 3);
        ts->var->key_len = 3;
        memset(ts->var->data, 0, 64);
	ts->var->data_size = 64;

	// Check pre-process creates the empty variables
	ASSERT(0 == list_length(&variable_bank));
	rc = edk2_compat_pre_process();
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	tmp = find_secvar("TS", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(64 == tmp->var->data_size);
	ASSERT(!(memcmp(tmp->var->data, ts->var->data, 64)));
	

	// Add PK to update and .process()
	printf("Add PK");
	tmp = alloc_secvar(PK1_auth_len);
	memcpy(tmp->var->key, "PK", 3);
	tmp->var->key_len = 3;
	memcpy(tmp->var->data, PK1_auth, PK1_auth_len);
	tmp->var->data_size = PK1_auth_len;
	ASSERT(0 == edk2_compat_validate(tmp->var));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("PK", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->var->data_size);
	ASSERT(PK_auth_len > tmp->var->data_size); // esl should be smaller without auth
	ASSERT(!setup_mode);

	// Add db, should fail with no KEK
	printf("Add db");
	dbsize = sizeof(DB_auth);
	tmp = alloc_secvar(dbsize);
	memcpy(tmp->var->key, "db", 3);
	tmp->var->key_len = 3;
	memcpy(tmp->var->data, DB_auth, dbsize);
	tmp->var->data_size = dbsize;
	ASSERT(0 == edk2_compat_validate(tmp->var));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	printf("rc is %d %04x\n", rc, rc);
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("db", 3, &variable_bank);
	ASSERT(NULL != tmp);

	printf("Add KEK");

	// Add valid KEK, .process(), succeeds 

	tmp = alloc_secvar(KEK_auth_len);
	memcpy(tmp->var->key, "KEK", 4);
	tmp->var->key_len = 4;
	memcpy(tmp->var->data, KEK_auth, KEK_auth_len);
	tmp->var->data_size = KEK_auth_len;
	ASSERT(0 == edk2_compat_validate(tmp->var));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->var->data_size);

	// Add valid KEK, .process(), timestamp check fails 

	tmp = alloc_secvar(ValidKEK_auth_len);
	memcpy(tmp->var->key, "KEK", 4);
	tmp->var->key_len = 4;
	memcpy(tmp->var->data, ValidKEK_auth, ValidKEK_auth_len);
	tmp->var->data_size = ValidKEK_auth_len;
	ASSERT(0 == edk2_compat_validate(tmp->var));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_PERMISSION == rc);
	ASSERT(5 == list_length(&variable_bank));
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
	ASSERT(0 == edk2_compat_validate(tmp->var));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("db", 3, &variable_bank);
	printf("tmp is %s\n", tmp->var->key);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->var->data_size);

	// Add db, .process(), should fail because of timestamp 
	printf("Add db again\n");
	dbsize = sizeof(DB_auth);
	tmp = alloc_secvar(dbsize);
	memcpy(tmp->var->key, "db", 3);
	tmp->var->key_len = 3;
	memcpy(tmp->var->data, DB_auth, dbsize);
	tmp->var->data_size = dbsize;
	ASSERT(0 == edk2_compat_validate(tmp->var));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_PERMISSION == rc);

	// Add invalid KEK, .process(), should fail
	printf("Add invalid KEK\n");
	keksize = sizeof(InvalidKEK_auth);
	tmp = alloc_secvar(keksize);
	memcpy(tmp->var->key, "KEK", 4);
	tmp->var->key_len = 4;
	memcpy(tmp->var->data, InvalidKEK_auth, keksize);
	tmp->var->data_size = keksize;
	ASSERT(0 == edk2_compat_validate(tmp->var));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(5 == list_length(&variable_bank));
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
	ASSERT(0 == edk2_compat_validate(tmp->var));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->var->data_size);

	// Add multiple KEK ESLs, one of them should sign the db 
	printf("Add multiple KEK\n");
	tmp = alloc_secvar(multipleKEK_auth_len);
	memcpy(tmp->var->key, "KEK", 4);
	tmp->var->key_len = 4;
	memcpy(tmp->var->data, multipleKEK_auth, multipleKEK_auth_len);
	tmp->var->data_size = multipleKEK_auth_len;
	ASSERT(0 == edk2_compat_validate(tmp->var));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->var->data_size);

	// Add multiple DB ESLs signed with second key of the KEK 
	printf("Add multiple db\n");
	tmp = alloc_secvar(multipleDB_auth_len);
	memcpy(tmp->var->key, "db", 3);
	tmp->var->key_len = 3;
	memcpy(tmp->var->data, multipleDB_auth, multipleDB_auth_len);
	tmp->var->data_size = multipleDB_auth_len;
	ASSERT(0 == edk2_compat_validate(tmp->var));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("db", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->var->data_size);

	// Delete PK. 
	printf("Delete PK\n");
	tmp = alloc_secvar(noPK_auth_len);
	memcpy(tmp->var->key, "PK", 3);
	tmp->var->key_len = 3;
	memcpy(tmp->var->data, noPK_auth, noPK_auth_len);
	tmp->var->data_size = noPK_auth_len;
	ASSERT(0 == edk2_compat_validate(tmp->var));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process();
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("PK", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 == tmp->var->data_size);
	ASSERT(setup_mode);

	// Add multiple PK. 
	printf("Multiple PK\n");
	tmp = alloc_secvar(multiplePK_auth_len);
	memcpy(tmp->var->key, "PK", 3);
	tmp->var->key_len = 3;
	memcpy(tmp->var->data, multiplePK_auth, multiplePK_auth_len);
	tmp->var->data_size = multiplePK_auth_len;
	ASSERT(0 != edk2_compat_validate(tmp->var));

	return 0;
}

int main(void)
{
	int rc;

	list_head_init(&variable_bank);
	list_head_init(&update_bank);

	secvar_storage.max_var_size = 4096;

	rc = run_test();

	clear_bank_list(&variable_bank);
	clear_bank_list(&update_bank);

	return rc;
}
