// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */

#define MBEDTLS_PKCS7_C
#include "secvar_common_test.c"
#include "../backend/edk2-compat.c"
#include "../backend/edk2-compat-process.c"
#include "../secvar_util.c"
#include "../../crypto/pkcs7/pkcs7.c"
#include "./data/PK.h"
#include "./data/noPK.h"
#include "./data/KEK.h"
#include "./data/invalidkek.h"
#include "./data/malformedkek.h"
#include "./data/db.h"
#include "./data/dbsigneddata.h"
#include "./data/OldTSKEK.h"
#include "./data/multipleKEK.h"
#include "./data/multipleDB.h"
#include "./data/multiplePK.h"
#include "./data/dbx.h"
#include "./data/dbxsha512.h"
#include "./data/dbxmalformed.h"

/* Hardcoding HW KEY HASH to avoid emulating device-tree in unit-tests */
const unsigned char hw_key_hash[64] = {
0xb6, 0xdf, 0xfe, 0x75, 0x53, 0xf9, 0x2e, 0xcb, 0x2b, 0x05, 0x55, 0x35, 0xd7, 0xda, 0xfe, 0x32, \
0x98, 0x93, 0x35, 0x1e, 0xd7, 0x4b, 0xbb, 0x21, 0x6b, 0xa0, 0x56, 0xa7, 0x1e, 0x3c, 0x0b, 0x56, \
0x6f, 0x0c, 0x4d, 0xbe, 0x31, 0x42, 0x13, 0x68, 0xcb, 0x32, 0x11, 0x6f, 0x13, 0xbb, 0xdd, 0x9e, \
0x4f, 0xe3, 0x83, 0x8b, 0x1c, 0x6a, 0x2e, 0x07, 0xdb, 0x95, 0x16, 0xc9, 0x33, 0xaa, 0x20, 0xef
};

int reset_keystore(struct list_head *bank __unused) { return 0; }
int verify_hw_key_hash(void) { return 0; }

int add_hw_key_hash(struct list_head *bank)
{
	struct secvar *var;
	uint32_t hw_key_hash_size = 64;

	var = new_secvar("HWKH", 5, hw_key_hash,
			hw_key_hash_size, SECVAR_FLAG_PROTECTED);
	list_add_tail(bank, &var->link);

	return OPAL_SUCCESS;
}

int delete_hw_key_hash(struct list_head *bank)
{
	struct secvar *var;

	var = find_secvar("HWKH", 5, bank);
	if (!var)
		return OPAL_SUCCESS;

	list_del(&var->link);
	dealloc_secvar(var);

	return OPAL_SUCCESS;
}

const char *secvar_test_name = "edk2-compat";

int secvar_set_secure_mode(void) { return 0; };

int run_test()
{
	int rc = -1;
	struct secvar *tmp;
	char empty[64] = {0};

	// Check pre-process creates the empty variables
	ASSERT(0 == list_length(&variable_bank));
	rc = edk2_compat_pre_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	tmp = find_secvar("TS", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(64 == tmp->data_size);
	ASSERT(!(memcmp(tmp->data, empty, 64)));

	// Add PK and a failed update
	printf("Add PK and failed dbx");
	tmp = new_secvar("PK", 3, PK_auth, PK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	tmp = new_secvar("dbx", 4, wrongdbxauth, wrong_dbx_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(2 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	rc = edk2_compat_post_process(&variable_bank, &update_bank);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(setup_mode);

	// Add PK and db, db update should fail, so all updates fail
	printf("Add PK");
	tmp = new_secvar("PK", 3, PK_auth, PK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));
	printf("Add db");
	tmp = new_secvar("db", 3, DB_auth, sizeof(DB_auth), 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(2 == list_length(&update_bank));
	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	rc = edk2_compat_post_process(&variable_bank, &update_bank);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(setup_mode);

	// Add PK to update and .process()
	printf("Add PK");
	tmp = new_secvar("PK", 3, PK_auth, PK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(6 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	rc = edk2_compat_post_process(&variable_bank, &update_bank);
	ASSERT(5 == list_length(&variable_bank));
	tmp = find_secvar("PK", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);
	ASSERT(PK_auth_len > tmp->data_size); // esl should be smaller without auth
	ASSERT(!setup_mode);

	// Add db, should fail with no KEK
	printf("Add db");
	tmp = new_secvar("db", 3, DB_auth, DB_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("db", 3, &variable_bank);
	ASSERT(NULL != tmp);

	// Add valid KEK, .process(), succeeds 
	printf("Add KEK");
	tmp = new_secvar("KEK", 4, KEK_auth, KEK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);

	// Add valid KEK, .process(), timestamp check fails 
	tmp = new_secvar("KEK", 4, OldTS_KEK_auth, OldTS_KEK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_PERMISSION == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);

	// Add db, .process(), should succeed
	printf("Add db again\n");
	tmp = new_secvar("db", 3, DB_auth, DB_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("db", 3, &variable_bank);
	printf("tmp is %s\n", tmp->key);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);

	// Add db, .process(), should fail because of timestamp 
	printf("Add db again\n");
	tmp = new_secvar("db", 3, DB_auth, DB_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_PERMISSION == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("db", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);

	// Add valid sha256 dbx
	printf("Add sha256 dbx\n");
	tmp = new_secvar("dbx", 4, dbxauth, dbx_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("db", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);

	// Add invalid KEK, .process(), should fail
	printf("Add invalid KEK\n");
	tmp = new_secvar("KEK", 4, InvalidKEK_auth, InvalidKEK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);

	// Add ill formatted KEK, .process(), should fail
	printf("Add invalid KEK\n");
	tmp = new_secvar("KEK", 4, MalformedKEK_auth, MalformedKEK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);

	// Add multiple KEK ESLs, one of them should sign the db 
	printf("Add multiple KEK\n");
	tmp = new_secvar("KEK", 4, multipleKEK_auth, multipleKEK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));
	printf("Add multiple db\n");
	tmp = new_secvar("db", 3, multipleDB_auth, multipleDB_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(2 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);
	tmp = find_secvar("db", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);


	/**
	// Add multiple DB ESLs signed with second key of the KEK 
	printf("Add multiple db\n");
	tmp = new_secvar("db", 3, multipleDB_auth, multipleDB_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));
	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("db", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);
	**/

	// Add db with signeddata PKCS7 format.
	printf("DB with signed data\n");
	tmp = new_secvar("db", 3, dbsigneddata_auth, dbsigneddata_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("db", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);

	//Delete PK and invalid dbx - to test queued updates for deleting PK
	printf("Delete PK\n");
	add_hw_key_hash(&variable_bank);
	ASSERT(6 == list_length(&variable_bank));
	tmp = new_secvar("PK", 3, noPK_auth, noPK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));
	printf("Add invalid dbx\n");
	tmp = new_secvar("dbx", 4, wrongdbxauth, wrong_dbx_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(2 == list_length(&update_bank));
	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(6 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	rc = edk2_compat_post_process(&variable_bank, &update_bank);
	ASSERT(5 == list_length(&variable_bank));
	tmp = find_secvar("PK", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);
	ASSERT(!setup_mode);

	// Delete PK. 
	printf("Delete PK\n");
	add_hw_key_hash(&variable_bank);
	ASSERT(6 == list_length(&variable_bank));
	tmp = new_secvar("PK", 3, noPK_auth, noPK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	rc = edk2_compat_post_process(&variable_bank, &update_bank);
	ASSERT(5 == list_length(&variable_bank));
	tmp = find_secvar("PK", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 == tmp->data_size);
	ASSERT(setup_mode);

	// Add multiple PK. 
	printf("Multiple PK\n");
	tmp = new_secvar("PK", 3, multiplePK_auth, multiplePK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("PK", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 == tmp->data_size);
	ASSERT(setup_mode);

	//Add invalid dbx like with wrong GUID
	printf("Add invalid dbx\n");
	tmp = new_secvar("dbx", 4, wrongdbxauth, wrong_dbx_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("PK", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 == tmp->data_size);
	ASSERT(setup_mode);

	// Ensure sha512 dbx is considered as valid.
	printf("Add sha512 dbx\n");
	tmp = new_secvar("dbx", 4, dbx512, dbx512_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("PK", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 == tmp->data_size);
	ASSERT(setup_mode);

	// We do not support cert as dbx.
	printf("Add db(cert) as dbx\n");
	tmp = new_secvar("dbx", 4, DB_auth, sizeof(DB_auth), 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("PK", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 == tmp->data_size);
	ASSERT(setup_mode);

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
