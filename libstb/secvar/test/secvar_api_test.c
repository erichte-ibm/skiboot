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


// Hack to include the code we actually want to test here...
#include "../secvar_api.c"
#include "../secvar_util.c"

// Stuff from secvar_main that we need, but not enough to
// include that file
int secvar_enabled = 0;
int secvar_ready = 0;


/**** Helper wrappers, so the caller doesn't have to cast ****/

static int64_t secvar_get(const char *k_key, uint64_t k_key_len, void *k_data, uint64_t *k_data_size)
{
	return opal_secvar_get( k_key,
				 k_key_len,
				 k_data,
				 k_data_size);
}

static int64_t secvar_get_next(char *k_key, uint64_t *k_key_len, uint64_t k_key_size)
{

	return opal_secvar_get_next( k_key,
					k_key_len,
					k_key_size);
}



static int64_t secvar_enqueue(const char *k_key, uint64_t k_key_len, void *k_data, uint64_t k_data_size)
{
	return opal_secvar_enqueue_update(k_key,
				k_key_len,
				k_data,
				k_data_size);

}



// Entry point
// TODO: do some real argparsing
int main(int argc, char **argv)
{
	int ret;

	(void) secvar_get;
	(void) secvar_get_next;
	(void) secvar_enqueue;
	(void) argc;
	(void) argv;

        secvar_enabled = 1;

        list_head_init(&variable_bank);
        list_head_init(&update_bank);

	secvar_ready = 1;

	printf("Running test '%s'...", secvar_test_name);
	ret = run_test();
	if (ret)
		printf(COLOR_RED "FAILED" COLOR_RESET "\n");
	else
		printf(COLOR_GREEN "OK" COLOR_RESET "\n");

	// Clean up for the test cases
	clear_bank_list(&variable_bank);
	clear_bank_list(&update_bank);

	return ret;
}
