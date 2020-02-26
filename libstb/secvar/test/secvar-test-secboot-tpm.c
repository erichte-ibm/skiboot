#define TPM_SKIBOOT
#include "secvar_common_test.c"
#include "../storage/secboot_tpm.c"
#include "../storage/fakenv_ops.c"
#include "../../crypto/mbedtls/library/sha256.c"
#include "../../crypto/mbedtls/library/platform_util.c"
#include "../secvar_util.c"

char *secboot_buffer;

#define ARBITRARY_SECBOOT_SIZE 128000

const char *secvar_test_name = "secboot_tpm";

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

static int secboot_info(uint32_t *total_size)
{
	*total_size = ARBITRARY_SECBOOT_SIZE;
	return 0;
}

struct platform platform;

int run_test(void)
{
	int rc;
	struct secvar_node *tmp;

	platform.secboot_read = secboot_read;
	platform.secboot_write = secboot_write;
	platform.secboot_info = secboot_info;

	secboot_buffer = zalloc(ARBITRARY_SECBOOT_SIZE);

	// Initialize and format the storage
	rc = secboot_tpm_store_init();
	ASSERT(OPAL_SUCCESS == rc);

	// Load the just-formatted empty section
	rc = secboot_tpm_load_bank(&variable_bank, SECVAR_VARIABLE_BANK);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(0 == list_length(&variable_bank));

	// Add some test variables
	tmp = alloc_secvar(8);
	tmp->var->key_len = 5;
	memcpy(tmp->var->key, "test", 5);
	tmp->var->data_size = 8;
	memcpy(tmp->var->data, "testdata", 8);
	list_add_tail(&variable_bank, &tmp->link);

	tmp = alloc_secvar(8);
	tmp->var->key_len = 4;
	memcpy(tmp->var->key, "foo", 4);
	tmp->var->data_size = 8;
	memcpy(tmp->var->data, "moredata", 8);
	list_add_tail(&variable_bank, &tmp->link);

	// Add a priority variable, ensure that works
	tmp = alloc_secvar(4);
	tmp->var->key_len = 9;
	memcpy(tmp->var->key, "priority", 9);
	tmp->var->data_size = 4;
	memcpy(tmp->var->data, "meep", 4);
	tmp->flags |= SECVAR_FLAG_PRIORITY;
	list_add_tail(&variable_bank, &tmp->link);

	// Write the bank
	rc = secboot_tpm_write_bank(&variable_bank, SECVAR_VARIABLE_BANK);
	ASSERT(OPAL_SUCCESS == rc);
	// should write to bank 1 first
	ASSERT(secboot_image->bank[1][0] != 0);
	ASSERT(secboot_image->bank[0][0] == 0);

	// Clear the variable list
	clear_bank_list(&variable_bank);
	ASSERT(0 == list_length(&variable_bank));

	// Load the bank
	rc = secboot_tpm_load_bank(&variable_bank, SECVAR_VARIABLE_BANK);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(3 == list_length(&variable_bank));

	// Change a variable
	tmp = list_tail(&variable_bank, struct secvar_node, link);
	memcpy(tmp->var->data, "somethin", 8);

	// Write the bank
	rc = secboot_tpm_write_bank(&variable_bank, SECVAR_VARIABLE_BANK);
	ASSERT(OPAL_SUCCESS == rc);
	// should have data in both now
	ASSERT(secboot_image->bank[0][0] != 0);
	ASSERT(secboot_image->bank[1][0] != 0);

	clear_bank_list(&variable_bank);

	// Tamper with pnor, hash check should catch this
	secboot_image->bank[0][0] = ~secboot_image->bank[0][0];

	rc = secboot_tpm_load_bank(&variable_bank, SECVAR_VARIABLE_BANK);
	ASSERT(rc != OPAL_SUCCESS); // TODO: permission?

	// Fix it back...
	secboot_image->bank[0][0] = ~secboot_image->bank[0][0];

	// Should be ok again
	rc = secboot_tpm_load_bank(&variable_bank, SECVAR_VARIABLE_BANK);
	ASSERT(rc == OPAL_SUCCESS);

	clear_bank_list(&variable_bank);
	free(secboot_buffer);

	return 0;
}

int main(void)
{
	int rc = 0;

	list_head_init(&variable_bank);

	rc = run_test();

	if (rc)
		printf(COLOR_RED "FAILED" COLOR_RESET "\n");
	else
		printf(COLOR_GREEN "OK" COLOR_RESET "\n");

	free(tpmnv_vars_image);
	free(tpmnv_control_image);
	free(secboot_image);

	return rc;
}
