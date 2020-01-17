#ifndef _SECBOOT_TPM_H_
#define _SECBOOT_TPM_H_

// TODO: Determine reasonable values for these, or have platform set it?
#define SECBOOT_VARIABLE_BANK_SIZE	32000
#define SECBOOT_UPDATE_BANK_SIZE	32000

#define SECBOOT_VARIABLE_BANK_NUM	2

/* 0x5053424b = "PSBK" or Power Secure Boot Keystore */
#define SECBOOT_MAGIC_NUMBER	0x5053424b
#define SECBOOT_VERSION		1

struct secboot_header {
	uint32_t magic_number;
	uint8_t version;
	uint8_t reserved[3];	// Fix alignment
} __packed;

struct secboot {
	struct secboot_header header;
	char bank[SECBOOT_VARIABLE_BANK_NUM][SECBOOT_VARIABLE_BANK_SIZE];
	char update[SECBOOT_UPDATE_BANK_SIZE];
} __packed;

#endif
