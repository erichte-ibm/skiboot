#ifndef _SECBOOT_TPM_H_
#define _SECBOOT_TPM_H_

// TODO: Determine reasonable values for these, or have platform set it?
#define SECBOOT_VARIABLE_BANK_SIZE	32000
#define SECBOOT_UPDATE_BANK_SIZE	32000

#define SECBOOT_VARIABLE_BANK_NUM	2

/* 0x5053424b = "PSBK" or Power Secure Boot Keystore */
#define SECBOOT_MAGIC_NUMBER	0x5053424b
#define SECBOOT_VERSION		1

#define SECBOOT_TPMNV_VARS_INDEX	0x01c10190
#define SECBOOT_TPMNV_CONTROL_INDEX	0x01c10191

struct secboot_header {
	uint32_t magic_number;
	uint8_t version;
	uint8_t reserved[3];	// Fix alignment
} __attribute__((packed));

struct secboot {
	struct secboot_header header;
	char bank[SECBOOT_VARIABLE_BANK_NUM][SECBOOT_VARIABLE_BANK_SIZE];
	char update[SECBOOT_UPDATE_BANK_SIZE];
} __attribute__((packed));

struct tpmnv_vars {
	struct secboot_header header;
	char vars[0];
} __attribute__((packed));

struct tpmnv_control {
	struct secboot_header header;
	uint8_t active_bit;
	char bank_hash[SECBOOT_VARIABLE_BANK_NUM][32]; // TODO: set to hashalg size?
} __attribute__((packed));

struct tpmnv_ops_s {
	int (*read)(uint32_t nvIndex, void *buf, size_t bufsize, uint64_t off);
	int (*write)(uint32_t nvIndex, void *buf, size_t bufsize, uint64_t off);
	int (*writelock)(uint32_t nvIndex);
	int (*definespace)(uint32_t, const char, const char, uint16_t);
};

#endif
