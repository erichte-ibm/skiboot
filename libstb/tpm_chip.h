// SPDX-License-Identifier: Apache-2.0
/* Copyright 2013-2018 IBM Corp. */

#ifndef __TPM_H
#define __TPM_H

#include <device.h>

#include "tss2/eventlog.h"
#include <eventlib.h>
#include "tss2/tssskiboot.h"

#include <tpm2.h>

struct tpm_chip {

	/* TPM chip id */
	int id;

	/* Indicates whether or not the device and log are functional */
	bool enabled;

	/* TPM device tree node */
	struct dt_node *node;

	/* Event log handler */
	struct _TpmLogMgr logmgr;

	/* TPM device handler */
	struct tpm_dev    *dev;

	/* TPM driver handler */
	struct tpm_driver *driver;

	struct list_node link;
};

/* TSS tweak */
typedef struct tpm_chip TpmTarget;

/*
 * Register a tpm chip by binding the driver to dev.
 * Event log is also registered by this function.
 */
extern int tpm_register_chip(struct dt_node *node, struct tpm_dev *dev,
			     struct tpm_driver *driver);

/*
 * tpm_extendl - For each TPM device, this extends the sha1 and sha 256 digests
 * to the indicated PCR and also records an event for the same PCR
 * in the event log
 * This calls a TSS extend function that supports multibank. Both sha1 and
 * sha256 digests are extended in a single operation sent to the TPM device.
 */
int tpm_extendl(TPMI_DH_PCR pcr,
		TPMI_ALG_HASH alg1, uint8_t *digest1,
		TPMI_ALG_HASH alg2, uint8_t *digest2,
		uint32_t event_type, const char *event_msg);

/* Add status property to the TPM devices */
extern void tpm_add_status_property(void);

extern int tpm_init(void);
extern void tpm_cleanup(void);

#endif /* __TPM_H */
