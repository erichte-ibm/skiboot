// SPDX-License-Identifier: Apache-2.0
/* Copyright 2019 IBM Corp. */

#ifndef __SECVAR_BACKEND_COMMON__
#define __SECVAR_BACKEND_COMMON__

#ifndef pr_fmt
#define pr_fmt(fmt) "BACKEN_COMMON : " fmt
#endif

#include <opal.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <ccan/endian/endian.h>
#include <device.h>
#include "opal-api.h"
#include "../secvar.h"
#include "../secvar_devtree.h"

extern bool setup_mode;

/* Update the variable with the new value. */
int add_to_variable_bank(struct secvar *secvar, const char *data,
			 uint64_t dsize);
/* clear all os keys */
int clear_all_os_keys(void);

/* Check if physical presence is asserted */
bool is_physical_presence_asserted(void);

#endif
