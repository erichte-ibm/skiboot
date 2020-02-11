// SPDX-License-Identifier: Apache-2.0
/* Copyright 2019 IBM Corp. */

#ifndef __SECVAR_EDK2_COMPAT_CLEAR_KEYS__
#define __SECVAR_EDK2_COMPAT_CLEAR_KEYS__

#ifndef pr_fmt
#define pr_fmt(fmt) "BACKEND_COMMON : " fmt
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

/* clear all os keys */
int clear_all_os_keys(void);

/* Check if physical presence is asserted */
bool is_physical_presence_asserted(void);

#endif
