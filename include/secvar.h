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

#ifndef _SECVAR_DRIVER_
#define _SECVAR_DRIVER_

#include <stdint.h>

struct secvar;

struct secvar_storage_driver {
        int (*load_bank)(struct list_head *bank, int section);
        int (*write_bank)(struct list_head *bank, int section);
        int (*store_init)(void);
};

struct secvar_backend_version {
	int major;
	int minor;
} __packed;

struct secvar_backend_driver {
        int (*pre_process)(void);               // Perform any pre-processing stuff (e.g. determine secure boot state)
        int (*process)(void);                   // Process all updates
        int (*post_process)(void);              // Perform any post-processing stuff (e.g. derive/update variables)
        int (*validate)(struct secvar *var);    // Validate a single variable, return boolean
        char compatible[32];			// String to use for compatible in secvar node
};


int secvar_main(struct secvar_storage_driver, struct secvar_backend_driver);

#endif
