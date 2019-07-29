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
#define SECBOOT_FILE "secboot.img"
#define SECBOOT_SIZE 128000

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <skiboot.h>
#include <ccan/list/list.h>
#include <stdarg.h>

// Force p9
enum proc_gen proc_gen = proc_gen_p9;

// Replace memalign with regular old malloc
#define memalign(a, b) malloc(b)
#define zalloc(a) calloc(1, a)



struct list_head variable_bank;
struct list_head update_bank;

struct secvar_storage_driver secvar_storage;


// For log file output instead of stdout
FILE *outfile;

#ifndef NO_COLOR
#define COLOR_RED	"\033[0;31m"
#define COLOR_GREEN	"\033[1;32m"
#define COLOR_RESET	"\033[0m"
#else
#define COLOR_RED	""
#define COLOR_GREEN	""
#define COLOR_RESET	""
#endif

// Helper functions and macros to make test case writing easier

// Semi-configurable assert, can use to jump to a clean up step on fail
#define ASSERT_POST(a,b) if(!(a)){fprintf(stdout, "Assert '%s' failed at %s:%d...", #a, __FILE__, __LINE__);b;}
#define ASSERT(a) ASSERT_POST(a, return 1)

// To be defined by test case
int run_test(void);
const char *secvar_test_name;
