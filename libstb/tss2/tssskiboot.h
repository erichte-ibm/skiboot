/********************************************************************************/
/*										*/
/*		SKIBOOT Interface			  			*/
/*										*/
/* (c) Copyright IBM Corporation 2019.						*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/
#ifdef __SKIBOOT__

#ifndef TSSSKIBOOT_H
#define TSSSKIBOOT_H

#include <ibmtss/tss.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include "tssproperties.h"

TPM_RC get_context(void);
int TSS_PCR_Read(TPMI_DH_PCR pcrHandle, TPMI_ALG_HASH *hashes,
		 uint8_t hashes_len);
int TSS_PCR_Extend(TPMI_DH_PCR pcrHandle, TPMI_ALG_HASH *v_hashes,
                   uint8_t hashes_len, const char *digest);

TPM_RC TSS_NV_Read_Public(TPMI_RH_NV_INDEX nvIndex);
TPM_RC TSS_NV_Read(TPMI_RH_NV_INDEX nvIndex, void *buf, size_t bufsize, uint64_t off);
TPM_RC TSS_NV_Write(TPMI_RH_NV_INDEX nvIndex, void *buf, size_t bufsize, uint64_t off);
TPM_RC TSS_NV_WriteLock(TPMI_RH_NV_INDEX nvIndex);

TPM_RC TSS_NV_ReadPublic(TSS_CONTEXT *ctx, NV_ReadPublic_In *in,
			 NV_ReadPublic_Out *out);
int TSS_NV_Define_Space(TPMI_RH_NV_INDEX nvIndex, const char hierarchy,
			const char hierarchy_authorization,
			uint16_t dataSize);
int TSS_Get_Random_Number(char *buffer, size_t len);
#endif /* TSSSKIBOOT_H */
#endif /* __SKIBOOT__ */
