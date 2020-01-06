/********************************************************************************/
/*										*/
/*		Skiboot Transmit and Receive Utilities				*/
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


#undef DEBUG
#define pr_fmt(fmt) "TSS-DEV-SKIBOOT: " fmt

#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsserror.h>
#include <ibmtss/tssprint.h>
#include "tssproperties.h"

#include "tpm2.h"
#include <skiboot.h>
#include "tssdevskiboot.h"

extern int tssVerbose;

TPM_RC TSS_Skiboot_Transmit(TSS_CONTEXT *tssContext,
			    uint8_t *responseBuffer, uint32_t *read,
			    const uint8_t *commandBuffer, uint32_t written,
			    const char *message)
{
	TPM_RC rc;
	size_t size;

	if (tssVerbose) {
		printf("%s: %s\n", __func__, message);
		TSS_PrintAll("TSS_Skiboot_Transmit: Command Buffer",
			     commandBuffer, written);
	}

	if ((tssContext->tpm_device == NULL) || (tssContext->tpm_driver == NULL)) {
		printf("%s: tpm device/driver not set\n", __func__);
		return TSS_RC_NO_CONNECTION;
	}

	tssContext->tssFirstTransmit = FALSE;

	/*
	 * the buffer used to send the command will be overwritten and store the
	 * response data after tpm execution. So here we copy the contents of
	 * commandBuffer to responseBuffer, using the latter to perform the
	 * operation and storing the response and keeping the former safe.
	 */
	memcpy(responseBuffer, commandBuffer, written);
	/*
	 * local copy of read - we update read itself once we confirm the
	 * transmit operation succeeded
	 */
	size = *read;
	rc = tssContext->tpm_driver->transmit(tssContext->tpm_device,
					      responseBuffer, written, &size);
	if (rc == 0) {
		*read = size;
		if (tssVerbose)
			TSS_PrintAll(
				"TSS_Skiboot_Transmit: response buffer data",
				responseBuffer, *read);

		if (*read < (sizeof(TPM_ST) + 2*sizeof(uint32_t))) {
			printf("received %d bytes < header\n", *read);
			rc = TSS_RC_MALFORMED_RESPONSE;
		}

	} else{
		printf("%s: receive error %d\n", __func__, rc);
		rc = TSS_RC_BAD_CONNECTION;
	}
	/*
	 * Now we need to get the actual return code from the response buffer
	 * and delivery it to the upper layers
	 */
	if (rc == 0)
		rc = be32_to_cpu(*(uint32_t *)(responseBuffer + sizeof(TPM_ST) + sizeof(uint32_t)));


	return rc;
}
