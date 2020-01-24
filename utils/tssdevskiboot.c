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

#include <string.h>

#include <ibmtss/tssresponsecode.h>
#include <ibmtss/Implementation.h>
#include <ibmtss/tsserror.h>
#include <ibmtss/tssprint.h>
#include <tssproperties.h>

#include <tpm2.h>
#include <tssdevskiboot.h>

extern int tssVerbose;

TPM_RC TSS_Dev_Transmit(TSS_CONTEXT *tssContext,
			    uint8_t *responseBuffer, uint32_t *read,
			    const uint8_t *commandBuffer, uint32_t written,
			    const char *message)
{
	TPM_RC rc = 0;
	size_t size, responseSize;

	if (tssVerbose) {
		printf("%s: %s\n", "TSS_Skiboot_Transmit", message);
		TSS_PrintAll("TSS_Skiboot_Transmit: Command ",
			     commandBuffer, written);
	}
	/* we don't neeed to open a device as it is done in user space but we
	 * need to be sure a device and the driver are available for use.
	 */
	if(tssContext->tssFirstTransmit == TRUE){
		tssContext->tpm_device = tpm2_get_device();
	        tssContext->tpm_driver = tpm2_get_driver();
		if ((tssContext->tpm_device == NULL) || (tssContext->tpm_driver == NULL)) {
			printf("%s: tpm device/driver not set\n", "TSS_Skiboot_Transmit");
			rc = TSS_RC_NO_CONNECTION;
		}

	}

	tssContext->tssFirstTransmit = FALSE;

	/*
	 * Let's issue compilation issue if eventually MAX_COMMAND_SIZE becomes
	 * potentialy greater than MAX_RESPONSE_SIZE
	 */
#if MAX_COMMAND_SIZE > MAX_RESPONSE_SIZE
#error "MAX_COMMAND_SIZE can be greater than MAX_RESPONSE_SIZE. Potential overflow on the buffer for Command and Response"
#endif

	if (written > MAX_RESPONSE_SIZE)
		rc = TSS_RC_BAD_CONNECTION;

	/*
	 * the buffer used to send the command will be overwritten and store the
	 * response data after tpm execution. So here we copy the contents of
	 * commandBuffer to responseBuffer, using the latter to perform the
	 * operation and storing the response and keeping the former safe.
	 */
	if (rc == 0){
		memcpy(responseBuffer, commandBuffer, written);
		/*
		 * local copy of read - we update read itself once we confirm the
		 * transmit operation succeeded
		 */
		size = *read;
		rc = tssContext->tpm_driver->transmit(tssContext->tpm_device,
					      responseBuffer, written, &size);
	}

	/*
	 * Check if the response size in the response buffer matches read
	 * matches the value in size
	 */
	responseSize = ntohl(*(uint32_t *)(responseBuffer + sizeof(TPM_ST)));
	if (responseSize != size){
		if (tssVerbose)
			printf("%s: Bytes read (%ld) and Buffer responseSize field (%ld) don't match\n",
			       "TSS_Skiboot_Transmit:", size, responseSize);
	    rc = TSS_RC_MALFORMED_RESPONSE;
	}


	if (rc == 0) {
		*read = size;
		if (tssVerbose)
			TSS_PrintAll("TSS_Skiboot_Transmit: Response", responseBuffer, *read);

		if (*read < (sizeof(TPM_ST) + 2*sizeof(uint32_t))) {
			if (tssVerbose)
				printf("%s: received %d bytes < header\n", "TSS_Skiboot_Transmit", *read);
			rc = TSS_RC_MALFORMED_RESPONSE;
		}

	} else{
		if (tssVerbose)
			printf("%s: receive error %d\n", "TSS_Skiboot_Transmit", rc);
		rc = TSS_RC_BAD_CONNECTION;
	}

	/*
	 * Now we need to get the actual return code from the response buffer
	 * and delivery it to the upper layers
	 */
	if (rc == 0)
		rc = be32_to_cpu(*(uint32_t *)(responseBuffer + sizeof(TPM_ST) + sizeof(uint32_t)));

	if (tssVerbose)
		printf("%s: Response Code: %d", "TSS_Skiboot_Transmit", rc);

	return rc;
}

TPM_RC TSS_Dev_Close(TSS_CONTEXT *tssContext)
{
	tssContext = tssContext;
	return 0;
}
