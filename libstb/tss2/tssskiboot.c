/********************************************************************************/
/*										*/
/*			 Skiboot Support Interface  				*/
/*										*/
/* (c) Copyright IBM Corporation 2019						*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssfile.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/Startup_fp.h>
#include <ibmtss/tssprint.h>
//#include <libstb/tpm2.h>
#include "tpm2.h"
#include "tssproperties.h"
#include "tssskiboot.h"

static TSS_CONTEXT *context = NULL;

TPM_RC get_context(void){
	TPM_RC rc = TPM_RC_SUCCESS;

	if(!context){
		rc = TSS_Create(&context);
		if(rc)
			return rc;

		context->tpm_device = tpm2_get_device();
		context->tpm_driver = tpm2_get_driver();
		context->tssInterfaceType = "skiboot";
	}

	return rc;
}

static void traceError(const char *command, TPM_RC rc)
{
    const char *msg;
    const char *submsg;
    const char *num;
    printf("%s: failed, rc %08x\n", command, rc);
    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
    printf("%s%s%s\n", msg, submsg, num);
}

/**
 * @brief readpublic fills the TSS context object slot with the
 *        wrapping key public part. The Name is required for
 *        the HMAC calculation.
 *
 */
TPM_RC TSS_NV_ReadPublic(TSS_CONTEXT *ctx, NV_ReadPublic_In *in,
				NV_ReadPublic_Out *out)
{
	TPM_RC rc;

	printf("%s: nvIndex %x\n", __func__, in->nvIndex);

	rc = TSS_Execute(ctx,
			 (RESPONSE_PARAMETERS *) out,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_NV_ReadPublic,
			 TPM_RH_NULL, NULL, 0);

	if (rc == 0) {
		printf("%s: name algorithm %04x\n", __func__,
		       out->nvPublic.nvPublic.nameAlg);
		printf("%s: data size %u\n", __func__,
		       out->nvPublic.nvPublic.dataSize);
		printf("%s: attributes %08x\n", __func__,
		       out->nvPublic.nvPublic.attributes.val);
		TSS_TPMA_NV_Print(out->nvPublic.nvPublic.attributes, 0);
		TSS_PrintAll("TSS_NV_ReadPublic: policy",
			     out->nvPublic.nvPublic.authPolicy.t.buffer,
			     out->nvPublic.nvPublic.authPolicy.t.size);
		TSS_PrintAll("TSS_NV_ReadPublic: name",
			     out->nvName.t.name, out->nvName.t.size);
	} else {
		traceError("TSS_NV_ReadPublic", rc);
	}

	return rc;
}

TPM_RC TSS_NV_Read_Public(TPMI_RH_NV_INDEX nvIndex)
{
	TPM_RC rc;

        TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
        TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
        TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
        unsigned int sessionAttributes0 = 0;
        unsigned int sessionAttributes1 = 0;
        unsigned int sessionAttributes2 = 0;

	NV_ReadPublic_In *in;
	NV_ReadPublic_Out *out;

	in = zalloc(sizeof(NV_ReadPublic_In));
	if (!in)
		return -1;
	out = zalloc(sizeof(NV_ReadPublic_Out));
	if (!out) {
		free(in);
		return -1;
	}

	in->nvIndex = nvIndex;

	rc = get_context();
	if (rc)
		goto cleanup;

	rc = TSS_Execute(context,
		(RESPONSE_PARAMETERS *) out,
		(COMMAND_PARAMETERS *) in,
		NULL,
		TPM_CC_NV_ReadPublic,
		sessionHandle0, NULL, sessionAttributes0,
		sessionHandle1, NULL, sessionAttributes1,
		sessionHandle2, NULL, sessionAttributes2,
		TPM_RH_NULL, NULL, 0);

cleanup:
	free(in);
	free(out);

	return rc;
}


TPM_RC TSS_NV_Read(TPMI_RH_NV_INDEX nvIndex, void *buf, size_t bufsize, uint64_t off)
{
	int rc;

        TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
        TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
        TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
        unsigned int sessionAttributes0 = 0;
        unsigned int sessionAttributes1 = 0;
        unsigned int sessionAttributes2 = 0;

	NV_Read_In *in;
	NV_Read_Out *out;

	in = zalloc(sizeof(NV_Read_In));
	if (!in)
		return -1;
	out = zalloc(sizeof(NV_Read_Out));
	if (!out) {
		free(in);
		return -1;
	}

	in->nvIndex = nvIndex;
	in->offset = off;
	in->size = bufsize;

	rc = get_context();
	if (rc)
		goto cleanup;

	// TODO: Wrap this in multiple reads based on NV Buffer Max (1024)
	// TODO: Maybe use getcap to make sure.
	rc = TSS_Execute(context,
		(RESPONSE_PARAMETERS *) out,
		(COMMAND_PARAMETERS *) in,
		NULL,
		TPM_CC_NV_Read,
		sessionHandle0, NULL, sessionAttributes0,
		sessionHandle1, NULL, sessionAttributes1,
		sessionHandle2, NULL, sessionAttributes2,
		TPM_RH_NULL, NULL, 0);

	if (!rc) {
		if (out->data.b.size < bufsize)
			bufsize = out->data.b.size;
		memcpy(buf, out->data.b.buffer, bufsize);
	}

cleanup:
	free(in);
	free(out);

	return rc;


}


TPM_RC TSS_NV_Write(TPMI_RH_NV_INDEX nvIndex, void *buf, size_t bufsize, uint64_t off)
{
	int rc;

        TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
        TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
        TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
        unsigned int sessionAttributes0 = 0;
        unsigned int sessionAttributes1 = 0;
        unsigned int sessionAttributes2 = 0;

	NV_Write_In *in;

	in = zalloc(sizeof(NV_Read_In));
	if (!in)
		return -1;

	in->nvIndex = nvIndex;
	in->offset = off;

	// TODO: wtf is this doing
	rc = TSS_TPM2B_Create(&in->data.b, buf, bufsize, sizeof(in->data.t.buffer));
	if (rc)
		goto cleanup;

	rc = get_context();
	if (rc)
		goto cleanup;

	// TODO: Wrap this in multiple writes based on NV Buffer Max (1024)
	rc = TSS_Execute(context,
		NULL,
		(COMMAND_PARAMETERS *) in,
		NULL,
		TPM_CC_NV_Read,
		sessionHandle0, NULL, sessionAttributes0,
		sessionHandle1, NULL, sessionAttributes1,
		sessionHandle2, NULL, sessionAttributes2,
		TPM_RH_NULL, NULL, 0);

cleanup:
	free(in);

	return rc;


}


TPM_RC TSS_NV_WriteLock(TPMI_RH_NV_INDEX nvIndex)
{
	int rc;

        TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
        TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
        TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
        unsigned int sessionAttributes0 = 0;
        unsigned int sessionAttributes1 = 0;
        unsigned int sessionAttributes2 = 0;

	NV_WriteLock_In *in;

	in = zalloc(sizeof(NV_Read_In));
	if (!in)
		return -1;

	// TODO: make this an arg probably?
	in->authHandle = 'p';
	in->nvIndex = nvIndex;

	rc = get_context();
	if (rc)
		goto cleanup;

	rc = TSS_Execute(context,
		NULL,
		(COMMAND_PARAMETERS *) in,
		NULL,
		TPM_CC_NV_Read,
		sessionHandle0, NULL, sessionAttributes0,
		sessionHandle1, NULL, sessionAttributes1,
		sessionHandle2, NULL, sessionAttributes2,
		TPM_RH_NULL, NULL, 0);

cleanup:
	free(in);

	return rc;


}


int TSS_NV_Define_Space(TPMI_RH_NV_INDEX nvIndex, const char hierarchy,
			const char hierarchy_authorization,
			uint16_t dataSize)
{
	//NOTE(maurosr): we don't care with session values so far
	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = 0;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;


	TPMA_NV nvAttributes, setAttributes, clearAttributes;


	TPMI_ALG_HASH nalg = TPM_ALG_SHA256;
	char typeChar = 'o';
	const char *nvPassword = NULL, *parentPassword = NULL;

	NV_DefineSpace_In *in = calloc(1, sizeof(NV_DefineSpace_In));
	TPM_RC rc;

	nvAttributes.val = 0;
	setAttributes.val = TPMA_NVA_NO_DA;
	clearAttributes.val = 0;


	if(!in)
		return 1;

	rc = get_context();
	if(rc)
		goto cleanup;


	switch(hierarchy_authorization){
		case 'o':
			nvAttributes.val |= TPMA_NVA_OWNERWRITE | TPMA_NVA_OWNERREAD;
			break;
		case 'p':
			nvAttributes.val |= TPMA_NVA_PPWRITE | TPMA_NVA_PPREAD;
			break;
		case '\0':
			nvAttributes.val |= TPMA_NVA_AUTHWRITE | TPMA_NVA_AUTHREAD;
			break;
		default:
			printf("Invalid value for hierarchy authorization");
			rc = 1;
			goto cleanup;
	}
	switch(hierarchy){
		case 'p':
			in->authHandle = TPM_RH_PLATFORM;
			nvAttributes.val |= TPMA_NVA_PLATFORMCREATE;
			break;
		case 'o':
			nvAttributes.val |= TPMA_NVA_PLATFORMCREATE;
			in->authHandle = TPM_RH_OWNER;
			break;
		default:
			printf("Invalid value for hierarchy");
			rc = 1;
			goto cleanup;
	}


	if (typeChar == 'o')
		nvAttributes.val |= TPMA_NVA_ORDINARY;
	else{
		printf("TypeChar is set to somehing other than 'o', please add code to support that\n");
		rc = 1;
		goto cleanup;
        }

	/*
	 * NOTE(maurosr): This should receive proper piece of code for password
	 * handling when it becomes a parameter for this function.
	 * Ideally the code in here should just use TSS's parameters handling
	 * helpers, such helpers don't exist yet, but we should extract them from
	 * the main function of the binary utils living in TSS code.
	 * */
	if (nvPassword == NULL)
		in->auth.b.size = 0;
	else{

		printf("Password is not NULL, you need to add code for supporting this case. Aborting...\n");
		rc = 1;
		goto cleanup;
	}

	// Empty policy, support for non-empty should be added
	in->publicInfo.nvPublic.authPolicy.t.size = 0;

	in->publicInfo.nvPublic.nvIndex = nvIndex;
	// Default alg is SHA256, support for customizing this should be added.
	in->publicInfo.nvPublic.nameAlg = nalg;

	/*
	 * This carries the flags set according to default settings, excepting
	 * for what is set by this function parameters. Further customization
	 * will require a different setup for nvAttribute flags as is done in
	 * TSS's code.
	 * */
	in->publicInfo.nvPublic.attributes = nvAttributes;

	in->publicInfo.nvPublic.attributes.val |= setAttributes.val;
	in->publicInfo.nvPublic.attributes.val &= ~(clearAttributes.val);

	in->publicInfo.nvPublic.dataSize = dataSize;

	rc = TSS_Execute(context,
			 NULL,
			 (COMMAND_PARAMETERS *)in,
			 NULL,
			 TPM_CC_NV_DefineSpace,
			 sessionHandle0, parentPassword, sessionAttributes0,
			 sessionHandle1, NULL, sessionAttributes1,
			 sessionHandle2, NULL, sessionAttributes2,
			 TPM_RH_NULL, NULL, 0);
	if(rc)
		traceError("TSS_NV_Define_Space", rc);


cleanup:
	free(in);
	return rc? 1: 0 ;
}

/**
 * @brief Extends a PCR using the given hashes and digest
 * @param pcrHandle	The PCR to be extended
 * @param hashes	A pointer to an array of hash algorithms, each one
 * 			used to extend its respective PCR bank.
 * @param hashes_len	The length of hashes array.
 * @param digest	The digest data.
 */
int TSS_PCR_Extend(TPMI_DH_PCR pcrHandle, TPMI_ALG_HASH *hashes,
		      uint8_t hashes_len, const char *digest)
{
	PCR_Extend_In *in = calloc(1, sizeof(PCR_Extend_In));

	uint32_t rc = 1;

	if(!in || (strlen(digest) > sizeof(TPMU_HA)) )
		return 1;

	if(hashes_len >= HASH_COUNT)
		goto exit;

	rc = get_context();
	if(rc)
		goto exit;

	in->digests.count = hashes_len;
	in->pcrHandle = pcrHandle;
	for(int i=0; i < hashes_len; i++){
		in->digests.digests[i].hashAlg = hashes[i];
		// memset zeroes first to assure the digest data is zero padded.
		memset((uint8_t*) &in->digests.digests[i].digest, 0, sizeof(TPMU_HA));
		memcpy((uint8_t*) &in->digests.digests[i].digest, digest, strlen(digest));
	}
	rc = TSS_Execute(context,
			 NULL,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_PCR_Extend,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);

	if (rc !=  0){
		traceError("TSS_PCR_Extend", rc);
	}

exit:
	free(in);
	return rc? 1: 0;
}

/**
 * @brief Reads the PCR content
 * @param
 */
int TSS_PCR_Read(TPMI_DH_PCR pcrHandle, TPMI_ALG_HASH *hashes,
		 uint8_t hashes_len)
{
	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = 0;
	PCR_Read_Out *out;
	PCR_Read_In *in;
	uint32_t rc = 1;

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");

	if (hashes_len >= HASH_COUNT)
		return 1;

	in = calloc(1, sizeof(PCR_Read_In));
	if (!in)
		return 1;

	out = calloc(1, sizeof(PCR_Read_Out));
	if (!out)
		goto cleanup_in;

	rc = get_context();

	if (rc)
		goto cleanup_all;

	in->pcrSelectionIn.count = hashes_len;
	for( int i=0; i < hashes_len; i++){
		in->pcrSelectionIn.pcrSelections[i].hash = hashes[i];
		in->pcrSelectionIn.pcrSelections[i].sizeofSelect = 3;
		in->pcrSelectionIn.pcrSelections[i].pcrSelect[0] = 0;
		in->pcrSelectionIn.pcrSelections[i].pcrSelect[1] = 0;
		in->pcrSelectionIn.pcrSelections[i].pcrSelect[2] = 0;
		in->pcrSelectionIn.pcrSelections[i].pcrSelect[pcrHandle/8] = 1 << (pcrHandle % 8);
	}

	rc = TSS_Execute(context,
			 (RESPONSE_PARAMETERS *) out,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_PCR_Read,
                         sessionHandle0, NULL, sessionAttributes0,
			 TPM_RH_NULL, NULL, 0);

	if (rc !=  0)
		traceError("newTSS_PCR_Read", rc);


cleanup_all:
	free(out);
cleanup_in:
	free(in);
	return rc? 1: 0;
}

int TSS_Get_Random_Number(char *buffer, size_t len){
	TPM_RC rc = 0;
	TSS_CONTEXT *tssContext = NULL;
	GetRandom_In in;
	GetRandom_Out out;
	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = 0;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	unsigned int sessionAttributes1 = 0;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes2 = 0;


	in.bytesRequested = len;
        rc = TSS_Execute(tssContext,
                         (RESPONSE_PARAMETERS *)&out,
                         (COMMAND_PARAMETERS *)&in,
                         NULL, TPM_CC_GetRandom,
			 sessionHandle0, NULL, sessionAttributes0,
                         sessionHandle1, NULL, sessionAttributes1,
                         sessionHandle2, NULL, sessionAttributes2,
                         TPM_RH_NULL, NULL, 0);
	if (rc != 0)
		return -1;
	memcpy(buffer, out.randomBytes.t.buffer, len);
	return rc;

}
#endif /* __SKIBOOT__ */
