/********************************************************************************/
/*										*/
/*			 TSS Library Dependent Crypto Support			*/
/*				 Written by Ken Goldman				*/
/*			   IBM Thomas J. Watson Research Center			*/
/*		ECC Salt functions written by Bill Martin			*/
/*										*/
/* (c) Copyright IBM Corporation 2020.						*/
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

/* Interface to mbedtls crypto library */

#include <string.h>
#include <stdio.h>

#ifndef TPM_TSS_NORSA
#include <mbedtls/rsa.h>
#endif
#include <mbedtls/md.h>
#ifdef TPM_ALG_SHA1
#include <mbedtls/sha1.h>
#endif
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/aes.h>
#include <mbedtls/hmac_drbg.h>

#include <tssskiboot.h>
#include <lock.h>
/* if no RSA and no ECC, don't need any asymmetric support */
#ifdef TPM_TSS_NORSA
#ifdef TPM_TSS_NOECC
#define TPM_TSS_NOASYM
#endif
#endif

#ifndef TPM_TSS_NOASYM
#include <mbedtls/pk.h>
#endif

#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/tsserror.h>

#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsscrypto.h>

extern int tssVverbose;
extern int tssVerbose;

/* local prototypes */

static void TSS_Error(int irc);
static TPM_RC TSS_Hash_GetMd(mbedtls_md_type_t *mdType,
			     TPMI_ALG_HASH hashAlg);
#ifndef TPM_TSS_NORSA
static TPM_RC TSS_RsaNew(void **rsaKey);
#endif
static int32_t crypto_seed_bytes(void *ctx __unused, unsigned char *buf, size_t len);
static int32_t tss_skiboot_crypto_drbg_init(void);
/*
  Initialization
*/
static struct lock drbg_lock = LOCK_UNLOCKED;
static mbedtls_hmac_drbg_context drbg_ctx;





#ifndef TPM_TSS_NOASYM
static TPM_RC TSS_PkContextNew(mbedtls_pk_context **ctx);
#endif

/* TSS_PkContextNew() allocates and initializes a mbedtls_pk_context */

#ifndef TPM_TSS_NOASYM

static TPM_RC TSS_PkContextNew(mbedtls_pk_context **ctx) /* freed by caller */
{
	TPM_RC 	rc = 0;

	/* sanity check for the free */
	if (rc == 0) {
		if (*ctx != NULL) {
			if (tssVerbose) printf("TSS_PkContextNew: Error (fatal), token %p should be NULL\n",
					       *ctx);
			rc = TSS_RC_ALLOC_INPUT;
		}
	}
	/* allocate the mbedtls_pk_context */
	if (rc == 0) {
		rc = TSS_Malloc((unsigned char **)ctx, sizeof(mbedtls_pk_context));
	}
	/* initialize but do not set up the context */
	if (rc == 0) {
		mbedtls_pk_init(*ctx);
	}
	return rc;
}
#endif	/* TPM_TSS_NOASYM */

/* Error trace */

static void TSS_Error(int irc)
{
	int src = 0 - irc;
	if (tssVerbose) printf("mbedtls error -%04x\n", src);
	return;
}

/*
  Digests
*/

/* TSS_Hash_GetMd() maps from a TCG hash algorithm to am mbedtls_md_type_t  */

static TPM_RC TSS_Hash_GetMd(mbedtls_md_type_t *mdType,
			     TPMI_ALG_HASH hashAlg)
{
	TPM_RC rc = 0;

	if (rc == 0) {
		switch (hashAlg) {
#ifdef TPM_ALG_SHA1
		case TPM_ALG_SHA1:
			*mdType = MBEDTLS_MD_SHA1;
			break;
#endif
#ifdef TPM_ALG_SHA256
		case TPM_ALG_SHA256:
			*mdType = MBEDTLS_MD_SHA256;
			break;
#endif
#ifdef TPM_ALG_SHA384
		case TPM_ALG_SHA384:
			*mdType = MBEDTLS_MD_SHA384;
			break;
#endif
#ifdef TPM_ALG_SHA512
		case TPM_ALG_SHA512:
			*mdType = MBEDTLS_MD_SHA512;
			break;
#endif
		default:
			rc = TSS_RC_BAD_HASH_ALGORITHM;
		}
	}
	return rc;
}

/* On call, digest->hashAlg is the desired hash algorithm

   length 0 is ignored, buffer NULL terminates list.
*/

TPM_RC TSS_HMAC_Generate_valist(TPMT_HA *digest,		/* largest size of a digest */
				const TPM2B_KEY *hmacKey,
				va_list ap)
{
	const mbedtls_md_info_t	*mdInfo = NULL;
	mbedtls_md_type_t mdType;
	mbedtls_md_context_t ctx;
	int done = FALSE;
	uint8_t *buffer;
	TPM_RC rc = 0;
	int irc = 0;
	int length;

	mbedtls_md_init(&ctx);	/* initialize the context */
	/* map from TPM digest algorithm to mbedtls type */
	if (rc == 0) {
		rc = TSS_Hash_GetMd(&mdType, digest->hashAlg);
	}
	if (rc == 0) {
		mdInfo =  mbedtls_md_info_from_type(mdType);
		if (mdInfo == NULL) {
			rc = TSS_RC_HMAC;
		}
	}
	if (rc == 0) {
		irc = mbedtls_md_setup(&ctx,		/* freed @1 */
					   mdInfo,
					   1); 		/* flag, hmac used */
		if (irc != 0) {
			TSS_Error(irc);
			rc = TSS_RC_HMAC;
		}
	}
	if (rc == 0) {
		rc = mbedtls_md_hmac_starts(&ctx,
						 hmacKey->b.buffer,
						 hmacKey->b.size);
		if (irc != 0) {
			TSS_Error(irc);
			rc = TSS_RC_HMAC;
		}
		}
	while ((rc == 0) && !done) {
		length = va_arg(ap, int);		/* first vararg is the length */
		buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
		if (buffer != NULL) {			/* loop until a NULL buffer terminates */
			if (length < 0) {
				if (tssVerbose) printf("TSS_HMAC_Generate: Length is negative\n");
				rc = TSS_RC_HMAC;
			}
			else {
				irc = mbedtls_md_hmac_update(&ctx, buffer, length);
				if (irc != 0) {
					TSS_Error(irc);
					if (tssVerbose) printf("TSS_HMAC_Generate: HMAC_Update failed\n");
					rc = TSS_RC_HMAC;
				}
			}
		}
		else {
			done = TRUE;
		}
	}

	if (rc == 0) {
		irc = mbedtls_md_hmac_finish(&ctx, (uint8_t *)&digest->digest);
		if (irc != 0) {
			TSS_Error(irc);
			rc = TSS_RC_HMAC;
		}
	}
	mbedtls_md_free(&ctx);	/* @1 */
	return rc;
}

/*
  valist is int length, unsigned char *buffer pairs

  length 0 is ignored, buffer NULL terminates list.
*/

TPM_RC TSS_Hash_Generate_valist(TPMT_HA *digest,		/* largest size of a digest */
				va_list ap)
{
	const mbedtls_md_info_t *mdInfo = NULL;
	mbedtls_md_context_t ctx;
	mbedtls_md_type_t mdType;
	int done = FALSE;
	uint8_t *buffer;
	TPM_RC rc = 0;
	int irc = 0;
	int length;

	mbedtls_md_init(&ctx);	/* initialize the context */
	/* map from TPM digest algorithm to mbedtls type */
	if (rc == 0) {
		rc = TSS_Hash_GetMd(&mdType, digest->hashAlg);
	}
	if (rc == 0) {
		mdInfo =  mbedtls_md_info_from_type(mdType);
		if (mdInfo == NULL) {
			if (tssVerbose) printf("TSS_Hash_Generate: Hash algorithm not found\n");
				rc = TSS_RC_HASH;
		}
	}
	if (rc == 0) {
		irc = mbedtls_md_setup(&ctx,		/* freed @1 */
					   mdInfo,
					   0); 		/* flag, hash used */
		if (irc != 0) {
			TSS_Error(irc);
			if (tssVerbose) printf("TSS_Hash_Generate: mbedtls_md_setup failed\n");
			rc = TSS_RC_HASH;
		}
	}
	if (rc == 0) {
		irc = mbedtls_md_starts(&ctx);
		if (irc != 0) {
			TSS_Error(irc);
			if (tssVerbose) printf("TSS_Hash_Generate: mbedtls_md_starts failed\n");
			rc = TSS_RC_HASH;
		}
	}
	while ((rc == 0) && !done) {
		length = va_arg(ap, int);		/* first vararg is the length */
		buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
		if (buffer != NULL) {			/* loop until a NULL buffer terminates */
			if (length < 0) {
				if (tssVerbose) printf("TSS_Hash_Generate: Length is negative\n");
				rc = TSS_RC_HASH;
			}
			else {
				/* if (tssVverbose) TSS_PrintAll("TSS_Hash_Generate:", buffer, length); */
				if (length != 0) {
					irc = mbedtls_md_update(&ctx, buffer, length);
					if (irc != 0) {
						TSS_Error(irc);
						rc = TSS_RC_HASH;
					}
				}
			}
		}
		else {
			done = TRUE;
		}
	}
	if (rc == 0) {
		irc = mbedtls_md_finish(&ctx, (uint8_t *)&digest->digest);
		if (irc != 0) {
		TSS_Error(irc);
		rc = TSS_RC_HASH;
	}
	}
	mbedtls_md_free(&ctx);	/* @1 */
	return rc;
}

/* Random Numbers */

TPM_RC TSS_RandBytes(unsigned char *buffer, uint32_t size)
{
	TPM_RC rc = 0;

	tss_skiboot_crypto_drbg_init();
	lock(&drbg_lock);
	rc = mbedtls_hmac_drbg_random(&drbg_ctx, buffer, size);
	unlock(&drbg_lock);

	return rc;
}

static int32_t crypto_seed_bytes(void *ctx __unused, unsigned char *buf,
				 size_t len)
{
	return tss_get_random_number(buf, len);
}

/*
  RSA functions
*/

#ifndef TPM_TSS_NORSA

/* NOTE: For mbedtls, TSS_RsaNew() and TSS_RsaFree() are not symmetrical.

   TSS_RsaNew() allocates the inner mbedtls_rsa_context structure.  TSS_RsaNew() should not have
   been public for OpenSSL, and is tetained but deprecated.  It is private for mbedtls.

   TSS_RsaFree(), which is public because it frees the TSS_RSAGeneratePublicTokenI() result, frees
   the outer mbedtls_pk_context structure.
*/


/* TSS_RsaNew() allocates an mbedtls RSA key token.

   This abstracts the crypto library specific allocation.

   For mbedtls, rsaKey is a mbedtls_rsa_context structure.
*/

TPM_RC TSS_RsaNew(void **rsaKey)
{
	TPM_RC  	rc = 0;

	/* sanity check for the free */
	if (rc == 0) {
		if (*rsaKey != NULL) {
			if (tssVerbose) printf("TSS_RsaNew: Error (fatal), token %p should be NULL\n",
					       *rsaKey);
			rc = TSS_RC_ALLOC_INPUT;
		}
	}
	/* construct the private key object */
	if (rc == 0) {
		rc = TSS_Malloc((unsigned char **)rsaKey, sizeof(mbedtls_rsa_context));
	}
	if (rc == 0) {
		mbedtls_rsa_init(*rsaKey, MBEDTLS_RSA_PKCS_V15, 0);
	}
	return rc;
}

/* TSS_RsaFree() frees an mbedtls_pk_context RSA key token.

   For compatibility with other crypto libraries, this is the outer wrapper, not the inner RSA
   structure.

   This abstracts the crypto library specific free.
*/

void TSS_RsaFree(void *rsaKey)
{
	mbedtls_pk_free(rsaKey);
	free(rsaKey);
	return;
}

/* TSS_RSAGeneratePublicTokenI() generates an mbedtls_pk_context RSA public key token from n and e

   Free rsa_pub_key using TSS_RsaFree();
*/

TPM_RC TSS_RSAGeneratePublicTokenI(void **rsa_pub_key,		/* freed by caller */
				   const unsigned char *narr,	/* public modulus */
				   uint32_t nbytes,
				   const unsigned char *earr,	/* public exponent */
				   uint32_t ebytes)
{
	const mbedtls_pk_info_t *pkInfo = NULL;
	mbedtls_rsa_context *rsaCtx = NULL;
	TPM_RC rc = 0;
	int irc;


	/* allocate and initialize the mbedtls_pk_context public key token */
	if (rc == 0) {
		rc = TSS_PkContextNew((mbedtls_pk_context **)rsa_pub_key);	/* freed by caller */
	}
	/* allocate and initialize the inner mbedtls_rsa_context */
	if (rc == 0) {
		rc = TSS_RsaNew((void **)&rsaCtx);	/* freed @1 contexts freed with wrapper */
	}
	if (rc == 0) {
		irc = mbedtls_rsa_import_raw(rsaCtx,
					     narr, nbytes,
					     NULL, 0,		/* p */
					     NULL, 0,		/* q */
					     NULL, 0,		/* d */
					     earr, ebytes);
		if (irc != 0) {
			TSS_Error(irc);
			rc = TSS_RC_RSA_KEY_CONVERT;
		}
	}
	if (rc == 0) {
	irc = mbedtls_rsa_complete(rsaCtx);
		if (irc != 0) {
			TSS_Error(irc);
			rc = TSS_RC_RSA_KEY_CONVERT;
		}
	}
	if (rc == 0) {
		irc = mbedtls_rsa_check_pubkey(rsaCtx);
		if (irc != 0) {
			TSS_Error(irc);
			rc = TSS_RC_RSA_KEY_CONVERT;
		}
	}
	/* build the mbedtls_pk_context from the mbedtls_rsa_context */
	if (rc == 0) {
		pkInfo = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
		if (pkInfo == NULL) {
			if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: "
				   	        "Error in mbedtls_pk_info_from_type()\n");
			rc = TSS_RC_RSA_KEY_CONVERT;
		}
	}
	/* set the metadata */
	if (rc == 0) {
		irc = mbedtls_pk_setup(*rsa_pub_key, pkInfo);
		if (irc != 0) {
			TSS_Error(irc);
			if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: Error in mbedtls_pk_setup()\n");
			rc = TSS_RC_RSA_KEY_CONVERT;
		}
	}
	/* copy the key data */
	if (rc == 0) {
		mbedtls_pk_context *pkCtx = (mbedtls_pk_context *)*rsa_pub_key;
		mbedtls_rsa_context *rsaPkCtx = mbedtls_pk_rsa(*pkCtx);
		memcpy(rsaPkCtx, rsaCtx, sizeof(mbedtls_rsa_context));
	}
	free(rsaCtx);
	return rc;
}

/* TSS_RSAPublicEncrypt() pads 'decrypt_data' to 'encrypt_data_size' and encrypts using the public
   key 'n, e'.
*/

TPM_RC TSS_RSAPublicEncrypt(unsigned char *encrypt_data,	/* encrypted data */
			    size_t encrypt_data_size,		/* size of encrypted data buffer */
			    const unsigned char *decrypt_data,	/* decrypted data */
			    size_t decrypt_data_size,
			    unsigned char *narr,		/* public modulus */
			    uint32_t nbytes,
			    unsigned char *earr,		/* public exponent */
			    uint32_t ebytes,
			    unsigned char *p,			/* encoding parameter */
			    int pl,
			    TPMI_ALG_HASH halg)			/* OAEP hash algorithm */
{
	unsigned char *padded_data = NULL;
	mbedtls_pk_context *pkCtx = NULL;
	TPM_RC rc = 0;
	int irc;

	if (tssVverbose) printf(" TSS_RSAPublicEncrypt: Input data size %lu\n",
				(unsigned long)decrypt_data_size);
	/* intermediate buffer for the decrypted but still padded data */
	if (rc == 0) {
		rc = TSS_Malloc(&padded_data, encrypt_data_size);	/* freed @2 */
	}
	/* construct the mbedtls_pk_context public key */
	if (rc == 0) {
		rc = TSS_RSAGeneratePublicTokenI((void **)&pkCtx,	/* freed @1 */
						 narr,	  		/* public modulus */
						 nbytes,
						 earr,	  		/* public exponent */
						 ebytes);
	}
	if (rc == 0) {
		padded_data[0] = 0x00;
		rc = TSS_RSA_padding_add_PKCS1_OAEP(padded_data,		/* to */
							encrypt_data_size,		/* to length */
							decrypt_data,		/* from */
							decrypt_data_size,		/* from length */
							p,		/* encoding parameter */
							pl,		/* encoding parameter length */
							halg);	/* OAEP hash algorithm */
	}
	if (rc == 0) {
		mbedtls_rsa_context *rsaCtx = NULL;
		if (tssVverbose)
			printf("  TSS_RSAPublicEncrypt: Padded data size %lu\n",
		   	       (unsigned long)encrypt_data_size);
		if (tssVverbose) TSS_PrintAll("  TPM_RSAPublicEncrypt: Padded data", padded_data,
					      encrypt_data_size);
		/* encrypt with public key.  Must pad first and then encrypt because the encrypt
		 * call cannot specify an encoding parameter
		 * returns the size of the encrypted data.  On error, -1 is returned
		 */
		rsaCtx  = mbedtls_pk_rsa(*pkCtx);		/* get inner RSA key */
		irc = mbedtls_rsa_public(rsaCtx,		/* key */
				 padded_data,			/* from - the clear text data */
				 encrypt_data);			/* the padded and encrypted data */
		if (irc != 0) {
			TSS_Error(irc);
			if (tssVerbose) printf("TSS_RSAPublicEncrypt: Error in mbedtls_rsa_public()\n");
			rc = TSS_RC_RSA_ENCRYPT;
		}
	}
	if (rc == 0) {
		if (tssVverbose) printf("  TSS_RSAPublicEncrypt: RSA_public_encrypt() success\n");
	}
	TSS_RsaFree(pkCtx);			/* @1 */
	free(padded_data);			/* @2 */
	return rc;
}

#endif /* TPM_TSS_NORSA */

#ifndef TPM_TSS_NOECC
/* TSS_GeneratePlatformEphemeralKey sets the EC parameters to NIST P256 for generating the ephemeral
   key. Some OpenSSL versions do not come with NIST p256.  */

static TPM_RC TSS_ECC_GeneratePlatformEphemeralKey(CURVE_DATA *eCurveData,
						   EC_KEY *myecc)
{
	if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: Unimplemented for mbedtls library\n");
	TPM_RC rc = TSS_RC_COMMAND_UNIMPLEMENTED;
	return rc;
}


/* TSS_ECC_Salt() returns both the plaintext and excrypted salt, based on the salt key bPublic.

   This is currently hard coded to the TPM_ECC_NIST_P256 curve.
*/

TPM_RC TSS_ECC_Salt(TPM2B_DIGEST *salt,
		    TPM2B_ENCRYPTED_SECRET *encryptedSalt,
		    TPMT_PUBLIC *publicArea)
{
	if (tssVerbose) printf("TSS_ECC_Salt: Unimplemented for mbedtls library\n");
	rc = TSS_RC_COMMAND_UNIMPLEMENTED;
	return rc;
}

#endif	/* TPM_TSS_NOECC */

/*
  AES
*/

TPM_RC TSS_AES_GetEncKeySize(size_t *tssSessionEncKeySize)
{
	*tssSessionEncKeySize = sizeof(mbedtls_aes_context);
	return 0;
}
TPM_RC TSS_AES_GetDecKeySize(size_t *tssSessionDecKeySize)
{
	*tssSessionDecKeySize = sizeof(mbedtls_aes_context);
	return 0;
}

#define TSS_AES_KEY_BITS 128

#ifndef TPM_TSS_NOCRYPTO
#ifndef TPM_TSS_NOFILE

TPM_RC TSS_AES_KeyGenerate(void *tssSessionEncKey,
			   void *tssSessionDecKey)
{
	TPM_RC		rc = 0;
	int 		irc;
	unsigned char 	userKey[AES_128_BLOCK_SIZE_BYTES];
	const char 		*envKeyString = NULL;
	unsigned char 	*envKeyBin = NULL;
	size_t 		envKeyBinLen;

	if (rc == 0) {
		envKeyString = getenv("TPM_SESSION_ENCKEY");
	}
	if (envKeyString == NULL) {
		/* If the env variable TPM_SESSION_ENCKEY is not set, generate a random key for this
		   TSS_CONTEXT */
		if (rc == 0) {
			rc = TSS_RandBytes(userKey, AES_128_BLOCK_SIZE_BYTES);
		}
	}
	/* The env variable TPM_SESSION_ENCKEY can set a (typically constant) encryption key.  This is
	   useful for scripting, where the env variable is set to a random seed at the beginning of the
	   script. */
	else {
		/* hexascii to binary */
		if (rc == 0) {
			rc = TSS_Array_Scan(&envKeyBin,			/* freed @1 */
					&envKeyBinLen, envKeyString);
		}
		/* range check */
		if (rc == 0) {
			if (envKeyBinLen != AES_128_BLOCK_SIZE_BYTES) {
				if (tssVerbose)
					printf("TSS_AES_KeyGenerate: Error, env variable length %lu not %lu\n",
					   (unsigned long)envKeyBinLen, (unsigned long)sizeof(userKey));
				rc = TSS_RC_BAD_PROPERTY_VALUE;

			}
		}
		/* copy the binary to the common userKey for use below */
		if (rc == 0) {
			memcpy(userKey, envKeyBin, envKeyBinLen);
		}
	}
	/* translate to an mbedtls key token */
	if (rc == 0) {
		mbedtls_aes_init(tssSessionEncKey);
		irc = mbedtls_aes_setkey_enc(tssSessionEncKey, userKey, TSS_AES_KEY_BITS);
		if (irc != 0) {
			TSS_Error(irc);
			if (tssVerbose)
				printf("TSS_AES_KeyGenerate: Error setting mbedtls AES encryption key\n");
			rc = TSS_RC_AES_KEYGEN_FAILURE;
		}
	}
	if (rc == 0) {
		mbedtls_aes_init(tssSessionDecKey);
		irc = mbedtls_aes_setkey_dec(tssSessionDecKey, userKey, TSS_AES_KEY_BITS);
		if (irc != 0) {
			TSS_Error(irc);
			if (tssVerbose) {
				printf("TSS_AES_KeyGenerate: Error setting mbedtls AES decryption key\n");
			}
			rc = TSS_RC_AES_KEYGEN_FAILURE;
		}
	}
	free(envKeyBin);	/* @1 */
	return rc;
}

#endif
#endif

/* TSS_AES_Encrypt() is AES non-portable code to encrypt 'decrypt_data' to 'encrypt_data' using CBC.
   This function uses the session encryption key for encrypting session state.

   The stream is padded as per PKCS#7 / RFC2630

   'encrypt_data' must be free by the caller
*/

#ifndef TPM_TSS_NOFILE

TPM_RC TSS_AES_Encrypt(void *tssSessionEncKey,
		       unsigned char **encrypt_data,		/* output, caller frees */
		       uint32_t *encrypt_length,		/* output */
		       const unsigned char *decrypt_data,	/* input */
		       uint32_t decrypt_length)			/* input */
{
	unsigned char ivec[AES_128_BLOCK_SIZE_BYTES];		/* initial chaining vector */
	unsigned char *decrypt_data_pad;
	uint32_t pad_length;
	TPM_RC rc = 0;
	int irc;

	decrypt_data_pad = NULL;	/* freed @1 */
	if (rc == 0) {
		/* calculate the pad length and padded data length */
		 pad_length = AES_128_BLOCK_SIZE_BYTES - (decrypt_length % AES_128_BLOCK_SIZE_BYTES);
		*encrypt_length = decrypt_length + pad_length;
		/* allocate memory for the encrypted response */
		rc = TSS_Malloc(encrypt_data, *encrypt_length);
	}
	/* allocate memory for the padded decrypted data */
	if (rc == 0) {
		rc = TSS_Malloc(&decrypt_data_pad, *encrypt_length);
	}
	/* pad the decrypted clear text data */
	if (rc == 0) {
		/* unpadded original data */
		memcpy(decrypt_data_pad, decrypt_data, decrypt_length);
		/* last gets pad = pad length */
		memset(decrypt_data_pad + decrypt_length, pad_length, pad_length);
		/* set the IV */
		memset(ivec, 0, sizeof(ivec));
		/* encrypt the padded input to the output */
		irc = mbedtls_aes_crypt_cbc(tssSessionEncKey,
					MBEDTLS_AES_ENCRYPT,
					*encrypt_length,
					ivec,
					decrypt_data_pad,
					*encrypt_data);
		if (irc != 0) {
			TSS_Error(irc);
			if (tssVerbose) printf("TSS_AES_Encrypt: Encryption failure -%04x\n", -irc);
			rc = TSS_RC_AES_ENCRYPT_FAILURE;
		}
	}
	free(decrypt_data_pad);		/* @1 */
	return rc;
}

#endif 	/* TPM_TSS_NOFILE */

/* TSS_AES_Decrypt() is AES non-portable code to decrypt 'encrypt_data' to 'decrypt_data' using CBC.
   This function uses the session encryption key for decrypting session state.

   The stream must be padded as per PKCS#7 / RFC2630

   decrypt_data must be free by the caller
*/

#ifndef TPM_TSS_NOFILE

TPM_RC TSS_AES_Decrypt(void *tssSessionDecKey,
		       unsigned char **decrypt_data,   		/* output, caller frees */
		       uint32_t *decrypt_length,		/* output */
		       const unsigned char *encrypt_data,	/* input */
		       uint32_t encrypt_length)			/* input */
{
	TPM_RC rc = 0;
	int irc;
	uint32_t pad_length;
	uint32_t i;
	unsigned char *pad_data;
	unsigned char ivec[AES_128_BLOCK_SIZE_BYTES];		/* initial chaining vector */

	/* sanity check encrypted length */
	if (rc == 0) {
		if (encrypt_length < AES_128_BLOCK_SIZE_BYTES) {
			if (tssVerbose) printf("TSS_AES_Decrypt: Error, bad length %u\n",
				   	       encrypt_length);
			rc = TSS_RC_AES_DECRYPT_FAILURE;
		}
	}
	/* allocate memory for the padded decrypted data */
	if (rc == 0) {
		rc = TSS_Malloc(decrypt_data, encrypt_length);
	}
	/* decrypt the input to the padded output */
	if (rc == 0) {
		/* set the IV */
		memset(ivec, 0, sizeof(ivec));
		/* decrypt the padded input to the output */
		irc = mbedtls_aes_crypt_cbc(tssSessionDecKey,
					MBEDTLS_AES_DECRYPT,
					encrypt_length,
					ivec,
					encrypt_data,
					*decrypt_data);
	}
	/* get the pad length */
	if (rc == 0) {
		/* get the pad length from the last byte */
		pad_length = (uint32_t)*(*decrypt_data + encrypt_length - 1);
		/* sanity check the pad length */
		if ((pad_length == 0) ||
			(pad_length > AES_128_BLOCK_SIZE_BYTES)) {
		if (tssVerbose) printf("TSS_AES_Decrypt: Error, illegal pad length\n");
			rc = TSS_RC_AES_DECRYPT_FAILURE;
		}
	}
	if (rc == 0) {
		/* get the unpadded length */
		*decrypt_length = encrypt_length - pad_length;
		/* pad starting point */
		pad_data = *decrypt_data + *decrypt_length;
		/* sanity check the pad */
		for (i = 0 ; (rc == 0) && (i < pad_length) ; i++, pad_data++) {
			if (*pad_data != pad_length) {
				if (tssVerbose) printf("TSS_AES_Decrypt: Error, bad pad %02x at index %u\n",
						   *pad_data, i);
				rc = TSS_RC_AES_DECRYPT_FAILURE;
			}
		}
	}
	return rc;
}

#endif 	/* TPM_TSS_NOFILE */

/* TSS_AES_EncryptCFB() is the unpadded AES used for command parameter encryption.

   The input and output are the same length.
*/

TPM_RC TSS_AES_EncryptCFB(uint8_t	*dOut,		/* OUT: the encrypted data */
			  uint32_t	keySizeInBits,	/* IN: key size in bits */
			  uint8_t 	*key,		/* IN: key buffer */
			  uint8_t 	*iv,		/* IN/OUT: IV for decryption */
			  uint32_t	dInSize,	/* IN: data size */
			  uint8_t 	*dIn)		/* IN: data buffer */
{
	mbedtls_aes_context aes_ctx;
	TPM_RC rc = 0;
	int irc;

	mbedtls_aes_init(&aes_ctx);
	if (rc == 0) {
		irc = mbedtls_aes_setkey_enc(&aes_ctx, key, keySizeInBits);	/* freed @1 */
		if (irc != 0) {
			TSS_Error(irc);
			rc = TSS_RC_AES_KEYGEN_FAILURE;
		}
	}
	if (rc == 0) {
		size_t iv_off = 0;
		irc = mbedtls_aes_crypt_cfb128(&aes_ctx,
					   MBEDTLS_AES_ENCRYPT,
					   dInSize,
					   &iv_off,
					   iv,
					   dIn,
					   dOut);
		if (irc != 0) {
			TSS_Error(irc);
			if (tssVerbose) printf("TSS_AES_EncryptCFB: Encryption failure -%04x\n", -irc);
			rc = TSS_RC_AES_ENCRYPT_FAILURE;
		}
	}
	mbedtls_aes_free(&aes_ctx);		/* @1 */
	return rc;
}

/* TSS_AES_DecryptCFB() is the unpadded AES used for response parameter decryption.

   The input and output are the same length.
*/

TPM_RC TSS_AES_DecryptCFB(uint8_t *dOut,	 	/* OUT: the decrypted data */
			  uint32_t keySizeInBits, 	/* IN: key size in bits */
			  uint8_t *key,			/* IN: key buffer */
			  uint8_t *iv,			/* IN/OUT: IV for decryption. */
			  uint32_t dInSize,	   	/* IN: data size */
			  uint8_t *dIn)			/* IN: data buffer */
{
	mbedtls_aes_context aes_ctx;
	TPM_RC rc = 0;
	int irc;

	if (tssVverbose) TSS_PrintAll("TSS_AES_DecryptCFB:", key, keySizeInBits/8);
	mbedtls_aes_init(&aes_ctx);
	if (rc == 0) {
		irc = mbedtls_aes_setkey_enc(&aes_ctx, key, keySizeInBits);	/* freed @1 */
		if (irc != 0) {
			TSS_Error(irc);
			rc = TSS_RC_AES_KEYGEN_FAILURE;
		}
	}
	if (rc == 0) {
		size_t iv_off = 0;
		irc = mbedtls_aes_crypt_cfb128(&aes_ctx,
					   MBEDTLS_AES_DECRYPT,
					   dInSize,
					   &iv_off,
					   iv,
					   dIn,
					   dOut);
		if (irc != 0) {
			TSS_Error(irc);
			if (tssVerbose) printf("TSS_AES_DecryptCFB: Decryption failure -%04x\n", -irc);
			rc = TSS_RC_AES_DECRYPT_FAILURE;
		}
	}
	mbedtls_aes_free(&aes_ctx);		/* @1 */
	return rc;
}

static int32_t tss_skiboot_crypto_drbg_init(void)
{
	int32_t rc;
	const mbedtls_md_info_t *md_info;

	if (tssVerbose) printf("mbedtls_hmac_drbg_init\n");
	mbedtls_hmac_drbg_init(&drbg_ctx);

	if (tssVerbose) printf("mbedtls_md_info_from_type\n");
	md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	assert(md_info);

	if (tssVerbose) printf("mbedtls_hmac_drbg_seed\n");
	rc = mbedtls_hmac_drbg_seed(&drbg_ctx, md_info,
					crypto_seed_bytes, NULL, NULL, 0);
	if (tssVerbose) printf("mbedtls_hmac_drbg_seed rc=%d\n",rc);
	if (rc) {
		return rc;
	}

	if (tssVerbose) printf("mbedtls_hmac_drbg_set_reseed_interval\n");
	mbedtls_hmac_drbg_set_reseed_interval(&drbg_ctx, 1000);

	if (tssVerbose) printf("mbedtls_hmac_drbg_set_prediction_resistance\n");
	mbedtls_hmac_drbg_set_prediction_resistance(&drbg_ctx,
			MBEDTLS_HMAC_DRBG_PR_OFF);

	if (tssVerbose) printf("crypto_drbg_init end\n");
	return rc;
}
