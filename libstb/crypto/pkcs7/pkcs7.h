/**
 * \file pkcs7.h
 *
 * \brief PKCS7 generic defines and structures
 */
/*
 *  Copyright (C) 2019,  IBM Corp, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_PKCS7_H
#define MBEDTLS_PKCS7_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/asn1.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

/**
 * \name PKCS7 Error codes
 * \{
 */
#define MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE              -0x7080  /**< Unavailable feature, e.g. anything other than signed data. */
#define MBEDTLS_ERR_PKCS7_INVALID_FORMAT                   -0x7100  /**< The CRT/CRL format is invalid, e.g. different type expected. */
#define MBEDTLS_ERR_PKCS7_INVALID_VERSION                  -0x7180  /**< The PKCS7 version element is invalid or cannot be parsed. */
#define MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO             -0x7200  /**< The PKCS7 content info invalid or cannot be parsed. */
#define MBEDTLS_ERR_PKCS7_INVALID_ALG                      -0x7280  /**< The algorithm tag or value is invalid or cannot be parsed. */
#define MBEDTLS_ERR_PKCS7_INVALID_SIGNATURE                -0x7300  /**< Error parsing the signature */
#define MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO              -0x7380  /**< Error parsing the signer's info */
#define MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA                   -0x7400  /**< Input invalid. */
#define MBEDTLS_ERR_PKCS7_ALLOC_FAILED                     -0x7480  /**< Allocation of memory failed. */
#define MBEDTLS_ERR_PKCS7_FILE_IO_ERROR                    -0x7500  /**< File Read/Write Error */
/* \} name */

/**
 * \name PKCS7 Supported Version
 * \{
 */
#define MBEDTLS_PKCS7_SUPPORTED_VERSION                           0x01
/* \} name */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Type-length-value structure that allows for ASN1 using DER.
 */
typedef mbedtls_asn1_buf mbedtls_pkcs7_buf;

/**
 * Container for ASN1 named information objects.
 * It allows for Relative Distinguished Names (e.g. cn=localhost,ou=code,etc.).
 */
typedef mbedtls_asn1_named_data mbedtls_pkcs7_name;

/**
 * Container for a sequence of ASN.1 items
 */
typedef mbedtls_asn1_sequence mbedtls_pkcs7_sequence;

/**
 * Structure holding PKCS7 signer info
 */
typedef struct mbedtls_pkcs7_signer_info {
        int version;
        mbedtls_x509_buf serial;
        mbedtls_x509_name issuer;
        mbedtls_x509_buf issuer_raw;
        mbedtls_x509_buf alg_identifier;
        mbedtls_x509_buf sig_alg_identifier;
        mbedtls_x509_buf sig;
        struct mbedtls_pkcs7_signer_info *next;
}
mbedtls_pkcs7_signer_info;

/**
 * Structure holding attached data as part of PKCS7 signed data format
 */
typedef struct mbedtls_pkcs7_data {
        mbedtls_pkcs7_buf oid;
        mbedtls_pkcs7_buf data;
}
mbedtls_pkcs7_data;

/**
 * Structure holding the signed data section
 */
typedef struct mbedtls_pkcs7_signed_data {
        int version;
        mbedtls_pkcs7_buf digest_alg_identifiers;
        struct mbedtls_pkcs7_data content;
        mbedtls_x509_crt certs;
        mbedtls_x509_crl crl;
        struct mbedtls_pkcs7_signer_info signers;
}
mbedtls_pkcs7_signed_data;

/**
 * Structure holding PKCS7 structure, only signed data for now
 */
typedef struct mbedtls_pkcs7 {
        mbedtls_pkcs7_buf content_type_oid;
        struct mbedtls_pkcs7_signed_data signed_data;
}
mbedtls_pkcs7;

void mbedtls_pkcs7_init( mbedtls_pkcs7 *pkcs7 );

int mbedtls_pkcs7_parse_der(const unsigned char *buf, const int buflen, mbedtls_pkcs7 *pkcs7);

int mbedtls_pkcs7_signed_data_verify(mbedtls_pkcs7 *pkcs7, mbedtls_x509_crt *cert, const unsigned char *data, int datalen);
int mbedtls_pkcs7_signed_hash_verify(mbedtls_pkcs7 *pkcs7, mbedtls_x509_crt *cert, const unsigned char *hash, int hashlen);

int mbedtls_pkcs7_load_file( const char *path, unsigned char **buf, size_t *n );

void mbedtls_pkcs7_free(  mbedtls_pkcs7 *pkcs7 );

/*
 * PKCS#7 OIDs
 */
#define MBEDTLS_OID_PKCS7				MBEDTLS_OID_PKCS "\x07" /**< pkcs-7 */
#define MBEDTLS_OID_PKCS7_DATA				MBEDTLS_OID_PKCS7 "\x01" /**< pbeWithMD2AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 1} */
#define MBEDTLS_OID_PKCS7_SIGNED_DATA			MBEDTLS_OID_PKCS7 "\x02" /**< pbeWithMD2AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 1} */
#define MBEDTLS_OID_PKCS7_ENVELOPED_DATA		MBEDTLS_OID_PKCS7 "\x03" /**< pbeWithMD2AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 1} */
#define MBEDTLS_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA	MBEDTLS_OID_PKCS7 "\x04" /**< pbeWithMD2AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 1} */
#define MBEDTLS_OID_PKCS7_DIGESTED_DATA			MBEDTLS_OID_PKCS7 "\x05" /**< pbeWithMD2AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 1} */
#define MBEDTLS_OID_PKCS7_ENCRYPTED_DATA		MBEDTLS_OID_PKCS7 "\x06" /**< pbeWithMD2AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 1} */

#ifdef __cplusplus
}
#endif

#endif /* pkcs7.h */
