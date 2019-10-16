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

#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif
//#if defined(MBEDTLS_PKCS7_USE_C)

#include <mbedtls/x509.h>
#include <mbedtls/asn1.h>
#include "pkcs7.h"
#include <mbedtls/x509_crt.h>
#include <mbedtls/oid.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include <mbedtls/platform.h>
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_free      free
#define mbedtls_calloc    calloc
#define mbedtls_printf    printf
#define mbedtls_snprintf  snprintf
#endif

#if defined(MBEDTLS_HAVE_TIME)
#include <mbedtls/platform_time.h>
#endif
#if defined(MBEDTLS_HAVE_TIME_DATE)
#include <mbedtls/platform_util.h>
#include <time.h>
#endif

/*
 * Load all data from a file into a given buffer.
 *
 * The file is expected to contain DER encoded data.
 * A terminating null byte is always appended.
 */

#if 0
int mbedtls_pkcs7_load_file( const char *path, unsigned char **buf, size_t *n )
{
    FILE *f;
    long size;


    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( MBEDTLS_ERR_PKCS7_FILE_IO_ERROR );

    fseek( f, 0, SEEK_END );
    if( ( size = ftell( f ) ) == -1 )
    {
        fclose( f );
        return( MBEDTLS_ERR_PKCS7_FILE_IO_ERROR );
    }
    fseek( f, 0, SEEK_SET );

    *n = (size_t) size;

    if( *n + 1 == 0 ||
        ( *buf = mbedtls_calloc( 1, *n + 1 ) ) == NULL )
    {
        fclose( f );
        return( MBEDTLS_ERR_PKCS7_ALLOC_FAILED );
    }

    if( fread( *buf, 1, *n, f ) != *n )
    {
        fclose( f );

        mbedtls_platform_zeroize( *buf, *n + 1 );
        mbedtls_free( *buf );

        return( MBEDTLS_ERR_PKCS7_FILE_IO_ERROR );
    }

    fclose( f );

    (*buf)[*n] = '\0';

    return( 0 );
}
#endif

/**
 * Initializes the pkcs7 structure.
 */
void mbedtls_pkcs7_init( mbedtls_pkcs7 *pkcs7 )
{
    memset( pkcs7, 0, sizeof( mbedtls_pkcs7 ) );
}


static int pkcs7_get_next_content_len( unsigned char **p, unsigned char *end, size_t *len )
{
   int ret;

   if ( ( ret = mbedtls_asn1_get_tag( p, end, len, MBEDTLS_ASN1_CONSTRUCTED
                          | MBEDTLS_ASN1_CONTEXT_SPECIFIC ) ) != 0 )
      return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

   return ( 0 );
}

/**
 * version Version
 * Version ::= INTEGER
 **/
static int pkcs7_get_version( unsigned char **p, unsigned char *end, int *ver )
{
   int ret;

   if ( ( ret = mbedtls_asn1_get_int( p, end, ver ) ) != 0 )
       return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

   return ( 0 );
}

/**
 * ContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      content
 *              [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
 **/
static int pkcs7_get_content_info_type( unsigned char **p, unsigned char *end, mbedtls_pkcs7_buf *pkcs7 )
{
      size_t len = 0;
      int ret;

      ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                                            | MBEDTLS_ASN1_SEQUENCE );
      if ( ret )
              return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_OID );
      if ( ret )
              return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      pkcs7->tag = MBEDTLS_ASN1_OID;
      pkcs7->len = len;
      pkcs7->p = *p;

      return ret;
}

/**
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * This is from x509.h
 **/
static int pkcs7_get_digest_algorithm( unsigned char **p, unsigned char *end, mbedtls_x509_buf *alg )
{
      int ret;

      if ( ( ret = mbedtls_asn1_get_alg_null( p, end, alg ) ) != 0 )
          return ( MBEDTLS_ERR_PKCS7_INVALID_ALG + ret );

      return ( 0 );
}

/**
 * DigestAlgorithmIdentifiers :: SET of DigestAlgorithmIdentifier
 **/
static int pkcs7_get_digest_algorithm_set( unsigned char **p, unsigned char *end,
                                 mbedtls_x509_buf *alg )
{
      size_t len = 0;
      int ret;

      ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                                            | MBEDTLS_ASN1_SET );
      if ( ret != 0 )
              return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      end = *p + len;

      /** For now, it assumes there is only one digest algorithm specified **/
      ret = mbedtls_asn1_get_alg_null( p, end, alg );
      if ( ret )
              return ret;

      return ( 0 );
}

/**
 * certificates :: SET OF ExtendedCertificateOrCertificate,
 * ExtendedCertificateOrCertificate ::= CHOICE {
 *      certificate Certificate -- x509,
 *      extendedCertificate[0] IMPLICIT ExtendedCertificate }
 **/
static int pkcs7_get_certificates( unsigned char **buf, size_t buflen,
              mbedtls_x509_crt *certs )
{
      int ret;

      if ( ( ret = mbedtls_x509_crt_parse( certs, *buf, buflen ) ) != 0 )
          return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      return ( 0 );
}

/**
 * EncryptedDigest ::= OCTET STRING
 **/
static int pkcs7_get_signature( unsigned char **p, unsigned char *end,
              mbedtls_pkcs7_buf *signature )
{
      int ret;
      size_t len = 0;

      ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_OCTET_STRING);
      if ( ret != 0 )
              return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      signature->tag = MBEDTLS_ASN1_OCTET_STRING;
      signature->len = len;
      signature->p = *p;

      return ( 0 );
}

/**
 * SignerInfo ::= SEQUENCE {
 *      version Version;
 *      issuerAndSerialNumber   IssuerAndSerialNumber,
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      authenticatedAttributes
 *              [0] IMPLICIT Attributes OPTIONAL,
 *      digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
 *      encryptedDigest EncryptedDigest,
 *      unauthenticatedAttributes
 *              [1] IMPLICIT Attributes OPTIONAL,
 **/
static int pkcs7_get_signers_info_set( unsigned char **p, unsigned char *end,
                             mbedtls_pkcs7_signer_info *signers_set )
{
      unsigned char *end_set;
      int ret;
      size_t len = 0;

      ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                                            | MBEDTLS_ASN1_SET );
      if ( ret != 0 )
              return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      end_set = *p + len;

      ret = mbedtls_asn1_get_tag( p, end_set, &len, MBEDTLS_ASN1_CONSTRUCTED
                                                | MBEDTLS_ASN1_SEQUENCE );
      if ( ret != 0 )
              return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      ret = mbedtls_asn1_get_int( p, end_set, &signers_set->version );
      if ( ret != 0 )
              return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      ret = mbedtls_asn1_get_tag( p, end_set, &len, MBEDTLS_ASN1_CONSTRUCTED
                                                | MBEDTLS_ASN1_SEQUENCE );
      if ( ret != 0 )
              return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      signers_set->issuer_raw.p = *p;

      ret = mbedtls_asn1_get_tag( p, end_set, &len, MBEDTLS_ASN1_CONSTRUCTED
                                                | MBEDTLS_ASN1_SEQUENCE );
      if ( ret != 0 )
              return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      ret  = mbedtls_x509_get_name( p, *p + len, &signers_set->issuer );
      if ( ret != 0 )
              return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      signers_set->issuer_raw.len =  *p - signers_set->issuer_raw.p;

      ret = mbedtls_x509_get_serial( p, end_set, &signers_set->serial );
      if ( ret != 0 )
              return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      ret = pkcs7_get_digest_algorithm( p, end_set,
                                      &signers_set->alg_identifier );
      if ( ret != 0 )
              return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      ret = pkcs7_get_digest_algorithm( p, end_set,
                                      &signers_set->sig_alg_identifier );
      if ( ret != 0 )
              return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      ret = pkcs7_get_signature( p, end, &signers_set->sig );
      if ( ret != 0 )
              return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      signers_set->next = NULL;

      return ( 0 );
}

/**
 * SignedData ::= SEQUENCE {
 *      version Version,
 *      digestAlgorithms DigestAlgorithmIdentifiers,
 *      contentInfo ContentInfo,
 *      certificates
 *              [0] IMPLICIT ExtendedCertificatesAndCertificates
 *                  OPTIONAL,
 *      crls
 *              [0] IMPLICIT CertificateRevocationLists OPTIONAL,
 *      signerInfos SignerInfos }
 */
static int pkcs7_get_signed_data( unsigned char *buf, size_t buflen,
                        mbedtls_pkcs7_signed_data *signed_data )
{
      unsigned char *p = buf;
      unsigned char *end = buf + buflen;
      size_t len = 0;
      int ret;

      ret = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                                             | MBEDTLS_ASN1_SEQUENCE );
      if ( ret != 0 )
              return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

      /* Get version of signed data */
      ret = pkcs7_get_version( &p, end, &signed_data->version );
      if ( ret != 0 )
              return ( ret );

      /* If version != 1, return invalid version */
      if ( signed_data->version != MBEDTLS_PKCS7_SUPPORTED_VERSION ) {
              mbedtls_printf("Invalid version\n");
              return ( MBEDTLS_ERR_PKCS7_INVALID_VERSION );
      }

      /* Get digest algorithm */
      ret = pkcs7_get_digest_algorithm_set( &p, end,
                                          &signed_data->digest_alg_identifiers );
      if ( ret != 0 ) {
              mbedtls_printf("error getting digest algorithms\n");
              return ( ret );
      }

      if ( signed_data->digest_alg_identifiers.len != strlen( MBEDTLS_OID_DIGEST_ALG_SHA256 ) )
              return ( MBEDTLS_ERR_PKCS7_INVALID_ALG );

      if ( memcmp( signed_data->digest_alg_identifiers.p, MBEDTLS_OID_DIGEST_ALG_SHA256,
                 signed_data->digest_alg_identifiers.len ) ) {
              mbedtls_fprintf(stdout, "Digest Algorithm other than SHA256 is not supported\n");
              return ( MBEDTLS_ERR_PKCS7_INVALID_ALG );
      }

      /* Do not expect any content */
      ret = pkcs7_get_content_info_type( &p, end, &signed_data->content.oid );
      if ( ret != 0 )
              return ( MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA );

      if ( memcmp( signed_data->content.oid.p, MBEDTLS_OID_PKCS7_DATA,
                 signed_data->content.oid.len ) ) {
              mbedtls_printf("Invalid PKCS7 data\n");
              return ( MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA ) ;
      }

      p = p + signed_data->content.oid.len;

      ret = pkcs7_get_next_content_len( &p, end, &len );
      if ( ret != 0 )
              return ( ret ); 

      /* Get certificates */
      mbedtls_x509_crt_init( &signed_data->certs );
      ret = pkcs7_get_certificates( &p, len, &signed_data->certs );
      if ( ret != 0 )
              return ( ret ) ;

      p = p + len;

      /* Get signers info */
      ret = pkcs7_get_signers_info_set( &p, end, &signed_data->signers );
      if ( ret != 0 )
              return ( ret );

      return ( ret );
}

int mbedtls_pkcs7_parse_der( const unsigned char *buf, const int buflen,
                      mbedtls_pkcs7 *pkcs7 )
{
      unsigned char *start;
      unsigned char *end;
      size_t len = 0;
      int ret;

      /* use internal buffer for parsing */
      start = ( unsigned char * )buf;
      end = start + buflen;

      ret = pkcs7_get_content_info_type( &start, end, &pkcs7->content_type_oid );
      if ( ret != 0 )
              goto out;

      if ( ( !memcmp( pkcs7->content_type_oid.p, MBEDTLS_OID_PKCS7_DATA,
                 pkcs7->content_type_oid.len ) )
          || ( !memcmp( pkcs7->content_type_oid.p, MBEDTLS_OID_PKCS7_ENCRYPTED_DATA,
                 pkcs7->content_type_oid.len ) )
          || ( !memcmp(pkcs7->content_type_oid.p, MBEDTLS_OID_PKCS7_ENVELOPED_DATA,
                 pkcs7->content_type_oid.len ) )
            || ( !memcmp(pkcs7->content_type_oid.p, MBEDTLS_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA,
                 pkcs7->content_type_oid.len ) )
            || ( !memcmp(pkcs7->content_type_oid.p, MBEDTLS_OID_PKCS7_DIGESTED_DATA,
                 pkcs7->content_type_oid.len ) )
          || ( !memcmp(pkcs7->content_type_oid.p, MBEDTLS_OID_PKCS7_ENCRYPTED_DATA,
                 pkcs7->content_type_oid.len ) ) ) {
              mbedtls_printf("Unsupported PKCS7 data type\n");
              ret =  MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE;
              goto out;
      }

      if ( ( memcmp( pkcs7->content_type_oid.p, MBEDTLS_OID_PKCS7_SIGNED_DATA,
                 pkcs7->content_type_oid.len ) ) ) {
               mbedtls_printf("Invalid PKCS7 data type\n");
               ret = MBEDTLS_ERR_PKCS7_INVALID_ALG;
               goto out;
        }
      mbedtls_printf("Content type is SignedData, continue...\n");

      start = start + pkcs7->content_type_oid.len;

      ret = pkcs7_get_next_content_len( &start, end, &len );
      if ( ret != 0 )
              goto out;

      ret = pkcs7_get_signed_data( start, len, &pkcs7->signed_data );
      if ( ret != 0 )
              goto out;

out:
      return ( ret );
}

int mbedtls_pkcs7_signed_data_verify( mbedtls_pkcs7 *pkcs7, mbedtls_x509_crt *cert, const unsigned char *data, int datalen )
{

       int ret;
       unsigned char hash[32];
       mbedtls_pk_context pk_cxt = cert->pk;
       const mbedtls_md_info_t *md_info =
               mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );

       mbedtls_md( md_info, data, datalen, hash );
       ret = mbedtls_pk_verify( &pk_cxt, MBEDTLS_MD_SHA256,hash, 32, pkcs7->signed_data.signers.sig.p, pkcs7->signed_data.signers.sig.len );

       printf("rc is %02x\n", ret);

       return ( ret );
}

//#endif
