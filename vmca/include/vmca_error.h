/*
 * Copyright © 2012-2018 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */



/*
 * Module Name: VMware Certificate Server
 *
 * Filename: defines.h
 *
 * Abstract:
 *
 * VMware Certificate Server Error codes and Text
 *
 * Definitions
 *
 */

#ifndef __VMCA_ERROR_H__
#define __VMCA_ERROR_H__

typedef struct _VMCA_ERROR_CODE_NAME_MAP
{
    int         code;
    const char* name;
    const char* desc;

} VMCA_ERROR_CODE_NAME_MAP, *PVMCA_DB_ERROR_CODE_NAME_MAP;

#define UNKNOWN_STRING "UNKNOWN"

#define VMCA_SUCCESS                        0

#define VMCA_ROOT_CA_MISSING                70000
#define VMCA_ROOT_CA_ALREADY_EXISTS         (VMCA_ROOT_CA_MISSING +  1)
#define VMCA_INVALID_TIME_SPECIFIED         (VMCA_ROOT_CA_MISSING +  2)
#define VMCA_ARGUMENT_ERROR                 (VMCA_ROOT_CA_MISSING +  3)
#define VMCA_ERROR_TIME_OUT                 (VMCA_ROOT_CA_MISSING +  4)
#define VMCA_OUT_MEMORY_ERR                 (VMCA_ROOT_CA_MISSING +  5)
#define VMCA_REQUEST_ERROR                  (VMCA_ROOT_CA_MISSING +  6)
#define VMCA_KEY_CREATION_FAILURE           (VMCA_ROOT_CA_MISSING +  7)
#define VMCA_CERT_DECODE_FAILURE            (VMCA_ROOT_CA_MISSING +  8)
#define VMCA_KEY_IO_FAILURE                 (VMCA_ROOT_CA_MISSING +  9)
#define VMCA_CERT_IO_FAILURE                (VMCA_ROOT_CA_MISSING + 10)
#define VMCA_NOT_CA_CERT                    (VMCA_ROOT_CA_MISSING + 11)
#define VMCA_INVALID_CSR_FIELD              (VMCA_ROOT_CA_MISSING + 12)
#define VMCA_SELF_SIGNATURE_FAILED          (VMCA_ROOT_CA_MISSING + 13)
#define VMCA_INIT_CA_FAILED                 (VMCA_ROOT_CA_MISSING + 14)
#define VMCA_ERROR_INVALID_KEY_LENGTH       (VMCA_ROOT_CA_MISSING + 15)
#define VMCA_PKCS12_CREAT_FAIL              (VMCA_ROOT_CA_MISSING + 16)
#define VMCA_PKCS12_IO_FAIL                 (VMCA_ROOT_CA_MISSING + 17)
#define VMCA_CRL_ERROR                      (VMCA_ROOT_CA_MISSING + 18)
#define VMCA_NO_NEW_CRL                     (VMCA_ROOT_CA_MISSING + 19)
#define VMCA_ERROR_READING_CRL              (VMCA_ROOT_CA_MISSING + 20)
#define VMCA_CRL_LOCAL_ERROR                (VMCA_ROOT_CA_MISSING + 21)
#define VMCA_FILE_IO_ERROR                  (VMCA_ROOT_CA_MISSING + 22)
#define VMCA_FILE_TIME_ERROR                (VMCA_ROOT_CA_MISSING + 23)
#define VMCA_FILE_REMOVE_ERROR              (VMCA_ROOT_CA_MISSING + 24)
#define VMCA_SSL_SET_PUBKEY_ERR             (VMCA_ROOT_CA_MISSING + 25)
#define VMCA_SSL_ADD_EXTENSION              (VMCA_ROOT_CA_MISSING + 26)
#define VMCA_SSL_REQ_SIGN_ERR               (VMCA_ROOT_CA_MISSING + 27)
#define VMCA_SSL_RAND_ERR                   (VMCA_ROOT_CA_MISSING + 28)
#define VMCA_SSL_CERT_SIGN_ERR              (VMCA_ROOT_CA_MISSING + 29)
#define VMCA_SSL_TIME_ERROR                 (VMCA_ROOT_CA_MISSING + 30)
#define VMCA_SSL_EXT_ERR                    (VMCA_ROOT_CA_MISSING + 31)
#define VMCA_SSL_SIGN_FAIL                  (VMCA_ROOT_CA_MISSING + 32)
#define VMCA_SSL_SET_ISSUER_NAME            (VMCA_ROOT_CA_MISSING + 33)
#define VMCA_SSL_SET_START_TIME             (VMCA_ROOT_CA_MISSING + 34)
#define VMCA_SSL_SET_END_TIME               (VMCA_ROOT_CA_MISSING + 35)
#define VMCA_SSL_SET_EXT_ERR                (VMCA_ROOT_CA_MISSING + 36)
#define VMCA_CERT_PRIVATE_KEY_MISMATCH      (VMCA_ROOT_CA_MISSING + 37)
#define VMCA_INVALID_DOMAIN_NAME            (VMCA_ROOT_CA_MISSING + 38)
#define VMCA_INVALID_USER_NAME              (VMCA_ROOT_CA_MISSING + 39)
#define VMCA_UNABLE_GET_CRED_CACHE_NAME     (VMCA_ROOT_CA_MISSING + 40)
#define VMCA_NO_CACHE_FOUND                 (VMCA_ROOT_CA_MISSING + 41)
#define VMCA_KRB_ACCESS_DENIED              (VMCA_ROOT_CA_MISSING + 42)
#define VMCA_GET_ADDR_INFO_FAIL             (VMCA_ROOT_CA_MISSING + 43)
#define VMCA_NOT_IMPLEMENTED                (VMCA_ROOT_CA_MISSING + 44)
#define VMCA_GET_NAME_INFO_FAIL             (VMCA_ROOT_CA_MISSING + 45)
#define VMCA_CRL_SET_SERIAL_FAIL            (VMCA_ROOT_CA_MISSING + 46)
#define VMCA_CRL_SET_TIME_FAIL              (VMCA_ROOT_CA_MISSING + 47)
#define VMCA_CRL_CERT_ALREADY_REVOKED       (VMCA_ROOT_CA_MISSING + 48)
#define VMCA_CRLNUMBER_READ_ERROR           (VMCA_ROOT_CA_MISSING + 49)
#define VMCA_CRL_SIGN_FAIL                  (VMCA_ROOT_CA_MISSING + 50)
#define VMCA_CRL_REASON_FAIL                (VMCA_ROOT_CA_MISSING + 51)
#define VMCA_CRL_SORT_FAILED                (VMCA_ROOT_CA_MISSING + 52)
#define VMCA_CRL_NULL_TIME                  (VMCA_ROOT_CA_MISSING + 53)
#define VMCA_CRL_DECODE_ERROR               (VMCA_ROOT_CA_MISSING + 54)
#define VMCA_VPX_RSUTIL_ERROR               (VMCA_ROOT_CA_MISSING + 55)
#define VMCA_DIR_CREATE_ERROR               (VMCA_ROOT_CA_MISSING + 56)
#define VMCA_LOTUS_CERT_UPDATE_FAIL         (VMCA_ROOT_CA_MISSING + 57)
#define VMCA_LOTUS_CERT_READ_FAIL           (VMCA_ROOT_CA_MISSING + 58)
#define VMCA_LDAP_UFN_FAIL                  (VMCA_ROOT_CA_MISSING + 59)
#define VMCA_ERROR_INVALID_SN               (VMCA_ROOT_CA_MISSING + 60)
#define VMCA_ERROR_INVALID_SAN              (VMCA_ROOT_CA_MISSING + 61)
#define VMCA_ERROR_INCOMPLETE_CHAIN         (VMCA_ROOT_CA_MISSING + 62)
#define VMCA_ERROR_INVALID_CHAIN            (VMCA_ROOT_CA_MISSING + 63)
#define VMCA_ERROR_CANNOT_FORM_REQUEST      (VMCA_ROOT_CA_MISSING + 64)
#define VMCA_KEY_DECODE_FAILURE             (VMCA_ROOT_CA_MISSING + 65)
#define VMCA_ERROR_CN_HOSTNAME_MISMATCH     (VMCA_ROOT_CA_MISSING + 67)
#define VMCA_ERROR_SAN_HOSTNAME_MISMATCH    (VMCA_ROOT_CA_MISSING + 68)
#define VMCA_ERROR_SAN_IPADDR_INVALID       (VMCA_ROOT_CA_MISSING + 69)
#define VMCA_OPENSSL_ERROR                  (VMCA_ROOT_CA_MISSING + 70)

// REST
#define VMCA_ERROR_INVALID_URI              (VMCA_ROOT_CA_MISSING + 71)
#define VMCA_ERROR_MISSING_PARAMETER        (VMCA_ROOT_CA_MISSING + 72)
#define VMCA_ERROR_INVALID_METHOD           (VMCA_ROOT_CA_MISSING + 73)
#define VMCA_ERROR_CANNOT_LOAD_LIBRARY      (VMCA_ROOT_CA_MISSING + 74)
#define VMCA_ERROR_NO_FILE_OR_DIRECTORY     (VMCA_ROOT_CA_MISSING + 75)
#define VMCA_ERROR_AUTH_BAD_DATA            (VMCA_ROOT_CA_MISSING + 76)
#define VMCA_ERROR_INVALID_REQUEST          (VMCA_ROOT_CA_MISSING + 77)
#define VMCA_ERROR_UNAVAILABLE              (VMCA_ROOT_CA_MISSING + 78)
#define VMCA_ERROR_DLL_SYMBOL_NOTFOUND      (VMCA_ROOT_CA_MISSING + 79)

// hashing
#define VMCA_ERROR_EVP_DIGEST               (VMCA_ROOT_CA_MISSING + 80)

// JSON
#define VMCA_JSON_FILE_LOAD_ERROR           (VMCA_ROOT_CA_MISSING + 90)
#define VMCA_JSON_PARSE_ERROR               (VMCA_ROOT_CA_MISSING + 91)

#define VMCA_POLICY_VALIDATION_ERROR        (VMCA_ROOT_CA_MISSING + 95)
#define VMCA_POLICY_CONFIG_ERROR            (VMCA_ROOT_CA_MISSING + 96)
#define VMCA_ERROR_ENTRY_NOT_FOUND          (VMCA_ROOT_CA_MISSING + 97)
#define VMCA_ERROR_INVALID_STATE            (VMCA_ROOT_CA_MISSING + 98)
#define VMCA_ERROR_INVALID_ENTRY            (VMCA_ROOT_CA_MISSING + 99)

#define VMCA_UNKNOW_ERROR                   (VMCA_ROOT_CA_MISSING + 101)
#define VMCA_SSL_BIO_READ_ERROR             (VMCA_ROOT_CA_MISSING + 102)
 
//security offset 110 to 130
#define VMCA_SECURITY_NOT_INITIALIZED       (VMCA_ROOT_CA_MISSING + 110)
#define VMCA_SECURITY_ALREADY_INITIALIZED   (VMCA_ROOT_CA_MISSING + 111)
#define VMCA_SECURITY_INVALID_PLUGIN        (VMCA_ROOT_CA_MISSING + 112)
#define VMCA_SECURITY_KEY_ALREADY_IN_CACHE  (VMCA_ROOT_CA_MISSING + 113)
#define VMCA_SECURITY_KEY_NOT_IN_CACHE      (VMCA_ROOT_CA_MISSING + 114)
#define VMCA_SECURITY_KEY_NOT_IN_DB         (VMCA_ROOT_CA_MISSING + 115)

#define VMCA_ERROR_TABLE_INITIALIZER \
{ \
    { VMCA_SUCCESS                      ,   "VMCA_SUCCESS"                      ,   "The request succeded without any errors"}, \
    { VMCA_ROOT_CA_MISSING              ,   "VMCA_ROOT_CA_MISSING"              ,   "The Root CA certificate is missing or failed to Initialize" }, \
    { VMCA_ROOT_CA_ALREADY_EXISTS       ,   "VMCA_ROOT_CA_ALREADY_EXISTS"       ,   "Root CA Certificate is already present, Please use --force if you want to overwrite." }, \
    { VMCA_INVALID_TIME_SPECIFIED       ,   "VMCA_INVALID_TIME_SPECIFIED"       ,   "Invalid time specified for the Certififcate" }, \
    { VMCA_ARGUMENT_ERROR               ,   "VMCA_ARGUMENT_ERROR"               ,   "Invalid arguments found" }, \
    { VMCA_ERROR_TIME_OUT               ,   "VMCA_ERROR_TIME_OUT"               ,   "Time out occurred before specified Event." }, \
    { VMCA_OUT_MEMORY_ERR               ,   "VMCA_OUT_MEMORY_ERR"               ,   "Unable to allocate Memory" }, \
    { VMCA_REQUEST_ERROR                ,   "VMCA_REQUEST_ERROR"                ,   "Unable decode CSR" }, \
    { VMCA_KEY_CREATION_FAILURE         ,   "VMCA_KEY_CREATION_FAILURE"         ,   "Key Creation failure" }, \
    { VMCA_CERT_DECODE_FAILURE          ,   "VMCA_CERT_DECODE_FAILURE"          ,   "Cert Decode failure" }, \
    { VMCA_KEY_IO_FAILURE               ,   "VMCA_KEY_IO_FAILURE"               ,   "Key I/O failure" }, \
    { VMCA_CERT_IO_FAILURE              ,   "VMCA_CERT_IO_FAILURE"              ,   "Cert I/O failure" }, \
    { VMCA_NOT_CA_CERT                  ,   "VMCA_NOT_CA_CERT"                  ,   "Not a CA Cert" }, \
    { VMCA_INVALID_CSR_FIELD            ,   "VMCA_INVALID_CSR_FIELD"            ,   "Invalid CSR field" }, \
    { VMCA_SELF_SIGNATURE_FAILED        ,   "VMCA_SELF_SIGNATURE_FAILED"        ,   "Self Signature failed" }, \
    { VMCA_INIT_CA_FAILED               ,   "VMCA_INIT_CA_FAILED"               ,   "Init CA failure" }, \
    { VMCA_ERROR_INVALID_KEY_LENGTH     ,   "VMCA_ERROR_INVALID_KEY_LENGTH"     ,   "Key length has to be between 2048(2KB) and 16384(16KB)" }, \
    { VMCA_PKCS12_CREAT_FAIL            ,   "VMCA_PKCS12_CREAT_FAIL"            ,   "PKCS12 creation Failure" }, \
    { VMCA_PKCS12_IO_FAIL               ,   "VMCA_PKCS12_IO_FAIL"               ,   "PCKS12 I/O failure" }, \
    { VMCA_CRL_ERROR                    ,   "VMCA_CRL_ERROR"                    ,   "CRL update failed" }, \
    { VMCA_NO_NEW_CRL                   ,   "VMCA_NO_NEW_CRL"                   ,   "Client already has the latest CRL" }, \
    { VMCA_CRL_LOCAL_ERROR              ,   "VMCA_CRL_LOCAL_ERROR"              ,   "Failed in File I/O, Please Check Path / Permission" }, \
    { VMCA_FILE_IO_ERROR                ,   "VMCA_FILE_IO_ERROR"                ,   "File I/O Error" }, \
    { VMCA_FILE_TIME_ERROR              ,   "VMCA_FILE_TIME_ERROR"              ,   "Unable to parse time" }, \
    { VMCA_FILE_REMOVE_ERROR            ,   "VMCA_FILE_REMOVE_ERROR"            ,   "Unable to Remove File" }, \
    { VMCA_INVALID_DOMAIN_NAME          ,   "VMCA_INVALID_DOMAIN_NAME"          ,   "Invalid Domain Name" }, \
    { VMCA_INVALID_USER_NAME            ,   "VMCA_INVALID_USER_NAME"            ,   "Invalid User Name" }, \
    { VMCA_UNABLE_GET_CRED_CACHE_NAME   ,   "VMCA_UNABLE_GET_CRED_CACHE_NAME"   ,   "Failed to get cache Name" }, \
    { VMCA_NO_CACHE_FOUND               ,   "VMCA_NO_CACHE_FOUND"               ,   "Cred Cache not found" }, \
    { VMCA_GET_ADDR_INFO_FAIL           ,   "VMCA_GET_ADDR_INFO_FAIL"           ,   "getaddrinfo failure" }, \
    { VMCA_NOT_IMPLEMENTED              ,   "VMCA_NOT_IMPLEMENTED"              ,   "Not Implemented" }, \
    { VMCA_GET_NAME_INFO_FAIL           ,   "VMCA_GET_NAME_INFO_FAIL"           ,   "getnameinfo failure" }, \
    { VMCA_SSL_SET_PUBKEY_ERR           ,   "VMCA_SSL_SET_PUBKEY_ERR"           ,   "Set Public Key Failed" }, \
    { VMCA_SSL_ADD_EXTENSION            ,   "VMCA_SSL_ADD_EXTENSION"            ,   "Adding Extesions to cert failed" }, \
    { VMCA_SSL_REQ_SIGN_ERR             ,   "VMCA_SSL_REQ_SIGN_ERR"             ,   "Request Signing Failed" }, \
    { VMCA_SSL_RAND_ERR                 ,   "VMCA_SSL_RAND_ERR"                 ,   "Rand generation failed" }, \
    { VMCA_SSL_CERT_SIGN_ERR            ,   "VMCA_SSL_CERT_SIGN_ERR"            ,   "Certificate Signing failed" }, \
    { VMCA_SSL_TIME_ERROR               ,   "VMCA_SSL_TIME_ERROR"               ,   "Invalid Time Argument" }, \
    { VMCA_SSL_EXT_ERR                  ,   "VMCA_SSL_EXT_ERR"                  ,   "Unable to add this Extension" }, \
    { VMCA_SSL_SIGN_FAIL                ,   "VMCA_SSL_SIGN_FAIL"                ,   "Failed to sign the certificate" }, \
    { VMCA_SSL_SET_ISSUER_NAME          ,   "VMCA_SSL_SET_ISSUER_NAME"          ,   "Failed to set issuer name" }, \
    { VMCA_SSL_SET_START_TIME           ,   "VMCA_SSL_SET_START_TIME"           ,   "Start Time Error" }, \
    { VMCA_SSL_SET_END_TIME             ,   "VMCA_SSL_SET_END_TIME"             ,   "End Time Error" }, \
    { VMCA_SSL_SET_EXT_ERR              ,   "VMCA_SSL_SET_EXT_ERR"              ,   "Set Extenion Failed" }, \
    { VMCA_CERT_PRIVATE_KEY_MISMATCH    ,   "VMCA_CERT_PRIVATE_KEY_MISMATCH"    ,   "Cert/Key pair does not match" }, \
    { VMCA_INVALID_DOMAIN_NAME          ,   "VMCA_INVALID_DOMAIN_NAME"          ,   "Domain name error" }, \
    { VMCA_INVALID_USER_NAME            ,   "VMCA_INVALID_USER_NAME"            ,   "User name error" }, \
    { VMCA_UNABLE_GET_CRED_CACHE_NAME   ,   "VMCA_UNABLE_GET_CRED_CACHE_NAME"   ,   "Krb cred cache name error" }, \
    { VMCA_NO_CACHE_FOUND               ,   "VMCA_NO_CACHE_FOUND"               ,   "Krb cache not found" }, \
    { VMCA_KRB_ACCESS_DENIED            ,   "VMCA_KRB_ACCESS_DENIED"            ,   "Kerb access denied" }, \
    { VMCA_GET_ADDR_INFO_FAIL           ,   "VMCA_GET_ADDR_INFO_FAIL"           ,   "Network - Get addr info call failed" }, \
    { VMCA_NOT_IMPLEMENTED              ,   "VMCA_NOT_IMPLEMENTED"              ,   "Not implemented" }, \
    { VMCA_GET_NAME_INFO_FAIL           ,   "VMCA_GET_NAME_INFO_FAIL"           ,   "Network - Get name info call failed" }, \
    { VMCA_CRL_SET_SERIAL_FAIL          ,   "VMCA_CRL_SET_SERIAL_FAIL"          ,   "CRL - Setting serial number failed" }, \
    { VMCA_CRL_SET_TIME_FAIL            ,   "VMCA_CRL_SET_TIME_FAIL"            ,   "CRL - Setting time failed" }, \
    { VMCA_CRL_CERT_ALREADY_REVOKED     ,   "VMCA_CRL_CERT_ALREADY_REVOKED"     ,   "This is already revoked cert" }, \
    { VMCA_CRLNUMBER_READ_ERROR         ,   "VMCA_CRLNUMBER_READ_ERROR"         ,   "Unable to read CRL serial" }, \
    { VMCA_CRL_SIGN_FAIL                ,   "VMCA_CRL_SIGN_FAIL"                ,   "CRL - signing failed" }, \
    { VMCA_CRL_REASON_FAIL              ,   "VMCA_CRL_REASON_FAIL"              ,   "CRL - Unable to set reason" }, \
    { VMCA_CRL_SORT_FAILED              ,   "VMCA_CRL_SORT_FAILED"              ,   "CRL - Sorting failed" }, \
    { VMCA_CRL_NULL_TIME                ,   "VMCA_CRL_NULL_TIME"                ,   "CRL - Null time encountered" }, \
    { VMCA_CRL_DECODE_ERROR             ,   "VMCA_CRL_DECODE_ERROR"             ,   "CRL - Unable to decode CRL" }, \
    { VMCA_VPX_RSUTIL_ERROR             ,   "VMCA_VPX_RSUTIL_ERROR"             ,   "Unable to find a dependency." }, \
    { VMCA_DIR_CREATE_ERROR             ,   "VMCA_DIR_CREATE_ERROR"             ,   "Directory creation failed" }, \
    { VMCA_LOTUS_CERT_UPDATE_FAIL       ,   "VMCA_LOTUS_CERT_READ_FAIL"         ,   "Writing root cert to lotus failed" }, \
    { VMCA_LOTUS_CERT_READ_FAIL         ,   "VMCA_LOTUS_CERT_READ_FAIL"         ,   "Reading root cert from lotus failed" } , \
    { VMCA_LDAP_UFN_FAIL                ,   "VMCA_LDAP_UFN_FAIL"                ,   "LDAP call to dn2ufn failed." }, \
    { VMCA_ERROR_INVALID_SN             ,   "VMCA_ERROR_INVALID_SN"             ,   "Invalid Subject Name specified" }, \
    { VMCA_ERROR_INVALID_SAN            ,   "VMCA_ERROR_INVALID_SAN"            ,   "Invalid Subject Alternate Name specified." }, \
    { VMCA_ERROR_INCOMPLETE_CHAIN       ,   "VMCA_ERROR_INCOMPLETE_CERT_CHAIN"  ,   "Certificate Chain is not complete" }, \
    { VMCA_ERROR_INVALID_CHAIN          ,   "VMCA_ERROR_INVALID_CERT_CHAIN"     ,   "Invalid Certificate Chain was gives as input" }, \
    { VMCA_ERROR_CANNOT_FORM_REQUEST    ,   "VMCA_ERROR_CANNOT_FORM_REQUEST"    ,   "Could not create the CSR from the certificate" }, \
    { VMCA_KEY_DECODE_FAILURE           ,   "VMCA_KEY_DECODE_FAILURE"           ,   "Could not decode the Private Key from the given format" }, \
    { VMCA_ERROR_CN_HOSTNAME_MISMATCH   ,   "VMCA_ERROR_CN_HOSTNAME_MISMATCH"   ,   "CSR CN does not match to hostname" }, \
    { VMCA_ERROR_SAN_HOSTNAME_MISMATCH  ,   "VMCA_ERROR_SAN_HOSTNAME_MISMATCH"  ,   "CSR SAN does not match to hostname" }, \
    { VMCA_ERROR_SAN_IPADDR_INVALID     ,   "VMCA_ERROR_SAN_IPADDR_INVALID"     ,   "CSR SAN has an invalid ip" }, \
    { VMCA_OPENSSL_ERROR                ,   "VMCA_OPENSSL_ERROR"                ,   "OpenSSL Error" }, \
    { VMCA_ERROR_INVALID_URI            ,   "VMCA_ERROR_INVALID_URI"            ,   "Unknown request URI" }, \
    { VMCA_ERROR_MISSING_PARAMETER      ,   "VMCA_ERROR_MISSING_PARAMETER"      ,   "Missing expected parameter" }, \
    { VMCA_ERROR_INVALID_METHOD         ,   "VMCA_ERROR_INVALID_METHOD"         ,   "Invalid HTTP method" }, \
    { VMCA_ERROR_CANNOT_LOAD_LIBRARY    ,   "VMCA_ERROR_CANNOT_LOAD_LIBRARY"    ,   "Unable to load library" }, \
    { VMCA_ERROR_NO_FILE_OR_DIRECTORY   ,   "VMCA_ERROR_NO_FILE_OR_DIRECTORY"   ,   "Unable to find the specified file or directory" }, \
    { VMCA_ERROR_AUTH_BAD_DATA          ,   "VMCA_ERROR_AUTH_BAD_DATA"          ,   "Bad auth data presented" }, \
    { VMCA_ERROR_INVALID_REQUEST        ,   "VMCA_ERROR_INVALID_REQUEST"        ,   "Bad request caused by client error"}, \
    { VMCA_ERROR_UNAVAILABLE            ,   "VMCA_ERROR_UNAVAILABLE"            ,   "Server is unavailable/shutdown"}, \
    { VMCA_ERROR_DLL_SYMBOL_NOTFOUND    ,   "VMCA_ERROR_DLL_SYMBOL_NOTFOUND"    ,   "Unable to find symbol in library" }, \
    { VMCA_ERROR_EVP_DIGEST             ,   "VMCA_ERROR_EVP_DIGEST"             ,   "Error processing EVP digest" }, \
    { VMCA_JSON_FILE_LOAD_ERROR         ,   "VMCA_JSON_FILE_LOAD_ERROR"         ,   "Unable to load JSON file" }, \
    { VMCA_JSON_PARSE_ERROR             ,   "VMCA_JSON_PARSE_ERROR"             ,   "Failed to parse JSON file" }, \
    { VMCA_POLICY_VALIDATION_ERROR      ,   "VMCA_POLICY_VALIDATION_ERROR"      ,   "Request does not comply with policy" }, \
    { VMCA_POLICY_CONFIG_ERROR          ,   "VMCA_POLICY_CONFIG_ERROR"          ,   "Invalid content in policy config file" }, \
    { VMCA_ERROR_ENTRY_NOT_FOUND        ,   "VMCA_ERROR_ENTRY_NOT_FOUND"        ,   "Unable to find requested entry" }, \
    { VMCA_ERROR_INVALID_STATE          ,   "VMCA_ERROR_INVALID_STATE"          ,   "Invalid state of service" }, \
    { VMCA_ERROR_INVALID_ENTRY          ,   "VMCA_ERROR_INVALID_ENTRY"          ,   "Requested entry is invalid" }, \
    { VMCA_UNKNOW_ERROR                 ,   "VMCA_UNKNOWN_ERROR"                ,   "Certificate Server Unknown Error" }, \
    { VMCA_SSL_BIO_READ_ERROR           ,   "VMCA_SSL_BIO_READ_ERROR"           ,   "Failed to read data." }, \
    { VMCA_SECURITY_ALREADY_INITIALIZED ,   "VMCA_SECURITY_ALREADY_INITIALIZED" ,   "Initialize of security plugin is not allowed when already initialized." }, \
    { VMCA_SECURITY_NOT_INITIALIZED     ,   "VMCA_SECURITY_NOT_INITIALIZED"     ,   "Error initializing security plugin." }, \
    { VMCA_SECURITY_INVALID_PLUGIN      ,   "VMCA_SECURITY_INVALID_PLUGIN"      ,   "Loaded security plugin is invalid. Check plugin init state." }, \
    { VMCA_SECURITY_KEY_ALREADY_IN_CACHE,   "VMCA_SECURITY_KEY_ALREADY_IN_CACHE",   "An encrypted key is already present in local cache for this ca id." }, \
    { VMCA_SECURITY_KEY_NOT_IN_CACHE    ,   "VMCA_SECURITY_KEY_NOT_IN_CACHE"    ,   "An encrypted key is not present in local cache for this ca id." }, \
    { VMCA_SECURITY_KEY_NOT_IN_DB       ,   "VMCA_SECURITY_KEY_NOT_IN_DB"       ,   "An encrypted key is not present in db for this ca id." }, \
};



#endif //__VMCA_ERROR_H__

