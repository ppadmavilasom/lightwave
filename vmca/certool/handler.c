/*
 * Copyright © 2012-2019 VMware, Inc.  All Rights Reserved.
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
#include "includes.h"

static
DWORD
_GetConfigValue(
    PCERTOOL_CONFIG_DATA pConfig,
    VMCA_OID oid,
    PCSTR *ppcszValue
    )
{
    DWORD dwError = 0;
    PSTR pcszValue = NULL;
    PCERTOOL_CONFIG_DATA pTemp = pConfig;

    if (!pConfig || !ppcszValue)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

    for(pTemp = pConfig; pTemp; pTemp = pTemp->pNext)
    {
        if (pTemp->oidKey == oid)
        {
            pcszValue = pTemp->pszValue ? pTemp->pszValue : pTemp->pszDefault;
            break;
        }
    }
    if (!pTemp)
    {
        dwError = ERROR_NOT_FOUND;
        BAIL_ON_VMCA_ERROR(dwError);
    }
    *ppcszValue = pcszValue;

cleanup:
    return dwError;

error:
    goto cleanup;
}

static
DWORD
_UpdateReqData(
    PCERTOOL_CONFIG_DATA pConfig,
    PVMCA_PKCS_10_REQ_DATAA pCertReqData
    )
{
    DWORD dwError = ERROR_SUCCESS;
    PCSTR pcszValue = NULL;
    int i = 0;

    VMCA_OID oids[] =
    {
        VMCA_OID_CN, VMCA_OID_DC, VMCA_OID_COUNTRY, VMCA_OID_LOCALITY,
        VMCA_OID_STATE, VMCA_OID_ORGANIZATION, VMCA_OID_ORG_UNIT,
        VMCA_OID_DNS, VMCA_OID_EMAIL, VMCA_OID_IPADDRESS,
    };

    if (!pConfig || !pCertReqData)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

    for(i = 0; i < sizeof(oids)/sizeof(oids[0]); ++i)
    {
        dwError = _GetConfigValue(pConfig, oids[i], &pcszValue);
        BAIL_ON_VMCA_ERROR(dwError);

        if (IsNullOrEmptyString(pcszValue))
        {
            continue;
        }

        dwError = VMCASetCertValueA(oids[i], pCertReqData, (PSTR)pcszValue);
        BAIL_ON_VMCA_ERROR(dwError);
    }

cleanup:
    return dwError;
error:
    goto cleanup;
}

static
DWORD
_HandleGenCSR(
    PCERTOOL_CMD_ARGS pCmdArgs
    )
//
// This function generates a Root CA CSR , A private Key and Public Key for
// CA Certificates use, In order to use this CSR the generated file must
// taken to a CA that can sign the certificate and return it to us.
//
// Here are the steps in the initCSR creation process
//  1) We need to create a Public/Private Key Pair
//  2) Create a Certificate Signing Request Object -- which is PVMCA_PKCS_10_REQ_DATAA
//  3) Populate all fields that we are intersted in
//  4) Sign the CSR with our Private Key -- Please note: Private key never leaves our machine
//  5) Write the Private Key, Public Key and CSR to  user specified location
//
{
    DWORD dwError = 0;
    PVMCA_KEY pPrivateKey = NULL;
    PVMCA_KEY pPublicKey = NULL;
    PVMCA_PKCS_10_REQ_DATAA pCertReqData = NULL;
    PVMCA_CSR pCSR = NULL;
    PVMCA_CERTIFICATE pCertificate = NULL;
    PCERTOOL_CMD_GENCSR pCmd = pCmdArgs->pCmdGenCSR;

    if (!pCmd ||
        IsNullOrEmptyString(pCmd->pszPrivateKeyFile) ||
        IsNullOrEmptyString(pCmd->pszPublicKeyFile) ||
        IsNullOrEmptyString(pCmd->pszCSRFile))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

//
// Step 1: Create a Public / Private Key Pair
// The Key Length is set to 1024, Password is set to NULL
//
    dwError = VMCACreatePrivateKey( NULL, CERTOOL_PRIVATE_KEY_LENGTH, &pPrivateKey, &pPublicKey );
    BAIL_ON_VMCA_ERROR(dwError);
//
// Step 2: Create a Certificate Signing Request Object
//
    dwError = VMCAAllocatePKCS10DataA(&pCertReqData);
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = _UpdateReqData(pCmdArgs->pConfig, pCertReqData);
    BAIL_ON_VMCA_ERROR(dwError);

//
// Step 4: Create a Signing Request CSR ( PKCS10)
//
    dwError =  VMCACreateSigningRequestA(
                   pCertReqData,
                   pPrivateKey,
                   NULL,
                   &pCSR);
    BAIL_ON_VMCA_ERROR(dwError);
//
// Step 5 :
// write the private key to a location specified by the user
// This for illustration purpose only, you can also use
// VMCAWritePrivateKeyToFile which will handle things like Password on the
// Private Key.
//
    dwError = VMCAWriteAllText(pCmd->pszPrivateKeyFile, pPrivateKey);
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAWriteAllText(pCmd->pszPublicKeyFile, pPublicKey);
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAWriteAllText(pCmd->pszCSRFile, pCSR);
    BAIL_ON_VMCA_ERROR(dwError);

cleanup:
    VMCAFreeKey(pPrivateKey);
    VMCAFreeKey(pPublicKey);
    VMCAFreePKCS10DataA(pCertReqData);
    VMCAFreeCSR(pCSR);
    VMCAFreeCertificate(pCertificate);

    return dwError;
error:
    goto cleanup;
}

static
DWORD
_HandleGenKey(
    PCERTOOL_CMD_ARGS pCmdArgs
    )
//
// This function generates a Private / Public Key pair and
// write it down to a file.
//
// Here are the steps
//  1) Create Key Pair
//  2) Write to files
//
{
    DWORD dwError = 0;
    PVMCA_KEY pPrivateKey = NULL;
    PVMCA_KEY pPublicKey = NULL;
    PCERTOOL_CMD_GENKEY pCmd = pCmdArgs->pCmdGenKey;

    if (!pCmd ||
        IsNullOrEmptyString(pCmd->pszPrivateKeyFile) ||
        IsNullOrEmptyString(pCmd->pszPublicKeyFile))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }
//
// Step 1: Create a Public / Private Key Pair
// The Key Length is set to 1024, Password is set to NULL
//
    dwError = VMCACreatePrivateKey( NULL, CERTOOL_PRIVATE_KEY_LENGTH, &pPrivateKey, &pPublicKey );
    BAIL_ON_ERROR(dwError);
//
// Step 2.1 Write Private key to a file
//
    dwError =  VMCAWritePrivateKeyToFile(
                   pCmd->pszPrivateKeyFile,
                   (LPSTR) pPrivateKey,
                   NULL,
                   NULL);
    BAIL_ON_ERROR(dwError);

//
// Step 2.2 Write Public Key to File
//
    dwError = VMCAWritePublicKeyToFile(
                  pCmd->pszPublicKeyFile,
                  (LPSTR) pPublicKey
              );
    BAIL_ON_ERROR(dwError);

error:
    VMCAFreeKey(pPublicKey);
    VMCAFreeKey(pPrivateKey);

    return dwError;
}

DWORD
VMCAInvokeCommand(
    PCERTOOL_CMD_ARGS pCmdArgs
    )
{
    DWORD dwError = 0;
    typedef DWORD (*PFN_CERTOOL_CMD)(PCERTOOL_CMD_ARGS);
    struct stCmdMap
    {
        CERTOOL_CMD_TYPE type;
        PFN_CERTOOL_CMD pFnCmd;
    } arCmd[] =
    {
        {CERTOOL_CMD_TYPE_HELP,   HandleHelp},
        {CERTOOL_CMD_TYPE_GENCSR, _HandleGenCSR},
        {CERTOOL_CMD_TYPE_GENKEY, _HandleGenKey},
    };
    int i = 0;
    int nCommandCount = sizeof(arCmd)/sizeof(arCmd[0]);

    if (!pCmdArgs)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

    for(i = 0; i < nCommandCount; ++i)
    {
        if (pCmdArgs->cmdType == arCmd[i].type)
        {
            dwError = arCmd[i].pFnCmd(pCmdArgs);
            BAIL_ON_VMCA_ERROR(dwError);
            break;
        }
    }

    if (i >= nCommandCount)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}
