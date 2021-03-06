/*
 * Copyright © 2016 VMware, Inc.  All Rights Reserved.
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

DWORD
VdcSchemaConnInit(
    PVDC_SCHEMA_CONN*   ppConn
    )
{
    DWORD   dwError = 0;
    PVDC_SCHEMA_CONN    pConn = NULL;

    if (!ppConn)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirAllocateMemory(sizeof(VDC_SCHEMA_CONN), (PVOID*)&pConn);
    BAIL_ON_VMDIR_ERROR(dwError);

    *ppConn = pConn;

error:
    return dwError;
}

DWORD
VdcSchemaConnValidateAndSetDefault(
    PVDC_SCHEMA_CONN    pConn
    )
{
    DWORD   dwError = 0;

    if (!pConn)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    // domain is mandatory
    if (!pConn->pszDomain)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    // default host is "localhost"
    if (!pConn->pszHostName)
    {
        dwError = VmDirAllocateStringA("localhost", &pConn->pszHostName);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    // default user is "administrator"
    if (!pConn->pszUserName)
    {
        dwError = VmDirAllocateStringA("administrator", &pConn->pszUserName);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirAllocateStringPrintf(
            &pConn->pszUPN, "%s@%s", pConn->pszUserName, pConn->pszDomain);
    BAIL_ON_VMDIR_ERROR(dwError);

error:
    return dwError;
}

DWORD
VdcSchemaConnOpen(
    PVDC_SCHEMA_CONN    pConn
    )
{
    DWORD   dwError = 0;
    PSTR    pszLeader = NULL;

    if (!pConn)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    if (!pConn->pszPassword)
    {
        fprintf(stdout, "Enter password for %s: ", pConn->pszUPN);
        fflush(stdout);

        dwError = VdcSchemaReadPassword(&pConn->pszPassword);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    // Get the leader for this hostname
    dwError = VmDirRaftLeader(pConn->pszHostName, &pszLeader);
    BAIL_ON_VMDIR_ERROR(dwError);
    if (!pszLeader)
    {
        BAIL_WITH_VMDIR_ERROR(dwError, VMDIR_ERROR_NO_LEADER);
    }

    // always connect to leader
    dwError = VmDirSafeLDAPBindExt1(
        &pConn->pLd,
        pszLeader,
        pConn->pszUPN,
        pConn->pszPassword,
        MAX_LDAP_CONNECT_NETWORK_TIMEOUT);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    VMDIR_SAFE_FREE_MEMORY(pszLeader);
    return dwError;

error:
    goto cleanup;
}

VOID
VdcSchemaFreeConn(
    PVDC_SCHEMA_CONN    pConn
    )
{
    if (pConn)
    {
        VDIR_SAFE_LDAP_UNBIND_EXT_S(pConn->pLd);
        VMDIR_SAFE_FREE_MEMORY(pConn->pszDomain);
        VMDIR_SAFE_FREE_MEMORY(pConn->pszHostName);
        VMDIR_SAFE_FREE_MEMORY(pConn->pszUserName);
        VMDIR_SAFE_FREE_MEMORY(pConn->pszUPN);
        VMDIR_SECURE_FREE_STRINGA(pConn->pszPassword);
        VMDIR_SAFE_FREE_MEMORY(pConn);
    }
}
