/*
 * Copyright © 2012-2017 VMware, Inc.  All Rights Reserved.
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
VmDirInitDatabaseIndex(
    PVDIR_BACKEND_INSTANCE pBEInstance,
    PVOID pUserData
    );

static
VOID
VmDirFreeIndexData(
    PVDIR_INDEX_DATA pIndexData
    );

DWORD
VmDirIndexLibInit(
    PVMDIR_MUTEX    pModMutex
    )
{
    DWORD   dwError = 0;

    if (!pModMutex)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    // pModMutex refers to gVdirSchemaGlobals.cacheModMutex,
    // so do not free it during shutdown
    gVdirIndexGlobals.mutex = pModMutex;

    /* Initialize map from db path to db index data */
    dwError = LwRtlCreateHashMap(
            &gVdirIndexGlobals.pDBIndexData,
            LwRtlHashDigestPointer,
            LwRtlHashEqualPointer,
            NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

    /* Initialize all databases */
    dwError = VmDirIterateInstances(VmDirInitDatabaseIndex, NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

static
DWORD
VmDirInitDatabaseIndex(
    PVDIR_BACKEND_INSTANCE pBEInstance,
    PVOID pUserData
    )
{
    static VDIR_DEFAULT_INDEX_CFG defIdx[] = VDIR_INDEX_INITIALIZER;

    DWORD dwError = 0;
    DWORD                   i = 0;
    VDIR_BACKEND_CTX        beCtx = {0};
    PSTR                    pszLastOffset = NULL;
    BOOLEAN                 bHasTxn = FALSE;
    PVDIR_INDEX_CFG         pIndexCfg = NULL;
    PVDIR_SCHEMA_CTX        pSchemaCtx = NULL;
    PVDIR_SCHEMA_AT_DESC    pATDesc = NULL;
    PVDIR_INDEX_DATA        pIndexData = NULL;
    PVDIR_BACKEND_INTERFACE pBE = NULL;
    BOOLEAN                 bFreeIndexDataOnError = TRUE;

    if(!pBEInstance || !pBEInstance->pBE)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    pBE = pBEInstance->pBE;

    /* find index data */
    if (LwRtlHashMapFindKey(
            gVdirIndexGlobals.pDBIndexData,
            NULL,
            pBE) == 0)
    {
        dwError = ERROR_ALREADY_INITIALIZED;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirAllocateMemory(
                  sizeof(VDIR_INDEX_DATA),
                  (PVOID *)&pIndexData);
    BAIL_ON_VMDIR_ERROR(dwError);

    pIndexData->pBE = pBE;

    /* add db index data to map */
    dwError = LwRtlHashMapInsert(
            gVdirIndexGlobals.pDBIndexData,
            pBE,
            pIndexData,
            NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

    bFreeIndexDataOnError = FALSE;

    dwError = VmDirAllocateCondition(&pIndexData->cond);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = LwRtlCreateHashMap(
            &pIndexData->pIndexCfgMap,
            LwRtlHashDigestPstrCaseless,
            LwRtlHashEqualPstrCaseless,
            NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

    beCtx.pBE = pBE;

    dwError = beCtx.pBE->pfnBETxnBegin(&beCtx, VDIR_BACKEND_TXN_WRITE);
    BAIL_ON_VMDIR_ERROR(dwError);
    bHasTxn = TRUE;

    // get fields to continue indexing from where it left last time
    dwError = beCtx.pBE->pfnBEUniqKeyGetValue(
            &beCtx, INDEX_LAST_OFFSET_KEY, &pszLastOffset);
    if (dwError)
    {
        gVdirIndexGlobals.bFirstboot = TRUE;

        // set index_last_offset = -1 to indicate indexing has started
        pIndexData->offset = -1;
        dwError = beCtx.pBE->pfnBEUniqKeySetValue(
                &beCtx, INDEX_LAST_OFFSET_KEY, "-1");
        BAIL_ON_VMDIR_ERROR(dwError);
    }
    else
    {
        pIndexData->offset = VmDirStringToIA(pszLastOffset);
    }

    dwError = beCtx.pBE->pfnBETxnCommit(&beCtx);
    BAIL_ON_VMDIR_ERROR(dwError);
    bHasTxn = FALSE;

    dwError = VmDirSchemaCtxAcquire(&pSchemaCtx);
    BAIL_ON_VMDIR_ERROR(dwError);

    // open default indices
    for (i = 0; defIdx[i].pszAttrName; i++)
    {
        dwError = VmDirDefaultIndexCfgInit(pBE, &defIdx[i], &pIndexCfg);
        BAIL_ON_VMDIR_ERROR(dwError);

        // update attribute types in schema cache with their index info
        dwError = VmDirSchemaAttrNameToDescriptor(
                pSchemaCtx, pIndexCfg->pszAttrName, &pATDesc);
        BAIL_ON_VMDIR_ERROR(dwError);

        dwError = VmDirIndexCfgGetAllScopesInStrArray(
                pIndexCfg, &pATDesc->ppszUniqueScopes);
        BAIL_ON_VMDIR_ERROR(dwError);

        pATDesc->dwSearchFlags |= 1;

        // for free later
        pATDesc->pLdapAt->ppszUniqueScopes = pATDesc->ppszUniqueScopes;
        pATDesc->pLdapAt->dwSearchFlags = pATDesc->dwSearchFlags;

        dwError = VmDirIndexOpen(pBE, pIndexCfg);
        BAIL_ON_VMDIR_ERROR(dwError);
        pIndexCfg = NULL;
    }

    dwError = InitializeIndexingThread(pIndexData);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    if (bHasTxn)
    {
        beCtx.pBE->pfnBETxnAbort(&beCtx);
    }
    VmDirBackendCtxContentFree(&beCtx);
    VmDirSchemaCtxRelease(pSchemaCtx);
    VMDIR_SAFE_FREE_MEMORY(pszLastOffset);
    return dwError;

error:
    VMDIR_LOG_ERROR(
            VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)",
            __FUNCTION__,
            dwError);

    if(bFreeIndexDataOnError)
    {
        VmDirFreeIndexData(pIndexData);
    }
    VmDirFreeIndexCfg(pIndexCfg);
    goto cleanup;
}

/*
 * should only be used during bootstrap
 * maybe add state check?
 */
DWORD
VmDirIndexOpen(
    PVDIR_BACKEND_INTERFACE pBE,
    PVDIR_INDEX_CFG         pIndexCfg
    )
{
    DWORD   dwError = 0;
    BOOLEAN bInLock = FALSE;
    PVDIR_INDEX_DATA pIndexData = NULL;
    VDIR_BACKEND_CTX beCtx = {0};

    if (!pBE || !pIndexCfg)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    VMDIR_LOCK_MUTEX(bInLock, gVdirIndexGlobals.mutex);

    beCtx.pBE = pBE;

    dwError = VmDirLookupIndexData(pBE, &pIndexData);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (LwRtlHashMapFindKey(
            pIndexData->pIndexCfgMap, NULL, pIndexCfg->pszAttrName) == 0)
    {
        dwError = ERROR_ALREADY_INITIALIZED;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = LwRtlHashMapInsert(
            pIndexData->pIndexCfgMap,
            pIndexCfg->pszAttrName,
            pIndexCfg,
            NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = pBE->pfnBEIndexOpen(pBE, pIndexCfg);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    VMDIR_UNLOCK_MUTEX(bInLock, gVdirIndexGlobals.mutex);
    return dwError;

error:
    goto cleanup;
}


VOID
VmDirIndexLibShutdownDbIndex(
    PVDIR_INDEX_DATA pIndexData
    )
{
    if (!pIndexData)
    {
        return;
    }

    if (pIndexData->pThrInfo)
    {
        VmDirSrvThrShutdown(pIndexData->pThrInfo);
        pIndexData->pThrInfo = NULL;
    }

    if (pIndexData->pIndexCfgMap)
    {
        LwRtlHashMapClear(pIndexData->pIndexCfgMap,
                VmDirFreeIndexCfgMapPair, NULL);
        LwRtlFreeHashMap(&pIndexData->pIndexCfgMap);
        pIndexData->pIndexCfgMap = NULL;
    }

    VmDirIndexUpdFree(pIndexData->pIndexUpd);
    pIndexData->pIndexUpd = NULL;

    VMDIR_SAFE_FREE_CONDITION(pIndexData->cond);
    pIndexData->cond = NULL;
}

static
VOID
VmDirFreeIndexData(
    PVDIR_INDEX_DATA pIndexData
    )
{
    if(pIndexData)
    {
        VmDirIndexLibShutdownDbIndex(pIndexData);
        VMDIR_SAFE_FREE_MEMORY(pIndexData);
    }
}

/*
    iterator callback which initiates shutdown for each index
*/
static
VOID
_VmDirIndexLibShutdownPair(
    PLW_HASHMAP_PAIR    pPair,
    LW_PVOID            pUnused
    )
{
    PVDIR_INDEX_DATA pIndexData = (PVDIR_INDEX_DATA)pPair->pValue;
    VmDirFreeIndexData(pIndexData);
}

VOID
VmDirIndexLibShutdown(
    VOID
    )
{
    if (gVdirIndexGlobals.pDBIndexData)
    {
        LwRtlHashMapClear(
            gVdirIndexGlobals.pDBIndexData,
            _VmDirIndexLibShutdownPair,
            NULL);
        LwRtlFreeHashMap(&gVdirIndexGlobals.pDBIndexData);
        gVdirIndexGlobals.pDBIndexData = NULL;
    }
    gVdirIndexGlobals.mutex = NULL;
    gVdirIndexGlobals.bFirstboot = FALSE;
}
