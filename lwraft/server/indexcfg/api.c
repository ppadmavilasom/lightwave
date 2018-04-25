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

DWORD
VmDirLookupIndexData(
    PVDIR_BACKEND_INTERFACE pBE,
    PVDIR_INDEX_DATA        *ppIndexData
    )
{
    DWORD dwError = 0;
    PVDIR_INDEX_DATA pIndexData = NULL;

    if (!pBE || !ppIndexData)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    /* find index data */
    if (LwRtlHashMapFindKey(
            gVdirIndexGlobals.pDBIndexData,
            (PVOID *)&pIndexData,
            pBE))
    {
        dwError = VMDIR_ERROR_NOT_FOUND;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    *ppIndexData = pIndexData;

error:
    return dwError;
}

DWORD
VmDirIndexCfgMap(
    PVDIR_BACKEND_INTERFACE pBE,
    PLW_HASHMAP*            ppIndexCfgMap
    )
{
    DWORD   dwError = 0;
    PVDIR_INDEX_DATA pIndexData = NULL;
    VDIR_SERVER_STATE   vmdirState = VmDirdState();

    if (!pBE || !ppIndexCfgMap)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    if (vmdirState != VMDIRD_STATE_STARTUP)
    {
        dwError = VMDIR_ERROR_UNWILLING_TO_PERFORM;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirLookupIndexData(pBE, &pIndexData);
    BAIL_ON_VMDIR_ERROR(dwError);

    *ppIndexCfgMap = pIndexData->pIndexCfgMap;

error:
    return dwError;
}

DWORD
VmDirIndexCfgAcquire(
    PVDIR_BACKEND_INTERFACE pBE,
    PCSTR                   pszAttrName,
    VDIR_INDEX_USAGE        usage,
    PVDIR_INDEX_CFG*        ppIndexCfg
    )
{
    DWORD   dwError = 0;
    BOOLEAN bInLock = FALSE;
    PVDIR_INDEX_CFG pIndexCfg = NULL;
    PVMDIR_MUTEX    pMutex = NULL;
    PVDIR_INDEX_DATA pIndexData = NULL;

    if (!pBE ||
        IsNullOrEmptyString(pszAttrName) ||
        !ppIndexCfg)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    *ppIndexCfg = NULL;

    dwError = VmDirLookupIndexData(pBE, &pIndexData);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (LwRtlHashMapFindKey(
            pIndexData->pIndexCfgMap, (PVOID*)&pIndexCfg, pszAttrName))
    {
        goto cleanup;
    }

    pMutex = pIndexCfg->mutex;
    VMDIR_LOCK_MUTEX(bInLock, pMutex);

    if (pIndexCfg->status == VDIR_INDEXING_SCHEDULED)
    {
        goto cleanup;
    }
    else if (pIndexCfg->status == VDIR_INDEXING_IN_PROGRESS &&
            usage == VDIR_INDEX_READ)
    {
        dwError = VMDIR_ERROR_UNWILLING_TO_PERFORM;
    }
    else if (pIndexCfg->status == VDIR_INDEXING_DISABLED ||
            pIndexCfg->status == VDIR_INDEXING_DELETED)
    {
        goto cleanup;
    }
    BAIL_ON_VMDIR_ERROR(dwError);

    pIndexCfg->usRefCnt++;
    *ppIndexCfg = pIndexCfg;

cleanup:
    VMDIR_UNLOCK_MUTEX(bInLock, pMutex);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );

    goto cleanup;
}

VOID
VmDirIndexCfgRelease(
    PVDIR_INDEX_CFG pIndexCfg
    )
{
    BOOLEAN bInLock = FALSE;

    if (pIndexCfg)
    {
        VMDIR_LOCK_MUTEX(bInLock, pIndexCfg->mutex);
        pIndexCfg->usRefCnt--;
        VMDIR_UNLOCK_MUTEX(bInLock, pIndexCfg->mutex);

        if (pIndexCfg->usRefCnt == 0)
        {
            VmDirFreeIndexCfg(pIndexCfg);

        }
    }
}

BOOLEAN
VmDirIndexExist(
    PCSTR   pszAttrName
    )
{
    DWORD dwError = 0;
    BOOLEAN bExist = TRUE;
    PLW_HASHMAP pCurMap = NULL;
    PLW_HASHMAP pUpdMap = NULL;
    PVDIR_INDEX_CFG pIndexCfg = NULL;
    PVDIR_INDEX_DATA pIndexData = NULL;
    PVDIR_BACKEND_INTERFACE pBE = VmDirBackendSelect(NULL);

    dwError = VmDirLookupIndexData(pBE, &pIndexData);
    BAIL_ON_VMDIR_ERROR(dwError);

    pCurMap = pIndexData->pIndexCfgMap;
    pUpdMap = pIndexData->pIndexUpd ?
            pIndexData->pIndexUpd->pUpdIndexCfgMap : NULL;

    if (IsNullOrEmptyString(pszAttrName))
    {
        bExist = FALSE;
    }
    else
    {
        if (pUpdMap)
        {
            LwRtlHashMapFindKey(pUpdMap, (PVOID*)&pIndexCfg, pszAttrName);
        }
        if (!pIndexCfg)
        {
            LwRtlHashMapFindKey(pCurMap, (PVOID*)&pIndexCfg, pszAttrName);
        }
        if (!pIndexCfg ||
            pIndexCfg->status == VDIR_INDEXING_DISABLED ||
            pIndexCfg->status == VDIR_INDEXING_DELETED)
        {
            bExist = FALSE;
        }
    }

cleanup:
    return bExist;

error:
    bExist = FALSE;
    goto cleanup;
}

BOOLEAN
VmDirIndexIsDefault(
    PVDIR_BACKEND_INTERFACE pBE,
    PCSTR                   pszAttrName
    )
{
    DWORD dwError = 0;
    BOOLEAN bIsDefault = FALSE;
    PVDIR_INDEX_CFG pIndexCfg = NULL;
    PVDIR_INDEX_DATA pIndexData = NULL;

    dwError = VmDirLookupIndexData(pBE, &pIndexData);
    BAIL_ON_VMDIR_ERROR(dwError);


    if (!IsNullOrEmptyString(pszAttrName) &&
            LwRtlHashMapFindKey(
                    pIndexData->pIndexCfgMap,
                    (PVOID*)&pIndexCfg,
                    pszAttrName) == 0)
    {
        bIsDefault = pIndexCfg->bDefaultIndex;
    }

cleanup:
    return bIsDefault;

error:
    bIsDefault = FALSE;
    goto cleanup;
}

/*
 * If you want this update to be a part of bigger transaction,
 * provide pBECtx. Or leave it NULL otherwise.
 */
DWORD
VmDirIndexUpdateBegin(
    PVDIR_BACKEND_CTX   pBECtx,
    PVDIR_INDEX_UPD*    ppIndexUpd
    )
{
    DWORD   dwError = 0;
    PVDIR_INDEX_UPD pIndexUpd = NULL;
    PVDIR_INDEX_DATA pIndexData = NULL;
    PVDIR_BACKEND_INTERFACE pBE = VmDirSafeBEFromCtx(pBECtx);

    if(!pBE)
    {
        pBE = VmDirBackendSelect(NULL);
    }

    if (!pBE || !ppIndexUpd)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirLookupIndexData(pBE, &pIndexData);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirIndexUpdInit(pBECtx, &pIndexUpd);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirIndexUpdCopy(pIndexData->pIndexUpd, pIndexUpd);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (pIndexUpd->bOwnBECtx)
    {
        PVDIR_BACKEND_INTERFACE pBE = pIndexUpd->pBECtx->pBE;
        assert(pBE);

        dwError = pBE->pfnBETxnBegin(pIndexUpd->pBECtx, VDIR_BACKEND_TXN_WRITE);
        BAIL_ON_VMDIR_ERROR(dwError);
        pIndexUpd->bHasBETxn = TRUE;
    }

    *ppIndexUpd = pIndexUpd;

    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s succeeded", __FUNCTION__ );

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );

    VmDirIndexUpdFree(pIndexUpd);
    goto cleanup;
}

DWORD
VmDirIndexUpdateCommit(
    PVDIR_INDEX_UPD     pIndexUpd
    )
{
    DWORD   dwError = 0;
    LW_HASHMAP_ITER iter = LW_HASHMAP_ITER_INIT;
    LW_HASHMAP_PAIR pair = {NULL, NULL};
    PSTR            pszStatus = NULL;
    PVDIR_INDEX_DATA pIndexData = NULL;
    PVDIR_BACKEND_INTERFACE pBE = VmDirBackendSelect(NULL);

    if (!pIndexUpd)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirLookupIndexData(pBE, &pIndexData);
    BAIL_ON_VMDIR_ERROR(dwError);

    while (LwRtlHashMapIterate(pIndexUpd->pUpdIndexCfgMap, &iter, &pair))
    {
        PVDIR_INDEX_CFG pIndexCfg = (PVDIR_INDEX_CFG)pair.pValue;

        dwError = VmDirIndexCfgRecordProgress(pIndexUpd->pBECtx, pIndexCfg);
        BAIL_ON_VMDIR_ERROR(dwError);

        VMDIR_SAFE_FREE_MEMORY(pszStatus);
        dwError = VmDirIndexCfgStatusStringfy(pIndexCfg, &pszStatus);
        BAIL_ON_VMDIR_ERROR(dwError);

        VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, pszStatus );
    }

    if (pIndexUpd->bHasBETxn)
    {
        PVDIR_BACKEND_INTERFACE pBE = pIndexUpd->pBECtx->pBE;

        dwError = pBE->pfnBETxnCommit(pIndexUpd->pBECtx);
        BAIL_ON_VMDIR_ERROR(dwError);
        pIndexUpd->bHasBETxn = FALSE;
    }

    VmDirIndexUpdFree(pIndexData->pIndexUpd);
    pIndexData->pIndexUpd = pIndexUpd;

    VmDirConditionSignal(pIndexData->cond);

    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s succeeded", __FUNCTION__ );

cleanup:
    VMDIR_SAFE_FREE_MEMORY(pszStatus);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );

    goto cleanup;
}

DWORD
VmDirIndexUpdateAbort(
    PVDIR_INDEX_UPD     pIndexUpd
    )
{
    DWORD   dwError = 0;

    if (!pIndexUpd)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    if (pIndexUpd->bHasBETxn)
    {
        PVDIR_BACKEND_INTERFACE pBE = pIndexUpd->pBECtx->pBE;

        dwError = pBE->pfnBETxnAbort(pIndexUpd->pBECtx);
        BAIL_ON_VMDIR_ERROR(dwError);
        pIndexUpd->bHasBETxn = FALSE;
    }

    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s succeeded", __FUNCTION__ );

cleanup:
    VmDirIndexUpdFree(pIndexUpd);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );

    goto cleanup;
}

DWORD
VmDirIndexSchedule(
    PVDIR_INDEX_UPD     pIndexUpd,
    PCSTR               pszAttrName,
    PCSTR               pszAttrSyntaxOid
    )
{
    DWORD   dwError = 0;
    PLW_HASHMAP pCurCfgMap = NULL;
    PLW_HASHMAP pUpdCfgMap = NULL;
    PVDIR_INDEX_CFG pCurCfg = NULL;
    PVDIR_INDEX_CFG pUpdCfg = NULL;
    PVDIR_INDEX_CFG pNewCfg = NULL;
    PVDIR_INDEX_DATA pIndexData = NULL;
    PVDIR_BACKEND_INTERFACE pBE = VmDirBackendSelect(NULL);

    if (!pIndexUpd || IsNullOrEmptyString(pszAttrName))
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirLookupIndexData(pBE, &pIndexData);
    BAIL_ON_VMDIR_ERROR(dwError);

    pCurCfgMap = pIndexData->pIndexCfgMap;
    pUpdCfgMap = pIndexUpd->pUpdIndexCfgMap;

    (VOID)LwRtlHashMapFindKey(pCurCfgMap, (PVOID*)&pCurCfg, pszAttrName);
    (VOID)LwRtlHashMapFindKey(pUpdCfgMap, (PVOID*)&pUpdCfg, pszAttrName);

    if (pUpdCfg)
    {
        dwError = ERROR_ALREADY_EXISTS;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    if (pCurCfg)
    {
        if (pCurCfg->status == VDIR_INDEXING_DELETED)
        {
            dwError = VmDirIndexCfgCopy(pCurCfg, &pUpdCfg);
            BAIL_ON_VMDIR_ERROR(dwError);
            pNewCfg = pUpdCfg;

            pUpdCfg->status = VDIR_INDEXING_SCHEDULED;
        }
        else if (pCurCfg->status == VDIR_INDEXING_DISABLED)
        {
            dwError = VMDIR_ERROR_BUSY;
            BAIL_ON_VMDIR_ERROR(dwError);
        }
        else
        {
            dwError = ERROR_ALREADY_EXISTS;
            BAIL_ON_VMDIR_ERROR(dwError);
        }
    }
    else
    {
        dwError = VmDirIndexCfgCreate(pszAttrName, &pUpdCfg);
        BAIL_ON_VMDIR_ERROR(dwError);
        pNewCfg = pUpdCfg;

        pUpdCfg->bIsNumeric = VmDirSchemaSyntaxIsNumeric(pszAttrSyntaxOid);
    }

    dwError = LwRtlHashMapInsert(pUpdCfgMap, pUpdCfg->pszAttrName, pUpdCfg, NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );

    VmDirFreeIndexCfg(pNewCfg);
    goto cleanup;
}

DWORD
VmDirIndexDelete(
    PVDIR_INDEX_UPD     pIndexUpd,
    PCSTR               pszAttrName
    )
{
    DWORD   dwError = 0;
    PLW_HASHMAP pCurCfgMap = NULL;
    PLW_HASHMAP pUpdCfgMap = NULL;
    PVDIR_INDEX_CFG pCurCfg = NULL;
    PVDIR_INDEX_CFG pUpdCfg = NULL;
    PVDIR_INDEX_CFG pNewCfg = NULL;
    PVDIR_INDEX_DATA pIndexData = NULL;
    PVDIR_BACKEND_INTERFACE pBE = VmDirBackendSelect(NULL);

    if (!pIndexUpd || IsNullOrEmptyString(pszAttrName))
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirLookupIndexData(pBE, &pIndexData);
    BAIL_ON_VMDIR_ERROR(dwError);

    pCurCfgMap = pIndexData->pIndexCfgMap;
    pUpdCfgMap = pIndexUpd->pUpdIndexCfgMap;

    (VOID)LwRtlHashMapFindKey(pCurCfgMap, (PVOID*)&pCurCfg, pszAttrName);
    (VOID)LwRtlHashMapFindKey(pUpdCfgMap, (PVOID*)&pUpdCfg, pszAttrName);

    if (pCurCfg && !pUpdCfg)
    {
        dwError = VmDirIndexCfgCopy(pCurCfg, &pUpdCfg);
        BAIL_ON_VMDIR_ERROR(dwError);
        pNewCfg = pUpdCfg;
    }

    if (!pUpdCfg ||
         pUpdCfg->status == VDIR_INDEXING_DISABLED ||
         pUpdCfg->status == VDIR_INDEXING_DELETED)
    {
        dwError = VMDIR_ERROR_NOT_FOUND;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    if (pUpdCfg->bDefaultIndex)
    {
        dwError = VMDIR_ERROR_UNWILLING_TO_PERFORM;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    pUpdCfg->status = VDIR_INDEXING_DISABLED;

    dwError = LwRtlHashMapInsert(pUpdCfgMap, pUpdCfg->pszAttrName, pUpdCfg, NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );

    VmDirFreeIndexCfg(pNewCfg);
    goto cleanup;
}

DWORD
VmDirIndexAddUniquenessScope(
    PVDIR_INDEX_UPD     pIndexUpd,
    PCSTR               pszAttrName,
    PCSTR*              ppszUniqScopes
    )
{
    DWORD   dwError = 0;
    DWORD   i = 0;
    PLW_HASHMAP pCurCfgMap = NULL;
    PLW_HASHMAP pUpdCfgMap = NULL;
    PVDIR_INDEX_CFG pCurCfg = NULL;
    PVDIR_INDEX_CFG pUpdCfg = NULL;
    PVDIR_INDEX_CFG pNewCfg = NULL;
    PVDIR_INDEX_DATA pIndexData = NULL;
    PVDIR_BACKEND_INTERFACE pBE = VmDirBackendSelect(NULL);

    if (!pIndexUpd || IsNullOrEmptyString(pszAttrName) || !ppszUniqScopes)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirLookupIndexData(pBE, &pIndexData);
    BAIL_ON_VMDIR_ERROR(dwError);

    pCurCfgMap = pIndexData->pIndexCfgMap;
    pUpdCfgMap = pIndexUpd->pUpdIndexCfgMap;

    (VOID)LwRtlHashMapFindKey(pCurCfgMap, (PVOID*)&pCurCfg, pszAttrName);
    (VOID)LwRtlHashMapFindKey(pUpdCfgMap, (PVOID*)&pUpdCfg, pszAttrName);

    if (pCurCfg && !pUpdCfg)
    {
        dwError = VmDirIndexCfgCopy(pCurCfg, &pUpdCfg);
        BAIL_ON_VMDIR_ERROR(dwError);
        pNewCfg = pUpdCfg;
    }

    if (!pUpdCfg ||
         pUpdCfg->status == VDIR_INDEXING_DISABLED ||
         pUpdCfg->status == VDIR_INDEXING_DELETED)
    {
        dwError = VMDIR_ERROR_NOT_FOUND;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    if (!pUpdCfg->bScopeEditable ||
         pUpdCfg->status == VDIR_INDEXING_VALIDATING_SCOPES)
    {
        dwError = VMDIR_ERROR_UNWILLING_TO_PERFORM;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    for (i = 0; ppszUniqScopes[i]; i++)
    {
        dwError = VmDirIndexCfgAddUniqueScopeMod(pUpdCfg, ppszUniqScopes[i]);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = LwRtlHashMapInsert(pUpdCfgMap, pUpdCfg->pszAttrName, pUpdCfg, NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );

    VmDirFreeIndexCfg(pNewCfg);
    goto cleanup;
}

DWORD
VmDirIndexDeleteUniquenessScope(
    PVDIR_INDEX_UPD     pIndexUpd,
    PCSTR               pszAttrName,
    PCSTR*              ppszUniqScopes
    )
{
    DWORD   dwError = 0;
    DWORD   i = 0;
    PLW_HASHMAP pCurCfgMap = NULL;
    PLW_HASHMAP pUpdCfgMap = NULL;
    PVDIR_INDEX_CFG pCurCfg = NULL;
    PVDIR_INDEX_CFG pUpdCfg = NULL;
    PVDIR_INDEX_CFG pNewCfg = NULL;
    PVDIR_INDEX_DATA pIndexData = NULL;
    PVDIR_BACKEND_INTERFACE pBE = VmDirBackendSelect(NULL);

    if (!pIndexUpd || IsNullOrEmptyString(pszAttrName) || !ppszUniqScopes)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirLookupIndexData(pBE, &pIndexData);
    BAIL_ON_VMDIR_ERROR(dwError);

    pCurCfgMap = pIndexData->pIndexCfgMap;
    pUpdCfgMap = pIndexUpd->pUpdIndexCfgMap;

    (VOID)LwRtlHashMapFindKey(pCurCfgMap, (PVOID*)&pCurCfg, pszAttrName);
    (VOID)LwRtlHashMapFindKey(pUpdCfgMap, (PVOID*)&pUpdCfg, pszAttrName);

    if (pCurCfg && !pUpdCfg)
    {
        dwError = VmDirIndexCfgCopy(pCurCfg, &pUpdCfg);
        BAIL_ON_VMDIR_ERROR(dwError);
        pNewCfg = pUpdCfg;
    }

    if (!pUpdCfg ||
         pUpdCfg->status == VDIR_INDEXING_DISABLED ||
         pUpdCfg->status == VDIR_INDEXING_DELETED)
    {
        dwError = VMDIR_ERROR_NOT_FOUND;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    if (!pUpdCfg->bScopeEditable ||
         pUpdCfg->status == VDIR_INDEXING_VALIDATING_SCOPES)
    {
        dwError = VMDIR_ERROR_UNWILLING_TO_PERFORM;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    for (i = 0; ppszUniqScopes[i]; i++)
    {
        dwError = VmDirIndexCfgDeleteUniqueScopeMod(pUpdCfg, ppszUniqScopes[i]);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = LwRtlHashMapInsert(pUpdCfgMap, pUpdCfg->pszAttrName, pUpdCfg, NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );

    VmDirFreeIndexCfg(pNewCfg);
    goto cleanup;
}
