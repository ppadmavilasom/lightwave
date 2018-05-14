/*
 * Copyright © 2012-2015 VMware, Inc.  All Rights Reserved.
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
_VmDirLoadIndexForBE(
    PVDIR_BACKEND_INSTANCE pBEInstance,
    PVOID pUserData
    )
{
    DWORD   dwError = 0;
    DWORD   i = 0;
    PVDIR_SCHEMA_CTX        pSchemaCtx = NULL;
    PVDIR_SCHEMA_AT_DESC*   ppATDescList = NULL;
    PVDIR_INDEX_CFG         pIndexCfg = NULL;
    PVDIR_BACKEND_INTERFACE pBE = NULL;
    PVDIR_LOAD_INDEX_DATA   pLoadIndexData = (PVDIR_LOAD_INDEX_DATA)pUserData;

    if (!pBEInstance || !pLoadIndexData)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    pBE = pBEInstance->pBE;
    pSchemaCtx = pLoadIndexData->pSchemaCtx;
    ppATDescList = pLoadIndexData->ppATDescList;

    assert(pBE && pSchemaCtx && ppATDescList);

    // Identify non-default indices by their searchFlags and open them
    for (i = 0; ppATDescList[i]; i++)
    {
        if ((ppATDescList[i]->dwSearchFlags & 1) &&
                !VmDirIndexIsDefault(pBE, ppATDescList[i]->pszName))
        {
            dwError = VmDirCustomIndexCfgInit(pBE, ppATDescList[i], &pIndexCfg);
            BAIL_ON_VMDIR_ERROR(dwError);

            dwError = VmDirIndexOpen(pBE, pIndexCfg);
            BAIL_ON_VMDIR_ERROR(dwError);
            pIndexCfg = NULL;
        }
    }

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );

    VmDirFreeIndexCfg(pIndexCfg);
    goto cleanup;
}

DWORD
VmDirLoadIndex(
    )
{
    DWORD   dwError = 0;
    PVDIR_SCHEMA_CTX        pSchemaCtx = NULL;
    PVDIR_SCHEMA_AT_DESC*   ppATDescList = NULL;
    VDIR_BACKEND_INSTANCE   beInstance = {0};
    VDIR_LOAD_INDEX_DATA    indexData = {0};

    dwError = VmDirSchemaCtxAcquire(&pSchemaCtx);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirSchemaAttrList(pSchemaCtx, &ppATDescList);
    BAIL_ON_VMDIR_ERROR(dwError);

    indexData.pSchemaCtx = pSchemaCtx;
    indexData.ppATDescList = ppATDescList;

    /* load indices for main db */
    beInstance.pBE = VmDirBackendSelect(ALIAS_MAIN);
    dwError = _VmDirLoadIndexForBE(&beInstance, &indexData);
    BAIL_ON_VMDIR_ERROR(dwError);

#ifdef MULTI_MDB_ENABLED
    /* Initialize all additional databases */
    //dwError = VmDirIterateInstances(_VmDirLoadIndexForBE, &indexData);
    BAIL_ON_VMDIR_ERROR(dwError);
#endif

error:
    VMDIR_SAFE_FREE_MEMORY(ppATDescList);
    VmDirSchemaCtxRelease(pSchemaCtx);
    return dwError;
}
