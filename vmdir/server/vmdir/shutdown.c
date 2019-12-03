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
VOID
VmDirStopSrvThreads(
    VOID);

static
VOID
VmDirCleanupGlobals(
    VOID
    );

/*
 * Server shutdown
 */
VOID
VmDirShutdown(
    PBOOLEAN pbVmDirStopped
    )
{
    PVDIR_BACKEND_INTERFACE pBE = NULL;
    BOOLEAN bRESTHeadStopped = FALSE;
    BOOLEAN bLDAPHeadStopped = FALSE;

    assert(pbVmDirStopped);
    *pbVmDirStopped = FALSE;

    pBE = VmDirBackendSelect(NULL);

    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s: stop REST listening threads", __func__);
    if (VmDirRESTServerStop() == 0)
    {
        VmDirRESTServerShutdown();
        bRESTHeadStopped = TRUE;
    }

    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s: stop LDAP listening threads", __func__);
    VmDirShutdownConnAcceptThread();

    VmDirRpcServerShutdown();
    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s: RPC service stopped", __func__);

    VmDirIpcServerShutDown();
    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s: IPC service stopped", __func__);

    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s: wait for LDAP operation threads to stop ...", __func__);
    VmDirWaitForLDAPOpThr(&bLDAPHeadStopped);

    VmDirBkgdThreadShutdown();
    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s: background thread stopped", __func__);

    VmDirStopSrvThreads();
    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s: server threads stopped", __func__);

    VmDirVmAclShutdownFlush();
    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s: Flush ACL complete.", __func__);

    if (!bRESTHeadStopped || !bLDAPHeadStopped)
    {
        //Cannot make a graceful shutdown
        VMDIR_LOG_WARNING( VMDIR_LOG_MASK_ALL,
            "%s: timeout while waiting for LDAP(%d)/REST(%d) operation threads to stop.",
            __func__, bLDAPHeadStopped, bRESTHeadStopped);

        goto done;
    }
    else
    {
        *pbVmDirStopped = TRUE;
        VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s: operation threads stopped gracefully", __func__);
    }

    VmDirPasswordSchemeFree();

    VmDirVmAclShutdown();
    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s: shutdown ACL complete.", __func__);

    VmDirMiddleLayerLibShutdown();
    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s: shutdown middle layer complete.", __func__);

    VmDirSASLShutdown();
    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s: SASL shutdown complete.", __func__);

    VmDirIndexLibShutdown();
    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s: shutdown indexing complete.", __func__);

    VmDirSchemaLibShutdown();
    VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s: shutdown schema complete.", __func__ );

    if (pBE)
    {
        pBE->pfnBEShutdown();
        VMDIR_LOG_INFO( VMDIR_LOG_MASK_ALL, "%s shutdown backend complete.", __func__);
    }

    VmDirCleanupGlobals();

    VmDirMetricsShutdown();

    VmDirFreeThreadContext();

    (VOID)VmDirSetRegKeyValueDword(
            VMDIR_CONFIG_PARAMETER_KEY_PATH,
            VMDIR_REG_KEY_DIRTY_SHUTDOWN,
            FALSE);

done:
    return;
}

/*
 * wait till all ldap operation threads are done
 */
VOID
VmDirWaitForLDAPOpThr(
    PBOOLEAN pbStopped
    )
{
    DWORD       dwError = 0;
    BOOLEAN     bTimedOut = FALSE;

    if (!pbStopped)
    {
        BAIL_WITH_VMDIR_ERROR(dwError, VMDIR_ERROR_INVALID_PARAMETER);
    }

    // wait for operation threads to finish, timeout in 10 seconds.
    dwError = VmDirSyncCounterWaitEvent(gVmdirGlobals.pOperationThrSyncCounter, &bTimedOut);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (!bTimedOut)
    {
        *pbStopped = TRUE;
    }

cleanup:
    return;

error:
    goto cleanup;
}

static
VOID
VmDirStopSrvThreads(
    VOID)
{
    BOOLEAN             bInLock = FALSE;
    PVDIR_THREAD_INFO   pThrInfo = NULL;

    VMDIR_LOCK_MUTEX(bInLock, gVmdirGlobals.mutex);

    pThrInfo = gVmdirGlobals.pSrvThrInfo;

    VMDIR_UNLOCK_MUTEX(bInLock, gVmdirGlobals.mutex);

    // do shutdown outside lock as mutex is used for other resources too
    while (pThrInfo)
    {
        PVDIR_THREAD_INFO pNext = pThrInfo->pNext;

        VmDirSrvThrShutdown(pThrInfo); // this free pThrInfo
        pThrInfo = pNext;
    }

    return;
}

static
VOID
VmDirCleanupGlobals(
    VOID
    )
{
    DWORD dwCnt = 0;

    // Free Server global 'gVmdirServerGlobals' upon shutdown
    VmDirFreeBervalContent(&gVmdirServerGlobals.invocationId);
    VmDirFreeBervalContent(&gVmdirServerGlobals.bvDefaultAdminDN);
    VmDirFreeBervalContent(&gVmdirServerGlobals.systemDomainDN);
    VmDirFreeBervalContent(&gVmdirServerGlobals.delObjsContainerDN);
    VmDirFreeBervalContent(&gVmdirServerGlobals.bvDCGroupDN);
    VmDirFreeBervalContent(&gVmdirServerGlobals.bvDCClientGroupDN);
    VmDirFreeBervalContent(&gVmdirServerGlobals.bvSchemaManagersGroupDN);
    VmDirFreeBervalContent(&gVmdirServerGlobals.bvServicesRootDN);
    VmDirFreeBervalContent(&gVmdirServerGlobals.serverObjDN);
    VmDirFreeBervalContent(&gVmdirServerGlobals.bvServerObjName);
    VmDirFreeUTDVectorGlobalCache();

    // Free vmdir global 'gVmdirGlobals' upon shutdown
    VMDIR_SAFE_FREE_MEMORY(gVmdirGlobals.pszBDBHome);
    VMDIR_SAFE_FREE_MEMORY(gVmdirGlobals.pszBootStrapSchemaFile);

    VMDIR_SAFE_FREE_MUTEX(gVmdirGlobals.replCycleDoneMutex);
    VMDIR_SAFE_FREE_MUTEX(gVmdirGlobals.replAgrsMutex);
    VMDIR_SAFE_FREE_MUTEX(gVmdirGlobals.pFlowCtrlMutex);
    VMDIR_SAFE_FREE_MUTEX(gVmdirGlobals.mutex);

    VMDIR_SAFE_FREE_CONDITION(gVmdirGlobals.replCycleDoneCondition);
    VMDIR_SAFE_FREE_CONDITION(gVmdirGlobals.replAgrsCondition);

    VMDIR_SAFE_FREE_SYNCCOUNTER(gVmdirGlobals.pOperationThrSyncCounter);

    // Free vmdir plugin global 'gVmdirPluginGlobals'
    VmDirPluginShutdown();

    VMDIR_SAFE_FREE_MUTEX(gVmdirKrbGlobals.pmutex);
    VMDIR_SAFE_FREE_CONDITION(gVmdirKrbGlobals.pcond);

    VMDIR_SAFE_FREE_MUTEX(gVmdirTrackLastLoginTime.pMutex);
    VMDIR_SAFE_FREE_CONDITION(gVmdirTrackLastLoginTime.pCond);
    // ignore gVmdirTrackLastLoginTime.pTSStack

    VMDIR_SAFE_FREE_MUTEX(gVmdirIntegrityCheck.pMutex);
    VMDIR_SAFE_FREE_MEMORY(gVmdirIntegrityCheck.pJob);

    VmDirDBIntegrityCheckJobFree(gVmdirDBIntegrityCheck.pJob);
    VMDIR_SAFE_FREE_MUTEX(gVmdirDBIntegrityCheck.pMutex);

    VMDIR_SAFE_FREE_MUTEX(gVmdirDBCrossCheck.pMutex);

    // Free gVmdirdSDGlobals upon shutdown
    VMDIR_SAFE_FREE_MEMORY(gVmdirdSDGlobals.pSDdcAdminGX);
    VMDIR_SAFE_FREE_MEMORY(gVmdirdSDGlobals.pSDdcAdminRPWPDE);
    VmDirFreeAbsoluteSecurityDescriptor(&gVmdirdSDGlobals.pSDdcAdminGXAbsolute);
    VmDirFreeAbsoluteSecurityDescriptor(&gVmdirdSDGlobals.pSDdcAdminRPWPDEAbsolute);

    VMDIR_SAFE_FREE_MUTEX(gVmDirServerOpsGlobals.pMutex);
    VmDirFreeLinkedList(gVmDirServerOpsGlobals.pWriteQueue->pList);

    VMDIR_SAFE_FREE_MEMORY(gVmDirServerOpsGlobals.pWriteQueue);

    if (gVmdirServerGlobals.searchOptMap.bMapLoaded)
    {
        for (dwCnt=0; dwCnt < VMDIR_SEARCH_MAP_CACHE_SIZE; dwCnt++)
        {
            if (gVmdirServerGlobals.searchOptMap.ppAttrTypePriMap[dwCnt])
            {
                LwRtlHashMapClear(gVmdirServerGlobals.searchOptMap.ppAttrTypePriMap[dwCnt], VmDirSimpleHashMapPairFree, NULL);
            }

            if (gVmdirServerGlobals.searchOptMap.ppSearchTypePriMap[dwCnt])
            {
                LwRtlHashMapClear(gVmdirServerGlobals.searchOptMap.ppSearchTypePriMap[dwCnt], VmDirSimpleHashMapPairFree, NULL);
            }
        }

        LwRtlFreeHashMap(gVmdirServerGlobals.searchOptMap.ppAttrTypePriMap);
        LwRtlFreeHashMap(gVmdirServerGlobals.searchOptMap.ppSearchTypePriMap);
    }

}
