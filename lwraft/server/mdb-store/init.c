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
MDBOpenMainDB(
    PVDIR_MDB_DB pDB
    );

static
DWORD
MDBInitSequence(
    PVDIR_MDB_DB pDB,
    VDIR_DB      mdbDbi
    );

static
DWORD
MDBOpenSequence(
    PVDIR_MDB_DB pDB
    );

static
DWORD
MDBOpenGeneric(
    PVDIR_MDB_DB pDB
    );

static
void
MDBCloseDBs(
    PVDIR_MDB_DB pDB
    );

#define W_TXNS_OUTSTANDING_THRESH_D 500;
static int g_w_txns_outstanding = 0;
static int g_w_txns_outstanding_thresh = W_TXNS_OUTSTANDING_THRESH_D;
static PVMDIR_MUTEX g_w_txns_mutex = NULL;
static UINT64 g_start_ts_ms = 0;
static int g_stats_cnt = 0;

static
DWORD
_VmDirWtxnStatsInit()
{
    DWORD dwWtxnOutstandingThresh = W_TXNS_OUTSTANDING_THRESH_D;
    DWORD dwError = 0;

    if (g_w_txns_mutex == NULL)
    {
        dwError = VmDirAllocateMutex(&g_w_txns_mutex);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirGetRegKeyValueDword(
        VMDIR_CONFIG_PARAMETER_V1_KEY_PATH,
        VMDIR_REG_KEY_WTXN_OUTSTANDING_THRESH,
        &dwWtxnOutstandingThresh, 0);

    if (dwError == 0)
    {
       g_w_txns_outstanding_thresh = dwWtxnOutstandingThresh;
    } else
    {
       //Use the default value.
       dwError = 0;
    }

    VMDIR_LOG_INFO(VMDIR_LOG_MASK_ALL, "%s: W_TXNS_OUTSTANDING_THRESH = %d", __func__, g_w_txns_outstanding_thresh);

done:
    return dwError;

error:
    goto done;
}

//The log is to detect bursting traffic that
// caused write transaction avg. latency to spike.
VOID
VmDirWtxnOutstandingInc()
{
   BOOLEAN bLock = FALSE;
   double stats_peroid_ms = 0.0;
   double offered_rate = 0.0;

   VMDIR_LOCK_MUTEX(bLock, g_w_txns_mutex);
   if (g_w_txns_outstanding == 0)
   {
      g_start_ts_ms = VmDirGetTimeInMilliSec();
      g_stats_cnt = 0;
   }
   g_w_txns_outstanding++;
   g_stats_cnt++;

   if (g_w_txns_outstanding >= g_w_txns_outstanding_thresh && g_stats_cnt >= g_w_txns_outstanding_thresh)
   {
       stats_peroid_ms = (double)(VmDirGetTimeInMilliSec() - g_start_ts_ms);
       if (stats_peroid_ms > 1) //avoid float point division overflow
       {
           offered_rate = (double)g_stats_cnt * 1000.0 / stats_peroid_ms;
           VMDIR_LOG_INFO(VMDIR_LOG_MASK_ALL, "%s: write transactions outstanding %d for peroid %.2g ms with offered rate %.3g on %d write requests",
                       __func__,  g_w_txns_outstanding, stats_peroid_ms, offered_rate, g_stats_cnt);
       }
       g_stats_cnt = 0;
       g_start_ts_ms = VmDirGetTimeInMilliSec();
   }
   VMDIR_UNLOCK_MUTEX(bLock, g_w_txns_mutex);
}

VOID
VmDirWtxnOutstandingDec()
{
    BOOLEAN bLock = FALSE;

    VMDIR_LOCK_MUTEX(bLock, g_w_txns_mutex);
    g_w_txns_outstanding--;
    VMDIR_UNLOCK_MUTEX(bLock, g_w_txns_mutex);
}

DWORD
VmDirMDBBEInterface (
    PVDIR_BACKEND_INTERFACE *ppInterface
    )
{
    DWORD dwError = 0;
    PVDIR_BACKEND_INTERFACE pInterface = NULL;

    if (!ppInterface)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirAllocateMemory(
                  sizeof(VDIR_BACKEND_INTERFACE),
                  ((PVOID*)&pInterface));
    BAIL_ON_VMDIR_ERROR(dwError);

    pInterface->pfnBEInit                = VmDirMDBInitializeDB;
    pInterface->pfnBEShutdown            = VmDirMDBShutdownDB;
    pInterface->pfnBEIndexOpen           = VmDirMDBIndexOpen;
    pInterface->pfnBEIndexExist          = VmDirMDBIndexExist;
    pInterface->pfnBEIndexDelete         = VmDirMDBIndexDelete;
    pInterface->pfnBEIndexPopulate       = VmDirMDBIndicesPopulate;
    pInterface->pfnBEIndexIteratorInit   = VmDirMDBIndexIteratorInit;
    pInterface->pfnBEIndexIterate        = VmDirMDBIndexIterate;
    pInterface->pfnBEIndexIteratorFree   = VmDirMDBIndexIteratorFree;
    pInterface->pfnBETxnBegin            = VmDirMDBTxnBegin;
    pInterface->pfnBETxnAbort            = VmDirMDBTxnAbort;
    pInterface->pfnBETxnCommit           = VmDirMDBTxnCommit;
    pInterface->pfnBESimpleIdToEntry     = VmDirMDBSimpleEIdToEntry;
    pInterface->pfnBESimpleDnToEntry     = VmDirMDBSimpleDnToEntry;
    pInterface->pfnBEIdToEntry           = VmDirMDBEIdToEntry;
    pInterface->pfnBEDNToEntry           = VmDirMDBDNToEntry;
    pInterface->pfnBEDNToEntryId         = VmDirMDBDNToEntryId;
    pInterface->pfnBEObjectGUIDToEntryId = VmDirMDBObjectGUIDToEntryId;
    pInterface->pfnBEChkDNReference      = VmDirMDBCheckRefIntegrity;
    pInterface->pfnBEChkIsLeafEntry      = VmDirMDBCheckIfALeafNode;
    pInterface->pfnBEGetCandidates       = VmDirMDBGetCandidates;
    pInterface->pfnBEEntryAdd            = VmDirMDBAddEntry;
    pInterface->pfnBEEntryDelete         = VmDirMDBDeleteEntry;
    pInterface->pfnBEEntryModify         = VmDirMDBModifyEntry;
    pInterface->pfnBEMaxEntryId          = VmDirMDBMaxEntryId;
    pInterface->pfnBEGetAttrMetaData     = VmDirMDBGetAttrMetaData;
    pInterface->pfnBEGetAllAttrsMetaData = VmDirMDBGetAllAttrsMetaData;
    pInterface->pfnBEGetNextUSN          = VmDirMDBGetNextUSN;
    pInterface->pfnBEDupKeyGetValues     = VmDirMDBDupKeyGetValues;
    pInterface->pfnBEDupKeySetValues     = VmDirMDBDupKeySetValues;
    pInterface->pfnBEUniqKeyGetValue     = VmDirMDBUniqKeyGetValue;
    pInterface->pfnBEUniqKeySetValue     = VmDirMDBUniqKeySetValue;
    pInterface->pfnBEConfigureFsync      = VmDirMDBConfigureFsync;

    *ppInterface = pInterface;
cleanup:
    return dwError;

error:
    VMDIR_SAFE_FREE_MEMORY(pInterface);
    goto cleanup;
}

/*
 last_pgno and max_pgs are logged. If last_pgno + pages for adding
 new data > max_pgs, mdb_put will fail with error MDB_MAP_FULL.
 Mdb first tries to reuse released pages before trying to get
 new pages from the free list. Thus even if an operation request
 new pages failed (last_pgno + pages > max_pgs),
 adding smaller data may still succeeded if the there are
 enough pages in the released pages. Max memory can be
 calculated from max_pgs * page size which is the same as the OS
 page size.
*/
void
VmDirLogDBStats(
    PVDIR_MDB_DB pDB
    )
{
    MDB_envinfo env_stats = {0};
    MDB_stat db_stats = {0};

    assert(pDB);

    if (mdb_env_info(pDB->mdbEnv, &env_stats) != MDB_SUCCESS ||
        mdb_env_stat(pDB->mdbEnv, &db_stats)!= MDB_SUCCESS)
    {
        goto error;
    }
    VMDIR_LOG_INFO(VMDIR_LOG_MASK_ALL, "mdb stats: last_pgno %llu, max_pgs %lld",
                   env_stats.me_last_pgno, env_stats.me_mapsize/db_stats.ms_psize);

cleanup:
    return;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL, "Error retrieving MDB statistics");
    goto cleanup;
}

static
DWORD
_VmDirMDBInitializeDBEntry(
    const char *pszDBPath,
    PVDIR_MDB_DB *ppDB
    )
{
    DWORD dwError = 0;
    PVDIR_MDB_DB pDB = NULL;

    if (!pszDBPath || !ppDB)
    {
        BAIL_WITH_VMDIR_ERROR(dwError, ERROR_INVALID_PARAMETER);
    }

    dwError = VmDirAllocateMemory (sizeof(VDIR_MDB_DB), ((PVOID*)&pDB));
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirAllocateStringA (pszDBPath, &pDB->pszDBPath);
    BAIL_ON_VMDIR_ERROR(dwError);

    *ppDB = pDB;

cleanup:
    return dwError;

error:
    if (pDB)
    {
        VMDIR_SAFE_FREE_MEMORY(pDB->pszDBPath);
        VMDIR_SAFE_FREE_MEMORY(pDB);
    }
    goto cleanup;
}

/*
 * Initialize MDB db
 * (reference openldap 2.4.31 back-mdb/init.c)
 */
DWORD
VmDirMDBInitializeDB(
    BOOLEAN bMainDB,
    const char *dbHomeDir,
    PVDIR_DB_HANDLE *phHandle
    )
{
    DWORD           dwError = 0;
    unsigned int    envFlags = 0;
    mdb_mode_t      oflags;
    uint64_t        db_max_mapsize = BE_MDB_ENV_MAX_MEM_MAPSIZE;
    DWORD           db_max_size_mb = 0;
    DWORD           db_chkpt_interval = 0;
    BOOLEAN         bMdbWalEnable = TRUE;
    PVDIR_MDB_DB pDB = NULL;

    VmDirLog( LDAP_DEBUG_TRACE, "MDBInitializeDB: Begin, DB Home Dir = %s", dbHomeDir );

    //Make a db entry for path. fail if already exist
    dwError = _VmDirMDBInitializeDBEntry(dbHomeDir, &pDB);
    BAIL_ON_VMDIR_ERROR( dwError );

    dwError = (sizeof(ENTRYID) == sizeof(VDIR_DB_SEQ_T)) ? 0 : ERROR_BACKEND_ERROR;
    BAIL_ON_VMDIR_ERROR( dwError );

    dwError = MDBInitConfig(pDB);
    BAIL_ON_VMDIR_ERROR( dwError );

    /* Create the environment */
    dwError = mdb_env_create ( &pDB->mdbEnv );
    BAIL_ON_VMDIR_ERROR( dwError );

    dwError = mdb_env_set_maxreaders( pDB->mdbEnv, BE_MDB_ENV_MAX_READERS );
    BAIL_ON_VMDIR_ERROR( dwError );

    /* FROM mdb.h
     * The size should be a multiple of the OS page size. The default is
     * 10485760 bytes. The size of the memory map is also the maximum size
     * of the database. The value should be chosen as large as possible,
     * to accommodate future growth of the database.
     *
     * // TODO, this is also the max size of database (per logical mdb db or the total dbs)
     */

     dwError = VmDirGetMaxDbSizeMb(&db_max_size_mb);
     if (dwError != 0)
     {
         VMDIR_LOG_INFO(VMDIR_LOG_MASK_ALL, "Use default max-database-size %llu", BE_MDB_ENV_MAX_MEM_MAPSIZE);
     } else
     {
         db_max_mapsize = (uint64_t)(db_max_size_mb)*1024*1024;
         if (db_max_mapsize < BE_MDB_ENV_MAX_MEM_MAPSIZE)
         {
             db_max_mapsize = BE_MDB_ENV_MAX_MEM_MAPSIZE;
             VMDIR_LOG_WARNING(VMDIR_LOG_MASK_ALL, "RegKey %s value (%u) is too small. Use default max-database-size %llu",
                            VMDIR_REG_KEY_MAXIMUM_DB_SIZE_MB, db_max_size_mb, db_max_mapsize);
         } else
         {
             VMDIR_LOG_INFO(VMDIR_LOG_MASK_ALL, "max-database-size is set to %llu per RegKey %s",
                            db_max_mapsize, VMDIR_REG_KEY_MAXIMUM_DB_SIZE_MB);
         }
     }

     dwError = mdb_env_set_mapsize( pDB->mdbEnv, db_max_mapsize);
     BAIL_ON_VMDIR_ERROR( dwError );

     dwError = mdb_env_set_maxdbs ( pDB->mdbEnv, BE_MDB_ENV_MAX_DBS );
     BAIL_ON_VMDIR_ERROR( dwError );

     dwError = VmDirGetMdbChkptInterval(&db_chkpt_interval);
     if (dwError)
     {
         db_chkpt_interval = VMDIR_REG_KEY_MDB_CHKPT_INTERVAL_DEFAULT;
         dwError = 0;
     }

     VMDIR_LOG_INFO(VMDIR_LOG_MASK_ALL, "%s: %s is set to %d",
        __func__, VMDIR_REG_KEY_MDB_CHKPT_INTERVAL, db_chkpt_interval);

     dwError = mdb_env_set_chkpt_interval(pDB->mdbEnv, db_chkpt_interval);
     BAIL_ON_VMDIR_ERROR( dwError );

     if(bMainDB)
     {
         mdb_set_raft_prepare_commit_func(pDB->mdbEnv, VmDirRaftPrepareCommit);

         mdb_set_raft_post_commit_func(pDB->mdbEnv, VmDirRaftPostCommit);

         mdb_set_raft_commit_fail_func(pDB->mdbEnv, VmDirRaftCommitFail);
     }

#ifdef MDB_NOTLS
     envFlags = MDB_NOTLS; // Required for versions of mdb which have this flag
#endif

     // this is experimental from mdb.h comments
     //envFlags = MDB_FIXEDMAP;        /* use a fixed address for the mmap region */

     //envFlags |= MDB_NOSYNC       need sync for durability
     //envFlags |= MDB_RDONLY       need to open for read and write

    /* Open the environment.  */

#ifndef _WIN32
    oflags = O_RDWR;
#else
    oflags = GENERIC_READ|GENERIC_WRITE;
#endif

    //MDB WAL is the default mode and can be turned off with reg key MdbEnableWal set to 0
    dwError = VmDirGetMdbWalEnable(&bMdbWalEnable);
    if (dwError)
    {
        bMdbWalEnable = TRUE;
        dwError = 0;
    }

    VMDIR_LOG_INFO(VMDIR_LOG_MASK_ALL, "%s: %s is set to %s",
      __func__, VMDIR_REG_KEY_MDB_ENABLE_WAL, bMdbWalEnable?"True":"False");

    if (bMdbWalEnable)
    {
        envFlags |= MDB_WAL;
    }

    dwError = mdb_env_open ( pDB->mdbEnv, dbHomeDir, envFlags, oflags );
//TODO, what if open failed?  how to recover??
    BAIL_ON_VMDIR_ERROR( dwError );

    /* Open main database. */
    dwError = MDBOpenMainDB(pDB);
    BAIL_ON_VMDIR_ERROR( dwError );

    /* Open sequences */
    dwError = MDBOpenSequence(pDB);
    BAIL_ON_VMDIR_ERROR( dwError );

    /* Open generic */
    dwError = MDBOpenGeneric(pDB);
    BAIL_ON_VMDIR_ERROR( dwError );

    /* Initialize indices */
    dwError = VmDirMDBInitializeIndexDB(pDB);
    BAIL_ON_VMDIR_ERROR( dwError );

    VmDirLogDBStats(pDB);

    if (bMainDB)
    {
        dwError = _VmDirWtxnStatsInit();
        BAIL_ON_VMDIR_ERROR( dwError );
    }

    *phHandle = pDB;
cleanup:
    VmDirLog( LDAP_DEBUG_TRACE, "MDBInitializeDB: End" );

    return dwError;

error:

    VmDirLog( LDAP_DEBUG_ANY, "MDBInitializeDB failed with error code: %d, error string: %s", dwError, mdb_strerror(dwError) );

//TODO, should shutdown here or caller will do that?
//gVdirMdbGlobals.mdbEnv = NULL;

    goto cleanup;
}

/*
 * Close all opened DBs and free environment
 */
DWORD
VmDirMDBShutdownDB(
    PVDIR_DB_HANDLE hDB
    )
{
    PVDIR_MDB_DB pDB = (PVDIR_MDB_DB)hDB;

    VmDirLog( LDAP_DEBUG_TRACE, "MDBShutdownDB: Begin" );

    VmDirLogDBStats(pDB);

    if (pDB->mdbEnv != NULL)
    {
        MDBCloseDBs(pDB);

        VmDirMDBShutdownIndexDB(pDB);

        // force buffer sync
        mdb_env_sync(pDB->mdbEnv, 1);

        mdb_env_close(pDB->mdbEnv);
        pDB->mdbEnv = NULL;
    }

    if (pDB->mdbEntryDB.pMdbDataFiles)
    {
        VMDIR_SAFE_FREE_MEMORY(pDB->mdbEntryDB.pMdbDataFiles->pszDBFile);
        VMDIR_SAFE_FREE_MEMORY(pDB->mdbEntryDB.pMdbDataFiles->pszDBName);
        VMDIR_SAFE_FREE_MEMORY(pDB->mdbEntryDB.pMdbDataFiles);
    }
    VMDIR_SAFE_FREE_MEMORY(pDB->pszDBPath);
    VMDIR_SAFE_FREE_MEMORY(pDB);

    VmDirLog( LDAP_DEBUG_TRACE, "MDBShutdownDB: End" );

    return 0;
}

DWORD
MDBOpenDB(
    PVDIR_MDB_DB        pDB,
    PVDIR_DB            pmdbDBi,
    const char *        dbName,
    const char *        fileName,
    PFN_BT_KEY_CMP      btKeyCmpFcn,
    unsigned int        extraFlags)
{
    DWORD               dwError = 0;
    MDB_txn*            pTxn = NULL;
    VDIR_DB             mdbDBi  = 0;

    VmDirLog( LDAP_DEBUG_TRACE, "MdbOpenDB: Begin, DN name = %s", fileName );

    assert(pDB && pmdbDBi);

    extraFlags |= MDB_CREATE;

    dwError = mdb_txn_begin( pDB->mdbEnv, NULL, BE_DB_FLAGS_ZERO, &pTxn );
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = mdb_open( pTxn, dbName, extraFlags, &mdbDBi);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (NULL != btKeyCmpFcn)
    {
        // set customize "key" compare function.
        dwError = mdb_set_compare( pTxn, mdbDBi, btKeyCmpFcn);
        BAIL_ON_VMDIR_ERROR(dwError);

        // if db is opened with MDB_DUPSORT flag, you can set customize "data" compare function.
        // we use default lexical comparison.
        //dwError = mdb_set_dupsort( pTxn, mdbDBi, btKeyCmpFcn);
        //BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = mdb_txn_commit(pTxn);
    // regardless of commit result, pTxn should not be accessed anymore
    // see mdb-back/init.c mdb_db_open example.
    // this is consistent with BDB DB_TXN->commit() man page.
    pTxn = NULL;
    BAIL_ON_VMDIR_ERROR(dwError);

    *pmdbDBi = mdbDBi;

cleanup:

    VmDirLog( LDAP_DEBUG_TRACE, "MdbOpenDB: End" );
    return dwError;

error:

    if (pTxn)
    {
        mdb_txn_abort(pTxn);
        pTxn = NULL;
    }

    VmDirLog( LDAP_DEBUG_ANY, "MdbOpenDB failed with error code: %d, error string: %s", dwError, mdb_strerror(dwError) );

    goto cleanup;
}

VOID
MDBCloseDB(
    PVDIR_MDB_DB pDB,
    VDIR_DB      mdbDBi
    )
{
    if (pDB)
    {
        mdb_close(pDB->mdbEnv, mdbDBi);
    }
}

DWORD
MDBDropDB(
    PVDIR_MDB_DB pDB,
    VDIR_DB      mdbDBi
    )
{
    DWORD               dwError = 0;
    MDB_txn*            pTxn = NULL;

    assert(pDB);

    dwError = mdb_txn_begin(pDB->mdbEnv, NULL, BE_DB_FLAGS_ZERO, &pTxn);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = mdb_drop(pTxn, mdbDBi, 1);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = mdb_txn_commit(pTxn);
    pTxn = NULL;
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    return dwError;

error:
    if (pTxn)
    {
        mdb_txn_abort(pTxn);
        pTxn = NULL;
    }
    goto cleanup;
}

/*
 * Error map from MDB to BE space
 * If no map specified, ERROR_BACKEND_ERROR is returned.
 *
 * BECtx.dwBEErrorCode is set to the first mdb error encountered
 * BECtx.pszBEErrorMsg is set to the first mdb error text encountered
 *
 * NOTE, this could be called multiple times during one LDAP level operation.
 * The last one counts.
 */
DWORD
MDBToBackendError(
    DWORD               dwMdbError,
    DWORD               dwFromMdbError,
    DWORD               dwToBEError,
    PVDIR_BACKEND_CTX   pBECtx,
    PCSTR               pszErrorContext)
{
    DWORD   dwError = 0;

    assert(pBECtx);

    if (dwMdbError != 0)
    {
        pBECtx->dwBEErrorCode = dwMdbError;
        VMDIR_SAFE_FREE_MEMORY(pBECtx->pszBEErrorMsg);
        // ignore error
        VmDirAllocateStringPrintf(    &pBECtx->pszBEErrorMsg,
                                          "(%s)(%s)",
                                          mdb_strerror(dwMdbError),
                                          VDIR_SAFE_STRING(pszErrorContext));

        if (dwMdbError == dwFromMdbError)
        {
            dwError = dwToBEError;
        }
        // check if the error is caused by one of raft callbacks
        // if yes return the same error
        else if (IS_VMDIR_ERROR_SPACE(dwMdbError))
        {
            dwError = dwMdbError;
        }
        else
        {
            dwError = ERROR_BACKEND_ERROR;
        }
    }

    return dwError;
}

/*
 * Open Entry/Blob Database.
 *
 * Called during server startup, so it is safe to access gVdirMdbGlobals
 * w/o protection.
 */
static
DWORD
MDBOpenMainDB(
    PVDIR_MDB_DB pDB
    )
{
    DWORD           dwError = 0;
    unsigned int    iDbFlags = 0;

    VmDirLog( LDAP_DEBUG_TRACE, "MdbOpenDBs: Begin" );

    // default database has unique key. i.e. no DUP key allowed.
    iDbFlags |= MDB_CREATE;
    //    iDbFlags |= MDB_INTEGERKEY; our keys do not have same size

    dwError = MDBOpenDB(pDB,
                        &pDB->mdbEntryDB.pMdbDataFiles[0].mdbDBi,
                        pDB->mdbEntryDB.pMdbDataFiles[0].pszDBName,
                        pDB->mdbEntryDB.pMdbDataFiles[0].pszDBFile,
                        pDB->mdbEntryDB.btKeyCmpFcn,
                        iDbFlags);
    BAIL_ON_VMDIR_ERROR( dwError );

cleanup:

    VmDirLog( LDAP_DEBUG_TRACE, "MdbOpenDBs: End" );
    return dwError;

error:

    goto cleanup;
}

/*
 * Initialize ENTRYID and USN sequence.
 */
static
DWORD
MDBInitSequence(
    PVDIR_MDB_DB pDB,
    VDIR_DB      mdbDbi
    )
{
    DWORD           dwError = 0;
    PVDIR_DB_TXN    pTxn = NULL;
    VDIR_DB_DBT     key = {0};
    VDIR_DB_DBT     value = {0};
    unsigned char   EidBytes[sizeof( ENTRYID )] = {0};
    ENTRYID         initEIDValue = ENTRY_ID_SEQ_INITIAL_VALUE;
    ENTRYID         initUNSValue = USN_SEQ_INITIAL_VALUE;

    assert(pDB);

    dwError = mdb_txn_begin( pDB->mdbEnv, NULL, BE_DB_FLAGS_ZERO, &pTxn );
    BAIL_ON_VMDIR_ERROR(dwError);

    key.mv_data = &EidBytes[0];
    MDBEntryIdToDBT(BE_MDB_ENTRYID_SEQ_KEY, &key);

    dwError =  mdb_get(pTxn, mdbDbi, &key, &value);
    if (dwError == MDB_NOTFOUND)
    {
        // first time, initialize two sequence records
        value.mv_data = &initEIDValue;
        value.mv_size = sizeof(initEIDValue);

        // set entryid sequence record
        dwError = mdb_put(pTxn, mdbDbi, &key, &value,  MDB_NOOVERWRITE);
        BAIL_ON_VMDIR_ERROR(dwError);

        MDBEntryIdToDBT(BE_MDB_USN_SEQ_KEY, &key);
        value.mv_data = &initUNSValue;
        value.mv_size = sizeof(initUNSValue);

        // set usn sequence record
        dwError = mdb_put(pTxn, mdbDbi, &key, &value, MDB_NOOVERWRITE);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = mdb_txn_commit(pTxn);
    pTxn = NULL;
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:

    return dwError;

error:

    if (pTxn)
    {
        mdb_txn_abort(pTxn);
    }

    goto cleanup;
}
/*
 * MDB has not SEQUENCE support.
 * Use a separate database and have one record representing one logic sequence.
 */
static
DWORD
MDBOpenSequence(
    PVDIR_MDB_DB pDB
    )
{
    DWORD           dwError = 0;
    unsigned int    iDbFlags = 0;
    VDIR_DB         mdbDBi = 0;

    VmDirLog( LDAP_DEBUG_TRACE, "MdbOpenSequence: Begin" );

    // default database has unique key. i.e. no DUP key allowed.
    iDbFlags |= MDB_CREATE;
    //    iDbFlags |= MDB_INTEGERKEY; our keys do not have same size

    dwError = MDBOpenDB( pDB,
                        &mdbDBi,
                        BE_MDB_SEQ_DB_NAME,
                        pDB->mdbEntryDB.pMdbDataFiles[0].pszDBFile, // use same file as Entry DB
                        NULL,
                        iDbFlags);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = MDBInitSequence(pDB, mdbDBi);
    BAIL_ON_VMDIR_ERROR(dwError);

    pDB->mdbSeqDBi = mdbDBi;

cleanup:

    VmDirLog( LDAP_DEBUG_TRACE, "MdbOpenSequence: End" );

    return dwError;

error:

    goto cleanup;
}

static
DWORD
MDBOpenGeneric(
    PVDIR_MDB_DB pDB
    )
{
    DWORD           dwError = 0;
    unsigned int    iDbFlags = 0;
    VDIR_DB         mdbDBi = 0;

    assert(pDB);

    iDbFlags |= MDB_CREATE;

    dwError = MDBOpenDB(
            pDB,
            &mdbDBi,
            BE_MDB_GENERIC_UNIQKEY_DB_NAME,
            pDB->mdbEntryDB.pMdbDataFiles[0].pszDBFile, // use same file as Entry DB
            NULL,
            iDbFlags);
    BAIL_ON_VMDIR_ERROR(dwError);

    pDB->mdbGenericUniqKeyDBi = mdbDBi;

    iDbFlags |= MDB_DUPSORT; // allow dup keys

    dwError = MDBOpenDB(
            pDB,
            &mdbDBi,
            BE_MDB_GENERIC_DUPKEY_DB_NAME,
            pDB->mdbEntryDB.pMdbDataFiles[0].pszDBFile, // use same file as Entry DB
            NULL,
            iDbFlags);
    BAIL_ON_VMDIR_ERROR(dwError);

    pDB->mdbGenericDupKeyDBi = mdbDBi;

cleanup:

    VmDirLog( LDAP_DEBUG_TRACE, "MDBOpenGeneric: End" );

    return dwError;

error:

    goto cleanup;
}

/*
 * Close all opened database.
 *
 * Called during server shutdown, so it is safe to access gVdirMdbGlobals
 * w/o protection.
 */
static
void
MDBCloseDBs(
    PVDIR_MDB_DB pDB
    )
{
    VmDirLog( LDAP_DEBUG_TRACE, "MdbCloseDBs: Begin" );

    if (pDB->mdbEntryDB.pMdbDataFiles)
    {
        // close entry db
        mdb_close(pDB->mdbEnv, pDB->mdbEntryDB.pMdbDataFiles[0].mdbDBi);
    }

    // close sequence db
    if (pDB->mdbSeqDBi)
    {
        mdb_close(pDB->mdbEnv, pDB->mdbSeqDBi);
    }

    // close generic dbs
    if (pDB->mdbGenericDupKeyDBi)
    {
        mdb_close(pDB->mdbEnv, pDB->mdbGenericDupKeyDBi);
    }
    if (pDB->mdbGenericUniqKeyDBi)
    {
        mdb_close(pDB->mdbEnv, pDB->mdbGenericUniqKeyDBi);
    }

    VmDirLog( LDAP_DEBUG_TRACE, "MdbCloseDBs: End" );
}

/*
 * See file client.c VmDirSetBackendState on parameters
 */
DWORD
VmDirSetMdbBackendState(
    MDB_state_op        op,
    DWORD               *pdwLogNum,
    DWORD               *pdwDbSizeMb,
    DWORD               *pdwDbMapSizeMb,
    PSTR                pszDbPath,
    DWORD               dwDbPathSize)
{
    DWORD dwError = 0;
    unsigned long lognum = 0L;
    unsigned long  dbSizeMb = 0L;
    unsigned long  dbMapSizeMb = 0L;
    PVDIR_MDB_DB pDB = NULL;

    /* TODO: Should apply to all backends when there are multiple mdbs */
    PVDIR_BACKEND_INTERFACE pBE = VmDirBackendSelect(NULL);

    pDB = (PVDIR_MDB_DB)VmDirSafeDBFromBE(pBE);

    if (!pDB || op < MDB_STATE_CLEAR || op > MDB_STATE_GETXLOGNUM)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    *pdwLogNum = 0;
    *pdwDbSizeMb = 0;
    *pdwDbMapSizeMb = 0;
    dwError = mdb_env_set_state(
                  pDB->mdbEnv, op, &lognum, &dbSizeMb,
                  &dbMapSizeMb, pszDbPath, dwDbPathSize);
    BAIL_ON_VMDIR_ERROR(dwError);
    *pdwLogNum = lognum;
    *pdwDbSizeMb = dbSizeMb;
    *pdwDbMapSizeMb = dbMapSizeMb;

cleanup:
    return dwError;

error:
    goto cleanup;
}
