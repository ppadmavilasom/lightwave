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


typedef struct _VDIR_CFG_MDB_DATAFILE_DESC
{
    MDB_dbi     mdbDBi;
    PSTR        pszDBName;
    PSTR        pszDBFile;
    BOOLEAN     bIsUnique;

} VDIR_CFG_MDB_DATAFILE_DESC, *PVDIR_CFG_MDB_DATAFILE_DESC;

typedef MDB_cmp_func    PFN_BT_KEY_CMP;

typedef struct _VDIR_MDB_ENTRY_DATABASE
{
    USHORT                      usNumDataFiles;
    PVDIR_CFG_MDB_DATAFILE_DESC pMdbDataFiles;

    // Btree key comparison function
    PFN_BT_KEY_CMP*             btKeyCmpFcn;

} VDIR_MDB_ENTRY_DATABASE, *PVDIR_MDB_ENTRY_DATABASE;

typedef struct _VDIR_MDB_INDEX_DATABASE
{
    PSTR                        pszAttrName;    // Used as key in mdbIndexDBs
    USHORT                      usNumDataFiles;

    // Array of MDBDataFiles indexed by VDIR_CFG_ATTR_INDEX_DESC.iId
    PVDIR_CFG_MDB_DATAFILE_DESC pMdbDataFiles;

    // Btree key comparison function
    PFN_BT_KEY_CMP*             btKeyCmpFcn;

} VDIR_MDB_INDEX_DATABASE, *PVDIR_MDB_INDEX_DATABASE;

typedef struct _VDIR_MDB_INDEX_ITERATOR
{
    PVDIR_DB_TXN    pTxn;
    PVDIR_DB_DBC    pCursor;
    BOOLEAN         bAbort;

    // use to iteratte cursor (MDB_NEXT/MDB_PREV...)
    DWORD           dwCursorFlag;

    // use to position cursor (MDB_SET_RANGE...)
    // 1. single call iterator based search (external or internal)
    // 2. paged multiple calls iterator based search
    // 3. iterator refresh txn
    int             dwInitCursorFlag;

    // if dwInitCursorFlag was MDB_FIRST, say in PRESENT search scenario, all subsequent
    // calls to reposition cursor should use override flags
    int             dwOverrideInitCursorFlag;

    VDIR_DB         mdbDBi;
    int             iIterCount;

} VDIR_MDB_INDEX_ITERATOR, *PVDIR_MDB_INDEX_ITERATOR;

typedef struct _VDIR_MDB_PARENT_ID_INDEX_ITERATOR
{
    PVDIR_DB_TXN    pTxn;
    PVDIR_DB_DBC    pCursor;
    ENTRYID         parentId;
    ENTRYID         entryId;
    BOOLEAN         bAbort;

} VDIR_MDB_PARENT_ID_INDEX_ITERATOR, *PVDIR_MDB_PARENT_ID_INDEX_ITERATOR;

typedef struct _VDIR_MDB_ENTRYBLOB_ITERATOR
{
    PVDIR_DB_TXN    pTxn;
    PVDIR_DB_DBC    pCursor;
    ENTRYID         entryId;
    BOOLEAN         bAbort;

} VDIR_MDB_ENTRYBLOB_ITERATOR, *PVDIR_MDB_ENTRYBLOB_ITERATOR;

typedef struct _VDIR_MDB_ITERATOR
{
    BOOLEAN                    bAbort;
    BOOLEAN                    bHasTxn;
    PVDIR_DB_DBC               pCursor;
    PVDIR_DB_TXN               pTxn;
    VMDIR_COMPACT_KV_PAIR      data;

} VDIR_MDB_ITERATOR, *PVDIR_MDB_ITERATOR;

typedef struct _VDIR_MDB_GLOBALS
{
    // NOTE: order of fields MUST stay in sync with struct initializer...
    VDIR_MDB_ENTRY_DATABASE         mdbEntryDB;
    PLW_HASHMAP                     mdbIndexDBs;
    MDB_env *                       mdbEnv;
    MDB_dbi                         mdbSeqDBi;
    MDB_dbi                         mdbGenericDupKeyDBi;
    MDB_dbi                         mdbGenericUniqKeyDBi;

} VDIR_MDB_GLOBALS, *PVDIR_MDB_GLOBALS;

typedef struct _VDIR_MDB_STATE_GLOBALS
{
    PVMDIR_MUTEX    pMutex;
    DWORD           dwDBCopyCount;
    unsigned long   xLogNum;
    unsigned long   dbSizeMb;
    unsigned long   dbMapMb;
    CHAR            bufDBPath[VMDIR_MAX_FILE_NAME_LEN];
} VDIR_MDB_STATE_GLOBALS, *PVDIR_MDB_STATE_GLOBALS;
