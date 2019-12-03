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
int
_VmDirDeleteOldValueMetaData(
    PVDIR_BACKEND_CTX                  pBECtx,
    ENTRYID                            entryId,
    short                              attrId,
    PVMDIR_VALUE_ATTRIBUTE_METADATA    pValueMetaData
    );

static
DWORD
_VmDirMDBWriteRecord(
    PVDIR_BACKEND_CTX       pBECtx,
    PVDIR_DB                pMdbDBi,
    PVDIR_BERVALUE          pBVKey,     // normalize key
    PVDIR_BERVALUE          pBVValue,   // existing value (update/delete)
    PVDIR_BERVALUE          pNewBVValue // new value (create/update)
    );

static
PVDIR_DB
_VmDirMDBNameToDBi(
    PCSTR   pszDBName
    );

/*
 * MDBUpdateKeyValue(). If it is a unique index, just delete the key, otherwise using cursor, go to the desired
 * entryId value for the key, and delete that particular key-value pair.
 *
 * Return values:
 *     On Success: 0
 *     On Error: MDB error
 */
DWORD
MdbUpdateKeyValue(
   VDIR_DB             mdbDBi,
   PVDIR_DB_TXN        pTxn,
   PVDIR_DB_DBT        pKey,
   PVDIR_DB_DBT        pValue,
   BOOLEAN             bIsUniqueVal,
   ULONG               ulOPMask)
{
    DWORD   dwError = 0;

    switch ( ulOPMask )
    {
        case BE_INDEX_OP_TYPE_CREATE:
            dwError = mdb_put(pTxn, mdbDBi, pKey, pValue, bIsUniqueVal ? MDB_NOOVERWRITE : BE_DB_FLAGS_ZERO);
            BAIL_ON_VMDIR_ERROR( dwError );
            break;
        case BE_INDEX_OP_TYPE_UPDATE:
            dwError = mdb_put(pTxn, mdbDBi, pKey, pValue, BE_DB_FLAGS_ZERO);
            BAIL_ON_VMDIR_ERROR( dwError );
            break;
        case BE_INDEX_OP_TYPE_DELETE:
            dwError = MdbDeleteKeyValue(mdbDBi, pTxn, pKey, pValue, bIsUniqueVal);
            BAIL_ON_VMDIR_ERROR( dwError );
            break;
        default:
            assert(FALSE);
    }

cleanup:

    return dwError;

error:

    VMDIR_LOG_ERROR( LDAP_DEBUG_BACKEND, "MDBUpdateKeyValue: failed with error code: %d, error string: %s",
              dwError, mdb_strerror(dwError) );

    goto cleanup;
}

/*
 * DeleteKeyValue(). If it is a unique index, just delete the key, otherwise using cursor, go to the desired
 * value for the key, and delete that particular key-value pair.
 *
 * Return values:
 *     On Success: 0
 *     On Error: MDB error
*/
DWORD
MdbDeleteKeyValue(
    VDIR_DB             mdbDBi,
    PVDIR_DB_TXN        pTxn,
    PVDIR_DB_DBT        pKey,
    PVDIR_DB_DBT        pValue,
    BOOLEAN             bIsUniqueVal)
{
    DWORD   dwError = 0;

    if (bIsUniqueVal)
    {   // unique key case, no need to match pValue parameter
        dwError = mdb_del(pTxn, mdbDBi, pKey, NULL);
        BAIL_ON_VMDIR_ERROR(dwError);
    }
    else
    {   // delete matched key and value record only.
        dwError = mdb_del(pTxn, mdbDBi, pKey, pValue);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

cleanup:

    return dwError;

error:

    VMDIR_LOG_ERROR( LDAP_DEBUG_BACKEND, "DeleteKeyValue failed with error code: %d, error string: %s",
              dwError, mdb_strerror(dwError) );

    goto cleanup;
}

/*
 * MDBDeleteEIdIndex(): In blob.db, delete entryid => blob index.
 *
 * Return values:
 *     On Success: 0
 *     On Error: BE error
 */
DWORD
MDBDeleteEIdIndex(
    PVDIR_DB_TXN    pTxn,
    ENTRYID         entryId
    )
{
    DWORD               dwError = 0;
    VDIR_DB_DBT         key = {0};
    VDIR_DB             mdbDBi = 0;
    unsigned char       EIdBytes[sizeof( ENTRYID )] = {0};

    assert(pTxn);

    mdbDBi = gVdirMdbGlobals.mdbEntryDB.pMdbDataFiles[0].mdbDBi;

    key.mv_data = &EIdBytes[0];
    MDBEntryIdToDBT(entryId, &key);
    // entry DB is guarantee to be unique key.
    dwError = MdbDeleteKeyValue(mdbDBi, pTxn, &key, NULL, TRUE);
    BAIL_ON_VMDIR_ERROR( dwError );

cleanup:

    return dwError;

error:

    VMDIR_SET_BACKEND_ERROR(dwError);

    goto cleanup;
}

/*
 * delete all records that match string compare "key*"
 */
DWORD
MdbDeleteAllReccord(
    VDIR_DB             mdbDBi,
    PVDIR_DB_TXN        pTxn,
    PVDIR_DB_DBT        pKey
    )
{
    DWORD           dwError = 0;
    PVDIR_DB_DBC    pCursor = NULL;
    unsigned int    cursorFlags =0;
    VDIR_DB_DBT     currKey = {0};
    VDIR_DB_DBT     currValue = {0};
    BOOLEAN         bHasMore = TRUE;

    assert(pTxn);
    assert(pKey);

    while (bHasMore)
    {
        dwError = mdb_cursor_open(pTxn, mdbDBi, &pCursor);
        BAIL_ON_VMDIR_ERROR(dwError);

        memset(&currKey, 0, sizeof(currKey));
        currKey.mv_size = pKey->mv_size;
        currKey.mv_data = pKey->mv_data;

        cursorFlags = MDB_SET_RANGE;

        bHasMore = FALSE;
        if ((dwError = mdb_cursor_get(pCursor, &currKey, &currValue, cursorFlags )) != 0)
        {
            if (dwError == MDB_NOTFOUND)
            {
                dwError = 0;
                break;
            }

            BAIL_ON_VMDIR_ERROR(dwError);
        }

        /*
         * there was at least one instance where key.size > currKey.size
         * adding size check before memcmp
        */
        if (pKey->mv_size > currKey.mv_size ||
            memcmp(pKey->mv_data, currKey.mv_data, pKey->mv_size) != 0)
        {
            break;
        }

        {
            unsigned char* p = (unsigned char*)currKey.mv_data;
            VMDIR_LOG_VERBOSE(
                LDAP_DEBUG_BACKEND,
                "delete key size %d key %02X %02X %02X %02X %02X %02X %02X",
                currKey.mv_size, p[0],p[1],p[2],p[3],p[4],p[5],p[6]);
        }

        dwError = mdb_cursor_del(pCursor, 0);
        BAIL_ON_VMDIR_ERROR(dwError);

        // after mdb_cursor_del call, it is not safe to use the same cursor and go to MDB_NEXT.
        // with small DB, it seems fine but has strange behavior with big size DB.
        // close current cursor and open a new one instead.
        bHasMore = TRUE;
        mdb_cursor_close(pCursor);
        pCursor = NULL;
    }

cleanup:
    if (pCursor)
    {
        mdb_cursor_close(pCursor);
    }
    return dwError;

error:
    VMDIR_LOG_VERBOSE(LDAP_DEBUG_BACKEND,
             "%s error:(%d) key=(%p)(%.*s)",
             __FUNCTION__, dwError,
             pKey->mv_data, VMDIR_MIN(pKey->mv_size,VMDIR_MAX_LOG_OUTPUT_LEN), (char *)pKey->mv_data);

    goto cleanup;
}

/*
 * MdbDeleteAllAttrMetaData(): delete all attribute metadata for an entry
 * Called during tombstone entry aging
 *
 * Return values:
 *     On Success: 0
 *     On Error: MDB error
 */
DWORD
MdbDeleteAllAttrMetaData(
    PVDIR_DB_TXN     pTxn,
    ENTRYID          entryId
    )
{
    DWORD                 dwError = 0;
    VDIR_DB_DBT           key = {0};
    char                  keyData[ sizeof( ENTRYID ) + 1] = {0}; /* key format is: <entry ID>: */
    VDIR_DB               mdbDBi = 0;
    VDIR_BERVALUE         attrMetaDataAttr = { {ATTR_ATTR_META_DATA_LEN, ATTR_ATTR_META_DATA}, 0, 0, NULL };
    PVDIR_INDEX_CFG       pIndexCfg = NULL;

    assert(pTxn);

    dwError = VmDirIndexCfgAcquire(
            attrMetaDataAttr.lberbv.bv_val, VDIR_INDEX_WRITE, &pIndexCfg);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirMDBIndexGetDBi(pIndexCfg, &mdbDBi);
    BAIL_ON_VMDIR_ERROR(dwError);

    key.mv_data = &keyData[0];
    MDBEntryIdToDBT( entryId, &key );
    *(unsigned char *)((unsigned char *)key.mv_data + key.mv_size) = ':';
    key.mv_size++;

    dwError = MdbDeleteAllReccord(mdbDBi, pTxn, &key);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    VmDirIndexCfgRelease(pIndexCfg);
    return dwError;

error:
    VMDIR_LOG_ERROR(LDAP_DEBUG_BACKEND,
             "%s failed: error=%d,eid=%ld", __FUNCTION__, dwError, entryId);

    VMDIR_LOG_VERBOSE(LDAP_DEBUG_BACKEND,
             "%s failed: key=(%p)(%.*s)",
             __FUNCTION__,
             key.mv_data, VMDIR_MIN(key.mv_size,VMDIR_MAX_LOG_OUTPUT_LEN), (char *) key.mv_data);

    goto cleanup;
}

/*
 * UpdateAttributeMetaData(): Update attribute's meta data.
 *
 * Return values:
 *     On Success: 0
 *     On Error: MDB error
 */
DWORD
MdbUpdateAttrMetaData(
    PVDIR_DB_TXN     pTxn,
    VDIR_ATTRIBUTE * attr,
    ENTRYID          entryId,
    ULONG            ulOPMask)
{
    DWORD                 dwError = 0;
    VDIR_DB_DBT           key = {0};
    VDIR_DB_DBT           value = {0};
    char                  keyData[ sizeof( ENTRYID ) + 1 + 2 ] = {0}; /* key format is: <entry ID>:<attribute ID (a short)> */
    PSZ_METADATA_BUF      pszMetaData = {'\0'};
    VDIR_DB               mdbDBi = 0;
    int                   indTypes = 0;
    BOOLEAN               bIsUniqueVal = FALSE;
    VDIR_BERVALUE         attrMetaDataAttr = { {ATTR_ATTR_META_DATA_LEN, ATTR_ATTR_META_DATA}, 0, 0, NULL };
    unsigned char *       pWriter = NULL;
    PVDIR_INDEX_CFG       pIndexCfg = NULL;

    // E.g. while deleting a user, and therefore updating the member attribute of the groups to which the user belongs,
    // member attrMetaData of the group object is left unchanged (at least in the current design, SJ-TBD).
    if (ulOPMask == BE_INDEX_OP_TYPE_UPDATE &&
        (!attr->pMetaData || !attr->pMetaData->pszOrigInvoId))
    {
        goto cleanup;
    }

    dwError = VmDirIndexCfgAcquire(
            attrMetaDataAttr.lberbv.bv_val, VDIR_INDEX_WRITE, &pIndexCfg);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirMDBIndexGetDBi(pIndexCfg, &mdbDBi);
    BAIL_ON_VMDIR_ERROR(dwError);

    indTypes = pIndexCfg->iTypes;
    assert( indTypes == INDEX_TYPE_EQUALITY );
    bIsUniqueVal = pIndexCfg->bGlobalUniq;
    assert( bIsUniqueVal );

    key.mv_data = &keyData[0];
    MDBEntryIdToDBT( entryId, &key );
    *(unsigned char *)((unsigned char *)key.mv_data + key.mv_size) = ':';
    key.mv_size++;
    pWriter = ((unsigned char *)key.mv_data + key.mv_size);
    VmDirEncodeShort( &pWriter, attr->pATDesc->usAttrID );
    key.mv_size += 2;

    dwError = VmDirMetaDataSerialize(attr->pMetaData, &pszMetaData[0]);
    BAIL_ON_VMDIR_ERROR(dwError);

    value.mv_data = &pszMetaData[0];
    value.mv_size = VmDirStringLenA(pszMetaData);

    dwError = MdbUpdateKeyValue( mdbDBi, pTxn, &key, &value, bIsUniqueVal, ulOPMask );
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    VmDirIndexCfgRelease(pIndexCfg);
    return dwError;

error:
    VMDIR_LOG_ERROR(LDAP_DEBUG_BACKEND,
             "UpdateAttributeMetaData failed: error=%d,eid=%ld", dwError, entryId);

    VMDIR_LOG_VERBOSE(LDAP_DEBUG_BACKEND,
             "UpdateAttributeMetaData failed: key=(%p)(%.*s), value=(%p)(%.*s)\n",
             key.mv_data,   VMDIR_MIN(key.mv_size,   VMDIR_MAX_LOG_OUTPUT_LEN), (char *) key.mv_data,
             value.mv_data, VMDIR_MIN(value.mv_size, VMDIR_MAX_LOG_OUTPUT_LEN), (char *) value.mv_data);

    goto cleanup;
}

/*
 * UpdateIndicesForAttribute(): If the given attribute is indexed, create/delete the required indices.
 *
 * Return values:
 *     On Success: 0
 *     On Error: MDB error
 *
 *     Returns Success if the attribute is not indexed. => nothing to be done.
 */
DWORD
MdbUpdateIndicesForAttr(
    PVDIR_DB_TXN        pTxn,
    VDIR_BERVALUE *     entryDN,
    VDIR_BERVALUE *     attrType,
    VDIR_BERVARRAY      attrVals, // Normalized Attribute Values
    unsigned            numVals,
    ENTRYID             entryId,
    ULONG               ulOPMask
    )
{
    DWORD               dwError = 0;
    VDIR_DB_DBT         value = {0};
    VDIR_DB_DBT         key = {0};
    ber_len_t           maxRqdKeyLen = 0;
    PSTR                pKeyData = NULL;
    VDIR_DB             mdbDBi = 0;
    int                 indTypes = 0;
    BOOLEAN             bIsUniqueVal = FALSE;
    unsigned char       eIdBytes[sizeof( ENTRYID )] = {0};
    PVDIR_INDEX_CFG     pIndexCfg = NULL;

    dwError = VmDirIndexCfgAcquire(
            attrType->lberbv.bv_val, VDIR_INDEX_WRITE, &pIndexCfg);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (pIndexCfg)
    {
        unsigned int    i = 0;
        PSTR            pszDN = BERVAL_NORM_VAL(*entryDN);

        indTypes = pIndexCfg->iTypes;
        bIsUniqueVal = pIndexCfg->bGlobalUniq;

        dwError = VmDirMDBIndexGetDBi(pIndexCfg, &mdbDBi);
        BAIL_ON_VMDIR_ERROR(dwError);

        // Calculate required maximum length of the key.
        for (i=0; i<numVals; i++)
        {
            if (BERVAL_NORM_LEN(attrVals[i]) > maxRqdKeyLen)
            {
                maxRqdKeyLen = BERVAL_NORM_LEN(attrVals[i]);
            }
        }
        maxRqdKeyLen += 1; // For adding the Key type in front

        if (VmDirAllocateMemory( maxRqdKeyLen, (PVOID *)&pKeyData ) != 0)
        {
            dwError = ERROR_BACKEND_OPERATIONS;
            BAIL_ON_VMDIR_ERROR( dwError );
        }
        assert (pKeyData != NULL);

        value.mv_data = &eIdBytes[0];
        MDBEntryIdToDBT(entryId, &value);

        for (i=0; i<numVals; i++)
        {
            char*       pNormVal   = BERVAL_NORM_VAL(attrVals[i]);
            ber_len_t   normValLen = BERVAL_NORM_LEN(attrVals[i]);

            dwError = MdbValidateAttrUniqueness(pIndexCfg, pNormVal, pszDN, ulOPMask);
            BAIL_ON_VMDIR_ERROR( dwError );

            key.mv_size = 0;
            key.mv_data = pKeyData;

            // Create a normal index
            if (indTypes & INDEX_TYPE_EQUALITY)
            {
                *(char *)(key.mv_data) = BE_INDEX_KEY_TYPE_FWD;
                dwError = VmDirCopyMemory(((char *)key.mv_data + 1), normValLen, pNormVal, normValLen);
                BAIL_ON_VMDIR_ERROR(dwError);

                key.mv_size = normValLen + 1;

                dwError = MdbUpdateKeyValue( mdbDBi, pTxn, &key, &value, bIsUniqueVal, ulOPMask );
                BAIL_ON_VMDIR_ERROR( dwError );
            }

            // At least create a reverse index. => Normal index and reverse index should take care of initial substring
            // and final substring filters.
            if (indTypes & INDEX_TYPE_SUBSTR)
            {
                ber_len_t     j = 0;
                ber_len_t     k = 0;

                *(char *)key.mv_data = BE_INDEX_KEY_TYPE_REV;
                // Reverse copy from attrVals[i]->lberbv.bv_val to &(key.data[1])
                for (j=normValLen, k=1; j > 0; j--, k++)
                {
                    *((char *)key.mv_data + k) = pNormVal[j-1];
                }

                key.mv_size = normValLen + 1;

                dwError = MdbUpdateKeyValue( mdbDBi, pTxn, &key, &value, bIsUniqueVal, ulOPMask );
                BAIL_ON_VMDIR_ERROR( dwError );
            }
        }
    }

cleanup:
    VmDirIndexCfgRelease(pIndexCfg);
    VMDIR_SAFE_FREE_MEMORY(pKeyData);

    return dwError;

error:
    VMDIR_LOG_ERROR(LDAP_DEBUG_BACKEND,
             "MDBUpdateIndicesForAttr failed: error=%d,eid=%ld,attr=%s",
             dwError, entryId, VDIR_SAFE_STRING(attrType->lberbv.bv_val));

    VMDIR_LOG_VERBOSE(LDAP_DEBUG_BACKEND,
             "MDBUpdateIndicesForAttr failed: key=(%p)(%.*s), value=(%p)(%.*s)",
             key.mv_data,   VMDIR_MIN(key.mv_size,   VMDIR_MAX_LOG_OUTPUT_LEN),  (char *) key.mv_data,
             value.mv_data, VMDIR_MIN(value.mv_size, VMDIR_MAX_LOG_OUTPUT_LEN),  (char *) value.mv_data);

    goto cleanup;
}

DWORD
MdbValidateAttrUniqueness(
    PVDIR_INDEX_CFG     pIndexCfg,
    PSTR                pszAttrVal,
    PSTR                pszEntryDN,
    ULONG               ulOPMask
    )
{
    DWORD   dwError = 0;
    PVDIR_BACKEND_INDEX_ITERATOR    pIterator = NULL;
    PLW_HASHMAP             pOccupiedScopes = NULL;
    LW_HASHMAP_ITER         iter = LW_HASHMAP_ITER_INIT;
    LW_HASHMAP_PAIR         pair = {NULL, NULL};
    PVDIR_LINKED_LIST_NODE  pNode = NULL;
    VDIR_ENTRY  entry = {0};
    PSTR        pszScope = NULL;
    PSTR        pszScopeCopy = NULL;
    PSTR        pszDN = NULL;
    PSTR        pszDNCopy = NULL;
    PVMDIR_MUTEX    pMutex = NULL;
    BOOLEAN         bInLock = FALSE;
    VDIR_ITERATOR_CONTEXT       iterContext = {0};
    VDIR_ITERATOR_SEARCH_PLAN   searchPlan = {0};

    if (!pIndexCfg || IsNullOrEmptyString(pszAttrVal))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = LwRtlCreateHashMap(&pOccupiedScopes,
            LwRtlHashDigestPstrCaseless,
            LwRtlHashEqualPstrCaseless,
            NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

    // delete cannot violate uniqueness
    if (ulOPMask == BE_INDEX_OP_TYPE_DELETE)
    {
        goto cleanup;
    }

    // no uniqueness enforced
    if (LwRtlHashMapGetCount(pIndexCfg->pUniqScopes) == 0)
    {
        // use pNewUniqScopes if VDIR_INDEXING_VALIDATING_SCOPES
        if (pIndexCfg->status != VDIR_INDEXING_VALIDATING_SCOPES ||
            VmDirLinkedListIsEmpty(pIndexCfg->pNewUniqScopes))
        {
            goto cleanup;
        }
    }

    dwError = VmDirIterSearchPlanInitContent(
            LDAP_FILTER_EQUALITY,
            FALSE,
            pIndexCfg->pszAttrName,
            pszAttrVal,
            &searchPlan);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirIterContextInitContent(&iterContext, &searchPlan);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirMDBIndexIteratorInit(pIndexCfg, &iterContext, &pIterator);
    BAIL_ON_VMDIR_ERROR(dwError);

    pMutex = pIndexCfg->mutex;
    VMDIR_LOCK_MUTEX(bInLock, pMutex);

    // find all uniqueness scopes that are already occupied
    while (pIterator->bHasNext)
    {
        dwError = VmDirMDBSimpleEIdToEntry(iterContext.eId, &entry);
        BAIL_ON_VMDIR_ERROR(dwError);

        pszDN = BERVAL_NORM_VAL(entry.dn);

        // find occupied scopes in pUniqScopes
        LwRtlHashMapResetIter(&iter);
        while (LwRtlHashMapIterate(pIndexCfg->pUniqScopes, &iter, &pair))
        {
            pszScope = pair.pKey;

            if (VmDirStringCompareA(PERSISTED_DSE_ROOT_DN, pszScope, FALSE) == 0 ||
                VmDirStringEndsWith(pszDN, pszScope, FALSE))
            {
                if (LwRtlHashMapFindKey(pOccupiedScopes, NULL, pszScope) != 0)
                {
                    // create and store copies in the map
                    dwError = VmDirAllocateStringA(pszScope, &pszScopeCopy);
                    BAIL_ON_VMDIR_ERROR(dwError);

                    dwError = VmDirAllocateStringA(pszDN, &pszDNCopy);
                    BAIL_ON_VMDIR_ERROR(dwError);

                    dwError = LwRtlHashMapInsert(
                            pOccupiedScopes, pszScopeCopy, pszDNCopy, NULL);
                    BAIL_ON_VMDIR_ERROR(dwError);

                    pszScopeCopy = NULL;
                    pszDNCopy = NULL;
                }
                else
                {
                    // uniqueness is already violated, no recovery plan
                    assert(FALSE);
                }
            }
        }

        // find occupied scopes in pNewUniqScopes
        if (pIndexCfg->status == VDIR_INDEXING_VALIDATING_SCOPES)
        {
            pNode = pIndexCfg->pNewUniqScopes->pTail;
            while (pNode)
            {
                pszScope = (PSTR)pNode->pElement;

                if (VmDirStringCompareA(PERSISTED_DSE_ROOT_DN, pszScope, FALSE) == 0 ||
                    VmDirStringEndsWith(pszDN, pszScope, FALSE))
                {
                    if (LwRtlHashMapFindKey(pOccupiedScopes, NULL, pszScope) != 0)
                    {
                        // create and store copies in the map
                        dwError = VmDirAllocateStringA(pszScope, &pszScopeCopy);
                        BAIL_ON_VMDIR_ERROR(dwError);

                        dwError = VmDirAllocateStringA(pszDN, &pszDNCopy);
                        BAIL_ON_VMDIR_ERROR(dwError);

                        dwError = LwRtlHashMapInsert(
                                pOccupiedScopes, pszScopeCopy, pszDNCopy, NULL);
                        BAIL_ON_VMDIR_ERROR(dwError);

                        pszScopeCopy = NULL;
                        pszDNCopy = NULL;
                    }
                }

                pNode = pNode->pPrev;
            }
        }

        VmDirFreeEntryContent(&entry);

        dwError = VmDirMDBIndexIterate(pIterator, &iterContext);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    // check if the new entry dn matches any occupied scope
    LwRtlHashMapResetIter(&iter);
    while (LwRtlHashMapIterate(pOccupiedScopes, &iter, &pair))
    {
        pszScope = (PSTR)pair.pKey;
        pszDN = (PSTR)pair.pValue;

        if (VmDirStringCompareA(pszEntryDN, pszDN, FALSE) != 0 &&
            (VmDirStringCompareA(PERSISTED_DSE_ROOT_DN, pszScope, FALSE) == 0 ||
             VmDirStringEndsWith(pszEntryDN, pszScope, FALSE)))
        {
            // found conflict
            // reject in order to preserve uniqueness
            dwError = VMDIR_ERROR_DATA_CONSTRAINT_VIOLATION;

            VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                    "%s detected that attr '%s' value '%s' "
                    "already exists in scope '%s', "
                    "will return error %d",
                    __FUNCTION__,
                    pIndexCfg->pszAttrName,
                    pszAttrVal,
                    pszScope,
                    dwError );

            BAIL_ON_VMDIR_ERROR(dwError);
        }
    }

cleanup:
    VMDIR_UNLOCK_MUTEX(bInLock, pMutex);
    VmDirMDBIndexIteratorFree(pIterator);
    if (pOccupiedScopes)
    {
        LwRtlHashMapClear(pOccupiedScopes, VmDirSimpleHashMapPairFree, NULL);
        LwRtlFreeHashMap(&pOccupiedScopes);
    }
    VmDirFreeEntryContent(&entry);
    VmDirIterSearchPlanFreeContent(&searchPlan);
    VmDirIterContextFreeContent(&iterContext);
    return dwError;

error:
    if (dwError != VMDIR_ERROR_DATA_CONSTRAINT_VIOLATION)
    {
        VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                "%s failed, error (%d)", __FUNCTION__, dwError );
    }

    VMDIR_SAFE_FREE_MEMORY(pszScopeCopy);
    VMDIR_SAFE_FREE_MEMORY(pszDNCopy);
    goto cleanup;
}

/*
 * CreateParentIdIndex(): In parentid.db, create parentId => entryId index. => mainly used in one-level searches.
 *
 * Return values:
 *     On Success: 0
 *     On Error: BE error
 */
DWORD
MDBCreateParentIdIndex(
    PVDIR_BACKEND_CTX   pBECtx,
    VDIR_BERVALUE *     pdn,
    ENTRYID             entryId)
{
    DWORD               dwError = 0;
    VDIR_DB_DBT         key = {0};
    VDIR_DB_DBT         value = {0};
    VDIR_DB             mdbDBi = 0;
    BOOLEAN             bIsUniqueVal = FALSE;
    VDIR_BERVALUE       parentIdAttr = { {ATTR_PARENT_ID_LEN, ATTR_PARENT_ID}, 0, 0, NULL };
    ENTRYID             parentId = 0;
    unsigned char       eIdBytes[sizeof( ENTRYID )] = {0};
    unsigned char       parentEIdBytes[sizeof( ENTRYID )] = {0};
    PVDIR_INDEX_CFG     pIndexCfg = NULL;
    PSTR                pszLocalErrMsg = NULL;

    assert(pBECtx && pBECtx->pBEPrivate && pdn);

    dwError = VmDirMDBDNToEntryId( pBECtx, pdn, &parentId );
    BAIL_ON_VMDIR_ERROR( dwError );

    // Update parentId => entryId index in parentid.db.
    dwError = VmDirIndexCfgAcquire(
            parentIdAttr.lberbv.bv_val, VDIR_INDEX_WRITE, &pIndexCfg);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirMDBIndexGetDBi(pIndexCfg, &mdbDBi);
    BAIL_ON_VMDIR_ERROR(dwError);

    bIsUniqueVal = pIndexCfg->bGlobalUniq;
    assert( bIsUniqueVal == FALSE );

    key.mv_data = &parentEIdBytes[0];
    MDBEntryIdToDBT(parentId, &key);

    value.mv_data = &eIdBytes[0];
    MDBEntryIdToDBT(entryId, &value);

    if ((dwError = mdb_put((PVDIR_DB_TXN)pBECtx->pBEPrivate, mdbDBi, &key, &value, BE_DB_FLAGS_ZERO)) != 0)
    {
        DWORD   dwTmp = dwError;
        dwError = MDBToBackendError(dwError, 0, ERROR_BACKEND_ERROR, pBECtx, VDIR_SAFE_STRING(pdn->lberbv.bv_val));
        BAIL_ON_VMDIR_ERROR_WITH_MSG( dwError, pszLocalErrMsg,
                        "CreateParentIdIndex: For entryId: %lld, mdb_put failed with error code: %d, error "
                        "string: %s", entryId, dwTmp, VDIR_SAFE_STRING(pBECtx->pszBEErrorMsg) );
    }

cleanup:
    VmDirIndexCfgRelease(pIndexCfg);
    VMDIR_SAFE_FREE_MEMORY(pszLocalErrMsg);

    return dwError;

error:

    VMDIR_LOG_ERROR( LDAP_DEBUG_BACKEND, VDIR_SAFE_STRING(pszLocalErrMsg));

    VMDIR_SET_BACKEND_ERROR(dwError);

    goto cleanup;
}

/*
 * DeleteParentIdIndex(): In parentid.db, delete parentId => entryId index.
 *
 * Return values:
 *     On Success: 0
 *     On Error: BE error
 */
DWORD
MDBDeleteParentIdIndex(
    PVDIR_BACKEND_CTX   pBECtx,
    VDIR_BERVALUE *     pdn,
    ENTRYID             entryId)
{
    DWORD               dwError = 0;
    VDIR_DB_DBT         key = {0};
    VDIR_DB_DBT         value = {0};
    VDIR_DB             mdbDBi = 0;
    BOOLEAN             bIsUniqueVal = FALSE;
    VDIR_BERVALUE       parentIdAttr = { {ATTR_PARENT_ID_LEN, ATTR_PARENT_ID}, 0, 0, NULL };
    ENTRYID             parentId = 0;
    unsigned char       parentEIdBytes[sizeof( ENTRYID )] = {0};
    unsigned char       entryIdBytes[sizeof( ENTRYID )] = {0};
    PVDIR_INDEX_CFG     pIndexCfg = NULL;

    assert(pBECtx && pBECtx->pBEPrivate && pdn);

    dwError = VmDirMDBDNToEntryId( pBECtx, pdn, &parentId );
    BAIL_ON_VMDIR_ERROR( dwError );

    dwError = VmDirIndexCfgAcquire(
            parentIdAttr.lberbv.bv_val, VDIR_INDEX_WRITE, &pIndexCfg);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirMDBIndexGetDBi(pIndexCfg, &mdbDBi);
    BAIL_ON_VMDIR_ERROR(dwError);

    bIsUniqueVal = pIndexCfg->bGlobalUniq;
    assert( bIsUniqueVal == FALSE );

    key.mv_data = &parentEIdBytes[0];
    MDBEntryIdToDBT(parentId, &key);

    value.mv_data = &entryIdBytes[0];
    MDBEntryIdToDBT(entryId, &value);

    dwError = MdbDeleteKeyValue(mdbDBi, (VDIR_DB_TXN*)pBECtx->pBEPrivate, &key, &value, bIsUniqueVal);
    BAIL_ON_VMDIR_ERROR( dwError );

cleanup:
    VmDirIndexCfgRelease(pIndexCfg);
    return dwError;

error:

    VMDIR_SET_BACKEND_ERROR(dwError);

    goto cleanup;
}

/*
 * CreateEntryIdIndex(): In entry DB, create entryId => encodedEntry entry.
 *
 * Return values:
 *     On Success: 0
 *     On Error: MDB error
 */
DWORD
MdbCreateEIDIndex(
    PVDIR_DB_TXN     pTxn,
    ENTRYID          eId,
    VDIR_BERVALUE *  pEncodedEntry,
    BOOLEAN          bIsCreateIndex // Creating a new or updating an existing index recrod.
    )
{
    int             dwError = 0;
    VDIR_DB_DBT     key = {0};
    VDIR_DB_DBT     value = {0};
    VDIR_DB         mdbDBi = 0;
    BOOLEAN         bIsUniqueVal = FALSE;
    unsigned char   eIdBytes[sizeof( ENTRYID )] = {0};

    assert(pTxn && pEncodedEntry);

    mdbDBi = gVdirMdbGlobals.mdbEntryDB.pMdbDataFiles[0].mdbDBi;
    bIsUniqueVal = gVdirMdbGlobals.mdbEntryDB.pMdbDataFiles[0].bIsUnique;
    assert( bIsUniqueVal );

    key.mv_data = &eIdBytes[0];
    MDBEntryIdToDBT(eId, &key);

    value.mv_data = pEncodedEntry->lberbv.bv_val;
    value.mv_size = pEncodedEntry->lberbv.bv_len;

    // new index case    - MDB_NOOVERWRITE
    // update index case - MDB_FLAGS_ZERO
    dwError = mdb_put( pTxn, mdbDBi, &key, &value, bIsCreateIndex ? MDB_NOOVERWRITE : BE_DB_FLAGS_ZERO);
    BAIL_ON_VMDIR_ERROR( dwError );

cleanup:

    return dwError;

error:

    VMDIR_LOG_ERROR( LDAP_DEBUG_BACKEND, "CreateEntryIdIndex failed for entryId: %lld, error code: %d, error string: %s",
              eId, dwError, mdb_strerror(dwError) );

    goto cleanup;
}

/*
 * VmDirUpdateAttributeValueMetaData(): Update attribute's value meta data.
 * The attribute meta value data to be added or deleted are stored in
 * valueMetaData.
 * ulOPMask is BE_INDEX_OP_TYPE_UPDATE (for adding) or BE_INDEX_OP_TYPE_DELETE
 * (for deleting) the attribute's value meta data.
 * After consuming the attribute's value meta data or any error, contents in
 * valueMetaData are removed and freed from the queue.
 */
DWORD
VmDirMdbUpdateAttrValueMetaData(
    PVDIR_BACKEND_CTX   pBECtx,
    ENTRYID             entryId,
    short               attrId,
    ULONG               ulOPMask,
    PDEQUE              pValueMetaDataQueue
    )
{
    DWORD                              dwError = 0;
    VDIR_BERVALUE                      bervValueMetaData = VDIR_BERVALUE_INIT;
    PVDIR_DB_TXN                       pTxn = NULL;
    VDIR_DB_DBT                        key = {0};
    VDIR_DB_DBT                        value = {0};
    //key format is: <entry ID>:<attribute ID
    char                               keyData[sizeof(ENTRYID) + 1 + 2] = {0};
    VDIR_DB                            mdbDBi = 0;
    int                                indTypes = 0;
    VDIR_BERVALUE                      attrValueMetaDataAttr =
                                       {{ATTR_ATTR_VALUE_META_DATA_LEN, ATTR_ATTR_VALUE_META_DATA},
                                         0, 0, NULL};
    unsigned char                     *pWriter = NULL;
    PVDIR_INDEX_CFG                    pIndexCfg = NULL;
    PVMDIR_VALUE_ATTRIBUTE_METADATA    pValueMetaData = NULL;

    if (!VDIR_CONCURRENT_ATTR_VALUE_UPDATE_ENABLED)
    {
        goto cleanup;
    }

    if (dequeIsEmpty(pValueMetaDataQueue))
    {
        goto cleanup;
    }

    assert(pBECtx && pBECtx->pBEPrivate);
    pTxn = (PVDIR_DB_TXN)pBECtx->pBEPrivate;

    dwError = VmDirIndexCfgAcquire(
            attrValueMetaDataAttr.lberbv.bv_val, VDIR_INDEX_READ, &pIndexCfg);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirMDBIndexGetDBi(pIndexCfg, &mdbDBi);
    BAIL_ON_VMDIR_ERROR(dwError);

    indTypes = pIndexCfg->iTypes;
    assert(indTypes == INDEX_TYPE_EQUALITY);

    key.mv_data = &keyData[0];
    MDBEntryIdToDBT(entryId, &key);
    *(unsigned char *)((unsigned char *)key.mv_data + key.mv_size) = ':';
    key.mv_size++;
    pWriter = ((unsigned char *)key.mv_data + key.mv_size);
    VmDirEncodeShort(&pWriter, attrId);
    key.mv_size += 2;

    while(!dequeIsEmpty(pValueMetaDataQueue))
    {
        dequePopLeft(pValueMetaDataQueue, (PVOID*)&pValueMetaData);

        if (ulOPMask == BE_INDEX_OP_TYPE_UPDATE)
        {
            dwError = _VmDirDeleteOldValueMetaData(pBECtx, entryId, attrId, pValueMetaData);
            BAIL_ON_VMDIR_ERROR(dwError);
        }

        dwError = VmDirValueMetaDataSerialize(pValueMetaData, &bervValueMetaData);
        BAIL_ON_VMDIR_ERROR(dwError);

        VMDIR_LOG_INFO(
                LDAP_DEBUG_REPL_ATTR,
                "%s: serialized value: %s len: %lu ulOPMask: %lu",
                __FUNCTION__,
                bervValueMetaData.lberbv_val,
                bervValueMetaData.lberbv_len,
                ulOPMask);

        value.mv_data = bervValueMetaData.lberbv_val;
        value.mv_size = bervValueMetaData.lberbv_len;

        dwError = MdbUpdateKeyValue(mdbDBi, pTxn, &key, &value, FALSE, ulOPMask);
        BAIL_ON_VMDIR_ERROR(dwError);

        VmDirFreeBervalContent(&bervValueMetaData);
        VMDIR_SAFE_FREE_VALUE_METADATA(pValueMetaData);
    }

cleanup:
    VmDirIndexCfgRelease(pIndexCfg);
    VmDirFreeBervalContent(&bervValueMetaData);
    VMDIR_SAFE_FREE_VALUE_METADATA(pValueMetaData);
    return dwError;

error:
    VMDIR_LOG_ERROR(VMDIR_LOG_MASK_ALL, "failed: error=%d, eid=%ld", dwError, entryId);

    VMDIR_LOG_VERBOSE(
            LDAP_DEBUG_BACKEND,
             "%s failed: key=(%p)(%.*s), value=(%p)(%.*s)\n",
             __FUNCTION__,
             key.mv_data,
             VMDIR_MIN(key.mv_size, VMDIR_MAX_LOG_OUTPUT_LEN),
             (char *) key.mv_data,
             value.mv_data,
             VMDIR_MIN(value.mv_size, VMDIR_MAX_LOG_OUTPUT_LEN),
             (char *) value.mv_data);

    goto cleanup;
}

/*
 * VmDirMdbDeleteAllAttrValueMetaData(): delete all attribute meta value data for the entryId
 * Return values:
 *     On Success: 0
 *     On Error: MDB error
 */
DWORD
VmDirMdbDeleteAllAttrValueMetaData(
    PVDIR_BACKEND_CTX   pBECtx,
    PVDIR_SCHEMA_CTX    pSchemaCtx,
    ENTRYID             entryId
)
{
    DWORD                              dwError = 0;
    VDIR_BERVALUE                      bervValueMetaData = VDIR_BERVALUE_INIT;
    PVDIR_DB_TXN                       pTxn = NULL;
    VDIR_DB                            mdbDBi = 0;
    int                                indTypes = 0;
    VDIR_BERVALUE                      attrValueMetaDataAttr =
                                       {{ATTR_ATTR_VALUE_META_DATA_LEN, ATTR_ATTR_VALUE_META_DATA},
                                         0, 0, NULL};
    PVDIR_INDEX_CFG                    pIndexCfg = NULL;
    DEQUE                              valueMetaDataQueue = {0};
    PVMDIR_VALUE_ATTRIBUTE_METADATA    pValueMetaData = NULL;

    if (!VDIR_CONCURRENT_ATTR_VALUE_UPDATE_ENABLED)
    {
        goto cleanup;
    }

    dwError = VmDirMDBGetAllAttrValueMetaData(pBECtx, entryId, &valueMetaDataQueue);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (dequeIsEmpty(&valueMetaDataQueue))
    {
        goto cleanup;
    }

    assert(pBECtx && pBECtx->pBEPrivate);
    pTxn = (PVDIR_DB_TXN)pBECtx->pBEPrivate;

    dwError = VmDirIndexCfgAcquire(
            attrValueMetaDataAttr.lberbv.bv_val, VDIR_INDEX_READ, &pIndexCfg);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirMDBIndexGetDBi(pIndexCfg, &mdbDBi);
    BAIL_ON_VMDIR_ERROR(dwError);

    indTypes = pIndexCfg->iTypes;
    assert(indTypes == INDEX_TYPE_EQUALITY);

    while(!dequeIsEmpty(&valueMetaDataQueue))
    {
        VDIR_DB_DBT              key = {0};
        VDIR_DB_DBT              value = {0};
        //key format is: <entry ID>:<attribute ID (a short)
        char                     keyData[sizeof(ENTRYID) + 1 + 2] = {0};
        unsigned char           *pWriter = NULL;
        PVDIR_SCHEMA_AT_DESC     pATDesc = NULL;

        dequePopLeft(&valueMetaDataQueue, (PVOID*)&pValueMetaData);

        pATDesc = VmDirSchemaAttrNameToDesc(pSchemaCtx, pValueMetaData->pszAttrType);

        if (pATDesc == NULL)
        {
            VMDIR_LOG_ERROR(
                    VMDIR_LOG_MASK_ALL,
                    "VmDirSchemaAttrNameToDesc failed for attr %s",
                    VDIR_SAFE_STRING(pValueMetaData->pszAttrType));
            BAIL_WITH_VMDIR_ERROR(dwError, ERROR_BACKEND_OPERATIONS);
        }

        key.mv_data = &keyData[0];

        MDBEntryIdToDBT(entryId, &key);
        *(unsigned char *)((unsigned char *)key.mv_data + key.mv_size) = ':';
        key.mv_size++;
        pWriter = ((unsigned char *)key.mv_data + key.mv_size);
        VmDirEncodeShort(&pWriter, pATDesc->usAttrID);
        key.mv_size += 2;

        dwError = VmDirValueMetaDataSerialize(pValueMetaData, &bervValueMetaData);
        BAIL_ON_VMDIR_ERROR(dwError);

        VMDIR_LOG_INFO(
                LDAP_DEBUG_REPL_ATTR,
                "%s: serialized value: %s Len: %lu",
                __FUNCTION__,
                bervValueMetaData.lberbv_val,
                bervValueMetaData.lberbv_len);

        value.mv_data = bervValueMetaData.lberbv_val;
        value.mv_size = bervValueMetaData.lberbv_len;

        dwError = MdbUpdateKeyValue(mdbDBi, pTxn, &key, &value, FALSE, BE_INDEX_OP_TYPE_DELETE);
        BAIL_ON_VMDIR_ERROR(dwError);

        VmDirFreeBervalContent(&bervValueMetaData);
        VMDIR_SAFE_FREE_VALUE_METADATA(pValueMetaData);
    }

cleanup:
    VmDirIndexCfgRelease(pIndexCfg);
    VmDirFreeBervalContent(&bervValueMetaData);
    VMDIR_SAFE_FREE_VALUE_METADATA(pValueMetaData);
    VmDirFreeAttrValueMetaDataDequeueContent(&valueMetaDataQueue);
    return dwError;

error:
    VMDIR_LOG_ERROR(VMDIR_LOG_MASK_ALL, "failed: error=%d,eid=%ld", dwError, entryId);
    goto cleanup;
}

static
DWORD
_VmDirMDBWriteRecord(
    PVDIR_BACKEND_CTX       pBECtx,
    PVDIR_DB                pMdbDBi,
    PVDIR_BERVALUE          pBVKey,     // normalize key
    PVDIR_BERVALUE          pBVValue,   // existing value (update/delete)
    PVDIR_BERVALUE          pNewBVValue // new value (create/update)
    )
{
    DWORD           dwError = 0;
    VDIR_DB_DBT     key = {0};
    VDIR_DB_DBT     current = {0};
    VDIR_DB_DBT     value = {0};
    PVDIR_DB_TXN    pTxn = (PVDIR_DB_TXN)pBECtx->pBEPrivate;

    assert(pMdbDBi && pBVKey && pBVKey->bvnorm_val);

    key.mv_data = pBVKey->bvnorm_val;
    key.mv_size = pBVKey->bvnorm_len;
    current.mv_data = pBVValue? pBVValue->bvnorm_val : NULL;
    current.mv_size = pBVValue? pBVValue->bvnorm_len : 0;
    value.mv_data   = pNewBVValue ? pNewBVValue->bvnorm_val : NULL;
    value.mv_size   = pNewBVValue ? pNewBVValue->bvnorm_len : 0;

    if (current.mv_data)
    {   // delete
        dwError = mdb_del(pTxn, *pMdbDBi, &key, &current);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    if (value.mv_data)
    {   // create
        dwError = mdb_put(pTxn, *pMdbDBi, &key, &value, BE_DB_FLAGS_ZERO);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR(VMDIR_LOG_MASK_ALL, "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * support BLOB table for now.  can extend to other tables later.
 */
static
PVDIR_DB
_VmDirMDBNameToDBi(
    PCSTR   pszDBName
    )
{
    PVDIR_DB pMdbDBi = NULL;

    if (VmDirStringCompareA(pszDBName, ATTR_EID_SEQUENCE_NUMBER, FALSE) == 0)
    {   // BLOB table
        pMdbDBi = &gVdirMdbGlobals.mdbEntryDB.pMdbDataFiles[0].mdbDBi;
    }

    return pMdbDBi;
}

/*
 * Function to create/update/delete record in a backend table.
 *
 */
DWORD
VmDirMDBBackendTableWriteRecord(
    PVDIR_BACKEND_CTX       pBECtx,
    VDIR_BACKEND_RECORD_WRITE_TYPE  opType,
    PCSTR                   pszTableName,
    PVDIR_BERVALUE          pBVKey,     // normalize key
    PVDIR_BERVALUE          pBVValue,   // existing value (update/delete)
    PVDIR_BERVALUE          pNewBVValue // new value (create/update)
    )
{
    DWORD           dwError = 0;
    PVDIR_DB        pMdbDBi = NULL;

    if (!pBECtx ||
        !pBECtx->pBEPrivate ||
        !pszTableName ||
        !pBVKey ||
        !pBVKey->bvnorm_val)
    {
        BAIL_WITH_VMDIR_ERROR(dwError, VMDIR_ERROR_INVALID_PARAMETER);
    }

    if (((opType == VDIR_BACKEND_RECORD_WRITE_CREATE || opType == VDIR_BACKEND_RECORD_WRITE_UPDATE) &&
         (!pNewBVValue || !pNewBVValue->bvnorm_val))     ||
        ((opType == VDIR_BACKEND_RECORD_WRITE_DELETE || opType == VDIR_BACKEND_RECORD_WRITE_UPDATE) &&
         (!pBVValue || !pBVValue->bvnorm_val)))
    {
        BAIL_WITH_VMDIR_ERROR(dwError, VMDIR_ERROR_INVALID_PARAMETER);
    }

    pMdbDBi = _VmDirMDBNameToDBi(pszTableName);
    if (pMdbDBi)
    {
        dwError = _VmDirMDBWriteRecord(pBECtx, pMdbDBi, pBVKey, pBVValue, pNewBVValue);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR(VMDIR_LOG_MASK_ALL, "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Function to create/update/delete record in a index table.
 *
 */
DWORD
VmDirMDBIndexTableWriteRecord(
    PVDIR_BACKEND_CTX       pBECtx,
    VDIR_BACKEND_RECORD_WRITE_TYPE  opType,
    PVDIR_BERVALUE          pBVDN,
    PCSTR                   pszIndexName,
    PVDIR_BERVALUE          pBVCurrentKey,  // current normalize key
    PVDIR_BERVALUE          pBVNewKey,      // new normalize key
    PVDIR_BERVALUE          pBVEID          // entry id
    )
{
    DWORD           dwError = 0;
    VDIR_BERVALUE   bvAttrType = {0};
    ENTRYID         entryId = 0;

    if (!pBECtx ||
        !pBECtx->pBEPrivate ||
        !pszIndexName ||
        !pBVEID ||
        !pBVEID->bvnorm_val ||
        !pBVDN || !pBVDN->bvnorm_val)
    {
        BAIL_WITH_VMDIR_ERROR(dwError, VMDIR_ERROR_INVALID_PARAMETER);
    }

    if (((opType == VDIR_BACKEND_RECORD_WRITE_CREATE || opType == VDIR_BACKEND_RECORD_WRITE_UPDATE) &&
         (!pBVNewKey || !pBVNewKey->bvnorm_val))     ||
        ((opType == VDIR_BACKEND_RECORD_WRITE_DELETE || opType == VDIR_BACKEND_RECORD_WRITE_UPDATE) &&
         (!pBVCurrentKey || !pBVCurrentKey->bvnorm_val)))
    {
        BAIL_WITH_VMDIR_ERROR(dwError, VMDIR_ERROR_INVALID_PARAMETER);
    }

    dwError = VmDirBVToEntryId(pBVEID, &entryId);
    BAIL_ON_VMDIR_ERROR(dwError);

    bvAttrType.lberbv_val = (PSTR)pszIndexName;
    bvAttrType.lberbv_len = VmDirStringLenA(pszIndexName);

    if (pBVCurrentKey && pBVCurrentKey->bvnorm_val)
    {
        dwError = MdbUpdateIndicesForAttr(
            (PVDIR_DB_TXN)pBECtx->pBEPrivate,
            pBVDN,
            &bvAttrType,
            pBVCurrentKey,
            1,
            entryId,
            BE_INDEX_OP_TYPE_DELETE);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    if (pBVNewKey && pBVNewKey->bvnorm_val)
    {
        dwError = MdbUpdateIndicesForAttr(
            (PVDIR_DB_TXN)pBECtx->pBEPrivate,
            pBVDN,
            &bvAttrType,
            pBVNewKey,
            1,
            entryId,
            BE_INDEX_OP_TYPE_CREATE);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR(VMDIR_LOG_MASK_ALL, "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Remove the attr-value-meta-data item that matches the entryid, attrId
 * and pAVmetaToAdd's value part from the index database.
 * It is called before the new attr-value-meta-data (pAVmetaToAdd's) with the same value
 * (but with different opeartion or orignating server) is to be inserted into the index.
 * The purpose is to remove obsolete attr-value-meta-data to save storage, though it wouldn't
 * have impact on the correctness of the replication and conflict resolotion.
 * E.g. if an attr is added, and then removed on the same value, only attr-value-meta-data for
 * the removing needs to be kept for replication.
 */
static
int
_VmDirDeleteOldValueMetaData(
    PVDIR_BACKEND_CTX                  pBECtx,
    ENTRYID                            entryId,
    short                              attrId,
    PVMDIR_VALUE_ATTRIBUTE_METADATA    pValueMetaData
    )
{
    DWORD                              dwError = 0;
    DEQUE                              currValueMetaDataQueue = {0};
    DEQUE                              valueMetaDataToDeleteQueue = {0};
    PVMDIR_VALUE_ATTRIBUTE_METADATA    pCurrValueMetaData = NULL;

    dwError = VmDirMDBGetAttrValueMetaData(pBECtx, entryId, attrId, &currValueMetaDataQueue);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (dequeIsEmpty(&currValueMetaDataQueue))
    {
        goto cleanup;
    }

    while(!dequeIsEmpty(&currValueMetaDataQueue))
    {
        dequePopLeft(&currValueMetaDataQueue, (PVOID*)&pCurrValueMetaData);

        if (pValueMetaData->dwValSize == pCurrValueMetaData->dwValSize &&
            VmDirCompareMemory(
                pCurrValueMetaData->pszValue,
                pValueMetaData->pszValue,
                pValueMetaData->dwValSize) == 0 &&
            VmDirStringCompareA(
                pCurrValueMetaData->pszValChgOrigTime,
                pValueMetaData->pszValChgOrigTime,
                TRUE) <= 0)
        {
            dwError = dequePush(&valueMetaDataToDeleteQueue, pCurrValueMetaData);
            BAIL_ON_VMDIR_ERROR(dwError);

            pCurrValueMetaData = NULL;
        }

        VMDIR_SAFE_FREE_VALUE_METADATA(pCurrValueMetaData);
    }

    if (!dequeIsEmpty(&valueMetaDataToDeleteQueue))
    {
        dwError = VmDirMdbUpdateAttrValueMetaData(
                pBECtx, entryId, attrId, BE_INDEX_OP_TYPE_DELETE, &valueMetaDataToDeleteQueue);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

cleanup:
    VmDirFreeAttrValueMetaDataDequeueContent(&valueMetaDataToDeleteQueue);
    VmDirFreeAttrValueMetaDataDequeueContent(&currValueMetaDataQueue);
    return dwError;

error:
    VMDIR_LOG_ERROR(
            VMDIR_LOG_MASK_ALL, "failed, error=%d,eid=%ld,attrId=%d", dwError, entryId, attrId);
    goto cleanup;
}
