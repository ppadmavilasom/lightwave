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



#ifndef COMMON_INTERFACE_H_
#define COMMON_INTERFACE_H_

#include <vmmetrics.h>
extern PVM_METRICS_CONTEXT pmContext;

#define VMDIR_COLLECT_TIME(time) (time = time ? time : VmDirGetTimeInMilliSec())
#define VMDIR_RESPONSE_TIME(start, end) ((start < end) ? (end - start) : 0)

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#define __func__ __FUNCTION__
#endif

#define VMDIR_ORIG_TIME_STR_LEN         ( 4 /* year */ + 2 /* month */ + 2 /* day */ + 2 /* hour */ + 2 /* minute */ + \
                                          2 /* sec */ + 1 /* . */ + 3 /* milli sec */ + 1 /* null byte terminator */ )

#define VMDIR_MAX_USN_STR_LEN           VMDIR_MAX_I64_ASCII_STR_LEN
#define VMDIR_MAX_VERSION_NO_STR_LEN    VMDIR_MAX_I64_ASCII_STR_LEN
#define VMDIR_MAX_OP_CODE_LEN           VMDIR_MAX_UI32_ASCII_STR_LEN
//
// If the new paged search is turned on then the cookie is a guid; otherwise,
// it's an ENTRYID.
//
#define VMDIR_PS_COOKIE_LEN             (VMDIR_MAX(VMDIR_MAX_I64_ASCII_STR_LEN, VMDIR_GUID_STR_LEN))

// Format is: <local USN>:<version no>:<originating server ID>:<originating time>:<originating USN>
#define VMDIR_MAX_ATTR_META_DATA_LEN    (VMDIR_MAX_USN_STR_LEN + 1 + \
                                         VMDIR_MAX_VERSION_NO_STR_LEN + 1 + \
                                         VMDIR_GUID_STR_LEN + 1 + \
                                         VMDIR_ORIG_TIME_STR_LEN + 1 + \
                                         VMDIR_MAX_USN_STR_LEN + 1)

// Format is: <attr-name>:<local-usn>:<version-no>:<originating-server-id>:
// <value-change-originating-server-id>:<value-change-originating time>:
// <value-change-originating-usn>:
// add string len of attr-name and value to obtain complete length
#define VMDIR_PARTIAL_ATTR_VALUE_META_DATA_LEN    (VMDIR_MAX_USN_STR_LEN + 1 + \
                                                   VMDIR_MAX_VERSION_NO_STR_LEN + 1 + \
                                                   VMDIR_GUID_STR_LEN + 1 + \
                                                   VMDIR_GUID_STR_LEN + 1 + \
                                                   VMDIR_ORIG_TIME_STR_LEN + 1 + \
                                                   VMDIR_MAX_USN_STR_LEN + 1 + \
                                                   VMDIR_MAX_OP_CODE_LEN + 1 + \
                                                   VMDIR_MAX_UI32_ASCII_STR_LEN + 1) //Value size

#define VMDIR_IS_DELETED_TRUE_STR      "TRUE"
#define VMDIR_IS_DELETED_TRUE_STR_LEN  4

#define VMDIR_UTD_VECTOR_HASH_TABLE_SIZE  100
#define VMDIR_PAGED_SEARCH_CACHE_HASH_TABLE_SIZE 32
#define VMDIR_LOCKOUT_VECTOR_HASH_TABLE_SIZE  1000

//Note: Ssetting replinterval to 1 second could have negative impact on a star topology where many nodes(say > 5) all
//      have same sigle replication partner.
//      In such case, the center node could potentially starve and could not catch up with changes from other nodes
//      because there are constant repl pull from other nodes and current replication algorithm exclude roles a node can play (consumer/supplier).
#define VMDIR_DEFAULT_REPL_INTERVAL     "1"

#define VMDIR_DEFAULT_REPL_PAGE_SIZE    "1000"
#define VMDIR_REPL_CONT_INDICATOR       "continue:1,"
#define VMDIR_REPL_CONT_INDICATOR_LEN   sizeof(VMDIR_REPL_CONT_INDICATOR)-1

#define VMDIR_RUN_MODE_NORMAL           "normal"
#define VMDIR_RUN_MODE_RESTORE          "restore"
#define VMDIR_RUN_MODE_STANDALONE       "standalone"

// backend generic table keys
#define VMDIR_KEY_BE_GENERIC_ACL_MODE   "acl-mode"
#define VMDIR_ACL_MODE_ENABLED          "enabled"

#define VMDIR_DEFAULT_REPL_LAST_USN_PROCESSED_LEN   sizeof(VMDIR_DEFAULT_REPL_LAST_USN_PROCESSED)

#define GENERALIZED_TIME_STR_LEN       17
#define GENERALIZED_TIME_STR_SIZE      GENERALIZED_TIME_STR_LEN + 1

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#define SOCK_BUF_MAX_INCOMING ((1<<24) - 1) // 16M - 1, e.g. to handle large Add object requests.

// Fix bootstrap attribute id used in schema/defines.h VDIR_SCHEMA_BOOTSTRP_ATTR_INITIALIZER definition
#define SCHEMA_BOOTSTRAP_EID_SEQ_ATTRID_22     22
#define SCHEMA_BOOTSTRAP_USN_SEQ_ATTRID_23     23

#define VDIR_FOREST_FUNCTIONAL_LEVEL    "1"
// This value is the DFL for the current version
#define VDIR_DOMAIN_FUNCTIONAL_LEVEL	"4"

// Mapping of functionality to levels
// Base DFL, support for all 6.0 and earlier functionality
#define VDIR_DFL_DEFAULT 1

// Support for 6.5 functionality, PSCHA
#define VDIR_DFL_PSCHA   2

// Support for 6.6 functionality, ModDn
// Support for LW 1.0 functionality, ModDn
#define VDIR_DFL_MODDN   3

// Support for 6.6 functionality, Custom Schema Modification
// Support for LW 1.0 functionality, Custom Schema Modification
#define VDIR_DFL_CUSTOM_SCHEMA_MODIFICATION     3

// Support for 6.6 functionality, Concurrent Attribute Value Update
// Support for LW 1.1 functionality, Concurrent Attribute Value Update
#define VDIR_DFL_CONCURRENT_ATTR_VALUE_UPDATE   4

// Support for 6.6 functionality, better write operation audit
// Support for LW 1.1 functionality, better write operation audit
#define VDIR_DFL_WRITE_OP_AUDIT                 4

#define VDIR_CUSTOM_SCHEMA_MODIFICATION_ENABLED     \
    (gVmdirServerGlobals.dwDomainFunctionalLevel >= \
            VDIR_DFL_CUSTOM_SCHEMA_MODIFICATION)

#define VDIR_WRITE_OP_AUDIT_ENABLED   \
    (gVmdirServerGlobals.dwDomainFunctionalLevel >= \
            VDIR_DFL_WRITE_OP_AUDIT)

#define VDIR_CONCURRENT_ATTR_VALUE_UPDATE_ENABLED   \
    (gVmdirServerGlobals.dwDomainFunctionalLevel >= \
            VDIR_DFL_CONCURRENT_ATTR_VALUE_UPDATE)

#define MAX_NUM_CONTENT_LOG     256

// Keys for backend funtion pfnBEStrkeyGet/SetValues to access attribute IDs
#define ATTR_ID_MAP_KEY   "1VmdirAttrIDToNameTb"

typedef struct _VDIR_INDEX_CFG*             PVDIR_INDEX_CFG;
typedef struct _VDIR_INDEX_UPD*             PVDIR_INDEX_UPD;
typedef struct _VDIR_BACKEND_INTERFACE*     PVDIR_BACKEND_INTERFACE;
typedef struct _VDIR_SCHEMA_CTX*            PVDIR_SCHEMA_CTX;
typedef struct _VDIR_SCHEMA_DIFF*           PVDIR_SCHEMA_DIFF;
typedef struct _VDIR_ACL_CTX*               PVDIR_ACL_CTX;
typedef struct _VMDIR_BKGD_TASK_CTX*        PVMDIR_BKGD_TASK_CTX;

typedef char PSZ_METADATA_BUF[VMDIR_MAX_ATTR_META_DATA_LEN];

typedef struct _VDIR_BERVALUE
{
#define lberbv_val   lberbv.bv_val
#define lberbv_len   lberbv.bv_len
    BerValue        lberbv;     // native lber BerValue

    // TRUE if we own bv_val.
    // Generally, when data coming from BER, BER owns bv_val at the connection level.
    // If server creates VDIR_BERVAL internally, it owns bv_val and should set this TRUE.
    // (TODO, should assume server owns bv_val by default and set to FALSE at BER parse area.)
    unsigned short  bOwnBvVal; // true if owns bv_val

    // initially, bvnorm_len=0 and bvnorm_val=NULL
    // after normalize call, it becomes
    // if normalize form != original form
    //    bvnorm_val = heap with normalize string NULL terminated
    //    bvnorm_len = strlen(bvnorm_val);
    //  else
    //    bvnorm_val = bv_val and bvnorm_len = bv_len
    ber_len_t       bvnorm_len;
    char*           bvnorm_val;

} VDIR_BERVALUE, *PVDIR_BERVALUE;

#define VDIR_BERVALUE_INIT  { {0,NULL}, 0, 0, NULL }

typedef PVDIR_BERVALUE VDIR_BERVARRAY;

typedef struct _VDIR_BACKEND_CTX
{
    PVDIR_BACKEND_INTERFACE pBE;
    // per data store specific private structure to support transaction context
    int         iBEPrivateRef;
    PVOID       pBEPrivate;
    DWORD       dwBEErrorCode;
    PSTR        pszBEErrorMsg;
    USN         wTxnUSN;            // lowest USN associates with a write txn (could be nested tnx)
                                    // i.e. should be the first USN number acquired per backend write txn.
} VDIR_BACKEND_CTX, *PVDIR_BACKEND_CTX;

// accessRoleBitmap is a bit map on bind dn access role if the info is valid

// valid info in accessRoleBitmap on system domain admins
#define VDIR_ACCESS_ADMIN_MEMBER_VALID_INFO             0x0001

// bind dn is a member of system domain admins
#define VDIR_ACCESS_IS_ADMIN_MEMBER                     0x0002

#define VDIR_ACCESS_ADMIN_MEMBER_INFO VDIR_ACCESS_ADMIN_MEMBER_VALID_INFO

// valid info in accessRoleBitmap member of DC group
#define VDIR_ACCESS_DCGROUP_MEMBER_VALID_INFO           0x0004

// bind dn is a member of DC group
#define VDIR_ACCESS_IS_DCGROUP_MEMBER                   0x0008

#define VDIR_ACCESS_DCGROUP_MEMBER_INFO VDIR_ACCESS_DCGROUP_MEMBER_VALID_INFO

// valid info in accessRoleBitmap on member of DC client group
#define VDIR_ACCESS_DCCLIENT_GROUP_MEMBER_VALID_INFO    0x0010

// bind dn is a member of DC client group
#define VDIR_ACCESS_IS_DCCLIENT_GROUP_MEMBER            0x0020

#define VDIR_ACCESS_DCCLIENT_GROUP_MEMBER_INFO VDIR_ACCESS_DCCLIENT_GROUP_MEMBER_VALID_INFO

#define VMDIR_IS_ADMIN_OR_DC_GROUP_MEMBER(accessRoleBitmap) \
    (accessRoleBitmap & (VDIR_ACCESS_IS_ADMIN_MEMBER | VDIR_ACCESS_IS_DCGROUP_MEMBER))

typedef struct _VDIR_ACCESS_INFO
{
    ENTRYID       bindEID;     // bind user ENTRYID
    PSTR          pszBindedDn; // original DN passed in on the wire
    PSTR          pszNormBindedDn;
    PSTR          pszBindedObjectSid;
    PACCESS_TOKEN pAccessToken;
    UINT32        accessRoleBitmap; // access role if the info is valid
} VDIR_ACCESS_INFO, *PVDIR_ACCESS_INFO;

typedef struct _VDIR_SASL_BIND_INFO*    PVDIR_SASL_BIND_INFO;

typedef struct _VDIR_SUPERLOG_RECORD_SEARCH_INFO
{
    PSTR    pszAttributes;
    PSTR    pszBaseDN;
    PSTR    pszScope;
    PSTR    pszIndexResults;
    DWORD   dwScanned;
    DWORD   dwReturned;
} VDIR_SUPERLOG_RECORD_SEARCH_INFO;

typedef union _VDIR_SUPERLOG_RECORD_OPERATION_INFO
{
    VDIR_SUPERLOG_RECORD_SEARCH_INFO searchInfo;
} VDIR_SUPERLOG_RECORD_OPERATION_INFO;

typedef struct _VDIR_SUPERLOG_RECORD
{
    uint64_t   iStartTime;
    uint64_t   iEndTime;

    // bind op
    PSTR       pszBindID; // could be either DN or UPN
    PSTR       pszOperationParameters;

    VDIR_SUPERLOG_RECORD_OPERATION_INFO opInfo;
} VDIR_SUPERLOG_RECORD, *PVDIR_SUPERLOG_RECORD;

typedef struct _VDIR_CONN_REPL_SUPP_STATE
{
// TODO remove this
    PLW_HASHMAP     phmSyncStateOneMap;
} VDIR_CONN_REPL_SUPP_STATE, *PVDIR_CONN_REPL_SUPP_STATE;

typedef struct _VDIR_CONNECTION_CTRL_RESOURCE
{
    BOOLEAN bOwnDbCopyCtrlFd; //this is added to fix the case where VDIR_CONNECTION is allocated without calling VmDirAllocateConnection
    int     dbCopyCtrlFd;
} VDIR_CONNECTION_CTRL_RESOURCE, *PVDIR_CONNECTION_CTRL_RESOURCE;

#define VDIR_IS_LOGIN_BLOCKED(pPPolicyState)    \
    (pPPolicyState->bLockedout || pPPolicyState->bPwdExpired)

typedef struct _VDIR_CONNECTION
{
    Sockbuf *               sb;
    ber_socket_t            sd;
    VDIR_ACCESS_INFO        AccessInfo;
    BOOLEAN                 bIsAnonymousBind;
    BOOLEAN                 bIsLdaps;
    BOOLEAN                 bInReplLock;
    PVDIR_SASL_BIND_INFO    pSaslInfo;
    char                    szServerIP[INET6_ADDRSTRLEN];
    DWORD                   dwServerPort;
    char                    szClientIP[INET6_ADDRSTRLEN];
    DWORD                   dwClientPort;
    VDIR_SUPERLOG_RECORD    SuperLogRec;
    VDIR_CONN_REPL_SUPP_STATE   ReplConnState;
    PVMDIR_THREAD_LOG_CONTEXT   pThrLogCtx;
    VDIR_CONNECTION_CTRL_RESOURCE ConnCtrlResource;
    VDIR_PPOLICY_STATE          PPolicyState;
} VDIR_CONNECTION, *PVDIR_CONNECTION;

typedef struct _VDIR_CONNECTION_CTX
{
  ber_socket_t sockFd;
  Sockbuf_IO   *pSockbuf_IO;
  BOOLEAN      bIsLdaps;
} VDIR_CONNECTION_CTX, *PVDIR_CONNECTION_CTX;

typedef struct _VDIR_SCHEMA_AT_DESC*    PVDIR_SCHEMA_AT_DESC;

typedef struct _VMDIR_ATTRIBUTE_METADATA
{
    USN     localUsn;
    UINT64  version;
    PSTR    pszOrigInvoId;
    PSTR    pszOrigTime;
    USN     origUsn;
} VMDIR_ATTRIBUTE_METADATA, *PVMDIR_ATTRIBUTE_METADATA;

typedef struct _VMDIR_REPL_ATTRIBUTE_METADATA
{
    PSTR                         pszAttrType;
    PVMDIR_ATTRIBUTE_METADATA    pMetaData;
} VMDIR_REPL_ATTRIBUTE_METADATA, *PVMDIR_REPL_ATTRIBUTE_METADATA;

typedef struct _VMDIR_ATTRIBUTE_VALUE_METADATA
{
    PSTR            pszAttrType;
    USN             localUsn;
    UINT64          version;
    PSTR            pszOrigInvoId;
    PSTR            pszValChgOrigInvoId;
    PSTR            pszValChgOrigTime;
    USN             valChgOrigUsn;
    DWORD           dwOpCode;
    DWORD           dwValSize;
    PSTR            pszValue;
} VMDIR_VALUE_ATTRIBUTE_METADATA, *PVMDIR_VALUE_ATTRIBUTE_METADATA;

typedef struct _VDIR_ATTRIBUTE
{
   PVDIR_SCHEMA_AT_DESC pATDesc;

   // type.bv_val always points to in-place storage and should not have bvnormval.
   VDIR_BERVALUE        type;

   // allocated space for array of bervals
   VDIR_BERVARRAY       vals;
   unsigned             numVals;

   PVMDIR_ATTRIBUTE_METADATA   pMetaData;

   /* A queue of attr-value-meta-data elements to add to the backend index database.
    * Each element contains a VDIR_BERVALUE variable, and its bv_val is in format:
    *     <local-usn>:<version-no>:<originating-server-id>:<value-change-originating-server-id>
    *       :<value-change-originating time>:<value-change-originating-usn>:<opcode>:<value-size>:<value>
    *     <value> is an octet string.
    */
   DEQUE  valueMetaDataToAdd;
   /* Hold obsolete attr-value-meta-data elements to be deleted.
    * The elements to be added to this queue when MOD_OP_REPLACE
    * or modify MOD_OP_DELETE with empty value on multi-value attribute.
    */
   DEQUE  valueMetaDataToDelete;

   struct _VDIR_ATTRIBUTE *  next;
} VDIR_ATTRIBUTE, *PVDIR_ATTRIBUTE;

typedef struct _ATTRIBUTE_META_DATA_NODE
{
    USHORT  attrID;
    PVMDIR_ATTRIBUTE_METADATA    pMetaData;
} ATTRIBUTE_META_DATA_NODE, *PATTRIBUTE_META_DATA_NODE;

#define VDIR_DEFAULT_FORCE_VERSION_GAP  512

/*
 * MOD_IGNORE_ALL
 *     Used internally, to skip processing a Delete mod when the attr
 *     does not exist in the entry
 * MOD_IGNORE_ATTR_VALUES
 *     Used internally, in the repl scenario to commit attrMetaData only and ignore
 *     attr value and attrValueMetaData update.
 *     1) Attr was added and deleted on the supplier side (only attrMetaData will remain)
 *     2) In the consumer side, attrMetaData has to be committed even though corresponding
 *        attr does not exist, to avoid data discrepancy.
 */
typedef enum _VDIR_MOD_IGNORE
{
    MOD_IGNORE_NONE = 0,
    MOD_IGNORE_ALL,
    MOD_IGNORE_ATTR_VALUES
} VDIR_MOD_IGNORE;

typedef struct _VDIR_MODIFICATION
{
    VDIR_LDAP_MOD_OP            operation;
    VDIR_ATTRIBUTE              attr;
    VDIR_MOD_IGNORE             modIgnoreType;
    unsigned short              usForceVersionGap;  // to intentionally create gap between attribute version
    struct _VDIR_MODIFICATION * next;
} VDIR_MODIFICATION, *PVDIR_MODIFICATION;

typedef enum _VDIR_ENTRY_ALLOCATION_TYPE
{
    ENTRY_STORAGE_FORMAT_PACK,
    ENTRY_STORAGE_FORMAT_NORMAL
} VDIR_ENTRY_ALLOCATION_TYPE;

typedef struct _VDIR_LDAP_DN
{
    // libldap data structure to handle DN parsing
    LDAPDN                       internalDN;
    VDIR_BERVALUE                dn;
    PCSTR                        pszParentNormDN;   // in place into dn.bvnorm_val; otherwise, NULL if no parent.
} VDIR_LDAP_DN, *PVDIR_LDAP_DN;

typedef struct _VDIR_ENTRY
{

   VDIR_ENTRY_ALLOCATION_TYPE   allocType;

   // Internally constructed Entry (non-persist entry) has eId == 0
   ENTRYID                      eId;     // type must match BDB's db_seq_t

   VDIR_LDAP_DN                 ldapDN; // will replace following dn later.
   // dn.bv_val is heap allocated; dn.bvnorm_bv follows BerValue rule
   VDIR_BERVALUE                dn;
   // pdn.bv_val is in-place into dn.bv_val.  pdn.bvnrom_val follows BerValue rule
   VDIR_BERVALUE                pdn;
   // pdnnew is set during rename operations if the entry is being re-parented
   VDIR_BERVALUE                newpdn;

   // FORMAT_PACK, savedAttrsPtr is array of Attribute from one heap allocate
   // FORMAT_NORMAL, attrs (and next...) are individually heap allocated
   PVDIR_ATTRIBUTE              attrs;
   PVDIR_ATTRIBUTE              savedAttrsPtr; // Used to free the allocated Attribute array. "attrs" could change from its
                                               // original value e.g. after a "delete attribute" modification.

   // computed (non-persist) attributes (such as memberof...)
   PVDIR_ATTRIBUTE              pComputedAttrs;

   // bvs only apply to FORMAT_PACK allocType
   VDIR_BERVALUE *              bvs; // Pointer to allocated BerValue structures.
   unsigned short               usNumBVs;

   // encodedEntry is used in PACK format (in-place for dn and bvs)
   // (though NORMAL entry could have this value as well e.g. modify op could reencode)
   unsigned char *              encodedEntry;

   // make sure entry does not out live its schema context
   // if we do not allow live schema update, then we can eliminate this and
   // schema instance lock and reference count overhead.
   PVDIR_SCHEMA_CTX             pSchemaCtx;

   // name of the structure object class (points into Entry.attrs.vals[x].bv_val)
   // its value is set after VmDirSchemaCheck call.
   PSTR                         pszStructureOC;

   // carries the SD information to support access check
   PVDIR_ACL_CTX                pAclCtx;

   // carries a GUID string used to construct entry's objectSid
   // The guid string is in the format of "00000000-0000-0001-8888-000000000000"
   // This is only given when creating root domain nodes (host instance
   // due to replication needs, metadata domain entries need fixed domainSid
   PSTR pszGuid;

   // we own parent entry if exists
   // we cache parent entry for various logic such as ACL, schema structure rule and  parentid index handling...etc.
   struct _VDIR_ENTRY*          pParentEntry;

   // Flag to indicate if the entry was sent back to client in the search result or not.
   BOOLEAN                      bSearchEntrySent;

} VDIR_ENTRY, *PVDIR_ENTRY;

typedef struct _VDIR_ENTRY_ARRAY
{
    PVDIR_ENTRY     pEntry;
    size_t          iSize;      // size of used array
    size_t          iArraySize; // capacity of array.
} VDIR_ENTRY_ARRAY, *PVDIR_ENTRY_ARRAY;

typedef struct AttrValAssertion
{
    PVDIR_SCHEMA_AT_DESC pATDesc;
    VDIR_BERVALUE        type;
    VDIR_BERVALUE        value;
} AttrValAssertion;

typedef struct _VDIR_CANDIDATES
{
    ENTRYID *  eIds;
    int        size;        // Current count of eIds in the list.
    int        max;         // Size of the allocated list.
    BOOLEAN    positive;    // +ve candidates list (TRUE) or -ve candidates list (FALSE).
    BOOLEAN    eIdsSorted;  // entryIds in eIds array are sorted or not
} VDIR_CANDIDATES, *PVDIR_CANDIDATES;

typedef enum _VDIR_FILTER_COMPUTE_RESULT
{
    FILTER_RES_NORMAL = 0,
    FILTER_RES_TRUE,
    FILTER_RES_FALSE,
    FILTER_RES_PENDING,
    FILTER_RES_UNDEFINED
} VDIR_FILTER_COMPUTE_RESULT;

typedef struct SubStringFilter
{
   PVDIR_SCHEMA_AT_DESC  pATDesc;
   VDIR_BERVALUE         type;
   VDIR_BERVALUE         initial;
   VDIR_BERVALUE *       any;
   int                   anySize;
   int                   anyMax;
   VDIR_BERVALUE         final;
} SubStringFilter;

/*
 * represents a search filter
 */

// Standard LDAP values for "choice" are present in ldap.h, and additional internal values are:
#define FILTER_ONE_LEVEL_SEARCH              0x00

typedef struct _VDIR_FILTER VDIR_FILTER, *PVDIR_FILTER;

typedef union FilterComponent
{
    VDIR_BERVALUE       present;    // Present filter just containing the attribute type
    AttrValAssertion    ava;        // simple value assertion
    SubStringFilter     subStrings; // Sub-string filter
    PVDIR_FILTER        complex;    // and, or, not
    VDIR_BERVALUE       parentDn;   // Parent DN, relevant when f_choice = LDAP_FILTER_ONE_LEVEL_SRCH
} FilterComponent;

struct _VDIR_FILTER
{
    ber_tag_t                   choice;
    FilterComponent             filtComp;
    struct _VDIR_FILTER *       next;
    VDIR_FILTER_COMPUTE_RESULT  computeResult;
    int                         iMaxIndexScan;  // limit scan to qualify for good filter. 0 means unlimited.
    BOOLEAN                     bAncestorGotPositiveCandidateSet;  // any of ancestor filters got a positive candidate set
    VDIR_CANDIDATES *           candidates;    // Entry IDs candidate list that matches this filter, maintained for internal Ber operation.
    BerElement *                pBer; // If this filter was built by the server, then 'ber' must be deallocated when the filter is deallocated and this will not be NULL. Otherwise the filter components are 'owned' by the operation / client connection.
    BOOLEAN                     bLastScanPositive;  // last index scan result in a complete set or not
};

typedef struct AddReq
{
    PVDIR_ENTRY     pEntry;
} AddReq;

typedef struct _BindReq
{
    ber_tag_t       method;
    VDIR_BERVALUE   bvMechanism;        // SASL bind mechanism
    VDIR_BERVALUE   cred;
} BindReq, VDIR_BIND_REQ, *PVDIR_BIND_REQ;

typedef struct DeleteReq
{
    VDIR_BERVALUE           dn;
    PVDIR_MODIFICATION      mods;
    unsigned                numMods;
} DeleteReq;

typedef struct ModifyReq
{
    VDIR_BERVALUE           dn;
    PVDIR_MODIFICATION      mods;
    unsigned                numMods;
    BOOLEAN                 bPasswordModify;
    VDIR_BERVALUE           newrdn;
    BOOLEAN                 bDeleteOldRdn;
    VDIR_BERVALUE           newSuperior;
    VDIR_BERVALUE           newdn;
} ModifyReq;

// metadata to evaluate iterator based search
// loaded from CFG_ITERATION_MAP_DN entry
#define VMDIR_SEARCH_MAP_CACHE_SIZE 5

typedef struct _VDIR_SEARCH_OPT_DATA
{
    PLW_HASHMAP     *ppSearchTypePriMap;
    PLW_HASHMAP     *ppAttrTypePriMap;
    int64_t         iCurrent;
    int64_t         iNext;
    BOOLEAN         bMapLoaded;
} VDIR_SEARCH_OPT_DATA, *PVDIR_SEARCH_OPT_DATA;

// MDB KEY BLOB first byte is FWD/REV flag, bypass it to get the key content.
#define VMDIR_FILTER_MDB_KEY_TO_STRING(bvMDB, bvStr)    \
    {                                                   \
        assert(bvMDB.lberbv_len > 1);                   \
        bvStr.lberbv_val = bvMDB.lberbv_val+1;          \
        bvStr.lberbv_len = bvMDB.lberbv_len-1;          \
    }

typedef struct _VDIR_ITERATOR_CONTEXT
{
    BOOLEAN         bInit;
    int             iSearchType;    // Iterator Search (filter) Type.
    BOOLEAN         bReverseSearch; // Reverse search flag - only DN substring is using reverse search now.
    PSTR            pszIterTable;   // The table iterates on.
    VDIR_BERVALUE   bvFilterValue;  // Filter value translated into appropriate MDB key format

    ENTRYID         eId;            // The current entry id the iterator retrieved
    VDIR_BERVALUE   bvCurrentKey;   // The current key (iterate) or
                                    //   the first position wanted (iteratorInit for very first and subsequent calls)

    PLW_HASHMAP     pSentIDMap;     // Used to track duplicated EID be sent to the client
    int             iIterCount;     // The counter for total iterations - used to terminate expensive iteration search
} VDIR_ITERATOR_CONTEXT, *PVDIR_ITERATOR_CONTEXT;

typedef struct _VDIR_ITERATOR_SEARCH_PLAN
{
    VDIR_BERVALUE   attr;           // the attribute type selected for iterator based search
    VDIR_BERVALUE   attrNormVal;    // the "normalized" value selected for iterator based search
    int             pri;            // used to calculate which attribute will be used for iterator.
    int             iterSearchType; // the search type used for the iterator search;
    BOOLEAN         bReverseSearch; // whether it is a reverse search in iterator search.
} VDIR_ITERATOR_SEARCH_PLAN, *PVDIR_ITERATOR_SEARCH_PLAN;

typedef struct SearchReq
{
    int             scope;
    int             derefAlias;
    int             sizeLimit;
    int             timeLimit;
    int             attrsOnly;
    VDIR_BERVALUE * attrs;
    VDIR_FILTER *   filter;
    VDIR_BERVALUE   filterStr;
    ACCESS_MASK     accessRequired;
    size_t          iNumEntrySent;      // total number entries sent for this request
    BOOLEAN         bStoreRsltInMem;    // store results in mem vs. writing to ber
    ENTRYID         baseEID;

    // data needed to determine execution path
    int             iBuildCandDepth;
    int             iOrFilterDepth;

    VDIR_SEARCH_EXEC_PATH       srvExecPath;        // server search execution details
    VDIR_ITERATOR_SEARCH_PLAN   iteratorSearchPlan; // iterator based plan details
} SearchReq;

typedef union _VDIR_LDAP_REQUEST
{
    AddReq     addReq;
    BindReq    bindReq;
    DeleteReq  deleteReq;
    ModifyReq  modifyReq;
    SearchReq  searchReq;
} VDIR_LDAP_REQUEST;

typedef enum _VDIR_REPLY_TYPE
{
    REP_SASL = 1
} VDIR_REPLY_TYPE;

typedef struct _VDIR_LDAP_REPLY {
    VDIR_REPLY_TYPE     type;

    union VDIR_LDAP_REPLY_UNION {
        VDIR_BERVALUE   bvSaslReply;
    } replyData;

} VDIR_LDAP_REPLY, *PVDIR_LDAP_REPLY;

typedef struct VDIR_LDAP_RESULT
{
    DWORD           vmdirErrCode;   // internal VMDIR_ERROR_XXX
    ber_int_t       errCode;        // ldap error code
    VDIR_BERVALUE   matchedDn;
    PSTR            pszErrMsg;      // owns this heap allocated error message
    VDIR_BERVALUE * referral;
    VDIR_LDAP_REPLY replyInfo;
} VDIR_LDAP_RESULT, *PVDIR_LDAP_RESULT;

typedef enum SyncRequestMode
{
    UNUSED              = LDAP_SYNC_NONE,
    REFRESH_ONLY        = LDAP_SYNC_REFRESH_ONLY,
    RESERVED            = LDAP_SYNC_RESERVED,
    REFRESH_AND_PERSIST = LDAP_SYNC_REFRESH_AND_PERSIST
} SyncRequestMode;

typedef struct UptoDateVectorEntry
{
    VDIR_BERVALUE           invocationId;
    USN                     reqLastOrigUsnProcessed;
    USN                     currMaxOrigUsnProcessed;
    LW_HASHTABLE_NODE       Node;
} UptoDateVectorEntry;

typedef struct SyncRequestControlValue
{
    SyncRequestMode         mode;
    VDIR_BERVALUE           reqInvocationId;
    VDIR_BERVALUE           bvLastLocalUsnProcessed;
    USN                     intLastLocalUsnProcessed;
    VDIR_BERVALUE           bvUtdVector;
    BOOLEAN                 bFirstPage;
} SyncRequestControlValue;

typedef struct SyncDoneControlValue
{
    USN                     intLastLocalUsnProcessed;
    PLW_HASHTABLE           htUtdVector;

    // supplier asks consumer to come back if
    // 1. there are out-standing uncommitted USN that needs further processing
    //   (done in result.c/VmDirSendSearchEntry)
    // 2. full page request sent and there could be more changes pending.
    BOOLEAN                 bContinue;
} SyncDoneControlValue;

typedef struct _VDIR_PAGED_RESULT_CONTROL_VALUE
{
    DWORD                   pageSize;
    CHAR                    cookie[VMDIR_PS_COOKIE_LEN];
} VDIR_PAGED_RESULT_CONTROL_VALUE;

typedef struct _VDIR_DIGEST_CONTROL_VALUE
{
    CHAR                    sha1Digest[SHA_DIGEST_LENGTH+1];
} VDIR_DIGEST_CONTROL_VALUE, *PVDIR_DIGEST_CONTROL_VALUE;

typedef struct _VDIR_RAFT_PING_CONTROL_VALUE
{
    PSTR                    pszFQDN;
    int                     term;
} VDIR_RAFT_PING_CONTROL_VALUE, *PVDIR_RAFT_PING_CONTROL_VALUE;

typedef struct _VDIR_RAFT_VOTE_CONTROL_VALUE
{
    PSTR                    pszCandidateId;
    int                     term;
} VDIR_RAFT_VOTE_CONTROL_VALUE, *PVDIR_RAFT_VOTE_CONTROL_VALUE;

typedef struct _VDIR_STATE_PING_CONTROL_VALUE
{
    PSTR                    pszFQDN;
    PSTR                    pszInvocationId;
    USN                     maxOrigUsn;
} VDIR_STATE_PING_CONTROL_VALUE, *PVDIR_STATE_PING_CONTROL_VALUE;

typedef union LdapControlValue
{
    SyncRequestControlValue             syncReqCtrlVal;
    SyncDoneControlValue                syncDoneCtrlVal;
    VDIR_PAGED_RESULT_CONTROL_VALUE     pagedResultCtrlVal;
    VDIR_DIGEST_CONTROL_VALUE           digestCtrlVal;
    VDIR_RAFT_PING_CONTROL_VALUE        raftPingCtrlVal;
    VDIR_RAFT_VOTE_CONTROL_VALUE        raftVoteCtrlVal;
    VDIR_STATE_PING_CONTROL_VALUE       statePingCtrlVal;
    VDIR_DB_COPY_CONTROL_VALUE          dbCopyCtrlVal;
} LdapControlValue;

typedef struct _VDIR_LDAP_CONTROL
{
    char *                type;
    BOOLEAN               criticality;
    LdapControlValue      value;
    struct _VDIR_LDAP_CONTROL *  next;
} VDIR_LDAP_CONTROL, *PVDIR_LDAP_CONTROL;

typedef enum
{
    VDIR_OPERATION_TYPE_EXTERNAL = 1,
    VDIR_OPERATION_TYPE_INTERNAL = 2,
    VDIR_OPERATION_TYPE_REPL = 4,
} VDIR_OPERATION_TYPE;

typedef enum
{
    VDIR_OPERATION_PROTOCOL_LDAP,
    VDIR_OPERATION_PROTOCOL_REST

} VDIR_OPERATION_PROTOCOL;

typedef struct _VDIR_OPERATION_ML_METRIC
{
    // Times will be collected in this following order
    uint64_t    iMLStartTime;
    uint64_t    iPrePluginsStartTime;
    uint64_t    iPrePluginsEndTime;
    uint64_t    iWriteQueueWaitStartTime;
    uint64_t    iWriteQueueWaitEndTime;
    uint64_t    iBETxnBeginStartTime;
    uint64_t    iBETxnBeginEndTime;
    uint64_t    iBETxnCommitStartTime;
    uint64_t    iBETxnCommitEndTime;
    uint64_t    iPostPluginsStartTime;
    uint64_t    iPostPluginsEndTime;
    uint64_t    iMLEndTime;

} VDIR_OPERATION_ML_METRIC, *PVDIR_OPERATION_ML_METRIC;

typedef struct _VMDIR_WRITE_QUEUE
{
    PVDIR_LINKED_LIST  pList;
} VMDIR_WRITE_QUEUE, *PVMDIR_WRITE_QUEUE;

typedef struct _VMDIR_WRITE_QUEUE_ELEMENT
{
    USN   usn;
    PVMDIR_COND pCond;
} VMDIR_WRITE_QUEUE_ELEMENT, *PVMDIR_WRITE_QUEUE_ELEMENT;

typedef struct _VDIR_OPERATION
{
    VDIR_OPERATION_TYPE       opType;
    VDIR_OPERATION_PROTOCOL   protocol;
    VDIR_OPERATION_ML_METRIC  MLMetrics;

    ///////////////////////////////////////////////////////////////////////////
    // fields valid only for EXTERNAL operation
    ///////////////////////////////////////////////////////////////////////////
    ber_int_t           protocolVer;    // version of the LDAP protocol used by client
    BerElement *        ber;         // ber of the request
    ber_int_t           msgId;       // msgid of the request
    PVDIR_CONNECTION    conn;        // Connection
    BOOLEAN             bOwnConn;    // true if own connection

    PVDIR_LDAP_CONTROL  reqControls; // Request Controls, sent by client.
    PVDIR_LDAP_CONTROL  syncReqCtrl; // Sync Request Control, points in reqControls list.
    PVDIR_LDAP_CONTROL  syncDoneCtrl; // Sync Done Control.
    PVDIR_LDAP_CONTROL  showDeletedObjectsCtrl; // points in reqControls list.
    PVDIR_LDAP_CONTROL  showMasterKeyCtrl;
    PVDIR_LDAP_CONTROL  showPagedResultsCtrl;
    PVDIR_LDAP_CONTROL  digestCtrl;
    PVDIR_LDAP_CONTROL  raftPingCtrl;
    PVDIR_LDAP_CONTROL  raftVoteCtrl;
    PVDIR_LDAP_CONTROL  statePingCtrl;
    PVDIR_LDAP_CONTROL  passblobCtrl;
    PVDIR_LDAP_CONTROL  dbCopyCtrl;
    PVDIR_LDAP_CONTROL  pReplAgrDisableCtrl;
    PVDIR_LDAP_CONTROL  pReplAgrEnableCtrl;
    PVDIR_LDAP_CONTROL  pSearchPlanCtrl;
    PVDIR_LDAP_CONTROL  pPPolicyCtrl;

    // SJ-TBD: If we add quite a few controls, we should consider defining a
    // structure to hold all those pointers.
    DWORD               dwSchemaWriteOp; // this operation is schema modification

    ///////////////////////////////////////////////////////////////////////////
    // fields valid for both INTERNAL and EXTERNAL operations
    ///////////////////////////////////////////////////////////////////////////
    VDIR_BERVALUE       reqDn;       // request's target DN (in-place storage)
    ber_tag_t           reqCode;     // LDAP_REQ_ADD/MODIFY/DELETE/SEARCH....
    VDIR_LDAP_REQUEST   request;     // LDAP request (parameters)
    VDIR_LDAP_RESULT    ldapResult;

    PVDIR_SCHEMA_CTX    pSchemaCtx;

#define pBEIF       pBECtx->pBE
#define pBEErrorMsg pBECtx->pszBEErrorMsg
    // backend context
    PVDIR_BACKEND_CTX   pBECtx;

    ///////////////////////////////////////////////////////////////////////////
    // fields valid for INTERNAL operations
    ///////////////////////////////////////////////////////////////////////////
    VDIR_ENTRY_ARRAY    internalSearchEntryArray; // internal search result
    PSTR                pszFilters; // filter candidates' size recorded in string
    DWORD               dwSentEntries; // number of entries sent back to client

    ///////////////////////////////////////////////////////////////////////////
    // fields valid for REPLICATION operations
    ///////////////////////////////////////////////////////////////////////////
    PCSTR               pszPartner;
    USN                 ulPartnerUSN; // in replication, the partner USN been processed.

    ///////////////////////////////////////////////////////////////////////////
    // fields valid for write operations
    ///////////////////////////////////////////////////////////////////////////
    PVMDIR_WRITE_QUEUE_ELEMENT   pWriteQueueEle;

} VDIR_OPERATION, *PVDIR_OPERATION;

typedef struct _VDIR_THREAD_INFO
{
    VMDIR_THREAD                tid;
    BOOLEAN                     bJoinThr;       // join by main thr

    // mutexUsed is real mutex used (i.e. it may not == mutex)
    PVMDIR_MUTEX mutex;
    PVMDIR_MUTEX mutexUsed;

    // conditionUsed is real condition used (i.e. it may not == condition)
    PVMDIR_COND               condition;
    PVMDIR_COND               conditionUsed;

    struct _VDIR_THREAD_INFO*   pNext;

} REPO_THREAD_INFO, *PVDIR_THREAD_INFO;

typedef struct _VMDIR_REPLICATION_METRICS
{
    /*
     * Note this struct will be accessed by multiple threads
     * concurrently so keep it concurrency-safe
     */
    PSTR                    pszSrcHostname;
    PSTR                    pszSrcSite;
    PSTR                    pszDstHostname;
    PSTR                    pszDstSite;
    PVM_METRICS_GAUGE       pTimeConverge;
    PVM_METRICS_GAUGE       pTimeOnehop;
    PVM_METRICS_HISTOGRAM   pTimeCycleSucceeded;
    PVM_METRICS_HISTOGRAM   pTimeCycleFailed;
    PVM_METRICS_HISTOGRAM   pUsnBehind;
    PVM_METRICS_GAUGE       pCountConnectionClosed;
    PVM_METRICS_GAUGE       pCountConflictPermanent;
    PVM_METRICS_COUNTER     pCountConflictResolved;
    PVM_METRICS_COUNTER*    pCountError;
    BOOLEAN                 bActive;

} VMDIR_REPLICATION_METRICS, *PVMDIR_REPLICATION_METRICS;

typedef enum _VMDIR_DC_CONNECTION_TYPE
{
    DC_CONNECTION_TYPE_BASIC,
    DC_CONNECTION_TYPE_REPL,
    DC_CONNECTION_TYPE_CLUSTER_STATE
} VMDIR_DC_CONNECTION_TYPE;

typedef enum _VMDIR_DC_CONNECTION_STATE
{
    DC_CONNECTION_STATE_NOT_CONNECTED,  // default not connected
    DC_CONNECTION_STATE_CONNECTING,     // set by owner to transfer ownership to background thread
    DC_CONNECTION_STATE_CONNECTED,      // set by background thread to transfer back ownership
    DC_CONNECTION_STATE_FAILED          // set by background thread to transfer back ownership
} VMDIR_DC_CONNECTION_STATE;

typedef struct _VMDIR_CONNECTION_CREDS
{
    BOOLEAN bUseDCAccountCreds;
    PSTR    pszUPN;
    PSTR    pszPassword;
    // old password if password change not yet converged in replication
    PSTR    pszOldPassword;
} VMDIR_CONNECTION_CREDS, *PVMDIR_CONNECTION_CREDS;

typedef struct _VMDIR_DC_CONNECTION
{
    VMDIR_DC_CONNECTION_TYPE    connType;
    VMDIR_DC_CONNECTION_STATE   connState;

    PSTR                        pszHostname;
    time_t                      iLastFailedTime;
    DWORD                       dwlastFailedError;
    DWORD                       dwConsecutiveFailAttempt;
    DWORD                       dwConnectTimeoutSec;
    LDAP*                       pLd;
    VMDIR_CONNECTION_CREDS      creds;
} VMDIR_DC_CONNECTION, *PVMDIR_DC_CONNECTION;

typedef struct _VMDIR_REPLICATION_AGREEMENT
{
    VDIR_BERVALUE               dn;
    char                        ldapURI[VMDIR_MAX_LDAP_URI_LEN];
    PSTR                        pszHostname;
    VDIR_BERVALUE               lastLocalUsnProcessed;
    BOOLEAN                     isDeleted;
    VMDIR_DC_CONNECTION         dcConn;
    BOOLEAN                     isDisabled;

    struct _VMDIR_REPLICATION_AGREEMENT *   next;

} VMDIR_REPLICATION_AGREEMENT, *PVMDIR_REPLICATION_AGREEMENT;

typedef struct _VMDIR_OPERATION_STATISTIC
{
    PVMDIR_MUTEX    pmutex;
    PCSTR           pszOPName;
    uint64_t        iTotalCount;
    uint64_t        iCount;
    uint64_t        iTimeInMilliSec;

} VMDIR_OPERATION_STATISTIC, *PVMDIR_OPERATION_STATISTIC;

extern VMDIR_FIRST_REPL_CYCLE_MODE   gFirstReplCycleMode;

//
// Wrapper for a relative security descriptor and some of its related info.
//
typedef struct _VMDIR_SECURITY_DESCRIPTOR
{
    PSECURITY_DESCRIPTOR_RELATIVE pSecDesc;
    ULONG ulSecDesc;
    SECURITY_INFORMATION SecInfo;
} VMDIR_SECURITY_DESCRIPTOR, *PVMDIR_SECURITY_DESCRIPTOR;

typedef struct _VMDIR_SERVER_OBJECT
{
    PSTR        pszFQDN;
    PSTR        pszDN;
    PSTR        pszSite;
    PSTR        pszInvocationId;
    DWORD       dwServerId;
} VMDIR_SERVER_OBJECT, *PVMDIR_SERVER_OBJECT;

typedef struct _VMDIR_COMPACT_KV_PAIR
{
    PVOID    pKeyAndValue;
    DWORD    dwKeySize;
    DWORD    dwValueSize;

} VMDIR_COMPACT_KV_PAIR, *PVMDIR_COMPACT_KV_PAIR;

//clusterstate/statecache.c
DWORD
VmDirClusterCacheCloneSrvObj(
    PVDIR_LINKED_LIST*  ppSrvObjList
    );

VOID
VmDirFreeSrvObjLinkedList(
    PVDIR_LINKED_LIST   pSrvObjList
    );

VOID
VmDirFreeServerObjectContent(
    PVMDIR_SERVER_OBJECT    pSrvObj
    );

VOID
VmDirFreeServerObject(
    PVMDIR_SERVER_OBJECT    pSrvObj
    );

DWORD
VmDirCloneServerObject(
    PVMDIR_SERVER_OBJECT    pSrvObj,
    PVMDIR_SERVER_OBJECT*   ppOutSrvObj
    );

// common/dcconnthr.c

VOID
VmDirFreeConnCredContent(
    PVMDIR_CONNECTION_CREDS pCreds
    );

VOID
VmDirFreeDCConnContent(
    PVMDIR_DC_CONNECTION pDCConn
    );

DWORD
VmDirInitDCConnThread(
    PVMDIR_DC_CONNECTION pDCConn
    );

// schema/dn.c
DWORD
VmDirDNStrToInternalDN(
    PVDIR_LDAP_DN   pLdapDN
    );

DWORD
VmDirNormDN(
    PVDIR_LDAP_DN       pLdapDN,
    PVDIR_SCHEMA_CTX    pSchemaCtx
    );

DWORD
VmDirParentNormDN(
    PVDIR_LDAP_DN   pLdapDN
    );

VOID
VmDirFreeLDAPDNContent(
    PVDIR_LDAP_DN   pLdapDN
    );

VOID
VmDirFreeLDAPDN(
    PVDIR_LDAP_DN   pLdapDN
    );

// vmdir/init.c

DWORD
VmDirInitBackend(
    VOID
    );

DWORD
VmDirSetSdGlobals(
    VOID
    );

// vmdirentry.c

/*
 * allocate structure resources (but not content) of an entry
 * used in SEARCH_REPLY type entry
 */
DWORD
VmDirInitializeEntry(
   PVDIR_ENTRY pEntry,
   VDIR_ENTRY_ALLOCATION_TYPE   allocType,
   int                          nAttrs,
   int                          nVals);

/*
 * Convert entry allocType from ENTRY_FROM_DB to ENTRY_FROM_WIRE
 */
DWORD
VmDirEntryUnpack(
    PVDIR_ENTRY  pEntry
    );

DWORD
VmDirEntryAttributeAppendBervArray(
    PVDIR_ATTRIBUTE    pAttr,
    PVDIR_BERVALUE     pBervs,
    USHORT             usBervSize
    );

DWORD
VmDirEntryAttributeRemoveValue(
    PVDIR_ATTRIBUTE    pAttr,
    PCSTR              pszValue
    );

/*
 * release contents of an entry (but not entry itself, e.g. stack entry)
 */
void
VmDirFreeEntryContent(
    PVDIR_ENTRY pEntry
    );

/*
 * free heap allocated entry (used in but not all ADD_REQUEST type entry)
 */
void
VmDirFreeEntry(
    PVDIR_ENTRY pEntry
    );

void
VmDirFreeEntryArrayContent(
    PVDIR_ENTRY_ARRAY   pArray
    );

void
VmDirFreeEntryArray(
    PVDIR_ENTRY_ARRAY   pEntryAry
    );

/*
 * if success, pEntry takes ownership of pAttr.
 */
DWORD
VmDirEntryAddAttribute(
    PVDIR_ENTRY        pEntry,
    PVDIR_ATTRIBUTE    pAttr
    );

/*
 * Add an array of bervalue attribute values into an entry.
 */
DWORD
VmDirEntryAddBervArrayAttribute(
    PVDIR_ENTRY     pEntry,
    PCSTR           pszAttrName,
    VDIR_BERVARRAY  attrVals,
    USHORT          usNumVals
    );

/*
 * add a single "string" type value attribute to entry.
 */
DWORD
VmDirEntryAddSingleValueStrAttribute(
    PVDIR_ENTRY pEntry,
    PCSTR pszAttrName,
    PCSTR pszAttrValue
    );

/*
 * add a single value attribute to entry.
 */
DWORD
VmDirEntryAddSingleValueAttribute(
    PVDIR_ENTRY pEntry,
    PCSTR pszAttrName,
    PCSTR pszAttrValue,
    size_t iAttrValueLen
    );

/*
 * remove an attribute of an entry.
 */
DWORD
VmDirEntryRemoveAttribute(
    PVDIR_ENTRY     pEntry,
    PCSTR           pszName
    );

/*
 * find attribute(pszName) in pEntry
 */
PVDIR_ATTRIBUTE
VmDirEntryFindAttribute(
    PSTR pszName,
    PVDIR_ENTRY pEntry
    );

DWORD
VmDirAttributeInitialize(
    PSTR    pszName,
    USHORT  usBerSize,
    PVDIR_SCHEMA_CTX pCtx,
    PVDIR_ATTRIBUTE pAttr
    );

VOID
VmDirFreeAttribute(
    PVDIR_ATTRIBUTE pAttr
    );

DWORD
VmDirAttributeAllocate(
    PCSTR               pszName,
    USHORT              usBerSize,
    PVDIR_SCHEMA_CTX    pCtx,
    PVDIR_ATTRIBUTE*    ppOutAttr
    );


DWORD
VmDirAttributeDup(
    PVDIR_ATTRIBUTE  pAttr,
    PVDIR_ATTRIBUTE* ppDupAttr
    );

DWORD
VmDirStringToBervalContent(
    PCSTR              pszBerval,
    PVDIR_BERVALUE     pDupBerval
    );

VOID
VmDirFreeBervalArrayContent(
    PVDIR_BERVALUE pBervs,
    USHORT  usSize
    );

BOOLEAN
VmDirIsInternalEntry(
    PVDIR_ENTRY pEntry
    );

BOOLEAN
VmDirEntryIsObjectclass(
    PVDIR_ENTRY     pEntry,
    PCSTR           pszOCName
    );

DWORD
VmDirEntryIsAttrAllowed(
    PVDIR_ENTRY pEntry,
    PSTR        pszAttrName,
    PBOOLEAN    pbMust,
    PBOOLEAN    pbMay
    );

/*
 * free a heap allocated bervalue, bervalue.bv_val and bervalue.bvnorm_val
 */
VOID
VmDirFreeBerval(
    VDIR_BERVALUE* pBerv
    );

/*
 * free bervalue.bvnorm_val and bervalue.bv_val
 */
VOID
VmDirFreeBervalContent(
    VDIR_BERVALUE *pBerv);

DWORD
VmDirBervalContentDup(
    PVDIR_BERVALUE     pBerval,
    PVDIR_BERVALUE     pDupBerval
    );

DWORD
VmDirCreateTransientSecurityDescriptor(
    BOOLEAN                     bAllowAnonymousRead,
    PVMDIR_SECURITY_DESCRIPTOR  pvsd
    );

DWORD
VmDirAttrListToNewEntry(
    PVDIR_SCHEMA_CTX    pSchemaCtx,
    PSTR                pszDN,
    PSTR*               ppszAttrList,
    BOOLEAN             bAllowAnonymousRead,
    PVDIR_ENTRY*        ppEntry
    );

PVDIR_ATTRIBUTE
VmDirFindAttrByName(
    PVDIR_ENTRY      pEntry,
    PSTR        pszName
    );

DWORD
VmDirEntryReplaceAttribute(
    PVDIR_ENTRY     pEntry,
    PVDIR_ATTRIBUTE pNewAttr
    );

DWORD
VmDirDeleteEntryViaDN(
    PCSTR   pszDN
    );

DWORD
VmDirDeleteEntry(
    PVDIR_ENTRY pEntry
    );

DWORD
VmDirSimpleEntryDeleteAttribute(
    PCSTR   pszDN,
    PCSTR   pszAttr
    );

// util.c
VOID
VmDirAssertServerGlobals(
    VOID
    );

BOOLEAN
VmDirIsDeletedContainer(
    PCSTR   pszDN
    );

DWORD
VmDirInternalGetDSERootServerCN(
    PSTR*   ppServerCN
    );

DWORD
VmDirInternalSearchSeverObj(
    PCSTR               pszServerObjName,
    PVDIR_OPERATION     pSearchOp
    );

BOOLEAN
VmDirIsTombStoneObject(
    PCSTR   pszDN
    );

DWORD
VmDirToLDAPError(
    DWORD   dwVmDirError
    );

void const *
UtdVectorEntryGetKey(
    PLW_HASHTABLE_NODE     pNode,
    PVOID                  pUnused
    );

int
VmDirQsortPPCHARCmp(
    const void*		ppStr1,
    const void*		ppStr2
    );

int
VmDirQsortPEIDCmp(
    const void*     pEID1,
    const void*     pEID2
    );

void
VmDirCurrentGeneralizedTime(
    PSTR    pszTimeBuf,
    int     iBufSize
    );

void
VmDirCurrentGeneralizedTimeWithOffset(
    PSTR    pszTimeBuf,
    int     iBufSize,
    DWORD   dwOffset
    );

VOID
VmDirForceExit(
    VOID
    );

DWORD
VmDirUuidFromString(
    PCSTR pStr,
    uuid_t* pGuid
);

DWORD
VmDirFQDNToDNSize(
    PCSTR pszFQDN,
    UINT32 *sizeOfDN
);

DWORD
VmDirFQDNToDN(
    PCSTR pszFQDN,
    PSTR* ppszDN
);

VOID
VmDirLogStackFrame(
    int     logLevel
    );

DWORD
VmDirSrvCreateDN(
    PCSTR pszContainerName,
    PCSTR pszDomainDN,
    PSTR* ppszContainerDN
    );

DWORD
VmDirSrvCreateReplAgrsContainer(
    PVDIR_SCHEMA_CTX pSchemaCtx);

DWORD
VmDirKrbInit(
    VOID
    );

DWORD
VmDirSrvCreateContainerWithEID(
    PVDIR_SCHEMA_CTX pSchemaCtx,
    PCSTR            pszContainerDN,
    PCSTR            pszContainerName,
    PVMDIR_SECURITY_DESCRIPTOR pSecDesc,
    ENTRYID          eID);

DWORD
VmDirSrvCreateContainer(
    PVDIR_SCHEMA_CTX pSchemaCtx,
    PCSTR            pszContainerDN,
    PCSTR            pszContainerName);

DWORD
VmDirSrvCreateDomain(
    PVDIR_SCHEMA_CTX pSchemaCtx,
    BOOLEAN          bSetupHost,
    PCSTR            pszDomainDN
    );

DWORD
VmDirFindMemberOfAttribute(
    PVDIR_ENTRY pEntry,
    PVDIR_ATTRIBUTE* ppMemberOfAttr
    );

DWORD
VmDirBuildMemberOfAttribute(
    PVDIR_OPERATION     pOperation,
    PVDIR_ENTRY         pEntry,
    PVDIR_ATTRIBUTE*    ppComputedAttr
    );

DWORD
VmDirSASLGSSBind(
     LDAP*  pLD
     );

DWORD
VmDirUPNToDN(
    PCSTR           pszUPN,
    PSTR*           ppszEntryDN
    );

DWORD
VmDirTenantizeUPNToDN(
    PCSTR       pszTenant,
    PCSTR       pszUPN,
    PSTR*       ppszEntryDN
    );

DWORD
VmDirUPNToDNBerWrap(
    PCSTR           pszUPN,
    PVDIR_BERVALUE  pBervDN
    );

DWORD
VmDirIsAncestorDN(
    PVDIR_BERVALUE  pBervAncestorDN,
    PVDIR_BERVALUE  pBervTargetDN,
    PBOOLEAN        pbResult
    );

DWORD
VmDirHasSingleAttrValue(
    PVDIR_ATTRIBUTE pAttr
    );

DWORD
VmDirValidatePrincipalName(
    PVDIR_ATTRIBUTE pAttr,
    PSTR*           ppErrMsg
    );

DWORD
VmDirSrvGetDomainFunctionalLevel(
    PDWORD pdwLevel
    );

DWORD
VmDirInitSrvDFLGlobal(
    VOID
    );

PCSTR
VmDirLdapModOpTypeToName(
    VDIR_LDAP_MOD_OP modOp
    );

PCSTR
VmDirLdapReqCodeToName(
    ber_tag_t reqCode
    );

PCSTR
VmDirOperationTypeToName(
    VDIR_OPERATION_TYPE opType
    );

PCSTR
VmDirMdbStateToName(
    MDB_state_op opType
    );

BOOLEAN
VmDirIsSameConsumerSupplierEntryAttr(
    PVDIR_ATTRIBUTE pAttr,
    PVDIR_ENTRY     pSrcEntry,
    PVDIR_ENTRY     pDstEntry
    );

int
VmDirPVdirBValCmp(
    const void *p1,
    const void *p2
    );

DWORD
VmDirCopySingleAttributeString(
    PVDIR_ENTRY  pEntry,
    PCSTR        pszAttribute,
    BOOL         bOptional,
    PSTR*        ppszOut
    );

DWORD
VmDirDNCopySingleAttributeString(
    PCSTR   pszDN,
    PCSTR   pszAttr,
    PSTR    *ppszAttrVal
    );

DWORD
VmDirAllocateBerValueAVsnprintf(
    PVDIR_BERVALUE pbvValue,
    PCSTR pszFormat,
    ...
    );

DWORD
VmDirFillMDBIteratorDataContent(
    PVOID    pKey,
    DWORD    dwKeySize,
    PVOID    pValue,
    DWORD    dwValueSize,
    PVMDIR_COMPACT_KV_PAIR    pMDBIteratorData
    );

VOID
VmDirFreeMDBIteratorDataContents(
    PVMDIR_COMPACT_KV_PAIR    pMDBIteratorData
    );

VOID
VmDirResetPPolicyState(
    PVDIR_PPOLICY_STATE pPPolicyState
    );

//accnt_mgmt.c
DWORD
VmDirSrvGetConnectionObj(
    PCSTR  pszUPN,
    PVDIR_CONNECTION* ppConnection
    );

DWORD
VmDirSrvCreateComputerOUContainer(
    PVDIR_CONNECTION pConnection,
    PCSTR pszDomainName,
    PCSTR pszOUContainer
    );

DWORD
VmDirSrvSetupComputerAccount(
    PVDIR_CONNECTION pConnection,
    PCSTR pszDomainName,
    PCSTR pszComputerOU,
    PCSTR pszMachineAccountName,
    PVMDIR_MACHINE_INFO_A* ppMachineInfo
    );

DWORD
VmDirSrvSetupServiceAccount(
    PVDIR_CONNECTION pConnection,
    PCSTR            pszDomainName,
    PCSTR            pszServiceName,
    PCSTR            pszDCHostName         // Self host name
    );

DWORD
VmDirSrvGetKeyTabInfoClient(
    PVDIR_CONNECTION pConnection,
    PCSTR            pszDomainName,
    PCSTR            pszHostName,
    PVMDIR_KRB_INFO* ppKrbInfo
    );

DWORD
VmDirSrvGetComputerAccountInfo(
    PVDIR_CONNECTION pConnection,
    PCSTR            pszDomainName,
    PCSTR            pszComputerHostName,
    PSTR*            ppszComputerDN,
    PSTR*            ppszMachineGUID,
    PSTR*            ppszSiteName
    );

DWORD
VmDirSrvAllocateRpcKrbInfo(
    PVMDIR_KRB_INFO  pKrbInfoIn,
    PVMDIR_KRB_INFO* ppRpcKrbInfo
    );

DWORD
VmDirSrvAllocateRpcMachineInfoAFromW(
    PVMDIR_MACHINE_INFO_W pMachineInfo,
    PVMDIR_MACHINE_INFO_A *ppRpcMachineInfo
    );

DWORD
VmDirSrvAllocateRpcMachineInfoWFromA(
    PVMDIR_MACHINE_INFO_A pMachineInfo,
    PVMDIR_MACHINE_INFO_W *ppRpcMachineInfo
    );

// candidates.c
void
AndFilterResults(
    VDIR_FILTER * src,
    VDIR_FILTER * dst);

void
DeleteCandidates(
    PVDIR_CANDIDATES* ppCans);

DWORD
VmDirAddToCandidates(
    PVDIR_CANDIDATES    pCands,
    ENTRYID             eId
    );

PVDIR_CANDIDATES
NewCandidates(
    int      startAllocSize,
    BOOLEAN  positive);

void
NotFilterResults(
    VDIR_FILTER * src,
    VDIR_FILTER * dst);

void
OrFilterResults(
    VDIR_FILTER * src,
    VDIR_FILTER * dst);

VOID
VmDirSortCandidateList(
    VDIR_CANDIDATES *  pCl
    );

// entryencodedecode.c
DWORD
VmDirComputeEncodedEntrySize(
    PVDIR_ENTRY     pEntry,
    int *           nAttrs,
    int *           nVals,
    ber_len_t*      pEncodedEntrySize);

DWORD
VmDirEncodeEntry(
    PVDIR_ENTRY              pEntry,
    VDIR_BERVALUE*           pEncodedBerval,
    BOOLEAN                  bValidateEntry);

unsigned short
VmDirDecodeShort(
    unsigned char ** ppbuf);

void
VmDirEncodeShort(
    unsigned char ** ppbuf,
    ber_len_t        len);

DWORD
VmDirDecodeEntry(
   PVDIR_SCHEMA_CTX     pSchemaCtx,
   PVDIR_ENTRY          pEntry,
   PVDIR_BERVALUE       pbvDn);

int
VmDirGenOriginatingTimeStr(
    char * timeStr);

// oprequestutil.c

void
VmDirModificationFree(
    PVDIR_MODIFICATION pMod
    );

DWORD
VmDirOperationAddModReq(
    PVDIR_OPERATION   pOperation,
    int               modOp,
    char *            pszAttrName,
    PVDIR_BERVALUE    pBerValue,
    size_t            iBerValueSize
    );

DWORD
VmDirAppendAMod(
    PVDIR_OPERATION   pOperation,
    int          modOp,
    const char*  attrName,
    int          attrNameLen,
    const char*  attrVal,
    size_t       attrValLen
    );

DWORD
VmDirSimpleEntryCreate(
    PVDIR_SCHEMA_CTX    pSchemaCtx,
    PSTR*               ppszEntryInitializer,
    PSTR                pszDN,
    ENTRYID             ulEntryId
    );

DWORD
VmDirSimpleEntryCreateWithGuid(
    PVDIR_SCHEMA_CTX    pSchemaCtx,
    PSTR*               ppszEntryInitializer,
    PSTR                pszDN,
    ENTRYID             ulEntryId,
    PSTR                pszGuid
    );

DWORD
VmDirModAddSingleValueAttribute(
    PVDIR_MODIFICATION      pMod,
    PVDIR_SCHEMA_CTX        pSchemaCtx,
    PCSTR                   pszAttrName,
    PCSTR                   pszAttrValue,
    size_t                  iAttrValueLen
    );

DWORD
VmDirModAddSingleStrValueAttribute(
    PVDIR_MODIFICATION      pMod,
    PVDIR_SCHEMA_CTX        pSchemaCtx,
    PCSTR                   pszAttrName,
    PCSTR                   pszAttrValue
    );

DWORD
VmDirInternalEntryAttributeReplace(
    PVDIR_SCHEMA_CTX    pSchemaCtx,
    PCSTR               pszNormDN,
    PCSTR               pszAttrName,
    PVDIR_BERVALUE      pBerv
    );

DWORD
VmDirInternalEntryAttributeAdd(
    PVDIR_SCHEMA_CTX    pSchemaCtx,
    PCSTR               pszNormDN,
    PCSTR               pszAttrName,
    PVDIR_BERVALUE      pBervAttrValue
    );

DWORD
VmDirInternalAddMemberToGroup(
    PCSTR   pszGroupDN,
    PCSTR   pszMemberDN
    );

// ldap-head/operation.c
DWORD
VmDirInitStackOperation(
    PVDIR_OPERATION         pOp,
    VDIR_OPERATION_TYPE     opType,
    ber_tag_t               requestCode,
    PVDIR_SCHEMA_CTX        pSchemaCtx
    );

void
VmDirFreeOperationContent(
    PVDIR_OPERATION     pOp
    );

// middle-layer search.c
DWORD
VmDirSimpleEqualFilterInternalSearch(
    PCSTR               pszBaseDN,
    int                 searchScope,
    PCSTR               pszAttrName,
    PCSTR               pszAttrValue,
    PVDIR_ENTRY_ARRAY   pEntryArray
    );

DWORD
VmDirFilterInternalSearch(
        PCSTR               pszBaseDN,
        int                 searchScope,
        PCSTR               pszFilter,
        unsigned long       ulPageSize,
        PSTR                *ppszPageCookie,
        PVDIR_ENTRY_ARRAY   pEntryArray
    );

// middle-layer result.c
int
VmDirSendSearchEntry(
   PVDIR_OPERATION     pOperation,
   PVDIR_ENTRY         pSrEntry
   );

// middle-layer password.c
DWORD
VdirPasswordCheck(
    PVDIR_BERVALUE      pClearTextPassword,
    PVDIR_ENTRY         pEntry
    );

// middle-layer usn.c
DWORD
VmDirEntryUpdateUsnChanged(
    PVDIR_ENTRY    pEntry,
    USN            localUSN
    );

DWORD
VmDirEntryUpdateUsnCreated(
    PVDIR_ENTRY    pEntry,
    USN            localUSN
    );

DWORD
VmDirAttributeUpdateUsnValue(
    PVDIR_ATTRIBUTE    pAttr,
    USN                localUSN
    );

// iterContext.c
DWORD
VmDirIterSearchPlanInitContent(
    int     iSearchType,
    BOOLEAN bReverse,
    PSTR    pszAttrName,
    PSTR    pszAttrVal,
    PVDIR_ITERATOR_SEARCH_PLAN  pIterSearchPlan
    );

VOID
VmDirIterSearchPlanFreeContent(
    PVDIR_ITERATOR_SEARCH_PLAN  pIterSearchPlan
    );

DWORD
VmDirIterContextInitContent(
    PVDIR_ITERATOR_CONTEXT      pIteratorContext,
    PVDIR_ITERATOR_SEARCH_PLAN  pIteratorSearchPlan
    );

VOID
VmDirIterContextFreeContent(
    PVDIR_ITERATOR_CONTEXT pContext
    );

// security-sd.c
DWORD
VmDirSetGroupSecurityDescriptor(
    PSECURITY_DESCRIPTOR_ABSOLUTE SecurityDescriptor,
    PSID Group,
    BOOLEAN IsGroupDefaulted
    );

ULONG
VmDirLengthSid(
    PSID Sid
    );

DWORD
VmDirCreateAcl(
    PACL Acl,
    ULONG AclLength,
    ULONG AclRevision
    );

DWORD
VmDirGetAce(
    PACL pAcl,
    ULONG dwIndex,
    PACE_HEADER *ppAce
    );

DWORD
VmDirAddAccessAllowedAceEx(
    PACL Acl,
    ULONG AceRevision,
    ULONG AceFlags,
    ACCESS_MASK AccessMask,
    PSID Sid
    );

DWORD
VmDirAddAccessDeniedAceEx(
    PACL Acl,
    ULONG AceRevision,
    ULONG AceFlags,
    ACCESS_MASK AccessMask,
    PSID Sid
    );

DWORD
VmDirSetDaclSecurityDescriptor(
    PSECURITY_DESCRIPTOR_ABSOLUTE SecurityDescriptor,
    BOOLEAN IsDaclPresent,
    PACL Dacl,
    BOOLEAN IsDaclDefaulted
    );

BOOLEAN
VmDirValidSecurityDescriptor(
    PSECURITY_DESCRIPTOR_ABSOLUTE SecurityDescriptor
    );

DWORD
VmDirAbsoluteToSelfRelativeSD(
    PSECURITY_DESCRIPTOR_ABSOLUTE AbsoluteSecurityDescriptor,
    PSECURITY_DESCRIPTOR_RELATIVE SelfRelativeSecurityDescriptor,
    PULONG BufferLength
    );

DWORD
VmDirQuerySecurityDescriptorInfo(
    SECURITY_INFORMATION SecurityInformationNeeded,
    PSECURITY_DESCRIPTOR_RELATIVE SecurityDescriptorInput,
    PSECURITY_DESCRIPTOR_RELATIVE SecurityDescriptorOutput,
    PULONG Length
    );

DWORD
VmDirSelfRelativeToAbsoluteSD(
    PSECURITY_DESCRIPTOR_RELATIVE SelfRelativeSecurityDescriptor,
    PSECURITY_DESCRIPTOR_ABSOLUTE AbsoluteSecurityDescriptor,
    PULONG AbsoluteSecurityDescriptorSize,
    PACL pDacl,
    PULONG pDaclSize,
    PACL pSacl,
    PULONG pSaclSize,
    PSID Owner,
    PULONG pOwnerSize,
    PSID PrimaryGroup,
    PULONG pPrimaryGroupSize
    );

BOOLEAN
VmDirAccessCheck(
    PSECURITY_DESCRIPTOR_ABSOLUTE SecurityDescriptor,
    PACCESS_TOKEN AccessToken,
    ACCESS_MASK DesiredAccess,
    ACCESS_MASK PreviouslyGrantedAccess,
    PGENERIC_MAPPING GenericMapping,
    PACCESS_MASK GrantedAccess,
    PDWORD pAccessError
    );

DWORD
VmDirGetOwnerSecurityDescriptor(
    PSECURITY_DESCRIPTOR_ABSOLUTE SecurityDescriptor,
    PSID* Owner,
    PBOOLEAN pIsOwnerDefaulted
    );

DWORD
VmDirGetGroupSecurityDescriptor(
    PSECURITY_DESCRIPTOR_ABSOLUTE SecurityDescriptor,
    PSID* Group,
    PBOOLEAN pIsGroupDefaulted
    );

DWORD
VmDirGetDaclSecurityDescriptor(
    PSECURITY_DESCRIPTOR_ABSOLUTE SecurityDescriptor,
    PBOOLEAN pIsDaclPresent,
    PACL* Dacl,
    PBOOLEAN pIsDaclDefaulted
    );

DWORD
VmDirGetSaclSecurityDescriptor(
    PSECURITY_DESCRIPTOR_ABSOLUTE SecurityDescriptor,
    PBOOLEAN pIsSaclPresent,
    PACL* Sacl,
    PBOOLEAN pIsSaclDefaulted
    );

BOOLEAN
VmDirValidRelativeSecurityDescriptor(
    PSECURITY_DESCRIPTOR_RELATIVE SecurityDescriptor,
    ULONG SecurityDescriptorLength,
    SECURITY_INFORMATION RequiredInformation
    );

DWORD
VmDirSetSecurityDescriptorInfo(
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR_RELATIVE InputSecurityDescriptor,
    PSECURITY_DESCRIPTOR_RELATIVE ObjectSecurityDescriptor,
    PSECURITY_DESCRIPTOR_RELATIVE NewObjectSecurityDescriptor,
    PULONG NewObjectSecurityDescripptorLength,
    PGENERIC_MAPPING GenericMapping
    );

DWORD
VmDirCreateSecurityDescriptorAbsolute(
    PSECURITY_DESCRIPTOR_ABSOLUTE *ppSecurityDescriptor
    );

VOID
VmDirReleaseAccessToken(
    PACCESS_TOKEN* AccessToken
    );

DWORD
VmDirSetOwnerSecurityDescriptor(
    PSECURITY_DESCRIPTOR_ABSOLUTE SecurityDescriptor,
    PSID Owner,
    BOOLEAN IsOwnerDefaulted
    );

DWORD
VmDirCreateWellKnownSid(
    WELL_KNOWN_SID_TYPE wellKnownSidType,
    PSID pDomainSid,
    PSID pSid,
    DWORD* pcbSid
);

VOID
VmDirMapGenericMask(
    PDWORD pdwAccessMask,
    PGENERIC_MAPPING pGenericMapping
);

DWORD
VmDirQueryAccessTokenInformation(
    HANDLE hTokenHandle,
    TOKEN_INFORMATION_CLASS tokenInformationClass,
    PVOID pTokenInformation,
    DWORD dwTokenInformationLength,
    PDWORD pdwReturnLength
);

DWORD
VmDirAllocateSddlCStringFromSecurityDescriptor(
    PSECURITY_DESCRIPTOR_RELATIVE pSecurityDescriptor,
    DWORD dwRequestedStringSDRevision,
    SECURITY_INFORMATION securityInformation,
    PSTR* ppStringSecurityDescriptor
);

DWORD
VmDirSetSecurityDescriptorControl(
    PSECURITY_DESCRIPTOR_ABSOLUTE pSecurityDescriptor,
    SECURITY_DESCRIPTOR_CONTROL BitsToChange,
    SECURITY_DESCRIPTOR_CONTROL BitsToSet
    );

// srp.c
DWORD
VmDirSRPCreateSecret(
    PVDIR_BERVALUE   pUPN,
    PVDIR_BERVALUE   pClearTextPasswd,
    PVDIR_BERVALUE   pSecretResult
    );

// vmafdlib.c
DWORD
VmDirOpenVmAfdClientLib(
    VMDIR_LIB_HANDLE*   pplibHandle
    );

DWORD
VmDirKeySetGetKvno(
    PBYTE pUpnKeys,
    DWORD upnKeysLen,
    DWORD *kvno
    );

DWORD
VmDirGetKeyTabRecBlob(
    PSTR      pszUpnName,
    PBYTE*    ppBlob,
    DWORD*    pdwBlobLen
);

// background.c
DWORD
VmDirBkgdThreadInitialize(
    VOID
    );

VOID
VmDirBkgdThreadShutdown(
    VOID
    );

DWORD
VmDirBkgdTaskUpdatePrevTime(
    PVMDIR_BKGD_TASK_CTX    pTaskCtx
    );

// oidctovmdirerror.c
DWORD
VmDirOidcToVmdirError(
    DWORD dwOidcError
    );

// nodeidentity.c
DWORD
VmDirSrvCreateServerObj(
    PVDIR_SCHEMA_CTX pSchemaCtx
    );

DWORD
VmDirSetGlobalServerId(
    VOID
    );

//vectorutils.c
typedef DWORD (*PFN_VEC_PAIR_TO_STR) (LW_HASHMAP_PAIR, BOOLEAN, PSTR*);

DWORD
VmDirVectorToStr(
    PLW_HASHMAP          pMap,
    PFN_VEC_PAIR_TO_STR  pPairToStr,
    PSTR*                ppOutStr
    );

typedef DWORD (*PFN_VEC_STR_TO_PAIR) (PSTR, PSTR, LW_HASHMAP_PAIR*);

DWORD
VmDirStrtoVector(
    PCSTR               pszVector,
    PFN_VEC_STR_TO_PAIR pStrToPair,
    PLW_HASHMAP         pMap
    );

//externaloputil.c
DWORD
VmDirExternalEntryAttributeReplace(
    PVDIR_CONNECTION    pConn,
    PCSTR               pszEntryDn,
    PCSTR               pszAttrName,
    PVDIR_BERVALUE      pBervAttrValue
    );

//metadata.c
DWORD
VmDirMetaDataDeserialize(
    PCSTR                        pszMetadata,
    PVMDIR_ATTRIBUTE_METADATA*   ppMetadata
    );

DWORD
VmDirMetaDataSerialize(
    PVMDIR_ATTRIBUTE_METADATA    pMetadata,
    PSTR                         pszMetadata
    );

DWORD
VmDirAttributeMetaDataToList(
    PVDIR_ATTRIBUTE       pAttrAttrMetaData,
    PVDIR_LINKED_LIST*    ppMetaDataList
    );

DWORD
VmDirAttributeMetaDataListConvertToHashMap(
    PVDIR_LINKED_LIST    pMetaDataList,
    PLW_HASHMAP         *ppMetaDataMap
    );

DWORD
VmDirMetaDataCopyContent(
    PVMDIR_ATTRIBUTE_METADATA    pSrcMetaData,
    PVMDIR_ATTRIBUTE_METADATA    pDestMetaData
    );

DWORD
VmDirMetaDataCreate(
    USN                           localUsn,
    UINT64                        version,
    PCSTR                         pszOrigInvoId,
    PCSTR                         pszOrigTimeStamp,
    USN                           origUsn,
    PVMDIR_ATTRIBUTE_METADATA*    ppMetaData
    );

DWORD
VmDirMetaDataSetLocalUsn(
    PVMDIR_ATTRIBUTE_METADATA    pMetaData,
    USN                          localUsn
    );

BOOLEAN
VmDirMetaDataIsEmpty(
    PVMDIR_ATTRIBUTE_METADATA    pMetaData
    );

VOID
VmDirFreeMetaDataContent(
    PVMDIR_ATTRIBUTE_METADATA    pMetaData
    );

VOID
VmDirFreeMetaData(
    PVMDIR_ATTRIBUTE_METADATA    pMetaData
    );

VOID
VmDirFreeAttrMetaDataNode(
    PATTRIBUTE_META_DATA_NODE   pAttrMetaData,
    DWORD                       dwNumAttrMetaData
    );

VOID
VmDirFreeMetaDataMapPair(
    PLW_HASHMAP_PAIR    pPair,
    PVOID               pUnused
    );

//replmetadata.c
VOID
VmDirFreeReplMetaData(
    PVMDIR_REPL_ATTRIBUTE_METADATA    pReplMetaData
    );

VOID
VmDirFreeReplMetaDataList(
    PVDIR_LINKED_LIST    pMetaDataList
    );

DWORD
VmDirReplMetaDataDeserialize(
    PCSTR                              pszReplMetaData,
    PVMDIR_REPL_ATTRIBUTE_METADATA*    ppReplMetaData
    );

DWORD
VmDirReplMetaDataCreate(
    PCSTR                              pszAttrType,
    USN                                localUsn,
    UINT64                             version,
    PCSTR                              pszOrigInvoId,
    PCSTR                              pszOrigTime,
    USN                                origUsn,
    PVMDIR_REPL_ATTRIBUTE_METADATA*    ppReplMetaData
    );

//valuemetadata.c
DWORD
VmDirValueMetaDataDeserialize(
    PCSTR                               pszValueMetaData,
    PVMDIR_VALUE_ATTRIBUTE_METADATA*    ppValueMetaData
    );

DWORD
VmDirValueMetaDataSerialize(
    PVMDIR_VALUE_ATTRIBUTE_METADATA    pValueMetaData,
    PVDIR_BERVALUE                     pBervValueMetaData
    );

BOOLEAN
VmDirValueMetaDataIsValid(
    PVMDIR_VALUE_ATTRIBUTE_METADATA    pValueMetaData
    );

BOOLEAN
VmDirValueMetaDataIsEmpty(
    PVMDIR_VALUE_ATTRIBUTE_METADATA    pValueMetaData
    );

VOID
VmDirFreeValueMetaData(
    PVMDIR_VALUE_ATTRIBUTE_METADATA    pValueMetaData
    );

DWORD
VmDirAttributeValueMetaDataToList(
    PVDIR_ATTRIBUTE       pAttrAttrValueMetaData,
    PVDIR_LINKED_LIST*    ppValueMetaDataList
    );

DWORD
VmDirAttributeValueMetaDataListConvertToDequeue(
    PVDIR_LINKED_LIST    pValueMetaDataList,
    PDEQUE               pValueMetaDataQueue
    );

VOID
VmDirFreeValueMetaDataList(
    PVDIR_LINKED_LIST    pValueMetaDataList
    );

VOID
VmDirFreeAttrValueMetaDataDequeueContent(
    PDEQUE  pValueMetaData
    );

DWORD
VmDirValueMetaDataCreate(
    PCSTR                               pszAttrType,
    USN                                 localUsn,
    UINT64                              version,
    PCSTR                               pszOrigInvoId,
    PCSTR                               pszValChgOrigInvoId,
    PCSTR                               pszValChgOrigTime,
    USN                                 valChgOrigUsn,
    DWORD                               dwOpCode,
    PVDIR_BERVALUE                      pBervValue,
    PVMDIR_VALUE_ATTRIBUTE_METADATA*    ppValueMetaData
    );

// writequeue.c
DWORD
VmDirWriteQueueElementAllocate(
    PVMDIR_WRITE_QUEUE_ELEMENT*    ppWriteQueueEle
    );

VOID
VmDirWriteQueueElementFree(
    PVMDIR_WRITE_QUEUE_ELEMENT    pWriteQueueEle
    );

DWORD
VmDirWriteQueuePush(
    PVDIR_BACKEND_CTX           pBECtx,
    PVMDIR_WRITE_QUEUE          pWriteQueue,
    PVMDIR_WRITE_QUEUE_ELEMENT  pWriteQueueEle
    );

VOID
VmDirWriteQueuePop(
    PVMDIR_WRITE_QUEUE          pWriteQueue,
    PVMDIR_WRITE_QUEUE_ELEMENT  pWriteQueueEle
    );

DWORD
VmDirWriteQueueWait(
    PVMDIR_WRITE_QUEUE          pWriteQueue,
    PVMDIR_WRITE_QUEUE_ELEMENT  pWriteQueueEle
    );

#ifdef __cplusplus
}
#endif

#include <vmdirmetrics.h>

#endif /* COMMON_INTERFACE_H_ */
