/*
 * Copyright © 2012-2016 VMware, Inc.  All Rights Reserved.
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
VmDirTestReplaceBinaryAttributeValues(
    LDAP *pLd,
    PCSTR pszDN,
    PCSTR pszAttribute,
    BYTE *pbAttributeValue,
    DWORD dwDataLength
    )
{
    DWORD dwError = 0;
    BerValue *ppBerValues[2] = {NULL, NULL};
    BerValue bvSecurityDescriptor = {0};
    LDAPMod addReplace;
    LDAPMod *mods[2];

    /* Initialize the attribute, specifying 'modify' as the operation */
    bvSecurityDescriptor.bv_val = (PVOID) pbAttributeValue;
    bvSecurityDescriptor.bv_len = dwDataLength;
    ppBerValues[0] = &bvSecurityDescriptor;
    addReplace.mod_op     = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    addReplace.mod_type   = (PSTR)pszAttribute;
    addReplace.mod_bvalues = ppBerValues;

    /* Fill the attributes array (remember it must be NULL-terminated) */
    mods[0] = &addReplace;
    mods[1] = NULL;

    dwError = ldap_modify_ext_s(pLd, pszDN, mods, NULL, NULL);

    return dwError;
}

DWORD
VmDirTestGetAttributeValueString(
    LDAP *pLd,
    PCSTR pBase,
    int ldapScope,
    PCSTR pszFilter,
    PCSTR pszAttribute,
    PSTR *ppszAttributeValue
    )
{
    DWORD dwError = 0;
    PCSTR ppszAttrs[2] = {0};
    LDAPMessage *pResult = NULL;
    BerValue** ppBerValues = NULL;
    PSTR pszAttributeValue = NULL;
    LDAPMessage *pEntry = NULL;

    ppszAttrs[0] = pszAttribute;
    dwError = ldap_search_ext_s(
                pLd,
                pBase,
                ldapScope,
                pszFilter,
                (PSTR*)ppszAttrs,
                0,
                NULL,
                NULL,
                NULL,
                -1,
                &pResult);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (ldap_count_entries(pLd, pResult) != 1)
    {
        BAIL_WITH_VMDIR_ERROR(dwError, ERROR_INVALID_STATE);
    }

    pEntry = ldap_first_entry(pLd, pResult);
    if (!pEntry)
    {
        BAIL_WITH_VMDIR_ERROR(dwError, ERROR_INVALID_STATE);
    }

    ppBerValues = ldap_get_values_len(pLd, pEntry, pszAttribute);
    if (!ppBerValues || (ldap_count_values_len(ppBerValues) != 1))
    {
        BAIL_WITH_VMDIR_ERROR(dwError, ERROR_INVALID_STATE);
    }

    dwError = VmDirAllocateStringA(ppBerValues[0]->bv_val, &pszAttributeValue);
    BAIL_ON_VMDIR_ERROR(dwError);

    *ppszAttributeValue = pszAttributeValue;
    pszAttributeValue = NULL;

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszAttributeValue);

    if (ppBerValues)
    {
        ldap_value_free_len(ppBerValues);
        ppBerValues = NULL;
    }

    if (pResult)
    {
        ldap_msgfree(pResult);
        pResult = NULL;
    }

    return dwError;

error:
    goto cleanup;
}

static
DWORD
_VmDirTestModifyAttributeValues(
    LDAP *pLd,
    PCSTR pszDN,
    int   modType,
    PCSTR pszAttribute,
    PCSTR *ppszAttributeValues
    )
{
    DWORD dwError = 0;

    LDAPMod ldapMod = {0};
    LDAPMod *mods[2];

    /* Initialize the attribute, specifying 'ADD' as the operation */
    ldapMod.mod_op     = modType;
    ldapMod.mod_type   = (PSTR) pszAttribute;
    ldapMod.mod_values = (PSTR*) ppszAttributeValues;

    /* Fill the attributes array (remember it must be NULL-terminated) */
    mods[0] = &ldapMod;
    mods[1] = NULL;

    /* ....initialize connection, etc. */

    dwError = ldap_modify_ext_s(pLd, pszDN, mods, NULL, NULL);

    return dwError;
}

DWORD
VmDirTestReplaceAttributeValues(
    LDAP *pLd,
    PCSTR pszDN,
    PCSTR pszAttribute,
    PCSTR *ppszAttributeValues
    )
{
    return _VmDirTestModifyAttributeValues(pLd, pszDN, LDAP_MOD_REPLACE, pszAttribute, ppszAttributeValues);
}

DWORD
VmDirTestAddAttributeValues(
    LDAP *pLd,
    PCSTR pszDN,
    PCSTR pszAttribute,
    PCSTR *ppszAttributeValues
    )
{
    return _VmDirTestModifyAttributeValues(pLd, pszDN, LDAP_MOD_ADD, pszAttribute, ppszAttributeValues);
}

DWORD
VmDirTestDeleteAttributeValues(
    LDAP *pLd,
    PCSTR pszDN,
    PCSTR pszAttribute,
    PCSTR *ppszAttributeValues
    )
{
    return _VmDirTestModifyAttributeValues(pLd, pszDN, LDAP_MOD_DELETE, pszAttribute, ppszAttributeValues);
}

DWORD
VmDirTestGetEntryAttributeValuesInStr(
    LDAP *pLd,
    PCSTR pBase,
    int ldapScope,
    PCSTR pszFilter,
    PCSTR pszAttribute,
    PVMDIR_STRING_LIST* ppList
    )
{
    DWORD dwError = 0;
    DWORD dwCnt = 0;
    PCSTR ppszAttrs[] = {NULL, NULL};
    LDAPMessage* pEntry = NULL;
    LDAPMessage *pResult = NULL;
    BerValue** ppBerValues = NULL;
    PSTR                pszValue = NULL;
    PVMDIR_STRING_LIST  pLocalList = NULL;

    dwError = VmDirStringListInitialize(&pLocalList, 0);
    BAIL_ON_VMDIR_ERROR(dwError);

    ppszAttrs[0] = pszAttribute;
    dwError = ldap_search_ext_s(
                pLd,
                pBase,
                ldapScope,
                pszFilter ? pszFilter : NULL,
                (PSTR*)ppszAttrs,
                0,
                NULL,
                NULL,
                NULL,
                -1,
                &pResult);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (ldap_count_entries(pLd, pResult) == 0)
    {
        BAIL_WITH_VMDIR_ERROR(dwError, VMDIR_ERROR_ENTRY_NOT_FOUND);
    }
    else if (ldap_count_entries(pLd, pResult) > 1)
    {
        BAIL_WITH_VMDIR_ERROR(dwError, VMDIR_ERROR_DATA_CONSTRAINT_VIOLATION);
    }

    pEntry = ldap_first_entry(pLd, pResult);
    ppBerValues = ldap_get_values_len(pLd, pEntry, pszAttribute);

    if (ppBerValues != NULL && ldap_count_values_len(ppBerValues) > 0)
    {
        for (dwCnt = 0; ppBerValues[dwCnt] != NULL; dwCnt++)
        {
            dwError = VmDirAllocateStringA(
                        ppBerValues[dwCnt]->bv_val,
                        &pszValue);
            BAIL_ON_VMDIR_ERROR(dwError);

            dwError = VmDirStringListAdd(pLocalList, pszValue);
            BAIL_ON_VMDIR_ERROR(dwError);
            pszValue = NULL;
        }
    }

    *ppList = pLocalList;
    pLocalList = NULL;

cleanup:
    VmDirStringListFree(pLocalList);

    if (ppBerValues)
    {
        ldap_value_free_len(ppBerValues);
        ppBerValues = NULL;
    }

    if (pResult)
    {
        ldap_msgfree(pResult);
        pResult = NULL;
    }

    return dwError;

error:
    goto cleanup;
}

DWORD
VmDirTestGetAttributeValue(
    LDAP *pLd,
    PCSTR pBase,
    int ldapScope,
    PCSTR pszFilter,
    PCSTR pszAttribute,
    BYTE **ppbAttributeValue,
    PDWORD pdwAttributeLength
    )
{
    DWORD dwError = 0;
    PCSTR ppszAttrs[2] = {0};
    LDAPMessage *pResult = NULL;
    BerValue** ppBerValues = NULL;
    BYTE *pbAttributeValue = NULL;
    DWORD dwAttributeLength = 0;

    ppszAttrs[0] = pszAttribute;
    dwError = ldap_search_ext_s(
                pLd,
                pBase,
                ldapScope,
                pszFilter ? pszFilter : "",
                (PSTR*)ppszAttrs,
                0,
                NULL,
                NULL,
                NULL,
                -1,
                &pResult);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (ldap_count_entries(pLd, pResult) > 0)
    {
        LDAPMessage* pEntry = ldap_first_entry(pLd, pResult);

        for (; pEntry != NULL; pEntry = ldap_next_entry(pLd, pEntry))
        {
            BerValue** ppBerValues = NULL;
            ppBerValues = ldap_get_values_len(pLd, pEntry, pszAttribute);
            if (ppBerValues != NULL && ldap_count_values_len(ppBerValues) > 0)
            {
                dwError = VmDirAllocateAndCopyMemory(
                            ppBerValues[0][0].bv_val,
                            ppBerValues[0][0].bv_len,
                            (PVOID*)&pbAttributeValue);
                BAIL_ON_VMDIR_ERROR(dwError);

                dwAttributeLength = ppBerValues[0][0].bv_len;
                break;
            }
        }
    }

    *ppbAttributeValue = pbAttributeValue;
    *pdwAttributeLength = dwAttributeLength;
    pbAttributeValue = NULL;

cleanup:
    VMDIR_SAFE_FREE_MEMORY(pbAttributeValue);

    if (ppBerValues)
    {
        ldap_value_free_len(ppBerValues);
        ppBerValues = NULL;
    }

    if (pResult)
    {
        ldap_msgfree(pResult);
        pResult = NULL;
    }

    return dwError;

error:
    goto cleanup;
}

VOID
VmDirTestLdapUnbind(
    LDAP *pLd
    )
{
    if (pLd)
    {
        ldap_unbind_ext_s(pLd, NULL, NULL);
    }
}

//
// Enumerates the objects at a certain DN. If you just want to verify that the
// user can enumerate but don't care about the actual objects, pass NULL
// for ppObjectList.
//
// NB -- The VMDIR_STRING_LIST returned contains full DNs for the individual
// objects.
//
DWORD
VmDirTestGetObjectList(
    LDAP*               pLd,
    PCSTR               pszDn,
    PCSTR               pszFilter,      /* OPTIONAL */
    PCSTR               pszAttr,        /* OPTIONAL */
    PVMDIR_STRING_LIST* ppObjectList    /* OPTIONAL */
    )
{
    DWORD   dwError = 0;
    DWORD   dwObjectCount = 0;
    PSTR    pszAttrs[] = { (PSTR)pszAttr, NULL };
    LDAPMessage *pResult = NULL;
    PVMDIR_STRING_LIST pObjectList = NULL;

    dwError = ldap_search_ext_s(
                pLd,
                pszDn,
                LDAP_SCOPE_SUBTREE,
                pszFilter,
                pszAttrs,
                0,
                NULL,
                NULL,
                NULL,
                -1,
                &pResult);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (ppObjectList != NULL)
    {
        dwObjectCount = ldap_count_entries(pLd, pResult);
        dwError = VmDirStringListInitialize(&pObjectList, dwObjectCount);
        BAIL_ON_VMDIR_ERROR(dwError);

        if (dwObjectCount > 0)
        {
            LDAPMessage* pEntry = ldap_first_entry(pLd, pResult);

            for (; pEntry != NULL; pEntry = ldap_next_entry(pLd, pEntry))
            {
                PCSTR pszObjDn = ldap_get_dn(pLd, pEntry);
                // skip the root entry
                if (VmDirStringCompareA(pszDn, pszObjDn, FALSE))
                {
                    dwError = VmDirStringListAddStrClone(ldap_get_dn(pLd, pEntry), pObjectList);
                    BAIL_ON_VMDIR_ERROR(dwError);
                }
            }
        }

        *ppObjectList = pObjectList;
    }

cleanup:
    if (pResult)
    {
        ldap_msgfree(pResult);
    }

    return dwError;

error:
    VmDirStringListFree(pObjectList);
    goto cleanup;
}

DWORD
VmDirTestConnectionFromUser(
    PVMDIR_TEST_STATE pState,
    PCSTR pszUserName,
    LDAP **ppLd
    )
{
    DWORD dwError = 0;
    PSTR pszUserUPN = NULL;
    LDAP *pLd;

    dwError = VmDirAllocateStringPrintf(
                &pszUserUPN,
                "%s@%s",
                pszUserName,
                pState->pszDomain);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirSafeLDAPBind(
                &pLd,
                pState->pszServerName,
                pszUserUPN,
                pState->pszPassword);
    BAIL_ON_VMDIR_ERROR(dwError);

    *ppLd = pLd;

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszUserUPN);
    return dwError;
error:
    goto cleanup;
}

DWORD
VmDirTestConnectionUser(
    PCSTR   pszHost,
    PCSTR   pszDomain,
    PCSTR   pszUserName,
    PCSTR   pszUserPassword,
    LDAP**  ppLd
    )
{
    DWORD dwError = 0;
    PSTR pszUserUPN = NULL;
    LDAP *pLd;

    dwError = VmDirAllocateStringPrintf(
                &pszUserUPN,
                "%s@%s",
                pszUserName,
                pszDomain);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirSafeLDAPBind(
                &pLd,
                pszHost,
                pszUserUPN,
                pszUserPassword);
    BAIL_ON_VMDIR_ERROR(dwError);

    *ppLd = pLd;

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszUserUPN);
    return dwError;
error:
    goto cleanup;
}

DWORD
VmDirTestDeleteContainerByDn(
    LDAP *pLd,
    PCSTR pszContainerDn
    )
{
    DWORD dwError = 0;
    DWORD dwIndex = 0;
    PVMDIR_STRING_LIST pObjectList = NULL;

    dwError = VmDirTestGetObjectList(pLd, pszContainerDn, NULL, NULL, &pObjectList);
    BAIL_ON_VMDIR_ERROR(dwError);

    for (dwIndex = 0; dwIndex < pObjectList->dwCount; ++dwIndex)
    {
        dwError = ldap_delete_ext_s(
                pLd, pObjectList->pStringList[dwIndex], NULL, NULL);
        if (dwError == LDAP_NOT_ALLOWED_ON_NONLEAF)
        {
            dwError = VmDirTestDeleteContainerByDn(
                    pLd, pObjectList->pStringList[dwIndex]);
            BAIL_ON_VMDIR_ERROR(dwError);
        }
    }

    dwError = ldap_delete_ext_s(pLd, pszContainerDn, NULL, NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    VmDirStringListFree(pObjectList);
    return dwError;

error:
    goto cleanup;
}

DWORD
VmDirTestCreateSimpleUser(
    LDAP *pLd,
    PCSTR pszCN,
    PCSTR pszUserDN
    )
{
    DWORD       dwError = 0;

    PCSTR       valsCn[] = {pszCN, NULL};
    PCSTR       valsClass[] = {OC_USER, NULL};

    LDAPMod     mod[2]={
                            {LDAP_MOD_ADD, ATTR_CN, {(PSTR*)valsCn}},
                            {LDAP_MOD_ADD, ATTR_OBJECT_CLASS, {(PSTR*)valsClass}}
                       };
    LDAPMod*    attrs[] = {&mod[0], &mod[1], NULL};

    dwError = ldap_add_ext_s(pLd, pszUserDN, attrs, NULL, NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:

    return dwError;

error:
    goto cleanup;
}

DWORD
VmDirTestCreateSimpleContainer(
    LDAP *pLd,
    PCSTR pszCN,
    PCSTR pszContainerDN
    )
{
    DWORD       dwError = 0;

    PCSTR       valsCn[] = {pszCN, NULL};
    PCSTR       valsClass[] = {OC_CONTAINER, NULL};

    LDAPMod     mod[2]={
                            {LDAP_MOD_ADD, ATTR_CN, {(PSTR*)valsCn}},
                            {LDAP_MOD_ADD, ATTR_OBJECT_CLASS, {(PSTR*)valsClass}}
                       };
    LDAPMod*    attrs[] = {&mod[0], &mod[1], NULL};

    dwError = ldap_add_ext_s(pLd, pszContainerDN, attrs, NULL, NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:

    return dwError;

error:
    goto cleanup;
}

BOOLEAN
VmDirTestCanReadSingleEntry(
    LDAP* pLd,
    PCSTR pszBaseDn
    )
{
    DWORD   dwError = 0;
    LDAPMessage* pResult = NULL;
    BOOLEAN bRtn = FALSE;

    dwError = ldap_search_ext_s(
                pLd,
                pszBaseDn,
                LDAP_SCOPE_BASE,
                NULL,
                NULL,
                0,
                NULL,
                NULL,
                NULL,
                -1,
                &pResult);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (ldap_count_entries(pLd, pResult) == 1)
    {
        bRtn = TRUE;
    }

cleanup:
    if (pResult)
    {
        ldap_msgfree(pResult);
    }

    return bRtn;

error:
    goto cleanup;
}
