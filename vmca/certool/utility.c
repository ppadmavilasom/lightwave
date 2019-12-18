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

// This file contains mostly utility functions needed by the CertTool
int
GetSleepTime(int secondsToSleep)
{
    return secondsToSleep; // Posix Sleeps in Seconds.
}

DWORD
GetMachineNameInternal(int type, PSTR *ppMachineName)
{
    const int NAMEBUF = 1024;
    DWORD dwError = 0;
    char CompName[NAMEBUF];

    DWORD dwSize = sizeof(CompName);

    struct hostent* h = NULL;
    dwError = gethostname(CompName,dwSize);
    BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
    if (type == FQDN)
    {
        h = gethostbyname(CompName);
        if ( h == NULL) 
        {
            dwError = -1;
            BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
        }
        strncpy(CompName, h->h_name, NAMEBUF);
    }
error :
    if ((type == FQDN) &&
        (dwError > 0) &&
        CompName[0] != '\0')
    {
        // Clear the Error we will just return the host Name as the
        // FQDN.
        dwError = 0;
    }

    dwError = VMCAAllocateStringA(CompName,ppMachineName);

    return dwError;
}


DWORD
GetMachineName(PSTR *ppMachineName)
{
    return GetMachineNameInternal(NETBIOSNAME, ppMachineName);
}


DWORD
GetFQDN(PSTR *ppFQDN)
{
    return GetMachineNameInternal(FQDN, ppFQDN);
}

PCSTR
ErrorCodeToName(int code)
{
    int i = 0;
    VMCA_ERROR_CODE_NAME_MAP VMCA_ERROR_Table[] =
                                 VMCA_ERROR_TABLE_INITIALIZER;

    if (code == 0) return "Success";
    for (i=0; i<sizeof(VMCA_ERROR_Table)/sizeof(VMCA_ERROR_Table[0]); i++)
    {
        if ( code == VMCA_ERROR_Table[i].code)
        {
            return VMCA_ERROR_Table[i].name;
        }
    }

    return UNKNOWN_STRING;
}

VOID
VMCAFreeCommandLineA(
    int argc,
    PSTR* pArgs
    )
{
    if (pArgs)
    {
        for (int i = 0; i < argc; ++i)
        {
            VMCA_SAFE_FREE_STRINGA(pArgs[i]);
        }
        VMCA_SAFE_FREE_MEMORY(pArgs);
    }
}

VOID
VMCAFreeCmdGenCSR(
    PCERTOOL_CMD_GENCSR pCmdGenCSR
    )
{
    if (pCmdGenCSR)
    {
        VMCA_SAFE_FREE_MEMORY(pCmdGenCSR->pszPrivateKeyFile);
        VMCA_SAFE_FREE_MEMORY(pCmdGenCSR->pszPublicKeyFile);
        VMCA_SAFE_FREE_MEMORY(pCmdGenCSR->pszCSRFile);
        VMCA_SAFE_FREE_MEMORY(pCmdGenCSR);
    }
}

VOID
VMCAFreeCmdGenKey(
    PCERTOOL_CMD_GENKEY pCmdGenKey
    )
{
    if (pCmdGenKey)
    {
        VMCA_SAFE_FREE_MEMORY(pCmdGenKey->pszPrivateKeyFile);
        VMCA_SAFE_FREE_MEMORY(pCmdGenKey->pszPublicKeyFile);
        VMCA_SAFE_FREE_MEMORY(pCmdGenKey);
    }
}

VOID
VMCAFreeCmdHelp(
    PCERTOOL_CMD_HELP pCmdHelp
    )
{
    if (pCmdHelp)
    {
        VMCA_SAFE_FREE_MEMORY(pCmdHelp->pszArg);
        VMCA_SAFE_FREE_MEMORY(pCmdHelp);
    }
}

VOID
VMCAFreeConfigData(
    PCERTOOL_CONFIG_DATA pConfig
    )
{
    PCERTOOL_CONFIG_DATA pTemp = pConfig;
    while(pConfig)
    {
        pTemp = pConfig->pNext;

        VMCA_SAFE_FREE_MEMORY(pConfig->pszName);
        VMCA_SAFE_FREE_MEMORY(pConfig->pszValue);
        VMCA_SAFE_FREE_MEMORY(pConfig->pszDefault);
        VMCAFreeMemory(pConfig);

        pConfig = pTemp;
    }
}

VOID
VMCAFreeCmdArgs(
    PCERTOOL_CMD_ARGS pArgs
    )
{
    if (pArgs)
    {
        VMCA_SAFE_FREE_MEMORY(pArgs->pszConfigFile);
        VMCA_SAFE_FREE_MEMORY(pArgs->pszServer);
        VMCA_SAFE_FREE_MEMORY(pArgs->pszSRPUPN);
        VMCA_SAFE_FREE_MEMORY(pArgs->pszSRPPass);
        VMCAFreeStringArrayA(pArgs->ppszCmds, pArgs->nCmdCount);
        VMCAFreeConfigData(pArgs->pConfig);
        switch(pArgs->cmdType)
        {
            case CERTOOL_CMD_TYPE_HELP:
                VMCAFreeCmdHelp(pArgs->pCmdHelp);
            break;
            case CERTOOL_CMD_TYPE_GENCSR:
                VMCAFreeCmdGenCSR(pArgs->pCmdGenCSR);
            break;
            case CERTOOL_CMD_TYPE_GENKEY:
                VMCAFreeCmdGenKey(pArgs->pCmdGenKey);
            break;
            default:
            break;
        }
        VMCAFreeMemory(pArgs);
    }
}

DWORD
VMCADuplicateArgv(
    int argc,
    char* const* argv,
    char*** argvDup
    )
{
    DWORD dwError = 0;
    int i = 0;
    char** dup = NULL;

    if(!argv || !argvDup)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

    dwError = VMCAAllocateMemory(sizeof(char*) * argc, (PVOID *)&dup);
    BAIL_ON_VMCA_ERROR(dwError);

    for(i = 0; i < argc; ++i)
    {
        dup[i] = strdup(argv[i]);
    }
    *argvDup = dup;

cleanup:
    return dwError;

error:
    if(argvDup)
    {
        *argvDup = NULL;
    }
    goto cleanup;
}

DWORD
VMCAWriteAllText(
    PCSTR pcszFile,
    PCSTR pcszText
    )
{
    DWORD dwError = 0;
    FILE *fp = NULL;

    if (!pcszFile || !pcszText)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }


    fp = fopen(pcszFile, "w");
    if (!fp)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

    if (fprintf(fp, "%s", pcszText) < 0)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

error:
   if (fp)
   {
       fclose(fp);
   }
   return dwError;
}
