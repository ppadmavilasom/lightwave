/*
 * Copyright © 2012-2019 VMware, Inc.  All Rights Reserved.
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

#define CMD_HELP   "help"
#define CMD_GENCSR "gencsr"
#define CMD_GENKEY "genkey"

#define OPT_CONFIG "config"
#define OPT_SERVER "server"
#define OPT_SRP_UPN "srp-upn"
#define OPT_SRP_PASS "srp-pwd"
#define OPT_VERSION "version"

static struct option commonOptions[] =
{
    {CMD_HELP, optional_argument, NULL, 'h'},
    {CMD_GENCSR, no_argument, NULL, 0},
    {CMD_GENKEY, no_argument, NULL, 0},

    {OPT_CONFIG, required_argument, NULL, 'c'},
    {OPT_SERVER, required_argument, NULL, 0},
    {OPT_SRP_UPN, required_argument, NULL, 0},
    {OPT_SRP_PASS, required_argument, NULL, 0},
    {OPT_VERSION, no_argument, NULL, 'v'},
    {NULL, 0, NULL, 0}
};

static
DWORD
_VMCACommandGetExtraArgs(
    int argIndex,
    int argc,
    PSTR *argv,
    PSTR** pppszCmds,
    int* pnCmdCount
    )
{
    DWORD dwError = 0;
    PSTR *ppszCmds = NULL;
    int nCmdCount = 0;

    if (argIndex < argc)
    {
        int nIndex = 0;
        nCmdCount = argc - argIndex;
        dwError = VMCAAllocateMemory(
                      nCmdCount * sizeof(PSTR),
                      (PVOID *)&ppszCmds);
        BAIL_ON_VMCA_ERROR_NO_LOG(dwError);

        while (argIndex < argc)
        {
            dwError = VMCAAllocateStringA(
                          argv[argIndex++],
                          &ppszCmds[nIndex++]);
            BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
        }
    }

    *pppszCmds = ppszCmds;
    *pnCmdCount = nCmdCount;

cleanup:
    return dwError;

error:
    if(pppszCmds)
    {
        *pppszCmds = NULL;
    }
    if(pnCmdCount)
    {
        *pnCmdCount = 0;
    }
    VMCAFreeStringArrayA(ppszCmds, nCmdCount);
    goto cleanup;
}

static
DWORD
_VMCAParseCommonOption(
    PCSTR pcszName,
    PCSTR pcszArg,
    PCERTOOL_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    PSTR *ppszOptArg = NULL;

    if(!pcszName || !pCmdArgs)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
    }

    if(!VMCAStringCompareA(pcszName, CMD_HELP, TRUE))
    {
        pCmdArgs->cmdType = CERTOOL_CMD_TYPE_HELP;

        dwError = VMCAAllocateMemory(
                  sizeof(*(pCmdArgs->pCmdHelp)),
                  (PVOID *)&pCmdArgs->pCmdHelp);
        BAIL_ON_VMCA_ERROR_NO_LOG(dwError);

        ppszOptArg = &pCmdArgs->pCmdHelp->pszArg;
    }
    else if(!VMCAStringCompareA(pcszName, CMD_GENCSR, TRUE))
    {
        pCmdArgs->cmdType = CERTOOL_CMD_TYPE_GENCSR;
    }
    else if(!VMCAStringCompareA(pcszName, CMD_GENKEY, TRUE))
    {
        pCmdArgs->cmdType = CERTOOL_CMD_TYPE_GENKEY;
    }
    else if(!VMCAStringCompareA(pcszName, OPT_SERVER, TRUE))
    {
        ppszOptArg = &pCmdArgs->pszServer;
    }
    else if(!VMCAStringCompareA(pcszName, OPT_CONFIG, TRUE))
    {
        ppszOptArg = &pCmdArgs->pszConfigFile;
    }
    else if(!VMCAStringCompareA(pcszName, OPT_SRP_UPN, TRUE))
    {
        ppszOptArg = &pCmdArgs->pszSRPUPN;
    }
    else if(!VMCAStringCompareA(pcszName, OPT_SRP_PASS, TRUE))
    {
        ppszOptArg = &pCmdArgs->pszSRPPass;
    }

    if(ppszOptArg)
    {
        if(!pcszArg)
        {
            dwError = ERROR_CERTOOL_OPTION_ARG_REQUIRED;
            BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
        }
        dwError = VMCAAllocateStringA(pcszArg, ppszOptArg);
        BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

static
DWORD
_VMCAParseGenCSRArgs(
    int argc,
    char **argv,
    PCERTOOL_CMD_GENCSR *ppCmd
    )
{
    DWORD dwError = 0;
    PCERTOOL_CMD_GENCSR pCmd = NULL;
    int nOptionIndex = -1;
    int nOption = 0;

    #define OPT_GENCSR_PRIVKEY "privkey"
    #define OPT_GENCSR_PUBKEY  "pubkey"
    #define OPT_GENCSR_CSRFILE "csrfile"
    struct option gencsrOptions[] =
    {
        {CMD_GENCSR, no_argument, NULL, 0},
        {OPT_GENCSR_PRIVKEY, required_argument, NULL, 0},
        {OPT_GENCSR_PUBKEY,  required_argument, NULL, 0},
        {OPT_GENCSR_CSRFILE, required_argument, NULL, 0},
        {NULL, 0, NULL, 0}
    };

    /* restart scanning for new command args */
    optind = 0;

    dwError = VMCAAllocateMemory(
                  sizeof(*(pCmd)),
                  (PVOID *)&pCmd);
    BAIL_ON_VMCA_ERROR_NO_LOG(dwError);

    while(1)
    {
        nOption = getopt_long(
                      argc,
                      argv,
                      "",
                      gencsrOptions,
                      &nOptionIndex);
        if (nOption == -1)
            break;
        if (nOptionIndex == -1)
        {
            continue;
        }
        if (!strcmp(gencsrOptions[nOptionIndex].name, OPT_GENCSR_PRIVKEY))
        {
            dwError = VMCAAllocateStringA(optarg, &pCmd->pszPrivateKeyFile);
            BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
        }
        else if (!strcmp(gencsrOptions[nOptionIndex].name, OPT_GENCSR_PUBKEY))
        {
            dwError = VMCAAllocateStringA(optarg, &pCmd->pszPublicKeyFile);
            BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
        }
        else if (!strcmp(gencsrOptions[nOptionIndex].name, OPT_GENCSR_CSRFILE))
        {
            dwError = VMCAAllocateStringA(optarg, &pCmd->pszCSRFile);
            BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
        }
    }

    *ppCmd = pCmd;

cleanup:
    return dwError;

error:
    VMCAFreeCmdGenCSR(pCmd);
    goto cleanup;

}

static
DWORD
_VMCAParseGenKeyArgs(
    int argc,
    char **argv,
    PCERTOOL_CMD_GENKEY *ppCmd
    )
{
    DWORD dwError = 0;
    PCERTOOL_CMD_GENKEY pCmd = NULL;
    int nOptionIndex = -1;
    int nOption = 0;

    #define OPT_GENKEY_PRIVKEY "privkey"
    #define OPT_GENKEY_PUBKEY  "pubkey"
    struct option genkeyOptions[] =
    {
        {CMD_GENKEY, no_argument, NULL, 0},
        {OPT_GENKEY_PRIVKEY, required_argument, NULL, 0},
        {OPT_GENKEY_PUBKEY,  required_argument, NULL, 0},
        {NULL, 0, NULL, 0}
    };

    /* restart scanning for new command args */
    optind = 0;

    dwError = VMCAAllocateMemory(
                  sizeof(*(pCmd)),
                  (PVOID *)&pCmd);
    BAIL_ON_VMCA_ERROR_NO_LOG(dwError);

    while(1)
    {
        nOption = getopt_long(
                      argc,
                      argv,
                      "",
                      genkeyOptions,
                      &nOptionIndex);
        if (nOption == -1)
            break;
        if (nOptionIndex == -1)
        {
            continue;
        }
        if (!strcmp(genkeyOptions[nOptionIndex].name, OPT_GENKEY_PRIVKEY))
        {
            dwError = VMCAAllocateStringA(optarg, &pCmd->pszPrivateKeyFile);
            BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
        }
        else if (!strcmp(genkeyOptions[nOptionIndex].name, OPT_GENKEY_PUBKEY))
        {
            dwError = VMCAAllocateStringA(optarg, &pCmd->pszPublicKeyFile);
            BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
        }
    }

    *ppCmd = pCmd;

cleanup:
    return dwError;

error:
    VMCAFreeCmdGenKey(pCmd);
    goto cleanup;

}


static
DWORD
_VMCAParseCommonArgs(
    int argc,
    char **argv,
    PCERTOOL_CMD_ARGS pCmdArgs
    )
{
    DWORD dwError = 0;
    char **argvDup = NULL;

    int nOptionIndex = -1;
    int nOption = 0;

    /* suppress getopt error reporting */
    opterr = 0;

    /* keep a duplicate of args to handle sub commands */
    dwError = VMCADuplicateArgv(argc, argv, &argvDup);
    BAIL_ON_VMCA_ERROR_NO_LOG(dwError);

    while(1)
    {
        nOption = getopt_long(
                      argc,
                      argv,
                      "h:",
                      commonOptions,
                      &nOptionIndex);
        if (nOption == -1)
            break;
        /* ignore errors. subcommands will be processed in own context */
        if (nOptionIndex == -1)
        {
            continue;
        }

        dwError = _VMCAParseCommonOption(
                      commonOptions[nOptionIndex].name,
                      optarg,
                      pCmdArgs);
        BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
    }

    if (pCmdArgs->cmdType == CERTOOL_CMD_TYPE_GENCSR)
    {
        dwError = _VMCAParseGenCSRArgs(argc, argvDup, &pCmdArgs->pCmdGenCSR);
        BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
    }
    else if (pCmdArgs->cmdType == CERTOOL_CMD_TYPE_GENKEY)
    {
        dwError = _VMCAParseGenKeyArgs(argc, argvDup, &pCmdArgs->pCmdGenKey);
        BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
    }

    dwError = _VMCACommandGetExtraArgs(
                  optind,
                  argc,
                  argv,
                  &pCmdArgs->ppszCmds,
                  &pCmdArgs->nCmdCount);
    BAIL_ON_VMCA_ERROR_NO_LOG(dwError);

cleanup:
    VMCAFreeStringArrayA(argvDup, argc);
    return dwError;

error:
    goto cleanup;
}

DWORD
VMCAParseArgs(
    int argc,
    char **argv,
    PCERTOOL_CMD_ARGS pCmdArgs
    )
{
    DWORD dwError = 0;

    if (argc < 2 || !argv || !pCmdArgs)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
    }

    dwError = _VMCAParseCommonArgs(argc, argv, pCmdArgs);
    BAIL_ON_VMCA_ERROR_NO_LOG(dwError);

    if (pCmdArgs->cmdType == CERTOOL_CMD_TYPE_NONE)
    {
        dwError = ERROR_CERTOOL_UNKNOWN_COMMAND;
        BAIL_ON_VMCA_ERROR_NO_LOG(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

static
DWORD
_MakeConfigItem(
    VMCA_OID oid,
    PCSTR pcszName,
    PCSTR pcszValue,
    PCSTR pcszDefault,
    PCERTOOL_CONFIG_DATA *ppData
    )
{
    DWORD dwError = 0;
    PCERTOOL_CONFIG_DATA pData = NULL;

    if (!ppData || IsNullOrEmptyString(pcszName))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

    dwError = VMCAAllocateMemory(sizeof(*pData), (PVOID *)&pData);
    BAIL_ON_VMCA_ERROR(dwError);

    pData->oidKey = oid;
    dwError = VMCAAllocateStringA(pcszName, &pData->pszName);
    BAIL_ON_VMCA_ERROR(dwError);

    if (pcszValue)
    {
        dwError = VMCAAllocateStringA(pcszValue, &pData->pszValue);
        BAIL_ON_VMCA_ERROR(dwError);
    }

    if (pcszDefault)
    {
        dwError = VMCAAllocateStringA(pcszDefault, &pData->pszDefault);
        BAIL_ON_VMCA_ERROR(dwError);
    }

    *ppData = pData;

cleanup:
    return dwError;

error:
    VMCAFreeConfigData(pData);
    goto cleanup;
}

static
DWORD
_InitConfig(
    PCERTOOL_CMD_ARGS pCmdArgs
    )
{
    DWORD dwError = 0;
    int i = 0;
    PCERTOOL_CONFIG_DATA pConfigRoot = NULL;
    PCERTOOL_CONFIG_DATA pLast = NULL;
    PCERTOOL_CONFIG_DATA pNew = NULL;
    CERTOOL_CONFIG_DATA arData[] =
    {
        {VMCA_OID_CN, "Name", NULL, "Acme"},
        {VMCA_OID_DC, "DomainComponent", NULL, "acme.local"},
        {VMCA_OID_COUNTRY, "Country", NULL, "US"},
        {VMCA_OID_LOCALITY, "Locality", NULL, "Palo Alto"},
        {VMCA_OID_STATE, "State", NULL, "California"},
        {VMCA_OID_ORGANIZATION, "Organization", NULL, "AcmeOrg"},
        {VMCA_OID_ORG_UNIT, "OrgUnit", NULL, "AcmeOrg Engineering"},
        {VMCA_OID_EMAIL, "Email", NULL, "email@acme.com"},
        {VMCA_OID_IPADDRESS, "IPAddress", NULL, "127.0.0.1"},
        {VMCA_OID_DNS, "Hostname", NULL, "server.acme.com"},
    };

    for(i = 0; i < sizeof(arData)/sizeof(arData[0]); ++i)
    {
        dwError = _MakeConfigItem(arData[i].oidKey,
                                  arData[i].pszName,
                                  arData[i].pszValue,
                                  arData[i].pszDefault,
                                  &pNew);
        BAIL_ON_VMCA_ERROR(dwError);

        if(!pConfigRoot)
        {
            pConfigRoot = pNew;
        }
        else
        {
            pLast->pNext = pNew;
        }
        pLast = pNew;
    }

    pCmdArgs->pConfig = pConfigRoot;
cleanup:
    return dwError;

error:
    VMCAFreeConfigData(pConfigRoot);
    goto cleanup;
}

DWORD
VMCAInitArgs(
    PCERTOOL_CMD_ARGS *ppCmdArgs
    )
{
    DWORD dwError = 0;
    PCERTOOL_CMD_ARGS pCmdArgs = NULL;

    if (!ppCmdArgs)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

    dwError = VMCAAllocateMemory(
                  sizeof(*pCmdArgs),
                  (PVOID *)&pCmdArgs);
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = _InitConfig(pCmdArgs);
    BAIL_ON_VMCA_ERROR(dwError);

    *ppCmdArgs = pCmdArgs;

cleanup:
    return dwError;

error:
    VMCAFreeCmdArgs(pCmdArgs);
    if (ppCmdArgs)
    {
        *ppCmdArgs = NULL;
    }
    goto cleanup;
}
