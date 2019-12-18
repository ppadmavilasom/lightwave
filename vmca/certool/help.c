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

static
VOID
_ShowGeneralHelp(
    VOID
    )
{
    fprintf(stdout, "certool general command options:\n");
    fprintf(stdout, "--help arg\n");
    fprintf(stdout, "help <command> for help with each command\n");
    fprintf(stdout, "Commands are :\n");
    fprintf(stdout, "certool --help=init - shows help for all ");
    fprintf(stdout, "initialization relevant functions\n");
    fprintf(stdout, "certool --help=functions - shows help for all other ");
    fprintf(stdout, "functions\n");
    fprintf(stdout, "certool --help=config - shows help for the ");
    fprintf(stdout, "parameters of the config file\n");
}

static
VOID
_GenCSRHelp(
    VOID
    )
{
    printf("--gencsr Generate Certificate Request\n");
    printf("Generates a Certificate Signing Request\n");
    printf("A PKCS10 file and a key pair is generated in this mode.\n");
    printf("Different flags used for this command are :\n");
    printf("--gencsr - required, the command flag\n");
    printf("--privkey - required, file name for private key\n");
    printf("--pubkey  - required, file name for public key\n");
    printf("--csrfile - required, file name for the CSR\n");
    printf("--config  - optional, default value \"certool.cfg\" will\n");
    printf("be used.\n");
    printf("\n");
    printf("Example : certool --gencsr --privkey=<filename>\n");
    printf("--pubkey=<filename> --csrfile=<filename>\n");
}

static
VOID
_GenKeyHelp(
    VOID
    )
{
    printf("--genkey Generates a private and public key pair\n");
    printf("Different flags used for this command are :\n");
    printf("--genkey  - required, the command flag\n");
    printf("--privkey - required, file name for private key\n");
    printf("--pubkey  - required, file name for public key\n");
    printf("\n");
    printf("Example: certool --genkey --privkey=<filename>\n");
    printf("--pubkey=<filename>\n");
}

static
VOID
_InitHelp(
    VOID
    )
{
    _GenCSRHelp();
}

static
VOID
_FunctionsHelp(
    VOID
    )
{
    _GenKeyHelp();
}

DWORD
_ShowHelp(
    CERTOOL_CMD_TYPE cmdType,
    PCSTR pszArg
    )
{
    DWORD dwError = 0;
    typedef VOID (*PFN_CMD_HELP)(VOID);
    struct stHelpMap
    {
        CERTOOL_CMD_TYPE type;
        PCSTR pcszName;
        PFN_CMD_HELP pFnCmdHelp;
    } arHelp[] =
    {
        /* init */
        {CERTOOL_CMD_TYPE_NONE, "init", _InitHelp},
        {CERTOOL_CMD_TYPE_GENCSR, "gencsr", _GenCSRHelp},
        /* functions */
        {CERTOOL_CMD_TYPE_NONE, "functions", _FunctionsHelp},
        {CERTOOL_CMD_TYPE_GENKEY, "genkey", _GenKeyHelp},
    };
    int i = 0;
    int nCommandCount = sizeof(arHelp)/sizeof(struct stHelpMap);

    for(i = 0; i < nCommandCount; ++i)
    {
        if (pszArg)
        {
            if (!strcmp(pszArg, arHelp[i].pcszName))
            {
                arHelp[i].pFnCmdHelp();
                goto cleanup;
            }
        }
        else if (cmdType == arHelp[i].type)
        {
            arHelp[i].pFnCmdHelp();
            goto cleanup;
        }
    }

    dwError = ERROR_INVALID_PARAMETER;
    BAIL_ON_VMCA_ERROR_NO_LOG(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

DWORD
HandleHelp(
    PCERTOOL_CMD_ARGS pCmdArgs
    )
{
    DWORD dwError = 0;
    PCERTOOL_CMD_HELP pCmdHelp = NULL;

    if (!pCmdArgs)
    {
        dwError = ERROR_INVALID_PARAMETER;
        goto error;
    }

    if (pCmdArgs->cmdType == CERTOOL_CMD_TYPE_NONE ||
        pCmdArgs->cmdType == CERTOOL_CMD_TYPE_HELP)
    {
        pCmdHelp = pCmdArgs->pCmdHelp;

        if (!pCmdHelp || IsNullOrEmptyString(pCmdHelp->pszArg))
        {
            _ShowGeneralHelp();
        }
        else
        {
            dwError = _ShowHelp(CERTOOL_CMD_TYPE_NONE, pCmdHelp->pszArg);
        }
    }
    else
    {
        dwError = _ShowHelp(pCmdArgs->cmdType, NULL);
    }
error:
    return dwError;
}
