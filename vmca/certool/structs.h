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
#pragma once

typedef enum _CERTOOL_CMD_ARG_TYPE_
{
    NO_ARG,
    OPTIONAL_ARG,
    REQUIRED_ARG
}CERTOOL_CMD_ARG_TYPE;

typedef struct _CERTOOL_CMD_OPTION_
{
    PSTR pszOption;
    CERTOOL_CMD_ARG_TYPE argType;
    PSTR pszFlag;
    PSTR pszHelp;
    PSTR pszDefault;
}CERTOOL_CMD_OPTION, *PCERTOOL_CMD_OPTION;

typedef struct _CERTOOL_CMD_
{
    PSTR pszCmd;
    PSTR pszHelp;
    PCERTOOL_CMD_OPTION pOptions;
}CERTOOL_CMD, *PCERTOOL_CMD;

typedef enum _CERTOOL_CMD_TYPE_
{
    CERTOOL_CMD_TYPE_NONE = -1,
    CERTOOL_CMD_TYPE_HELP,
    CERTOOL_CMD_TYPE_VERSION,
    CERTOOL_CMD_TYPE_GENCSR,
    CERTOOL_CMD_TYPE_GENKEY,
    CERTOOL_CMD_TYPE_SELF_CA,
}CERTOOL_CMD_TYPE;

typedef struct _CERTOOL_CONFIG_DATA_
{
    VMCA_OID oidKey;
    PSTR pszName;
    PSTR pszValue;
    PSTR pszDefault;
    struct _CERTOOL_CONFIG_DATA_ *pNext;
}CERTOOL_CONFIG_DATA, *PCERTOOL_CONFIG_DATA;

typedef struct _CERTOOL_CONFIG_
{
    PSTR pszCountry;
    PSTR pszName;
    PSTR pszDomainComponent;
    PSTR pszOrganization;
    PSTR pszOrgUnit;
    PSTR pszState;
    PSTR pszLocality;
    PSTR pszIPAddress;
    PSTR pszEmail;
    PSTR pszHostName;
}CERTOOL_CONFIG, *PCERTOOL_CONFIG;

typedef struct _CERTOOL_CMD_HELP_
{
    PSTR pszArg;
}CERTOOL_CMD_HELP, *PCERTOOL_CMD_HELP;

typedef struct _CERTOOL_CMD_GENCSR_
{
    PSTR pszPrivateKeyFile;
    PSTR pszPublicKeyFile;
    PSTR pszCSRFile;
}CERTOOL_CMD_GENCSR, *PCERTOOL_CMD_GENCSR;

typedef struct _CERTOOL_CMD_GENKEY_
{
    PSTR pszPrivateKeyFile;
    PSTR pszPublicKeyFile;
}CERTOOL_CMD_GENKEY, *PCERTOOL_CMD_GENKEY;

typedef struct _CERTOOL_CMD_SELF_CA_
{
    int nNotBeforeMinutes;
}CERTOOL_CMD_SELF_CA, *PCERTOOL_CMD_SELF_CA;

typedef struct _CERTOOL_CMD_ARGS_
{
    CERTOOL_CMD_TYPE cmdType;
    PCERTOOL_CONFIG_DATA pConfig;
    PSTR pszConfigFile;
    PSTR pszServer;
    PSTR pszSRPUPN;
    PSTR pszSRPPass;
    PSTR *ppszCmds;
    int nCmdCount;
    union
    {
        PCERTOOL_CMD_HELP    pCmdHelp;
        PCERTOOL_CMD_GENCSR  pCmdGenCSR;
        PCERTOOL_CMD_GENKEY pCmdGenKey;
        PCERTOOL_CMD_SELF_CA pCmdSelfCA;
    };
}CERTOOL_CMD_ARGS, *PCERTOOL_CMD_ARGS;
