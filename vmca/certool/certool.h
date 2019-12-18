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
#ifndef __CERT_TOOL_H__
#define __CERT_TOOL_H__

#include "includes.h"

#define ERROR_CERTOOL_UNKNOWN_COMMAND       201
#define ERROR_CERTOOL_OPTION_ARG_REQUIRED   202

#define VMCA_TIME_SECS_PER_MINUTE           ( 60)
#define VMCA_TIME_SECS_PER_HOUR             ( 60 * VMCA_TIME_SECS_PER_MINUTE)
#define VMCA_TIME_SECS_PER_DAY              ( 24 * VMCA_TIME_SECS_PER_HOUR)
#define VMCA_TIME_SECS_PER_WEEK             (  7 * VMCA_TIME_SECS_PER_DAY)
#define VMCA_TIME_SECS_PER_YEAR             (365 * VMCA_TIME_SECS_PER_DAY)

#define VMCA_DEFAULT_CA_CERT_VALIDITY       (10 * VMCA_TIME_SECS_PER_YEAR)
#define VMCA_CA_CERT_EXPIRY_START_LAG       ( 3 * VMCA_TIME_SECS_PER_DAY)
#define VMCA_CERT_EXPIRY_START_LAG          (10 * VMCA_TIME_SECS_PER_MINUTE)
#define VMCA_DEFAULT_CERT_VALIDITY          (10 * VMCA_TIME_SECS_PER_YEAR)

#define VMCA_MAX_PREDATE_PERMITED           (VMCA_TIME_SECS_PER_WEEK/VMCA_TIME_SECS_PER_MINUTE)
#define VMCA_DEFAULT_CA_CERT_START_PREDATE  (VMCA_CA_CERT_EXPIRY_START_LAG/VMCA_TIME_SECS_PER_MINUTE)

#define VMCA_OPTION_MULTIPLE_SAN            "multiplesan"

typedef enum _VMCA_FILE_ENCODING
{
    VMCA_FILE_ENCODING_UTF8,
    VMCA_FILE_ENCODING_UTF16LE,
    VMCA_FILE_ENCODING_UTF16BE,
    VMCA_FILE_ENCODING_UTF7
}VMCA_FILE_ENCODING;

DWORD
HandleInitCSR();

DWORD
HandleCreateSelfSignedCA();

DWORD
HandleRootCACertificate();

DWORD
HandleGenCert();

DWORD
HandleGenKey();

DWORD
HandleRevokeCert();

DWORD
HandleViewCert();

DWORD
HandleGetRootCA();

DWORD
HandleVersionRequest();

DWORD
HandleEnumCerts();

DWORD
HandleGetDC();

DWORD
HandleGenCISCert();

DWORD
HandleWaitVMCA();

DWORD
HandleWaitVMDIR();

DWORD
HandleStatusCert();

DWORD
HandleInitVMCA();

DWORD
HandleLogin();

DWORD
HandleLogout();

DWORD
HandleVecsEnum();

DWORD
HandleGetCRL();

DWORD
HandleGenCRL();

DWORD
HandleCRLInfo();

DWORD
HandlePrintError();

DWORD
HandlePrintCRL();

DWORD
HandlePublishRoots();

DWORD
HandleUpdateSchema();

DWORD
HandleSetRootCA();

DWORD
HandleGenSelfCert();

DWORD
HandleGenCSRFromCert();

DWORD
HandleSetServerOption();

DWORD
HandleUnsetServerOption();

DWORD
HandleGetServerOption();

DWORD
HandleHelp(
    PCERTOOL_CMD_ARGS pCmdArgs
    );

/* handle.c */
DWORD
VMCAInvokeCommand(
    PCERTOOL_CMD_ARGS pCmdArgs
    );

/* common.c */
DWORD
VMCAInitArgs(
    PCERTOOL_CMD_ARGS *ppCmdArgs
    );

DWORD
VMCAParseArgs(
    int argc,
    char **argv,
    PCERTOOL_CMD_ARGS pCmdArgs
    );

DWORD
ProcessCommand(
    int argc,
    char **argv
    );

//Utility Functions

#define FQDN 1
#define NETBIOSNAME 3

int
GetSleepTime(int secondToSleep);

DWORD
GetMachineName(PSTR *ppMachineName);

DWORD
GetFQDN(PSTR *ppFQDN);

PCSTR
ErrorCodeToName(int code);

VOID
VMCAFreeCmdGenCSR(
    PCERTOOL_CMD_GENCSR pCmdGenCSR
    );

VOID
VMCAFreeCmdGenKey(
    PCERTOOL_CMD_GENKEY pCmdGenKey
    );

VOID
VMCAFreeCmdHelp(
    PCERTOOL_CMD_HELP pCmdHelp
    );

VOID
VMCAFreeConfigData(
    PCERTOOL_CONFIG_DATA pConfig
    );

VOID
VMCAFreeCmdArgs(
    PCERTOOL_CMD_ARGS pCmdArgs
    );

DWORD
VMCADuplicateArgv(
    int argc,
    char* const* argv,
    char*** argvDup
    );

VOID
VMCAFreeArgv(
    int argc,
    char **argv
    );

DWORD
VMCAWriteAllText(
    PCSTR pcszFile,
    PCSTR pcszText
    );

/* help.c */
DWORD
ShowHelp(
    PCSTR pszArg
    );
#endif //__CERT_TOOL_H__
