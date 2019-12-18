/*
 * Copyright © 2019 VMware, Inc.  All Rights Reserved.
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

int
main(
    int argc,
    char* argv[]
    )
{
    DWORD dwError = 0;
    PCERTOOL_CMD_ARGS pCmdArgs = NULL;

    dwError = VMCAInitArgs(&pCmdArgs);
    BAIL_ON_VMCA_ERROR_NO_LOG(dwError);

    dwError = VMCAParseArgs(argc, argv, pCmdArgs);
    BAIL_ON_VMCA_ERROR_NO_LOG(dwError);

    dwError = VMCAInvokeCommand(pCmdArgs);
    BAIL_ON_VMCA_ERROR_NO_LOG(dwError);

cleanup:
    VMCAFreeCmdArgs(pCmdArgs);
    return dwError;

error:
    HandleHelp(pCmdArgs);
    goto cleanup;
}
