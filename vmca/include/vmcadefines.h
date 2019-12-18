/*
 * Copyright © 2012-2018 VMware, Inc.  All Rights Reserved.
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

#define BAIL_ON_VMCA_ERROR_NO_LOG(dwError)                                  \
    if (dwError)                                                            \
    {                                                                       \
        goto error;                                                         \
    }

#ifndef IsNullOrEmptyString
#define IsNullOrEmptyString(str) (!(str) || !*(str))
#endif

#ifndef VMCA_SAFE_STRING
#define VMCA_SAFE_STRING(str) ((str) ? (str) : "")
#endif

#define VMCA_SAFE_FREE_STRINGA(PTR)    \
    do {                          \
        if ((PTR)) {              \
            VMCAFreeStringA(PTR); \
            (PTR) = NULL;         \
        }                         \
    } while(0)

#define VMCA_SAFE_FREE_MEMORY(PTR)\
    do {                          \
        if ((PTR)) {              \
            VMCAFreeMemory(PTR);  \
            (PTR) = NULL;         \
        }                         \
    } while(0)
