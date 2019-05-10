/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2019, Jonas Witschel
 * All rights reserved.
 *******************************************************************************/

#include "tpm2-totp-tcti.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <tss2/tss2_tcti.h>

#define ERR(...) fprintf(stderr, __VA_ARGS__)

#define TPM2TOTP_ENV_TCTI "TPM2TOTP_TCTI"
#define TSS2_TCTI_SO_FORMAT "libtss2-tcti-%s.so.0"

static struct tcti {
    void *dlhandle;
    TSS2_TCTI_CONTEXT *context;
} tcti;

static void
tcti_parse_string(char *str, char **path, char **conf)
{
    *path = str;
    char *split = strchr(str, ':');
    if (split == NULL) {
        *conf = NULL;
    } else {
        split[0] = '\0';
        *conf = &split[1];
    }
}

static void*
tcti_dlopen(const char *path)
{
    void* dlhandle;

    dlhandle = dlopen(path, RTLD_LAZY);

    if (dlhandle) {
        return dlhandle;
    } else {
        /* Expand <tcti> to libtss2-tcti-<tcti>.so.0 */
        char *dlname;

        int size = snprintf(NULL, 0, TSS2_TCTI_SO_FORMAT, path);
        if (size <= 0) {
            ERR("Could not open TCTI %s.\n", path);
            return NULL;
        }

        dlname = malloc(size+1);
        if (!dlname) {
            ERR("oom");
            return NULL;
        }

        snprintf(dlname, size+1, TSS2_TCTI_SO_FORMAT, path);
        dlhandle = dlopen(dlname, RTLD_LAZY);
        free(dlname);
        return dlhandle;
    }
}

int
tcti_init(char *str, TSS2_TCTI_CONTEXT **context)
{
    *context = tcti.context = NULL;

    /* If no option is given, load from environment or use default TCTI */
    if (!str) {
        str = getenv(TPM2TOTP_ENV_TCTI);
        if (!str) {
            return 0;
        }
    }

    char* path;
    char* conf;
    tcti_parse_string(str, &path, &conf);
    if (path[0] == '\0') {
       ERR("No TCTI given.\n");
       return 1;
    }

    tcti.dlhandle = tcti_dlopen(path);
    if (!tcti.dlhandle) {
        ERR("Could not open TCTI '%s'.\n", path);
        return 1;
    }

    TSS2_TCTI_INFO_FUNC infofn =
        (TSS2_TCTI_INFO_FUNC) dlsym(tcti.dlhandle, TSS2_TCTI_INFO_SYMBOL);
    if (!infofn) {
        dlclose(tcti.dlhandle);
        ERR("Symbol '%s' not found in library '%s'.\n", TSS2_TCTI_INFO_SYMBOL, path);
        return 1;
    }
    const TSS2_TCTI_INFO *info = infofn();
    const TSS2_TCTI_INIT_FUNC init = info->init;

    size_t context_size;
    if (init(NULL, &context_size, conf) != TPM2_RC_SUCCESS) {
        ERR("TCTI init routine failed.\n");
        goto err;
    }

    tcti.context = (TSS2_TCTI_CONTEXT*) malloc(context_size);
    if (!tcti.context) {
        ERR("oom");
        goto err;
    }

    if (init(tcti.context, &context_size, conf) != TPM2_RC_SUCCESS) {
        ERR("TCTI context creation failed.\n");
        goto err;
    }

    *context = tcti.context;
    return 0;

err:
    free(tcti.context);
    tcti.context = NULL;
    dlclose(tcti.dlhandle);
    tcti.dlhandle = NULL;
    return 1;
}

void
tcti_finalize()
{
    if (tcti.context) {
        Tss2_Tcti_Finalize(tcti.context);
        free(tcti.context);
        dlclose(tcti.dlhandle);
    }
}
