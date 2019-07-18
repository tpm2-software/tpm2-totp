/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2018, Fraunhofer SIT
 * All rights reserved.
 *******************************************************************************/

#include <tpm2-totp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <liboath/oath.h>
#include <tss2/tss2_tctildr.h>

#define chkrc(rc, cmd) if (rc != TSS2_RC_SUCCESS) {\
    fprintf(stderr, "ERROR in %s:%i: 0x%08x\n", __FILE__, __LINE__, rc); cmd; }

#define TPM2TOTP_ENV_TCTI "TPM2TOTP_TCTI"

#define PWD "hallo"

int
main(int argc, char **argv)
{
    (void)(argc); (void)(argv);

    int rc;
    uint8_t *secret = NULL;
    uint8_t *keyBlob = NULL;
    uint8_t *newBlob = NULL;
    size_t secret_size, keyBlob_size, newBlob_size;
    uint64_t totp;
    char totp_string[7], totp_check[7];
    time_t now;
    TSS2_TCTI_CONTEXT *tcti_context;

/**********/

    rc = Tss2_TctiLdr_Initialize(getenv(TPM2TOTP_ENV_TCTI), &tcti_context);
    chkrc(rc, goto err);

/**********/

    rc = tpm2totp_generateKey(0x00, 0x00, PWD, tcti_context,
                              &secret, &secret_size, &keyBlob, &keyBlob_size);
    chkrc(rc, goto err);

    rc = tpm2totp_calculate(keyBlob, keyBlob_size, tcti_context, &now, &totp);
    chkrc(rc, goto err);
    snprintf(&totp_string[0], 7, "%.*ld", 6, totp);

    rc = oath_totp_generate((char *)secret, secret_size, now, 30, 0, 6, &totp_check[0]);
    chkrc(rc, goto err);

    if (!!memcmp(&totp_string[0], &totp_check[0], 7)) {
        fprintf(stderr, "TPM's %s != %s\n", totp_string, totp_check);
        goto err;
    }

/**********/

    rc = tpm2totp_reseal(keyBlob, keyBlob_size, PWD, 0, 0, tcti_context, &newBlob, &newBlob_size);
    chkrc(rc, goto err);

    rc = tpm2totp_calculate(newBlob, newBlob_size, tcti_context, &now, &totp);
    chkrc(rc, goto err);
    snprintf(&totp_string[0], 7, "%.*ld", 6, totp);

    rc = oath_totp_generate((char *)secret, secret_size, now, 30, 0, 6, &totp_check[0]);
    chkrc(rc, goto err);

    if (!!memcmp(&totp_string[0], &totp_check[0], 7)) {
        fprintf(stderr, "TPM's %s != %s\n", totp_string, totp_check);
        goto err;
    }
    free(newBlob);

/**********/

    rc = tpm2totp_getSecret(keyBlob, keyBlob_size, PWD, tcti_context,
                            &secret, &secret_size);
    chkrc(rc, goto err);

/**********/

    rc = tpm2totp_storeKey_nv(keyBlob, keyBlob_size, 0, tcti_context);
    chkrc(rc, goto err);

    free(keyBlob);
    rc = tpm2totp_loadKey_nv(0, tcti_context, &keyBlob, &keyBlob_size);
    chkrc(rc, goto err);

    rc = tpm2totp_deleteKey_nv(0, tcti_context);
    chkrc(rc, goto err);

    rc = tpm2totp_storeKey_nv(keyBlob, keyBlob_size, 0, tcti_context);
    chkrc(rc, goto err);

    rc = tpm2totp_deleteKey_nv(0, tcti_context);
    chkrc(rc, goto err);

/***********/

    free(keyBlob);
    free(secret);
    Tss2_TctiLdr_Finalize(&tcti_context);
    return 0;

err:
    free(keyBlob);
    free(secret);
    Tss2_TctiLdr_Finalize(&tcti_context);
    return 1;
}
