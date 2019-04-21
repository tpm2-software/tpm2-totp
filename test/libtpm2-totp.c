/* SPDX-License-Identifier: BSD-3 */
/*******************************************************************************
 * Copyright 2018, Fraunhofer SIT
 * All rights reserved.
 *******************************************************************************/

#include <tpm2-totp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <liboath/oath.h>

#define chkrc(rc, cmd) if (rc != TSS2_RC_SUCCESS) {\
    fprintf(stderr, "ERROR in %s:%i: 0x%08x\n", __FILE__, __LINE__, rc); cmd; }

#define PWD "hallo"

int
main(int argc, char **argv)
{
    (void)(argc); (void)(argv);

    int rc;
    uint8_t *secret, *keyBlob, *newBlob;
    size_t secret_size, keyBlob_size, newBlob_size;
    uint64_t totp;
    char totp_string[7], totp_check[7];
    time_t now;

/**********/

    rc = tpm2totp_generateKey(0x00, 0x00, PWD, NULL,
                              &secret, &secret_size, &keyBlob, &keyBlob_size);
    chkrc(rc, exit(1));

    rc = tpm2totp_calculate(keyBlob, keyBlob_size, NULL, &now, &totp);
    chkrc(rc, exit(1));
    snprintf(&totp_string[0], 7, "%.*ld", 6, totp);

    rc = oath_totp_generate((char *)secret, secret_size, now, 30, 0, 6, &totp_check[0]);
    chkrc(rc, exit(1));

    if (!!memcmp(&totp_string[0], &totp_check[0], 7)) {
        fprintf(stderr, "TPM's %s != %s\n", totp_string, totp_check);
        exit(1);
    }    

/**********/

    rc = tpm2totp_reseal(keyBlob, keyBlob_size, PWD, 0, 0, NULL, &newBlob, &newBlob_size);
    chkrc(rc, exit(1));

    rc = tpm2totp_calculate(newBlob, newBlob_size, NULL, &now, &totp);
    chkrc(rc, exit(1));
    snprintf(&totp_string[0], 7, "%.*ld", 6, totp);

    rc = oath_totp_generate((char *)secret, secret_size, now, 30, 0, 6, &totp_check[0]);
    chkrc(rc, exit(1));

    if (!!memcmp(&totp_string[0], &totp_check[0], 7)) {
        fprintf(stderr, "TPM's %s != %s\n", totp_string, totp_check);
        exit(1);
    }
    free(newBlob);

/**********/

    rc = tpm2totp_getSecret(keyBlob, keyBlob_size, PWD, NULL,
                            &secret, &secret_size);
    chkrc(rc, exit(1));

/**********/

    rc = tpm2totp_storeKey_nv(keyBlob, keyBlob_size, 0, NULL);
    chkrc(rc, exit(1));

    free(keyBlob);
    rc = tpm2totp_loadKey_nv(0, NULL, &keyBlob, &keyBlob_size);
    chkrc(rc, exit(1));

    rc = tpm2totp_deleteKey_nv(0, NULL);
    chkrc(rc, exit(1));

    rc = tpm2totp_storeKey_nv(keyBlob, keyBlob_size, 0, NULL);
    chkrc(rc, exit(1));

    rc = tpm2totp_deleteKey_nv(0, NULL);
    chkrc(rc, exit(1));

/***********/

    free(keyBlob);
    free(secret);
    return 0;
}
