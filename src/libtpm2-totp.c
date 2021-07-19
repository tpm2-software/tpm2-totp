/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2018, Fraunhofer SIT
 * All rights reserved.
 *******************************************************************************/

#define _DEFAULT_SOURCE

#include <tpm2-totp.h>

#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>

/* RFC 6238 TOTP defines */
#define TIMESTEPSIZE 30
#define SECRETLEN 20

#define DEFAULT_PCRS (0b000000000000000000010101)
#define DEFAULT_BANKS (0b11)
#define DEFAULT_NV 0x018094AF

const TPM2B_DIGEST ownerauth = { .size = 0 };

#ifdef NDEBUG
#define dbg(m, ...)
#else
#define dbg(m, ...) fprintf(stderr, m "\n", ##__VA_ARGS__)
#endif

#define chkrc(rc, cmd) if (rc != TSS2_RC_SUCCESS) { cmd; }

#define TPM2B_PUBLIC_PRIMARY_TEMPLATE { .size = 0, \
    .publicArea = { \
        .type = TPM2_ALG_ECC, \
        .nameAlg = TPM2_ALG_SHA256, \
        .objectAttributes = ( TPMA_OBJECT_USERWITHAUTH | \
                              TPMA_OBJECT_RESTRICTED | \
                              TPMA_OBJECT_DECRYPT | \
                              TPMA_OBJECT_NODA | \
                              TPMA_OBJECT_FIXEDTPM | \
                              TPMA_OBJECT_FIXEDPARENT | \
                              TPMA_OBJECT_SENSITIVEDATAORIGIN ), \
        .authPolicy = { .size = 0, }, \
        .parameters.eccDetail = { \
            .symmetric = { .algorithm = TPM2_ALG_AES, \
                .keyBits.aes = 128, .mode.aes = TPM2_ALG_CFB, }, \
            .scheme = { .scheme = TPM2_ALG_NULL, .details = {} }, \
            .curveID = TPM2_ECC_NIST_P256, \
            .kdf = { .scheme = TPM2_ALG_NULL, .details = {} }, }, \
        .unique.ecc = { .x.size = 0, .y.size = 0 } \
     } }

#define TPM2B_PUBLIC_KEY_TEMPLATE_UNSEAL { .size = 0, \
    .publicArea = { \
        .type = TPM2_ALG_KEYEDHASH, \
        .nameAlg = TPM2_ALG_SHA256, \
        .objectAttributes = ( TPMA_OBJECT_USERWITHAUTH ), \
        .authPolicy = { .size = 0, .buffer = { 0 } }, \
        .parameters.keyedHashDetail.scheme = { .scheme = TPM2_ALG_NULL, \
            .details = { .hmac = { .hashAlg = TPM2_ALG_SHA1 } } }, \
        .unique.keyedHash = { .size = 0, .buffer = { 0 }, }, \
    } }

#define TPM2B_PUBLIC_KEY_TEMPLATE_HMAC { .size = 0, \
    .publicArea = { \
        .type = TPM2_ALG_KEYEDHASH, \
        .nameAlg = TPM2_ALG_SHA256, \
        .objectAttributes = ( TPMA_OBJECT_SIGN_ENCRYPT ), \
        .authPolicy = { .size = 0, .buffer = { 0 } }, \
        .parameters.keyedHashDetail.scheme = { .scheme = TPM2_ALG_HMAC, \
            .details = { .hmac = { .hashAlg = TPM2_ALG_SHA1 } } }, \
        .unique.keyedHash = { .size = 0, .buffer = { 0 }, }, \
    } }

#define TPM2B_SENSITIVE_CREATE_TEMPLATE { .size = 0, \
        .sensitive = { \
            .userAuth = { .size = 0, .buffer = { 0 } }, \
            .data = { .size = 0, .buffer = { 0 } }, \
        } };

TPM2B_PUBLIC primaryPublic = TPM2B_PUBLIC_PRIMARY_TEMPLATE;
TPM2B_SENSITIVE_CREATE primarySensitive = TPM2B_SENSITIVE_CREATE_TEMPLATE;

TPM2B_DATA allOutsideInfo = { .size = 0, };
TPML_PCR_SELECTION allCreationPCR = { .count = 0 };

TPM2B_AUTH emptyAuth = { .size = 0, };

/** @defgroup tpm2-totp libtpm2-totp
 *  Attest the trustworthiness of a device against a human using time-based one-time passwords.
 *  @{
 */

/** Generate a key.
 *
 * @param[in] pcrs PCRs the key should be sealed against.
 * @param[in] banks PCR banks the key should be sealed against.
 * @param[in] password Optional password to recover or reseal the secret.
 * @param[in] tcti_context Optional TCTI context to select TPM to use.
 * @param[out] secret Generated secret.
 * @param[out] secret_size Size of the secret.
 * @param[out] keyBlob Generated key.
 * @param[out] keyBlob_size Size of the generated key.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int
tpm2totp_generateKey(uint32_t pcrs, uint32_t banks, const char *password,
                     TSS2_TCTI_CONTEXT *tcti_context,
                     uint8_t **secret, size_t *secret_size,
                     uint8_t **keyBlob, size_t *keyBlob_size)
{
    if (secret == NULL || secret_size == NULL ||
        keyBlob == NULL || keyBlob_size == NULL) {
        return -1;
    }

    TPM2B_DIGEST *t, *policyDigest;
    ESYS_CONTEXT *ctx = NULL;
    ESYS_TR primary, session;
    TSS2_RC rc;

    TPMT_SYM_DEF sym = {.algorithm = TPM2_ALG_AES,
                        .keyBits = {.aes = 128},
                        .mode = {.aes = TPM2_ALG_CFB}
    };

    TPM2B_PUBLIC keyInPublicHmac = TPM2B_PUBLIC_KEY_TEMPLATE_HMAC;
    TPM2B_PUBLIC keyInPublicSeal = TPM2B_PUBLIC_KEY_TEMPLATE_UNSEAL;
    TPM2B_SENSITIVE_CREATE keySensitive = TPM2B_SENSITIVE_CREATE_TEMPLATE;
    TPM2B_PUBLIC *keyPublicHmac = NULL;
    TPM2B_PRIVATE *keyPrivateHmac = NULL;
    TPM2B_PUBLIC *keyPublicSeal = NULL;
    TPM2B_PRIVATE *keyPrivateSeal = NULL;

    TPML_PCR_SELECTION *pcrcheck, pcrsel = { .count = 0 };

    if (pcrs == 0) pcrs = DEFAULT_PCRS;
    if (banks == 0) banks = DEFAULT_BANKS;

    if ((banks & TPM2TOTP_BANK_SHA1)) {
        pcrsel.pcrSelections[pcrsel.count].hash = TPM2_ALG_SHA1;
        pcrsel.count++;
    }
    if ((banks & TPM2TOTP_BANK_SHA256)) {
        pcrsel.pcrSelections[pcrsel.count].hash = TPM2_ALG_SHA256;
        pcrsel.count++;
    }
    if ((banks & TPM2TOTP_BANK_SHA384)) {
        pcrsel.pcrSelections[pcrsel.count].hash = TPM2_ALG_SHA384;
        pcrsel.count++;
    }

    for (size_t i = 0; i < pcrsel.count; i++) {
        pcrsel.pcrSelections[i].sizeofSelect = 3;
        pcrsel.pcrSelections[i].pcrSelect[0] = pcrs & 0xff;
        pcrsel.pcrSelections[i].pcrSelect[1] = pcrs >>8 & 0xff;
        pcrsel.pcrSelections[i].pcrSelect[2] = pcrs >>16 & 0xff;
    }

    *secret_size = 0;
    *secret = malloc(SECRETLEN);
    if (!*secret) {
        return -1;
    }

    rc = Esys_Initialize(&ctx, tcti_context, NULL);
    chkrc(rc, goto error);

    rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
    if (rc != TPM2_RC_INITIALIZE) chkrc(rc, goto error);

    while (*secret_size < SECRETLEN) {
        dbg("Calling Esys_GetRandom for %zu bytes", SECRETLEN - *secret_size);
        rc = Esys_GetRandom(ctx,
                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            SECRETLEN - *secret_size, &t);
        chkrc(rc, goto error);

        memcpy(&(*secret)[*secret_size], &t->buffer[0], t->size);
        *secret_size += t->size;
        free(t);
    }

    dbg("Calling Esys_CreatePrimary");
    rc = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &primarySensitive, &primaryPublic,
                            &allOutsideInfo, &allCreationPCR,
                            &primary, NULL, NULL, NULL, NULL);
    chkrc(rc, goto error);

    rc = Esys_PCR_Read(ctx,
                       ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                       &pcrsel, NULL, &pcrcheck, NULL);
    chkrc(rc, goto error);

    if (pcrcheck->count == 0) {
        dbg("No active banks selected");
        return -1;
    }
    free(pcrcheck);

    rc = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    NULL, TPM2_SE_POLICY, &sym, TPM2_ALG_SHA256,
                    &session);
    chkrc(rc, goto error);

    rc = Esys_PolicyPCR(ctx, session,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        NULL, &pcrsel);
    chkrc(rc, Esys_FlushContext(ctx, session); goto error);

    rc = Esys_PolicyGetDigest(ctx, session,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &policyDigest);
    Esys_FlushContext(ctx, session);
    chkrc(rc, goto error);

    keyInPublicHmac.publicArea.authPolicy = *policyDigest;
    free(policyDigest);

    keySensitive.sensitive.data.size = *secret_size;
    memcpy(&keySensitive.sensitive.data.buffer[0], &(*secret)[0],
           *secret_size);

    rc = Esys_Create(ctx, primary,
                     ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                     &keySensitive, &keyInPublicHmac,
                     &allOutsideInfo, &allCreationPCR,
                     &keyPrivateHmac, &keyPublicHmac, NULL, NULL, NULL);
    chkrc(rc, Esys_FlushContext(ctx, primary); goto error);

    if (password && strlen(password) > 0) {
        keySensitive.sensitive.userAuth.size = strlen(password);
        if (keySensitive.sensitive.userAuth.size)
            memcpy(&keySensitive.sensitive.userAuth.buffer[0], password,
                   keySensitive.sensitive.userAuth.size);

        rc = Esys_Create(ctx, primary,
                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         &keySensitive, &keyInPublicSeal,
                         &allOutsideInfo, &allCreationPCR,
                         &keyPrivateSeal, &keyPublicSeal, NULL, NULL, NULL);
        chkrc(rc, Esys_FlushContext(ctx, primary); goto error);
    }

    Esys_FlushContext(ctx, primary);
    Esys_Finalize(&ctx);

    rc = tpm2totp_marshal_blob(keyBlob, keyBlob_size,
                               pcrs, banks,
                               keyPublicHmac, keyPrivateHmac,
                               keyPublicSeal, keyPrivateSeal);
    if (rc != 0) {
        chkrc(rc, goto error);
    }

    return 0;

error:
    free(keyPublicHmac);
    free(keyPrivateHmac);
    free(keyPublicSeal);
    free(keyPrivateSeal);
    Esys_Finalize(&ctx);
    free(*secret);
    *secret = NULL;
    *secret_size = 0;
    return (rc)? (int)rc : -1;
}

/** Marshal keyBlob.
 *
 * @param[out] keyBlob Generated key.
 * @param[out] keyBlob_size Size of the generated key.
 * @param[in] pcrs PCRs the key should be sealed against.
 * @param[in] banks PCR banks the key should be sealed against.
 * @param[in] keyPublicHmac Public TOTP blob.
 * @param[in] keyPrivateHmac Private TOTP blob .
 * @param[in] keyPublicSeal Public resealing blob. Ignored if NULL.
 * @param[in] keyPrivateSeal Private resealing blob. Ignored if NULL.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int
tpm2totp_marshal_blob(uint8_t **keyBlob, size_t *keyBlob_size,
                      uint32_t pcrs, uint32_t banks,
                      TPM2B_PUBLIC *keyPublicHmac, TPM2B_PRIVATE *keyPrivateHmac,
                      TPM2B_PUBLIC *keyPublicSeal, TPM2B_PRIVATE *keyPrivateSeal)
{
    TSS2_RC rc;

    /* determine blob size */
    *keyBlob_size = 4 + 4; /* fixed pcrs and banks size */
    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(keyPublicHmac, NULL, -1, keyBlob_size);
    chkrc(rc, goto error);
    rc = Tss2_MU_TPM2B_PRIVATE_Marshal(keyPrivateHmac, NULL, -1, keyBlob_size);
    chkrc(rc, goto error);
    if (keyPublicSeal != NULL && keyPrivateSeal != NULL) {
        rc = Tss2_MU_TPM2B_PUBLIC_Marshal(keyPublicSeal, NULL, -1, keyBlob_size);
        chkrc(rc, goto error);
        rc = Tss2_MU_TPM2B_PRIVATE_Marshal(keyPrivateSeal, NULL, -1, keyBlob_size);
        chkrc(rc, goto error);
    }

    /* marshal blob */
    *keyBlob = malloc(*keyBlob_size);
    if (*keyBlob == NULL) {
        dbg("Could not allocate memory.");
        *keyBlob_size = 0;
        return -1;
    }

    size_t offset = 0;

    rc = Tss2_MU_UINT32_Marshal(pcrs, *keyBlob, *keyBlob_size, &offset);
    chkrc(rc, goto error_marshall);
    rc = Tss2_MU_UINT32_Marshal(banks, *keyBlob, *keyBlob_size, &offset);
    chkrc(rc, goto error_marshall);
    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(keyPublicHmac, *keyBlob, *keyBlob_size, &offset);
    chkrc(rc, goto error_marshall);
    rc = Tss2_MU_TPM2B_PRIVATE_Marshal(keyPrivateHmac, *keyBlob, *keyBlob_size, &offset);
    chkrc(rc, goto error_marshall);
    if (keyPublicSeal != NULL && keyPrivateSeal != NULL) {
        rc = Tss2_MU_TPM2B_PUBLIC_Marshal(keyPublicSeal, *keyBlob, *keyBlob_size, &offset);
        chkrc(rc, goto error_marshall);
        rc = Tss2_MU_TPM2B_PRIVATE_Marshal(keyPrivateSeal, *keyBlob, *keyBlob_size, &offset);
        chkrc(rc, goto error_marshall);
    }

    return 0;

error_marshall:
    free(*keyBlob);
    *keyBlob = NULL;
    *keyBlob_size = 0;

    return (rc)? (int)rc : -1;

error:
    return (rc)? (int)rc : -1;
}

/** Unmarshal keyBlob.
 *
 * @param[in] keyBlob Key to unmarshal.
 * @param[in] keyBlob_size Size of the key.
 * @param[out] pcrs PCRs the key was sealed against (untrusted).
 * @param[out] banks PCR banks the key was sealed against (untrusted).
 * @param[out] keyPublicHmac Public TOTP blob.
 * @param[out] keyPrivateHmac Private TOTP blob .
 * @param[out] keyPublicSeal Public resealing blob.
 * @param[out] keyPrivateSeal Private resealing blob.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval -20 when no password-protected recovery copy of the secret has been stored.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int
tpm2totp_unmarshal_blob(const uint8_t *keyBlob, size_t keyBlob_size,
                        uint32_t *pcrs, uint32_t *banks,
                        TPM2B_PUBLIC *keyPublicHmac, TPM2B_PRIVATE *keyPrivateHmac,
                        TPM2B_PUBLIC *keyPublicSeal, TPM2B_PRIVATE *keyPrivateSeal)
{
    TSS2_RC rc;
    size_t offset = 0;

    rc = Tss2_MU_UINT32_Unmarshal(keyBlob, keyBlob_size, &offset, pcrs);
    chkrc(rc, goto error);
    rc = Tss2_MU_UINT32_Unmarshal(keyBlob, keyBlob_size, &offset, banks);
    chkrc(rc, goto error);

    rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(keyBlob, keyBlob_size, &offset, keyPublicHmac);
    chkrc(rc, goto error);
    rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(keyBlob, keyBlob_size, &offset, keyPrivateHmac);
    chkrc(rc, goto error);

    if (offset == keyBlob_size) {
        dbg("No unseal blob included.");
        return -20;
    }

    rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(keyBlob, keyBlob_size, &offset, keyPublicSeal);
    chkrc(rc, goto error);
    rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(keyBlob, keyBlob_size, &offset, keyPrivateSeal);
    chkrc(rc, goto error);

    if (offset != keyBlob_size) {
        dbg("bad blob size");
        return -1;
    }

    return 0;

error:
    return (rc)? (int)rc : -1;
}

/** Reseal a key to new PCR values.
 *
 * @param[in] keyBlob Original key.
 * @param[in] keyBlob_size Size of the key.
 * @param[in] password Password of the key.
 * @param[in] pcrs PCRs the key should be sealed against.
 * @param[in] banks PCR banks the key should be sealed against.
 * @param[in] tcti_context Optional TCTI context to select TPM to use.
 * @param[out] newBlob New key.
 * @param[out] newBlob_size Size of the new key.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval -10 on empty password.
 * @retval -20 when no password-protected recovery copy of the secret has been stored.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int
tpm2totp_reseal(const uint8_t *keyBlob, size_t keyBlob_size,
                const char *password, uint32_t pcrs, uint32_t banks,
                TSS2_TCTI_CONTEXT *tcti_context,
                uint8_t **newBlob, size_t *newBlob_size)
{
    if (keyBlob == NULL || !password || newBlob == NULL || newBlob_size == NULL) {
        return -1;
    }
    if (!strlen(password)) {
        dbg("Password required.");
        return -10;
    }

    ESYS_CONTEXT *ctx = NULL;
    ESYS_TR primary = ESYS_TR_NONE, key, session;
    TSS2_RC rc;
    TPM2B_SENSITIVE_DATA *secret2b = NULL;
    TPM2B_AUTH auth;
    TPM2B_DIGEST *policyDigest;

    TPM2B_PUBLIC keyInPublicHmac = TPM2B_PUBLIC_KEY_TEMPLATE_HMAC;
    TPM2B_SENSITIVE_CREATE keySensitive = TPM2B_SENSITIVE_CREATE_TEMPLATE;
    TPM2B_PUBLIC keyPublicSeal = { .size = 0 };
    TPM2B_PRIVATE keyPrivateSeal = { .size = 0 };
    TPM2B_PUBLIC *keyPublicHmac = NULL;
    TPM2B_PRIVATE *keyPrivateHmac = NULL;

    TPML_PCR_SELECTION *pcrcheck, pcrsel = { .count = 0 };

    TPMT_SYM_DEF sym = {.algorithm = TPM2_ALG_AES,
                        .keyBits = {.aes = 128},
                        .mode = {.aes = TPM2_ALG_CFB}
    };

    if (pcrs == 0) pcrs = DEFAULT_PCRS;
    if (banks == 0) banks = DEFAULT_BANKS;

    if ((banks & TPM2TOTP_BANK_SHA1)) {
        pcrsel.pcrSelections[pcrsel.count].hash = TPM2_ALG_SHA1;
        pcrsel.count++;
    }
    if ((banks & TPM2TOTP_BANK_SHA256)) {
        pcrsel.pcrSelections[pcrsel.count].hash = TPM2_ALG_SHA256;
        pcrsel.count++;
    }
    if ((banks & TPM2TOTP_BANK_SHA384)) {
        pcrsel.pcrSelections[pcrsel.count].hash = TPM2_ALG_SHA384;
        pcrsel.count++;
    }

    for (size_t i = 0; i < pcrsel.count; i++) {
        pcrsel.pcrSelections[i].sizeofSelect = 3;
        pcrsel.pcrSelections[i].pcrSelect[0] = pcrs & 0xff;
        pcrsel.pcrSelections[i].pcrSelect[1] = pcrs >>8 & 0xff;
        pcrsel.pcrSelections[i].pcrSelect[2] = pcrs >>16 & 0xff;
    }

    auth.size = strlen(password);
    memcpy(&auth.buffer[0], password, auth.size);

    /* We skip over the pcrs and banks from NV because they are not trustworthy */
    rc = tpm2totp_unmarshal_blob(keyBlob, keyBlob_size,
                                  NULL, NULL,
                                  NULL, NULL,
                                  &keyPublicSeal, &keyPrivateSeal);
    if (rc != 0) {
        chkrc(rc, goto error);
    }


    rc = Esys_Initialize(&ctx, tcti_context, NULL);
    chkrc(rc, goto error);

    rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
    if (rc != TPM2_RC_INITIALIZE) chkrc(rc, goto error);

    rc = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &primarySensitive, &primaryPublic,
                            &allOutsideInfo, &allCreationPCR,
                            &primary, NULL, NULL, NULL, NULL);
    chkrc(rc, goto error);

    rc = Esys_Load(ctx, primary,
                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                   &keyPrivateSeal, &keyPublicSeal,
                   &key);
    chkrc(rc, goto error);

    Esys_TR_SetAuth(ctx, key, &auth);

    rc = Esys_Unseal(ctx, key,
                     ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                     &secret2b);
    Esys_FlushContext(ctx, key);
    chkrc(rc, goto error);

    rc = Esys_PCR_Read(ctx,
                       ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                       &pcrsel, NULL, &pcrcheck, NULL);
    chkrc(rc, goto error);

    if (pcrcheck->count == 0) {
        dbg("No active banks selected");
        return -1;
    }
    free(pcrcheck);

    rc = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    NULL, TPM2_SE_POLICY, &sym, TPM2_ALG_SHA256,
                    &session);
    chkrc(rc, goto error);

    rc = Esys_PolicyPCR(ctx, session,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        NULL, &pcrsel);
    chkrc(rc, Esys_FlushContext(ctx, session); goto error);

    rc = Esys_PolicyGetDigest(ctx, session,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &policyDigest);
    Esys_FlushContext(ctx, session);
    chkrc(rc, goto error);

    keyInPublicHmac.publicArea.authPolicy = *policyDigest;
    free(policyDigest);

    keySensitive.sensitive.data.size = secret2b->size;
    memcpy(&keySensitive.sensitive.data.buffer[0], &secret2b->buffer[0],
           keySensitive.sensitive.data.size);
    free(secret2b);

    rc = Esys_Create(ctx, primary,
                     ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                     &keySensitive, &keyInPublicHmac,
                     &allOutsideInfo, &allCreationPCR,
                     &keyPrivateHmac, &keyPublicHmac, NULL, NULL, NULL);
    chkrc(rc, goto error);
    Esys_FlushContext(ctx, primary);
    Esys_Finalize(&ctx);

    rc = tpm2totp_marshal_blob(newBlob, newBlob_size,
                               pcrs, banks,
                               keyPublicHmac, keyPrivateHmac,
                               &keyPublicSeal, &keyPrivateSeal);
    if (rc != 0) {
        chkrc(rc, goto error);
    }

    free(keyPublicHmac);
    free(keyPrivateHmac);

    return 0;

error:
    free(keyPublicHmac);
    free(keyPrivateHmac);
    if (primary != ESYS_TR_NONE) Esys_FlushContext(ctx, primary);
    Esys_Finalize(&ctx);
    return (rc)? (int)rc : -1;
}

/** Store a key in a NV index.
 *
 * @param[in] keyBlob Key to store to NVRAM.
 * @param[in] keyBlob_size Size of the key.
 * @param[in] nv NV index to store the key.
 * @param[in] tcti_context Optional TCTI context to select TPM to use.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int
tpm2totp_storeKey_nv(const uint8_t *keyBlob, size_t keyBlob_size, uint32_t nv,
                     TSS2_TCTI_CONTEXT *tcti_context)
{
    if (!keyBlob)
        return -1;

    TSS2_RC rc;
    ESYS_CONTEXT *ctx;
    ESYS_TR nvHandle;

    if (!nv) nv = DEFAULT_NV; /* Some random handle from owner space */

    TPM2B_NV_PUBLIC publicInfo = { .size = 0,
        .nvPublic = {
            .nvIndex = nv,
            .nameAlg = TPM2_ALG_SHA1,
            .attributes = (TPMA_NV_OWNERWRITE |
                           TPMA_NV_AUTHWRITE |
                           TPMA_NV_WRITE_STCLEAR |
                           TPMA_NV_READ_STCLEAR |
                           TPMA_NV_AUTHREAD |
                           TPMA_NV_OWNERREAD ),
            .authPolicy = { .size = 0, .buffer = {}, },
            .dataSize = keyBlob_size,
        } };

    TPM2B_MAX_NV_BUFFER blob = { .size = keyBlob_size };
    if (blob.size > sizeof(blob.buffer)) {
        dbg("keyBlob too large");
        return -1;
    }
    memcpy(&blob.buffer[0], keyBlob, blob.size);

    rc = Esys_Initialize(&ctx, tcti_context, NULL);
    chkrc(rc, return rc);

    rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
    if (rc != TPM2_RC_INITIALIZE) chkrc(rc, goto error);

    rc = Esys_NV_DefineSpace(ctx, ESYS_TR_RH_OWNER,
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             &emptyAuth, &publicInfo, &nvHandle);
    chkrc(rc, goto error);

    rc = Esys_NV_Write(ctx, nvHandle, nvHandle,
                       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                       &blob, 0/*=offset*/);
    Esys_TR_Close(ctx, &nvHandle);
    chkrc(rc, goto error);

    Esys_Finalize(&ctx);

    return 0;

error:
    Esys_Finalize(&ctx);

    return (rc)? (int)rc : -1;
}

/** Load a key from a NV index.
 *
 * @param[in] nv NV index of the key.
 * @param[in] tcti_context Optional TCTI context to select TPM to use.
 * @param[out] keyBlob Loaded key.
 * @param[out] keyBlob_size Size of the key.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int
tpm2totp_loadKey_nv(uint32_t nv, TSS2_TCTI_CONTEXT *tcti_context,
                    uint8_t **keyBlob, size_t *keyBlob_size)
{
    TSS2_RC rc;
    ESYS_CONTEXT *ctx;
    ESYS_TR nvHandle;
    TPM2B_MAX_NV_BUFFER *blob;
    TPM2B_NV_PUBLIC *publicInfo;

    if (!nv) nv = DEFAULT_NV; /* Some random handle from owner space */

    rc = Esys_Initialize(&ctx, tcti_context, NULL);
    chkrc(rc, return rc);

    rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
    if (rc != TPM2_RC_INITIALIZE) chkrc(rc, goto error);

    rc = Esys_TR_FromTPMPublic(ctx, nv,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &nvHandle);
    chkrc(rc, goto error);

    rc = Esys_NV_ReadPublic(ctx, nvHandle,
                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            &publicInfo, NULL);
    chkrc(rc, goto error);

    rc = Esys_NV_Read(ctx, nvHandle, nvHandle,
                      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                      publicInfo->nvPublic.dataSize, 0/*=offset*/, &blob);
    Esys_TR_Close(ctx, &nvHandle);
    free(publicInfo);
    chkrc(rc, goto error);

    Esys_Finalize(&ctx);

    *keyBlob_size = blob->size;
    *keyBlob = malloc(blob->size);
    memcpy(*keyBlob, &blob->buffer[0], *keyBlob_size);

    return 0;

error:
    Esys_Finalize(&ctx);

    return (rc)? (int)rc : -1;
}


/** Delete a key from a NV index.
 *
 * @param[in] nv NV index to delete.
 * @param[in] tcti_context Optional TCTI context to select TPM to use.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int
tpm2totp_deleteKey_nv(uint32_t nv, TSS2_TCTI_CONTEXT *tcti_context)
{
    TSS2_RC rc;
    ESYS_CONTEXT *ctx;
    ESYS_TR nvHandle;

    if (!nv) nv = DEFAULT_NV; /* Some random handle from owner space */

    rc = Esys_Initialize(&ctx, tcti_context, NULL);
    chkrc(rc, return rc);

    rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
    if (rc != TPM2_RC_INITIALIZE) chkrc(rc, goto error);

    rc = Esys_TR_FromTPMPublic(ctx, nv,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &nvHandle);
    chkrc(rc, goto error);

    rc = Esys_NV_UndefineSpace(ctx, ESYS_TR_RH_OWNER, nvHandle,
                               ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    chkrc(rc, Esys_TR_Close(ctx, &nvHandle); goto error);

    Esys_Finalize(&ctx);

    return 0;

error:

    Esys_Finalize(&ctx);

    return (rc)? (int)rc : -1;
}

/** Calculate a time-based one-time password for a key.
 *
 * @param[in] keyBlob Key to generate the TOTP.
 * @param[in] keyBlob_size Size of the key.
 * @param[in] tcti_context Optional TCTI context to select TPM to use.
 * @param[out] nowp Current time.
 * @param[out] otp Calculated TOTP.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int
tpm2totp_calculate(const uint8_t *keyBlob, size_t keyBlob_size,
                   TSS2_TCTI_CONTEXT *tcti_context,
                   time_t *nowp, uint64_t *otp)
{
    if (keyBlob == NULL || otp == NULL) {
        return -1;
    }

    ESYS_CONTEXT *ctx = NULL;
    ESYS_TR primary, key, session;
    TSS2_RC rc;
    TPM2B_PUBLIC keyPublic = { .size=0 };
    TPM2B_PRIVATE keyPrivate = { .size=0 };
    TPM2B_DIGEST *output;
    uint32_t pcrs;
    uint32_t banks;
    time_t now;
    uint64_t tmp;
    int offset;

    TPM2B_MAX_BUFFER input;

    TPML_PCR_SELECTION pcrsel = { .count = 0 };

    TPMT_SYM_DEF sym = {.algorithm = TPM2_ALG_AES,
                        .keyBits = {.aes = 128},
                        .mode = {.aes = TPM2_ALG_CFB}
    };

    rc = tpm2totp_unmarshal_blob(keyBlob, keyBlob_size,
                                  &pcrs, &banks,
                                  &keyPublic, &keyPrivate,
                                  NULL, NULL);
    if (rc != 0) {
        chkrc(rc, goto error);
    }

    if ((banks & TPM2TOTP_BANK_SHA1)) {
        pcrsel.pcrSelections[pcrsel.count].hash = TPM2_ALG_SHA1;
        pcrsel.count++;
    }
    if ((banks & TPM2TOTP_BANK_SHA256)) {
        pcrsel.pcrSelections[pcrsel.count].hash = TPM2_ALG_SHA256;
        pcrsel.count++;
    }
    if ((banks & TPM2TOTP_BANK_SHA384)) {
        pcrsel.pcrSelections[pcrsel.count].hash = TPM2_ALG_SHA384;
        pcrsel.count++;
    }

    for (size_t i = 0; i < pcrsel.count; i++) {
        pcrsel.pcrSelections[i].sizeofSelect = 3;
        pcrsel.pcrSelections[i].pcrSelect[0] = pcrs & 0xff;
        pcrsel.pcrSelections[i].pcrSelect[1] = pcrs >>8 & 0xff;
        pcrsel.pcrSelections[i].pcrSelect[2] = pcrs >>16 & 0xff;
    }

    rc = Esys_Initialize(&ctx, tcti_context, NULL);
    chkrc(rc, goto error);

    rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
    if (rc != TPM2_RC_INITIALIZE) chkrc(rc, goto error);

    rc = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &primarySensitive, &primaryPublic,
                            &allOutsideInfo, &allCreationPCR,
                            &primary, NULL, NULL, NULL, NULL);
    chkrc(rc, goto error);

    rc = Esys_Load(ctx, primary,
                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                   &keyPrivate, &keyPublic,
                   &key);
    Esys_FlushContext(ctx, primary);
    chkrc(rc, goto error);

    rc = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    NULL, TPM2_SE_POLICY, &sym, TPM2_ALG_SHA256,
                    &session);
    chkrc(rc, goto error);

    rc = Esys_PolicyPCR(ctx, session,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        NULL, &pcrsel);
    chkrc(rc, Esys_FlushContext(ctx, session); goto error);

    /* Construct the RFC 6238 input */
    now = time(NULL);
    tmp = now / TIMESTEPSIZE;
    tmp = htobe64(tmp);
    input.size = sizeof(tmp);
    memcpy(&input.buffer[0], ((void*)&tmp), input.size);

    rc = Esys_HMAC(ctx, key,
                   session, ESYS_TR_NONE, ESYS_TR_NONE,
                   &input, TPM2_ALG_SHA1, &output);
    Esys_FlushContext(ctx, session);
    Esys_FlushContext(ctx, key);
    chkrc(rc, goto error);

    Esys_Finalize(&ctx);

    if (output->size != 20) {
        free(output);
        goto error;
    }

    /* Perform the RFC 6238 -> RFC 4226 HOTP truncing */
    offset = output->buffer[output->size - 1] & 0x0f;

    *otp = ((uint32_t)output->buffer[offset]   & 0x7f) << 24
         | ((uint32_t)output->buffer[offset+1] & 0xff) << 16
         | ((uint32_t)output->buffer[offset+2] & 0xff) <<  8
         | ((uint32_t)output->buffer[offset+3] & 0xff);
    *otp %= (1000000);

    free(output);

    if (nowp) *nowp = now;

    return 0;
error:
    Esys_Finalize(&ctx);
    return (rc)? (int)rc : -1;
}

/** Recover a secret from a key.
 *
 * @param[in] keyBlob Key to recover the secret from.
 * @param[in] keyBlob_size Size of the key.
 * @param[in] password Password of the key.
 * @param[in] tcti_context Optional TCTI context to select TPM to use.
 * @param[out] secret Recovered secret.
 * @param[out] secret_size Size of the secret.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval -10 on empty password.
 * @retval -20 when no password-protected recovery copy of the secret has been stored.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int
tpm2totp_getSecret(const uint8_t *keyBlob, size_t keyBlob_size,
                   const char *password, TSS2_TCTI_CONTEXT *tcti_context,
                   uint8_t **secret, size_t *secret_size)
{
    if (keyBlob == NULL || !password || secret == NULL || secret_size == NULL) {
        return -1;
    }
    if (!strlen(password)) {
        dbg("Password required.");
        return -10;
    }

    ESYS_CONTEXT *ctx = NULL;
    ESYS_TR primary, key;
    TSS2_RC rc;
    TPM2B_PUBLIC keyPublic = { .size=0 };
    TPM2B_PRIVATE keyPrivate = { .size=0 };
    TPM2B_SENSITIVE_DATA *secret2b;
    TPM2B_AUTH auth;

    auth.size = strlen(password);
    memcpy(&auth.buffer[0], password, auth.size);

    rc = tpm2totp_unmarshal_blob(keyBlob, keyBlob_size,
                                  NULL, NULL,
                                  NULL, NULL,
                                  &keyPublic, &keyPrivate);
    if (rc != 0) {
        chkrc(rc, goto error);
    }

    rc = Esys_Initialize(&ctx, tcti_context, NULL);
    chkrc(rc, goto error);

    rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
    if (rc != TPM2_RC_INITIALIZE) chkrc(rc, goto error);

    rc = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &primarySensitive, &primaryPublic,
                            &allOutsideInfo, &allCreationPCR,
                            &primary, NULL, NULL, NULL, NULL);
    chkrc(rc, goto error);

    rc = Esys_Load(ctx, primary,
                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                   &keyPrivate, &keyPublic,
                   &key);
    Esys_FlushContext(ctx, primary);
    chkrc(rc, goto error);

    Esys_TR_SetAuth(ctx, key, &auth);

    rc = Esys_Unseal(ctx, key,
                     ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                     &secret2b);
    Esys_FlushContext(ctx, key);
    chkrc(rc, goto error);

    Esys_Finalize(&ctx);

    *secret = malloc(secret2b->size);
    if (!*secret) goto error;

    *secret_size = secret2b->size;
    memcpy(&(*secret)[0], &secret2b->buffer[0], *secret_size);

    return 0;
error:
    Esys_Finalize(&ctx);
    return (rc)? (int)rc : -1;
}

/** @} */
