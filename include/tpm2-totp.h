/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2018, Fraunhofer SIT
 * All rights reserved.
 *******************************************************************************/

#ifndef TPM2_TOTP_H
#define TPM2_TOTP_H

#include <stdint.h>
#include <time.h>
#include <tss2/tss2_tcti.h>

#define TPM2TOTP_BANK_SHA1 (1 << 0)
#define TPM2TOTP_BANK_SHA256 (1 << 1)
#define TPM2TOTP_BANK_SHA384 (1 << 2)

int
tpm2totp_generateKey(uint32_t pcrs, uint32_t banks, const char *password,
                     TSS2_TCTI_CONTEXT *tcti_context,
                     uint8_t **secret, size_t *secret_size,
                     uint8_t **keyBlob, size_t *keyBlob_size);

int
tpm2totp_marshal_blob(uint8_t **keyBlob, size_t *keyBlob_size,
                      uint32_t pcrs, uint32_t banks,
                      TPM2B_PUBLIC *keyPublicHmac, TPM2B_PRIVATE *keyPrivateHmac,
                      TPM2B_PUBLIC *keyPublicSeal, TPM2B_PRIVATE *keyPrivateSeal);

int
tpm2totp_unmarshal_blob(const uint8_t *keyBlob, size_t keyBlob_size,
                        uint32_t *pcrs, uint32_t *banks,
                        TPM2B_PUBLIC *keyPublicHmac, TPM2B_PRIVATE *keyPrivateHmac,
                        TPM2B_PUBLIC *keyPublicSeal, TPM2B_PRIVATE *keyPrivateSeal);

int
tpm2totp_reseal(const uint8_t *keyBlob, size_t keyBlob_size,
                const char *password, uint32_t pcrs, uint32_t banks,
                TSS2_TCTI_CONTEXT *tcti_context,
                uint8_t **newBlob, size_t *newBlob_size);

int
tpm2totp_storeKey_nv(const uint8_t *keyBlob, size_t keyBlob_size, uint32_t nv,
                     TSS2_TCTI_CONTEXT *tcti_context);

int
tpm2totp_loadKey_nv(uint32_t nv, TSS2_TCTI_CONTEXT *tcti_context,
                    uint8_t **keyBlob, size_t *keyBlob_size);

int
tpm2totp_deleteKey_nv(uint32_t nv, TSS2_TCTI_CONTEXT *tcti_context);

int
tpm2totp_calculate(const uint8_t *keyBlob, size_t keyBlob_size,
                   TSS2_TCTI_CONTEXT *tcti_context,
                   time_t *now, uint64_t *otp);

int
tpm2totp_getSecret(const uint8_t *keyBlob, size_t keyBlob_size,
                   const char *password, TSS2_TCTI_CONTEXT *tcti_context,
                   uint8_t **secret, size_t *secret_size);

#endif /* TPM2_TOTP_H */
