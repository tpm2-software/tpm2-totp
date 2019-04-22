/* SPDX-License-Identifier: BSD-3 */
/*******************************************************************************
 * Copyright 2019, Jonas Witschel
 * All rights reserved.
 *******************************************************************************/

#ifndef TPM2_TOTP_TCTI_H
#define TPM2_TOTP_TCTI_H

#include <tss2/tss2_tcti.h>

int
tcti_init(char *str, TSS2_TCTI_CONTEXT **context);

void
tcti_finalize();

#endif /* TPM2_TOTP_TCTI_H */
