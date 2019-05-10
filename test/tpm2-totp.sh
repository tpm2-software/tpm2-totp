#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2018 Fraunhofer SIT
# All rights reserved.

set -eufx

tpm2-totp -P abc -p 0,1,2,3,4,5,6 -b SHA1,SHA256 generate

# Changing an unselected PCR bank should not affect the TOTP calculation
tpm2_pcrextend 0:sha384=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

tpm2-totp -t calculate

tpm2_pcrextend 1:sha1=0000000000000000000000000000000000000000

if tpm2-totp -t calculate; then
    echo "The TOTP was calculated despite a changed PCR state!"
    exit 1
fi

tpm2-totp -P abc recover

tpm2-totp -P abc -p 0,1,2,3,4,5,6 -b SHA1,SHA256 reseal

# Changing an unselected PCR bank should not affect the TOTP calculation
tpm2_pcrextend 0:sha384=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

tpm2-totp calculate

tpm2_pcrextend 1:sha1=0000000000000000000000000000000000000000

if tpm2-totp calculate; then
    echo "The TOTP was calculated despite a changed PCR state!"
    exit 1
fi

tpm2-totp clean
