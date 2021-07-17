#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2018 Fraunhofer SIT
# All rights reserved.

set -eufx

exit_status=0
tpm2-totp invalid-argument || exit_status=$?
if [ "$exit_status" -ne 1 ]; then
	echo "tpm2-totp should have exit status 1 on invalid arguments!"
	exit 1
fi

tpm2-totp -P abc -p 0,1,2,3,4,5,6 -b SHA1,SHA256 init

# Changing an unselected PCR bank should not affect the TOTP calculation
tpm2_pcrextend 0:sha384=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

tpm2-totp -t show

tpm2_pcrextend 1:sha1=0000000000000000000000000000000000000000

if tpm2-totp -t show; then
    echo "The TOTP was calculated despite a changed PCR state!"
    exit 1
fi

tpm2-totp -P abc recover

# Test reading password from stdin
echo -n 'abc' | tpm2-totp -P - recover

if tpm2-totp -P wrongpassword recover; then
    echo "The secret was recovered despite an incorrect password!"
    exit 1
fi

tpm2-totp -P abc -p 0,1,2,3,4,5,6 -b SHA1,SHA256 reseal

# Changing an unselected PCR bank should not affect the TOTP calculation
tpm2_pcrextend 0:sha384=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

tpm2-totp show

tpm2_pcrextend 1:sha1=0000000000000000000000000000000000000000

if tpm2-totp show; then
    echo "The TOTP was calculated despite a changed PCR state!"
    exit 1
fi

tpm2-totp clean
