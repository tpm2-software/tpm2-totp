# SPDX-License-Identifier: BSD-3
# Copyright (c) 2018 Fraunhofer SIT
# All rights reserved.
#!/bin/bash

echo "TPM tests"

set -eEuf

LANG=C
PS4='$LINENO:'

#Some debug options:
set -x

export TSS2_LOG=all+none
#export TSS2_LOG=esys+trace

PWD1="abc"

function error()
{
    echo "FAILED"
}

trap "error" ERR

libtpm2-totp


