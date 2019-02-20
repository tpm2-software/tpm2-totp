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

TPMSIM=tpm_server

PWD1="abc"

function prereq()
{
    if [ -f NVChip ]; then
        echo "There is a leftover file NVChip in the test directory."
        return 99 #ERROR
    fi

    if killall -0 $(basename $TPMSIM); then
        echo "There is already a tpm_simulator running."
        return 99 #ERROR
    fi

    trap "cleanup" EXIT
}

function prepare()
{
    $TPMSIM &
}

function cleanup()
{
    killall $(basename $TPMSIM) || true
    rm NVChip || true
    echo .
}

function error()
{
    echo "FAILED"
}

function fail()
{
    return 1
}

trap "error" ERR

prereq

prepare

./libtpm2-totp


