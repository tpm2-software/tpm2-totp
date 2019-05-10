#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019 Jonas Witschel
# All rights reserved.

set -eufx

success_or_timeout() {
    # 124 is the exit status GNU timeout returns when the timeout is reached
    [ "$1" -eq 0 ] || [ "$1" -eq 124 ]
    return $?
}

cleanup() {
   kill "$plymouth_tpm2_totp_pid" || true
   kill "$plymouthd_pid" || true
}

plymouthd_pid=''
plymouth_tpm2_totp_pid=''
trap "cleanup" EXIT

if pgrep plymouthd; then
   echo "ERROR: plymouthd is already running."
   exit 99
fi

plymouth-tpm2-totp --help

exit_status=0
timeout 10s plymouth-tpm2-totp || exit_status=$?
if success_or_timeout "$exit_status"; then
   echo "plymouth-tpm2-totp should fail when plymouthd is not running."
   exit 1
fi

if [ "$EUID" -eq 0 ]; then
    plymouthd --no-daemon &
else
    # plymouthd usually needs root access in order to display the splash screen.
    # Since we are only interested in the messaging infrastructure, attempt to
    # start plymouthd with fakeroot.
    fakeroot plymouthd --no-daemon &
fi
sleep 1

# We need the PID of plymouthd, not the fakeroot PID, so we cannot use $!
plymouthd_pid="$(pgrep plymouthd)"
if [ -z "$plymouthd_pid" ]; then
    echo "ERROR: Failed to start plymouthd."
    exit 99
fi

tpm2-totp --banks SHA256 --pcrs 0 --nvindex 0x018094AF --password abc generate

tpm2_pcrextend 0:sha256=0000000000000000000000000000000000000000000000000000000000000000
exit_status=0
timeout 10s plymouth-tpm2-totp --nvindex 0x018094AF || exit_status=$?
if success_or_timeout "$exit_status"; then
   echo "plymouth-tpm2-totp should fail when the PCR state is changed."
   exit 1
fi

tpm2-totp --nvindex 0x018094AF --password abc reseal

plymouth-tpm2-totp --nvindex 0x018094AF --time &
plymouth_tpm2_totp_pid=$!

# Wait for the TOTP to refresh after 30 seconds
sleep 40

kill "$plymouthd_pid"

# Give plymouth-tpm2-totp some time to quit
timeout 10s tail --pid "$plymouth_tpm2_totp_pid" --follow /dev/null

# plymouthd-tpm2-totp should exit successfully after plymouthd has quit
wait "$plymouth_tpm2_totp_pid"
