#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019 Jonas Witschel
# All rights reserved.

export LANG=C
export PATH="$PWD:$PATH"

test_script="$(realpath "$1")"

tmp_dir="$(mktemp --directory)"
echo "Switching to temporary directory $tmp_dir"
cd "$tmp_dir"

for attempt in $(seq 9 -1 0); do
    tpm_server_port="$(shuf --input-range 1024-65534 --head-count 1)"
    echo "Starting simulator on port $tpm_server_port"
    tpm_server -port "$tpm_server_port" &
    tpm_server_pid="$!"
    sleep 1

    if ( ss --listening --tcp --ipv4 --processes | grep "$tpm_server_pid" | grep --quiet "$tpm_server_port" &&
         ss --listening --tcp --ipv4 --processes | grep "$tpm_server_pid" | grep --quiet "$(( tpm_server_port + 1 ))" )
    then
        echo "Simulator with PID $tpm_server_pid started successfully"
        break
    else
        echo "Failed to start simulator, the port might be in use"
        kill "$tpm_server_pid"

        if [ "$attempt" -eq 0 ]; then
            echo 'ERROR: Reached maximum number of tries to start simulator, giving up'
            exit 99
        fi
    fi
done

export TPM2TOTP_TCTI="mssim:port=$tpm_server_port"
export TPM2TOOLS_TCTI="$TPM2TOTP_TCTI"

tpm2_startup --clear

echo "Starting $test_script"
"$test_script"
test_status="$?"

kill "$tpm_server_pid"
rm -rf "$tmp_dir"

exit "$test_status"
