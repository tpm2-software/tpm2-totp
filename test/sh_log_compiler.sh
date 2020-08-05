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

for simulator in 'swtpm' 'tpm_server'; do
    simulator_binary="$(command -v "$simulator")" && break
done
if [ -z "$simulator_binary" ]; then
    echo 'ERROR: No TPM simulator was found on PATH'
    exit 99
fi

for attempt in $(seq 9 -1 0); do
    simulator_port="$(shuf --input-range 1024-65534 --head-count 1)"
    echo "Starting simulator on port $simulator_port"
    case "$simulator_binary" in
        *swtpm) "$simulator_binary" socket --tpm2 --server port="$simulator_port" \
                                           --ctrl type=tcp,port="$(( simulator_port + 1 ))" \
                                           --flags not-need-init --tpmstate dir="$tmp_dir" &;;
        *tpm_server) "$simulator_binary" -port "$simulator_port" &;;
    esac
    simulator_pid="$!"
    sleep 1

    if ( ss --listening --tcp --ipv4 --processes | grep "$simulator_pid" | grep --quiet "$simulator_port" &&
         ss --listening --tcp --ipv4 --processes | grep "$simulator_pid" | grep --quiet "$(( simulator_port + 1 ))" )
    then
        echo "Simulator with PID $simulator_pid started successfully"
        break
    else
        echo "Failed to start simulator, the port might be in use"
        kill "$simulator_pid"

        if [ "$attempt" -eq 0 ]; then
            echo 'ERROR: Reached maximum number of tries to start simulator, giving up'
            exit 99
        fi
    fi
done

case "$simulator_binary" in
    *swtpm) export TPM2TOTP_TCTI="swtpm:port=$simulator_port";;
    *tpm_server) export TPM2TOTP_TCTI="mssim:port=$simulator_port";;
esac
export TPM2TOOLS_TCTI="$TPM2TOTP_TCTI"

tpm2_startup --clear

echo "Starting $test_script"
"$test_script"
test_status="$?"

kill "$simulator_pid"
rm -rf "$tmp_dir"

exit "$test_status"
