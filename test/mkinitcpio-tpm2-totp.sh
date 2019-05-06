#!/usr/lib/initcpio/busybox ash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019 Jonas Witschel
# All rights reserved.

set -eufx

tpm2-totp generate

. "$(dirname "$(realpath "$0")")"/../dist/initcpio/hooks/tpm2-totp

printf 'a' | run_hook | grep -Pz 'Verify the TOTP \(press any key to continue\):\n\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}: \d{6}' &
grep_pid=$!

# If the read call in run_hook fails, e.g. because some of the non-POSIX options
# are not recognised, we are stuck in an endless loop. Wait at most 10 seconds
# for the loop to finish, and check to exit status of grep.
timeout 10s tail --pid "$grep_pid" --follow /dev/null
wait "$grep_pid"
