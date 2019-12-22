#!/bin/sh
. /lib/dracut-lib.sh
nvindex="$(getarg rd.tpm2-totp.nvindex)"
printf 'KERNEL=="tpm0", RUN+="/sbin/initqueue --settled --onetime /bin/show-tpm2-totp %s & show_tpm2_totp_pid=$$!"\n' "${nvindex:+--nvindex "$nvindex"}" > /etc/udev/rules.d/80-tpm2-totp.rules
unset nvindex
