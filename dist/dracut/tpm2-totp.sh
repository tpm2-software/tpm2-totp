#!/bin/sh
. /lib/dracut-lib.sh
nvindex="$(getarg rd.tpm2-totp.nvindex)"
printf 'KERNEL=="tpm0", RUN+="/sbin/initqueue --settled --onetime /bin/plymouth-tpm2-totp %s &"\n' "${nvindex:+--nvindex "$nvindex"}" > /etc/udev/rules.d/80-tpm2-totp.rules
unset nvindex
