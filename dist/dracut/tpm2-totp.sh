#!/bin/sh
. /lib/dracut-lib.sh
nvindex="$(getarg rd.tpm2-totp.nvindex)"
export TSS2_LOG
printf 'KERNEL=="tpm0", RUN+="/sbin/initqueue --settled --onetime --env TSS2_LOG=esys+error /bin/plymouth-tpm2-totp %s &"\n' "${nvindex:+--nvindex "$nvindex"}" > /etc/udev/rules.d/80-tpm2-totp.rules
unset nvindex
