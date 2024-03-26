[![Linux Build Status](https://github.com/tpm2-software/tpm2-totp/workflows/Linux%20Build%20Status/badge.svg)](https://github.com/tpm2-software/tpm2-totp/actions)
[![Code Coverage](https://codecov.io/gh/tpm2-software/tpm2-totp/branch/master/graph/badge.svg)](https://codecov.io/gh/tpm2-software/tpm2-totp)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/tpm2-software/tpm2-totp.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tpm2-software/tpm2-totp/context:cpp)
[![Coverity Scan](https://scan.coverity.com/projects/22811/badge.svg)](https://scan.coverity.com/projects/tpm2-totp)

# Overview
This is a reimplementation of Matthew Garrett's
[tpmtotp](https://github.com/mjg59/tpmtotp) software for TPM 2.0 using the
[tpm2-tss](https://github.com/tpm2-software/tpm2-tss) software stack. Its
purpose is to attest the trustworthiness of a device against a human using
time-based one-time passwords (TOTP), facilitating the Trusted Platform Module
(TPM) to bind the TOTP secret to the known trustworthy system state. In
addition to the original tpmtotp, given the new capabilities of in-TPM HMAC
calculation, the tpm2-totp's secret HMAC keys do not have to be exported from
the TPM to the CPU's RAM on boot anymore. Another addition is the ability to
rebind an old secret to the current PCRs in case a software component was
changed on purpose, using a user-defined password.

# Operations
## Setup
When the platform is in a known trustworthy state, the user will generate a
tpm2-totp secret that is sealed to the current PCR values of the TPM. The
secret is also exported (e.g. via QR-Code) so it can be recorded in a TOTP
application (e.g. freeotp on Android phones). The secret is also stored inside
the TPM's NV space.

## Boot
During boot the OS sends the current time to the TPM. The TPM checks that the
correct PCR values are present and calculates the HMAC of the time input. This
result is the TOTP value that will be displayed to the user. The user can
compare this value to the TOTP value of his/her external device (e.g. phone) and
thus assert the unalteredness and trustworthiness of his/her device.

## Recovery
If the TOTP secret on the external device gets lost, there is a way to recover
the secret, if a password was set during its generation. In this case the same
QR code will be displayed to the user again.

If an update occurs that changes one of the PCR values (e.g. BIOS or Bootloader)
then the secret can be resealed to the new PCR values using the password. Then
it will be available again on the next boot.

# Build and install instructions
Standard installation using
```
./bootstrap
./configure
make
make install
```
Followed by setting up the initrd, see below.

Instructions on packages needed to build and install tpm2-totp and different
build options are available in the [INSTALL](INSTALL.md) file.

# Initramfs integration
The project includes hooks for [dracut](https://dracut.wiki.kernel.org/),
[initramfs-tools](https://wiki.debian.org/initramfs-tools) and
[mkinitcpio](https://wiki.archlinux.org/index.php/Mkinitcpio) to display
the TOTP during boot using [Plymouth](https://www.freedesktop.org/wiki/Software/Plymouth/).
They are automatically installed if the corresponding tool is found on the
system (also see [INSTALL](INSTALL.md) regarding necessary configuration
options). To use them, install tpm2-totp and initialize a TOTP secret, then enable
the tpm2-totp hook in your initramfs generator and rebuild the initramfs.

# Usage

## Setup
The TOTP secret can be initialized with and without password. It is recommended to
set a password `-P` in order to enable recovery options. Further, it is strongly
recommended to provide the password via stdin, rather than directly as a
command line option, to protect it from other processes, shell history, etc.
Also the PCRs and PCR banks can be selected `-p` and `-b`. Default values are
PCRs `0,2,4` and banks `SHA1, SHA256`.
```
tpm2-totp init

tpm2-totp -P - init
> verysecret<CTRL-D>

# or (recommended)
gpg --decrypt /path/to/password.gpg | tpm2-totp -P - init

# or (discouraged)
tpm2-totp -P verysecret init

tpm2-totp -P - -p 0,1,2,3,4,5,6 init
tpm2-totp -p 0,1,2,3,4,5,6 -b SHA1,SHA256 init
```

## Boot
During boot the TOTP value for the current time, together with the current time
should be shown to the user, e.g. using plymouth from mkinitrd or from dracut.
The command to be executed is:
```
tpm2-totp show
tpm2-totp -t show
```

## Recovery
In order to recover the QR code:
```
tpm2-totp -P - recover
```
In order to reseal the secret:
```
tpm2-totp -P - reseal
tpm2-totp -P - -p 1,3,5,6 reseal
```

## Status
Check enrollment status:
```
tpm2-totp status
```
Tip: try piping the output to e.g. `bat -l yaml -pp` for nice syntax
highlighting or to `yq` for YAML processing.

## Deletion
In order to delete the created NV index:
```
tpm2-totp clean
```

## NV index
All command additionally take the `-N` option to specify the NV index to be
used. By default, 0x018094AF is used and recommended.
```
tpm2-totp -N 0x01800001 -P - init
tpm2-totp -N 0x01800001 show
tpm2-totp -N 0x01800001 -P - recover
tpm2-totp -N 0x01800001 -P - reseal
tpm2-totp -N 0x01800001 status
```

# Limitations
Whilst tpm2-totp provided the added security (in comparison to tpm-totp) that
the key will not leave the TPM during the calculate operation, the time source
is still not trustworthy and thus an attacker might in some situations be able
to calculate a set of TOTP values for the future. Depending on the size of the
possible attack window this can be very large though.

It is not yet possible to specify specific PCR values independent of the
currently set PCR values. This would allow disabling the password-less calculate
operation after booting the device. This makes most sense, once a TSS2 FAPI
is available that will enable an interface to a canonical PCR event log.

Currently, an empty owner password is assumed.
