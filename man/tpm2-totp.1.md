% tpm2-totp(1) tpm2-totp | General Commands Manual
%
% DECEMBER 2018

# NAME
**tpm2-totp**(1) -- generate or calculate TPM based TOTPs

# SYNOPSIS

**tpm2-totp** [*options*] <command>

# DESCRIPTION

**tpm2-totp** creates a key inside a TPM 2.0 that can be used to generate
time-based onetime passwords (TOTPs) to demonstrate to the user that a platform
was not altered during his/her abscense and thus still trustworthy.

# ARGUMENTS

The `tpm2-totp` command expects one of five command and provides a set of
options.

## COMMANDS

  * `generate`:
    Generate a new TOTP secret.
    Possible options: `-b`, `-l`, `-N`, `-p`, `-P`, `-T`

  * `calculate`:
    Calculate a TOTP value.
    Possible options: `-N`, `-t`, `-T`

  * `reseal`:
    Reseal TOTP secret to new PCRs, banks or values.
    Possible options: `-b`, `-N`, `-p`, `-P` (required), `-T`

  * `recover`:
    Recover the TOTP secret and display it again.
    Possible Options: `-N`, `-P` (required), `-T`

  * `clean`:
    Delete the consumed NV index.
    Possible Options: `-N`, `-T`

## OPTIONS

  * `-b <bank>[,<bank>[,...]]`, `--banks <bank>[,<bank>[,...]]`:
    Selected PCR banks (default: SHA1,SHA256)

  * `-h`, `--help`:
    Print help

  * `-l`, `--label`:
    Label to use for display in the TOTP authenticator app (default: TPM2-TOTP)

  * `-N <nvindex>`, `--nvindex <nvindex>`:
    TPM NV index to store data (default: 0x018094AF)

  * `-p <pcr>[,<pcr>[,...]]`, `--pcrs <pcr>[,<pcr>[,...]]`:
    Selected PCR registers (default: 0,2,4,6)

  * `-P <password>`, `--password <password>`:
    Password for the secret (default: none) (commands: generate, recover, reseal)

  * `-t`, `--time`:
    Display the date/time of the TOTP calculation (commands: calculate)

  * `-T <tcti-name>[:<tcti-config>]`, `--tcti <tcti-name>[:<tcti-config>]`:
    Select the TCTI to use. *tcti-name* is the name of the TCTI library.
    If present, the configuration string *tcti-config* is passed verbatim to the
    chosen TCTI library.

    The TCTI can additionally be specified using the environment variable
    `TPM2TOTP_TCTI`. If both the command line option and the environment
    variable are present, the command line option is used.

    If no TCTI is specified, the default TCTI configured on the system is used.

  * `-v`, `--verbose`:
    Print verbose messages

# EXAMPLES

## Setup
The TOTP secret can be generated with and without password. It is recommended to
set a password `-P`in order to enable recovery options. Also the PCRs and PCR
banks can be selected `-p` and `-b`. Default values are PCRs `0,2,4` and
banks `SHA1, SHA256`.
```
tpm2-totp generate
tpm2-totp -P verysecret generate
tpm2-totp -P verysecret -p 0,1,2,3,4,5,6 generate
tpm2-totp -p 0,1,2,3,4,5,6 -b SHA1,SHA256 generate
```

## Boot
During boot the TOTP value for the current time, together with the current time
should be shown to the user, e.g. using plymouth from mkinitrd or from dracut.
The command to be executed is:
```
tpm2-totp calculate
tpm2-totp -t calculate
```

## Recovery
In order to recover the QR code:
```
tpm2-totp -P verysecret recover
```
In order to reseal the secret:
```
tpm2-totp -P verysecret reseal
tpm2-totp -P verysecret -p 1,3,5,6 reseal
```

## Deletion
In order to delete the created NV index:
```
tpm2-totp clean
```

## NV index
All command additionally take the `-N` option to specify the NV index to be
used. By default, 0x018094AF is used and recommended.
```
tpm2-totp -N 0x01800001 -P verysecret generate
tpm2-totp -N 0x01800001 calculate
tpm2-totp -N 0x01800001 -P verysecret recover
tpm2-totp -N 0x01800001 -P verysecret reseal
```

## TCTI configuration
All commands take the `-T` option or the `TPM2TOTP_TCTI` environment variable
to specify the TCTI to be used. If the TCTI is not specified explicitly, the
default TCTI configured on the system is used. To e.g. use the TPM simulator
bound to a given port, use
```
tpm2-totp -T mssim:port=2321 generate
```

# RETURNS

0 on success or 1 on failure.

# AUTHOR

Written by Andreas Fuchs.

# COPYRIGHT

tpm2tss is Copyright (C) 2018 Fraunhofer SIT. License BSD 3-clause.

# SEE ALSO

tpm2totp_generateKey(3)
