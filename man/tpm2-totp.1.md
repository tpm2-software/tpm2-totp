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
    Generate a new TOTP seret.
    Possible options: `-b, -N, -p, -P`

  * `calculate`:
    Calculate a TOTP value.
    Possible options: `-N, -t`

  * `reseal`:
    Reseal TOTP secret to new PCRs, banks or values.
    Possible options: `-b, -N, -p, -P`(required)

  * `recover`:
    Recover the TOTP secret and display it again.
    Possible Options: `-N, -P`(required)

  * `clean`:
    Delete the consumed NV index.
    Possible Options: `-N`

## OPTIONS

  * `-b <bank>[,<bank>[,...]]`, `--banks <bank>[,<bank>[,...]]`:
    Selected PCR banks (default: SHA1,SHA256,SHA512)

  * `-h`, `--help`:
    Print help

  * `-N <nvindex>`, `--nvindex <nvindex>`:
    TPM NV index to store data (default: 0x018094AF)

  * `-p <pcr>[,<pcr>[,...]]`, `--pcrs <pcr>[,<pcr>[,...]]`:
    Selected PCR registers (default: 0,2,4,6)

  * `-P <password>`, `--password <password>`:
    Password for the secret (default: none) (commands: generate, recover, reseal)

  * `-t`, `--time`:
    Display the date/time of the TOTP calculation (commands: calculate)

  * `-v`, `--verbose`:
    Print verbose messages

# EXAMPLES

## Setup
The TOTP secret can be generated with and without password. It is recommended to
set a password `-P`in order to enable recovery options. Also the PCRs and PCR
banks can be selected `-p` and `-b`. Default values are PCRs `0,2,4` and all
available banks from the list `SHA1, SHA256, SHA384`.
```
./tpm2-totp generate
./tpm2-totp -P verysecret generate
./tpm2-totp -P verysecret -p 0,1,2,3,4,5,6 generate
./tpm2-totp -p 0,1,2,3,4,5,6 -b SHA1,SHA256 generate #TODO to be implemented
```

## Boot
During boot the TOTP value for the current time, together with the current time
should be shown to the user, eg using plymouth from mkinitrd or from dracut.
The command to be executed is:
```
./tpm2-totp calculate
./tpm2-totp -t calculate
```

## Recovery
In order to recover the QR code:
```
./tpm2-totp -P verysecret recover
```
In order to reseal the secret:
```
./tpm2-totp -P verysecret reseal
./tpm2-totp -P verysecret -p 1,3,5,6 reseal
```

## Deletion
In order to delete the created NV index:
```
./tpm2-totp clean
```

## NV index
All command additionally take the `-N` option to specify the NV index to be
used. By default, 0x018094AF is used and recommended.
```
./tpm2-totp -N 0x01800001 -P verysecret generate
./tpm2-totp -N 0x01800001 calculate
./tpm2-totp -N 0x01800001 -P verysecret recover
./tpm2-totp -N 0x01800001 -P verysecret reseal
```

# RETURNS

0 on success or 1 on failure.

# AUTHOR

Written by Andreas Fuchs.

# COPYRIGHT

tpm2tss is Copyright (C) 2018 Fraunhofer SIT. License BSD 3-clause.

# SEE ALSO

tpm2totp_generateKey(3)

