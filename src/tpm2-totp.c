/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2018, Fraunhofer SIT
 * Copyright 2018, Jonas Witschel
 * All rights reserved.
 *******************************************************************************/

#include <tpm2-totp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <getopt.h>
#include <qrencode.h>
#include <tss2/tss2_tctildr.h>

#define VERB(...) if (opt.verbose) fprintf(stderr, __VA_ARGS__)
#define ERR(...) fprintf(stderr, __VA_ARGS__)

#define chkrc(rc, cmd) if (rc != TSS2_RC_SUCCESS) {\
    ERR("ERROR in %s (%s:%i): 0x%08x\n", __func__, __FILE__, __LINE__, rc); cmd; }

#define TPM2TOTP_ENV_TCTI "TPM2TOTP_TCTI"

char *help =
    "Usage: [options] {generate|calculate|reseal|recover|clean}\n"
    "Options:\n"
    "    -h, --help      print help\n"
    "    -b, --banks     Selected PCR banks (default: SHA1,SHA256)\n"
    "    -N, --nvindex   TPM NV index to store data (default: 0x018094AF)\n"
    "    -P, --password  Password for recovery/resealing (default: None)\n"
    "    -p, --pcrs      Selected PCR registers (default: 0,2,4,6)\n"
    "    -t, --time      Show the time used for calculation\n"
    "    -T, --tcti      TCTI to use\n"
    "    -v, --verbose   print verbose messages\n"
    "\n";

static const char *optstr = "hb:N:P:p:tT:v";

static const struct option long_options[] = {
    {"help",     no_argument,       0, 'h'},
    {"banks",    required_argument, 0, 'b'},
    {"nvindex",  required_argument, 0, 'N'},
    {"password", required_argument, 0, 'P'},
    {"pcrs",     required_argument, 0, 'p'},
    {"time",     no_argument,       0, 't'},
    {"tcti",     required_argument, 0, 'T'},
    {"verbose",  no_argument,       0, 'v'},
    {0,          0,                 0,  0 }
};

static struct opt {
    enum { CMD_NONE, CMD_GENERATE, CMD_CALCULATE, CMD_RESEAL, CMD_RECOVER, CMD_CLEAN } cmd;
    int banks;
    int nvindex;
    char *password;
    int pcrs;
    int time;
    char *tcti;
    int verbose;
} opt;

int
parse_banks(char *str, int *banks)
{
    char *token;
    char *saveptr;

    *banks = 0;

    token = strtok_r(str, ",", &saveptr);
    if (!token) {
        return -1;
    }
    while (token) {
        if (strcmp(token, "SHA1") == 0) {
            *banks |= TPM2TOTP_BANK_SHA1;
        } else if (strcmp(token, "SHA256") == 0) {
            *banks |= TPM2TOTP_BANK_SHA256;
        } else if (strcmp(token, "SHA384") == 0) {
            *banks |= TPM2TOTP_BANK_SHA384;
        } else {
            return -1;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    return 0;
}

int
parse_pcrs(char *str, int *pcrs)
{
    char *token;
    char *saveptr;
    char *endptr;
    long pcr;

    *pcrs = 0;

    if (!str) {
        return -1;
    }
    token = strtok_r(str, ",", &saveptr);
    if (!token) {
        return -1;
    }
    while (token) {
        errno = 0;
        pcr = strtoul(token, &endptr, 0);
        if (errno || endptr == token || *endptr != '\0') {
            return -1;
        } else {
            *pcrs |= 1 << pcr;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    return 0;
}

/** Parse and set command line options.
 *
 * This function parses the command line options and sets the appropriate values
 * in the opt struct.
 * @param argc The argument count.
 * @param argv The arguments.
 * @retval 0 on success
 * @retval 1 on failure
 */
int
parse_opts(int argc, char **argv)
{
    /* set the default values */
    opt.cmd = CMD_NONE;
    opt.banks = 0;
    opt.nvindex = 0;
    opt.password = NULL;
    opt.pcrs = 0;
    opt.time = 0;
    opt.verbose = 0;

    /* parse the options */
    int c;
    int opt_idx = 0;
    while (-1 != (c = getopt_long(argc, argv, optstr,
                                  long_options, &opt_idx))) {
        switch(c) {
        case 'h':
            printf("%s", help);
            exit(0);
        case 'b':
            if (parse_banks(optarg, &opt.banks) != 0) {
                ERR("Error parsing banks.\n");
                return -1;
            }
            break;
        case 'N':
            if (sscanf(optarg, "0x%x", &opt.nvindex) != 1
                && sscanf(optarg, "%i", &opt.nvindex) != 1) {
                ERR("Error parsing nvindex.\n");
                return -1;
            }
            break;
        case 'P':
            opt.password = optarg;
            break;
        case 'p':
            if (parse_pcrs(optarg, &opt.pcrs) != 0) {
                ERR("Error parsing pcrs.\n");
                return -1;
            }
            break;
        case 't':
            opt.time = 1;
            break;
        case 'T':
            opt.tcti = optarg;
            break;
        case 'v':
            opt.verbose = 1;
            break;
        default:
            ERR("Unknown option at index %i.\n\n", opt_idx);
            ERR("%s", help);
            return -1;
        }
    }

    /* parse the non-option arguments */
    if (optind >= argc) {
        ERR("Missing command: generate, calculate, reseal, recover, clean.\n\n");
        ERR("%s", help);
        return -1;
    }
    if (!strcmp(argv[optind], "generate")) {
        opt.cmd = CMD_GENERATE;
    } else if (!strcmp(argv[optind], "calculate")) {
        opt.cmd = CMD_CALCULATE;
    } else if (!strcmp(argv[optind], "reseal")) {
        opt.cmd = CMD_RESEAL;
    } else if (!strcmp(argv[optind], "recover")) {
        opt.cmd = CMD_RECOVER;
    } else if (!strcmp(argv[optind], "clean")) {
        opt.cmd = CMD_CLEAN;
    } else {
        ERR("Unknown command: generate, calculate, reseal, recover, clean.\n\n");
        ERR("%s", help);
        return -1;
    }
    optind++;

    if (optind < argc) {
        ERR("Unknown argument provided.\n\n");
        ERR("%s", help);
        return -1;
    }
    return 0;
}

static char *
base32enc(const uint8_t *in, size_t in_size) {
	static unsigned char base32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    size_t i = 0, j = 0;
    size_t out_size = ((in_size + 4) / 5) * 8;
    unsigned char *r = malloc(out_size + 1);

    while (1) {
        r[i++]  = in[j] >> 3 & 0x1F;
        r[i++]  = in[j] << 2 & 0x1F;
        if (++j >= in_size) break; else i--;
        r[i++] |= in[j] >> 6 & 0x1F;
        r[i++]  = in[j] >> 1 & 0x1F;
        r[i++]  = in[j] << 4 & 0x1F;
        if (++j >= in_size) break; else i--;
        r[i++] |= in[j] >> 4 & 0x1F;
        r[i++]  = in[j] << 1 & 0x1F;
        if (++j >= in_size) break; else i--;
        r[i++] |= in[j] >> 7 & 0x1F;
        r[i++]  = in[j] >> 2 & 0x1F;
        r[i++]  = in[j] << 3 & 0x1F;
        if (++j >= in_size) break; else i--;
        r[i++] |= in[j] >> 5 & 0x1F;
        r[i++]  = in[j] & 0x1F;
        if (++j >= in_size) break;
    }
    for (j = 0; j < i; j++) {
        r[j] = base32[r[j]];
    }
    while (i < out_size) {
        r[i++] = '=';
    }
    r[i] = 0;
	return (char *)r;
}

char *
qrencode(const char *url)
{
    QRcode *qrcode = QRcode_encodeString(url, 0/*=version*/, QR_ECLEVEL_L,
                                         QR_MODE_8, 1/*=case*/);
    if (!qrcode) { ERR("QRcode failed."); return NULL; }

    char *qrpic = malloc(/* Margins top / bot*/ 2 * (
                            (qrcode->width+2) * 2 - 2 +
                            strlen("\033[47m%*s\033[0m\n") ) +
                         /* lines */ qrcode->width * (
                            strlen("\033[47m  ") * (qrcode->width + 1) +
                            strlen("\033[47m  \033[0m\n")
                         ) + 1 /* \0 */);
    size_t idx = 0;
    idx += sprintf(&qrpic[idx], "\033[47m%*s\033[0m\n", 2*(qrcode->width+2), "");
    for (int y = 0; y < qrcode->width; y++) {
        idx += sprintf(&qrpic[idx], "\033[47m  ");
        for (int x = 0; x < qrcode->width; x++) {
            if (qrcode->data[y*qrcode->width + x] & 0x01) {
                idx += sprintf(&qrpic[idx], "\033[40m  ");
            } else {
                idx += sprintf(&qrpic[idx], "\033[47m  ");
            }
        }
        idx += sprintf(&qrpic[idx], "\033[47m  \033[0m\n");
    }
    idx += sprintf(&qrpic[idx], "\033[47m%*s\033[0m\n", 2*(qrcode->width+2), "");
    (void)(idx);
    free(qrcode);
    return qrpic;
}

#define URL_PREFIX "otpauth://totp/TPM2-TOTP?secret="

/** Main function
 *
 * This function initializes OpenSSL and then calls the key generation
 * functions.
 * @param argc The argument count.
 * @param argv The arguments.
 * @retval 0 on success
 * @retval 1 on failure
 */
int
main(int argc, char **argv)
{
    int rc;
    uint8_t *secret, *keyBlob, *newBlob;
    size_t secret_size, keyBlob_size, newBlob_size;
    char *base32key, *url, *qrpic;
    uint64_t totp;
    time_t now;
    struct tm now_local;
    char timestr[100] = { 0, };
    TSS2_TCTI_CONTEXT *tcti_context = NULL;

    if (parse_opts(argc, argv) != 0) {
        goto err;
    }

    if (!opt.tcti) {
        opt.tcti = getenv(TPM2TOTP_ENV_TCTI);
    }
    rc = Tss2_TctiLdr_Initialize(opt.tcti, &tcti_context);
    chkrc(rc, goto err);

    switch(opt.cmd) {
    case CMD_GENERATE:

        rc = tpm2totp_generateKey(opt.pcrs, opt.banks, opt.password, tcti_context,
                                  &secret, &secret_size,
                                  &keyBlob, &keyBlob_size);
        chkrc(rc, goto err);

        rc = tpm2totp_storeKey_nv(keyBlob, keyBlob_size, opt.nvindex, tcti_context);
        free(keyBlob);
        chkrc(rc, goto err);

        base32key = base32enc(secret, secret_size);
        url = calloc(1, strlen(base32key) + strlen(URL_PREFIX) + 1);
        sprintf(url, URL_PREFIX "%s", base32key);
        free(base32key);

        qrpic = qrencode(url);
        if (!qrpic) {
            free(url);
            goto err;
        }

        printf("%s\n", qrpic);
        printf("%s\n", url);
        free(qrpic);
        free(url);
        break;
    case CMD_CALCULATE:
        rc = tpm2totp_loadKey_nv(opt.nvindex, tcti_context, &keyBlob, &keyBlob_size);
        chkrc(rc, goto err);

        rc = tpm2totp_calculate(keyBlob, keyBlob_size, tcti_context, &now, &totp);
        free(keyBlob);
        chkrc(rc, goto err);
        if (opt.time) {
            localtime_r(&now, &now_local);
            rc = !strftime(timestr, sizeof(timestr)-1, "%Y-%m-%d %H:%M:%S: ",
                           &now_local);
            chkrc(rc, goto err);
        }
        printf("%s%06" PRIu64, timestr, totp);
        break;
    case CMD_RESEAL:
        rc = tpm2totp_loadKey_nv(opt.nvindex, tcti_context, &keyBlob, &keyBlob_size);
        chkrc(rc, goto err);

        rc = tpm2totp_reseal(keyBlob, keyBlob_size, opt.password, opt.pcrs,
                             opt.banks, tcti_context, &newBlob, &newBlob_size);
        free(keyBlob);
        chkrc(rc, goto err);

        //TODO: Are your sure ?
        rc = tpm2totp_deleteKey_nv(opt.nvindex, tcti_context);
        chkrc(rc, goto err);

        rc = tpm2totp_storeKey_nv(newBlob, newBlob_size, opt.nvindex,
                                  tcti_context);
        free(newBlob);
        chkrc(rc, goto err);
        break;
    case CMD_RECOVER:
        rc = tpm2totp_loadKey_nv(opt.nvindex, tcti_context,
                                 &keyBlob, &keyBlob_size);
        chkrc(rc, goto err);

        rc = tpm2totp_getSecret(keyBlob, keyBlob_size, opt.password, tcti_context,
                                &secret, &secret_size);
        free(keyBlob);
        chkrc(rc, goto err);

        base32key = base32enc(secret, secret_size);
        url = calloc(1, strlen(base32key) + strlen(URL_PREFIX) + 1);
        sprintf(url, URL_PREFIX "%s", base32key);
        free(base32key);

        qrpic = qrencode(url);

        printf("%s\n", qrpic);
        printf("%s\n", url);
        free(qrpic);
        free(url);
        break;
    case CMD_CLEAN:
        //TODO: Are your sure ?
        rc = tpm2totp_deleteKey_nv(opt.nvindex, tcti_context);
        chkrc(rc, goto err);
        break;
    default:
        goto err;
    }

    Tss2_TctiLdr_Finalize(&tcti_context);
    return 0;

err:
    Tss2_TctiLdr_Finalize(&tcti_context);
    return 1;
}
