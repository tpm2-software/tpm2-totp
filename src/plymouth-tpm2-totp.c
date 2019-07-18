/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2019, Jonas Witschel
 * All rights reserved.
 *******************************************************************************/

#include <tpm2-totp.h>

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <getopt.h>
#include <ply-boot-client.h>
#include <tss2/tss2_tctildr.h>

#define VERB(...) if (opt.verbose) fprintf(stderr, __VA_ARGS__)
#define ERR(...) fprintf(stderr, __VA_ARGS__)

#define chkrc(rc, cmd) if (rc != TSS2_RC_SUCCESS) {\
    ERR("ERROR in %s (%s:%i): 0x%08x\n", __func__, __FILE__, __LINE__, rc); cmd; }

#define TPM2TOTP_ENV_TCTI "TPM2TOTP_TCTI"

typedef struct {
    ply_boot_client_t *boot_client;
    ply_event_loop_t *event_loop;
    TSS2_TCTI_CONTEXT *tcti_context;
    uint8_t *key_blob;
    size_t key_blob_size;
} state_t;

char *help =
    "Usage: [options]\n"
    "Options:\n"
    "    -h, --help      print help\n"
    "    -N, --nvindex   TPM NV index to store data (default: 0x018094AF)\n"
    "    -t, --time      Show the time used for calculation\n"
    "    -T, --tcti      TCTI to use\n"
    "    -v, --verbose   print verbose messages\n"
    "\n";

static const char *optstr = "hN:tT:v";

static const struct option long_options[] = {
    {"help",     no_argument,       0, 'h'},
    {"nvindex",  required_argument, 0, 'N'},
    {"time",     no_argument,       0, 't'},
    {"tcti",     required_argument, 0, 'T'},
    {"verbose",  no_argument,       0, 'v'},
    {0,          0,                 0,  0 }
};

static struct opt {
    int nvindex;
    int time;
    char *tcti;
    int verbose;
} opt;

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
    opt.nvindex = 0;
    opt.tcti = NULL;
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
        case 'N':
            if (sscanf(optarg, "0x%x", &opt.nvindex) != 1
                && sscanf(optarg, "%i", &opt.nvindex) != 1) {
                ERR("Error parsing nvindex.\n");
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

    if (optind < argc) {
        ERR("Unknown argument provided.\n\n");
        ERR("%s", help);
        return -1;
    }
    return 0;
}

/** Exit the plymouth event loop after plymouth quits.
 *
 * This function is called when plymouth quits after boot and exits the main
 * event loop so that the program quits.
 * @param event_loop The plymouth event loop.
 * @param boot_client The plymouth boot client.
 */
void
on_disconnect(void *event_loop, ply_boot_client_t *boot_client __attribute__((unused)))
{
    ply_event_loop_exit(event_loop, 0);
}

/** Display the TOTP.
 *
 * This function calculates and displays the TOTP using plymouth. If the
 * calcuation is successful, the function is rescheduled in the plymouth event
 * loop to run after the next full 30 seconds, otherwise the event loop is
 * stopped with a non-zero return code.
 * @param state a struct containing the boot client, TCTI context and key.
 * @param event_loop The plymouth event loop.
 */
void
display_totp(state_t *state, ply_event_loop_t *event_loop)
{
    int rc;
    uint64_t totp;
    time_t now;
    char timestr[30] = "";
    char totpstr[40] = "";

    rc = tpm2totp_calculate(state->key_blob, state->key_blob_size,
                            state->tcti_context, &now, &totp);

    if (rc == TSS2_RC_SUCCESS) {
        if (opt.time) {
            if (strftime(timestr, sizeof(timestr)-1, "%F %T: ", localtime(&now)) == 0) {
                timestr[0] = '\0';
            }
        }
        snprintf(totpstr, sizeof(totpstr)-1, "%s%06" PRIu64, timestr, totp);

        ply_boot_client_tell_daemon_to_display_message(state->boot_client, totpstr,
                                                       NULL, NULL, NULL);

        ply_event_loop_watch_for_timeout(event_loop, 30-(now % 30),
                                         (ply_event_loop_timeout_handler_t) display_totp,
                                         state);
    } else {
        ERR("Couldn't calculate TOTP.\n");
        ply_boot_client_tell_daemon_to_display_message(state->boot_client,
                                                       "TPM failure", NULL, NULL, NULL);
        ply_event_loop_exit(event_loop, 1);
    }
}

/** Main function
 *
 * This function connects to plymouth, loads the key from the TPM and calls
 * the function to display the TOTP.
 * @param argc The argument count.
 * @param argv The arguments.
 * @retval 0 on success
 * @retval 1 on failure
 */
int
main(int argc, char **argv)
{
    state_t state = { 0, };
    int rc;

    if (parse_opts(argc, argv) != 0) {
        return 1;
    }

    state.event_loop = ply_event_loop_new();
    state.boot_client = ply_boot_client_new();

    if (!ply_boot_client_connect(state.boot_client, on_disconnect, state.event_loop)) {
        ERR("plymouth daemon not running.\n");
        goto err;
    }

    ply_boot_client_attach_to_event_loop(state.boot_client, state.event_loop);

    if (!opt.tcti) {
        opt.tcti = getenv(TPM2TOTP_ENV_TCTI);
    }
    rc = Tss2_TctiLdr_Initialize(opt.tcti, &state.tcti_context);
    chkrc(rc, goto err);

    rc = tpm2totp_loadKey_nv(opt.nvindex, state.tcti_context, &state.key_blob, &state.key_blob_size);
    chkrc(rc, goto err);

    display_totp(&state, state.event_loop);

    rc = ply_event_loop_run(state.event_loop);

    free(state.key_blob);
    ply_boot_client_free(state.boot_client);
    ply_event_loop_free(state.event_loop);
    Tss2_TctiLdr_Finalize(&state.tcti_context);
    return rc;

err:
    /* The event loop needs to be run once so that it can be freed cleanly */
    ply_event_loop_exit(state.event_loop, 1);
    ply_event_loop_run(state.event_loop);

    free(state.key_blob);
    ply_boot_client_free(state.boot_client);
    ply_event_loop_free(state.event_loop);
    Tss2_TctiLdr_Finalize(&state.tcti_context);
    return 1;
}
