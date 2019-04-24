/* SPDX-License-Identifier: BSD-3 */
/*******************************************************************************
 * Copyright 2019, Fraunhofer SIT
 * All rights reserved.
 *******************************************************************************/

#include <inttypes.h>

#include <gtk/gtk.h>
#include <qrencode.h>
#include <tpm2-totp.h>

#define _STR(A) #A
#define _XSTR(A) _STR(A)

#define URL_PREFIX "otpauth://totp/TPM2-TOTP?secret="
#define NVINDEX 0

#define bindsignal(x) gtk_builder_add_callback_symbol(builder, _XSTR(x), G_CALLBACK(x))

#define ERR(...) fprintf(stderr, __VA_ARGS__)

#define chkrc(rc, cmd) if (rc != TSS2_RC_SUCCESS) {\
    ERR("ERROR in %s (%s:%i): 0x%08x\n", __func__, __FILE__, __LINE__, rc); cmd; }

GtkBuilder *builder;
static gint timer = 0;
static gboolean timer_running = FALSE;

static char *
base32enc(const guchar *in, size_t in_size) {
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

void
spinner(gboolean show)
{
    GtkWidget *spinner = GTK_WIDGET(gtk_builder_get_object(builder, "spinner"));
    if (show)
        gtk_widget_show(spinner);
    else
        gtk_widget_hide(spinner);
}

void
showview(const char *view)
{
    GtkWidget *child = GTK_WIDGET(gtk_builder_get_object(builder, view));
    GtkStack *views = GTK_STACK(gtk_builder_get_object(builder, "views"));
    gtk_stack_set_visible_child(views, child);
    spinner(FALSE);
}
void
setview(GtkButton *sender)
{
    const gchar *sender_name = gtk_widget_get_name(GTK_WIDGET(sender));
    showview(sender_name);
}

void
generate()
{
    int rc, pcrs = 0, banks = 0, n_channels, rowstride, size;
    char *url, *base32key;
    QRcode *qrcode;
    GdkPixbuf *image, *scaled;
    GtkImage *qrcodeimage;
    guchar *secret, *keyBlob, *pixels;
    size_t secret_size, keyBlob_size;

    GtkEntry *password;

    password = GTK_ENTRY(gtk_builder_get_object(builder,
                            "generatepassword"));

    rc = tpm2totp_generateKey(pcrs, banks,
                              gtk_entry_get_text(password),
                              NULL,
                              &secret, &secret_size,
                              &keyBlob, &keyBlob_size);
    chkrc(rc, return);

    rc = tpm2totp_storeKey_nv(keyBlob, keyBlob_size, NVINDEX, NULL);
    free(keyBlob);
    chkrc(rc, return);

    base32key = base32enc(secret, secret_size);
    url = calloc(1, strlen(base32key) + strlen(URL_PREFIX) + 1);
    sprintf(url, URL_PREFIX "%s", base32key);
    free(base32key);

    qrcode = QRcode_encodeString(url, 0/*=version*/, QR_ECLEVEL_L,
                                         QR_MODE_8, 1/*=case*/);
    if (!qrcode) { exit(1); }
    /* Note: qrcodes are quadratic. Thus qrcode objects do not have ->height */

    image = gdk_pixbuf_new(GDK_COLORSPACE_RGB, FALSE, 8,
                                      qrcode->width, qrcode->width);
    if (!image) { exit(1); }
    n_channels = gdk_pixbuf_get_n_channels (image);
    rowstride = gdk_pixbuf_get_rowstride (image);
    pixels = gdk_pixbuf_get_pixels (image);

    for (int y = 0; y < qrcode->width; y++) {
        for (int x = 0; x < qrcode->width; x++) {
            if (qrcode->data[y*qrcode->width + x] & 0x01) {
                memset(pixels + y * rowstride + x * n_channels, 0x00, n_channels);
            } else {
                memset(pixels + y * rowstride + x * n_channels, 0xff, n_channels);
            }
        }
    }

    qrcodeimage = GTK_IMAGE(gtk_builder_get_object(builder, "qrcodeimage"));

    size = gtk_widget_get_allocated_width(GTK_WIDGET(qrcodeimage));
    if (size > gtk_widget_get_allocated_height(GTK_WIDGET(qrcodeimage)))
        size = gtk_widget_get_allocated_height(GTK_WIDGET(qrcodeimage));

    printf("size: %i\n", size);

    size = 600;
    size -= size % qrcode->width;
    scaled = gdk_pixbuf_scale_simple(image, size, size, GDK_INTERP_NEAREST);

    gtk_image_set_from_pixbuf(qrcodeimage, scaled);

    showview("qrcode");
}

static void
delete()
{
    int rc = tpm2totp_deleteKey_nv(NVINDEX, NULL);
    chkrc(rc, exit(1));
}

gint
updatestatus(G_GNUC_UNUSED gpointer data)
{
    int rc;
    char text[100];
    uint64_t totp;
    time_t now;
    char timestr[100] = { 0, };
    uint8_t *keyBlob;
    size_t keyBlob_size;

    GtkLabel *label = GTK_LABEL(gtk_builder_get_object(builder, "totp"));
    rc = tpm2totp_loadKey_nv(NVINDEX, NULL, &keyBlob, &keyBlob_size);
    chkrc(rc, gtk_label_set_text(label, "Not active"); return FALSE);

    rc = tpm2totp_calculate(keyBlob, keyBlob_size, NULL, &now, &totp);
    free(keyBlob);
    chkrc(rc, return FALSE);
    rc = !strftime (timestr, sizeof(timestr)-1, "%Y-%m-%d %H:%M:%S: ",
                    localtime (&now));
    chkrc(rc, return FALSE);

    snprintf(text, sizeof(text) - 1, "%s%06" PRIu64, timestr, totp);
    gtk_label_set_text(label, text);
    spinner(FALSE);

    return TRUE;
}

static void
activate (GtkApplication *app, G_GNUC_UNUSED gpointer user_data)
{
    GtkWindow *window;

    builder = gtk_builder_new_from_file("./src/gtpm2-totp.ui");
    bindsignal(setview);
    bindsignal(generate);
    bindsignal(delete);
    gtk_builder_connect_signals(builder, NULL);
    window = GTK_WINDOW(gtk_builder_get_object(builder, "mainwindow"));
    gtk_window_set_application(window, app);
    gtk_window_present(window);

    updatestatus(NULL);
    if (!timer_running) {
        timer = g_timeout_add (10*1000, updatestatus, NULL);
        timer_running = TRUE;
    }
}

int
main(int argc, char *argv[])
{
    g_autoptr(GtkApplication) app = NULL;
    int status;

    app = gtk_application_new("org.gnome.gtpm2-tss", G_APPLICATION_FLAGS_NONE);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);

    return status;
}
