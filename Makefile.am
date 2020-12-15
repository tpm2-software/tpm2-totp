# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2018 Fraunhofer SIT
# All rights reserved.

-include $(top_srcdir)/git.mk

### Initialize global variables used throughout the file ###
INCLUDE_DIRS    = -I$(srcdir)/include -I$(srcdir)/src
ACLOCAL_AMFLAGS = -I m4 --install
AM_CFLAGS       = $(INCLUDE_DIRS) $(EXTRA_CFLAGS) $(TSS2_ESYS_CFLAGS) \
                  $(TSS2_MU_CFLAGS) $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS      = $(EXTRA_LDFLAGS) $(CODE_COVERAGE_LIBS)
AM_LDADD        = $(TSS2_ESYS_LIBS) $(TSS2_MU_LIBS)

AM_DISTCHECK_CONFIGURE_FLAGS = --with-dracutmodulesdir='$$(libdir)/dracut/modules.d'

# Initialize empty variables to be extended throughout
bin_PROGRAMS =
libexec_PROGRAMS =
helpers_PROGRAMS =
noinst_PROGRAMS =
check_PROGRAMS =
include_HEADERS =
lib_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST =
DISTCLEANFILES =
CLEANFILES =
MOSTLYCLEANFILES =
MAINTAINERCLEANFILES = \
    $(DIST_ARCHIVES) \
    AUTHORS
GITIGNOREFILES = \
    $(GITIGNORE_MAINTAINERCLEANFILES_TOPLEVEL) \
    $(GITIGNORE_MAINTAINERCLEANFILES_MAKEFILE_IN) \
    $(GITIGNORE_MAINTAINERCLEANFILES_M4_LIBTOOL) \
    aminclude_static.am \
    m4/ax_ac_append_to_file.m4 \
    m4/ax_ac_print_to_file.m4 \
    m4/ax_add_am_macro_static.m4 \
    m4/ax_add_fortify_source.m4 \
    m4/ax_am_macros_static.m4 \
    m4/ax_check_compile_flag.m4 \
    m4/ax_check_enable_debug.m4 \
    m4/ax_check_gnu_make.m4 \
    m4/ax_check_link_flag.m4 \
    m4/ax_code_coverage.m4 \
    m4/ax_file_escapes.m4 \
    m4/ax_is_release.m4 \
    m4/ax_prog_doxygen.m4 \
    m4/ax_recursive_eval.m4 \
    m4/pkg.m4

### Add ax_* rules ###
# ax_code_coverage
if AUTOCONF_CODE_COVERAGE_2019_01_06
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean
else
@CODE_COVERAGE_RULES@
endif

# ax_prog_doxygen
@DX_RULES@
MOSTLYCLEANFILES += $(DX_CLEANFILES)

### Library ###
lib_LTLIBRARIES += libtpm2-totp.la
include_HEADERS += include/tpm2-totp.h

libtpm2_totp_la_SOURCES = src/libtpm2-totp.c
libtpm2_totp_la_LIBADD = $(AM_LDADD)
libtpm2_totp_la_LDFLAGS = $(AM_LDFLAGS) '(tpm2_totp)'

pkgconfig_DATA = dist/tpm2-totp.pc

### Executable ###
bin_PROGRAMS += tpm2-totp

tpm2_totp_SOURCES = src/tpm2-totp.c
tpm2_totp_CFLAGS = $(AM_CFLAGS) $(TSS2_TCTILDR_CFLAGS) $(TSS2_RC_CFLAGS) $(QRENCODE_CFLAGS)
tpm2_totp_LDADD = $(AM_LDADD) $(TSS2_TCTILDR_LIBS) $(TSS2_RC_LIBS) $(QRENCODE_LIBS) libtpm2-totp.la
tpm2_totp_LDFLAGS = $(AM_LDFLAGS)

if HAVE_PLYMOUTH
helpers_PROGRAMS += plymouth-tpm2-totp
plymouth_tpm2_totp_SOURCES = src/plymouth-tpm2-totp.c
plymouth_tpm2_totp_CFLAGS = $(AM_CFLAGS) $(TSS2_TCTILDR_CFLAGS) $(PLY_BOOT_CLIENT_CFLAGS)
plymouth_tpm2_totp_LDADD = $(AM_LDADD) $(TSS2_TCTILDR_LIBS) $(PLY_BOOT_CLIENT_LIBS) libtpm2-totp.la
plymouth_tpm2_totp_LDFLAGS = $(AM_LDFLAGS)
endif # HAVE_PLYMOUTH

### Tests ###
TESTS =

if INTEGRATION
TESTS += $(TESTS_SHELL)

if HAVE_PLYMOUTH
TESTS += $(TESTS_PLYMOUTH)
endif # HAVE_PLYMOUTH
endif #INTEGRATION
TESTS_SHELL = test/libtpm2-totp.sh \
              test/tpm2-totp.sh
TESTS_PLYMOUTH = test/plymouth-tpm2-totp.sh
EXTRA_DIST += $(TESTS_SHELL) $(TESTS_PLYMOUTH)
TEST_EXTENSIONS = .sh
SH_LOG_COMPILER = $(srcdir)/test/sh_log_compiler.sh
EXTRA_DIST += $(SH_LOG_COMPILER)

if INTEGRATION
check_PROGRAMS += libtpm2-totp

libtpm2_totp_SOURCES = test/libtpm2-totp.c
libtpm2_totp_CFLAGS = $(AM_CFLAGS) $(TSS2_TCTILDR_CFLAGS) $(OATH_CFLAGS)
libtpm2_totp_LDADD = $(AM_LDADD) $(TSS2_TCTILDR_LIBS) $(OATH_LIBS) libtpm2-totp.la
libtpm2_totp_LDFLAGS = $(AM_LDFLAGS) $(OATH_LDFLAGS)
endif #INTEGRATION

# Adding user and developer information
EXTRA_DIST += \
    CHANGELOG.md \
    CONTRIBUTING.md \
    INSTALL.md \
    LICENSE \
    README.md

# Generate the AUTHORS file from git log
AUTHORS:
	$(AM_V_GEN)git log --format='%aN <%aE>' | \
			grep -v 'users.noreply.github.com' | sort -u > $@
EXTRA_DIST += AUTHORS
CLEANFILES += AUTHORS

if HAVE_PANDOC_MAN_PAGES
### Man Pages
man1_MANS = \
    man/man1/tpm2-totp.1
endif

if HAVE_PANDOC
# If pandoc is enabled, we want to generate the manpages for the dist tarball
EXTRA_DIST += \
    $(man1_MANS)

else
# If pandoc is not enabled, we want to complain that you need pandoc for make dist,
# so hook the target and complain.
dist-hook:
	@(>&2 echo "You do not have pandoc, a requirement for the distribution of manpages")
	@exit 1
endif

man/man1/%.1: man/%.1.md
	$(AM_V_GEN)mkdir -p man/man1 && cat $< | $(PANDOC) -s -t man >$@

EXTRA_DIST += \
    man/tpm2-totp.1.md
CLEANFILES += \
    $(man1_MANS)

if HAVE_DOXYGEN_MAN_PAGES
man3_MANS = doxygen-doc/man/man3/tpm2-totp.3
endif # HAVE_DOXYGEN_MAN_PAGES

if HAVE_DOXYGEN
$(man3_MANS): doxygen-doc
EXTRA_DIST += $(man3_MANS)
else # HAVE_DOXYGEN
dist-hook:
	@(>&2 echo "You do not have doxygen, a requirement for the distribution of manpages")
	@exit 1
endif # HAVE_DOXYGEN

### initramfs hooks ###

EXTRA_DIST += dist/show-tpm2-totp

if HAVE_DRACUT
helpers_SCRIPTS = dist/show-tpm2-totp
dracut_SCRIPTS = dist/dracut/module-setup.sh dist/dracut/show-tpm2-totp.sh \
                 dist/dracut/cleanup-tpm2-totp.sh
dracut_DATA = dist/dracut/README
endif # HAVE_DRACUT
EXTRA_DIST += dist/dracut/show-tpm2-totp.sh dist/dracut/cleanup-tpm2-totp.sh dist/dracut/README

if HAVE_INITRAMFSTOOLS
if HAVE_PLYMOUTH
initramfstools_hooks_SCRIPTS = dist/initramfs-tools/hooks/tpm2-totp
initramfstools_scripts_SCRIPTS = dist/initramfs-tools/scripts/init-premount/tpm2-totp
endif # HAVE_PLYMOUTH
endif # HAVE_INITRAMFSTOOLS
EXTRA_DIST += dist/initramfs-tools/scripts/init-premount/tpm2-totp

if HAVE_MKINITCPIO
helpers_SCRIPTS = dist/show-tpm2-totp
initcpio_install_DATA = dist/initcpio/install/tpm2-totp
initcpio_hooks_DATA = dist/initcpio/hooks/tpm2-totp
if HAVE_PLYMOUTH
initcpio_install_DATA += dist/initcpio/install/plymouth-tpm2-totp dist/initcpio/install/sd-plymouth-tpm2-totp
initcpio_hooks_DATA += dist/initcpio/hooks/plymouth-tpm2-totp

systemdsystemunit_DATA = dist/plymouth-tpm2-totp.service
install-data-hook:
	mkdir -p $(DESTDIR)$(systemdsystemunitdir)/sysinit.target.wants && \
	cd $(DESTDIR)$(systemdsystemunitdir)/sysinit.target.wants && \
	$(LN_S) ../plymouth-tpm2-totp.service
endif # HAVE_PLYMOUTH
endif # HAVE_MKINITCPIO
EXTRA_DIST += dist/initcpio/hooks/tpm2-totp dist/initcpio/hooks/plymouth-tpm2-totp
