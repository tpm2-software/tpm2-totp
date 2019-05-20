# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2018 Fraunhofer SIT
# All rights reserved.

### Initialize global variables used throughout the file ###
INCLUDE_DIRS    = -I$(srcdir)/include -I$(srcdir)/src
ACLOCAL_AMFLAGS = -I m4 --install
AM_CFLAGS       = $(INCLUDE_DIRS) $(EXTRA_CFLAGS) $(TSS2_ESYS_CFLAGS) \
                  $(TSS2_MU_CFLAGS) $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS      = $(EXTRA_LDFLAGS) $(CODE_COVERAGE_LIBS)
AM_LDADD        = $(TSS2_ESYS_LIBS) $(TSS2_MU_LIBS)

# Initialize empty variables to be extended throughout
bin_PROGRAMS =
libexec_PROGRAMS =
noinst_PROGRAMS =
check_PROGRAMS =
include_HEADERS =
lib_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST =
DISTCLEANFILES =
CLEANFILES =
MOSTLYCLEANFILES =

### Add ax_* rules ###
# ax_code_coverage
if AUTOCONF_CODE_COVERAGE_2019_01_06
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean
else
@CODE_COVERAGE_RULES@
endif

### Library ###
lib_LTLIBRARIES += libtpm2-totp.la
include_HEADERS += include/tpm2-totp.h

libtpm2_totp_la_SOURCES = src/libtpm2-totp.c
libtpm2_totp_la_LIBADD = $(AM_LDADD)
libtpm2_totp_la_LDFLAGS = $(AM_LDFLAGS) '(tpm2_totp)'

pkgconfig_DATA = dist/tpm2-totp.pc
DISTCLEANFILES += $(pkgconfig_DATA)

### Executable ###
bin_PROGRAMS += tpm2-totp

tpm2_totp_SOURCES = src/tpm2-totp.c src/tpm2-totp-tcti.c
tpm2_totp_CFLAGS = $(AM_CFLAGS) $(QRENCODE_CFLAGS)
tpm2_totp_LDADD = $(AM_LDADD) $(QRENCODE_LIBS) -ldl libtpm2-totp.la
tpm2_totp_LDFLAGS = $(AM_LDFLAGS)

if PLYMOUTH
libexec_PROGRAMS += plymouth-tpm2-totp
plymouth_tpm2_totp_SOURCES = src/plymouth-tpm2-totp.c src/tpm2-totp-tcti.c
plymouth_tpm2_totp_CFLAGS = $(AM_CFLAGS) $(PLY_BOOT_CLIENT_CFLAGS)
plymouth_tpm2_totp_LDADD = $(AM_LDADD) $(PLY_BOOT_CLIENT_LIBS) -ldl libtpm2-totp.la
plymouth_tpm2_totp_LDFLAGS = $(AM_LDFLAGS)
endif # PLYMOUTH

### Tests ###
TESTS =

if INTEGRATION
TESTS += $(TESTS_SHELL)

if HAVE_MKINITCPIO
TESTS += $(TESTS_MKINITCPIO)
endif # HAVE_MKINITCPIO

if PLYMOUTH
TESTS += $(TESTS_PLYMOUTH)
endif # PLYMOUTH
endif #INTEGRATION
TESTS_SHELL = test/libtpm2-totp.sh \
              test/tpm2-totp.sh
TESTS_MKINITCPIO = test/mkinitcpio-tpm2-totp.sh
TESTS_PLYMOUTH = test/plymouth-tpm2-totp.sh
EXTRA_DIST += $(TESTS_SHELL) $(TESTS_MKINITCPIO) $(TESTS_PLYMOUTH)
TEST_EXTENSIONS = .sh
SH_LOG_COMPILER = $(srcdir)/test/sh_log_compiler.sh
EXTRA_DIST += $(SH_LOG_COMPILER)

if INTEGRATION
check_PROGRAMS += libtpm2-totp

libtpm2_totp_SOURCES = test/libtpm2-totp.c src/tpm2-totp-tcti.c src/tpm2-totp-tcti.h
libtpm2_totp_CFLAGS = $(AM_CFLAGS) $(OATH_CFLAGS)
libtpm2_totp_LDADD = $(AM_LDADD) $(OATH_LIBS) -ldl libtpm2-totp.la
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

if HAVE_MAN_PAGES
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

man/man3/%.3: man/%.3.md
	$(AM_V_GEN)mkdir -p man/man3 && cat $< | $(PANDOC) -s -t man >$@

EXTRA_DIST += \
    man/tpm2-totp.1.md
CLEANFILES += \
    $(man1_MANS)

if HAVE_MKINITCPIO
initcpio_install_DATA = dist/initcpio/install/tpm2-totp
initcpio_hooks_DATA = dist/initcpio/hooks/tpm2-totp
if PLYMOUTH
initcpio_install_DATA += dist/initcpio/install/plymouth-tpm2-totp
initcpio_hooks_DATA += dist/initcpio/hooks/plymouth-tpm2-totp
endif # PLYMOUTH
endif # HAVE_MKINITCPIO
EXTRA_DIST += \
	dist/initcpio/install/tpm2-totp \
	dist/initcpio/hooks/tpm2-totp \
	dist/initcpio/hooks/plymouth-tpm2-totp
