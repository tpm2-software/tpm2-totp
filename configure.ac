# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2018 Fraunhofer SIT
# All rights reserved.

AC_PREREQ([2.68])

AC_INIT([tpm2-totp],
        [0.4.0-dev],
        [https://github.com/tpm2-software/tpm2-totp/issues],
        [],
        [https://github.com/tpm2-software/tpm2-totp])
dnl Avoid setting CFLAGS to anything by default; we use AC_CFLAGS below for this.
: ${CFLAGS=""}

dnl Let's be FHS-conform by default.
if test "$prefix" = '/usr'; then
    test "$sysconfdir" = '${prefix}/etc' && sysconfdir="/etc"
    test "$sharedstatedir" = '${prefix}/com' && sharedstatedir="/var"
    test "$localstatedir" = '${prefix}/var' && localstatedir="/var"
fi

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/tpm2-totp.c])
AC_CONFIG_AUX_DIR([build-aux])

# propagate configure arguments to distcheck
AC_SUBST([DISTCHECK_CONFIGURE_FLAGS],[$ac_configure_args])

AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Wno-portability])
#Backward compatible setting of "silent-rules"
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_MAINTAINER_MODE([enable])

AX_IS_RELEASE([dash-version])
AX_CHECK_ENABLE_DEBUG([info])

AC_USE_SYSTEM_EXTENSIONS

AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
LT_INIT()

PKG_INSTALLDIR()

helpersdir="$libexecdir/tpm2-totp"
AC_SUBST([helpersdir])
AX_RECURSIVE_EVAL([$helpersdir], [HELPERSDIR])
AC_SUBST([HELPERSDIR])

AC_CONFIG_FILES([Makefile Doxyfile dist/tpm2-totp.pc])

AC_ARG_ENABLE([defaultflags],
              [AS_HELP_STRING([--disable-defaultflags],
                              [Disable default preprocessor, compiler, and linker flags.])],,
              [enable_defaultflags=yes])
AS_IF([test "x$enable_defaultflags" = "xyes"],
      [
      AX_ADD_COMPILER_FLAG([-std=c99])
      AX_ADD_COMPILER_FLAG([-Wall])
      AX_ADD_COMPILER_FLAG([-Wextra])
      AX_ADD_COMPILER_FLAG([-Wformat-security])
      AS_IF([test "x$ax_is_release" = "xno"], [AX_ADD_COMPILER_FLAG([-Werror])])
      AX_ADD_COMPILER_FLAG([-fstack-protector-all])
      AX_ADD_COMPILER_FLAG([-fpic])
      AX_ADD_COMPILER_FLAG([-fPIC])
      AX_ADD_COMPILER_FLAG([-O2])
      AX_ADD_FORTIFY_SOURCE

      # work around GCC bug #53119
      #   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53119
      AX_ADD_COMPILER_FLAG([-Wno-missing-braces])

      AX_ADD_LINK_FLAG([-Wl,--no-undefined])
      AX_ADD_LINK_FLAG([-Wl,-z,noexecstack])
      AX_ADD_LINK_FLAG([-Wl,-z,now])
      AX_ADD_LINK_FLAG([-Wl,-z,relro])
      ])

AX_CODE_COVERAGE
m4_ifdef([_AX_CODE_COVERAGE_RULES],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [true])],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [false])])
AX_ADD_AM_MACRO_STATIC([])

PKG_PROG_PKG_CONFIG([0.25])
PKG_CHECK_MODULES([TSS2_ESYS],[tss2-esys])
PKG_CHECK_MODULES([TSS2_MU],[tss2-mu])
PKG_CHECK_MODULES([TSS2_TCTILDR],[tss2-tctildr])
PKG_CHECK_MODULES([TSS2_RC],[tss2-rc])
PKG_CHECK_VAR([TSS2_TCTI_DEVICE_LIBDIR], [tss2-tcti-device], [libdir], ,
              [AC_MSG_ERROR([Required library tss2-tcti-device not found])])
AC_SUBST([TSS2_TCTI_DEVICE_LIBDIR])
PKG_CHECK_MODULES([QRENCODE],[libqrencode])

DX_DOXYGEN_FEATURE(ON)
DX_DOT_FEATURE(OFF)
DX_HTML_FEATURE(OFF)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(ON)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN([$PACKAGE_NAME], [Doxyfile], [doxygen-doc])
AS_IF([test -z "$DX_DOXYGEN"],
    [AC_MSG_WARN([Required executable doxygen not found, man pages will not be built])])
AM_CONDITIONAL([HAVE_DOXYGEN],[test -n "$DX_DOXYGEN"])
AM_CONDITIONAL([HAVE_DOXYGEN_MAN_PAGES],[test -d "${srcdir}/doxygen-doc/man/man3" -o -n "$DX_DOXYGEN"])

AC_PATH_PROG([PANDOC], [pandoc])
AS_IF([test -z "$PANDOC"],
    [AC_MSG_WARN([Required executable pandoc not found, man pages will not be built])])
AM_CONDITIONAL([HAVE_PANDOC],[test -n "$PANDOC"])
AM_CONDITIONAL([HAVE_PANDOC_MAN_PAGES],[test -d "${srcdir}/man/man1" -o -n "$PANDOC"])

AC_ARG_WITH([dracutmodulesdir],
            AS_HELP_STRING([--with-dracutmodulesdir=DIR], [directory for dracut hooks]),,
            [PKG_CHECK_VAR([with_dracutmodulesdir], [dracut], [dracutmodulesdir])])
AM_CONDITIONAL(HAVE_DRACUT, [test -n "$with_dracutmodulesdir" -a "x$with_dracutmodulesdir" != xno])
AM_COND_IF([HAVE_DRACUT], [AC_SUBST([dracutdir], [$with_dracutmodulesdir/70tpm2-totp])])
AC_CONFIG_FILES([dist/dracut/module-setup.sh])

AC_CHECK_PROG([lsinitramfs], [lsinitramfs], [yes])
AC_ARG_WITH([initramfstoolsdir],
            AS_HELP_STRING([--with-initramfstoolsdir=DIR], [directory for initramfs-tools scripts]),,
            [AS_IF([test "x$lsinitramfs" = xyes], [with_initramfstoolsdir=$sysconfdir/initramfs-tools])])
AM_CONDITIONAL(HAVE_INITRAMFSTOOLS, [test -n "$with_initramfstoolsdir" -a "x$with_initramfstoolsdir" != xno])
AM_COND_IF([HAVE_INITRAMFSTOOLS],
           [AC_SUBST([initramfstools_hooksdir], [$with_initramfstoolsdir/hooks])
            AC_SUBST([initramfstools_scriptsdir], [$with_initramfstoolsdir/scripts/init-premount])
])
AC_CONFIG_FILES([dist/initramfs-tools/hooks/tpm2-totp])

AC_CHECK_PROG([mkinitcpio], [mkinitcpio], [yes])
AC_ARG_WITH([mkinitcpiodir],
            AS_HELP_STRING([--with-mkinitcpiodir=DIR], [directory for mkinitcpio hooks]),,
            [AS_IF([test "x$mkinitcpio" = xyes], [with_mkinitcpiodir=$sysconfdir/initcpio])])
AM_CONDITIONAL(HAVE_MKINITCPIO, [test -n "$with_mkinitcpiodir" -a "x$with_mkinitcpiodir" != xno])
AM_COND_IF([HAVE_MKINITCPIO],
           [AC_SUBST([initcpio_installdir], [$with_mkinitcpiodir/install])
            AC_SUBST([initcpio_hooksdir], [$with_mkinitcpiodir/hooks])
           ])
AC_CONFIG_FILES([dist/initcpio/install/tpm2-totp dist/initcpio/install/plymouth-tpm2-totp])

AC_ARG_ENABLE([plymouth],
              AS_HELP_STRING([--disable-plymouth], [Disable plymouth support]))
AS_IF([test "x$enable_plymouth" != "xno"],
      [PKG_CHECK_MODULES([PLY_BOOT_CLIENT], [ply-boot-client],
                         [have_plymouth=yes], [have_plymouth=no])],
      [have_plymouth=no])
AM_CONDITIONAL([HAVE_PLYMOUTH], [test "x$have_plymouth" = "xyes"])
AM_COND_IF([HAVE_PLYMOUTH],
           [PKG_CHECK_VAR([PLYMOUTHPLUGINSDIR], [ply-splash-core], [pluginsdir])
            AC_SUBST([PLYMOUTHPLUGINSDIR])
           ],
           [AS_IF([test "x$enable_plymouth" = "xyes"],
                  [AC_MSG_ERROR([plymouth requested but not found])])
           ])

AC_ARG_WITH([udevdir],
            AS_HELP_STRING([--with-udevdir=DIR], [udev directory]),,
            [PKG_CHECK_VAR([with_udevdir], [udev], [udevdir],, [with_udevdir="$libdir/udev"])])
AC_SUBST([UDEVDIR], [$with_udevdir])

AC_ARG_WITH([systemdsystemunitdir],
            AS_HELP_STRING([--with-systemdsystemunit=DIR], [systemd system unit directory]),,
            [PKG_CHECK_VAR([with_systemdsystemunitdir], [systemd], [systemdsystemunitdir],,
                           [with_systemdsystemunitdir="$libdir/systemd/system"])])
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])

AC_CONFIG_FILES([dist/initcpio/install/sd-plymouth-tpm2-totp dist/plymouth-tpm2-totp.service])

AC_ARG_ENABLE([integration],
            [AS_HELP_STRING([--enable-integration],
                            [build integration tests against TPM])],,
            [enable_integration=no])
AM_CONDITIONAL([INTEGRATION], [test "x$enable_integration" != xno])
AS_IF([test "x$enable_integration" != xno],
      [PKG_CHECK_MODULES([OATH],[liboath])
       AC_CHECK_PROG([swtpm], [swtpm], [yes])
       AC_CHECK_PROG([tpm_server], [tpm_server], [yes])
       AS_IF([test "x$swtpm" != xyes && test "x$tpm_server" != xyes],
             [AC_MSG_ERROR([Integration tests require either the swtpm or the tpm_server executable])])
       AC_CHECK_PROG([realpath], [realpath], [yes])
       AS_IF([test "x$realpath" != xyes],
             [AC_MSG_ERROR([Integration tests require the realpath executable])])
       AC_CHECK_PROG([ss], [ss], [yes])
       AS_IF([test "x$ss" != xyes],
             [AC_MSG_ERROR([Integration tests require the ss executable])])

       AM_COND_IF([HAVE_PLYMOUTH],
             [AC_CHECK_PROG([plymouthd], [plymouthd], [yes])
              AS_IF([test "x$plymouthd" != xyes],
                    [AC_MSG_ERROR([Integration tests require the plymouthd executable])])
              AC_CHECK_PROG([fakeroot], [fakeroot], [yes])
              AS_IF([test "x$fakeroot" != xyes],
                    [AC_MSG_WARN([Executable fakeroot not found, integration tests must be run as root])])
              AC_CHECK_PROG([pgrep], [pgrep], [yes])
              AS_IF([test "x$pgrep" != xyes],
                    [AC_MSG_ERROR([Integration tests require the pgrep executable])])
              AC_CHECK_PROG([timeout], [timeout], [yes])
              AS_IF([test "x$timeout" != xyes],
                    [AC_MSG_ERROR([Integration tests require the timeout executable])])
             ])
      ])

AC_OUTPUT

AC_MSG_RESULT([
$PACKAGE_NAME $VERSION
    doxygen:         $DX_DOXYGEN
    pandoc:          $PANDOC
    dracut:          $with_dracutmodulesdir
    initramfs-tools: $with_initramfstoolsdir
    mkinitcpio:      $with_mkinitcpiodir
    plymouth:        $have_plymouth
])
