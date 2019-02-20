# SPDX-License-Identifier: BSD-3
# Copyright (c) 2018 Fraunhofer SIT
# All rights reserved.

AC_PREREQ([2.68])

AC_INIT([tpm2-totp],
        [0.0.1],
        [https://github.com/tpm2-software/tpm2-totp],
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

AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
LT_INIT()

AC_CONFIG_FILES([Makefile])

AX_ADD_COMPILER_FLAG([-std=c99])
AX_ADD_COMPILER_FLAG([-Wall])
AX_ADD_COMPILER_FLAG([-Wextra])
AX_ADD_COMPILER_FLAG([-Wformat-security])
AX_ADD_COMPILER_FLAG([-Werror])
AX_ADD_COMPILER_FLAG([-fstack-protector-all])
AX_ADD_COMPILER_FLAG([-fpic])
AX_ADD_COMPILER_FLAG([-fPIC])

# work around GCC bug #53119
#   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53119
AX_ADD_COMPILER_FLAG([-Wno-missing-braces])

AX_ADD_LINK_FLAG([-Wl,--no-undefined])
AX_ADD_LINK_FLAG([-Wl,-z,noexecstack])
AX_ADD_LINK_FLAG([-Wl,-z,now])
AX_ADD_LINK_FLAG([-Wl,-z,relro])

AX_CODE_COVERAGE

AC_ARG_ENABLE([debug],
            [AS_HELP_STRING([--enable-debug],
                            [build with debug output (default is no)])],
            [enable_debug=$enableval],
            [enable_debug=no])
AS_IF([test "x$enable_debug" != "xno"],
      AC_DEFINE_UNQUOTED([DEBUG], [1], ["Debug output enabled"]))

PKG_PROG_PKG_CONFIG([0.25])
PKG_CHECK_MODULES([TSS2_ESYS],[tss2-esys])
PKG_CHECK_MODULES([QRENCODE],[libqrencode])
PKG_CHECK_MODULES([OATH],[liboath])

AC_PATH_PROG([PANDOC], [pandoc])
AS_IF([test -z "$PANDOC"],
    [AC_MSG_WARN([Required executable pandoc not found, man pages will not be built])])
AM_CONDITIONAL([HAVE_PANDOC],[test -n "$PANDOC"])

AC_ARG_ENABLE([integration],
            [AS_HELP_STRING([--enable-integration],
                            [build integration tests against TPM (default is no)])],
            [enable_integration=$enableval],
            [enable_integration=no])
AM_CONDITIONAL([INTEGRATION], [test "x$enable_integration" != xno])

AC_OUTPUT

AC_MSG_RESULT([
$PACKAGE_NAME $VERSION
    man-pages:  $PANDOC
])
    
