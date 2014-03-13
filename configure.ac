AC_PREREQ(2.52)

# Required initializer
AC_INIT([mod_sesehe], m4_normalize(m4_include([VERSION])), [francois.pesce@gmail.com])

# Automake initialization
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)

dnl can autoconf find the source ?
AC_CONFIG_SRCDIR([src/mod_sesehe.c])
AC_CONFIG_HEADER([src/config.h])

# Add a test for a compiler.
AC_HEADER_STDC

AC_PROG_CC

AM_PROG_LIBTOOL

# Specify Apache's apxs path
PATH_APXS

# Checking Lib pcre configuration
PCRE_CHECK

# Checking SSL configuration
SSL_CHECK

# Allow running test suites if check was found on system
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

USER_CFLAGS=$CFLAGS
CFLAGS=""
AC_SUBST(USER_CFLAGS)

PWD=`pwd`
ABS_TOP_SRCDIR=$PWD$top_srcdir
AC_SUBST(ABS_TOP_SRCDIR)

# Write config.status and the Makefile
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
