AUTOMAKE_OPTIONS = foreign dist-bzip2
CLEANFILES = *~ src/*~

MAINTAINERCLEANFILES = aclocal.m4 Makefile.in compile config.guess config.sub \
		       configure depcomp install-sh ltmain.sh missing
DISTCHECK_CONFIGURE_FLAGS = "--with-apxs=@apxs_path@"

EXTRA_DIST =

## This is the shared library to be built
lib_LTLIBRARIES = mod_sesehe.la

mod_sesehe_la_SOURCES = src/mod_sesehe.c

# CFLAGS is for additional C compiler flags
mod_sesehe_la_CFLAGS = @APR_CFLAGS@ -Wall -Werror @APACHE_CFLAGS@ @SSL_CFLAGS@

# CPPFLAGS is for -I and -D options (involving C preprocessor)
mod_sesehe_la_CPPFLAGS = @APR_CPPFLAGS@ @APU_CPPFLAGS@ -I$(top_srcdir)/src/

# LDADD and LIBADD are for linking libraries, -L, -l, -dlopen and -dlpreopen options
mod_sesehe_la_LIBADD = @APR_LTLIBS@ @APU_LTLIBS@ @SSL_LIBS@

# LDFLAGS is for additional linker flags
mod_sesehe_la_LDFLAGS = -module @APR_LTLIBS@ @APU_LTLIBS@ @SSL_LIBS@

## Module installation
install: all
	@echo
	@echo "Performing DSO installation."
	@echo
	$(INSTALL) -d @modules_dir@
	$(INSTALL) .libs/@PACKAGE@.so @modules_dir@/
	@echo
	@echo "Now don't forget to edit your main config and add"
	@echo "    LoadModule @PACKAGE@_module modules/@PACKAGE@.so"
	@echo
