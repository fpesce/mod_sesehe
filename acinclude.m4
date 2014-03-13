#
# PCRE_CHECK
#
AC_DEFUN([PCRE_CHECK],[
	AC_ARG_WITH(
		pcre,
		AC_HELP_STRING([--with-pcre=PATH], [prefix where libpcre is installed default=auto]),
		[pcre_dir=$withval],[pcre_dir=]
	)
	if test "x$pcre_dir" != "x"
	then
	  # If we passed a pcre dir 
	  CFLAGS="$CFLAGS -I$pcre_dir/include"
	  CPPFLAGS="$CPPFLAGS -I$pcre_dir/include"
	  LDFLAGS="$LDFLAGS -L$pcre_dir/lib"
	  LIBS="$LIBS -lpcre"
	else
	  # else check pcre install with pcre-config
	  AC_PATH_PROG(PCRE_CONFIG, pcre-config)	
	  if test "x$PCRE_CONFIG" != "x"
	  then
	    pcre_cflags=`$PCRE_CONFIG --cflags`
	    pcre_libs=`$PCRE_CONFIG --libs`
	    CFLAGS="$CFLAGS $pcre_cflags"
	    CPPFLAGS="$CPPFLAGS $pcre_cflags"
	    LIBS="$LIBS $pcre_libs"
	  else
	    AC_MSG_ERROR([pcre-config program not found, please make sure you installed devel files for libpcre])
	  fi
	fi

	#
	# Make sure we have "pcre.h".  If we don't, it means we probably
	# don't have libpcre, so don't use it.
	#
	AC_CHECK_HEADER(pcre.h,,
	  [
	    if test "x$pcre_dir" != "x"
	    then
	      AC_MSG_ERROR([$pcre_dir not found. Check the value you specified with --with-pcre])
	    else
	      AC_MSG_ERROR([lib pcre not found on the system, you need to specify the pcre directory using --with-pcre])
	    fi
	  ])

	# Trivial compilation test
	AC_CHECK_LIB(pcre, pcre_compile,
	[],
	[
		AC_MSG_ERROR([failed to compile a pcre test program, lib pcre not found.])
	])
])

#
# SSL_CHECK: Search libssl install dir for headers
#
AC_DEFUN([SSL_CHECK], [
	AC_ARG_WITH(ssl, AC_HELP_STRING([--with-ssl=PATH],[prefix where libSSL is installed default=auto]),,)
	AC_MSG_CHECKING([for ssl library])

	for dir in $withval /usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /usr; do
        	ssldir="$dir"

	        if test -f "$dir/include/openssl/ssl.h"; then
			xssldir="$ssldir/include/openssl"
        		found_ssl="yes";
			SSL_CFLAGS="-I$ssldir/include/openssl -L$ssldir/lib";
            		break;
        	fi
		if test -f "$dir/include/ssl.h"; then
            		found_ssl="yes";
			xssldir="$ssldir/include/"
            		SSL_CFLAGS="-I$ssldir/include/ -L$ssldir/lib";
	 	        break
	        fi
	done
	if test x_$found_ssl != x_yes; then
		AC_MSG_RESULT([no])
        	AC_MSG_ERROR([Cannot find ssl libraries, please add --with-ssl=PATH to the configure command.])
    	else
		AC_MSG_RESULT($xssldir)
        	SSL_LIBS="-lssl -lcrypto";
 		AC_DEFINE(HAVE_SSL, [], [enabled if linking with SSL])
	fi

	AC_SUBST(SSL_CFLAGS)
	AC_SUBST(SSL_LIBS)
])

AC_DEFUN([COMPILER_FLAG], [
	AC_MSG_CHECKING([whether compiler accepts $1])
	
	save_CFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS $1"
	
	AC_TRY_COMPILE([ ], [], [flag_ok=yes], [flag_ok=no])
	CFLAGS="$save_CFLAGS"
	
	if test "X$flag_ok" = Xyes ; then
	    $2
	    true
	else
	    $3
	    true
	fi
	AC_MSG_RESULT([$flag_ok])
	])

AC_DEFUN([PATH_APXS], [
	AC_ARG_WITH([apache], AC_HELP_STRING([--with-apache=PATH],[Apache server installation directory]),
		,
		[with_apache="no"]
	)

	if test "$with_apache" != "no"; then
	    apache_dir=$with_apache
	    AC_PATH_PROG([apxs],["`basename $apache_dir/bin/apxs`"],,["`AS_DIRNAME($withval/bin/apxs)`"])
	else
	    AC_ARG_WITH([apxs],AC_HELP_STRING([--with-apxs=PATH],
		    [location of APache eXtenSion tool (APXS)]),
		[AC_PATH_PROG([apxs],["`basename $withval`"],,
			["`AS_DIRNAME($withval)`"])],
		[AC_PATH_PROG([apxs],[apxs],,
			[/usr/sbin:/usr/local/apache2/bin:$PATH])])
	fi

	if test "x$apxs" = 'x'; then
	    AC_MSG_ERROR([apxs missing])
	fi

	apr_major="`$apxs -q APR_VERSION 2>/dev/null | cut -f 1 -d '.'`"
	if test "x$apr_major" == 'x'; then
	    apr_major='0'
	    apr_cfmjr=''
	else
	    apr_cfmjr="${apr_major}-"
	    AC_DEFINE(HAVE_APR_1, 1, [For APR 1])
	fi

	apxs_path="$apxs"
	AC_SUBST([apxs_path])

	modules_dir="`$apxs -q LIBEXECDIR 2>/dev/null`"
	AC_SUBST([modules_dir])
	bins_dir="`$apxs -q BINDIR 2>/dev/null`"
	AC_SUBST([bins_dir])

	aprconfig="`$apxs -q APR_CONFIG 2>/dev/null`"
	apuconfig="`$apxs -q APU_CONFIG 2>/dev/null`"

	if test "x$aprconfig" = 'x'; then
	    AC_PATH_PROG([aprconfig],[apr-${apr_cfmjr}config],,["`$apxs -q BINDIR`:$PATH"])
	fi
	if test "x$apuconfig" = 'x'; then
	    AC_PATH_PROG([apuconfig],[apu-${apr_cfmjr}config],,["`$apxs -q BINDIR`:$PATH"])
	fi
	
	if test "x$aprconfig" = 'x'; then
	    AC_MSG_ERROR([apr-${apr_cfmjr}config missing])
	fi
	if test "x$apuconfig" = 'x'; then
	    AC_MSG_ERROR([apu-${apr_cfmjr}config missing])
	fi

	APACHE_CFLAGS="-I`$apxs -q INCLUDEDIR 2>/dev/null`"
	AC_SUBST([APACHE_CFLAGS])

	APR_CFLAGS="`$aprconfig --cflags`"
	APR_CPPFLAGS="`$aprconfig --cppflags --includes`"
	APR_LTLIBS="`$aprconfig --libs --link-libtool`"
	APR_LIBS="`$aprconfig --libs --link-ld`"
	AC_SUBST([APR_CFLAGS])
	AC_SUBST([APR_CPPFLAGS])
	AC_SUBST([APR_LTLIBS])
	AC_SUBST([APR_LIBS])

	APU_CPPFLAGS="`$apuconfig --includes`"
	APU_LTLIBS="`$apuconfig --libs --link-libtool`"
	APU_LIBS="`$apuconfig --libs --link-ld`"
	AC_SUBST([APU_CPPFLAGS])
	AC_SUBST([APU_LTLIBS])
	AC_SUBST([APU_LIBS])

	# for extra libraries
	EXTRA_LIBS="`$apxs -q EXTRA_LDFLAGS 2>/dev/null`"
	AC_SUBST([EXTRA_LIBS])
	])
