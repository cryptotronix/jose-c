# Copyright (C) 2014-2015 Cryptotronix, LLC.

# This file is part of libjosec.

# libjosec is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# libjosec is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with libjosec.  If not, see <http://www.gnu.org/licenses/>.

SUBDIRS = lib . test
AUTOMAKE_OPTIONS = subdir-objects

AM_CFLAGS = -DDATA_DIR=\"$(pkgdatadir)\"

ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

libjosec_la_CPPFLAGS = $(CRYPTO_CFLAGS) $(OPENSSL_CFLAGS) \
                       $(YACL_CFLAGS) $(JANSSON_CFLAGS) \
		       -I$(top_srcdir)/lib $(LIBGCRYPT_CFLAGS)

libjosec_la_LIBADD = $(CRYPTO_LIBS) $(OPENSSL_LIBS) \
                     $(YACL_LIBS) $(JANSSON_LIBS) \
                     lib/libgnu.la $(LIBGCRYPT_LIBS)

if HAVE_GUILE
libjosec_la_CPPFLAGS += $(GUILE_CFLAGS)
libjosec_la_LIBADD += $(GUILE_LIBS)
endif

if BUILD_TOOLS
bin_PROGRAMS = jwt-decode
jwt_decode_SOURCES = src/tools/jwt_decode.c
jwt_decode_CFLAGS = $(JANSSON_CFLAGS) -I$(top_srcdir)/lib
jwt_decode_LDADD = libjosec.la $(JANSSON_LIBS) lib/libgnu.la
endif

lib_LTLIBRARIES = libjosec.la

libjosec_la_SOURCES =	src/jwt.c \
                        src/jwk.c \
			src/base64url.c \
			src/jws.c \
			src/context.c \
			src/hs256.c \
			src/soft_crypto.c \
			src/base64url.h \
                        src/hs256.h \
                        src/jwa.h \
                        src/jwk.h \
                        src/jws.h \
                        src/jwt.h \
                        src/soft_crypto.h \
                        src/jwa.c \
                        src/jwe.c \
                        src/util.c \
                        src/util.h

if HAVE_GUILE
libjosec_la_SOURCES += src/guile/extension.c \
                       src/guile/extension.h
endif

libjosec_la_LDFLAGS = -version-info $(JOSEC_SO_VERSION) -release $(JOSEC_API_VERSION)


josec_includedir = $(includedir)/josec-$(JOSEC_API_VERSION)
nobase_josec_include_HEADERS = libjosec.h

josec_libincludedir = $(libdir)/josec-$(JOSEC_API_VERSION)/include

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = josec.pc

dist_noinst_SCRIPTS = autogen.sh install-sh

EXTRA_DIST =  rpm/josec.spec
