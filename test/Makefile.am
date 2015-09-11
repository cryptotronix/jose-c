# Copyright (C) 2014-2015 Cryptotronix, LLC.

# This file is part of jose-c.

# jose-c is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# jose-c is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with jose-c.  If not, see <http://www.gnu.org/licenses/>.
TESTS = check_libjosec
TESTS_ENVIRONMENT = $(VALGRIND)

CFLAGS_TO_ADD = $(YACL_CFLAGS) $(JANSSON_CFLAGS) -I$(top_srcdir)/lib \
                -I$(top_builddir)/lib -I$(top_srcdir)/src $(LIBGCRYPT_CFLAGS)
LIBS_TO_ADD = ../libjosec.la @CHECK_LIBS@ $(JANSSON_LIBS) \
              $(top_srcdir)/lib/libgnu.la $(YACL_LIBS) $(LIBGCRYPT_LIBS)


check_PROGRAMS = check_libjosec leak
check_libjosec_SOURCES = test_jwt.c $(top_builddir)/libjosec.h
check_libjosec_CFLAGS = @CHECK_CFLAGS@ $(CFLAGS_TO_ADD)
check_libjosec_LDADD = $(LIBS_TO_ADD)

# jwtwrap_SOURCES = jwt_wrap.c $(top_builddir)/libjosec.h
# jwtwrap_CFLAGS = $(CFLAGS_TO_ADD)
# jwtwrap_LDADD = $(LIBS_TO_ADD)

# jwtunwrap_SOURCES = jwt_unwrap.c $(top_builddir)/libjosec.h
# jwtunwrap_CFLAGS = $(CFLAGS_TO_ADD)
# jwtunwrap_LDADD = $(LIBS_TO_ADD)

# handshake_SOURCES = handshake.c $(top_builddir)/libjosec.h
# handshake_CFLAGS = $(CFLAGS_TO_ADD)
# handshake_LDADD = $(LIBS_TO_ADD) -lcurl

# jwkutil_SOURCES = jwk_util.c $(top_builddir)/libjosec.h
# jwkutil_CFLAGS = $(CFLAGS_TO_ADD)
# jwkutil_LDADD = $(LIBS_TO_ADD) -lgpg-error

leak_SOURCES = leak.c $(top_builddir)/libjosec.h
leak_CFLAGS = $(CFLAGS_TO_ADD)
leak_LDADD = $(LIBS_TO_ADD)
