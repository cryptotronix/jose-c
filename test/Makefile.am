# Copyright (C) 2014-2015 Cryptotronix, LLC.

# This file is part of libcryptoauth.

# libcryptoauth is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# libcryptoauth is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with libcryptoauth.  If not, see <http://www.gnu.org/licenses/>.
TESTS = check_libjosec
TESTS_ENVIRONMENT = $(VALGRIND)
check_PROGRAMS = check_libjosec
check_libjosec_SOURCES = test_jwt.c $(top_builddir)/libjosec.h
check_libjosec_CFLAGS = @CHECK_CFLAGS@ $(JANSSON_CFLAGS) -I$(top_srcdir)/lib $(CRYPTOAUTH_CFLAGS)
check_libjosec_LDADD = ../libjosec-0.1.la @CHECK_LIBS@ $(JANSSON_LIBS) $(top_srcdir)/lib/libgnu.la $(CRYPTOAUTH_LIBS)

bin_PROGRAMS = jwtwrap jwtunwrap
jwtwrap_SOURCES = jwt_wrap.c $(top_builddir)/libjosec.h
jwtwrap_CFLAGS = $(CRYPTOAUTH_CFLAGS) $(JANSSON_CFLAGS) -I$(top_srcdir)/lib -I$(top_builddir)/lib -I$(top_srcdir)/src
jwtwrap_LDADD = ../libjosec-0.1.la $(JANSSON_LIBS) $(CRYPTOAUTH_LIBS) $(top_srcdir)/lib/libgnu.la

jwtunwrap_SOURCES = jwt_unwrap.c $(top_builddir)/libjosec.h
jwtunwrap_CFLAGS = $(CRYPTOAUTH_CFLAGS) $(JANSSON_CFLAGS) -I$(top_srcdir)/lib -I$(top_builddir)/lib -I$(top_srcdir)/src
jwtunwrap_LDADD = ../libjosec-0.1.la $(JANSSON_LIBS) $(CRYPTOAUTH_LIBS) $(top_srcdir)/lib/libgnu.la
