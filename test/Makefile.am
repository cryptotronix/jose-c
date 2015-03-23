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
check_PROGRAMS = check_libjosec
check_libjosec_SOURCES = test_jwt.c $(top_builddir)/libjosec.h
check_libjosec_CFLAGS = @CHECK_CFLAGS@ $(JANSSON_CFLAGS) -I$(top_srcdir)/lib
check_libjosec_LDADD = ../libjosec-0.1.la @CHECK_LIBS@ $(JANSSON_LIBS) /
		       $(top_srcdir)/lib/libgnu.la
