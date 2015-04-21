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
## Place generated object files (.o) into the same directory as their source
## files, in order to avoid collisions when non-recursive make is used.
AUTOMAKE_OPTIONS = subdir-objects

## Define the Data dir so we know where our data files are
AM_CFLAGS = -DDATA_DIR=\"$(pkgdatadir)\"

## Additional flags to pass to aclocal when it is invoked automatically at
## make time. The ${ACLOCAL_FLAGS} variable is picked up from the environment
## to provide a way for the user to supply additional arguments.
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

libjosec_@JOSEC_API_VERSION@_la_CPPFLAGS = $(CRYPTOAUTH_CFLAGS) $(XML_CFLAGS) $(JANSSON_CFLAGS) -I$(top_srcdir)/lib $(LIBGCRYPT_CFLAGS)

libjosec_@JOSEC_API_VERSION@_la_LIBADD = $(CRYPTOAUTH_LIBS) $(XML_LIBS) $(JANSSON_LIBS) lib/libgnu.la $(LIBGCRYPT_LIBS)


## Define a libtool archive target "libjosec-@EXAMPLE_API_VERSION@.la", with
## @JOSEC_API_VERSION@ substituted into the generated Makefile at configure
## time.
## The libtool archive file (.la) will be installed into the directory named
## by the predefined variable $(bindir), along with the actual shared library
## file (.so).
lib_LTLIBRARIES = libjosec-@JOSEC_API_VERSION@.la

## Define the source file list for the "libjosec-@JOSEC_API_VERSION@.la"
## target.  Note that @JOSEC_API_VERSION@ is not interpreted by Automake and
## will therefore be treated as if it were literally part of the target name,
## and the variable name derived from that.
## The file extension .cc is recognized by Automake, and makes it produce
## rules which invoke the C++ compiler to produce a libtool object file (.lo)
## from each source file.  Note that it is not necessary to list header files
## which are already listed elsewhere in a _HEADERS variable assignment.
libjosec_@JOSEC_API_VERSION@_la_SOURCES =	src/jwt.c \
						src/jwk.c \
						src/base64url.c \
						src/jws.c \
						src/hs264.c



## Instruct libtool to include ABI version information in the generated shared
## library file (.so).  The library ABI version is defined in configure.ac, so
## that all version information is kept in one place.
libjosec_@JOSEC_API_VERSION@_la_LDFLAGS = -version-info $(JOSEC_SO_VERSION)

## Define the list of public header files and their install location.  The
## nobase_ prefix instructs Automake to not strip the directory part from each
## filename, in order to avoid the need to define separate file lists for each
## installation directory.  This only works if the directory hierarchy in the
## source tree matches the hierarchy at the install location, however.
josec_includedir = $(includedir)/josec-$(JOSEC_API_VERSION)
nobase_josec_include_HEADERS = libjosec.h \
                               src/jwt.h \
			       src/jwk.h \
			       src/hs264.h \
			       src/jws.h \
			       src/base64url.h


## Data files
#dist_pkgdata_DATA = data/atecc108_default.xml

## The generated configuration header is installed in its own subdirectory of
## $(libdir).  The reason for this is that the configuration information put
## into this header file describes the target platform the installed library
## has been built for.  Thus the file must not be installed into a location
## intended for architecture-independent files, as defined by the Filesystem
## Hierarchy Standard (FHS).
## The nodist_ prefix instructs Automake to not generate rules for including
## the listed files in the distribution on 'make dist'.  Files that are listed
## in _HEADERS variables are normally included in the distribution, but the
## configuration header file is generated at configure time and should not be
## shipped with the source tarball.
josec_libincludedir = $(libdir)/josec-$(JOSEC_API_VERSION)/include
#nodist_crypti2c_libinclude_HEADERS = crypti2cconfig.h

## Install the generated pkg-config file (.pc) into the expected location for
## architecture-dependent package configuration information.  Occasionally,
## pkg-config files are also used for architecture-independent data packages,
## in which case the correct install location would be $(datadir)/pkgconfig.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = josec-$(JOSEC_API_VERSION).pc

## Define an independent executable script for inclusion in the distribution
## archive.  However, it will not be installed on an end user's system due to
## the noinst_ prefix.
dist_noinst_SCRIPTS = autogen.sh
