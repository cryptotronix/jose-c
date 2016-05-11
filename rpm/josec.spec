#
# Spec file for josec
#
%define _prefix /usr
%define _libdir %{_prefix}/lib64

Name: josec
Version: 0.15.3
Release: 0
Summary: josec library
License: see %{pkgdocdir}/copyright

%define packagebase josec-0.15.3

Group: System Environment/Libraries
Source: %{packagebase}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
Small library for basic crypto primitives

%package devel
Summary: Development files for libjosec
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}
Requires: pkgconfig

%description devel
This package contains the header files, libraries  and documentation needed to
develop applications that use libjosec.

%package static
Summary: Static development files for libjosec
Group: Development/Libraries
Requires: %{name}-devel = %{version}-%{release}

%description static
This package contains static libraries to develop applications that use josec.

%prep
%setup -n %{packagebase}

%build
%configure --with-guile --with-openssl

make %{?_smp_mflags}


%install
rm -rf %{buildroot}
make install-strip DESTDIR=%{buildroot}
# Clean out files that should not be part of the rpm.
%{__rm} -f %{buildroot}/usr/lib64/*.la


%post
/sbin/ldconfig

%preun

%postun
/sbin/ldconfig

%posttrans

%clean
%{__rm} -rf %{buildroot}

%files
%defattr( -, root, root )
#%define _prefix /
/usr/lib64/pkgconfig/josec.pc
/usr/include/josec-*/*
/usr/lib64/*.so
/usr/lib64/*.so.*

%files static
%defattr(-,root,root)
/usr/lib64/*.a
