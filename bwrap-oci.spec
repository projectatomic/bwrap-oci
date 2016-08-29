%global commit0 06ed9c9054db435ae33f0c917a2d5e7d3e40e6fa

Summary: Core execution tool for unprivileged containers
Name: bwrap-oci
Version: 0.1.1
Release: 2%{?dist}
Source0: https://github.com/projectatomic/%{name}/archive/%{name}-%{version}.tar.gz
License: LGPLv2+
URL: https://github.com/projectatomic/bwrap-oci

Requires: bubblewrap
BuildRequires: git
# We always run autogen.sh
BuildRequires: autoconf automake libtool
BuildRequires: json-glib-devel
BuildRequires: libseccomp-devel
BuildRequires: libxslt
BuildRequires: docbook-style-xsl

%description
bwrap-oci uses Bubblewrap to run a container from an OCI spec file.

%prep
%autosetup -Sgit -n %{name}-%{version}

%build
env NOCONFIGURE=1 ./autogen.sh
%configure --disable-silent-rules

make %{?_smp_mflags}

%install
make install DESTDIR=$RPM_BUILD_ROOT INSTALL="install -p -c"
find $RPM_BUILD_ROOT -name '*.la' -delete

%files
%license COPYING
%{_bindir}/bwrap-oci
%{_mandir}/man1/*
