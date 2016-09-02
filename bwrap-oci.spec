Summary: Run OCI containers with bubblewrap
Name: bwrap-oci
Version: 0.1.1
%global rel git
Release: %{rel}%{?dist}
Source0: %{url}/archive/%{name}-%{version}-%{rel}.tar.gz
License: LGPLv2+
URL: https://github.com/projectatomic/bwrap-oci

Requires: bubblewrap
# We always run autogen.sh
BuildRequires: autoconf automake libtool
BuildRequires: pkgconfig(json-glib-1.0)
BuildRequires: libseccomp-devel
BuildRequires: libxslt
BuildRequires: bubblewrap
BuildRequires: docbook-style-xsl
BuildRequires: gcc
BuildRequires: pkgconfig(gio-unix-2.0)

%description
bwrap-oci uses Bubblewrap to run a container from an OCI spec file.

%prep
%autosetup -n %{name}-%{name}-%{version}-%{rel}

%build
env NOCONFIGURE=1 ./autogen.sh
%configure --disable-silent-rules

%make_build

%install
%make_install INSTALL="install -p"

%files
%license COPYING
%{_bindir}/%{name}
%{_mandir}/man1/%{name}.1*
