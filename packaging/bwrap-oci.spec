%global commit0 0000000000000000000000000000000000000000
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7})

Summary: Core execution tool for unprivileged containers
Name: bwrap-oci
Version: 0
Release: 1%{?dist}
#VCS: git:https://github.com/projectatomic/bubblewrap
Source0: https://github.com/projectatomic/%{name}/archive/%{commit0}.tar.gz#/%{name}-%{shortcommit0}.tar.gz
License: LGPLv2+
URL: https://github.com/projectatomic/bubblewrap

Requires: bubblewrap
BuildRequires: git
# We always run autogen.sh
BuildRequires: autoconf automake libtool
BuildRequires: json-glib-devel
BuildRequires: libseccomp-devel

%description
bwrap-oci uses Bubblewrap to run a container from an OCI spec file.

%prep
%autosetup -Sgit -n %{name}-%{version}

%build
env NOCONFIGURE=1 ./autogen.sh
%configure --disable-silent-rules --with-priv-mode=none

make %{?_smp_mflags}

%install
make install DESTDIR=$RPM_BUILD_ROOT INSTALL="install -p -c"
find $RPM_BUILD_ROOT -name '*.la' -delete

%files
%license COPYING
%{_bindir}/bwrap-oci

