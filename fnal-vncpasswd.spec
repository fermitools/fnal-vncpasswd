Name:           fnal-vncpasswd
Version:        0.1.0
Release:        1%{?dist}

# Only the test_framework is CC-PDDC
License:        BSD-3-Clause AND CC-PDDC

URL:            https://github.com/fermitools/%{name}
Source0:        %{url}/archive/%{version}/%{name}-%{version}.tar.gz

BuildRequires:  redhat-rpm-config
BuildRequires:  cmake >= 3.21
BuildRequires:  gcc
BuildRequires:  pam-devel
BuildRequires:  libxcrypt-devel
BuildRequires:  openssl-devel
BuildRequires:  libbsd-devel
BuildRequires:  libselinux-devel
BuildRequires:  (rubygem-asciidoctor or asciidoc)

Summary:        Per-user VNC password manager and PAM authentication module
%description
fnal-vncpasswd lets users set a local VNC password stored under
~/.config/vnc/fnal-vncpasswd using a modern crypt(3) hash.  The password
file is readable only by the owning user and is never passed over the
network.

%package -n pam_%{name}
Summary:        PAM module for fnal-vncpasswd authentication
Requires:       %{name} = %{version}-%{release}

%description -n pam_%{name}
PAM module that authenticates VNC sessions against the password file
managed by fnal-vncpasswd.

You must still configure PAM yourself.


%prep
%autosetup


%build
%cmake \
    -Wdev -Wdeprecated --warn-uninitialized \
    -DVERSION=%{version}                    \
    -DBUILD_TESTING=ON
%cmake_build


%install
%cmake_install


%check
%ctest --output-on-failure


%files
%license LICENSE
%doc docs/README.md
%doc %{_mandir}/man1/fnal-vncpasswd.1*
%{_bindir}/%{name}

%files -n pam_%{name}
%license LICENSE
%doc %{_mandir}/man8/pam_fnal_vncpasswd.8*
%{_libdir}/security/pam_fnal_vncpasswd.so


%changelog
* Mon Feb 16 2026 Pat Riehecky <riehecky@fnal.gov> - 0.1.0-1
- Initial release
