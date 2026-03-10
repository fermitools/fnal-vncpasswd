%if 0%{?rhel} < 10 && 0%{?fedora} < 1
%bcond_with pam
%else
%bcond_without pam
%endif

Name:           fnal-vncpasswd
Version:        0.1.0
Release:        1%{?dist}

# Only the test_framework is CC-PDDC
License:        BSD-3-Clause AND CC-PDDC

URL:            https://github.com/fermitools/%{name}
Source0:        %{url}/archive/%{version}/%{name}-%{version}.tar.gz

BuildRequires:  redhat-rpm-config
BuildRequires:  cmake >= 3.21
BuildRequires:  openssl-devel
BuildRequires:  libbsd-devel
BuildRequires:  libselinux-devel
BuildRequires:  libxcrypt-devel
BuildRequires:  (rubygem-asciidoctor or asciidoc)

# PAM is included unconditionally
BuildRequires:  pam-devel

%if 0%{?rhel} < 10
BuildRequires:	gcc-toolset-14 scl-utils
%endif

Provides:	fermilab-util_fnal-vncpasswd = %{version}-%{release}

Summary:        Per-user VNC password manager and PAM authentication module
%description
fnal-vncpasswd lets users set a local VNC password stored under
~/.config/vnc/fnal-vncpasswd using a modern crypt(3) hash.  The password
file is readable only by the owning user and is never passed over the
network.

%if %{with pam}
%package -n pam_%{name}
Summary:        PAM module for fnal-vncpasswd authentication
Requires:       %{name} = %{version}-%{release}

%description -n pam_%{name}
PAM module that authenticates VNC sessions against the password file
managed by fnal-vncpasswd.

You must still configure PAM yourself.
%endif


%prep
%autosetup


%build
%if 0%{?rhel} < 10 && 0%{?fedora} < 31
source scl_source enable gcc-toolset-14
%endif

%if 0%{?rhel} < 9 && 0%{?fedora} < 31
mkdir build
cd build
%cmake3 \
    -DVERSION=%{version} \
    -DBUILD_TESTING=ON   \
    -Wdeprecated ..
make VERBOSE=2 %{?_smp_mflags}
%else
%cmake \
    -DVERSION=%{version} \
    -DBUILD_TESTING=ON
%cmake_build
%endif


%install
%if 0%{?rhel} < 9 && 0%{?fedora} < 31
cd build
make install DESTDIR=%{buildroot}
%else
%cmake_install
%endif

%if %{without pam}
rm -rf %{buildroot}%{_mandir}/man8/pam_fnal_vncpasswd.*
rm -rf %{buildroot}%{_libdir}/security/pam_fnal_vncpasswd.*
rmdir %{buildroot}%{_mandir}/man8/ || true
rmdir %{buildroot}%{_libdir}/security || true
rmdir %{buildroot}%{_libdir} || true
%endif


%check
%if 0%{?rhel} < 9 && 0%{?fedora} < 31
cd build
make test
%else
%ctest --output-on-failure
%endif

%files
%license LICENSE
%doc docs/README.md
%doc %{_mandir}/man1/fnal-vncpasswd.1*
%{_bindir}/%{name}

%if %{with pam}
%files -n pam_%{name}
%license LICENSE
%doc %{_mandir}/man8/pam_fnal_vncpasswd.8*
%{_libdir}/security/pam_fnal_vncpasswd.so
%endif


%changelog
* Mon Feb 16 2026 Pat Riehecky <riehecky@fnal.gov> - 0.1.0-1
- Initial release
