%global pname pgedge-safesession
%global extname pgedge_safesession
%global pginstdir /usr/pgsql-%{pgmajorversion}

%{!?llvm:%global llvm 1}

Name:		%{pname}_%{pgmajorversion}
Version:	%{safesession_version}
Release:	%{safesession_buildnum}%{?dist}
Summary:	Read-only session enforcement for PostgreSQL roles
License:	PostgreSQL License
URL:		https://github.com/pgEdge/%{pname}/
Source0:	https://github.com/pgEdge/%{pname}/archive/refs/tags/v%{version}.tar.gz

BuildRequires:	pgedge-postgresql%{pgmajorversion}-devel
Requires:	pgedge-postgresql%{pgmajorversion}-server
Provides:       %{extname}_%{pgmajorversion}

%description
pgEdge SafeSession is a PostgreSQL extension that enforces read-only sessions
for specified database roles. It uses executor and utility hooks to provide
defense-in-depth protection, blocking DML, DDL, COPY FROM, GRANT/REVOKE,
VACUUM/ANALYZE and volatile C-language function execution for restricted
roles.

The module must be listed in shared_preload_libraries and the restricted roles
configured through pgedge_safesession.roles before enforcement takes effect.

%if %llvm
%package llvmjit
Summary:	Just-in-time compilation support for %{extname}
Requires:	%{name}%{?_isa} = %{version}-%{release}
%if 0%{?suse_version} >= 1500
BuildRequires:	llvm17-devel clang17-devel
Requires:	llvm17
%endif
%if 0%{?fedora} || 0%{?rhel} >= 8
BuildRequires:	llvm-devel >= 13.0 clang-devel >= 13.0
Requires:	llvm => 13.0
Provides:       %{extname}_%{pgmajorversion}-llvmjit
%endif

%description llvmjit
This packages provides JIT support for %{extname}
%endif

%prep
%setup -q -n %{pname}-%{version}

%build
USE_PGXS=1 PATH=%{pginstdir}/bin:$PATH %{__make} #%{?_smp_mflags}
syft dir:%{_builddir}/%{pname}-%{version} -o cyclonedx-json > %{_builddir}/%{pname}-%{version}/%{pname}-sbom.json || exit 1

KEY_ID=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/{print $5}' | head -n 1); export KEY_ID
gpg --armor --detach-sign --output %{_builddir}/%{pname}-%{version}/%{pname}-sbom.json.asc %{_builddir}/%{pname}-%{version}/%{pname}-sbom.json || exit 1

%install
%{__rm} -rf %{buildroot}
USE_PGXS=1 PATH=%{pginstdir}/bin:$PATH %{__make} %{?_smp_mflags} install DESTDIR=%{buildroot}
mkdir -p %{buildroot}/%{pginstdir}/sbom
install -p -m 0644 %{_builddir}/%{pname}-%{version}/%{pname}-sbom.json %{buildroot}/%{pginstdir}/sbom/%{pname}-sbom.json
install -p -m 0644 %{_builddir}/%{pname}-%{version}/%{pname}-sbom.json.asc %{buildroot}/%{pginstdir}/sbom/%{pname}-sbom.json.asc

%files
%doc README.md
%license LICENCE.md
%{pginstdir}/lib/%{extname}.so
%{pginstdir}/share/extension/%{extname}.control
%{pginstdir}/share/extension/%{extname}*sql
%{pginstdir}/sbom/%{pname}-sbom.json
%{pginstdir}/sbom/%{pname}-sbom.json.asc

%if %llvm
%files llvmjit
  %{pginstdir}/lib/bitcode/%{extname}*.bc
  # The C sources live in src/, so PGXS emits the per-object bitcode one
  # directory deeper than the module name — own the whole tree instead of
  # globbing a single level.
  %{pginstdir}/lib/bitcode/%{extname}/
%endif

%changelog
* Wed Aug 12 2026 Muhammad Aqeel <muhammad.aqeel@pgedge.com> - 1.0
- Initial pgEdge SafeSession package.
