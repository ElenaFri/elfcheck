# elfcheck RPM spec for the openSUSE Build Service (OBS).
#
# Unlike packaging/elfcheck.spec (which packages a prebuilt binary for GitHub
# release assets), this spec builds elfcheck *from source* in OBS's clean
# chroot, so OBS can produce and sign a repository that users install from with
# a plain `zypper install elfcheck`.
#
# The accompanying _service pulls the source tarball from the GitHub tags and
# rewrites the Version below to match the tag (via the set_version service), so
# the version stays tied to the single source of truth (version_msg in
# src/elfcheck_data.inc, which the release tag mirrors).

# elfcheck is a freestanding, statically linked x86-64 binary with no GNU
# build-id, so there is nothing for find-debuginfo to key on: skip the debuginfo
# subpackage rather than fail on a missing build-id.
%global debug_package %{nil}

Name:           elfcheck
Version:        1.1.1
Release:        0
Summary:        Validate and inspect ELF64 binaries
License:        MIT
Group:          Development/Tools/Other
URL:            https://github.com/ElenaFri/elfcheck
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  nasm
BuildRequires:  binutils
BuildRequires:  make

# Hand-written NASM for Linux x86-64 with raw x86-64 syscalls: this binary is
# architecture-specific by design, so only build it where it can run.
ExclusiveArch:  x86_64

%description
Freestanding ELF64 inspector for Linux x86-64, written in NASM (no libc,
direct syscalls): validates structure and parses headers, segments, sections,
symbol and relocation tables and dynamic tags; disassembles machine code; and
reports notes, security and hardening posture plus a severity-ranked triage
verdict with a CI-friendly exit code. Optional single-line JSON output.

%prep
%autosetup -n %{name}-%{version}

%build
%make_build

%install
%make_install PREFIX=%{_prefix}

%check
# Smoke check only: the binary runs and validates its own structure. The full
# differential suite (make test) compares exact readelf output and builds
# GCC/Python fixtures, which is version-sensitive across distros; it runs in
# GitHub CI instead.
./elfcheck --version
./elfcheck --validate ./elfcheck

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/elfcheck
%{_mandir}/man1/elfcheck.1*

%changelog
