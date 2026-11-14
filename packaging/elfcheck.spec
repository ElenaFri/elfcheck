# elfcheck RPM spec.
#
# Packages the prebuilt, freestanding static binary and its manpage. elfcheck
# links no shared libraries (no libc, direct syscalls), so the package carries no
# runtime dependencies and installs on any RPM-based distribution (openSUSE,
# Fedora, RHEL, ...).
#
# This spec builds from prebuilt artifacts staged in the rpmbuild source dir;
# there is no %prep or %build step. The Makefile `rpm` target drives it and
# injects the version and release from the single source of truth (version_msg in
# src/elfcheck_data.inc):
#
#   rpmbuild -bb --target x86_64 \
#       --define "_topdir    <build tree>" \
#       --define "_sourcedir <dir with elfcheck + elfcheck.1>" \
#       --define "version 1.1.0" --define "release 1" \
#       packaging/elfcheck.spec

# No separate debuginfo subpackage: the shipped binary is self-contained and the
# freestanding, no-libc link carries no GNU build-id for find-debuginfo to key
# on. Disabling it also keeps the build portable across rpm toolchains (e.g.
# building the x86_64 package on a Debian/Ubuntu CI runner).
%global debug_package %{nil}
%global _build_id_links none

Name:           elfcheck
Version:        %{version}
Release:        %{release}
Summary:        Validate and inspect ELF64 binaries

License:        MIT
URL:            https://github.com/ElenaFri/elfcheck

%description
Freestanding ELF64 inspector for Linux x86-64, written in NASM (no libc,
direct syscalls): validates structure and parses headers, segments, sections,
symbol and relocation tables and dynamic tags; disassembles machine code; and
reports notes, security and hardening posture plus a severity-ranked triage
verdict with a CI-friendly exit code. Optional single-line JSON output.

%install
install -D -m 0755 %{_sourcedir}/elfcheck %{buildroot}%{_bindir}/elfcheck
install -D -m 0644 %{_sourcedir}/elfcheck.1 %{buildroot}%{_mandir}/man1/elfcheck.1

%files
%{_bindir}/elfcheck
%{_mandir}/man1/elfcheck.1*

%changelog
