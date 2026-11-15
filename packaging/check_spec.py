#!/usr/bin/env python3
"""Local validation of packaging/elfcheck.spec via the rpm Python bindings.

Parses the spec the same way `make rpm` invokes rpmbuild (same --define macros),
and asserts the resulting package metadata and file list are what we expect.
This does not produce an .rpm (that needs rpmbuild / the rpm-build package), but
it catches spec syntax errors, bad section layout, and metadata/%files mistakes.
"""
import atexit
import re
import shutil
import sys
import tempfile

import rpm

SPEC = "packaging/elfcheck.spec"


def source_version():
    """Extract the version the same way the Makefile does (single source of truth)."""
    pat = re.compile(r'^\s*version_msg:.*"elfcheck v(\d[\d.]*)"')
    with open("src/elfcheck_data.inc", encoding="utf-8") as fh:
        for line in fh:
            m = pat.match(line)
            if m:
                return m.group(1)
    raise SystemExit("FAIL: could not extract version from src/elfcheck_data.inc")


VERSION = source_version()
RELEASE = "1"

# rpm.spec() must be able to expand %{_topdir}/%{_sourcedir} while parsing. This
# script only parses the spec (it never builds), so nothing is written there, but
# we still point the macros at a private temporary directory created with a
# random name and 0700 permissions rather than a fixed, world-writable /tmp path.
workdir = tempfile.mkdtemp(prefix="elfcheck-spec-")
atexit.register(shutil.rmtree, workdir, ignore_errors=True)

rpm.addMacro("version", VERSION)
rpm.addMacro("release", RELEASE)
rpm.addMacro("_sourcedir", workdir)
rpm.addMacro("_topdir", workdir)

try:
    spec = rpm.spec(SPEC)
except Exception as exc:  # noqa: BLE001 - we want any parse error surfaced
    print(f"FAIL: spec did not parse: {exc}")
    sys.exit(1)

hdr = spec.sourceHeader
name = hdr[rpm.RPMTAG_NAME]
version = hdr[rpm.RPMTAG_VERSION]
release = hdr[rpm.RPMTAG_RELEASE]
summary = hdr[rpm.RPMTAG_SUMMARY]
license_ = hdr[rpm.RPMTAG_LICENSE]
url = hdr[rpm.RPMTAG_URL]


def dec(value):
    return value.decode() if isinstance(value, bytes) else value


name = dec(name)
version = dec(version)
release = dec(release)
license_ = dec(license_)

errors = []
if name != "elfcheck":
    errors.append(f"name={name!r} (expected 'elfcheck')")
if version != VERSION:
    errors.append(f"version={version!r} (expected {VERSION!r})")
if release != RELEASE:
    errors.append(f"release={release!r} (expected {RELEASE!r})")
if license_ != "MIT":
    errors.append(f"license={license_!r} (expected 'MIT')")

# The built binary package must carry no runtime dependencies (freestanding,
# no libc) beyond rpmlib() feature requirements that rpm injects itself.
pkg = spec.packages[0]
requires = [dec(r) for r in pkg.header[rpm.RPMTAG_REQUIRENAME] or []]
real_requires = [r for r in requires if not r.startswith("rpmlib(")]
if real_requires:
    errors.append(f"unexpected runtime Requires: {real_requires}")

# Expected payload: just the binary and the manpage. fileList is the raw %files
# section (one glob per line); globs resolve against the buildroot only at real
# build time, so the manpage still shows its pre-compress `.1*` glob here.
raw_files = pkg.fileList
if isinstance(raw_files, bytes):
    raw_files = raw_files.decode()
files = sorted(line.strip() for line in raw_files.splitlines() if line.strip())
print("parsed OK:")
print(f"  name    = {name}")
print(f"  version = {version}")
print(f"  release = {release}")
print(f"  license = {license_}")
print(f"  url     = {dec(url)}")
print(f"  summary = {dec(summary)}")
print(f"  requires(non-rpmlib) = {real_requires}")
print(f"  files   = {files}")

expected_files = ["/usr/bin/elfcheck", "/usr/share/licenses/elfcheck/LICENSE",
                  "/usr/share/man/man1/elfcheck.1*"]
if files != expected_files:
    errors.append(f"files={files} (expected {expected_files})")

if errors:
    print("\nFAIL:")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)

print("\nPASS: spec metadata and payload are as expected")
