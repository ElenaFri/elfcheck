# elfcheck - build pipeline
#
# Assembles NASM sources into ELF64 objects and links them with ld into a
# freestanding static binary (no libc). Usage:
#
#   make            build the elfcheck binary
#   make run ARGS=f run against a file
#   make test       build and run the test suite
#   make fuzz-smoke run a bounded deterministic mutation smoke test
#   make coverage   run tests under kcov and generate a source coverage report
#   make install    install the binary and manpage (PREFIX=/usr/local, DESTDIR=)
#   make uninstall  remove them
#   make deb        package the static binary and manpage as a .deb
#   make rpm        package the static binary and manpage as an .rpm
#   make rpm-sign   GPG-sign the built .rpm (GPG_NAME=key)
#   make clean      remove build and coverage artifacts

PREFIX ?= /usr/local
BINDIR  := $(PREFIX)/bin
MANDIR  := $(PREFIX)/share/man
MANPAGE := man/elfcheck.1

NASM      ?= nasm
LD        ?= ld
KCOV      ?= kcov
FUZZ_CASES ?= 16
COVERAGE_DIR ?= coverage

TARGET    := elfcheck
SRC_DIR   := src
BUILD_DIR := build

SRCS := $(wildcard $(SRC_DIR)/*.asm)
INCS := $(wildcard $(SRC_DIR)/*.inc)
OBJS := $(patsubst $(SRC_DIR)/%.asm,$(BUILD_DIR)/%.o,$(SRCS))

# The package version comes from the version string in the source, so there is a
# single source of truth shared by the .deb and .rpm: bump version_msg in
# src/elfcheck_data.inc.
PKG_VERSION := $(shell sed -n 's/^    version_msg:.*"elfcheck v\([0-9][0-9.]*\)".*/\1/p' $(SRC_DIR)/elfcheck_data.inc)
DEB_ROOT := $(BUILD_DIR)/deb
# Debian packages install to /usr, not the optional PREFIX location.
DEB_BINDIR := usr/bin
DEB_MANDIR := usr/share/man/man1
DEB      := elfcheck_$(PKG_VERSION)_amd64.deb

# RPM packaging (openSUSE, Fedora, ...). The freestanding static binary has no
# runtime dependencies, so the package is portable across RPM distributions and
# can even be built on a non-RPM CI runner that provides rpmbuild.
RPM_RELEASE ?= 1
RPM_ARCH    := x86_64
RPM_ROOT    := $(BUILD_DIR)/rpm
RPM_SPEC    := packaging/elfcheck.spec
RPM         := elfcheck-$(PKG_VERSION)-$(RPM_RELEASE).$(RPM_ARCH).rpm

# Detached GPG signing of the RPM (so zypper/dnf install cleanly once the public
# key is imported). GPG_NAME is the signing key id or email; the key must already
# be in the GPG keyring. For an automated/CI key prefer a passphrase-less key
# (the secret store is the protection); otherwise point GPG_PASSPHRASE_FILE at a
# file holding the passphrase. The sign command pins SHA-256 and loopback
# pinentry so it never blocks on a prompt.
GPG_NAME ?=
GPG_PASSPHRASE_FILE ?=
RPM_SIGN_CMD = %{__gpg} gpg --batch --no-verbose --no-armor --pinentry-mode loopback $(if $(GPG_PASSPHRASE_FILE),--passphrase-file $(GPG_PASSPHRASE_FILE) )--no-secmem-warning -u %{_gpg_name} -sbo %{__signature_filename} --digest-algo sha256 %{__plaintext_filename}

# Keep -Wall; suppress only the expected cross-section relative dword references
# and absolute qword pointers in dispatch tables used by the non-PIE binary.
NASMFLAGS ?= -f elf64 -g -F dwarf -Wall -w-reloc-rel-dword -w-reloc-abs-qword
LDFLAGS   ?= -nostdlib -no-pie

.PHONY: all run test fuzz-smoke coverage install uninstall deb rpm rpm-sign clean

all: $(TARGET)

$(TARGET): $(OBJS) Makefile
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.asm $(INCS) Makefile | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -I "$(SRC_DIR)/" -o "$@" "$(CURDIR)/$<"

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

run: $(TARGET)
	./$(TARGET) $(ARGS)

test: $(TARGET)
	./tests/run_tests.sh

fuzz-smoke: $(TARGET)
	@extra=""; \
	if command -v gcc >/dev/null 2>&1; then \
		printf 'int elfcheck_fuzz_fixture(void) { return 7; }\n' > $(BUILD_DIR)/fuzz-fixture.c; \
		if gcc -c -o $(BUILD_DIR)/fuzz-fixture.o $(BUILD_DIR)/fuzz-fixture.c 2>/dev/null; then \
			extra=" $(BUILD_DIR)/fuzz-fixture.o"; \
		fi; \
	fi; \
	for t in /bin/sh /bin/ls; do \
		if [ -r "$$t" ]; then extra="$$extra $$t"; fi; \
	done; \
	python3 ./tests/fuzz_smoke.py --cases $(FUZZ_CASES) ./$(TARGET) $$extra

coverage:
	@command -v $(KCOV) >/dev/null 2>&1 || { \
		echo "error: kcov is required (Debian/Ubuntu: sudo apt install kcov)" >&2; \
		exit 1; \
	}
	$(MAKE) $(TARGET)
	@rm -rf "$(COVERAGE_DIR)"
	KCOV_BIN="$(KCOV)" \
	KCOV_INCLUDE_PATH="$(CURDIR)/$(SRC_DIR)" \
	KCOV_OUTPUT_DIR="$(CURDIR)/$(COVERAGE_DIR)" \
	ELFCHECK_REAL_BIN="$(CURDIR)/$(TARGET)" \
	ELFCHECK_RUN_BIN="$(CURDIR)/tests/kcov-wrapper.sh" \
	./tests/run_tests.sh
	@printf 'Coverage report: %s/index.html\n' "$(COVERAGE_DIR)"

install: $(TARGET) $(MANPAGE)
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 "$(TARGET)" "$(DESTDIR)$(BINDIR)/$(TARGET)"
	install -d "$(DESTDIR)$(MANDIR)/man1"
	install -m 0644 "$(MANPAGE)" "$(DESTDIR)$(MANDIR)/man1/"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(TARGET)" "$(DESTDIR)$(MANDIR)/man1/elfcheck.1"

# Package the static binary and manpage as a Debian package. The staged binary
# is stripped: the dev build keeps the nasm -g DWARF lines and full symtab
# (~115 KB combined) for debugging, but a freestanding binary only needs
# .text/.rodata/.data/.bss at runtime. The manpage is gzipped, as Debian
# policy expects (the RPM build gzips it via brp-compress). The MIT license
# ships as the Debian copyright file, as the license requires.
deb: $(TARGET) $(MANPAGE) LICENSE
	@if [ -z "$(PKG_VERSION)" ]; then \
		echo "error: cannot extract version from $(SRC_DIR)/elfcheck_data.inc" >&2; \
		exit 1; \
	fi
	$(RM) -r "$(DEB_ROOT)"
	install -d "$(DEB_ROOT)/DEBIAN" "$(DEB_ROOT)/$(DEB_BINDIR)" "$(DEB_ROOT)/$(DEB_MANDIR)"
	install -m 0755 "$(TARGET)" "$(DEB_ROOT)/$(DEB_BINDIR)/$(TARGET)"
	strip --strip-all "$(DEB_ROOT)/$(DEB_BINDIR)/$(TARGET)"
	gzip -9n -c "$(MANPAGE)" > "$(DEB_ROOT)/$(DEB_MANDIR)/elfcheck.1.gz"
	install -d "$(DEB_ROOT)/usr/share/doc/elfcheck"
	install -m 0644 LICENSE "$(DEB_ROOT)/usr/share/doc/elfcheck/copyright"
	printf 'Package: elfcheck\nVersion: %s\nSection: utils\nPriority: optional\nArchitecture: amd64\nMaintainer: Elena FRISON <ElenaFri@users.noreply.github.com>\nDescription: validate and inspect ELF64 binaries\n Freestanding ELF64 inspector written in NASM (no libc, direct syscalls):\n parses headers, symbols, relocations and dynamic tags; disassembles\n code; reports notes, hardening and triage verdicts; optional JSON output.\n' \
		"$(PKG_VERSION)" > "$(DEB_ROOT)/DEBIAN/control"
	dpkg-deb --build --root-owner-group "$(DEB_ROOT)" "$(DEB)"

# Package the static binary and manpage as an RPM. Version and release are
# injected into packaging/elfcheck.spec from the single source of truth above,
# and the build tree is kept self-contained under $(RPM_ROOT) so it never
# touches ~/rpmbuild.
rpm: $(TARGET) $(MANPAGE) $(RPM_SPEC) LICENSE
	@if [ -z "$(PKG_VERSION)" ]; then \
		echo "error: cannot extract version from $(SRC_DIR)/elfcheck_data.inc" >&2; \
		exit 1; \
	fi
	@command -v rpmbuild >/dev/null 2>&1 || { \
		echo "error: rpmbuild is required (openSUSE: sudo zypper install rpm-build; Debian/Ubuntu: sudo apt install rpm)" >&2; \
		exit 1; \
	}
	$(RM) -r "$(RPM_ROOT)"
	install -d "$(RPM_ROOT)/SOURCES" "$(RPM_ROOT)/BUILD" "$(RPM_ROOT)/RPMS" "$(RPM_ROOT)/BUILDROOT"
	install -m 0755 "$(TARGET)" "$(RPM_ROOT)/SOURCES/$(TARGET)"
	strip --strip-all "$(RPM_ROOT)/SOURCES/$(TARGET)"
	install -m 0644 "$(MANPAGE)" "$(RPM_ROOT)/SOURCES/elfcheck.1"
	install -m 0644 LICENSE "$(RPM_ROOT)/SOURCES/LICENSE"
	rpmbuild -bb --target "$(RPM_ARCH)" \
		--define "_topdir $(CURDIR)/$(RPM_ROOT)" \
		--define "_sourcedir $(CURDIR)/$(RPM_ROOT)/SOURCES" \
		--define "version $(PKG_VERSION)" \
		--define "release $(RPM_RELEASE)" \
		"$(RPM_SPEC)"
	cp "$(RPM_ROOT)/RPMS/$(RPM_ARCH)/$(RPM)" "$(RPM)"

# GPG-sign the built RPM in place. Run after `make rpm`. Keeping this separate
# from `rpm` means an unsigned package is still produced when no key is
# configured (e.g. before the CI signing secret is set).
rpm-sign:
	@test -f "$(RPM)" || { echo "error: $(RPM) not found; run 'make rpm' first" >&2; exit 1; }
	@if [ -z "$(GPG_NAME)" ]; then \
		echo "error: set GPG_NAME to the signing key id or email" >&2; \
		exit 1; \
	fi
	@command -v rpmsign >/dev/null 2>&1 || { \
		echo "error: rpmsign is required (openSUSE: sudo zypper install rpm-sign; Debian/Ubuntu: sudo apt install rpm)" >&2; \
		exit 1; \
	}
	rpmsign --addsign \
		--define "_gpg_name $(GPG_NAME)" \
		--define "__gpg_sign_cmd $(RPM_SIGN_CMD)" \
		"$(RPM)"
	rpm -Kv "$(RPM)" || true

clean:
	rm -rf $(BUILD_DIR) $(TARGET) "$(COVERAGE_DIR)" "$(DEB)" "$(RPM)"
