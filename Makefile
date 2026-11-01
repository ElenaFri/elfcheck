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

# The .deb version comes from the version string in the source, so there is a
# single source of truth: bump version_msg in src/elfcheck_data.inc.
DEB_VERSION := $(shell sed -n 's/^    version_msg:.*"elfcheck v\([0-9][0-9.]*\)".*/\1/p' $(SRC_DIR)/elfcheck_data.inc)
DEB_ROOT := $(BUILD_DIR)/deb
# Debian packages install to /usr, not the optional PREFIX location.
DEB_BINDIR := usr/bin
DEB_MANDIR := usr/share/man/man1
DEB      := elfcheck_$(DEB_VERSION)_amd64.deb

# Keep -Wall; suppress only the expected cross-section relative dword references
# and absolute qword pointers in dispatch tables used by the non-PIE binary.
NASMFLAGS ?= -f elf64 -g -F dwarf -Wall -w-reloc-rel-dword -w-reloc-abs-qword
LDFLAGS   ?= -nostdlib -no-pie

.PHONY: all run test fuzz-smoke coverage install uninstall deb clean

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

# Package the static binary and manpage as a Debian package.
deb: $(TARGET) $(MANPAGE)
	@if [[ -z "$(DEB_VERSION)" ]]; then \
		echo "error: cannot extract version from $(SRC_DIR)/elfcheck_data.inc" >&2; \
		exit 1; \
	fi
	$(RM) -r "$(DEB_ROOT)"
	install -d "$(DEB_ROOT)/DEBIAN" "$(DEB_ROOT)/$(DEB_BINDIR)" "$(DEB_ROOT)/$(DEB_MANDIR)"
	install -m 0755 "$(TARGET)" "$(DEB_ROOT)/$(DEB_BINDIR)/$(TARGET)"
	install -m 0644 "$(MANPAGE)" "$(DEB_ROOT)/$(DEB_MANDIR)/"
	printf 'Package: elfcheck\nVersion: %s\nSection: utils\nPriority: optional\nArchitecture: amd64\nMaintainer: Elena FRISON <ElenaFri@users.noreply.github.com>\nDescription: validate and inspect ELF64 binaries\n Freestanding ELF64 inspector written in NASM (no libc, direct syscalls):\n parses headers, symbols, relocations and dynamic tags; disassembles\n code; reports notes, hardening and triage verdicts; optional JSON output.\n' \
		"$(DEB_VERSION)" > "$(DEB_ROOT)/DEBIAN/control"
	dpkg-deb --build --root-owner-group "$(DEB_ROOT)" "$(DEB)"

clean:
	rm -rf $(BUILD_DIR) $(TARGET) "$(COVERAGE_DIR)" "$(DEB)"
