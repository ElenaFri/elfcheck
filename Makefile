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
#   make clean      remove build and coverage artifacts

NASM      ?= nasm
LD        ?= ld
KCOV      ?= kcov
COVERAGE_DIR ?= coverage

TARGET    := elfcheck
SRC_DIR   := src
BUILD_DIR := build

SRCS := $(wildcard $(SRC_DIR)/*.asm)
INCS := $(wildcard $(SRC_DIR)/*.inc)
OBJS := $(patsubst $(SRC_DIR)/%.asm,$(BUILD_DIR)/%.o,$(SRCS))

# Keep -Wall; suppress only the expected cross-section relative dword references
# and absolute qword pointers in dispatch tables used by the non-PIE binary.
NASMFLAGS ?= -f elf64 -g -F dwarf -Wall -w-reloc-rel-dword -w-reloc-abs-qword
LDFLAGS   ?= -nostdlib -no-pie

.PHONY: all run test fuzz-smoke coverage clean

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
	python3 ./tests/fuzz_smoke.py ./$(TARGET)

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

clean:
	rm -rf $(BUILD_DIR) $(TARGET) "$(COVERAGE_DIR)"
