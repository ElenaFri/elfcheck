# elfcheck - build pipeline
#
# Assembles NASM sources into ELF64 objects and links them with ld into a
# freestanding static binary (no libc). Usage:
#
#   make            build the elfcheck binary
#   make run ARGS=f run against a file
#   make test       build and run the test suite
#   make clean      remove build artifacts

NASM      ?= nasm
LD        ?= ld

TARGET    := elfcheck
SRC_DIR   := src
BUILD_DIR := build

SRCS := $(wildcard $(SRC_DIR)/*.asm)
OBJS := $(patsubst $(SRC_DIR)/%.asm,$(BUILD_DIR)/%.o,$(SRCS))

# -Wall keeps real diagnostics; the reloc-rel warnings are suppressed because
# cross-section RIP-relative references (.text -> .rodata/.bss) are expected
# and harmless for a normal (non-PIE) static executable.
NASMFLAGS := -f elf64 -g -F dwarf -Wall -w-reloc-rel-dword
LDFLAGS   := -nostdlib

.PHONY: all run test clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

run: $(TARGET)
	./$(TARGET) $(ARGS)

test: $(TARGET)
	./tests/run_tests.sh

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
