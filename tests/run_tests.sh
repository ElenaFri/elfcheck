#!/usr/bin/env bash
#
# elfcheck test suite.
# Builds (via the caller / Makefile) are assumed done; this script exercises
# the elfcheck binary against valid and invalid inputs and checks exit codes
# and output.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/elfcheck"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

check() {
    # check <description> <expected_exit> <actual_exit> <expected_substr> <actual_output>
    local desc="$1" exp_code="$2" act_code="$3" exp_sub="$4" out="$5"
    if [[ "$act_code" == "$exp_code" && "$out" == *"$exp_sub"* ]]; then
        echo "  PASS: $desc"
        pass=$((pass + 1))
    else
        echo "  FAIL: $desc"
        echo "        expected exit=$exp_code substr='$exp_sub'"
        echo "        got      exit=$act_code output='$out'"
        fail=$((fail + 1))
    fi
}

if [[ ! -x "$BIN" ]]; then
    echo "error: $BIN not found or not executable (run 'make' first)" >&2
    exit 1
fi

echo "Running elfcheck tests..."

# 1. No argument -> usage, exit 1
out="$("$BIN" 2>&1)"; code=$?
check "no argument prints usage" 1 "$code" "Usage:" "$out"

# 2. Nonexistent file -> open error, exit 1
out="$("$BIN" "$TMP/does_not_exist" 2>&1)"; code=$?
check "missing file reports open error" 1 "$code" "cannot open" "$out"

# 3. Non-ELF file -> invalid, exit 1
printf 'not an elf file' > "$TMP/plain.txt"
out="$("$BIN" "$TMP/plain.txt" 2>&1)"; code=$?
check "non-ELF file rejected" 1 "$code" "not an ELF" "$out"

# 4. Valid ELF (the binary itself) -> header printed, exit 0
out="$("$BIN" "$BIN" 2>&1)"; code=$?
check "valid ELF prints header (self)" 0 "$code" "ELF Header:" "$out"
check "self reported as ELF64"        0 "$code" "ELF64"       "$out"
check "self machine is x86-64"       0 "$code" "x86-64"      "$out"
check "self lists program headers"   0 "$code" "Program Headers:" "$out"
check "self has a LOAD segment"      0 "$code" "LOAD"        "$out"
check "self lists section headers"   0 "$code" "Section Headers:" "$out"
check "self has a .text section"     0 "$code" ".text"       "$out"

# 5. Another known-good system ELF, if available
if [[ -r /bin/sh ]]; then
    out="$("$BIN" /bin/sh 2>&1)"; code=$?
    check "valid ELF prints header (/bin/sh)" 0 "$code" "ELF Header:" "$out"
fi

echo
echo "Results: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
