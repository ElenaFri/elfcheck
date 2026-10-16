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

# write_le <file> <offset> <value> <nbytes>
# Overwrite nbytes at offset with value, little-endian, in place.
write_le() {
    local file="$1" off="$2" val="$3" n="$4" i byte
    for ((i = 0; i < n; i++)); do
        byte=$(( (val >> (8 * i)) & 0xff ))
        printf "\\x$(printf %02x "$byte")" |
            dd of="$file" bs=1 seek=$((off + i)) count=1 conv=notrunc status=none 2>/dev/null
    done
}

# corrupt_copy <name> <offset> <value> <nbytes> -> echoes path of a corrupted
# copy of $BIN (a known-good ELF) with one field overwritten.
corrupt_copy() {
    local path="$TMP/$1"
    cp "$BIN" "$path"
    write_le "$path" "$2" "$3" "$4"
    echo "$path"
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
check "self passes validation"       0 "$code" "no structural issues" "$out"

# 5. Another known-good system ELF, if available
if [[ -r /bin/sh ]]; then
    out="$("$BIN" /bin/sh 2>&1)"; code=$?
    check "valid ELF prints header (/bin/sh)" 0 "$code" "ELF Header:" "$out"
fi

# 6. Malformed (truncated) ELF -> structural issues reported, exit 2
head -c 8192 "$BIN" > "$TMP/truncated.elf"
out="$("$BIN" "$TMP/truncated.elf" 2>&1)"; code=$?
check "truncated ELF flagged"        2 "$code" "issue(s) found"  "$out"
check "truncated ELF reports marker" 2 "$code" "[!]"            "$out"

# 6b. Corrupted header fields (ELF64 offsets): each must be flagged, exit 2.
#     A fresh unmodified copy must still validate cleanly (control).
out="$("$BIN" "$(corrupt_copy control.elf 0 0 0)" 2>&1)"; code=$?
check "unmodified copy validates"    0 "$code" "no structural issues" "$out"

out="$("$BIN" "$(corrupt_copy ehsize.elf 52 0 2)" 2>&1)"; code=$?
check "bad e_ehsize detected"        2 "$code" "e_ehsize"        "$out"

out="$("$BIN" "$(corrupt_copy shstrndx.elf 62 254 2)" 2>&1)"; code=$?
check "bad e_shstrndx detected"      2 "$code" "e_shstrndx"      "$out"

out="$("$BIN" "$(corrupt_copy shoff.elf 40 4000000000 8)" 2>&1)"; code=$?
check "bad e_shoff detected"         2 "$code" "section header table extends" "$out"

out="$("$BIN" "$(corrupt_copy phoff.elf 32 4000000000 8)" 2>&1)"; code=$?
check "bad e_phoff detected"         2 "$code" "program header table extends" "$out"

# 7. JSON output mode
out="$("$BIN" --json "$BIN" 2>&1)"; code=$?
check "--json exits 0 for valid ELF"  0 "$code" '{"header":{'       "$out"
check "--json has program_headers"   0 "$code" '"program_headers":' "$out"
check "--json has section_headers"   0 "$code" '"section_headers":' "$out"
check "--json reports valid:true"    0 "$code" '"valid":true'      "$out"

# flag accepted after the path too
out="$("$BIN" "$BIN" --json 2>&1)"; code=$?
check "--json accepted after path"   0 "$code" '{"header":{'       "$out"

# JSON on a malformed file -> valid:false, exit 2
out="$("$BIN" --json "$TMP/truncated.elf" 2>&1)"; code=$?
check "--json flags malformed ELF"   2 "$code" '"valid":false'     "$out"

# If python3 is available, assert the JSON actually parses
if command -v python3 >/dev/null 2>&1; then
    "$BIN" --json "$BIN" 2>/dev/null | python3 -m json.tool >/dev/null 2>&1
    pcode=$?
    check "--json is well-formed JSON" 0 "$pcode" "" ""
fi

echo
echo "Results: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
