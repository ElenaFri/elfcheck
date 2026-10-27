#!/usr/bin/env bash
#
# elfcheck test suite.
# Builds (via the caller / Makefile) are assumed done; this script exercises
# the elfcheck binary against valid and invalid inputs and checks exit codes
# and output.

set -uo pipefail

readonly SYMBOL_TABLES_HEADING='Symbol Tables:'
readonly RELOCATIONS_HEADING='Relocations:'
readonly TEXT_DISASSEMBLY_HEADING='Disassembly of section .text:'
readonly CALLEE_ANNOTATION='<elfcheck_callee>'
readonly USAGE_HEADING='Usage:'
readonly ELF_HEADER_HEADING='ELF Header:'
readonly HARDENING_HEADING='Hardening:'

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/elfcheck"
RUN_BIN="${ELFCHECK_RUN_BIN:-$BIN}"
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

check_absent() {
    # check_absent <description> <expected_exit> <actual_exit> <forbidden_substr> <actual_output>
    local desc="$1" exp_code="$2" act_code="$3" bad_sub="$4" out="$5"
    if [[ "$act_code" == "$exp_code" && "$out" != *"$bad_sub"* ]]; then
        echo "  PASS: $desc"
        pass=$((pass + 1))
    else
        echo "  FAIL: $desc"
        echo "        expected exit=$exp_code without substr='$bad_sub'"
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
    local name="$1" offset="$2" value="$3" nbytes="$4"
    local path="$TMP/$name"
    cp "$BIN" "$path"
    write_le "$path" "$offset" "$value" "$nbytes"
    echo "$path"
}

if [[ ! -x "$BIN" || ! -x "$RUN_BIN" ]]; then
    echo "error: elfcheck or its configured runner is not executable (run 'make' first)" >&2
    exit 1
fi

echo "Running elfcheck tests..."

# 1. No argument -> usage, exit 1
out="$("$RUN_BIN" 2>&1)"; code=$?
check "no argument prints usage" 1 "$code" "$USAGE_HEADING" "$out"

# 2. Nonexistent file -> open error, exit 1
out="$("$RUN_BIN" "$TMP/does_not_exist" 2>&1)"; code=$?
check "missing file reports open error" 1 "$code" "cannot open" "$out"

# 3. Non-ELF file -> invalid, exit 1
printf 'not an elf file' > "$TMP/plain.txt"
out="$("$RUN_BIN" "$TMP/plain.txt" 2>&1)"; code=$?
check "non-ELF file rejected" 1 "$code" "not an ELF" "$out"

# 4. Valid ELF (the binary itself) -> header printed, exit 0
out="$("$RUN_BIN" "$BIN" 2>&1)"; code=$?
check "valid ELF prints header (self)" 0 "$code" "$ELF_HEADER_HEADING" "$out"
check "self reported as ELF64"        0 "$code" "ELF64"       "$out"
check "self machine is x86-64"       0 "$code" "x86-64"      "$out"
check "self lists program headers"   0 "$code" "Program Headers:" "$out"
check "self has a LOAD segment"      0 "$code" "LOAD"        "$out"
check "self lists section headers"   0 "$code" "Section Headers:" "$out"
check "self has a .text section"     0 "$code" ".text"       "$out"
check "self passes validation"       0 "$code" "no structural issues" "$out"

# 5. Another known-good system ELF, if available
if [[ -r /bin/sh ]]; then
    out="$("$RUN_BIN" /bin/sh 2>&1)"; code=$?
    check "valid ELF prints header (/bin/sh)" 0 "$code" "$ELF_HEADER_HEADING" "$out"
fi

# 6. Truncated inputs: a short header is a read error; a cut-off ELF is structural.
head -c 4 "$BIN" > "$TMP/truncated-header.elf"
out="$("$RUN_BIN" "$TMP/truncated-header.elf" 2>&1)"; code=$?
check "truncated ELF header reports a clear error" 1 "$code" "truncated ELF header" "$out"

head -c 8192 "$BIN" > "$TMP/truncated.elf"
out="$("$RUN_BIN" "$TMP/truncated.elf" 2>&1)"; code=$?
check "truncated ELF flagged"        2 "$code" "issue(s) found"  "$out"
check "truncated ELF reports marker" 2 "$code" "[!]"            "$out"

# elfcheck parses ELF64 little-endian structures only; reject other encodings.
out="$("$RUN_BIN" "$(corrupt_copy class.elf 4 1 1)" 2>&1)"; code=$?
check "ELF32 input is rejected explicitly" 1 "$code" "only ELF64 little-endian" "$out"
out="$("$RUN_BIN" "$(corrupt_copy endian.elf 5 2 1)" 2>&1)"; code=$?
check "big-endian input is rejected explicitly" 1 "$code" "only ELF64 little-endian" "$out"

# 6b. Corrupted header fields (ELF64 offsets): each must be flagged, exit 2.
#     A fresh unmodified copy must still validate cleanly (control).
out="$("$RUN_BIN" "$(corrupt_copy control.elf 0 0 0)" 2>&1)"; code=$?
check "unmodified copy validates"    0 "$code" "no structural issues" "$out"

out="$("$RUN_BIN" "$(corrupt_copy ehsize.elf 52 0 2)" 2>&1)"; code=$?
check "bad e_ehsize detected"        2 "$code" "e_ehsize"        "$out"

out="$("$RUN_BIN" "$(corrupt_copy shstrndx.elf 62 254 2)" 2>&1)"; code=$?
check "bad e_shstrndx detected"      2 "$code" "e_shstrndx"      "$out"

out="$("$RUN_BIN" "$(corrupt_copy shoff.elf 40 4000000000 8)" 2>&1)"; code=$?
check "bad e_shoff detected"         2 "$code" "section header table extends" "$out"

out="$("$RUN_BIN" "$(corrupt_copy phoff.elf 32 4000000000 8)" 2>&1)"; code=$?
check "bad e_phoff detected"         2 "$code" "program header table extends" "$out"

out="$("$RUN_BIN" --validate "$(corrupt_copy shoff-wrap.elf 40 -1 8)" 2>&1)"; code=$?
check "wrapped section table end is detected" 2 "$code" "section header table extends" "$out"
out="$("$RUN_BIN" --validate "$(corrupt_copy phoff-wrap.elf 32 -1 8)" 2>&1)"; code=$?
check "wrapped program table end is detected" 2 "$code" "program header table extends" "$out"

out="$("$RUN_BIN" --validate "$(corrupt_copy phentsize.elf 54 0 2)" 2>&1)"; code=$?
check "bad e_phentsize is detected" 2 "$code" "unexpected e_phentsize=0" "$out"
out="$("$RUN_BIN" --validate "$(corrupt_copy shentsize.elf 58 0 2)" 2>&1)"; code=$?
check "bad e_shentsize is detected" 2 "$code" "unexpected e_shentsize=0" "$out"

out="$("$RUN_BIN" --validate "$(corrupt_copy ident-version.elf 6 0 1)" 2>&1)"; code=$?
check "bad EI_VERSION is detected" 2 "$code" "unexpected e_ident version=0" "$out"
out="$("$RUN_BIN" --validate "$(corrupt_copy version.elf 20 0 4)" 2>&1)"; code=$?
check "bad e_version is detected" 2 "$code" "unexpected e_version=0" "$out"

if command -v python3 >/dev/null 2>&1; then
    python3 - "$BIN" "$TMP" <<'PY'
import pathlib
import struct
import sys

source = bytearray(pathlib.Path(sys.argv[1]).read_bytes())
tmp = pathlib.Path(sys.argv[2])


def write_fixture(name, mutate):
    data = bytearray(source)
    mutate(data)
    (tmp / name).write_bytes(data)


def first_program_header(data, wanted_type):
    offset = struct.unpack_from('<Q', data, 32)[0]
    entry_size = struct.unpack_from('<H', data, 54)[0]
    count = struct.unpack_from('<H', data, 56)[0]
    for index in range(count):
        entry = offset + index * entry_size
        if struct.unpack_from('<I', data, entry)[0] == wanted_type:
            return entry
    raise SystemExit(f'program header type {wanted_type} not found')


def first_file_backed_section(data):
    offset = struct.unpack_from('<Q', data, 40)[0]
    entry_size = struct.unpack_from('<H', data, 58)[0]
    count = struct.unpack_from('<H', data, 60)[0]
    for index in range(count):
        entry = offset + index * entry_size
        section_type = struct.unpack_from('<I', data, entry + 4)[0]
        size = struct.unpack_from('<Q', data, entry + 32)[0]
        if section_type not in (0, 8) and size:
            return entry
    raise SystemExit('file-backed section not found')


def filesz_exceeds_memsz(data):
    entry = first_program_header(data, 1)
    file_size = struct.unpack_from('<Q', data, entry + 32)[0]
    if not file_size:
        raise SystemExit('non-empty PT_LOAD not found')
    struct.pack_into('<Q', data, entry + 40, file_size - 1)


def overflowing_segment_range(data):
    entry = first_program_header(data, 1)
    struct.pack_into('<Q', data, entry + 8, (1 << 64) - 8)
    struct.pack_into('<Q', data, entry + 32, 16)
    struct.pack_into('<Q', data, entry + 40, 16)


def overflowing_section_range(data):
    entry = first_file_backed_section(data)
    struct.pack_into('<QQ', data, entry + 24, (1 << 64) - 8, 16)


def remove_section_table(data):
    struct.pack_into('<Q', data, 40, 0)
    struct.pack_into('<H', data, 58, 0)
    struct.pack_into('<H', data, 60, 0)
    struct.pack_into('<H', data, 62, 0)


write_fixture('segment-filesz.elf', filesz_exceeds_memsz)
write_fixture('segment-overflow.elf', overflowing_segment_range)
write_fixture('section-overflow.elf', overflowing_section_range)
write_fixture('sectionless.elf', remove_section_table)
PY

    out="$("$RUN_BIN" --validate "$TMP/segment-filesz.elf" 2>&1)"; code=$?
    check "PT_LOAD filesz greater than memsz is detected" 2 "$code" "p_filesz > p_memsz" "$out"
    out="$("$RUN_BIN" --validate "$TMP/segment-overflow.elf" 2>&1)"; code=$?
    check "overflowing segment file range is detected" 2 "$code" "segment 0 extends past end of file" "$out"
    out="$("$RUN_BIN" --validate "$TMP/section-overflow.elf" 2>&1)"; code=$?
    check "overflowing section file range is detected" 2 "$code" "extends past end of file" "$out"
    out="$("$RUN_BIN" --validate "$TMP/sectionless.elf" 2>&1)"; code=$?
    check "sectionless ELF validates cleanly" 0 "$code" "no structural issues" "$out"
fi

# 7. JSON output mode
out="$("$RUN_BIN" --json "$BIN" 2>&1)"; code=$?
check "--json exits 0 for valid ELF"  0 "$code" '{"header":{'       "$out"
check "--json has program_headers"   0 "$code" '"program_headers":' "$out"
check "--json has section_headers"   0 "$code" '"section_headers":' "$out"
check "--json reports valid:true"    0 "$code" '"valid":true'      "$out"

# flag accepted after the path too
out="$("$RUN_BIN" "$BIN" --json 2>&1)"; code=$?
check "--json accepted after path"   0 "$code" '{"header":{'       "$out"

# JSON on a malformed file -> valid:false, exit 2
out="$("$RUN_BIN" --json "$TMP/truncated.elf" 2>&1)"; code=$?
check "--json flags malformed ELF"   2 "$code" '"valid":false'     "$out"

# If python3 is available, assert the JSON actually parses
if command -v python3 >/dev/null 2>&1; then
    "$RUN_BIN" --json "$BIN" 2>/dev/null | python3 -m json.tool >/dev/null 2>&1
    pcode=$?
    check "--json is well-formed JSON" 0 "$pcode" "" ""
fi

# 8. Symbol tables (opt-in text section, complete in JSON)
out="$("$RUN_BIN" --symbols "$BIN" 2>&1)"; code=$?
check "--symbols handles a static ELF"       0 "$code" ".symtab" "$out"
check "--symbols finds the static entry point" 0 "$code" "_start" "$out"
check_absent "static ELF has no dynamic symbol table" 0 "$code" "Symbol table '.dynsym'" "$out"

if command -v gcc >/dev/null 2>&1; then
    cat > "$TMP/symbols.c" <<'EOF'
int elfcheck_symbol_fixture(int value) { return value + 7; }
int main(void) { return elfcheck_symbol_fixture(1); }
EOF
    if gcc -g -O0 -o "$TMP/symbols.elf" "$TMP/symbols.c" 2>/dev/null; then
        out="$("$RUN_BIN" --symbols "$TMP/symbols.elf" 2>&1)"; code=$?
        check "--symbols exits 0 for valid ELF"    0 "$code" "$SYMBOL_TABLES_HEADING" "$out"
        check "--symbols lists static table"       0 "$code" ".symtab" "$out"
        check "--symbols lists dynamic table"      0 "$code" ".dynsym" "$out"
        check "--symbols resolves a defined name"  0 "$code" "elfcheck_symbol_fixture" "$out"
        check "--symbols prints type and binding"  0 "$code" "FUNC" "$out"

        cat > "$TMP/versioned.c" <<'EOF'
int elfcheck_versioned_api(void) { return 42; }
EOF
        cat > "$TMP/versioned.map" <<'EOF'
ELFCHECK_1.0 { global: elfcheck_versioned_api; local: *; };
EOF
        if gcc -shared -fPIC -Wl,--version-script="$TMP/versioned.map" -o "$TMP/libversioned.so" "$TMP/versioned.c" 2>/dev/null; then
            out="$("$RUN_BIN" --symbols "$TMP/libversioned.so" 2>&1)"; code=$?
            check "--symbols prints default GNU version" 0 "$code" "elfcheck_versioned_api@@ELFCHECK_1.0" "$out"
            out="$("$RUN_BIN" --json "$TMP/libversioned.so" 2>&1)"; code=$?
            printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); s=[x for t in d["symbol_tables"] if t["name"]==".dynsym" for x in t["symbols"] if x["name"]=="elfcheck_versioned_api"]; assert len(s)==1 and s[0]["version"]["kind"]=="defined" and s[0]["version"]["name"]=="ELFCHECK_1.0" and s[0]["version"]["library"] is None and s[0]["version"]["hidden"] is False'
            pcode=$?
            check "JSON exposes a defined GNU symbol version" 0 "$pcode" "" ""
        fi

        out="$("$RUN_BIN" "$TMP/symbols.elf" --symbols 2>&1)"; code=$?
        check "--symbols accepted after path"      0 "$code" "$SYMBOL_TABLES_HEADING" "$out"

        out="$("$RUN_BIN" --header --symbols "$TMP/symbols.elf" 2>&1)"; code=$?
        check "combined filter includes symbols"   0 "$code" "$SYMBOL_TABLES_HEADING" "$out"
        check "combined filter includes header"    0 "$code" "$ELF_HEADER_HEADING" "$out"
        check_absent "combined filter hides hardening" 0 "$code" "$HARDENING_HEADING" "$out"

        out="$("$RUN_BIN" "$TMP/symbols.elf" 2>&1)"; code=$?
        check_absent "default report keeps symbols opt-in" 0 "$code" "$SYMBOL_TABLES_HEADING" "$out"

        out="$("$RUN_BIN" --json "$TMP/symbols.elf" 2>&1)"; code=$?
        check "JSON includes symbol table array" 0 "$code" '"symbol_tables":[' "$out"
        check "JSON includes symbol metadata"   0 "$code" '"binding":"GLOBAL"' "$out"
        check "JSON includes fixture symbol"     0 "$code" '"name":"elfcheck_symbol_fixture"' "$out"
        if command -v python3 >/dev/null 2>&1; then
            printf '%s' "$out" | python3 -m json.tool >/dev/null 2>&1
            pcode=$?
            check "JSON with symbol tables parses" 0 "$pcode" "" ""
            printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); syms=[s for t in d["symbol_tables"] for s in t["symbols"]]; assert syms and all(isinstance(s["section_index"], int) and (s["section_kind"] is None or isinstance(s["section_kind"], str)) for s in syms)'
            pcode=$?
            check "JSON symbol section fields are typed" 0 "$pcode" "" ""
        fi

        if command -v strip >/dev/null 2>&1; then
            cp "$TMP/symbols.elf" "$TMP/symbols.stripped.elf"
            if strip --strip-all "$TMP/symbols.stripped.elf" 2>/dev/null; then
                out="$("$RUN_BIN" --symbols "$TMP/symbols.stripped.elf" 2>&1)"; code=$?
                check "stripped ELF retains dynamic symbols" 0 "$code" ".dynsym" "$out"
                check_absent "stripped ELF has no static symbol table" 0 "$code" ".symtab" "$out"
            fi
        fi

        if command -v python3 >/dev/null 2>&1; then
            cp "$TMP/symbols.elf" "$TMP/bad-symbols.elf"
            python3 - "$TMP/bad-symbols.elf" <<'PY'
import struct, sys
p = sys.argv[1]
d = bytearray(open(p, 'rb').read())
off = struct.unpack_from('<Q', d, 40)[0]
es = struct.unpack_from('<H', d, 58)[0]
n = struct.unpack_from('<H', d, 60)[0]
for i in range(n):
    at = off + i * es
    if struct.unpack_from('<I', d, at + 4)[0] in (2, 11):
        struct.pack_into('<Q', d, at + 56, 0)
open(p, 'wb').write(d)
PY
            out="$("$RUN_BIN" --symbols "$TMP/bad-symbols.elf" 2>&1)"; code=$?
            check "zero symbol entry size is handled safely" 0 "$code" "invalid symbol table metadata" "$out"
        fi
    fi
fi

# 9. REL/RELA relocation tables
if command -v gcc >/dev/null 2>&1; then
    cat > "$TMP/relocs.c" <<'EOF'
extern int elfcheck_reloc_target(int);
extern int elfcheck_reloc_data;
int elfcheck_reloc_fixture(int value) { return elfcheck_reloc_target(value) + 3; }
int elfcheck_reloc_read(void) { return elfcheck_reloc_data; }
int *elfcheck_reloc_address(void) {
    int *address;
    __asm__ volatile ("lea elfcheck_reloc_data(%%rip), %0" : "=r" (address));
    return address;
}
void elfcheck_reloc_write(void) { elfcheck_reloc_data = 7; }
EOF
    if gcc -c -fno-pic -o "$TMP/relocs.o" "$TMP/relocs.c" 2>/dev/null; then
        out="$("$RUN_BIN" --relocs "$TMP/relocs.o" 2>&1)"; code=$?
        check "--relocs exits 0 for relocatable ELF" 0 "$code" "$RELOCATIONS_HEADING" "$out"
        check "--relocs names the RELA section"       0 "$code" ".rela.text" "$out"
        check "--relocs shows target section"         0 "$code" "target: .text" "$out"
        check "--relocs decodes x86-64 PLT32"        0 "$code" "R_X86_64_PLT32" "$out"
        check "--relocs resolves symbol name"         0 "$code" "elfcheck_reloc_target" "$out"
        check "--relocs prints signed addend"         0 "$code" "-4" "$out"

        out="$("$RUN_BIN" --function elfcheck_reloc_fixture "$TMP/relocs.o" 2>&1)"; code=$?
        check "ET_REL branch resolves its relocation symbol and type" 0 "$code" "<elfcheck_reloc_target> [R_X86_64_PLT32]" "$out"
        out="$("$RUN_BIN" --function elfcheck_reloc_read "$TMP/relocs.o" 2>&1)"; code=$?
        check "ET_REL RIP-relative data read resolves relocation" 0 "$code" "[rip+elfcheck_reloc_data] [R_X86_64_PC32]" "$out"
        out="$("$RUN_BIN" --function elfcheck_reloc_address "$TMP/relocs.o" 2>&1)"; code=$?
        check "ET_REL RIP-relative data address resolves relocation" 0 "$code" "[rip+elfcheck_reloc_data] [R_X86_64_PC32]" "$out"
        out="$("$RUN_BIN" --function elfcheck_reloc_write "$TMP/relocs.o" 2>&1)"; code=$?
        check "ET_REL RIP-relative immediate store resolves displacement field" 0 "$code" "[rip+elfcheck_reloc_data] [R_X86_64_PC32], 0x7" "$out"

        out="$("$RUN_BIN" --disasm "$TMP/relocs.o" 2>&1)"; code=$?
        check "ET_REL full-section disassembly resolves relocation target" 0 "$code" "<elfcheck_reloc_target> [R_X86_64_PLT32]" "$out"

        cat > "$TMP/relocs-pic.c" <<'EOF'
extern int elfcheck_reloc_data;
int elfcheck_reloc_pic_read(void) { return elfcheck_reloc_data; }
EOF
        if gcc -c -fPIC -o "$TMP/relocs-pic.o" "$TMP/relocs-pic.c" 2>/dev/null; then
            out="$("$RUN_BIN" --function elfcheck_reloc_pic_read "$TMP/relocs-pic.o" 2>&1)"; code=$?
            check "ET_REL PIC data reference resolves a GOT relocation" 0 "$code" "[rip+elfcheck_reloc_data] [" "$out"
            case "$out" in
                *"[R_X86_64_GOTPCREL]"*|*"[R_X86_64_GOTPCRELX]"*|*"[R_X86_64_REX_GOTPCRELX]"*) got_code=0 ;;
                *) got_code=1 ;;
            esac
            check "ET_REL PIC data reference names its GOT relocation type" 0 "$got_code" "R_X86_64_" "$out"
        fi

        out="$("$RUN_BIN" "$TMP/relocs.o" --relocs 2>&1)"; code=$?
        check "--relocs accepted after path"           0 "$code" "$RELOCATIONS_HEADING" "$out"

        out="$("$RUN_BIN" --header --relocs "$TMP/relocs.o" 2>&1)"; code=$?
        check "combined filter includes relocations" 0 "$code" "$RELOCATIONS_HEADING" "$out"
        check "combined relocation filter includes header" 0 "$code" "$ELF_HEADER_HEADING" "$out"
        check_absent "combined relocation filter hides symbols" 0 "$code" "$SYMBOL_TABLES_HEADING" "$out"

        out="$("$RUN_BIN" "$TMP/relocs.o" 2>&1)"; code=$?
        check_absent "default report keeps relocations opt-in" 0 "$code" "$RELOCATIONS_HEADING" "$out"

        out="$("$RUN_BIN" --json "$TMP/relocs.o" 2>&1)"; code=$?
        check "JSON includes relocation table array" 0 "$code" '"relocation_tables":[' "$out"
        check "JSON includes relocation type" 0 "$code" '"type":"R_X86_64_PLT32"' "$out"
        check "JSON includes relocation symbol" 0 "$code" '"symbol_name":"elfcheck_reloc_target"' "$out"
        check "JSON includes signed relocation addend" 0 "$code" '"addend":-4' "$out"
        if command -v python3 >/dev/null 2>&1; then
            printf '%s' "$out" | python3 -m json.tool >/dev/null 2>&1
            pcode=$?
            check "JSON with relocations parses" 0 "$pcode" "" ""
            printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); t=next(t for t in d["relocation_tables"] if t["name"]==".rela.text"); r=t["relocations"][0]; assert t["kind"]=="RELA" and t["target_name"]==".text" and r["type_id"]==4 and r["symbol_name"]=="elfcheck_reloc_target" and r["addend"]==-4'
            pcode=$?
            check "JSON relocation fields match ELF record" 0 "$pcode" "" ""

            cp "$TMP/relocs.o" "$TMP/rel.o"
            python3 - "$TMP/rel.o" <<'PY'
import struct, sys
p = sys.argv[1]
d = bytearray(open(p, 'rb').read())
off = struct.unpack_from('<Q', d, 40)[0]
es = struct.unpack_from('<H', d, 58)[0]
n = struct.unpack_from('<H', d, 60)[0]
for i in range(n):
    at = off + i * es
    if struct.unpack_from('<I', d, at + 4)[0] == 4:
        rel_off, rel_size = struct.unpack_from('<QQ', d, at + 24)
        rel_entsize = struct.unpack_from('<Q', d, at + 56)[0]
        count = rel_size // rel_entsize
        records = [bytes(d[rel_off + i * rel_entsize:rel_off + i * rel_entsize + 16]) for i in range(count)]
        for i, record in enumerate(records):
            d[rel_off + i * 16:rel_off + (i + 1) * 16] = record
        struct.pack_into('<I', d, at + 4, 9)
        struct.pack_into('<Q', d, at + 32, count * 16)
        struct.pack_into('<Q', d, at + 56, 16)
        break
open(p, 'wb').write(d)
PY
            out="$("$RUN_BIN" --relocs "$TMP/rel.o" 2>&1)"; code=$?
            check "SHT_REL entries are decoded" 0 "$code" "(index 2, REL, target: .text" "$out"
            check "REL entries omit the addend" 0 "$code" "elfcheck_reloc_target" "$out"
            out="$("$RUN_BIN" --function elfcheck_reloc_fixture "$TMP/rel.o" 2>&1)"; code=$?
            check "ET_REL SHT_REL branch resolves its symbol and type" 0 "$code" "<elfcheck_reloc_target> [R_X86_64_PLT32]" "$out"
            out="$("$RUN_BIN" --function elfcheck_reloc_read "$TMP/rel.o" 2>&1)"; code=$?
            check "ET_REL SHT_REL data reference resolves its symbol and type" 0 "$code" "[rip+elfcheck_reloc_data] [R_X86_64_PC32]" "$out"
            out="$("$RUN_BIN" --json "$TMP/rel.o" 2>&1)"; code=$?
            check "JSON REL addend is null" 0 "$code" '"addend":null' "$out"

            cp "$TMP/relocs.o" "$TMP/bad-relocs.o"
            python3 - "$TMP/bad-relocs.o" <<'PY'
import struct, sys
p = sys.argv[1]
d = bytearray(open(p, 'rb').read())
off = struct.unpack_from('<Q', d, 40)[0]
es = struct.unpack_from('<H', d, 58)[0]
n = struct.unpack_from('<H', d, 60)[0]
for i in range(n):
    at = off + i * es
    if struct.unpack_from('<I', d, at + 4)[0] in (4, 9):
        struct.pack_into('<Q', d, at + 56, 0)
        break
open(p, 'wb').write(d)
PY
            out="$("$RUN_BIN" --relocs "$TMP/bad-relocs.o" 2>&1)"; code=$?
            check "zero relocation entry size is handled safely" 0 "$code" "invalid relocation section metadata" "$out"
        fi
    fi
fi

# 10. Disassembler mode
out="$("$RUN_BIN" --disasm "$BIN" 2>&1)"; code=$?
check "--disasm exits 0 for valid ELF"   0 "$code" "$TEXT_DISASSEMBLY_HEADING" "$out"
check "--disasm decodes syscall"         0 "$code" "syscall" "$out"
check "--disasm decodes call"            0 "$code" "call"    "$out"
check "--disasm decodes mov"             0 "$code" "mov"     "$out"
check "--disasm shows instruction bytes" 0 "$code" "0f 05"   "$out"

# -d is an alias for --disasm
out="$("$RUN_BIN" -d "$BIN" 2>&1)"; code=$?
check "-d alias works"                    0 "$code" "$TEXT_DISASSEMBLY_HEADING" "$out"

# flag accepted after the path too
out="$("$RUN_BIN" "$BIN" -d 2>&1)"; code=$?
check "-d accepted after path"            0 "$code" "$TEXT_DISASSEMBLY_HEADING" "$out"

# VEX/AVX disassembly: compare supported instructions and bytes against objdump.
if command -v nasm >/dev/null 2>&1 && command -v objdump >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    cat > "$TMP/vex.asm" <<'EOF'
BITS 64
section .text

global elfcheck_vex_fixture:function (elfcheck_vex_fixture.end - elfcheck_vex_fixture)
elfcheck_vex_fixture:
    vandps xmm0, xmm1, xmm2
    vandpd xmm3, xmm4, xmm5
    vandnps xmm5, xmm6, xmm7
    vandnpd xmm8, xmm9, xmm10
    vorps xmm0, xmm1, xmm2
    vorpd xmm3, xmm4, xmm5
    vxorps xmm5, xmm6, xmm7
    vxorpd xmm8, xmm9, xmm10
    vaddps xmm0, xmm1, xmm2
    vaddpd xmm3, xmm4, xmm5
    vaddss xmm5, xmm6, xmm7
    vmulps xmm0, xmm1, xmm2
    vmulsd xmm3, xmm4, xmm5
    vsubps xmm5, xmm6, xmm7
    vsubsd xmm8, xmm9, xmm10
    vminss xmm0, xmm1, xmm2
    vminpd xmm3, xmm4, xmm5
    vdivss xmm5, xmm6, xmm7
    vdivpd xmm8, xmm9, xmm10
    vmaxps xmm0, xmm1, xmm2
    vmaxsd xmm3, xmm4, xmm5
    vaddps xmm8, xmm9, xmm10
    vaddps ymm0, ymm1, ymm2
    vaddpd ymm3, ymm4, ymm5
    vandps ymm8, ymm9, ymm10
    vaddps ymm8, ymm9, ymm10
    vzeroupper
    ret
.end:

global elfcheck_vex_memory:function (elfcheck_vex_memory.end - elfcheck_vex_memory)
elfcheck_vex_memory:
    vaddps xmm0, xmm1, [r8 + r9*4 + 16]
    vaddps ymm0, ymm1, [r8 + r9*4 + 32]
    ret
.end:

global elfcheck_evex_unsupported:function (elfcheck_evex_unsupported.end - elfcheck_evex_unsupported)
elfcheck_evex_unsupported:
    db 0x62, 0xf1, 0x7c, 0x48, 0x58, 0xc2
    ret
.end:

global elfcheck_vex_scalar_l_unsupported:function (elfcheck_vex_scalar_l_unsupported.end - elfcheck_vex_scalar_l_unsupported)
elfcheck_vex_scalar_l_unsupported:
    db 0xc5, 0xf6, 0x58, 0xc2
    ret
.end:

global elfcheck_vex_truncated:function (elfcheck_vex_truncated.end - elfcheck_vex_truncated)
elfcheck_vex_truncated:
    db 0xc5
.end:
EOF
    if nasm -f elf64 -o "$TMP/vex.o" "$TMP/vex.asm" 2>/dev/null; then
        out="$("$RUN_BIN" --function elfcheck_vex_fixture "$TMP/vex.o" 2>&1)"; code=$?
        check "VEX decodes packed and scalar 128-bit arithmetic" 0 "$code" "vaddss" "$out"
        check "VEX decodes the inverted vvvv register field" 0 "$code" "xmm0, xmm1, xmm2" "$out"
        check "VEX C4 decodes extended XMM registers" 0 "$code" "xmm8, xmm9, xmm10" "$out"
        check "VEX.L=1 decodes 256-bit YMM registers" 0 "$code" "ymm0, ymm1, ymm2" "$out"
        check "VEX.L=1 decodes extended YMM registers" 0 "$code" "ymm8, ymm9, ymm10" "$out"
        check "VEX decodes vzeroupper" 0 "$code" "vzeroupper" "$out"

        printf '%s\n' "$out" > "$TMP/elfcheck-vex.out"
        objdump -d -Mintel --disassemble=elfcheck_vex_fixture "$TMP/vex.o" > "$TMP/objdump-vex.out"
        diff_out="$(python3 - "$TMP/elfcheck-vex.out" "$TMP/objdump-vex.out" <<'PY'
import re
import sys

instruction = re.compile(r"^\s*(?:0x)?[0-9a-f]+:\s*((?:[0-9a-f]{2}\s+)+)\s*(.*?)\s*$", re.I)

def parse(path):
    result = []
    for line in open(path, encoding="utf-8"):
        match = instruction.match(line)
        if not match:
            continue
        raw_bytes = " ".join(match.group(1).split()).lower()
        assembly = re.sub(r"\s*,\s*", ",", match.group(2).strip().lower())
        assembly = " ".join(assembly.split())
        result.append((raw_bytes, assembly))
    return result

elfcheck, objdump = map(parse, sys.argv[1:])
if not elfcheck or elfcheck != objdump:
    print(f"elfcheck: {elfcheck}")
    print(f"objdump:  {objdump}")
    raise SystemExit(1)
print("instruction sequences match")
PY
)"; diff_code=$?
        check "VEX instruction bytes and operands match objdump" 0 "$diff_code" "instruction sequences match" "$diff_out"

        out="$("$RUN_BIN" --function elfcheck_vex_memory "$TMP/vex.o" 2>&1)"; code=$?
        check "VEX C4 decodes extended memory base and index" 0 "$code" "[r8+r9*4+0x10]" "$out"
        check "256-bit VEX marks 32-byte memory operands" 0 "$code" "ymmword [r8+r9*4+0x20]" "$out"

        out="$("$RUN_BIN" --function elfcheck_evex_unsupported "$TMP/vex.o" 2>&1)"; code=$?
        check "EVEX remains on byte fallback" 0 "$code" ".byte 0x62" "$out"

        out="$("$RUN_BIN" --function elfcheck_vex_scalar_l_unsupported "$TMP/vex.o" 2>&1)"; code=$?
        check "scalar VEX.L=1 remains on byte fallback" 0 "$code" ".byte 0xc5" "$out"

        out="$("$RUN_BIN" --function elfcheck_vex_truncated "$TMP/vex.o" 2>&1)"; code=$?
        check "truncated VEX prefix safely falls back to one byte" 0 "$code" ".byte 0xc5" "$out"
    else
        check "NASM assembles VEX test fixture" 0 1 "unavailable" ""
    fi
fi

# --function narrows disassembly to a bounded STT_FUNC symbol
out="$("$RUN_BIN" --function 2>&1)"; code=$?
check "--function requires a name and file" 1 "$code" "$USAGE_HEADING" "$out"
if command -v gcc >/dev/null 2>&1; then
    cat > "$TMP/functions.c" <<'EOF'
__attribute__((noinline)) int elfcheck_callee(int value) { return value * 2; }
__attribute__((noinline)) int elfcheck_target(int value) { return elfcheck_callee(value) + 7; }
__attribute__((noinline)) int elfcheck_other(int value) {
    __asm__ volatile ("ud2");
    return value * 31;
}
__attribute__((noinline)) void elfcheck_sse_copy(float *destination, const float *source) {
    __asm__ volatile (
        "movups (%1), %%xmm0\n\t"
        "movups %%xmm0, (%0)\n\t"
        "movaps (%1), %%xmm1\n\t"
        "movaps %%xmm1, (%0)\n\t"
        "xorps %%xmm1, %%xmm0\n\t"
        "addps %%xmm1, %%xmm0\n\t"
        "movss (%1), %%xmm2\n\t"
        "movsd (%1), %%xmm3\n\t"
        "movupd (%1), %%xmm4\n\t"
        "xorpd %%xmm4, %%xmm3"
        : : "r"(destination), "r"(source)
        : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "memory");
}
__attribute__((naked, noinline)) void elfcheck_jump(void) {
    __asm__ volatile ("jmp elfcheck_callee");
}
__attribute__((naked, noinline)) void elfcheck_conditional_jump(void) {
    __asm__ volatile ("test %edi, %edi\n\tje elfcheck_callee\n\tret");
}
int main(void) { return elfcheck_target(1) + elfcheck_other(2); }
EOF
    if gcc -g -O0 -fno-inline -o "$TMP/functions.elf" "$TMP/functions.c" 2>/dev/null; then
        out="$("$RUN_BIN" --function elfcheck_target "$TMP/functions.elf" 2>&1)"; code=$?
        check "--function selects a named function" 0 "$code" "Disassembly of function elfcheck_target in section .text:" "$out"
        check "direct call target is annotated with its symbol" 0 "$code" "$CALLEE_ANNOTATION" "$out"
        check_absent "target disassembly excludes other function bytes" 0 "$code" ".byte 0x0f" "$out"
        check_absent "target disassembly omits whole-section title" 0 "$code" "$TEXT_DISASSEMBLY_HEADING" "$out"

        out="$("$RUN_BIN" "$TMP/functions.elf" --function elfcheck_other 2>&1)"; code=$?
        check "--function works after the path" 0 "$code" "Disassembly of function elfcheck_other in section .text:" "$out"
        check "other function range decodes UD2" 0 "$code" "ud2" "$out"

        out="$("$RUN_BIN" --function elfcheck_sse_copy "$TMP/functions.elf" 2>&1)"; code=$?
        check "SSE decoder prints XMM registers" 0 "$code" "xmm0" "$out"
        check "SSE decoder formats packed memory operands" 0 "$code" "xmmword [" "$out"
        check "SSE decoder handles aligned moves" 0 "$code" "movaps" "$out"
        check "SSE decoder handles unaligned moves" 0 "$code" "movups" "$out"
        check "SSE decoder handles scalar move widths" 0 "$code" "movss" "$out"
        check "SSE decoder handles double scalar move" 0 "$code" "movsd" "$out"
        check "SSE decoder handles packed arithmetic" 0 "$code" "addps" "$out"
        check "SSE decoder selects 66-prefix variants" 0 "$code" "movupd" "$out"
        check "SSE decoder handles packed double operation" 0 "$code" "xorpd" "$out"

        out="$("$RUN_BIN" --function elfcheck_jump "$TMP/functions.elf" 2>&1)"; code=$?
        check "direct jmp target is annotated" 0 "$code" "$CALLEE_ANNOTATION" "$out"
        out="$("$RUN_BIN" --function elfcheck_conditional_jump "$TMP/functions.elf" 2>&1)"; code=$?
        check "conditional branch target is annotated" 0 "$code" "$CALLEE_ANNOTATION" "$out"

        out="$("$RUN_BIN" --function elfcheck_missing "$TMP/functions.elf" 2>&1)"; code=$?
        check "missing function reports an error" 1 "$code" "function not found: elfcheck_missing" "$out"

        if command -v python3 >/dev/null 2>&1; then
            cp "$TMP/functions.elf" "$TMP/functions.zero-size.elf"
            python3 - "$TMP/functions.zero-size.elf" <<'PY'
import struct, sys
path = sys.argv[1]
data = bytearray(open(path, 'rb').read())
shoff = struct.unpack_from('<Q', data, 40)[0]
shentsize = struct.unpack_from('<H', data, 58)[0]
shnum = struct.unpack_from('<H', data, 60)[0]
found = False
for index in range(shnum):
    sh = shoff + index * shentsize
    section_type = struct.unpack_from('<I', data, sh + 4)[0]
    if section_type not in (2, 11):
        continue
    offset, size = struct.unpack_from('<QQ', data, sh + 24)
    link = struct.unpack_from('<I', data, sh + 40)[0]
    entsize = struct.unpack_from('<Q', data, sh + 56)[0]
    str_sh = shoff + link * shentsize
    str_off, str_size = struct.unpack_from('<QQ', data, str_sh + 24)
    strings = data[str_off:str_off + str_size]
    for symbol in range(offset, offset + size, entsize):
        name_off = struct.unpack_from('<I', data, symbol)[0]
        info = data[symbol + 4]
        if name_off < len(strings) and (info & 0x0f) == 2:
            name = strings[name_off:].split(bytes([0]), 1)[0]
            if name == b'elfcheck_target':
                struct.pack_into('<Q', data, symbol + 16, 0)
                found = True
                break
    if found:
        break
if not found:
    raise SystemExit('fixture function symbol not found')
open(path, 'wb').write(data)
PY
            out="$("$RUN_BIN" --function elfcheck_target "$TMP/functions.zero-size.elf" 2>&1)"; code=$?
            check "zero-sized function is rejected" 1 "$code" "no usable executable range: elfcheck_target" "$out"
        fi

        if gcc -g -O0 -fno-inline -c -o "$TMP/functions.o" "$TMP/functions.c" 2>/dev/null; then
            out="$("$RUN_BIN" --function elfcheck_target "$TMP/functions.o" 2>&1)"; code=$?
            check "--function resolves ET_REL section-relative values" 0 "$code" "Disassembly of function elfcheck_target in section .text:" "$out"
            check_absent "ET_REL target excludes other function bytes" 0 "$code" ".byte 0x0f" "$out"
        fi

        if gcc -no-pie -g -O0 -fno-inline -o "$TMP/functions.exec" "$TMP/functions.c" 2>/dev/null; then
            out="$("$RUN_BIN" --function elfcheck_target "$TMP/functions.exec" 2>&1)"; code=$?
            check "--function resolves ET_EXEC virtual addresses" 0 "$code" "Disassembly of function elfcheck_target in section .text:" "$out"
            check "ET_EXEC direct call target is annotated" 0 "$code" "$CALLEE_ANNOTATION" "$out"
        fi

        if command -v strip >/dev/null 2>&1 && gcc -rdynamic -g -O0 -fno-inline -o "$TMP/functions.exported" "$TMP/functions.c" 2>/dev/null && strip --strip-all "$TMP/functions.exported" 2>/dev/null; then
            out="$("$RUN_BIN" --function elfcheck_target "$TMP/functions.exported" 2>&1)"; code=$?
            check "stripped dynsym function is found" 0 "$code" "Disassembly of function elfcheck_target" "$out"
            check "stripped dynsym call target is annotated" 0 "$code" "$CALLEE_ANNOTATION" "$out"
        fi
    fi
fi

# 11. Security analysis (segment permissions + stack executability)
out="$("$RUN_BIN" "$BIN" 2>&1)"; code=$?
check "security section present"          0 "$code" "Security:" "$out"

out="$("$RUN_BIN" --json "$BIN" 2>&1)"; code=$?
check "--json has security object"       0 "$code" '"security":{'  "$out"
check "--json has gnu_stack field"       0 "$code" '"gnu_stack":' "$out"

# W^X detection: craft an RWX PT_LOAD segment (needs python3)
if command -v python3 >/dev/null 2>&1; then
    wx="$TMP/wx.elf"; cp "$BIN" "$wx"
    python3 - "$wx" <<'PY'
import sys, struct
p = sys.argv[1]; d = bytearray(open(p, 'rb').read())
off = struct.unpack_from('<Q', d, 32)[0]
es  = struct.unpack_from('<H', d, 54)[0]
n   = struct.unpack_from('<H', d, 56)[0]
for i in range(n):
    b = off + i * es
    t = struct.unpack_from('<I', d, b)[0]
    f = struct.unpack_from('<I', d, b + 4)[0]
    if t == 1 and (f & 1):           # PT_LOAD with X -> add W
        struct.pack_into('<I', d, b + 4, f | 2)
        break
open(p, 'wb').write(d)
PY
    out="$("$RUN_BIN" "$wx" 2>&1)"; code=$?
    check "W^X LOAD segment detected"     0 "$code" "W^X violation"  "$out"

    # suspicious: entry point outside any executable segment
    be="$TMP/badentry.elf"; cp "$BIN" "$be"
    python3 - "$be" <<'PY'
import sys, struct
p = sys.argv[1]; d = bytearray(open(p, 'rb').read())
struct.pack_into('<Q', d, 24, 0xdeadbeef)    # e_entry -> bogus address
open(p, 'wb').write(d)
PY
    out="$("$RUN_BIN" "$be" 2>&1)"; code=$?
    check "bad entry point detected"       0 "$code" "not inside any executable segment" "$out"
    out="$("$RUN_BIN" --json "$be" 2>&1)"; code=$?
    check "--json entry_in_exec false"     0 "$code" '"entry_in_exec":false' "$out"

    # suspicious: section header table stripped
    ns="$TMP/noshdr.elf"; cp "$BIN" "$ns"
    python3 - "$ns" <<'PY'
import sys, struct
p = sys.argv[1]; d = bytearray(open(p, 'rb').read())
struct.pack_into('<Q', d, 40, 0)             # e_shoff = 0
struct.pack_into('<H', d, 60, 0)             # e_shnum = 0
struct.pack_into('<H', d, 62, 0)             # e_shstrndx = 0
open(p, 'wb').write(d)
PY
    out="$("$RUN_BIN" "$ns" 2>&1)"; code=$?
    check "stripped section headers flagged" 0 "$code" "no section header table" "$out"

    # suspicious: writable + executable section
    ws="$TMP/wxsect.elf"; cp "$BIN" "$ws"
    python3 - "$ws" <<'PY'
import sys, struct
p = sys.argv[1]; d = bytearray(open(p, 'rb').read())
off = struct.unpack_from('<Q', d, 40)[0]
es  = struct.unpack_from('<H', d, 58)[0]
n   = struct.unpack_from('<H', d, 60)[0]
for i in range(n):
    b = off + i * es
    fl = struct.unpack_from('<Q', d, b + 8)[0]
    if fl & 4:                               # SHF_EXECINSTR -> add SHF_WRITE
        struct.pack_into('<Q', d, b + 8, fl | 1)
        break
open(p, 'wb').write(d)
PY
    out="$("$RUN_BIN" "$ws" 2>&1)"; code=$?
    check "W+X section detected"           0 "$code" "is writable and executable" "$out"
fi

# Executable stack detection (needs gcc)
if command -v gcc >/dev/null 2>&1; then
    printf 'int main(void){return 0;}\n' > "$TMP/es.c"
    if gcc -z execstack -o "$TMP/es.elf" "$TMP/es.c" 2>/dev/null; then
        out="$("$RUN_BIN" "$TMP/es.elf" 2>&1)"; code=$?
        check "executable stack detected"  0 "$code" "executable stack" "$out"
    fi
fi

# 12. Dynamic linking analysis (needed libraries + imported symbols)
#     Our own binary is statically linked (ld -nostdlib).
out="$("$RUN_BIN" "$BIN" 2>&1)"; code=$?
check "dynamic section present"           0 "$code" "Dynamic:"            "$out"
check "self reported statically linked"   0 "$code" "statically linked"   "$out"

out="$("$RUN_BIN" --json "$BIN" 2>&1)"; code=$?
check "--json has dynamic object"         0 "$code" '"dynamic":{'         "$out"
check "--json self is static"             0 "$code" '"static":true'       "$out"

# A dynamically-linked system ELF must list its libraries and imports.
if [[ -r /bin/ls ]]; then
    out="$("$RUN_BIN" /bin/ls 2>&1)"; code=$?
    check "dynamic lists needed libraries" 0 "$code" "Needed libraries:"  "$out"
    check "dynamic lists libc.so.6"        0 "$code" "libc.so.6"          "$out"
    check "dynamic lists imported symbols" 0 "$code" "Imported symbols:"  "$out"
    check "dynamic finds a known import"   0 "$code" "getenv"             "$out"
    check "dynamic import includes GNU version" 0 "$code" "getenv@GLIBC_" "$out"

    out="$("$RUN_BIN" --json /bin/ls 2>&1)"; code=$?
    check "--json dynamic is not static"   0 "$code" '"static":false'      "$out"
    check "--json lists needed array"      0 "$code" '"needed":['          "$out"
    check "--json lists a needed lib"      0 "$code" '"libc.so.6"'         "$out"
    check "--json lists imports array"     0 "$code" '"imports":['         "$out"
    printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); s=[x for t in d["symbol_tables"] if t["name"]==".dynsym" for x in t["symbols"]]; assert any(x["version"] and x["version"]["kind"]=="required" and x["version"]["library"] and x["version"]["name"].startswith("GLIBC_") for x in s)'
    pcode=$?
    check "JSON exposes required GNU symbol versions" 0 "$pcode" "" ""

    # JSON for a dynamic binary must stay well-formed
    if command -v python3 >/dev/null 2>&1; then
        if "$RUN_BIN" --json /bin/ls 2>/dev/null | python3 -m json.tool >/dev/null 2>&1; then
            check "--json dynamic parses cleanly" 0 0 "" ""
        else
            check "--json dynamic parses cleanly" 0 1 "" ""
        fi
    fi
fi

# 13. Hardening report (checksec-style mitigation posture)
out="$("$RUN_BIN" "$BIN" 2>&1)"; code=$?
check "hardening section present"          0 "$code" "$HARDENING_HEADING"   "$out"
check "hardening reports RELRO"           0 "$code" "RELRO:"       "$out"
check "hardening reports NX"              0 "$code" "NX:"          "$out"
check "hardening reports PIE"             0 "$code" "PIE:"         "$out"
check "hardening reports IBT"             0 "$code" "IBT:"         "$out"
check "hardening reports SHSTK"           0 "$code" "SHSTK:"       "$out"

out="$("$RUN_BIN" --json "$BIN" 2>&1)"; code=$?
check "--json has hardening object"       0 "$code" '"hardening":{' "$out"
check "--json has relro field"            0 "$code" '"relro":'      "$out"
check "--json has fortify field"          0 "$code" '"fortify":'    "$out"
check "--json has IBT field"              0 "$code" '"ibt":'         "$out"
check "--json has SHSTK field"            0 "$code" '"shstk":'       "$out"
check "JSON marks absent CET property unknown" 0 "$code" '"ibt":"unknown","shstk":"unknown"' "$out"

# A typical dynamically-linked system ELF should be fully hardened.
if [[ -r /bin/ls ]]; then
    out="$("$RUN_BIN" /bin/ls 2>&1)"; code=$?
    check "hardening detects full RELRO"   0 "$code" "RELRO:         full"    "$out"
    check "hardening detects PIE"          0 "$code" "PIE:           enabled" "$out"
    check "hardening detects canary"       0 "$code" "Stack canary:  found"   "$out"
    check "hardening detects fortify"      0 "$code" "fortified function"     "$out"
fi

# RPATH / RUNPATH and no-PIE detection (needs gcc)
if command -v gcc >/dev/null 2>&1; then
    printf 'int main(void){return 0;}\n' > "$TMP/h.c"
    if gcc -fcf-protection=full -Wl,-z,ibt,-z,shstk -o "$TMP/cet-full.elf" "$TMP/h.c" 2>/dev/null; then
        out="$("$RUN_BIN" --hardening "$TMP/cet-full.elf" 2>&1)"; code=$?
        check "hardening detects CET IBT"   0 "$code" "IBT:           enabled" "$out"
        check "hardening detects CET SHSTK" 0 "$code" "SHSTK:         enabled" "$out"
        out="$("$RUN_BIN" --json "$TMP/cet-full.elf" 2>&1)"; code=$?
        check "JSON reports enabled CET properties" 0 "$code" '"ibt":"enabled","shstk":"enabled"' "$out"
    fi
    if gcc -fcf-protection=branch -Wl,-z,ibt -o "$TMP/cet-ibt.elf" "$TMP/h.c" 2>/dev/null; then
        out="$("$RUN_BIN" --hardening "$TMP/cet-ibt.elf" 2>&1)"; code=$?
        check "hardening reports absent CET bit disabled" 0 "$code" "SHSTK:         disabled" "$out"
        out="$("$RUN_BIN" --json "$TMP/cet-ibt.elf" 2>&1)"; code=$?
        check "JSON distinguishes disabled CET bit" 0 "$code" '"ibt":"enabled","shstk":"disabled"' "$out"
    fi
    if gcc -no-pie -o "$TMP/nopie.elf" "$TMP/h.c" 2>/dev/null; then
        out="$("$RUN_BIN" "$TMP/nopie.elf" 2>&1)"; code=$?
        check "hardening detects no-PIE"   0 "$code" "PIE:           disabled" "$out"
    fi
    if gcc -o "$TMP/rpath.elf" "$TMP/h.c" -Wl,-rpath,/opt/x -Wl,--disable-new-dtags 2>/dev/null; then
        out="$("$RUN_BIN" "$TMP/rpath.elf" 2>&1)"; code=$?
        check "hardening detects RPATH"    0 "$code" "RPATH:         /opt/x"  "$out"
    fi
    if gcc -o "$TMP/runpath.elf" "$TMP/h.c" -Wl,-rpath,/opt/y -Wl,--enable-new-dtags 2>/dev/null; then
        out="$("$RUN_BIN" "$TMP/runpath.elf" 2>&1)"; code=$?
        check "hardening detects RUNPATH"  0 "$code" "RUNPATH:       /opt/y" "$out"
    fi
fi

# 14. CLI section filters and help
out="$("$RUN_BIN" --help 2>&1)"; code=$?
check "--help prints usage, exit 0"       0 "$code" "$USAGE_HEADING" "$out"
check "--help documents --symbols"       0 "$code" "--symbols" "$out"
check "--help documents --relocs"        0 "$code" "--relocs" "$out"
check "--help documents --function"      0 "$code" "--function <name>" "$out"
out="$("$RUN_BIN" -h 2>&1)"; code=$?
check "-h alias prints usage, exit 0"     0 "$code" "$USAGE_HEADING" "$out"

# --header shows only the ELF header
out="$("$RUN_BIN" --header "$BIN" 2>&1)"; code=$?
check        "--header shows header"        0 "$code" "$ELF_HEADER_HEADING" "$out"
check_absent "--header hides hardening"     0 "$code" "$HARDENING_HEADING"  "$out"
check_absent "--header hides sections"      0 "$code" "Section Headers:" "$out"

# --hardening shows only the hardening report
out="$("$RUN_BIN" --hardening "$BIN" 2>&1)"; code=$?
check        "--hardening shows hardening"   0 "$code" "$HARDENING_HEADING"  "$out"
check_absent "--hardening hides header"      0 "$code" "$ELF_HEADER_HEADING" "$out"

# filters combine
out="$("$RUN_BIN" --header --hardening "$BIN" 2>&1)"; code=$?
check "combined filters: header"          0 "$code" "$ELF_HEADER_HEADING" "$out"
check "combined filters: hardening"       0 "$code" "$HARDENING_HEADING"  "$out"

# a filter still yields the right exit code on a malformed file
# (validation runs silently even when its section is not displayed)
out="$("$RUN_BIN" --hardening "$TMP/truncated.elf" 2>&1)"; code=$?
check "filter keeps exit code on malformed" 2 "$code" "" "$out"

# no filter still shows every section (default behaviour unchanged)
out="$("$RUN_BIN" "$BIN" 2>&1)"; code=$?
check "default shows header"              0 "$code" "$ELF_HEADER_HEADING" "$out"
check "default shows hardening"           0 "$code" "$HARDENING_HEADING"  "$out"

# 15. Compare parsed header and tables against GNU readelf output.
if command -v python3 >/dev/null 2>&1 && command -v readelf >/dev/null 2>&1; then
    compare_files=("$BIN")
    if command -v gcc >/dev/null 2>&1 && [[ -r "$TMP/symbols.c" ]] &&
        gcc -fPIE -pie -g -O0 -o "$TMP/readelf-pie.elf" "$TMP/symbols.c" 2>/dev/null; then
        compare_files+=("$TMP/readelf-pie.elf")
        if command -v strip >/dev/null 2>&1; then
            cp "$TMP/readelf-pie.elf" "$TMP/readelf-pie-stripped.elf"
            if strip --strip-all "$TMP/readelf-pie-stripped.elf" 2>/dev/null; then
                compare_files+=("$TMP/readelf-pie-stripped.elf")
            fi
        fi
    fi
    for candidate in /bin/sh /bin/ls "$TMP/symbols.elf" "$TMP/symbols.stripped.elf" "$TMP/functions.exec" "$TMP/relocs.o"; do
        [[ -r "$candidate" ]] && compare_files+=("$candidate")
    done
    out="$(python3 "$ROOT/tests/compare_readelf.py" "$RUN_BIN" "${compare_files[@]}" 2>&1)"; code=$?
    check "readelf semantic comparisons pass" 0 "${code}" "readelf differential: all ${#compare_files[@]} files matched" "$out"
else
    echo "  SKIP: readelf differential tests require Python 3 and GNU readelf"
fi

echo
echo "Results: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
