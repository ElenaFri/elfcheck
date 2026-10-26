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

# 8. Symbol tables (opt-in text section, complete in JSON)
out="$("$BIN" --symbols "$BIN" 2>&1)"; code=$?
check "--symbols handles a static ELF"       0 "$code" ".symtab" "$out"
check "--symbols finds the static entry point" 0 "$code" "_start" "$out"
check_absent "static ELF has no dynamic symbol table" 0 "$code" "Symbol table '.dynsym'" "$out"

if command -v gcc >/dev/null 2>&1; then
    cat > "$TMP/symbols.c" <<'EOF'
int elfcheck_symbol_fixture(int value) { return value + 7; }
int main(void) { return elfcheck_symbol_fixture(1); }
EOF
    if gcc -g -O0 -o "$TMP/symbols.elf" "$TMP/symbols.c" 2>/dev/null; then
        out="$("$BIN" --symbols "$TMP/symbols.elf" 2>&1)"; code=$?
        check "--symbols exits 0 for valid ELF"    0 "$code" "Symbol Tables:" "$out"
        check "--symbols lists static table"       0 "$code" ".symtab" "$out"
        check "--symbols lists dynamic table"      0 "$code" ".dynsym" "$out"
        check "--symbols resolves a defined name"  0 "$code" "elfcheck_symbol_fixture" "$out"
        check "--symbols prints type and binding"  0 "$code" "FUNC" "$out"

        out="$("$BIN" "$TMP/symbols.elf" --symbols 2>&1)"; code=$?
        check "--symbols accepted after path"      0 "$code" "Symbol Tables:" "$out"

        out="$("$BIN" --header --symbols "$TMP/symbols.elf" 2>&1)"; code=$?
        check "combined filter includes symbols"   0 "$code" "Symbol Tables:" "$out"
        check "combined filter includes header"    0 "$code" "ELF Header:" "$out"
        check_absent "combined filter hides hardening" 0 "$code" "Hardening:" "$out"

        out="$("$BIN" "$TMP/symbols.elf" 2>&1)"; code=$?
        check_absent "default report keeps symbols opt-in" 0 "$code" "Symbol Tables:" "$out"

        out="$("$BIN" --json "$TMP/symbols.elf" 2>&1)"; code=$?
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
                out="$("$BIN" --symbols "$TMP/symbols.stripped.elf" 2>&1)"; code=$?
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
            out="$("$BIN" --symbols "$TMP/bad-symbols.elf" 2>&1)"; code=$?
            check "zero symbol entry size is handled safely" 0 "$code" "invalid symbol table metadata" "$out"
        fi
    fi
fi

# 9. REL/RELA relocation tables
if command -v gcc >/dev/null 2>&1; then
    cat > "$TMP/relocs.c" <<'EOF'
extern int elfcheck_reloc_target(int);
int elfcheck_reloc_fixture(int value) { return elfcheck_reloc_target(value) + 3; }
EOF
    if gcc -c -fno-pic -o "$TMP/relocs.o" "$TMP/relocs.c" 2>/dev/null; then
        out="$("$BIN" --relocs "$TMP/relocs.o" 2>&1)"; code=$?
        check "--relocs exits 0 for relocatable ELF" 0 "$code" "Relocations:" "$out"
        check "--relocs names the RELA section"       0 "$code" ".rela.text" "$out"
        check "--relocs shows target section"         0 "$code" "target: .text" "$out"
        check "--relocs decodes x86-64 PLT32"        0 "$code" "R_X86_64_PLT32" "$out"
        check "--relocs resolves symbol name"         0 "$code" "elfcheck_reloc_target" "$out"
        check "--relocs prints signed addend"         0 "$code" "-4" "$out"

        out="$("$BIN" --function elfcheck_reloc_fixture "$TMP/relocs.o" 2>&1)"; code=$?
        check "ET_REL branch resolves its relocation symbol and type" 0 "$code" "<elfcheck_reloc_target> [R_X86_64_PLT32]" "$out"

        out="$("$BIN" --disasm "$TMP/relocs.o" 2>&1)"; code=$?
        check "ET_REL full-section disassembly resolves relocation target" 0 "$code" "<elfcheck_reloc_target> [R_X86_64_PLT32]" "$out"

        out="$("$BIN" "$TMP/relocs.o" --relocs 2>&1)"; code=$?
        check "--relocs accepted after path"           0 "$code" "Relocations:" "$out"

        out="$("$BIN" --header --relocs "$TMP/relocs.o" 2>&1)"; code=$?
        check "combined filter includes relocations" 0 "$code" "Relocations:" "$out"
        check "combined relocation filter includes header" 0 "$code" "ELF Header:" "$out"
        check_absent "combined relocation filter hides symbols" 0 "$code" "Symbol Tables:" "$out"

        out="$("$BIN" "$TMP/relocs.o" 2>&1)"; code=$?
        check_absent "default report keeps relocations opt-in" 0 "$code" "Relocations:" "$out"

        out="$("$BIN" --json "$TMP/relocs.o" 2>&1)"; code=$?
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
        struct.pack_into('<I', d, at + 4, 9)
        struct.pack_into('<Q', d, at + 32, 16)
        struct.pack_into('<Q', d, at + 56, 16)
        break
open(p, 'wb').write(d)
PY
            out="$("$BIN" --relocs "$TMP/rel.o" 2>&1)"; code=$?
            check "SHT_REL entries are decoded" 0 "$code" "(index 2, REL, target: .text" "$out"
            check "REL entries omit the addend" 0 "$code" "elfcheck_reloc_target" "$out"
            out="$("$BIN" --function elfcheck_reloc_fixture "$TMP/rel.o" 2>&1)"; code=$?
            check "ET_REL SHT_REL branch resolves its symbol and type" 0 "$code" "<elfcheck_reloc_target> [R_X86_64_PLT32]" "$out"
            out="$("$BIN" --json "$TMP/rel.o" 2>&1)"; code=$?
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
            out="$("$BIN" --relocs "$TMP/bad-relocs.o" 2>&1)"; code=$?
            check "zero relocation entry size is handled safely" 0 "$code" "invalid relocation section metadata" "$out"
        fi
    fi
fi

# 10. Disassembler mode
out="$("$BIN" --disasm "$BIN" 2>&1)"; code=$?
check "--disasm exits 0 for valid ELF"   0 "$code" "Disassembly of section .text:" "$out"
check "--disasm decodes syscall"         0 "$code" "syscall" "$out"
check "--disasm decodes call"            0 "$code" "call"    "$out"
check "--disasm decodes mov"             0 "$code" "mov"     "$out"
check "--disasm shows instruction bytes" 0 "$code" "0f 05"   "$out"

# -d is an alias for --disasm
out="$("$BIN" -d "$BIN" 2>&1)"; code=$?
check "-d alias works"                    0 "$code" "Disassembly of section .text:" "$out"

# flag accepted after the path too
out="$("$BIN" "$BIN" -d 2>&1)"; code=$?
check "-d accepted after path"            0 "$code" "Disassembly of section .text:" "$out"

# --function narrows disassembly to a bounded STT_FUNC symbol
out="$("$BIN" --function 2>&1)"; code=$?
check "--function requires a name and file" 1 "$code" "Usage:" "$out"
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
        out="$("$BIN" --function elfcheck_target "$TMP/functions.elf" 2>&1)"; code=$?
        check "--function selects a named function" 0 "$code" "Disassembly of function elfcheck_target in section .text:" "$out"
        check "direct call target is annotated with its symbol" 0 "$code" "<elfcheck_callee>" "$out"
        check_absent "target disassembly excludes other function bytes" 0 "$code" ".byte 0x0f" "$out"
        check_absent "target disassembly omits whole-section title" 0 "$code" "Disassembly of section .text:" "$out"

        out="$("$BIN" "$TMP/functions.elf" --function elfcheck_other 2>&1)"; code=$?
        check "--function works after the path" 0 "$code" "Disassembly of function elfcheck_other in section .text:" "$out"
        check "other function range decodes UD2" 0 "$code" "ud2" "$out"

        out="$("$BIN" --function elfcheck_sse_copy "$TMP/functions.elf" 2>&1)"; code=$?
        check "SSE decoder prints XMM registers" 0 "$code" "xmm0" "$out"
        check "SSE decoder formats packed memory operands" 0 "$code" "xmmword [" "$out"
        check "SSE decoder handles aligned moves" 0 "$code" "movaps" "$out"
        check "SSE decoder handles unaligned moves" 0 "$code" "movups" "$out"
        check "SSE decoder handles scalar move widths" 0 "$code" "movss" "$out"
        check "SSE decoder handles double scalar move" 0 "$code" "movsd" "$out"
        check "SSE decoder handles packed arithmetic" 0 "$code" "addps" "$out"
        check "SSE decoder selects 66-prefix variants" 0 "$code" "movupd" "$out"
        check "SSE decoder handles packed double operation" 0 "$code" "xorpd" "$out"

        out="$("$BIN" --function elfcheck_jump "$TMP/functions.elf" 2>&1)"; code=$?
        check "direct jmp target is annotated" 0 "$code" "<elfcheck_callee>" "$out"
        out="$("$BIN" --function elfcheck_conditional_jump "$TMP/functions.elf" 2>&1)"; code=$?
        check "conditional branch target is annotated" 0 "$code" "<elfcheck_callee>" "$out"

        out="$("$BIN" --function elfcheck_missing "$TMP/functions.elf" 2>&1)"; code=$?
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
            out="$("$BIN" --function elfcheck_target "$TMP/functions.zero-size.elf" 2>&1)"; code=$?
            check "zero-sized function is rejected" 1 "$code" "no usable executable range: elfcheck_target" "$out"
        fi

        if gcc -g -O0 -fno-inline -c -o "$TMP/functions.o" "$TMP/functions.c" 2>/dev/null; then
            out="$("$BIN" --function elfcheck_target "$TMP/functions.o" 2>&1)"; code=$?
            check "--function resolves ET_REL section-relative values" 0 "$code" "Disassembly of function elfcheck_target in section .text:" "$out"
            check_absent "ET_REL target excludes other function bytes" 0 "$code" ".byte 0x0f" "$out"
        fi

        if gcc -no-pie -g -O0 -fno-inline -o "$TMP/functions.exec" "$TMP/functions.c" 2>/dev/null; then
            out="$("$BIN" --function elfcheck_target "$TMP/functions.exec" 2>&1)"; code=$?
            check "--function resolves ET_EXEC virtual addresses" 0 "$code" "Disassembly of function elfcheck_target in section .text:" "$out"
            check "ET_EXEC direct call target is annotated" 0 "$code" "<elfcheck_callee>" "$out"
        fi

        if command -v strip >/dev/null 2>&1; then
            if gcc -rdynamic -g -O0 -fno-inline -o "$TMP/functions.exported" "$TMP/functions.c" 2>/dev/null && strip --strip-all "$TMP/functions.exported" 2>/dev/null; then
                out="$("$BIN" --function elfcheck_target "$TMP/functions.exported" 2>&1)"; code=$?
                check "stripped dynsym function is found" 0 "$code" "Disassembly of function elfcheck_target" "$out"
                check "stripped dynsym call target is annotated" 0 "$code" "<elfcheck_callee>" "$out"
            fi
        fi
    fi
fi

# 11. Security analysis (segment permissions + stack executability)
out="$("$BIN" "$BIN" 2>&1)"; code=$?
check "security section present"          0 "$code" "Security:" "$out"

out="$("$BIN" --json "$BIN" 2>&1)"; code=$?
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
    out="$("$BIN" "$wx" 2>&1)"; code=$?
    check "W^X LOAD segment detected"     0 "$code" "W^X violation"  "$out"

    # suspicious: entry point outside any executable segment
    be="$TMP/badentry.elf"; cp "$BIN" "$be"
    python3 - "$be" <<'PY'
import sys, struct
p = sys.argv[1]; d = bytearray(open(p, 'rb').read())
struct.pack_into('<Q', d, 24, 0xdeadbeef)    # e_entry -> bogus address
open(p, 'wb').write(d)
PY
    out="$("$BIN" "$be" 2>&1)"; code=$?
    check "bad entry point detected"       0 "$code" "not inside any executable segment" "$out"
    out="$("$BIN" --json "$be" 2>&1)"; code=$?
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
    out="$("$BIN" "$ns" 2>&1)"; code=$?
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
    out="$("$BIN" "$ws" 2>&1)"; code=$?
    check "W+X section detected"           0 "$code" "is writable and executable" "$out"
fi

# Executable stack detection (needs gcc)
if command -v gcc >/dev/null 2>&1; then
    printf 'int main(void){return 0;}\n' > "$TMP/es.c"
    if gcc -z execstack -o "$TMP/es.elf" "$TMP/es.c" 2>/dev/null; then
        out="$("$BIN" "$TMP/es.elf" 2>&1)"; code=$?
        check "executable stack detected"  0 "$code" "executable stack" "$out"
    fi
fi

# 12. Dynamic linking analysis (needed libraries + imported symbols)
#     Our own binary is statically linked (ld -nostdlib).
out="$("$BIN" "$BIN" 2>&1)"; code=$?
check "dynamic section present"           0 "$code" "Dynamic:"            "$out"
check "self reported statically linked"   0 "$code" "statically linked"   "$out"

out="$("$BIN" --json "$BIN" 2>&1)"; code=$?
check "--json has dynamic object"         0 "$code" '"dynamic":{'         "$out"
check "--json self is static"             0 "$code" '"static":true'       "$out"

# A dynamically-linked system ELF must list its libraries and imports.
if [[ -r /bin/ls ]]; then
    out="$("$BIN" /bin/ls 2>&1)"; code=$?
    check "dynamic lists needed libraries" 0 "$code" "Needed libraries:"  "$out"
    check "dynamic lists libc.so.6"        0 "$code" "libc.so.6"          "$out"
    check "dynamic lists imported symbols" 0 "$code" "Imported symbols:"  "$out"
    check "dynamic finds a known import"   0 "$code" "getenv"             "$out"

    out="$("$BIN" --json /bin/ls 2>&1)"; code=$?
    check "--json dynamic is not static"   0 "$code" '"static":false'      "$out"
    check "--json lists needed array"      0 "$code" '"needed":['          "$out"
    check "--json lists a needed lib"      0 "$code" '"libc.so.6"'         "$out"
    check "--json lists imports array"     0 "$code" '"imports":['         "$out"

    # JSON for a dynamic binary must stay well-formed
    if command -v python3 >/dev/null 2>&1; then
        if "$BIN" --json /bin/ls 2>/dev/null | python3 -m json.tool >/dev/null 2>&1; then
            check "--json dynamic parses cleanly" 0 0 "" ""
        else
            check "--json dynamic parses cleanly" 0 1 "" ""
        fi
    fi
fi

# 13. Hardening report (checksec-style mitigation posture)
out="$("$BIN" "$BIN" 2>&1)"; code=$?
check "hardening section present"          0 "$code" "Hardening:"   "$out"
check "hardening reports RELRO"           0 "$code" "RELRO:"       "$out"
check "hardening reports NX"              0 "$code" "NX:"          "$out"
check "hardening reports PIE"             0 "$code" "PIE:"         "$out"

out="$("$BIN" --json "$BIN" 2>&1)"; code=$?
check "--json has hardening object"       0 "$code" '"hardening":{' "$out"
check "--json has relro field"            0 "$code" '"relro":'      "$out"
check "--json has fortify field"          0 "$code" '"fortify":'    "$out"

# A typical dynamically-linked system ELF should be fully hardened.
if [[ -r /bin/ls ]]; then
    out="$("$BIN" /bin/ls 2>&1)"; code=$?
    check "hardening detects full RELRO"   0 "$code" "RELRO:         full"    "$out"
    check "hardening detects PIE"          0 "$code" "PIE:           enabled" "$out"
    check "hardening detects canary"       0 "$code" "Stack canary:  found"   "$out"
    check "hardening detects fortify"      0 "$code" "fortified function"     "$out"
fi

# RPATH / RUNPATH and no-PIE detection (needs gcc)
if command -v gcc >/dev/null 2>&1; then
    printf 'int main(void){return 0;}\n' > "$TMP/h.c"
    if gcc -no-pie -o "$TMP/nopie.elf" "$TMP/h.c" 2>/dev/null; then
        out="$("$BIN" "$TMP/nopie.elf" 2>&1)"; code=$?
        check "hardening detects no-PIE"   0 "$code" "PIE:           disabled" "$out"
    fi
    if gcc -o "$TMP/rpath.elf" "$TMP/h.c" -Wl,-rpath,/opt/x -Wl,--disable-new-dtags 2>/dev/null; then
        out="$("$BIN" "$TMP/rpath.elf" 2>&1)"; code=$?
        check "hardening detects RPATH"    0 "$code" "RPATH:         /opt/x"  "$out"
    fi
    if gcc -o "$TMP/runpath.elf" "$TMP/h.c" -Wl,-rpath,/opt/y -Wl,--enable-new-dtags 2>/dev/null; then
        out="$("$BIN" "$TMP/runpath.elf" 2>&1)"; code=$?
        check "hardening detects RUNPATH"  0 "$code" "RUNPATH:       /opt/y" "$out"
    fi
fi

# 14. CLI section filters and help
out="$("$BIN" --help 2>&1)"; code=$?
check "--help prints usage, exit 0"       0 "$code" "Usage:" "$out"
check "--help documents --symbols"       0 "$code" "--symbols" "$out"
check "--help documents --relocs"        0 "$code" "--relocs" "$out"
check "--help documents --function"      0 "$code" "--function <name>" "$out"
out="$("$BIN" -h 2>&1)"; code=$?
check "-h alias prints usage, exit 0"     0 "$code" "Usage:" "$out"

# --header shows only the ELF header
out="$("$BIN" --header "$BIN" 2>&1)"; code=$?
check        "--header shows header"        0 "$code" "ELF Header:" "$out"
check_absent "--header hides hardening"     0 "$code" "Hardening:"  "$out"
check_absent "--header hides sections"      0 "$code" "Section Headers:" "$out"

# --hardening shows only the hardening report
out="$("$BIN" --hardening "$BIN" 2>&1)"; code=$?
check        "--hardening shows hardening"   0 "$code" "Hardening:"  "$out"
check_absent "--hardening hides header"      0 "$code" "ELF Header:" "$out"

# filters combine
out="$("$BIN" --header --hardening "$BIN" 2>&1)"; code=$?
check "combined filters: header"          0 "$code" "ELF Header:" "$out"
check "combined filters: hardening"       0 "$code" "Hardening:"  "$out"

# a filter still yields the right exit code on a malformed file
# (validation runs silently even when its section is not displayed)
out="$("$BIN" --hardening "$TMP/truncated.elf" 2>&1)"; code=$?
check "filter keeps exit code on malformed" 2 "$code" "" "$out"

# no filter still shows every section (default behaviour unchanged)
out="$("$BIN" "$BIN" 2>&1)"; code=$?
check "default shows header"              0 "$code" "ELF Header:" "$out"
check "default shows hardening"           0 "$code" "Hardening:"  "$out"

echo
echo "Results: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
