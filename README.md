# elfcheck

A lightweight ELF64 binary inspector for Linux x86-64, written in NASM assembly. Parses executable headers, segments and sections, and detects structural inconsistencies in binary files.

> Work in Progress

## Features

- [x] Read ELF binary files
- [x] Validate ELF magic and header
- [x] Identify architecture, file type and endianness
- [x] Display ELF header information
- [x] Parse and display program headers
- [x] Parse and display section headers
- [x] Validate file offsets and structure boundaries
- [x] Detect malformed or truncated ELF files
- [x] Report structural inconsistencies
- [x] Export analysis results as JSON
- [x] Add automated tests with valid and malformed ELF files
- [x] Disassemble machine code sections
- [x] Display assembly instructions with addresses and opcodes
- [x] Detect potentially suspicious ELF properties
- [x] Check segment permissions and executable stack settings
- [x] Identify imported functions and dynamic dependencies
- [ ] Generate a security-oriented analysis report

## Requirements

- Linux x86-64
- NASM
- GNU Binutils (`ld`)
- GNU Make

On Debian/Ubuntu:

```bash
sudo apt-get install nasm binutils make
```

## Build

```bash
make
```

Run the test suite:

```bash
make test
```

## Usage

```bash
./elfcheck <file>
```

Emit the analysis as a single-line JSON object instead of the human-readable
report (pipe through `jq` to pretty-print):

```bash
./elfcheck --json <file>
```

Disassemble the executable `.text` section (Intel syntax, with addresses and raw
opcodes). The decoder covers the common x86-64 integer instruction set; SSE/AVX
and other unhandled encodings are shown as `.byte` fallbacks:

```bash
./elfcheck --disasm <file>   # or: ./elfcheck -d <file>
```

The disassembly can be long; pipe it through a pager or the usual filters:

```bash
./elfcheck -d <file> | less
./elfcheck -d <file> | grep call
```

The default report ends with a `Security:` section that flags common red flags:
writable and executable (`W^X`) `PT_LOAD` segments and sections, stack
executability via `PT_GNU_STACK`, an entry point that falls outside any
executable segment, and a stripped section header table. These findings are
advisory and do not change the exit code.

A `Dynamic:` section then reports dynamic linking: the shared libraries the file
depends on (`DT_NEEDED`) and the symbols it imports (undefined `.dynsym`
entries), or a note when the binary is statically linked. The same data appears
under `"dynamic"` in `--json` output.

Exit codes: `0` valid with no structural issues, `1` usage/read error or not an
ELF file, `2` valid ELF header but structural inconsistencies were found.
