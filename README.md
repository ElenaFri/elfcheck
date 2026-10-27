# elfcheck

[![Coverage](https://codecov.io/gh/ElenaFri/elfcheck/branch/main/graph/badge.svg)](https://codecov.io/gh/ElenaFri/elfcheck)

A lightweight ELF64 inspector for Linux x86-64, written in NASM. It accepts ELF64 little-endian files, validates their structure, and parses headers, segments, sections, symbol and relocation tables. It also disassembles machine code and reports dynamic dependencies and hardening. Optional JSON output; no libc, direct syscalls only.

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
- [x] Filter report sections from the CLI
- [x] Add automated tests with valid and malformed ELF files
- [x] Disassemble machine code sections or selected functions
- [x] Display assembly instructions with addresses and opcodes
- [x] Decode selected 128- and 256-bit AVX/VEX arithmetic, packed integer operations and moves
- [x] Detect potentially suspicious ELF properties
- [x] Check segment permissions and executable stack settings
- [x] Identify imported functions and dynamic dependencies
- [x] Display static and dynamic symbol tables, including GNU symbol versions
- [x] Display REL/RELA relocation entries and resolve symbol names
- [x] Report RELRO, NX, PIE and GNU x86 CET (IBT/SHSTK) hardening properties

## Requirements

- Linux x86-64
- NASM
- GNU Binutils (`ld`, `strip` and `readelf`)
- GNU Make
- GCC and Python 3 for the full test suite

On Debian/Ubuntu:

```bash
sudo apt install nasm binutils make gcc python3
```

## Build

```bash
make
```

Run the test suite:

```bash
make test
```

The suite also compares ELF headers, segments, sections, symbol tables and relocations against GNU `readelf`.
Run the separate, bounded deterministic mutation smoke test with `make fuzz-smoke`.

Measure NASM source-line coverage with `kcov` (the HTML report is written to
`coverage/index.html`):

```bash
sudo apt install kcov
make coverage
```

CI uploads the report to Codecov to update the badge. Enable the repository on
Codecov and add its `CODECOV_TOKEN` as a GitHub Actions secret.

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
opcodes). The decoder covers common x86-64 integer instructions, selected SSE operations,
and a subset of 128- and 256-bit AVX/VEX instructions: packed/scalar floating-point
arithmetic, selected packed integer operations (`vpand`, `vpor`, `vpxor`, `vpadd*`,
`vpsub*`), packed moves (`vmovups`, `vmovupd`, `vmovaps`, `vmovapd`), and
`vzeroupper`. Scalar VEX moves, EVEX and unsupported instruction forms fall back to
`.byte` one byte at a time, so instruction boundaries may be lost after an
unsupported encoding. For linked executables,
direct branch targets are annotated when they exactly match a function symbol;
for relocatable `.o` files, PC-relative branch and RIP-relative data relocations
show their symbol and type.

```bash
./elfcheck --disasm <file>   # or: ./elfcheck -d <file>
./elfcheck --function main <file>  # only a sized function from .symtab/.dynsym
```

The disassembly can be long; pipe it through a pager or the usual filters:

```bash
./elfcheck -d <file> | less
./elfcheck -d <file> | grep call
```

By default the report prints its standard sections. Pass one or more **section
filters** to show only what you need (handy to keep the output short); symbol
and relocation tables are opt-in because they can be large:

```bash
./elfcheck --hardening <file>            # just the hardening report
./elfcheck --header --dynamic <file>     # header + dynamic linking only
./elfcheck --symbols <file>              # static and dynamic symbol tables
./elfcheck --relocs <file>               # REL/RELA relocations and symbols
```

Available filters: `--header`, `--segments`, `--sections`, `--validate`,
`--security`, `--dynamic`, `--hardening`, `--symbols`, `--relocs`. Symbol and
relocation tables are opt-in because they can be large; `--json` always includes
them under `symbol_tables` and `relocation_tables`. Structural validation always
runs so the exit code stays meaningful, even when its section is hidden. Filters
apply to the default text report; `--json` always emits the complete object. Use
`--help` (or `-h`) to list every option.

The default report ends with a `Security:` section that flags common red flags:
writable and executable (`W^X`) `PT_LOAD` segments and sections, stack
executability via `PT_GNU_STACK`, an entry point that falls outside any
executable segment, and a stripped section header table. These findings are
advisory and do not change the exit code.

A `Dynamic:` section reports the shared libraries the file depends on (`DT_NEEDED`)
and imported symbols with GNU versions (`name@VERSION`); default exported
versions use `name@@VERSION`. In `--json`, each `.dynsym` entry has a `version`
object (or `null`) with its name, index, required/defined kind, provider library,
and GNU hidden-version flag.

Finally, a `Hardening:` section summarises the binary's exploit-mitigation
posture, checksec-style: `RELRO` (none/partial/full), stack canary, `NX`
(non-executable stack), `PIE`, GNU x86 CET properties (`IBT`/`SHSTK`),
`RPATH`/`RUNPATH`, and the number of fortified (`_chk`) functions. CET is
reported as enabled/disabled from the ELF feature bits, or unknown when the
GNU property is absent; this does not prove runtime CPU or loader enforcement.
The report is mirrored under `"hardening"` in `--json` output and, like
`Security:`, is advisory and does not change the exit code.

Exit codes: `0` valid with no structural issues, `1` usage/read error or not an
ELF file, `2` valid ELF header but structural inconsistencies were found.
