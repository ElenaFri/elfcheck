# Changelog

Notable changes to elfcheck. This file is the source of the GitHub
release notes: the section matching the tag is published verbatim.

## [1.0.1] - 2025-10-31

- Version tags now build and publish release artifacts automatically: a
  dependency-free static binary and a Debian package
  (`apt install ./elfcheck_<version>_amd64.deb`)
- Release notes are now extracted from this changelog

## [1.0.0] - 2025-10-31

- First stable release: a lightweight ELF64 inspector for Linux x86-64,
  written in pure NASM — freestanding, statically linked, no libc, direct
  syscalls only
- ELF header, program and section headers with structural validation and
  clear errors on malformed, truncated, ELF32 and big-endian inputs
- CLI section filters to print only what you need
- `--dynamic`: full `.dynamic` tag table (`readelf -d`)
- `--mapping`: section-to-segment mapping (`readelf -l`)
- `-x` / `-p`: section hex and string dumps, byte-for-byte identical to
  `readelf -x` / `-p`
- `--symbols`: static and dynamic symbol tables with GNU symbol versions
- `--relocs`: REL/RELA entries with resolved symbols and signed addends
- Disassembler in Intel syntax with raw opcodes: x86-64 integer
  instructions, selected SSE, 128/256-bit AVX/VEX; `--function`,
  `--start-address`, `--count` to narrow the output; annotated branch
  targets and resolved relocations in `.o` files
- `--triage`: one-pass anomaly scan ranked HIGH/MED/LOW/INFO, exit code 2
  on HIGH/MED — usable directly as a CI/deploy gate
- `--hardening`: checksec-style RELRO, stack canary, NX, PIE, CET
  (IBT/SHSTK), RPATH/RUNPATH, Fortify
- `--security`: W^X segments and sections, executable stack, entry point
  outside executable segments
- `--notes`: GNU build-id, ABI tag, x86 feature properties
- `--json`: complete analysis as a single-line JSON object
- `make install` / `uninstall`, man page (`man elfcheck`)
- 294 automated tests including a semantic differential against GNU
  `readelf`, deterministic mutation fuzzing, kcov coverage tracked on
  Codecov, CI on every push

[1.0.1]: https://github.com/ElenaFri/elfcheck/releases/tag/v1.0.1
[1.0.0]: https://github.com/ElenaFri/elfcheck/releases/tag/v1.0.0
