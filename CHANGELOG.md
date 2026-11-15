# Changelog

Notable changes to elfcheck. This file is the source of the GitHub
release notes: the section matching the tag is published verbatim.

## [1.2.1] - 2026-11-15

- The binary now carries an explicit non-executable `PT_GNU_STACK` (`ld -z
  noexecstack`): without it the kernel falls back to its legacy default for
  the stack and rpmlint reports missing-PT_GNU_STACK-section. elfcheck's own
  hardening report now says `NX: enabled` about itself instead of
  `NX: unknown (no PT_GNU_STACK)`
- Both RPM specs now carry a `%changelog` entry (rpmlint no-changelogname-tag)

## [1.2.0] - 2026-11-15

- Colored output: `--triage` now color-codes the severity tags (red for HIGH,
  yellow for MED, cyan for LOW, grey for INFO), and the `--entropy` `[high]`
  marker turns red, making the verdict easier to scan at a glance
- Color is emitted only when standard output is a terminal, so redirected or
  piped output stays plain and script-friendly; `--json` output is never colored
- New `--no-color` flag and support for the `NO_COLOR` environment variable
  (see no-color.org) to disable colored output on a terminal
- Release packages now ship a stripped binary: the `nasm -g` DWARF lines and
  the symbol table are dev-only dead weight at runtime, so the shipped binary
  drops from 177 KB to 62 KB and the `.rpm` from 57 KB to 35 KB; the `.deb`
  manpage is now gzipped like the `.rpm`'s
- Release packages now include the MIT license text (`.rpm`:
  `/usr/share/licenses/elfcheck/LICENSE`, `.deb`:
  `/usr/share/doc/elfcheck/copyright`), as the license requires; the OBS
  package already shipped it
- The README examples now show the colored `--triage` and `--entropy` output as
  rendered images, covering the full severity palette (HIGH/MED/LOW/INFO)

## [1.1.1] - 2026-11-14

- openSUSE packaging via the openSUSE Build Service (OBS): a from-source spec and
  source service under `packaging/obs/` let OBS build and sign a repository, so
  users install with a plain `zypper install elfcheck` (no key import or
  `--no-gpg-checks`) and get automatic updates
- Releases now also ship an `.rpm` alongside the `.deb` and the static binary
  (`zypper install ./elfcheck-<version>-1.x86_64.rpm`), built and attached
  automatically from a version tag. Build it locally with `make rpm`; it holds
  the same dependency-free static binary, so it installs on any RPM distribution
- The released `.rpm` is GPG-signed when a `GPG_PRIVATE_KEY` secret is set, and
  the matching public key (`RPM-GPG-KEY-elfcheck`) is attached to the release so
  `zypper`/`dnf`/`rpm` verify and install it cleanly; sign locally with
  `make rpm-sign GPG_NAME=<key>`
- Hardened the parser against deliberately malformed header entry counts: a
  bogus `e_phnum`/`e_shnum` (including the reserved `PN_XNUM` escape and the
  `SHN_LORESERVE` range) is no longer walked as a real table, so no report mode
  can be driven into unbounded output by reading file padding as phantom
  program/section headers. Enumeration is now bounded by what actually fits the
  file through a single `effective_phnum`/`effective_shnum` choke point, and the
  reserved escape values are flagged by `--validate`
- `--security` no longer emits false `W^X` segment warnings from reading padding
  past a lying `e_phnum`
- Fuzz smoke test now also mutates large (padded) inputs so the
  "bogus-count-that-fits" class is covered, plus regression tests for bounded
  output on malformed counts

## [1.1.0] - 2026-11-01

- `--entropy`: per-section Shannon entropy (bits/byte) to flag packed,
  encrypted or compressed code; a high-entropy executable section is tagged
  `[high]`, exposed as `entropy.sections[].packed` in `--json`, and raised as a
  MED triage finding that gates CI
- `--triage --json`: machine-readable verdict (`findings`, `summary`,
  `gate_failed`) with the same CI exit code as the text form
- Triage now flags dangerous/capability imports from the dynamic symbol table:
  banned `gets()` (gates CI), command/process execution and networking

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
