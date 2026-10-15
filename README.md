# elfcheck

A lightweight ELF64 binary inspector for Linux x86-64, written in NASM assembly. Parses executable headers, segments and sections, and detects structural inconsistencies in binary files.

> Work in Progress

## Features

- [x] Read ELF binary files
- [x] Validate ELF magic and header
- [ ] Identify architecture, file type and endianness
- [ ] Display ELF header information
- [ ] Parse and display program headers
- [ ] Parse and display section headers
- [ ] Validate file offsets and structure boundaries
- [ ] Detect malformed or truncated ELF files
- [ ] Report structural inconsistencies
- [ ] Export analysis results as JSON
- [ ] Add automated tests with valid and malformed ELF files
- [ ] Disassemble machine code sections
- [ ] Display assembly instructions with addresses and opcodes
- [ ] Detect potentially suspicious ELF properties
- [ ] Check segment permissions and executable stack settings
- [ ] Identify imported functions and dynamic dependencies
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
