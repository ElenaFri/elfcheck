"""Compare elfcheck's JSON ELF tables with GNU readelf's semantic output."""

import json
import os
import re
import shutil
import subprocess
import sys

HEX = re.compile(r"^(?:0x)?[0-9a-f]+$", re.IGNORECASE)
HEADER_FIELDS = {
    "entry": (r"^\s*Entry point address:\s*(0x[0-9a-f]+)", 16),
    "phoff": (r"^\s*Start of program headers:\s*(\d+)", 10),
    "shoff": (r"^\s*Start of section headers:\s*(\d+)", 10),
    "ehsize": (r"^\s*Size of this header:\s*(\d+)", 10),
    "phentsize": (r"^\s*Size of program headers:\s*(\d+)", 10),
    "phnum": (r"^\s*Number of program headers:\s*(\d+)", 10),
    "shentsize": (r"^\s*Size of section headers:\s*(\d+)", 10),
    "shnum": (r"^\s*Number of section headers:\s*(\d+)", 10),
    "shstrndx": (r"^\s*Section header string table index:\s*(\d+)", 10),
}


def run(command, env, timeout=10):
    result = subprocess.run(
        command, text=True, capture_output=True, env=env, timeout=timeout, check=False
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ValueError(f"command failed ({result.returncode}): {command!r}: {detail}")
    return result.stdout


def require_equal(path, description, actual, expected):
    if actual != expected:
        raise ValueError(f"{path}: {description}: elfcheck={actual!r}, readelf={expected!r}")


def capture(text, pattern, label, base=10):
    match = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
    if match is None:
        raise ValueError(f"readelf output is missing {label!r}")
    return int(match.group(1), base)


def normalize_data(value):
    value = value.lower()
    if "little" in value:
        return "little"
    if "big" in value:
        return "big"
    return value


def normalize_machine(value):
    value = value.lower()
    if "x86-64" in value or "x86_64" in value:
        return "x86-64"
    return re.sub(r"[^a-z0-9]+", "", value)


def json_hex(value):
    return int(value, 16) if isinstance(value, str) else int(value)


def parse_program_headers(text):
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 7:
            continue
        if not all(HEX.fullmatch(value) for value in fields[1:6]):
            continue
        if not HEX.fullmatch(fields[-1]):
            continue
        readelf_flags = set("".join(fields[6:-1]).upper())
        if "E" in readelf_flags:
            readelf_flags.add("X")
        rows.append(
            {
                "offset": int(fields[1], 16),
                "vaddr": int(fields[2], 16),
                "filesz": int(fields[4], 16),
                "memsz": int(fields[5], 16),
                "align": int(fields[-1], 16),
                "flags": "".join(
                    flag if flag in readelf_flags else "-" for flag in "RWX"
                ),
            }
        )
    return rows


def parse_section_headers(text):
    rows = []
    for line in text.splitlines():
        index_match = re.match(r"^\s*\[\s*(\d+)\]\s*(.*?)\s*$", line)
        if index_match is None:
            continue
        tokens = index_match.group(2).split()
        parsed = None
        for type_position in (0, 1):
            if len(tokens) < type_position + 8:
                continue
            numeric = tokens[type_position + 1 : type_position + 5]
            if not all(HEX.fullmatch(value) for value in numeric):
                continue
            trailing = tokens[type_position + 5 :]
            if len(trailing) not in (3, 4) or not all(
                value.isdecimal() for value in trailing[-3:]
            ):
                continue
            flag_tokens = trailing[:-3]
            if len(flag_tokens) > 1:
                continue
            name = tokens[0] if type_position else ""
            parsed = {
                "index": int(index_match.group(1)),
                "name": name,
                "type": tokens[type_position],
                "addr": int(numeric[0], 16),
                "offset": int(numeric[1], 16),
                "size": int(numeric[2], 16),
                "flags": flag_tokens[0] if flag_tokens else "",
                "link": int(trailing[-3], 10),
                "info": int(trailing[-2], 10),
                "align": int(trailing[-1], 10),
            }
            break
        if parsed is None:
            raise ValueError(f"could not parse readelf section row: {line.strip()!r}")
        rows.append(parsed)
    return rows


def normalize_symbol_name(name, symbol_type):
    if name is None or symbol_type == "SECTION":
        return ""
    name = re.sub(r"\s+\(\d+\)$", "", name)
    return re.sub(
        r"@[A-Z][A-Z0-9_]*_(?:[0-9][A-Za-z0-9_.+-]*|PRIVATE)$", "", name
    )


def parse_symbol_section_index(value):
    special = {
        "UND": (0, "UND"),
        "*UND*": (0, "UND"),
        "ABS": (0xFFF1, "ABS"),
        "*ABS*": (0xFFF1, "ABS"),
        "COM": (0xFFF2, "COM"),
        "*COM*": (0xFFF2, "COM"),
    }
    if value in special:
        return special[value]
    if value.isdecimal():
        return int(value), None
    raise ValueError(f"unsupported readelf symbol section index {value!r}")


def parse_symbol_tables(text):
    tables = []
    current = None
    row_pattern = re.compile(
        r"^\s*(\d+):\s+([0-9a-f]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$",
        re.IGNORECASE,
    )

    def finish_table():
        if current is None:
            return
        if len(current["symbols"]) != current["entry_count"]:
            raise ValueError(
                f"readelf symbol table {current['name']!r} reports "
                f"{current['entry_count']} entries but parsed {len(current['symbols'])}"
            )
        tables.append(current)

    for line in text.splitlines():
        heading = re.match(
            r"^Symbol table '([^']+)' contains (\d+) entries:", line
        )
        if heading is not None:
            finish_table()
            current = {
                "name": heading.group(1),
                "entry_count": int(heading.group(2)),
                "symbols": [],
            }
            continue
        if current is None:
            continue
        match = row_pattern.match(line)
        if match is None:
            continue
        index, value, size, symbol_type, binding, visibility, section, name = match.groups()
        section_index, section_kind = parse_symbol_section_index(section)
        current["symbols"].append(
            {
                "index": int(index),
                "value": int(value, 16),
                "size": int(size),
                "type": symbol_type,
                "binding": binding,
                "visibility": visibility,
                "section_index": section_index,
                "section_kind": section_kind,
                "name": normalize_symbol_name(name or "", symbol_type),
            }
        )
    finish_table()
    return tables


def parse_relocation_tables(text, section_types):
    tables = []
    current = None
    for line in text.splitlines():
        heading = re.match(
            r"^Relocation section '([^']+)' at offset .* contains (\d+) entries?:",
            line,
        )
        if heading is not None:
            if current is not None:
                finish_relocation_table(current)
                tables.append(current)
            name = heading.group(1)
            if name not in section_types:
                raise ValueError(f"readelf section type is missing for relocation table {name!r}")
            current = {
                "name": name,
                "kind": section_types[name],
                "entry_count": int(heading.group(2)),
                "relocations": [],
            }
            continue
        if current is None:
            continue
        fields = line.split()
        if (
            len(fields) < 3
            or not HEX.fullmatch(fields[0])
            or not HEX.fullmatch(fields[1])
            or not fields[2].startswith("R_")
        ):
            continue
        addend = None
        if current["kind"] == "RELA":
            if (
                len(fields) >= 6
                and fields[-2] in ("+", "-")
                and HEX.fullmatch(fields[-1])
            ):
                magnitude = int(fields[-1], 16)
                addend = magnitude if fields[-2] == "+" else -magnitude
            elif (
                len(fields) == 4
                and int(fields[1], 16) >> 32 == 0
                and HEX.fullmatch(fields[-1])
            ):
                addend = int(fields[-1], 16)
        current["relocations"].append(
            {
                "offset": int(fields[0], 16),
                "symbol_index": int(fields[1], 16) >> 32,
                "type": fields[2],
                "addend": addend,
            }
        )
    if current is not None:
        finish_relocation_table(current)
        tables.append(current)
    return tables


def finish_relocation_table(table):
    if len(table["relocations"]) != table["entry_count"]:
        raise ValueError(
            f"readelf relocation table {table['name']!r} reports "
            f"{table['entry_count']} entries but parsed {len(table['relocations'])}"
        )


def compare_symbol_tables(path, report, expected_tables):
    actual_tables = {table["name"]: table for table in report["symbol_tables"]}
    expected_by_name = {table["name"]: table for table in expected_tables}
    require_equal(path, "symbol-table count", len(actual_tables), len(expected_by_name))
    for name, expected in expected_by_name.items():
        actual = actual_tables.get(name)
        if actual is None:
            raise ValueError(f"{path}: elfcheck is missing symbol table {name!r}")
        require_equal(path, f"symbol table {name} entry count", int(actual["entry_count"]), expected["entry_count"])
        require_equal(path, f"symbol table {name} parsed count", len(actual["symbols"]), len(expected["symbols"]))
        for index, (actual_symbol, expected_symbol) in enumerate(
            zip(actual["symbols"], expected["symbols"])
        ):
            for key in ("type", "binding", "visibility", "name"):
                require_equal(
                    path,
                    f"symbol table {name} entry {index} {key}",
                    (
                        normalize_symbol_name(actual_symbol[key], actual_symbol["type"])
                        if key == "name"
                        else actual_symbol[key]
                    ),
                    expected_symbol[key],
                )
            require_equal(
                path,
                f"symbol table {name} entry {index} value",
                json_hex(actual_symbol["value"]),
                expected_symbol["value"],
            )
            for key in ("size", "section_index", "section_kind"):
                value = actual_symbol[key]
                if key != "section_kind":
                    value = int(value)
                require_equal(
                    path,
                    f"symbol table {name} entry {index} {key}",
                    value,
                    expected_symbol[key],
                )


def compare_relocation_tables(
    path, report, expected_tables, expected_sections, expected_symbol_tables
):
    actual_tables = {table["name"]: table for table in report["relocation_tables"]}
    expected_by_name = {table["name"]: table for table in expected_tables}
    require_equal(path, "relocation-table count", len(actual_tables), len(expected_by_name))
    sections_by_index = {section["index"]: section for section in expected_sections}
    symbol_tables_by_name = {
        table["name"]: table for table in expected_symbol_tables
    }
    for name, expected in expected_by_name.items():
        actual = actual_tables.get(name)
        if actual is None:
            raise ValueError(f"{path}: elfcheck is missing relocation table {name!r}")
        section = sections_by_index.get(int(actual["index"]))
        if section is None:
            raise ValueError(f"{path}: readelf is missing section for relocation table {name!r}")
        require_equal(path, f"relocation table {name} kind", actual["kind"], section["type"])
        require_equal(path, f"relocation table {name} target index", int(actual["target_index"]), section["info"])
        target = sections_by_index.get(section["info"])
        if target is None:
            raise ValueError(f"{path}: readelf is missing target section for {name!r}")
        expected_target_name = None if section["info"] == 0 else target["name"]
        require_equal(path, f"relocation table {name} target name", actual["target_name"], expected_target_name)
        symbol_section = sections_by_index.get(section["link"])
        if symbol_section is None:
            raise ValueError(f"{path}: readelf is missing symbol table for relocation table {name!r}")
        symbol_table = symbol_tables_by_name.get(symbol_section["name"])
        if symbol_table is None:
            raise ValueError(f"{path}: elfcheck is missing symbol table {symbol_section['name']!r}")
        expected_symbols = symbol_table["symbols"]
        require_equal(path, f"relocation table {name} entry count", int(actual["entry_count"]), expected["entry_count"])
        require_equal(path, f"relocation table {name} parsed count", len(actual["relocations"]), len(expected["relocations"]))
        for index, (actual_relocation, expected_relocation) in enumerate(
            zip(actual["relocations"], expected["relocations"])
        ):
            for key in ("offset", "symbol_index", "type", "addend"):
                value = actual_relocation[key]
                if key == "offset":
                    value = json_hex(value)
                elif key in ("symbol_index",):
                    value = int(value)
                require_equal(
                    path,
                    f"relocation table {name} entry {index} {key}",
                    value,
                    expected_relocation[key],
                )
            symbol_index = expected_relocation["symbol_index"]
            if symbol_index >= len(expected_symbols):
                raise ValueError(
                    f"{path}: relocation table {name} references missing symbol {symbol_index}"
                )
            require_equal(
                path,
                f"relocation table {name} entry {index} symbol name",
                normalize_symbol_name(
                    actual_relocation["symbol_name"],
                    expected_symbols[symbol_index]["type"],
                ),
                expected_symbols[symbol_index]["name"],
            )


def parse_notes(text):
    """Extract the semantically comparable GNU notes from `readelf -n` output."""
    result = {}
    build = re.search(r"Build ID:\s*([0-9a-fA-F]+)", text)
    if build:
        result["build_id"] = build.group(1).lower()
    abi = re.search(r"OS:\s*(\S+),\s*ABI:\s*(\d+)\.(\d+)\.(\d+)", text)
    if abi:
        result["abi"] = f"{abi.group(1)} {abi.group(2)}.{abi.group(3)}.{abi.group(4)}"
    return result


def compare_notes(path, report, expected):
    by_type = {}
    for note in report.get("notes", []):
        by_type.setdefault(note.get("type"), note)
    if "build_id" in expected:
        note = by_type.get(3)
        if note is None or "desc" not in note:
            raise ValueError(f"{path}: elfcheck is missing the build-id note")
        require_equal(path, "note build-id", str(note["desc"]).lower(), expected["build_id"])
    if "abi" in expected:
        note = by_type.get(1)
        if note is None or "desc" not in note:
            raise ValueError(f"{path}: elfcheck is missing the ABI-tag note")
        require_equal(path, "note abi", note["desc"], expected["abi"])


DYNAMIC_ENTRY = re.compile(
    r"^\s*0x([0-9a-fA-F]+)\s+\(([^)]*)\)\s*(.*?)\s*$"
)


def parse_dynamic_value(text):
    """Return (number_or_None, bracketed_name_or_None) for a readelf value cell."""
    bracket = re.search(r"\[([^\]]*)\]", text)
    name = bracket.group(1) if bracket else None
    hex_match = re.fullmatch(r"0x[0-9a-fA-F]+", text)
    if hex_match:
        return int(text, 16), name
    bytes_match = re.fullmatch(r"(\d+)\s*\(bytes\)", text)
    if bytes_match:
        return int(bytes_match.group(1)), name
    if re.fullmatch(r"\d+", text):
        return int(text), name
    return None, name


def parse_dynamic_entries(text):
    """Parse `readelf -dW` into an ordered list of dynamic entries."""
    rows = []
    for line in text.splitlines():
        match = DYNAMIC_ENTRY.match(line)
        if match is None:
            continue
        value, name = parse_dynamic_value(match.group(3))
        rows.append({"tag": int(match.group(1), 16), "value": value, "name": name})
    return rows


def compare_dynamic_entries(path, report, expected):
    actual = report.get("dynamic", {}).get("entries", [])
    require_equal(path, "dynamic entry count", len(actual), len(expected))
    for index, (got, want) in enumerate(zip(actual, expected)):
        require_equal(path, f"dynamic entry {index} tag", int(got["tag"]), want["tag"])
        if want["value"] is not None:
            require_equal(
                path, f"dynamic entry {index} value", int(got["value"]), want["value"]
            )
        if want["name"] is not None:
            require_equal(
                path, f"dynamic entry {index} name", got.get("name"), want["name"]
            )
    return len(actual)


def compare_dump(path, runner, readelf, flag, section, env, label):
    expected = run([readelf, flag, section, path], env)
    actual = run([runner, flag, section, path], env)
    want = [line.rstrip() for line in expected.splitlines() if line.strip()]
    got = [line.rstrip() for line in actual.splitlines() if line.strip()]
    for index, (a, b) in enumerate(zip(got, want)):
        if a != b:
            raise ValueError(
                f"{path}: {label} line {index}: elfcheck={a!r}, readelf={b!r}"
            )
    if len(got) != len(want):
        raise ValueError(
            f"{path}: {label} line count: elfcheck={len(got)}, readelf={len(want)}"
        )


def compare_file(runner, readelf, path, env):
    output = run([runner, "--json", path], env)
    try:
        report = json.loads(output)
    except ValueError as error:
        raise ValueError(f"{path}: elfcheck did not emit valid JSON: {error}") from error
    if report.get("validation", {}).get("valid") is not True:
        raise ValueError(f"{path}: elfcheck marked the ELF invalid")

    header_output = run([readelf, "-hW", path], env)
    expected_header = {
        key: capture(header_output, pattern, key, base)
        for key, (pattern, base) in HEADER_FIELDS.items()
    }
    header = report["header"]
    expected_class = re.search(r"^\s*Class:\s*(\S+)", header_output, re.MULTILINE)
    expected_data = re.search(r"^\s*Data:\s*(.+)$", header_output, re.MULTILINE)
    expected_type = re.search(r"^\s*Type:\s*(.+)$", header_output, re.MULTILINE)
    expected_machine = re.search(r"^\s*Machine:\s*(.+)$", header_output, re.MULTILINE)
    if (
        expected_class is None
        or expected_data is None
        or expected_type is None
        or expected_machine is None
    ):
        raise ValueError(f"{path}: readelf header is missing required metadata")
    require_equal(path, "class", header["class"], expected_class.group(1))
    require_equal(path, "data encoding", normalize_data(header["data"]), normalize_data(expected_data.group(1)))
    require_equal(
        path,
        "file type",
        header["type"].split()[0],
        expected_type.group(1).strip().split()[0],
    )
    require_equal(
        path,
        "machine",
        normalize_machine(header["machine"]),
        normalize_machine(expected_machine.group(1)),
    )
    for key, expected in expected_header.items():
        actual = json_hex(header[key]) if key == "entry" else int(header[key])
        require_equal(path, f"header {key}", actual, expected)

    program_output = run([readelf, "-lW", path], env)
    expected_program_headers = parse_program_headers(program_output)
    actual_program_headers = report["program_headers"]
    require_equal(path, "program-header count", len(actual_program_headers), len(expected_program_headers))
    for index, (actual, expected) in enumerate(zip(actual_program_headers, expected_program_headers)):
        for key in ("offset", "vaddr", "filesz", "memsz", "align"):
            require_equal(path, f"program header {index} {key}", json_hex(actual[key]), expected[key])
        actual_flags = actual["flags"]
        require_equal(path, f"program header {index} flags", actual_flags, expected["flags"])

    section_output = run([readelf, "-SW", path], env)
    expected_sections = parse_section_headers(section_output)
    actual_sections = report["section_headers"]
    require_equal(path, "section-header count", len(actual_sections), len(expected_sections))
    for index, (actual, expected) in enumerate(zip(actual_sections, expected_sections)):
        require_equal(path, f"section {index} index", int(actual["index"]), expected["index"])
        require_equal(path, f"section {index} name", actual["name"], expected["name"])
        for key in ("addr", "offset", "size"):
            require_equal(path, f"section {index} {key}", json_hex(actual[key]), expected[key])
        require_equal(path, f"section {index} alignment", json_hex(actual["addralign"]), expected["align"])
        require_equal(
            path,
            f"section {index} flags",
            "".join(sorted(actual["flags"])),
            "".join(sorted(expected["flags"])),
        )

    symbol_output = run([readelf, "-sW", path], env)
    expected_symbol_tables = parse_symbol_tables(symbol_output)
    compare_symbol_tables(path, report, expected_symbol_tables)

    relocation_output = run([readelf, "-rW", path], env)
    section_types = {section["name"]: section["type"] for section in expected_sections}
    expected_relocation_tables = parse_relocation_tables(
        relocation_output, section_types
    )
    compare_relocation_tables(
        path,
        report,
        expected_relocation_tables,
        expected_sections,
        expected_symbol_tables,
    )

    notes_output = run([readelf, "-n", path], env)
    compare_notes(path, report, parse_notes(notes_output))

    dynamic_output = run([readelf, "-dW", path], env)
    dynamic_count = compare_dynamic_entries(
        path, report, parse_dynamic_entries(dynamic_output)
    )

    # .shstrtab exists in every ELF, so it exercises both section dumps.
    compare_dump(path, runner, readelf, "-x", ".shstrtab", env, "hex dump")
    compare_dump(path, runner, readelf, "-p", ".shstrtab", env, "string dump")

    symbol_count = sum(table["entry_count"] for table in expected_symbol_tables)
    relocation_count = sum(table["entry_count"] for table in expected_relocation_tables)
    return (
        len(actual_program_headers),
        len(actual_sections),
        symbol_count,
        relocation_count,
        dynamic_count,
    )


def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} ELFCHECK_RUNNER ELF_FILE...", file=sys.stderr)
        return 2
    readelf = shutil.which("readelf")
    if readelf is None:
        print("error: GNU readelf is required for differential tests", file=sys.stderr)
        return 2

    runner, *paths = sys.argv[1:]
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    failures = 0
    for path in paths:
        try:
            (
                program_count,
                section_count,
                symbol_count,
                relocation_count,
                dynamic_count,
            ) = compare_file(runner, readelf, path, env)
            print(
                f"readelf differential: matched {path} "
                f"({program_count} program headers, {section_count} sections, "
                f"{symbol_count} symbols, {relocation_count} relocations, "
                f"{dynamic_count} dynamic entries)"
            )
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
            print(f"readelf differential: mismatch: {error}", file=sys.stderr)
            failures += 1
    if failures:
        return 1
    print(f"readelf differential: all {len(paths)} files matched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
