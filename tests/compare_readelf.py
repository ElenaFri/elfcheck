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
                "addr": int(numeric[0], 16),
                "offset": int(numeric[1], 16),
                "size": int(numeric[2], 16),
                "flags": flag_tokens[0] if flag_tokens else "",
                "align": int(trailing[-1], 10),
            }
            break
        if parsed is None:
            raise ValueError(f"could not parse readelf section row: {line.strip()!r}")
        rows.append(parsed)
    return rows


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

    return len(actual_program_headers), len(actual_sections)


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
            program_count, section_count = compare_file(runner, readelf, path, env)
            print(
                f"readelf differential: matched {path} "
                f"({program_count} program headers, {section_count} sections)"
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
