"""Run bounded, deterministic mutations through elfcheck's CLI paths."""

import json
import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

SEED = 0xE1FC0DE
TIMEOUT_SECONDS = 1.0
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_RANDOM_CASES = 16
U64_MAX = (1 << 64) - 1


def build_cases(original):
    cases = []

    def add(name, data, mode="--json"):
        cases.append((name, data, mode))

    def changed(name, updates, mode="--json"):
        data = bytearray(original)
        for offset, fmt, value in updates:
            struct.pack_into(fmt, data, offset, value)
        add(name, bytes(data), mode)

    for length in (0, 3, 4, 63, 64, len(original) - 1):
        add(f"truncated-{length}", original[:length])

    changed("elf32-class", [(4, "B", 1)])
    changed("big-endian-data", [(5, "B", 2)])
    changed("bad-ident-version", [(6, "B", 0)])
    changed("bad-elf-version", [(20, "I", 0)])
    changed("bad-ehsize", [(52, "H", 0)])

    changed("program-offset-overflow", [(32, "Q", U64_MAX)], "--validate")
    changed("section-offset-overflow", [(40, "Q", U64_MAX)], "--validate")
    changed("zero-program-entry-size", [(54, "H", 0)], "--validate")
    changed("zero-section-entry-size", [(58, "H", 0)], "--validate")
    changed("maximum-program-count", [(56, "H", 0xFFFF)], "--validate")
    changed("maximum-section-count", [(60, "H", 0xFFFF)], "--validate")
    changed(
        "maximum-program-count-zero-entry-size",
        [(54, "H", 0), (56, "H", 0xFFFF)],
        "--validate",
    )
    changed(
        "maximum-section-count-zero-entry-size",
        [(58, "H", 0), (60, "H", 0xFFFF)],
        "--validate",
    )

    data = bytearray(original)
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    section_entry_size = struct.unpack_from("<H", data, 58)[0]
    section_count = struct.unpack_from("<H", data, 60)[0]
    names_index = struct.unpack_from("<H", data, 62)[0]
    names_header = section_offset + names_index * section_entry_size
    names_start, names_size = struct.unpack_from("<QQ", data, names_header + 24)
    section_names = data[names_start : names_start + names_size]
    for index in range(section_count):
        section = section_offset + index * section_entry_size
        name_offset = struct.unpack_from("<I", data, section)[0]
        name = section_names[name_offset:].split(b"\0", 1)[0]
        if name != b".strtab":
            continue
        strings_start, strings_size = struct.unpack_from("<QQ", data, section + 24)
        strings = data[strings_start : strings_start + strings_size]
        marker = strings.find(b"validate_structure")
        if marker < 0:
            raise ValueError("symbol name fixture was not found in .strtab")
        data[strings_start + marker + len(b"validate_")] = 0xEA
        add("non-ascii-symbol-name", bytes(data))
        break
    else:
        raise ValueError(".strtab section was not found")

    rng = random.Random(SEED)
    for index in range(MAX_RANDOM_CASES):
        data = bytearray(original)
        for _ in range(rng.randint(1, 4)):
            offset = rng.randrange(16, len(data))
            data[offset] ^= rng.randrange(1, 256)
        add(f"random-{index:02d}", bytes(data))

    return cases


def check_case(runner, input_path, mode):
    result = subprocess.run(
        [runner, mode, str(input_path)],
        text=True,
        capture_output=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode not in (0, 1, 2):
        raise ValueError(f"unexpected exit code {result.returncode}")
    if len(result.stdout.encode()) + len(result.stderr.encode()) > MAX_OUTPUT_BYTES:
        raise ValueError(f"output exceeded {MAX_OUTPUT_BYTES} bytes")

    if mode == "--json":
        if result.returncode in (0, 2):
            report = json.loads(result.stdout)
            validation = report.get("validation")
            if not isinstance(validation, dict):
                raise ValueError("JSON is missing the validation object")
            if validation.get("valid") is not (result.returncode == 0):
                raise ValueError("JSON validity does not match the exit code")
        elif result.stdout.strip():
            raise ValueError("error path unexpectedly wrote to stdout")
    elif result.returncode == 0 and "no structural issues detected" not in result.stdout:
        raise ValueError("clean validation did not report success")
    elif result.returncode == 2 and "issue(s) found" not in result.stdout:
        raise ValueError("invalid structure did not produce a validation summary")
    elif result.returncode == 1 and not (result.stdout or result.stderr):
        raise ValueError("error exit produced no diagnostic")


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} ELFCHECK_BINARY", file=sys.stderr)
        return 2

    binary = Path(sys.argv[1])
    try:
        original = binary.read_bytes()
        cases = build_cases(original)
        with tempfile.TemporaryDirectory(prefix="elfcheck-fuzz-") as tmp:
            input_path = Path(tmp) / "mutated.elf"
            for index, (name, data, mode) in enumerate(cases):
                input_path.write_bytes(data)
                try:
                    check_case(str(binary.resolve()), input_path, mode)
                except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError) as error:
                    print(
                        f"FAIL: case {index} ({name}, mode={mode}, seed={SEED}): {error}",
                        file=sys.stderr,
                    )
                    return 1
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(f"PASS: {len(cases)} deterministic mutations (seed={SEED})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
