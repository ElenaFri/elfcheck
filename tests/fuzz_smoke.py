"""Run bounded, deterministic mutations through elfcheck's CLI paths."""

import argparse
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
DEFAULT_RANDOM_CASES = 16
U64_MAX = (1 << 64) - 1

JSON_ARGS = ["--json"]
VALIDATE_ARGS = ["--validate"]
TRIAGE_ARGS = ["--triage"]
# Bounded disassembly keeps fuzz output under MAX_OUTPUT_BYTES on big binaries.
DISASM_ARGS = ["--disasm", "--count", "200"]
RANDOM_MODES = (JSON_ARGS, TRIAGE_ARGS, DISASM_ARGS, VALIDATE_ARGS)


def find_string_section(data):
    """Return (start, size) of .strtab, or .dynstr when there is no .strtab."""
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    section_entry_size = struct.unpack_from("<H", data, 58)[0]
    section_count = struct.unpack_from("<H", data, 60)[0]
    names_index = struct.unpack_from("<H", data, 62)[0]
    if not section_offset or not section_entry_size or section_count <= names_index:
        return None
    names_header = section_offset + names_index * section_entry_size
    if names_header + 64 > len(data):
        return None
    names_start, names_size = struct.unpack_from("<QQ", data, names_header + 24)
    names = data[names_start : names_start + names_size]
    if len(names) != names_size:
        return None
    for wanted in (b".strtab", b".dynstr"):
        for index in range(section_count):
            section = section_offset + index * section_entry_size
            if section + 64 > len(data):
                return None
            name_offset = struct.unpack_from("<I", data, section)[0]
            name = names[name_offset:].split(b"\0", 1)[0] if name_offset < len(names) else b""
            if name != wanted:
                continue
            strings_start, strings_size = struct.unpack_from("<QQ", data, section + 24)
            if strings_start + strings_size > len(data) or strings_size < 3:
                continue
            return strings_start, strings_size
    return None


def corrupt_string_case(original):
    """Flip one printable string byte to a non-ASCII value in .strtab/.dynstr."""
    found = find_string_section(original)
    if found is None:
        return None
    strings_start, strings_size = found
    strings = original[strings_start : strings_start + strings_size]
    for marker in range(len(strings) - 1):
        if strings[marker : marker + 2].isalpha() and strings[marker + 1] != 0:
            data = bytearray(original)
            data[strings_start + marker] = 0xEA
            return bytes(data)
    return None


def build_cases(original, target_name, random_cases):
    cases = []

    def add(name, data, args):
        cases.append((f"{target_name}:{name}", data, args))

    def changed(name, updates, args):
        data = bytearray(original)
        for offset, fmt, value in updates:
            struct.pack_into(fmt, data, offset, value)
        add(name, bytes(data), args)

    for length in (0, 3, 4, 63, 64, len(original) - 1):
        add(f"truncated-{length}", original[:length], JSON_ARGS)

    changed("elf32-class", [(4, "B", 1)], JSON_ARGS)
    changed("big-endian-data", [(5, "B", 2)], JSON_ARGS)
    changed("bad-ident-version", [(6, "B", 0)], JSON_ARGS)
    changed("bad-elf-version", [(20, "I", 0)], JSON_ARGS)
    changed("bad-ehsize", [(52, "H", 0)], JSON_ARGS)

    changed("program-offset-overflow", [(32, "Q", U64_MAX)], VALIDATE_ARGS)
    changed("section-offset-overflow", [(40, "Q", U64_MAX)], VALIDATE_ARGS)
    changed("zero-program-entry-size", [(54, "H", 0)], VALIDATE_ARGS)
    changed("zero-section-entry-size", [(58, "H", 0)], VALIDATE_ARGS)
    changed("maximum-program-count", [(56, "H", 0xFFFF)], VALIDATE_ARGS)
    changed("maximum-section-count", [(60, "H", 0xFFFF)], VALIDATE_ARGS)
    changed(
        "maximum-program-count-zero-entry-size",
        [(54, "H", 0), (56, "H", 0xFFFF)],
        VALIDATE_ARGS,
    )
    changed(
        "maximum-section-count-zero-entry-size",
        [(58, "H", 0), (60, "H", 0xFFFF)],
        VALIDATE_ARGS,
    )

    corrupted = corrupt_string_case(original)
    if corrupted is not None:
        add("non-ascii-string", corrupted, JSON_ARGS)

    # Per-target seeded RNG: adding or reordering targets never changes the
    # mutations of the others, so failures stay reproducible from the case name.
    rng = random.Random(f"{SEED}:{target_name}")
    for index in range(random_cases):
        data = bytearray(original)
        for _ in range(rng.randint(1, 4)):
            offset = rng.randrange(16, len(data))
            data[offset] ^= rng.randrange(1, 256)
        mode = RANDOM_MODES[index % len(RANDOM_MODES)]
        add(f"random-{index:02d}", bytes(data), mode)

    return cases


def run_case(runner, input_path, args):
    result = subprocess.run(
        [runner, *args, str(input_path)],
        text=True,
        capture_output=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
    )
    code = result.returncode
    if code not in (0, 1, 2):
        raise ValueError(f"unexpected exit code {code}")
    if len(result.stdout.encode()) + len(result.stderr.encode()) > MAX_OUTPUT_BYTES:
        raise ValueError(f"output exceeded {MAX_OUTPUT_BYTES} bytes")

    mode = args[0]
    if mode == "--json":
        if code in (0, 2):
            report = json.loads(result.stdout)
            validation = report.get("validation")
            if not isinstance(validation, dict):
                raise ValueError("JSON is missing the validation object")
            if validation.get("valid") is not (code == 0):
                raise ValueError("JSON validity does not match the exit code")
        elif result.stdout.strip():
            raise ValueError("error path unexpectedly wrote to stdout")
    elif mode == "--validate":
        if code == 0 and "no structural issues detected" not in result.stdout:
            raise ValueError("clean validation did not report success")
        elif code == 2 and "issue(s) found" not in result.stdout:
            raise ValueError("invalid structure did not produce a validation summary")
        elif code == 1 and not (result.stdout or result.stderr):
            raise ValueError("error exit produced no diagnostic")
    elif mode == "--triage":
        if code in (0, 2) and "Summary:" not in result.stdout:
            raise ValueError("triage did not produce a summary line")
        elif code == 1 and not (result.stdout or result.stderr):
            raise ValueError("error exit produced no diagnostic")
    # --disasm: exit code and output bounds are the invariants; the decoder
    # must cope with arbitrary bytes without crashing or hanging.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cases",
        type=int,
        default=DEFAULT_RANDOM_CASES,
        help="random mutation cases per target (default: %(default)s)",
    )
    parser.add_argument(
        "binaries",
        nargs="+",
        help="elfcheck binary (the runner), then extra mutation targets",
    )
    args = parser.parse_args()
    if args.cases < 0:
        parser.error("--cases must be >= 0")

    runner = Path(args.binaries[0])
    targets = [Path(p) for p in args.binaries]
    total = 0
    processed = 0
    try:
        with tempfile.TemporaryDirectory(prefix="elfcheck-fuzz-") as tmp:
            input_path = Path(tmp) / "mutated.elf"
            for target in targets:
                if not target.is_file():
                    print(f"note: skipping missing target {target}", file=sys.stderr)
                    continue
                original = target.read_bytes()
                cases = build_cases(original, target.name, args.cases)
                for index, (name, data, case_args) in enumerate(cases):
                    input_path.write_bytes(data)
                    try:
                        run_case(str(runner.resolve()), input_path, case_args)
                    except (
                        OSError,
                        subprocess.TimeoutExpired,
                        ValueError,
                        json.JSONDecodeError,
                    ) as error:
                        print(
                            f"FAIL: case {index} ({name}, args={case_args}, "
                            f"seed={SEED}): {error}",
                            file=sys.stderr,
                        )
                        return 1
                total += len(cases)
                processed += 1
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(f"PASS: {total} mutations across {processed} target(s) (seed={SEED})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
