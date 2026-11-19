#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Export each coverage mapping separately and publish a gated LCOV union.

Usage: coverage_union.py LOG SINGLE OUT
"""

from __future__ import annotations

import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

import lib_union


def logged_command(log: Path) -> tuple[list[str], dict[int, str]]:
    commands = []
    for line in log.read_text(encoding="utf-8").splitlines():
        if not line.lstrip().startswith("Running ") or "-format=lcov" not in line:
            continue
        match = re.fullmatch(r"\s*Running `(.*)`\s*", line)
        if match is None:
            raise ValueError("malformed Running command")
        argv = shlex.split(match[1])
        if len(argv) >= 2 and argv[1] == "export" and "-format=lcov" in argv:
            commands.append(argv)
    if len(commands) != 1:
        raise ValueError(f"expected one LCOV export Running line, found {len(commands)}")
    argv = commands[0]
    objects = {}
    profiles = []
    index = 2
    # These options take separate values in cargo-llvm-cov's logged command.
    # All other bare tokens must be refused rather than silently losing an object.
    value_options = {"-instr-profile", "-ignore-filename-regex"}
    while index < len(argv):
        token = argv[index]
        if token.startswith(("-object", "--object")):
            if token != "-object" or index + 1 == len(argv) or argv[index + 1].startswith("-"):
                raise ValueError(f"invalid object token: {token}")
            objects[index] = argv[index + 1]
            index += 2
        elif token in value_options:
            if index + 1 == len(argv) or argv[index + 1].startswith("-"):
                raise ValueError(f"missing value for {token}")
            if token == "-instr-profile":
                profiles.append(argv[index + 1])
            index += 2
        elif token.startswith("-instr-profile="):
            profiles.append(token.split("=", 1)[1])
            index += 1
        elif token.startswith("-"):
            index += 1
        else:
            raise ValueError(f"unexpected positional token after export: {token}")
    if not objects:
        raise ValueError("no -object pairs in Running command")
    if len(profiles) != 1 or not Path(profiles[0]).is_file():
        raise ValueError("-instr-profile must name one existing file")
    return argv, objects


def object_groups(objects: dict[int, str]) -> dict[str, list[int]]:
    root = Path(__file__).resolve().parents[2]
    count = lib_union.part_count(root / "scripts/dev/test-parts-build.rs")
    groups = {name: [] for name in ["other", *(f"p{k}" for k in range(1, count + 1))]}
    for index, obj in objects.items():
        parts = Path(obj).parts
        folders = [parts[i + 1] for i in range(len(parts) - 2)
                   if parts[i] == "deps" and re.fullmatch(r"p\d+", parts[i + 1])]
        if len(folders) > 1:
            raise ValueError(f"object belongs to multiple part folders: {obj}")
        group = folders[0] if folders else "other"
        if group not in groups:
            raise ValueError(f"unexpected folder {group}; expected p1..p{count}")
        groups[group].append(index)
    for group, indices in groups.items():
        if group != "other" and len(indices) != 1:
            raise ValueError(f"folder {group}: expected one object, found {len(indices)}")
    assigned = [index for indices in groups.values() for index in indices]
    if sorted(assigned) != sorted(objects):
        raise ValueError("every object must belong to exactly one group")
    return groups


def mismatch_count(stderr: str, group: str) -> int:
    warning = re.compile(r"warning: (\d+) functions have mismatched data")
    count = 0
    for line in stderr.splitlines():
        if "mismatched" not in line.lower():
            continue
        match = warning.fullmatch(line.strip())
        if match is None:
            raise ValueError(f"unparsed mismatch warning in {group}: {line}")
        count += int(match[1])
    return count


def export_groups(argv, objects, groups, directory):
    exports = []
    counts = {}
    for group, indices in groups.items():
        keep = set(indices)
        # Remove only complete object pairs; preserve every other token in place.
        dropped = {position for index in objects if index not in keep
                   for position in (index, index + 1)}
        command = [token for index, token in enumerate(argv) if index not in dropped]
        output = directory / f"{group}.lcov"
        stderr = directory / f"{group}.stderr"
        with output.open("wb") as stream, stderr.open("wb") as errors:
            try:
                done = subprocess.run(command, stdout=stream, stderr=errors, check=False)
            except OSError as error:
                raise ValueError(f"llvm-cov export failed for {group}: {error}") from error
        if done.returncode:
            raise ValueError(f"llvm-cov export failed for {group}: exit {done.returncode}; see {stderr}")
        counts[group] = mismatch_count(stderr.read_text(encoding="utf-8"), group)
        exports.append(output)
    (directory / "mismatch.txt").write_text(
        "".join(f"{group} {count}\n" for group, count in counts.items()), encoding="utf-8")
    if counts["other"]:
        raise ValueError(f"gate (a): other has {counts['other']} functions with mismatched data")
    return exports


def read_union(paths):
    # Maxima retain coverage from any mapping without adding the same aggregate
    # profile record more than once. Summary records must therefore be recounted.
    files = {}
    for path in paths:
        record = None
        source = None
        with path.open(encoding="utf-8") as stream:
            for number, raw in enumerate(stream, 1):
                line = raw.rstrip("\r\n")
                if line.startswith("BRDA:"):
                    raise ValueError(f"{path}:{number}: branch record is not supported")
                if line.startswith("SF:"):
                    if record is not None or not line[3:]:
                        raise ValueError(f"{path}:{number}: corrupt LCOV file record")
                    source = line[3:]
                    record = files.setdefault(source, {"fn": {}, "fnda": {}, "da": {}})
                elif line == "end_of_record":
                    if record is None:
                        raise ValueError(f"{path}:{number}: unexpected end_of_record")
                    record = None
                elif line.startswith(("FN:", "FNDA:", "DA:")):
                    if record is None:
                        raise ValueError(f"{path}:{number}: coverage outside a file record")
                    if line.startswith("FN:"):
                        start, name = line[3:].split(",", 1)
                        start = int(start)
                        previous = record["fn"].setdefault(name, start)
                        if previous != start:
                            raise ValueError(f"{source}: function {name} has start lines {previous} and {start}")
                    elif line.startswith("FNDA:"):
                        count, name = line[5:].split(",", 1)
                        record["fnda"][name] = max(record["fnda"].get(name, 0), int(count))
                    else:
                        line_number, count = line[3:].split(",")[:2]
                        line_number = int(line_number)
                        record["da"][line_number] = max(record["da"].get(line_number, 0), int(count))
                elif line and not line.startswith(("TN:", "LF:", "LH:", "FNF:", "FNH:", "BRF:", "BRH:")):
                    raise ValueError(f"{path}:{number}: unrecognized LCOV record: {line}")
        if record is not None:
            raise ValueError(f"{path}: truncated LCOV record for {source}")
    return files


def gate_baseline(joined, baseline):
    for source, record in baseline.items():
        actual = joined.get(source, {"fn": {}, "fnda": {}, "da": {}})
        for line, count in record["da"].items():
            if line not in actual["da"]:
                raise ValueError(f"gate (b): {source}: missing line {line}")
            if count > 0 and actual["da"][line] <= 0:
                raise ValueError(f"gate (b): {source}: lost coverage at line {line}")
        for name in record["fn"]:
            if name not in actual["fn"]:
                raise ValueError(f"gate (b): {source}: missing function {name}")
            if actual["fnda"].get(name, 0) < record["fnda"].get(name, 0):
                raise ValueError(f"gate (b): {source}: lower count for function {name}")


def write_report(stream, files):
    for source in sorted(files):
        record = files[source]
        names = sorted(record["fn"], key=lambda name: (record["fn"][name], name))
        stream.write(f"SF:{source}\n")
        for name in names:
            stream.write(f"FN:{record['fn'][name]},{name}\n")
        for name in names:
            stream.write(f"FNDA:{record['fnda'].get(name, 0)},{name}\n")
        called = sum(record["fnda"].get(name, 0) > 0 for name in names)
        stream.write(f"FNF:{len(names)}\nFNH:{called}\n")
        for line in sorted(record["da"]):
            stream.write(f"DA:{line},{record['da'][line]}\n")
        covered = sum(count > 0 for count in record["da"].values())
        stream.write(f"BRF:0\nBRH:0\nLF:{len(record['da'])}\nLH:{covered}\nend_of_record\n")


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("usage: coverage_union.py LOG SINGLE OUT", file=sys.stderr)
        return 2
    temporary = None
    try:
        log, single, out = map(Path, argv[1:])
        command, objects = logged_command(log)
        groups = object_groups(objects)
        artifacts = [out.parent / f"{group}.{suffix}" for group in groups for suffix in ("lcov", "stderr")]
        artifacts.append(out.parent / "mismatch.txt")
        # Diagnostic exports must not overwrite either the baseline or published report.
        for artifact in artifacts:
            if artifact.resolve() in {out.resolve(), single.resolve(), log.resolve()}:
                raise ValueError(f"diagnostic artifact conflicts with input or OUT: {artifact}")
        baseline = read_union([single])
        exports = export_groups(command, objects, groups, out.parent)
        joined = read_union(exports)
        gate_baseline(joined, baseline)
        # Keep a prior report intact even if writing the replacement fails.
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=out.parent,
                                         prefix=f".{out.name}.", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            write_report(stream, joined)
        temporary.replace(out)
        functions = sum(len(record["fn"]) for record in joined.values())
        print(f"coverage union: {len(groups)} groups, {len(joined)} files, {functions} functions")
        return 0
    except (OSError, ValueError, SystemExit) as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
