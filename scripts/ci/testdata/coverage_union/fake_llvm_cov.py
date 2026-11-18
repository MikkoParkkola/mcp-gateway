#!/usr/bin/env python3
"""Model the first-object mapping observed in probe run 44240619213.

FAKE_LLVM_COV_TABLE names a JSON document with objects -> function lists and
records -> "name|hash" -> {calls, lines}. Function entries have file, name,
start, hash and lines (line numbers). Optional exit_status maps a JSON-encoded
ordered object-path list (json.dumps defaults) to the exit code for that call.
Optional export_overrides uses the same keys to replace objects or records for
one call, allowing gate fixtures to disagree with the all-objects baseline.
Function entries may include branches as [line, block, branch, taken] arrays.
Even a failing export writes its lcov, to allow partial-output checks later.
FAKE_LLVM_COV_LOG receives one full sys.argv JSON array per invocation.
"""

import json
import os
import sys
from pathlib import Path


def main():
    with open(os.environ["FAKE_LLVM_COV_LOG"], "a", encoding="utf-8") as log:
        log.write(json.dumps(sys.argv) + "\n")
    table = json.loads(Path(os.environ["FAKE_LLVM_COV_TABLE"]).read_text())
    objects = [sys.argv[i + 1] for i, arg in enumerate(sys.argv) if arg == "-object"]
    table = {**table, **table.get("export_overrides", {}).get(json.dumps(objects), {})}
    selected = {}
    for obj in objects:
        for function in table["objects"][obj]:
            selected.setdefault(function["name"], function)

    files = {}
    mismatches = 0
    records = table["records"]
    for name, function in selected.items():
        record = records.get(f"{name}|{function['hash']}")
        if record is None and any(key.rsplit("|", 1)[0] == name for key in records):
            mismatches += 1
        record = record or {"calls": 0, "lines": {}}
        functions, lines, branches = files.setdefault(function["file"], ([], {}, set()))
        functions.append((function["start"], name, record["calls"]))
        branches.update(tuple(branch) for branch in function.get("branches", []))
        for line in function["lines"]:
            count = record["lines"].get(str(line), 0)
            lines[line] = max(lines.get(line, 0), count)

    if mismatches:
        print(f"warning: {mismatches} functions have mismatched data", file=sys.stderr)
    for filename, (functions, lines, branches) in sorted(files.items()):
        print(f"SF:{filename}")
        for start, name, _ in sorted(functions):
            print(f"FN:{start},{name}")
        for _, name, calls in sorted(functions):
            print(f"FNDA:{calls},{name}")
        print(f"FNF:{len(functions)}")
        print(f"FNH:{sum(calls > 0 for _, _, calls in functions)}")
        for line, count in sorted(lines.items()):
            print(f"DA:{line},{count}")
        for branch in sorted(branches):
            print("BRDA:" + ",".join(map(str, branch)))
        print(f"BRF:{len(branches)}")
        print(f"BRH:{sum(taken != '-' and int(taken) > 0 for _, _, _, taken in branches)}")
        print(f"LF:{len(lines)}")
        print(f"LH:{sum(count > 0 for count in lines.values())}")
        print("end_of_record")
    return table.get("exit_status", {}).get(json.dumps(objects), 0)


if __name__ == "__main__":
    sys.exit(main())
