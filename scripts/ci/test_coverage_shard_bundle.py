#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for scripts/ci/coverage_shard_bundle.sh: which executables a coverage part bundles, in cargo's old target
layout (test binaries in <profile>/deps, build scripts in <profile>/build) and in cargo 1.100's (every crate's
outputs under <profile>/build/<package>/<hash>/out, build scripts included), and that a part with no executable
fails instead of bundling nothing. Runs the real script in a temp dir with a stub `rustc`. Standard library only.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "ci" / "coverage_shard_bundle.sh"
T = "target/llvm-cov-target"


def bundle(files: list[str]) -> tuple[int, set[str], str]:
    """(exit code, bundled executable paths, stderr+stdout) for a target tree holding `files` (all executable)."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        target = tmp / T
        target.mkdir(parents=True)
        (target / "a-1.profraw").write_bytes(b"profile")
        for rel in files:
            p = target / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"#!/bin/sh\n")
            p.chmod(0o755)
        (tmp / "run.log").write_text("log\n")
        (tmp / "tests.tsv").write_text("bin\tname\tok\n")
        stub = tmp / "stub"
        stub.mkdir()
        (stub / "rustc").write_text("#!/bin/sh\necho 'release: 1.100.0'\necho 'commit-hash: 0'\n")
        (stub / "rustc").chmod(0o755)
        # COPYFILE_DISABLE: macOS tar would add `._` resource-fork entries (CI's GNU tar adds none).
        env = {**os.environ, "PATH": f"{stub}:{os.environ['PATH']}", "COPYFILE_DISABLE": "1"}
        p = subprocess.run(["bash", str(SCRIPT), "lib-a"], cwd=tmp, env=env, capture_output=True, text=True)
        got = set()
        tar = tmp / "bundle" / "files.tar"
        if p.returncode == 0 and tar.exists():
            with tarfile.open(tar) as tf:
                got = {os.path.normpath(n) for n in tf.getnames() if not n.startswith("profraw")}
        return p.returncode, got, p.stdout + p.stderr


def main() -> int:
    new_test = "debug/build/mcp-gateway/a2aa1ac763c42e38/out/mcp_gateway-a2aa1ac763c42e38"
    new_script = "debug/build/serde/0123456789abcdef/out/build_script_build"
    old_test = "debug/deps/mcp_gateway-ab12"
    old_script = "debug/build/serde-0123/build-script-build"
    rows = [
        ("cargo 1.100 layout: the test binary is bundled, the build script is not",
         [new_test, new_script], 0, {new_test}),
        ("old layout: deps binary bundled, build-script-build skipped",
         [old_test, old_script, "debug/build/serde-0123/build_script_build-0123"], 0, {old_test}),
        ("incremental and fingerprint output are skipped",
         [new_test, "debug/incremental/x/y", "debug/.fingerprint/z/w"], 0, {new_test}),
        ("a part with only build scripts fails (it would grade every function at 0%)", [new_script], 1, set()),
    ]
    wrong = 0
    for label, files, want_rc, want in rows:
        rc, got, out = bundle(files)
        ok = (rc == 0) == (want_rc == 0) and (want_rc != 0 or got == want)
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} {label}: exit {rc}, bundled {sorted(got)}" + ("" if ok else f"\n      {out[-300:]!r}"))
    print(f"coverage bundle rows: {wrong} wrong")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
