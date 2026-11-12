#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for scripts/ci/os_sensitive_diff.py: which diffs need the os-int label.

A lane pull request whose diff adds or removes a line, in a Rust or TOML file, that names the secret store,
the keychain or a file lock is OS-sensitive: macOS behaves differently there, and only a merge train ran
macOS (train 46u: the keychain change to `init` passed its own CI and broke the macOS int shard).
Docs, a file's name alone, and platform cfg lines do not count.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import os_sensitive_diff as osd  # noqa: E402


def diff(path: str, *lines: str) -> str:
    """A unified diff with zero context for one file: each line is '+...' or '-...'."""
    adds = [x for x in lines if x.startswith("+")]
    return (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
            f"@@ -10,{len(lines) - len(adds)} +10,{len(adds)} @@\n" + "\n".join(lines) + "\n")


def main() -> int:
    errors = []

    def row(name: str, got, want) -> None:
        if got != want:
            errors.append(f"{name}: got {got!r}, want {want!r}")

    # Rows the lead named.
    init = diff("src/cli_support/init.rs", "+    let token = secret_store::write_admin(&home)?;")
    row("init.rs with a secret-store line triggers", [(p, n) for p, n, _ in osd.scan(init)],
        [("src/cli_support/init.rs", 10)])
    adr = diff("docs/adr/ADR-028-secret-store-keychain-or-files.md", "+The keychain holds the admin token.")
    row("an ADR that mentions the keychain does not trigger", osd.scan(adr), [])
    cfg = diff("src/process.rs", "+#[cfg(unix)]", "+fn reap() {}", "-#[cfg(windows)]")
    row("a cfg-only change does not trigger", osd.scan(cfg), [])

    # Content, not names.
    named = diff("src/secret_store/keychain.rs", "+fn unrelated() {}")
    row("a file named for the keychain with no keychain line does not trigger", osd.scan(named), [])
    row("a removed line triggers", len(osd.scan(diff("src/config/save.rs", "-    flock(fd, LOCK_EX)?;"))), 1)
    row("a TOML dependency triggers", len(osd.scan(diff("Cargo.toml", '+keyring = "3"'))), 1)
    row("the same line in markdown does not trigger", osd.scan(diff("README.md", '+keyring = "3"')), [])
    row("a test file counts", len(osd.scan(diff("tests/e2e_first_run_journey.rs", "+    // Keychain is empty"))), 1)
    row("each of the named words triggers", [bool(osd.scan(diff("src/a.rs", f"+use {w};"))) for w in
        ("secret_store", "SecretStore", "keychain", "Keychain", "security_framework", "fs_lock", "flock", "fcntl",
         "O_EXLOCK", "keyring")], [True] * 10)

    # The check: exit status, message and label.
    msg = osd.verdict(osd.scan(init), labels=[], pr=4839)
    row("unlabelled hit fails", msg is not None, True)
    text = msg or ""
    row("the message names the file and line", "src/cli_support/init.rs:10" in text, True)
    row("the message names the matched line", "secret_store::write_admin" in text, True)
    row("the message gives the exact command", "gh pr edit 4839 --add-label os-int" in text, True)
    row("labelled hit passes", osd.verdict(osd.scan(init), labels=["os-int"], pr=4839), None)
    row("the other label does not satisfy it", osd.verdict(osd.scan(init), labels=["os-sensitive"], pr=7) is not None, True)
    row("no hit passes unlabelled", osd.verdict([], labels=[], pr=7), None)
    many = osd.scan(diff("src/a.rs", *[f"+secret_store::x{i}();" for i in range(30)]))
    row("a long list is cut with a count", "20 more" in (osd.verdict(many, labels=[], pr=7) or ""), True)

    # The command line, against a real repository.
    with tempfile.TemporaryDirectory() as tmp:
        def git(*a: str) -> str:
            return subprocess.run(["git", "-C", tmp, "-c", "user.email=t@t", "-c", "user.name=t", *a],
                                  check=True, capture_output=True, text=True).stdout
        git("init", "-q", "-b", "base")
        (Path(tmp) / "a.rs").write_text("fn a() {}\n")
        git("add", "."); git("commit", "-q", "-m", "base")
        (Path(tmp) / "a.rs").write_text("fn a() { secret_store::open(); }\n")
        git("commit", "-q", "-am", "head")
        run = lambda labels: subprocess.run(  # noqa: E731
            [sys.executable, str(Path(osd.__file__)), "--repo", tmp, "--base", "HEAD~1", "--head", "HEAD",
             "--pr", "12", "--labels", labels], capture_output=True, text=True)
        r = run("[]")
        row("the command exits 1 on an unlabelled hit", r.returncode, 1)
        row("and prints the add-label command", "gh pr edit 12 --add-label os-int" in r.stdout + r.stderr, True)
        row("the command exits 0 when labelled", run('["os-int"]').returncode, 0)

    for e in errors:
        print(f"os-sensitive-diff: {e}")
    if not errors:
        print("os-sensitive-diff: content triggers (secret store, keychain, file locks) in Rust and TOML only; "
              "docs, names and cfg lines do not; the failure names the lines and the label command")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
