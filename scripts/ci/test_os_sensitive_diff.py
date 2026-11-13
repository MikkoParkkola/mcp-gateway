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

    # Review findings (two seats, 2026-11-12): the parser, the lock APIs, the crate names.
    deleted = ("diff --git a/src/x.rs b/src/x.rs\ndeleted file mode 100644\n--- a/src/x.rs\n+++ /dev/null\n"
               "@@ -1,2 +0,0 @@\n-fn a() {}\n-    secret_store::drop_all();\n")
    row("a removed line of a deleted file triggers, numbered in the old file",
        [(p, n) for p, n, _ in osd.scan(deleted)], [("src/x.rs", 2)])
    for shown in ('+++ "b/src/m\\303\\251.rs"', "+++ b/src/my file.rs\t"):
        quoted = ("diff --git a/x b/x\n--- a/x\n" + shown + "\n@@ -1,0 +1,1 @@\n+    keychain::get();\n")
        row(f"a quoted or spaced path is read ({shown.strip()!r})", len(osd.scan(quoted)), 1)
    tricky = ("diff --git a/src/y.rs b/src/y.rs\n--- a/src/y.rs\n+++ b/src/y.rs\n@@ -5,1 +5,3 @@\n"
              "-- flock note\n+++ added line that starts with plus plus\n+    flock(fd);\n+    after();\n")
    row("a body line starting with '++ ' or '-- ' is content, not a header; numbers stay right",
        [(p, n) for p, n, _ in osd.scan(tricky)], [("src/y.rs", 5), ("src/y.rs", 6)])
    row("hyphenated crate names in Cargo.toml trigger",
        [bool(osd.scan(diff("Cargo.toml", f'+{w} = "1"'))) for w in ("security-framework", "fd-lock", "secret-store", "fs2")],
        [True] * 4)
    row("std file locks trigger by their names",
        [bool(osd.scan(diff("src/a.rs", f"+    {c}"))) for c in ("f.lock_shared()?;", "f.try_lock_exclusive()?;", "File::lock(&f)?;",
                                                                   "use std::os::unix::fs::FileExt;")],
        [True] * 4)
    row("a bare Mutex lock does not trigger", osd.scan(diff("src/a.rs", "+    let g = state.lock();")), [])

    # Round 2 (kimi, muse): case, unlock, renames.
    row("constants and type names count in any case",
        [bool(osd.scan(diff("src/a.rs", f"+{c}"))) for c in ('const KEYCHAIN_SERVICE: &str = "x";', "struct FileLock;", "use crate::KeyRing;")],
        [True] * 3)
    row("an unlock-only change triggers", len(osd.scan(diff("src/a.rs", "+    File::unlock(&f)?;"))), 1)
    renamed = ("diff --git a/src/a.rs b/docs/b.md\nsimilarity index 50%\nrename from src/a.rs\nrename to docs/b.md\n"
               "--- a/src/a.rs\n+++ b/docs/b.md\n@@ -3,1 +3,1 @@\n-    flock(fd);\n+prose\n")
    row("a removed line of a renamed file is read by its old path", [(p, n) for p, n, _ in osd.scan(renamed)], [("src/a.rs", 3)])

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

    # The command line, against real repositories shaped like GitHub's pull request merge ref: the base moves on, the
    # pull request's commits are merged into it with --no-ff, HEAD is that merge and HEAD^1 the base it was cut from.
    def make_pr(pr_files: dict[str, bytes], base_moves: dict[str, bytes] | None = None) -> tuple[str, str]:
        """(repo dir, the pull request's head sha) with HEAD checked out at the merge commit."""
        tmp = tempfile.mkdtemp()
        def git(*a: str) -> str:
            return subprocess.run(["git", "-C", tmp, "-c", "user.email=t@t", "-c", "user.name=t", *a],
                                  check=True, capture_output=True, text=True).stdout.strip()
        git("init", "-q", "-b", "base")
        (Path(tmp) / "a.rs").write_text("fn a() {}\n"); git("add", "."); git("commit", "-q", "-m", "base")
        git("checkout", "-q", "-b", "pr")
        for name, data in pr_files.items():
            (Path(tmp) / name).write_bytes(data)
        git("add", "."); git("commit", "-q", "-m", "pr")
        head = git("rev-parse", "HEAD")
        git("checkout", "-q", "base")
        for name, data in (base_moves or {"moved.txt": b"x\n"}).items():
            (Path(tmp) / name).write_bytes(data)
        git("add", "."); git("commit", "-q", "-m", "base moves")
        git("merge", "-q", "--no-ff", "-m", "merge", "pr")
        return tmp, head

    def run_cli(repo: str, second: str, labels: str = "[]", base: str = "HEAD^1", head: str = "HEAD"):
        return subprocess.run([sys.executable, str(Path(osd.__file__)), "--repo", repo, "--base", base, "--head", head,
                               "--pr", "12", "--labels", labels, "--expect-second-parent", second],
                              capture_output=True, text=True)

    repo, pr_head = make_pr({"b.rs": b"fn b() { secret_store::open(); }\n"})
    r = run_cli(repo, pr_head)
    row("the command exits 1 on an unlabelled hit", r.returncode, 1)
    row("and prints the add-label command", "gh pr edit 12 --add-label os-int" in r.stdout + r.stderr, True)
    row("the command exits 0 when labelled", run_cli(repo, pr_head, '["os-int"]').returncode, 0)

    # The base moves on with an OS-sensitive line of its own: only what the pull request brought counts.
    repo, pr_head = make_pr({"b.rs": b"fn b() { keychain::open(); }\n"}, {"c.rs": b"fn c() { flock(1); }\n"})
    moved = run_cli(repo, pr_head)
    row("against the first parent only the pull request's own hit counts", ("b.rs" in moved.stdout, "c.rs" in moved.stdout),
        (True, False))

    # A checkout that is not the pull request's merge commit fails loudly (exit 2), never diffs part of the pull request.
    row("a single-parent head is refused", run_cli(repo, pr_head, base="HEAD~1", head="HEAD^1").returncode, 2)
    row("a merge whose second parent is not the PR head is refused", run_cli(repo, "0" * 40).returncode, 2)
    row("an empty expected head is refused", run_cli(repo, "").returncode, 2)
    row("a short expected head is refused", run_cli(repo, pr_head[:12]).returncode, 2)
    row("a base that is not the first parent is refused", run_cli(repo, pr_head, base="HEAD").returncode, 2)
    row("without --expect-second-parent the command does not run",
        subprocess.run([sys.executable, str(Path(osd.__file__)), "--repo", repo, "--base", "HEAD^1", "--head", "HEAD", "--pr", "12"],
                       capture_output=True, text=True).returncode, 2)

    # Odd bytes in a source file, and a source file git takes for binary, still give a verdict.
    repo, pr_head = make_pr({"d.rs": b"fn d() { /* caf\xe9 */ secret_store::x(); }\n", "e.toml": b"keychain\x00 = 1\n"})
    odd = run_cli(repo, pr_head)
    row("non-UTF-8 and binary-looking sources still give a verdict (exit 1, both files named)",
        (odd.returncode, "d.rs" in odd.stdout, "e.toml" in odd.stdout), (1, True, True))
    # The receiver form of a file unlock counts too.
    row("a receiver-form unlock triggers", len(osd.scan(diff("src/a.rs", "+    guard.unlock()?;"))), 1)

    for e in errors:
        print(f"os-sensitive-diff: {e}")
    if not errors:
        print("os-sensitive-diff: content triggers (secret store, keychain, file locks) in Rust and TOML only; "
              "docs, names and cfg lines do not; the failure names the lines and the label command")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
