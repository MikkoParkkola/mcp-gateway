#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for scripts/dev/merge_ui_line.py, each on a small throwaway git repo.

    python3 -I scripts/dev/test_merge_ui_line.py

Every row builds a fixture repo holding a tiny UI shell and the real rehash script, makes a branch and a line
commit from the same base, and runs the merge script through its command line. A refusal must leave the caller's
repo byte for byte as it was; a success must leave no throwaway worktree or branch behind.

Output the rows rely on: a refusal prints `merge_ui_line: refused R<n>: <reason>: <names>` on stderr and exits 1;
for each key the branch changed, stdout holds a `== <key> before` block and a `== <key> after` block, each the
removed (-) and added (+) lines of one diff. The list rule is checked before the full-text rule.
"""

import base64
import difflib
import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "merge_ui_line.py"
REHASH = HERE / "rehash_ui_assets.py"
REAL_GIT = shutil.which("git")
UI = "src/gateway/ui"
SHELL = f"{UI}/shell"

# One naming rule for hashed assets: the rehash script's own pattern, loaded rather than restated (no bytecode
# written beside it).
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("rehash_ui_assets", REHASH)
rehash_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rehash_module)
NAMED = rehash_module.HASHED

FILES = {
    f"{SHELL}/shell.js": """\
        export function s1() {
          return "s1";
        }
        export function s2() {
          return "s2";
        }
        export function s3() {
          return "s3";
        }
        """,
    f"{SHELL}/a.js": """\
        import { s1 } from "/ui/assets/shell.js";
        export function one() {
          return 1; // twin
        }
        export function two() {
          return 2;
        }
        export function three() {
          return 1; // twin
        }
        export function four() {
          return 4;
        }
        """,
    f"{SHELL}/b.js": """\
        import { s2 } from "/ui/assets/shell.js";
        export function bee() {
          return "bee";
        }
        export function bop() {
          return "bop";
        }
        """,
    f"{SHELL}/app.css": """\
        .a1 { color: black; }
        .a2 { color: gray; }
        .a3 { color: white; }
        """,
    f"{SHELL}/nested/c.js": """\
        export const c1 = 1;
        export const cm = 0;
        export const c2 = 2;
        """,
    f"{SHELL}/data.json": """\
        {
          "first": "one",
          "ref": "/ui/assets/shell.0123456789ab.js",
          "last": "two"
        }
        """,
    f"{SHELL}/logo.svg": """\
        <svg xmlns="http://www.w3.org/2000/svg">
          <title>first</title>
          <desc>/ui/assets/shell.0123456789ab.js</desc>
          <g id="last"/>
        </svg>
        """,
    f"{SHELL}/index.html": """\
        <!doctype html>
        <html>
        <head>
        <link rel="stylesheet" href="/ui/assets/app.css">
        <style id="frame"></style>
        </head>
        <body>
        <script type="module" src="/ui/assets/a.js"></script>
        <script type="module" src="/ui/assets/b.js"></script>
        <p>shell</p>
        </body>
        </html>
        """,
    f"{UI}/shell-src/frame.css": """\
        body { background: url(/ui/assets/icon.png); }
        .f1 { color: red; }
        .f2 { color: blue; }
        """,
    f"{UI}/csp-base.txt": "default-src 'self'; style-src {frame}\n",
    f"{UI}/shell.rs": """\
        // fixture shell
        pub(super) const ASSETS: &[(&str, &[u8])] = &[];
        """,
    "README.txt": "readme one\nreadme two\nreadme three\n",
    "NOTES.txt": "notes one\nnotes two\nnotes three\n",
}
BINARIES = {f"{SHELL}/icon.png": b"\x89PNG0000", f"{SHELL}/font.woff2": b"wOF20000"}
TWIN = "  return 1; // twin"
TWIN_EDIT = "  return 9; // EDITED-TWIN"
B_SCRIPT = '<script type="module" src="/ui/assets/b.'


class Fixture:
    """One throwaway repo: base commit on main, plus helpers for branch and line commits."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.root = tmp / "repo"
        self.bin = tmp / "bin"
        self.log = tmp / "git-calls.log"
        self.skip_rehash_once = False
        self.root.mkdir()
        self.bin.mkdir()
        wrapper = self.bin / "git"
        wrapper.write_text(f'#!/bin/sh\necho "$*" >> "{self.log}"\nexec "{REAL_GIT}" "$@"\n')
        wrapper.chmod(0o755)
        self.env = {
            "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "HOME": str(tmp),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "LANG": "C.UTF-8",
        }
        self.git("init", "-q", "-b", "main")
        for key, value in (("user.name", "fixture"), ("user.email", "fixture@example.invalid"),
                           ("commit.gpgsign", "false"),
                           # Absolute: a relative hooks path resolves from where a hook runs, and in a linked
                           # worktree .git is a file, so the hook would silently never fire.
                           ("core.hooksPath", str(self.root / ".git/test-hooks"))):
            self.git("config", key, value)
        (self.root / ".git/test-hooks").mkdir()
        dev = self.root / "scripts/dev"
        dev.mkdir(parents=True)
        shutil.copy(REHASH, dev / REHASH.name)
        if SCRIPT.exists():
            shutil.copy(SCRIPT, dev / SCRIPT.name)
        for rel, body in FILES.items():
            self.write(rel, textwrap.dedent(body))
        for rel, data in BINARIES.items():
            (self.root / rel).write_bytes(data)
        self.commit("base")
        self.base = self.head()

    # ---- git and files ----

    def git(self, *args, check=True) -> str:
        proc = subprocess.run([REAL_GIT, *args], cwd=self.root, env=self.env, capture_output=True, text=True)
        if check and proc.returncode != 0:
            raise AssertionError(f"git {' '.join(args)} failed: {proc.stderr}")
        return proc.stdout.strip()

    def head(self) -> str:
        return self.git("rev-parse", "HEAD")

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def find(self, rel: str) -> Path:
        """The current file for an unhashed shell path (under its hashed name), or a plain path."""
        plain = self.root / rel
        m = NAMED.match(plain.name)
        if not rel.startswith(SHELL + "/") or not m:
            return plain
        for path in plain.parent.glob(f"{m['stem']}*.{m['ext']}"):
            got = NAMED.match(path.name)
            if got and got["stem"] == m["stem"]:
                return path
        return plain

    def text(self, rel: str) -> str:
        return self.find(rel).read_text()

    def edit(self, rel: str, old: str, new: str, last: bool = False) -> None:
        path = self.find(rel)
        body = path.read_text()
        assert old in body, f"{old!r} not in {rel}"
        if last:
            i = body.rindex(old)
            body = body[:i] + new + body[i + len(old):]
        else:
            body = body.replace(old, new, 1)
        path.write_text(body)

    def drop(self, rel: str) -> None:
        self.find(rel).unlink()

    def rehash(self) -> None:
        proc = subprocess.run([sys.executable, "-I", "scripts/dev/rehash_ui_assets.py"], cwd=self.root,
                              env=self.env, capture_output=True, text=True)
        if proc.returncode != 0:
            raise AssertionError("fixture rehash failed: " + proc.stderr)

    def commit(self, message: str, rehash: bool = True) -> str:
        if rehash:
            self.rehash()
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.head()

    def side(self, name: str, start: str, change) -> str:
        """A commit on branch `name` from `start`: `change(self)` edits files, then rehash (unless the change
        asked to skip it once) and commit."""
        self.git("checkout", "-q", "-B", name, start)
        change(self)
        skip, self.skip_rehash_once = self.skip_rehash_once, False
        return self.commit(name, rehash=not skip)

    def setup(self, branch_change, line_change) -> tuple[str, str]:
        """The line commit, then the UI branch checked out; returns (branch tip, line tip)."""
        line = self.side("line", self.base, line_change)
        tip = self.side("ui", self.base, branch_change)
        return tip, line

    def run(self, *args, script=None):
        cmd = [sys.executable, "-I", str(script or self.root / "scripts/dev/merge_ui_line.py"), *args]
        if self.log.exists():
            self.log.unlink()
        return subprocess.run(cmd, cwd=self.root, env=self.env, capture_output=True, text=True)

    # ---- the state a refusal must leave untouched ----

    def snapshot(self) -> dict:
        files = {}
        for path in sorted(self.root.rglob("*")):
            if ".git" in path.relative_to(self.root).parts or not path.is_file():
                continue
            files[path.relative_to(self.root).as_posix()] = path.read_bytes()
        merge_head = self.root / ".git/MERGE_HEAD"
        return {
            "files": files,
            "status": self.git("status", "--porcelain"),
            "head": self.head(),
            "attached": self.git("symbolic-ref", "-q", "HEAD", check=False),
            "merge_head": merge_head.read_text() if merge_head.exists() else None,
            "worktrees": self.git("worktree", "list", "--porcelain"),
            "branches": self.git("branch", "--list"),
            "index": self.git("ls-files", "--stage"),
        }

    def clean_after_success(self, test: unittest.TestCase) -> None:
        test.assertEqual(self.git("status", "--porcelain"), "")
        test.assertEqual(len(self.git("worktree", "list").splitlines()), 1)
        test.assertNotIn("merge-ui-line", self.git("branch", "--list"))
        test.assertFalse((self.root / ".git/MERGE_HEAD").exists())

    def calls(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    def swap_rehash(self, tail: str) -> None:
        """Rewrite the committed rehash script's last line as `tail`, and skip the fixture's own rehash for this
        commit (the swapped script is for the merge, not for this side)."""
        path = self.root / "scripts/dev/rehash_ui_assets.py"
        body = path.read_text().rstrip()
        assert body.endswith("sys.exit(main())")
        path.write_text(body[: -len("sys.exit(main())")] + tail + "\n")
        self.skip_rehash_once = True


def norm(text: str) -> str:
    """References with their 12-hex hash dropped (the test's own oracle, written independently of the script)."""
    return re.sub(r"(/ui/assets/[^\s\"'()]+?)\.[0-9a-f]{12}(\.[a-z0-9]+)(?![\w.-])", r"\1\2", text)


def changed_lines(old: str, new: str) -> list[str]:
    out = []
    for line in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0):
        if not line.startswith(("---", "+++", "@@")):
            out.append(line)
    return out


def printed_lists(stdout: str, key: str) -> tuple[list[str], list[str]]:
    blocks: dict[tuple[str, str], list[str]] = {}
    current = None
    for line in stdout.splitlines():
        m = re.match(r"^== (.+) (before|after)$", line)
        if m:
            current = (m[1], m[2])
            blocks[current] = []
        elif current and line[:1] in "+-":
            blocks[current].append(line)
        else:
            current = None
    return blocks.get((key, "before"), []), blocks.get((key, "after"), [])


def blob(fx: Fixture, rev: str, rel: str) -> str:
    """The text of an unhashed shell path at `rev`."""
    folder, name = rel.rsplit("/", 1)
    m = NAMED.match(name)
    for entry in fx.git("ls-tree", "--name-only", f"{rev}:{folder}").splitlines():
        got = NAMED.match(entry)
        if got and got["stem"] == m["stem"] and got["ext"] == m["ext"]:
            return fx.git("show", f"{rev}:{folder}/{entry}")
    raise AssertionError(f"{rel} not at {rev}")


def drop_b(fx: Fixture) -> None:
    fx.drop(f"{SHELL}/b.js")
    fx.edit(f"{SHELL}/index.html", B_SCRIPT, "<!-- b gone ")


def edit_b(fx: Fixture) -> None:
    fx.edit(f"{SHELL}/b.js", '"bop"', '"BOP"')


def edit_a(fx: Fixture) -> None:
    fx.edit(f"{SHELL}/a.js", "return 4;", "return 44;")


class Rows(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.fx = Fixture(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    # ---- the two kinds of row ----

    def succeed(self, tip: str, line: str):
        proc = self.fx.run("line")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.fx.clean_after_success(self)
        parents = self.fx.git("rev-list", "--parents", "-n", "1", "HEAD").split()[1:]
        self.assertEqual(parents, [tip, line])
        return proc

    def refuse(self, code: str, *names: str, reason: str | None = None, script: Path | None = None):
        before = self.fx.snapshot()
        proc = self.fx.run("line", script=script)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn(f"refused {code}", proc.stderr)
        for name in names:
            self.assertIn(name, proc.stderr)
        if reason:
            self.assertIn(reason, proc.stderr)
        self.assertEqual(self.fx.snapshot(), before)
        return proc

    def expected_tree(self, start: str, *changes) -> str:
        """`start` plus each change, rehashed: the tree a merge must produce."""
        self.fx.git("checkout", "-q", "-B", "expected", start)
        for change in changes:
            change(self.fx)
        self.fx.commit("expected")
        tree = self.fx.git("rev-parse", "HEAD^{tree}")
        self.fx.git("checkout", "-q", "ui")
        self.fx.git("branch", "-q", "-D", "expected")
        return tree

    def shim(self, body: str) -> Path:
        """A stand-in entry point outside the repo: loads the real script, wraps its merge_text, runs main()."""
        target = self.fx.root / "scripts/dev/merge_ui_line.py"
        lines = [
            "import importlib.util, sys",
            "sys.dont_write_bytecode = True",
            f"spec =importlib.util.spec_from_file_location('merge_ui_line', {str(target)!r})",
            "m = importlib.util.module_from_spec(spec)",
            "spec.loader.exec_module(m)",
            "original = m.merge_text",
            "state = {'done': False}",
            "def wrapped(base, ours, theirs):",
            "    text = original(base, ours, theirs)",
            *("    " + line for line in textwrap.dedent(body).splitlines()),
            "    return text",
            "m.merge_text = wrapped",
            "sys.exit(m.main(sys.argv))",
        ]
        path = self.fx.tmp / "shim.py"
        path.write_text("\n".join(lines) + "\n")
        return path

    # ---- success rows ----

    def test_t1_two_modules_sharing_the_shell(self):
        def branch(fx):
            fx.edit(f"{SHELL}/a.js", "  return 2;\n", "  const x = 2;\n  return x;\n")

        tip, line = self.fx.setup(branch, edit_b)
        want_tree = self.expected_tree(line, branch)
        proc = self.succeed(tip, line)
        self.assertEqual(self.fx.git("rev-parse", "HEAD^{tree}"), want_tree)
        before, after = printed_lists(proc.stdout, "a.js")
        want = changed_lines(norm(blob(self.fx, self.fx.base, f"{SHELL}/a.js")),
                             norm(blob(self.fx, tip, f"{SHELL}/a.js")))
        self.assertTrue(want)
        self.assertEqual(before, want)
        self.assertEqual(after, want)
        self.assertIn("-  return 2;", before)
        self.assertIn("+  const x = 2;", before)

    def test_t1b_both_edit_the_shared_shell(self):
        tip, line = self.fx.setup(lambda fx: fx.edit(f"{SHELL}/shell.js", '"s1"', '"S1"'),
                                  lambda fx: fx.edit(f"{SHELL}/shell.js", '"s3"', '"S3"'))
        self.succeed(tip, line)
        body = self.fx.text(f"{SHELL}/shell.js")
        self.assertIn('"S1"', body)
        self.assertIn('"S3"', body)
        self.fx.rehash()
        self.assertEqual(self.fx.git("status", "--porcelain"), "")

    def test_t5b_a_hash_only_change_is_no_change(self):
        tip, line = self.fx.setup(drop_b, lambda fx: fx.edit(f"{SHELL}/shell.js", '"s2"', '"S2"'))
        self.succeed(tip, line)
        self.assertFalse(list((self.fx.root / SHELL).glob("b.*")))
        self.assertIn('"S2"', self.fx.text(f"{SHELL}/shell.js"))

    def test_t6_a_frame_edit_reaches_the_frame_and_the_golden(self):
        # The line edits csp-base.txt, so both sides rewrite csp.golden's one line: plain git conflicts there.
        tip, line = self.fx.setup(lambda fx: fx.edit(f"{UI}/shell-src/frame.css", "blue", "green"),
                                  lambda fx: fx.edit(f"{UI}/csp-base.txt", "default-src 'self';",
                                                     "default-src 'none';"))
        self.succeed(tip, line)
        frame = (self.fx.root / f"{UI}/shell-src/frame.css").read_text()
        self.assertIn("green", frame)
        self.assertIn("default-src 'none';", (self.fx.root / f"{UI}/csp-base.txt").read_text())
        self.assertIn(f'<style id="frame">{frame}</style>', self.fx.text(f"{SHELL}/index.html"))
        digest = base64.b64encode(hashlib.sha256(frame.encode()).digest()).decode()
        policy = (self.fx.root / f"{UI}/csp-base.txt").read_text().strip()
        self.assertEqual((self.fx.root / f"{UI}/csp.golden").read_text(),
                         policy.replace("{frame}", f"'sha256-{digest}'") + "\n")

    def test_t8c_a_nested_asset_keeps_its_folder(self):
        # Both sides edit nested/c.js (one line apart), so each renames it to a different hash: plain git sees a
        # rename/rename conflict, and the script must merge it in place under nested/.
        tip, line = self.fx.setup(lambda fx: fx.edit(f"{SHELL}/nested/c.js", "c2 = 2", "c2 = 22"),
                                  lambda fx: fx.edit(f"{SHELL}/nested/c.js", "c1 = 1", "c1 = 11"))
        self.succeed(tip, line)
        self.assertIn("c1 = 11", self.fx.text(f"{SHELL}/nested/c.js"))
        found = list((self.fx.root / SHELL / "nested").glob("c.*.js"))
        self.assertEqual(len(found), 1)
        data = found[0].read_bytes()
        self.assertEqual(found[0].name, f"c.{hashlib.sha256(data).hexdigest()[:12]}.js")
        self.assertIn(b"c2 = 22", data)
        self.assertIn(f'include_bytes!("shell/nested/{found[0].name}")',
                      (self.fx.root / f"{UI}/shell.rs").read_text())

    def test_t10_the_lines_source_edit_is_kept(self):
        tip, line = self.fx.setup(edit_a, lambda fx: fx.edit(f"{UI}/csp-base.txt", "default-src 'self';",
                                                             "default-src 'none';"))
        self.succeed(tip, line)
        self.assertEqual((self.fx.root / f"{UI}/csp-base.txt").read_text(),
                         self.fx.git("show", f"{line}:{UI}/csp-base.txt") + "\n")
        self.assertIn("default-src 'none';", (self.fx.root / f"{UI}/csp.golden").read_text())

    def test_t13_a_merge_with_no_conflict_is_plain_git(self):
        tip, line = self.fx.setup(lambda fx: fx.edit("README.txt", "readme two", "README TWO"), edit_b)
        self.fx.git("checkout", "-q", "-B", "expected", tip)
        self.fx.git("merge", "-q", "--no-edit", line)
        self.fx.commit("expected")
        want = self.fx.git("rev-parse", "HEAD^{tree}")
        self.fx.git("checkout", "-q", "ui")
        self.fx.git("branch", "-q", "-D", "expected")
        self.succeed(tip, line)
        self.assertEqual(self.fx.git("rev-parse", "HEAD^{tree}"), want)

    def test_t14_one_sided_binary_changes(self):
        tip, line = self.fx.setup(lambda fx: fx.find(f"{SHELL}/icon.png").write_bytes(b"\x89PNG1111"),
                                  lambda fx: fx.find(f"{SHELL}/font.woff2").write_bytes(b"wOF22222"))
        self.succeed(tip, line)
        self.assertEqual(self.fx.find(f"{SHELL}/icon.png").read_bytes(), b"\x89PNG1111")
        self.assertEqual(self.fx.find(f"{SHELL}/font.woff2").read_bytes(), b"wOF22222")

    def test_t14b_identical_binary_changes(self):
        def png(fx):
            fx.find(f"{SHELL}/icon.png").write_bytes(b"\x89PNG3333")

        tip, line = self.fx.setup(png, lambda fx: (png(fx), edit_b(fx)))
        self.succeed(tip, line)
        self.assertEqual(self.fx.find(f"{SHELL}/icon.png").read_bytes(), b"\x89PNG3333")

    def test_t15_json_and_svg_merge_as_raw_text(self):
        def branch(fx):
            fx.edit(f"{SHELL}/data.json", '"one"', '"ONE"')
            fx.edit(f"{SHELL}/logo.svg", "<title>first", "<title>FIRST")

        def line(fx):
            fx.edit(f"{SHELL}/data.json", '"two"', '"TWO"')
            fx.edit(f"{SHELL}/logo.svg", 'id="last"', 'id="LAST"')

        tip, tip_line = self.fx.setup(branch, line)
        self.succeed(tip, tip_line)
        for rel, words in ((f"{SHELL}/data.json", ('"ONE"', '"TWO"')), (f"{SHELL}/logo.svg", ("FIRST", "LAST"))):
            body = self.fx.text(rel)
            for word in words:
                self.assertIn(word, body)
            self.assertIn("/ui/assets/shell.0123456789ab.js", body)

    def test_t16_one_sided_additions(self):
        tip, line = self.fx.setup(lambda fx: fx.write(f"{SHELL}/nested/e.js", "export const e = 1;\n"),
                                  lambda fx: fx.write(f"{SHELL}/f.js", "export const f = 1;\n"))
        self.succeed(tip, line)
        self.assertEqual(self.fx.text(f"{SHELL}/nested/e.js"), "export const e = 1;\n")
        self.assertEqual(self.fx.text(f"{SHELL}/f.js"), "export const f = 1;\n")

    def test_t16b_deleted_on_both_sides(self):
        def gone(fx):
            fx.drop(f"{SHELL}/nested/c.js")

        tip, line = self.fx.setup(gone, lambda fx: (gone(fx), edit_b(fx)))
        self.succeed(tip, line)
        self.assertFalse(list((self.fx.root / SHELL / "nested").glob("c.*")))

    # ---- refusal rows ----

    def test_t2_overlapping_edits_to_one_asset(self):
        self.fx.setup(lambda fx: fx.edit(f"{SHELL}/a.js", "return 4;", "return 40;"),
                      lambda fx: fx.edit(f"{SHELL}/a.js", "return 4;", "return 41;"))
        self.refuse("R3", "a.js")

    def test_t3_conflicts_outside_the_generated_files(self):
        self.fx.setup(lambda fx: (fx.edit("README.txt", "readme two", "branch two"),
                                  fx.edit("NOTES.txt", "notes two", "branch notes")),
                      lambda fx: (fx.edit("README.txt", "readme two", "line two"),
                                  fx.edit("NOTES.txt", "notes two", "line notes")))
        self.refuse("R2", "README.txt", "NOTES.txt")

    def test_t4_a_dirty_tree(self):
        self.fx.setup(edit_a, edit_b)
        self.fx.edit("README.txt", "readme one", "uncommitted")
        self.refuse("R1")
        self.assertNotIn("worktree add", self.fx.calls())

    def test_t4b_a_detached_head(self):
        tip, _ = self.fx.setup(edit_a, edit_b)
        self.fx.git("checkout", "-q", "--detach", tip)
        self.refuse("R1")
        self.assertNotIn("worktree add", self.fx.calls())

    def test_t4c_a_merge_in_progress(self):
        self.fx.side("other", self.fx.base, lambda fx: fx.edit("README.txt", "readme one", "other one"))
        self.fx.setup(lambda fx: fx.edit("README.txt", "readme one", "ui one"), edit_b)
        self.fx.git("merge", "-q", "other", check=False)
        self.assertTrue((self.fx.root / ".git/MERGE_HEAD").exists())
        self.refuse("R1")
        self.assertNotIn("worktree add", self.fx.calls())

    def test_t5_branch_deletes_what_the_line_edited(self):
        self.fx.setup(drop_b, edit_b)
        self.refuse("R5", "b.js")

    def test_t5c_line_deletes_what_the_branch_edited(self):
        self.fx.setup(edit_b, drop_b)
        self.refuse("R5", "b.js")

    def test_t6b_a_failing_rehash(self):
        def line(fx):
            edit_b(fx)
            fx.rehash()
            fx.swap_rehash("main()\nprint('SENTINEL-R6', file=sys.stderr)\nsys.exit(1)")

        self.fx.setup(edit_a, line)
        self.refuse("R6", "SENTINEL-R6")

    def test_t7_an_edit_moved_to_the_other_twin(self):
        self.fx.setup(lambda fx: fx.edit(f"{SHELL}/a.js", TWIN, TWIN_EDIT, last=True), edit_b)
        shim = self.shim(f"""\
            if not state['done'] and 'EDITED-TWIN' in ours:
                state['done'] = True
                text = text.replace({TWIN_EDIT!r}, {TWIN!r}).replace({TWIN!r}, {TWIN_EDIT!r}, 1)
            """)
        self.refuse("R7", "a.js", reason="full-text", script=shim)

    def test_t7b_a_dropped_added_line(self):
        self.fx.setup(lambda fx: fx.edit(f"{SHELL}/a.js", "  return 2;\n", "  const x = 2;\n  return x;\n"),
                      edit_b)
        shim = self.shim("""\
            if not state['done'] and 'const x = 2;' in ours:
                state['done'] = True
                text = text.replace('  const x = 2;\\n', '', 1)
            """)
        self.refuse("R7", "a.js", reason="list", script=shim)

    def test_t7c_a_conflict_marker_left_in_a_text(self):
        self.fx.setup(edit_a, edit_b)
        shim = self.shim("""\
            if not state['done'] and '.a2 {' in text:
                state['done'] = True
                text = text.replace('.a2 {', '<<<<<<< ours\\n.a2 {', 1)
            """)
        self.refuse("R7", "app.css", reason="conflict marker", script=shim)

    def test_t7d_a_reference_to_no_file(self):
        self.fx.setup(edit_a, edit_b)
        shim = self.shim("""\
            if not state['done'] and '<p>shell</p>' in text:
                state['done'] = True
                text = text.replace('<p>shell</p>', '<p>shell</p>\\n<script src="/ui/assets/missing.js"></script>', 1)
            """)
        self.refuse("R7", "missing.js", reason="missing asset", script=shim)

    def test_t8_the_same_new_asset_on_both_sides(self):
        def add(fx):
            fx.write(f"{SHELL}/new.js", "export const n = 1;\n")

        self.fx.setup(add, add)
        self.refuse("R7", "new.js", reason="the line already has this edit")

    def test_t8a_different_new_assets_with_one_name(self):
        self.fx.setup(lambda fx: fx.write(f"{SHELL}/new.js", "export const n = 1;\n"),
                      lambda fx: fx.write(f"{SHELL}/new.js", "export const n = 2;\n"))
        self.refuse("R3", "new.js")

    def test_t8b_a_png_changed_differently(self):
        self.fx.setup(lambda fx: fx.find(f"{SHELL}/icon.png").write_bytes(b"\x89PNG4444"),
                      lambda fx: fx.find(f"{SHELL}/icon.png").write_bytes(b"\x89PNG5555"))
        self.refuse("R4", "icon.png")

    def test_t8d_the_same_edit_on_both_sides(self):
        def same(fx):
            fx.edit(f"{SHELL}/b.js", '"bee"', '"BEE"')

        self.fx.setup(same, same)
        self.refuse("R7", "b.js", reason="the line already has this edit")

    def test_t8e_a_font_changed_differently(self):
        self.fx.setup(lambda fx: fx.find(f"{SHELL}/font.woff2").write_bytes(b"wOF24444"),
                      lambda fx: fx.find(f"{SHELL}/font.woff2").write_bytes(b"wOF25555"))
        self.refuse("R4", "font.woff2")

    def test_t9_rehash_writing_outside_the_generated_files(self):
        def line(fx):
            edit_b(fx)
            fx.rehash()
            fx.swap_rehash("rc = main()\n(ROOT / 'NOTES.txt').write_text('rehash wrote\\n')\nsys.exit(rc)")

        self.fx.setup(edit_a, line)
        self.refuse("R7", "NOTES.txt", reason="rehash wrote outside G")

    def test_t10b_rehash_writing_a_file_the_line_also_changed(self):
        def line(fx):
            fx.edit(f"{UI}/csp-base.txt", "default-src 'self';", "default-src 'none';")
            fx.rehash()
            fx.swap_rehash("rc = main()\nwith open(ROOT / 'src/gateway/ui/csp-base.txt', 'a') as f:\n"
                           "    f.write('extra\\n')\nsys.exit(rc)")

        self.fx.setup(edit_a, line)
        self.refuse("R7", "csp-base.txt", reason="rehash wrote outside G")

    def test_t11_a_refused_commit(self):
        self.fx.setup(edit_a, edit_b)
        hook = self.fx.root / ".git/test-hooks/pre-commit"
        hook.write_text("#!/bin/sh\nexit 1\n")
        hook.chmod(0o755)
        probe = subprocess.run([REAL_GIT, "commit", "-q", "--allow-empty", "-m", "probe"], cwd=self.fx.root,
                               env=self.fx.env, capture_output=True, text=True)
        self.assertNotEqual(probe.returncode, 0, "the fixture hook must refuse a plain commit")
        self.refuse("R7", reason="commit failed")

    def test_t12_one_stem_in_two_folders(self):
        self.fx.setup(lambda fx: fx.write(f"{SHELL}/nested/a.js", "export const na = 1;\n"), edit_b)
        self.refuse("R8", "nested/a", "a.js")

    def test_t12b_one_stem_in_two_folders_from_both_sides(self):
        self.fx.setup(lambda fx: fx.write(f"{SHELL}/nested/d.js", "export const nd = 1;\n"),
                      lambda fx: fx.write(f"{SHELL}/d.js", "export const d = 1;\n"))
        self.refuse("R8", "nested/d", "d.js")


if __name__ == "__main__":
    unittest.main()
