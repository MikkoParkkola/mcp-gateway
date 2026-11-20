# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The cargo test selection a throwaway branch names for its `Tests (throwaway)` jobs.

A throwaway branch may carry scripts/ci/throwaway-selection: one cargo argument per line, blank lines and lines
starting with `#` ignored. The jobs then run `cargo test --all-features --no-fail-fast <those arguments> -- <skips>`
instead of the whole suite, which does not fit their 60-minute limit. Use `--test` then a target name to run one
integration binary alone; a bare filter (a test name) still starts every harness, the lib binary and its 21,000
tests included, which is what times out.

  args          print the arguments one per line (nothing when the file is absent); a refused line, or a present
                file that names no argument, exits 2 with the reason on stderr
  check-absent  exit 1 when the file is on this head (it never belongs on the release line)
  --self-test   this script's rows

The file is opened by its path relative to the working directory: the jobs' steps run at the repository root.
Run it as `python3 scripts/ci/throwaway_selection.py`.
"""
import os
import subprocess
import sys
import tempfile

FILE = "scripts/ci/throwaway-selection"
ALLOWED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-:.=/")
LONGEST = 100


def args() -> int:
    """Stub: the real reader lands after these rows have run red."""
    return 0


def check_absent() -> int:
    """Stub: the real check lands after these rows have run red."""
    return 0


def self_test() -> int:
    """Each row runs this script as the jobs do, in a temporary repository root; expected values are literals."""
    me = os.path.abspath(__file__)
    problems: list = []

    def run(mode: str, content: "str | None") -> tuple:
        with tempfile.TemporaryDirectory() as root:
            if content is not None:
                os.makedirs(os.path.join(root, "scripts", "ci"))
                with open(os.path.join(root, FILE), "w", encoding="utf-8") as f:
                    f.write(content)
            p = subprocess.run([sys.executable, me, mode], cwd=root, capture_output=True, text=True)
            return p.returncode, p.stdout, p.stderr

    def row(name: str, got: object, want: object) -> None:
        if got != want:
            problems.append(f"{name}: got {got!r}, want {want!r}")

    # T1 no file: the full run, and nothing printed that could read like a subset run.
    row("T1", run("args", None), (0, "", ""))
    # T2 two arguments around a blank line and a comment line: exactly those, in order, and the one notice.
    row("T2", run("args", "--test\n\n# one integration target\nwriter_refusals\n"),
        (0, "--test\nwriter_refusals\n", "::notice::throwaway selection: --test writer_refusals\n"))
    # T3 one argument per line, `=` allowed, nothing split.
    row("T3", run("args", "a=b\n")[:2], (0, "a=b\n"))
    # T4 each refused character alone in an otherwise valid file; T4c a character outside that sample, and `#`
    # inside an argument (a comment only starts a line).
    for name, bad in [("T4 space", "a b"), ("T4 quote", "a'b"), ("T4 dquote", 'a"b'), ("T4 dollar", "a$b"),
                      ("T4 semicolon", "a;b"), ("T4 backslash", "a\\b"), ("T4 backtick", "a`b"),
                      ("T4 ampersand", "a&b"), ("T4 star", "a*b"), ("T4c pipe", "a|b"), ("T4c hash", "foo#bar")]:
        rc, out, err = run("args", f"--test\n{bad}\n")
        row(name, (rc, out, f"line 2: {bad!r}" in err), (2, "", True))
    # T4b the length bound decides, on allow-list characters only: 100 accepted, 101 refused.
    row("T4b 100", run("args", "x" * 100 + "\n")[:2], (0, "x" * 100 + "\n"))
    rc, out, err = run("args", "x" * 101 + "\n")
    row("T4b 101", (rc, out, "line 1:" in err), (2, "", True))
    # T6 a present file that names no argument would fall to the full run: refused, naming the path.
    rc, out, err = run("args", "\n# nothing selected\n")
    row("T6", (rc, out, FILE in err), (2, "", True))
    # T5 check-absent: both sides.
    row("T5 absent", run("check-absent", None)[0], 0)
    rc, out, err = run("check-absent", "--test\nx\n")
    row("T5 present", (rc, FILE in err), (1, True))
    for line in problems:
        print("SELF-TEST FAIL", line)
    print("throwaway_selection self-test:", "ok" if not problems else f"{len(problems)} rows fail")
    return 1 if problems else 0


def main(argv: list) -> int:
    mode = argv[1] if len(argv) == 2 else ""
    if mode == "args":
        return args()
    if mode == "check-absent":
        return check_absent()
    if mode == "--self-test":
        return self_test()
    print("usage: python3 scripts/ci/throwaway_selection.py args | check-absent | --self-test", file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
