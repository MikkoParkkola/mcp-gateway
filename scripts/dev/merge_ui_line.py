#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Merge the release line into a UI branch, re-deriving the web shell's generated files.

Every shell asset carries a content hash in its name (scripts/dev/rehash_ui_assets.py), so two UI branches that
edit different modules still collide on renamed files, rewritten references, index.html, the ASSETS table in
shell.rs and csp.golden. This script takes the line's version of those generated files, re-applies the branch's
own edit to each one (a three-way merge of the texts with their hashes dropped, keyed by asset name without the
hash), reruns the rehash script and commits the merge.

    python3 -I scripts/dev/merge_ui_line.py LINE_REF

Run it from the repository root, on the UI branch, with a clean tree. It never fetches. All the work happens in a
throwaway worktree; the branch only fast-forwards to the finished merge commit once every check has passed, so a
refusal (exit 1, `merge_ui_line: refused R<n>: ...`) leaves the branch and the tree exactly as they were.

For every text the branch changed it prints the branch's own -/+ lines before the merge and after it. They must be
equal, and the merged text must equal an independent three-way merge. Together they show the branch's reviewed
edits were carried byte for byte, hashes apart.
"""

import difflib
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

UI = "src/gateway/ui"
SHELL = f"{UI}/shell"
INDEX = f"{SHELL}/index.html"
FRAME = f"{UI}/shell-src/frame.css"
SHELL_RS = f"{UI}/shell.rs"
GOLDEN = f"{UI}/csp.golden"
REHASH = "scripts/dev/rehash_ui_assets.py"
TEXTS = (INDEX, FRAME, SHELL_RS)
# rehash rewrites references only inside these: index.html, frame.css, and the shell's stylesheets and scripts.
REWRITTEN_EXTS = ("css", "js")
BINARY_EXTS = ("woff2", "png")
PLACEHOLDER = "pub(super) const ASSETS: &[(&str, &[u8])] = &[];"
MARKER = re.compile(r"^(<<<<<<< |=======$|>>>>>>> )", re.M)
SAME_EDIT = "the line already has this edit"


def _rehash_patterns():
    """The rehash script's own name, table and frame patterns: one definition of each, not a copy. No bytecode is
    written: a __pycache__ folder would make the caller's tree look dirty."""
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("rehash_ui_assets", Path(__file__).resolve().parent / "rehash_ui_assets.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.HASHED, module.TABLE, module.FRAME_STYLE


HASHED, TABLE, FRAME_STYLE = _rehash_patterns()
HASH_IN_REF = re.compile(r"(/ui/assets/[^\s\"'()<>]+?)\.[0-9a-f]{12}(\.[a-z0-9]+)(?![\w.-])")
REF = re.compile(r"/ui/assets/([\w.-]+)")


class Refused(Exception):
    def __init__(self, code: str, reason: str, names=()):
        super().__init__(code)
        self.code, self.reason, self.names = code, reason, list(names)


# ---- git ------------------------------------------------------------------------------------------------------

def git(*args, cwd, check=True, binary=False, stdin=None) -> subprocess.CompletedProcess:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=not binary, input=stdin)
    if check and proc.returncode != 0:
        err = proc.stderr if not binary else proc.stderr.decode(errors="replace")
        raise RuntimeError(f"git {' '.join(args)} failed: {err.strip()}")
    return proc


def out(*args, cwd) -> str:
    return git(*args, cwd=cwd).stdout.strip()


# ---- keys: what a generated file is, independent of its hash --------------------------------------------------

def key_of(path: str):
    """(kind, display) for a generated path, or None. Assets are keyed by their shell-relative name without the
    hash ("a.js", "nested/c.js"); kind is "norm" (references normalised), "raw" (merged as is) or "binary"."""
    if path in TEXTS:
        return path, "norm"
    if not path.startswith(SHELL + "/"):
        return None
    folder, _, name = path[len(SHELL) + 1:].rpartition("/")
    m = HASHED.match(name)
    if not m:
        return None
    key = f"{folder}/{m['stem']}.{m['ext']}" if folder else f"{m['stem']}.{m['ext']}"
    kind = "binary" if m["ext"] in BINARY_EXTS else "norm" if m["ext"] in REWRITTEN_EXTS else "raw"
    return key, kind


def is_generated(path: str) -> bool:
    return path == GOLDEN or key_of(path) is not None


def norm(key: str, kind: str, text: str) -> str:
    """The text with every reference's hash dropped; index.html's frame emptied; shell.rs's table a placeholder.
    rehash puts all three back."""
    if kind != "norm":
        return text
    text = HASH_IN_REF.sub(r"\1\2", text)
    if key == INDEX:
        text = FRAME_STYLE.sub(lambda m: m[1] + m[3], text, count=1)
    if key == SHELL_RS:
        text = TABLE.sub(lambda _: PLACEHOLDER, text, count=1)
    return text


def tree_files(rev: str, root: str) -> dict:
    """{key: (kind, content)} for the generated files at `rev` (content: str, or bytes for binaries)."""
    listing = git("ls-tree", "-r", "-z", rev, "--", UI, cwd=root).stdout
    wanted = {}
    for entry in filter(None, listing.split("\0")):
        meta, path = entry.split("\t", 1)
        found = key_of(path)
        if found:
            wanted[found[0]] = (found[1], meta.split()[2])
    if not wanted:
        return {}
    batch = git("cat-file", "--batch", cwd=root, binary=True,
                stdin="".join(oid + "\n" for _, oid in wanted.values()).encode()).stdout
    files, pos = {}, 0
    for key, (kind, oid) in wanted.items():
        header_end = batch.index(b"\n", pos)
        size = int(batch[pos:header_end].split()[2])
        data = batch[header_end + 1: header_end + 1 + size]
        pos = header_end + 1 + size + 1
        files[key] = (kind, data if kind == "binary" else data.decode("utf-8"))
    return files


# ---- the merge of one key (section 4 of the design) --------------------------------------------------------------

def _merge_file(base: str, ours: str, theirs: str):
    """git merge-file of three texts: the merged text, or None when the edits overlap."""
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for name, text in (("ours", ours), ("base", base), ("theirs", theirs)):
            path = os.path.join(tmp, name)
            Path(path).write_bytes(text.encode("utf-8"))
            paths.append(path)
        proc = subprocess.run(["git", "merge-file", "-p", *paths], capture_output=True)
    if proc.returncode < 0 or proc.returncode > 127:
        raise RuntimeError("git merge-file failed")
    return None if proc.returncode else proc.stdout.decode("utf-8")


def merge_text(base: str, ours: str, theirs: str):
    """The producer: re-applies the branch's edit (base -> ours) onto the line's text (theirs)."""
    return _merge_file(base, ours, theirs)


def plan(b: dict, o: dict, t: dict) -> dict:
    """{key: (kind, content or None for deleted)}; raises Refused (R3, R4, R5, R8)."""
    results = {}
    for key in sorted(set(b) | set(o) | set(t)):
        kind = (o.get(key) or t.get(key) or b.get(key))[0]
        bv, ov, tv = (side[key][1] if key in side else None for side in (b, o, t))
        n = (lambda v: v) if kind == "binary" else (lambda v: norm(key, kind, v))
        if ov is None and tv is None:
            results[key] = (kind, None)
        elif bv is None and tv is None:
            results[key] = (kind, ov if kind == "binary" else n(ov))
        elif bv is None and ov is None:
            results[key] = (kind, tv if kind == "binary" else n(tv))
        elif ov is None or tv is None:
            kept = tv if ov is None else ov
            if n(kept) != n(bv):
                raise Refused("R5", "deleted on one side and changed on the other", [key])
            results[key] = (kind, None)
        elif kind == "binary":
            o_changed, t_changed = ov != (bv or b""), tv != (bv or b"")
            if bv is None or (o_changed and t_changed):
                if ov != tv:
                    raise Refused("R4", "a binary asset changed differently on both sides", [key])
            results[key] = (kind, ov if o_changed or bv is None else tv)
        else:
            merged = merge_text(n(bv) if bv is not None else "", n(ov), n(tv))
            if merged is None:
                raise Refused("R3", "overlapping edits", [key])
            results[key] = (kind, merged)
    clash: dict = {}
    for key, (kind, content) in results.items():
        if content is not None and key not in TEXTS:
            clash.setdefault(key.rpartition("/")[2], []).append(key)
    for name, keys in sorted(clash.items()):
        if len(keys) > 1:
            raise Refused("R8", "one asset name in two folders (rehash matches names only)", sorted(keys))
    return results


# ---- checks after rehash (sections 5 and 6) ------------------------------------------------------------------

def changed_lines(old: str, new: str) -> list:
    return [line for line in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0)
            if not line.startswith(("---", "+++", "@@"))]


def read_back(wt: Path, key: str, kind: str):
    """The key's file in the throwaway tree after rehash (under its new hashed name), or None."""
    if key in TEXTS:
        path = wt / key
        return path.read_text(encoding="utf-8") if path.exists() else None
    folder, _, name = key.rpartition("/")
    stem, _, ext = name.rpartition(".")
    for path in (wt / SHELL / folder).glob(f"{stem}*.{ext}"):
        m = HASHED.match(path.name)
        if m and m["stem"] == stem and m["ext"] == ext:
            return path.read_bytes() if kind == "binary" else path.read_text(encoding="utf-8")
    return None


def prove(b: dict, o: dict, t: dict, results: dict, wt: Path) -> None:
    """Per text the branch changed, print its -/+ lines before and after; refuse on any difference, then
    compare the merged text with an independent three-way merge."""
    for key, (kind, content) in results.items():
        if kind == "binary":
            continue
        n = lambda side: norm(key, kind, side[key][1]) if key in side else ""
        if n(o) == n(b):
            continue
        if key not in o and key not in t:
            continue  # deleted on both sides: nothing of the branch's left to carry
        got = read_back(wt, key, kind)
        got_n = norm(key, kind, got) if got is not None else ""
        before, after = changed_lines(n(b), n(o)), changed_lines(n(t), got_n)
        print(f"== {key} before", *before, f"== {key} after", *after, sep="\n")
        if before != after:
            raise Refused("R7", SAME_EDIT if n(o) == n(t) else "list rule: the branch's edit did not carry", [key])
        if key in o and key in t:
            expected = _merge_file(n(b), n(o), n(t))
        else:
            expected = n(o) if key in o else ""
        if got_n != expected:
            raise Refused("R7", "full-text rule: the merged text is not the three-way merge", [key])


def check_tree(wt: Path, results: dict) -> None:
    texts = [wt / k for k in (INDEX, FRAME, SHELL_RS, GOLDEN)]
    shell_files = [p for p in (wt / SHELL).rglob("*") if p.is_file()]
    texts += [p for p in shell_files if p.suffix[1:] in ("css", "js", "json", "svg")]
    for path in texts:
        if path.exists() and MARKER.search(path.read_text(encoding="utf-8", errors="replace")):
            raise Refused("R7", "conflict marker left", [display(wt, path)])
    served = {p.name for p in shell_files if HASHED.match(p.name)}
    rewritten = [wt / INDEX, wt / FRAME] + [p for p in shell_files if p.suffix[1:] in REWRITTEN_EXTS]
    missing = sorted({name for path in rewritten if path.exists()
                      for name in REF.findall(path.read_text(encoding="utf-8")) if name not in served})
    if missing:
        raise Refused("R7", "missing asset referenced", missing)


def display(wt: Path, path: Path) -> str:
    rel = path.relative_to(wt).as_posix()
    found = key_of(rel)
    return found[0] if found else rel


# ---- the run ------------------------------------------------------------------------------------------------------

def preconditions(root: str) -> None:
    if git("status", "--porcelain", cwd=root).stdout.strip():
        raise Refused("R1", "the tree has uncommitted changes")
    if git("rev-parse", "-q", "--verify", "MERGE_HEAD", cwd=root, check=False).returncode == 0:
        raise Refused("R1", "a merge is in progress")
    if git("symbolic-ref", "-q", "HEAD", cwd=root, check=False).returncode != 0:
        raise Refused("R1", "HEAD is detached; check out the UI branch")


def source_conflicts(root: str, line: str) -> None:
    proc = git("merge-tree", "--write-tree", "--name-only", "--no-messages", "HEAD", line, cwd=root, check=False)
    if proc.returncode not in (0, 1):
        raise RuntimeError("git merge-tree failed: " + proc.stderr.strip())
    paths = proc.stdout.splitlines()[1:]  # line 1 is the result tree
    outside = sorted({p for p in paths if p and not is_generated(p)})
    if outside:
        raise Refused("R2", "conflicts outside the generated files", outside)


def build(line: str, subject: str, b: dict, o: dict, t: dict, results: dict, wt: Path) -> str:
    """The merge commit, made in the throwaway worktree `wt`; returns its id."""
    git("merge", "--no-commit", "--no-ff", "-q", line, cwd=wt, check=False)
    # Every hashed asset is rewritten from `results`; anything untracked under the UI folder now is a merge
    # leftover (a rename/rename side copy such as `name~HEAD`), since the tree started clean.
    leftovers = git("ls-files", "--others", "--exclude-standard", "--", UI, cwd=wt).stdout.splitlines()
    for path in [wt / p for p in leftovers] + [p for p in (wt / SHELL).rglob("*") if HASHED.match(p.name)]:
        if path.is_file():
            path.unlink()
    for key, (kind, content) in results.items():
        if content is None:
            if key in TEXTS and (wt / key).exists():
                (wt / key).unlink()
            continue
        path = wt / key if key in TEXTS else wt / SHELL / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if kind == "binary" else content.encode("utf-8"))
    git("add", "-A", UI, cwd=wt)
    proc = subprocess.run([sys.executable, "-I", REHASH], cwd=wt, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + proc.stderr)
        raise Refused("R6", "rehash_ui_assets.py failed (its output is above)")
    touched = git("diff", "--name-only", cwd=wt).stdout.splitlines()
    touched += git("ls-files", "--others", "--exclude-standard", cwd=wt).stdout.splitlines()
    outside = sorted({p for p in touched if p and not is_generated(p)})
    if outside:
        raise Refused("R7", "rehash wrote outside G", outside)
    git("add", "-A", UI, cwd=wt)
    unmerged = git("diff", "--name-only", "--diff-filter=U", cwd=wt).stdout.split()
    if unmerged:
        raise Refused("R7", "unresolved paths after staging", unmerged)
    check_tree(wt, results)
    prove(b, o, t, results, wt)
    # Git's own merge subject would name the throwaway branch and a 40-character id; the repo's commit-msg hook
    # caps a subject at 72 characters.
    message = f"{subject}\n\nUI generated files re-derived by scripts/dev/merge_ui_line.py\n"
    with tempfile.NamedTemporaryFile("w", suffix=".msg", delete=False) as f:
        f.write(message)
    try:
        committed = git("commit", "-q", "--cleanup=strip", "-F", f.name, cwd=wt, check=False)
        if committed.returncode != 0:
            sys.stderr.write(committed.stdout + committed.stderr)
            raise Refused("R7", "commit failed (git's output is above)")
    finally:
        os.unlink(f.name)
    return out("rev-parse", "HEAD", cwd=wt)


def run(root: str, line_ref: str) -> int:
    preconditions(root)
    line = out("rev-parse", "--verify", f"{line_ref}^{{commit}}", cwd=root)
    base = out("merge-base", "HEAD", line, cwd=root)
    if base == line:
        print("merge_ui_line: the line is already merged; nothing to do")
        return 0
    source_conflicts(root, line)
    b, o, t = (tree_files(rev, root) for rev in (base, "HEAD", line))
    results = plan(b, o, t)
    branch = out("symbolic-ref", "--short", "HEAD", cwd=root)
    subject = f"Merge {line_ref} into {branch}"
    if len(subject) > 72:
        subject = f"Merge {line[:10]} into {branch}"[:72]
    common = Path(out("rev-parse", "--git-common-dir", cwd=root))
    common = common if common.is_absolute() else Path(root) / common
    name = f"merge-ui-line-{os.getpid()}"
    wt = common / name
    git("worktree", "add", "-q", "-b", name, str(wt), "HEAD", cwd=root)
    try:
        commit = build(line, subject, b, o, t, results, wt)
        git("merge", "--ff-only", "-q", commit, cwd=root)
    finally:
        # The throwaway tree is this script's own and freshly made: reset and clean it, then remove it without
        # force (a refusal here is printed, never forced).
        git("reset", "--hard", "-q", cwd=wt, check=False)
        git("clean", "-fdq", cwd=wt, check=False)
        removed = git("worktree", "remove", str(wt), cwd=root, check=False)
        if removed.returncode != 0:
            print(f"merge_ui_line: could not remove {wt}: {removed.stderr.strip()}", file=sys.stderr)
        git("branch", "-q", "-D", name, cwd=root, check=False)
    print(f"merge_ui_line: merged {line_ref} as {commit[:10]}")
    return 0


def main(argv: list) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    root = out("rev-parse", "--show-toplevel", cwd=os.getcwd())
    try:
        return run(root, argv[1])
    except Refused as refusal:
        names = ": " + ", ".join(refusal.names) if refusal.names else ""
        print(f"merge_ui_line: refused {refusal.code}: {refusal.reason}{names}", file=sys.stderr)
        return 1
    except RuntimeError as error:
        print(f"merge_ui_line: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
