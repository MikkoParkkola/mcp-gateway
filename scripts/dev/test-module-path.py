#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Print the libtest module path of a Rust source file, or warn that a test
filter names a file rather than its module.

A test filter is matched against libtest's module path, which a `#[path]`
declaration or a parent module can make differ from the file's name: the file
`relay_catalogue.rs` may run as `gateway::router::idempotency_caller_scope`.
A filter written from the file name then matches nothing, and on the shared
build host that is a wasted build slot. This reads the declarations with the
orphan checker's resolver (scripts/dev/check-orphan-test-modules.py), so the
two cannot disagree about which file a declaration loads. No compile.

  test-module-path.py FILE.rs...           one module path per line
  test-module-path.py --check-filter NAME...   warnings on stderr, exit 0

A file reached only from a crate root other than src/lib.rs prints as
`<root>: <path>`. A file no crate root reaches exits 1.
"""
from __future__ import annotations

import functools
import importlib.util
import sys
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "orphan_test_modules", Path(__file__).resolve().with_name("check-orphan-test-modules.py")
)
guard = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(guard)


# rustc prints `r#name` only where the bare word is a keyword (2018 edition and
# later); elsewhere `r#foo` and `foo` are the same identifier, printed `foo`.
KEYWORDS = frozenset(
    "as async await break const continue crate dyn else enum extern false fn for if impl in let loop "
    "match mod move mut pub ref return self Self static struct super trait true type unsafe use where "
    "while abstract become box do final gen macro override priv try typeof unsized virtual yield".split()
)


def display(name: str) -> str:
    bare = name.removeprefix("r#")
    return f"r#{bare}" if bare in KEYWORDS else bare


@functools.cache
def _walk(root: Path) -> dict[Path, list[str]]:
    """Every file reachable from `root`, with each module path that loads it.
    A file loading itself again down one branch (rustc rejects circular
    modules, so only a cfg-disabled `#[path]` can) is not followed: each
    entry carries the files above it. Cached: one walk
    per crate root per process."""
    found: dict[Path, list[str]] = {}
    stack = [(root.resolve(), True, (), frozenset())]
    while stack:
        path, owns_dir, names, ancestors = stack.pop()
        if path in ancestors or not path.is_file():
            continue
        found.setdefault(path, []).append("::".join(display(n) for n in names))
        below = ancestors | {path}
        for child, via_path, bound in guard.bindings(path, owns_dir):
            stack.append((child, via_path, names + bound, below))
    return found


def module_paths(file: Path) -> list[str]:
    """The module paths that load `file`: from src/lib.rs bare, from any other
    crate root prefixed `<root>: `. Empty when no root reaches it."""
    target, root_dir = file.resolve(), guard.ROOT.resolve()
    lib = (guard.ROOT / "src" / "lib.rs").resolve()
    out: list[str] = []
    for root in sorted({r.resolve() for r in guard.crate_roots()}, key=lambda r: (r != lib, str(r))):
        for path in sorted(_walk(root).get(target, [])):
            out.append(path if root == lib else f"{root.relative_to(root_dir)}: {path}")
        if out and root == lib:
            break
    return out


def check_filter(names: list[str]) -> list[str]:
    """A warning for each filter segment that equals a source file's stem
    (not mod/lib/main) but is no module's name anywhere the crate roots reach:
    the filter was written from the file name, and libtest, which matches the
    module path, will find nothing under it."""
    stems: dict[str, list[Path]] = {}
    for path in guard.src_sources():
        if path.stem not in {"mod", "lib", "main"}:
            stems.setdefault(path.stem, []).append(path)
    modules = {
        part
        for root in guard.crate_roots()
        for paths in _walk(root.resolve()).values()
        for path in paths
        for part in path.split("::")
    }
    root_dir = guard.ROOT.resolve()
    warnings: list[str] = []
    for name in names:
        for segment in dict.fromkeys(name.split("::")):
            if segment in modules:
                continue
            for path in stems.get(segment, []):
                paths = module_paths(path)
                if paths:
                    warnings.append(
                        f"test filter '{name}': '{segment}' is the file {path.resolve().relative_to(root_dir)}, "
                        f"whose module path is {', '.join(paths)}; libtest matches the module path"
                    )
    return warnings


def main(argv: list[str]) -> int:
    if argv[:1] == ["--check-filter"]:
        for line in check_filter(argv[1:]):
            print(f"warning: {line}", file=sys.stderr)
        return 0
    if not argv or any(a.startswith("-") for a in argv):
        print(__doc__, file=sys.stderr)
        return 2
    code = 0
    for arg in argv:
        paths = module_paths(Path(arg))
        if not paths:
            print(f"{arg}: no crate root declares this file (an orphan: compiled into nothing)", file=sys.stderr)
            code = 1
        for path in paths:
            print(path)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
