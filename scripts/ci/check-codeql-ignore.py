#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fail when CodeQL's paths-ignore would hide a product source file (MIK-8490).

codeql.yml skips test-only paths by name (`*_tests.rs`, `tests/`, ...). A
product file that happens to match one of those globs would silently leave the
scan. This check asks the compiler instead of trusting names: it runs
`cargo check --lib --bins` (no test cfg) for each feature set, reads the
dep-info rustc writes for every mcp-gateway lib and bin artifact (the exact
list of source files that build compiled), and fails if any of them matches a
paths-ignore glob read from codeql.yml itself.

Stated miss: a file compiled only on another OS (cfg(windows)) is not in a
Linux build's dep-info; it is still checked by name against the globs below
only if a Linux build reads it.

Usage: scripts/ci/check-codeql-ignore.py [--cargo CARGO] [--extra-glob GLOB]   (repo root)
"""
import argparse
import json
import os
import re
import subprocess
import sys

WORKFLOW = ".github/" + "workflows/codeql.yml"
FEATURE_SETS = ([], ["--all-features"], ["--no-default-features"])


def ignore_globs(text):
    """The `paths-ignore:` list of the inline CodeQL config."""
    globs, key_indent = [], None
    for line in text.splitlines():
        # A `#` comment, whole-line or trailing, is not part of the value.
        body = re.sub(r"(^|\s)#.*$", "", line).rstrip()
        stripped = body.strip()
        if not stripped:
            continue
        indent = len(body) - len(body.lstrip())
        if stripped == "paths-ignore:":
            key_indent = indent
            continue
        if key_indent is not None:
            # The list ends at the first line not nested under the key.
            if indent <= key_indent or not stripped.startswith("- "):
                break
            globs.append(stripped[2:].strip().strip("'\""))
    return globs


def glob_regex(glob):
    """GitHub-style glob: `**` spans directories (zero or more), `*` one segment."""
    out, i = "", 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif glob.startswith("**", i):
            out += ".*"
            i += 2
        elif glob[i] == "*":
            out += "[^/]*"
            i += 1
        else:
            out += re.escape(glob[i])
            i += 1
    return re.compile("^" + out + "$")


def ignored(path, regex):
    """CodeQL excludes a path when the pattern matches it or any parent directory."""
    parts = path.split("/")
    return any(regex.match("/".join(parts[:n])) for n in range(1, len(parts) + 1))


def product_sources(cargo, root):
    """Repo files rustc read for every non-test lib/bin build: sources and
    anything they embed (`include_str!`, `include_bytes!`)."""
    files = set()
    for features in FEATURE_SETS:
        cmd = [cargo, "check", "--locked", "--lib", "--bins", *features, "--message-format=json"]
        run = subprocess.run(cmd, cwd=root, stdout=subprocess.PIPE, text=True, check=False)
        if run.returncode != 0:
            sys.exit(f"check-codeql-ignore: `{' '.join(cmd)}` failed (rc={run.returncode})")
        artifacts = 0
        for line in run.stdout.splitlines():
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get("reason") != "compiler-artifact" or msg["profile"]["test"]:
                continue
            # This repository's own crate: its targets live under src/.
            if not msg["target"]["src_path"].startswith(os.path.join(root, "src") + os.sep):
                continue
            if not set(msg["target"]["kind"]) & {"lib", "bin"}:
                continue
            for artifact in msg["filenames"]:
                deps = os.path.dirname(artifact)
                if not deps.endswith("deps"):
                    deps = os.path.join(deps, "deps")
                stem = os.path.basename(artifact).split(".")[0]
                stem = stem[3:] if stem.startswith("lib") else stem
                dep_info = os.path.join(deps, stem + ".d")
                if not os.path.exists(dep_info):
                    # Fail closed: an artifact whose sources cannot be read
                    # would otherwise drop out of the comparison unseen.
                    sys.exit(f"check-codeql-ignore: no dep-info {dep_info} for {artifact}")
                artifacts += 1
                with open(dep_info, encoding="utf-8") as handle:
                    first = handle.readline()
                for path in first.split(":", 1)[1].split():
                    rel = os.path.relpath(path, root)
                    if not rel.startswith("..") and not rel.startswith("target"):
                        files.add(rel)
        if artifacts == 0:
            sys.exit(f"check-codeql-ignore: no mcp-gateway dep-info found for {features or 'default'}")
    return files


def self_test():
    """Negative controls on the parts that need no build; any failure exits."""
    text = "x:\n  paths-ignore:\n    # a comment line\n    - tests/**  # trailing\n    - src/gateway\n- name: next step\n"
    globs = ignore_globs(text)
    assert globs == ["tests/**", "src/gateway"], globs
    rx = {g: glob_regex(g) for g in globs}
    assert ignored("tests/a/b.rs", rx["tests/**"])
    assert ignored("src/gateway/deep/x.rs", rx["src/gateway"]), "a directory pattern covers descendants"
    assert not ignored("src/gatewayx.rs", rx["src/gateway"])
    assert ignored("src/a/b_tests.rs", glob_regex("src/**/*_tests.rs"))
    assert ignored("src/b_tests.rs", glob_regex("src/**/*_tests.rs")), "** spans zero directories"
    assert not ignored("src/a/b.rs", glob_regex("src/**/*_tests.rs"))
    assert ignored("src/cli/complete.js", glob_regex("src/**/*.js")), "embedded files are checked too"


def main():
    self_test()
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo", default=os.environ.get("CARGO", "cargo"))
    # Falsifier: an extra glob that names a product file must make this fail.
    parser.add_argument("--extra-glob", action="append", default=[])
    args = parser.parse_args()
    root = os.getcwd()
    globs = ignore_globs(open(os.path.join(root, WORKFLOW), encoding="utf-8").read())
    globs += args.extra_glob
    if not globs:
        sys.exit(f"check-codeql-ignore: no paths-ignore list found in {WORKFLOW}")
    patterns = [(g, glob_regex(g)) for g in globs]
    # The matcher must still recognise a known test file, or every check passes.
    probe = "src/gateway/auth_tests.rs"
    if not any(ignored(probe, rx) for _, rx in patterns):
        sys.exit(f"check-codeql-ignore: the globs no longer match {probe}; matcher or globs changed")
    product = product_sources(args.cargo, root)
    if len(product) < 100:
        sys.exit(f"check-codeql-ignore: only {len(product)} product files found; dep-info read is broken")
    hidden = sorted((f, g) for f in product for g, rx in patterns if ignored(f, rx))
    for path, glob in hidden:
        print(f"FAIL {path}: compiled into the product but skipped by CodeQL glob `{glob}`")
    if hidden:
        sys.exit(1)
    print(f"check-codeql-ignore: {len(product)} product files, none matched by {len(globs)} paths-ignore globs")


if __name__ == "__main__":
    main()
