#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Convert a single-file UI access matrix into per-route fragments.

    scripts/dev/split-ui-matrix.py [--bodies FILE] [ROOT]

ROOT is a checkout (default: the current directory). It reads the old
`src/gateway/router/ui_access_matrix.tsv`, writes `ui_access_matrix.d/<slug>.tsv`
(one file per route path) and deletes the old file. It refuses to run when
`ui_access_matrix.d/` already holds files, so it never overwrites fragments.

Digests named in `ui_access_matrix_bodies.tsv` become `status:@name` cells; a
digest not named there stays inline. `--bodies FILE` copies FILE over the bodies
file first (use the release line's, so every branch shares the frozen names).
Without any bodies file, one is created from the digests that occur on three or
more routes.

Migrating an in-flight branch that still edits the single table, BEFORE merging
the release line (merging first would let the old table overwrite release-side
rows):

    git show <line>:src/gateway/router/ui_access_matrix_bodies.tsv > /tmp/bodies.tsv
    scripts/dev/split-ui-matrix.py --bodies /tmp/bodies.tsv
    git add -A && git commit -m "test(ui): split the access matrix per route"
    git merge <line>

The merge then meets the line's fragments file by file: a fragment both sides
changed shows as an add/add conflict only where its rows differ; keep both sides'
rows.
"""
import collections
import os
import re
import shutil
import sys

ROUTER = "src/gateway/router"
# Routes whose answers are caller-scoped, or probed with a store, as the test's
# former hand lists said (they now live as `#@` header lines in each file).
SCOPED = {"/ui/api/status", "/ui/api/activity", "/ui/api/activity/export",
          "/ui/api/activity/{id}", "/ui/api/control-plane",
          "/ui/api/control-plane/export-status"}
WRITES = {"/ui/api/control-plane/grants", "/ui/api/control-plane/policies",
          "/ui/api/control-plane/decisions"}
READS = {"/ui/api/control-plane"}
MIN_ROUTES = 3


def slug(path):
    if path == "/dashboard":
        return "__dashboard"
    rest = path[len("/ui/api/"):]
    return re.sub(r"\{([a-z]+)\}", r"_\1_", rest.replace("/", "__"))


def read_rows(old):
    rows = collections.OrderedDict()
    for line in open(old, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        cells = line.split("\t")
        if len(cells) != 5:
            raise SystemExit(f"a matrix line has five cells: {line!r}")
        rows.setdefault(cells[0], []).append(cells)
    return rows


def read_bodies(path):
    names = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if line.strip() and not line.startswith("#"):
                name, digest = line.split("\t")[:2]
                names[digest] = name
    return names


def split(root, bodies_from=None):
    old = os.path.join(root, ROUTER, "ui_access_matrix.tsv")
    bodies = os.path.join(root, ROUTER, "ui_access_matrix_bodies.tsv")
    out = os.path.join(root, ROUTER, "ui_access_matrix.d")
    if os.path.isdir(out) and os.listdir(out):
        raise SystemExit(f"{out} already holds files; refusing to overwrite them")
    if bodies_from:
        shutil.copyfile(bodies_from, bodies)
    rows = read_rows(old)
    if len({slug(p) for p in rows}) != len(rows):
        raise SystemExit("two routes share a slug")
    names = read_bodies(bodies)
    if not names:
        routes_of = collections.defaultdict(set)
        for path, cells in rows.items():
            for c in cells:
                digest = c[4].partition(":")[2]
                if re.fullmatch(r"[0-9a-f]{12}", digest):
                    routes_of[digest].add(path)
        names = {d: "b_" + d[:8] for d, ps in routes_of.items() if len(ps) >= MIN_ROUTES}
        with open(bodies, "w", encoding="utf-8") as f:
            f.write("# name, digest, meaning. A body shared by 3 or more routes at the split; names are frozen, not recomputed.\n")
            for digest, name in sorted(names.items(), key=lambda x: x[1]):
                f.write(f"{name}\t{digest}\tshared answer body on {len(routes_of[digest])} routes\n")
    os.makedirs(out, exist_ok=True)
    for path, cells in rows.items():
        with open(os.path.join(out, slug(path) + ".tsv"), "w", encoding="utf-8") as f:
            f.write("# path, method, request shape, caller, answer. One route per file; a digest named in ../ui_access_matrix_bodies.tsv is written as status:@name.\n")
            for flag, routes in (("scoped", SCOPED), ("store_writes", WRITES), ("store_reads", READS)):
                if path in routes:
                    f.write(f"#@ {flag}\n")
            for c in cells:
                status, _, digest = c[4].partition(":")
                if digest in names:
                    c[4] = f"{status}:@{names[digest]}"
                f.write("\t".join(c) + "\n")
    os.remove(old)
    return len(rows), len(names)


if __name__ == "__main__":
    args = sys.argv[1:]
    bodies_from = None
    if args[:1] == ["--bodies"]:
        if len(args) < 2:
            raise SystemExit("--bodies needs a file")
        bodies_from, args = args[1], args[2:]
    files, named = split(args[0] if args else ".", bodies_from)
    print(f"{files} route files, {named} named bodies")
