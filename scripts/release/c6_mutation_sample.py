#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""NFR.BUILD.1 C6 sampler: hash-ordered Critical rows per named path.
usage: c6_mutation_sample.py NONCE [INVENTORY] -> prints every Critical row
ranked within its path as rank, status, path, file, qualified, occurrence,
reason; the first QUOTA[path] ranks are SAMPLE, later ranks understudies."""
import sys, hashlib
P = {"startup": ["src/gateway/server/"], "OAuth": ["src/oauth/"],
     "HTTP dispatch": ["src/transport/http/", "src/gateway/router/"],
     "stdio dispatch": ["src/transport/stdio.rs", "src/gateway/server/stdio_channel.rs", "src/transport/command_split.rs"],
     "bridge": ["src/gateway/input_bridge.rs"],
     "tasks": ["src/gateway/task_service/", "src/gateway/router/handlers/tasks.rs", "src/gateway/meta_mcp/task_confirmation"],
     "account paths": ["src/personal_accounts/", "src/gateway/server/account_bindings.rs", "src/config/account_bindings.rs", "src/identity_propagation/"]}
QUOTA = {"account paths": 16, "HTTP dispatch": 16}  # others 8 (bridge has 4)
nonce, inv = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "docs/release/v4.0.0-critical-functions.tsv")
by = {}
for line in open(inv, encoding="utf-8"):
    f = line.rstrip("\n").split("\t")
    if line.startswith(("#", "path\t")) or f[3] != "critical":
        continue
    hits = [(p, k) for k, ps in P.items() for p in ps if f[0].startswith(p)]
    if not hits:
        sys.exit(f"{f[0]}: Critical row outside every named path; update P")
    path = max(hits, key=lambda x: len(x[0]))[1]
    by.setdefault(path, []).append(f)
for path, rows in sorted(by.items()):
    key = lambda f: hashlib.sha256("\t".join([nonce, f[0], f[5], f[2]]).encode()).hexdigest()
    for rank, f in enumerate(sorted(rows, key=key), 1):
        tag = "SAMPLE" if rank <= QUOTA.get(path, 8) else "understudy"
        print(rank, tag, path, f[0], f[5], f[2], f[6], sep="\t")
