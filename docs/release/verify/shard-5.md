<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Shard 5 verification — RELEASE-4.0.0-criteria-status.md lines 355-431

Method: every citation each row makes — `file:line`, symbol, commit SHA — read at source.
Classification: MATCH (citation lands on the claimed content) / DRIFT (right symbol, right
body, right commit, stale line number, offset stated) / CONTRADICTION (source says something
different from the row's claim). VERDICT-RIGHT-REASONING-WRONG flagged separately.

Range covers the NFR table (rows 365-386, its narrative preamble 355-361) and the GH475
cluster-H table (rows 409-431, its preamble 389-405).

## Commit citations — all 17, checked as a block

Every SHA cited anywhere in 355-431 resolves and is an ancestor of HEAD:

```
32f135a6 chore(release): 3.5.0 (#454)                              anc=Y
32f135a61fb50c20a044fb4c2347bc1cf8015d89 (same commit, long form)  anc=Y
4ea2e79a fix(tests): fail when a tracked gap names no row          anc=Y
5c29494ac2140c2cfeb185cedeb901997397b6b8 Assert the retry refusal… anc=Y
75a47471 fix(recovery): GH475.RL.5 — throttled false-positive      anc=Y
81c0a8ad feat(stdio): record the tools/list surface on stdio       anc=Y
83b75675 fix(capability): keep the throttle record free of the r…  anc=Y
83c98902 fix(config): serve the modern revision by default         anc=Y
8f8a478a fix(capability): give a throttled backend a typed error   anc=Y
91defba9 docs(sec.6): make the MIK-7249 fix greppable              anc=Y
af36158f feat(continuation): count the hold eviction nobody came…  anc=Y
c3270021 feat(mrtr.8b): reclaim expired holds inside the lock      anc=Y
cccbb8f7 docs(obs4): design the abandoned-continuation expiry co…  anc=Y
d306c7e8 feat(obs): record the protocol revision on the path bot…  anc=Y
ed94ef45 docs(cache.4): name 4.g for what it discriminates         anc=Y
f60cf65c fix(upgrade): stop the 4.0.0 notice naming a command th…  anc=Y
f7781df8 fix(observability): record tools/list filters where the…  anc=Y
```

No SHA in this range is unresolvable, and none points off-branch.

## Worktree state of cited files

`git status --porcelain` over every path cited in this range returns exactly two cited files
dirty, both documents, neither source:

- `docs/requirements/RELEASE-4.0.0-blocking-rollup.md` — cited by NFR.COMPAT.1 (`:18-47` cited
  by a peer row) and by NFR.SEC.6. A peer session holds uncommitted edits, so any line-anchored
  citation into it is ambiguous and is reported as such below rather than as MATCH or DRIFT.
- `docs/requirements/RELEASE-4.0.0-criteria-status.md` — the ledger itself.

Every `src/` and `tests/` path cited in this range is clean, so line drift found below comes
from committed history, not from a concurrent session's uncommitted edits.

## Rows checked — NFR table (365-386)

| Row | Claim | Check | Verdict |
|---|---|---|---|
