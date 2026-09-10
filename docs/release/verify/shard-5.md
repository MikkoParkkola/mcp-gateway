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
| NFR.COMPAT.1 | `SUPPORTED_VERSIONS`/`PROTOCOL_VERSION` at `src/protocol/mod.rs:27,49`; `negotiate_version` at `:53`; `MODERN_VERSIONS` at `src/protocol/meta.rs:248`; default now true at `src/config/mod.rs:1236` in `83c98902`; modern revision advertised through discovery at `src/gateway/meta_mcp/mod.rs:1092-1099`; seven named tests in `tests/nfr_compat1_revisions.rs` | `:27` and `:49` exact (`PROTOCOL_VERSION = "2025-11-25"`; `SUPPORTED_VERSIONS` lists the four older revisions and not `2026-07-28`, as claimed). `negotiate_version` is at `:54`, cited `:53` — one line. `meta.rs:248` exact. `config/mod.rs:1236` exact (`modern_protocol: true`). All seven `compat_*` test fns named in the row exist in `tests/nfr_compat1_revisions.rs` (`:83`, `:96`, `:109`, `:125`, `:143`, `:169`, `:187`) | MATCH on the verdict-bearing citations; DRIFT (1 line) on `negotiate_version` |
| NFR.COMPAT.1 (discovery span) | "advertised through discovery (`src/gateway/meta_mcp/mod.rs:1092-1099`)" | That span is the doc comment of `Resolve the active RoutingProfile for a session` — it does not advertise a protocol revision. The mechanism the row describes is real and lives at `:1191` (`for version in crate::protocol::meta::MODERN_VERSIONS`), the only `MODERN_VERSIONS` reference in that file | DRIFT (~92 lines); substance holds at the true location |
| NFR.COMPAT.1 (superseded reading) | quotes an earlier reading, "defaults to false at `:1174`" | `src/config/mod.rs:1174` is a doc-comment line; the `modern_protocol` field is at `:1188`. The row marks this reading as superseded, so the stale anchor rides on text already labelled no longer true | DRIFT (~14 lines) inside a self-labelled superseded quotation |
| NFR.COMPAT.2 | `ac_discover_3_initialize_result_is_unchanged` at `tests/mik_7217_acs.rs:213`; `nfr_compat_2_a_3_5_0_client_completes_a_session_against_4_0_0` at `tests/nfr_compat_2_stdio_client_session.rs:124` | First is exact — `:213` is that fn's signature. Second is at `:130`, cited `:124` | MATCH / DRIFT (6 lines) |
| NFR.COMPAT.3 | N/A by operator waiver; `docs/release/v4.0.0-release-notes-DRAFT.md:38` calls `exposed_meta_tools` enforcement breaking | `:38` is exact: the table row reading "Config field was documented but had no caller outside tests; now enforced on `tools/list` and `tools/call`" | MATCH |
| NFR.COMPAT.4 | `tests/mik_7272_conformance.rs` module doc `:3`; `struct Row` `:40`; `role` `:45`; `transport` `:46`; `evidence` `:47`; `enum Role` `:19`; `enum Transport` `:30`; `matrix_has_no_empty_cells` `:316`; `MAJOR` `:52`; `MINOR` `:177`; `rg -c "Row {"` = 21; client rows `:249`, `:259`, `:268`; `the_client_role_is_covered_and_not_only_the_server_one` `:382`; verified against `4ea2e79a` | Eleven anchors exact, including the recount: `rg -c 'Row \{'` returns 21 as stated. `evidence` field is at `:48`, cited `:47`. The client-coverage test is at `:375`, cited `:382` (`:382` falls inside its body, two lines before the `client_side >= 7` assert at `:386`). `4ea2e79a` did touch this file; the file has since moved to `d09fe668`, which accounts for both offsets | MATCH on 11 of 13 anchors; DRIFT (1 line, 7 lines) on two |
| NFR.COMPAT.4 (enforcement claim) | "`matrix_has_no_empty_cells` (`:316`) fails the build on any statement with no test naming it" | The test at `:316` filters empty-evidence rows and then **excludes any row whose statement appears in `TRACKED_GAPS`**. `MINOR` carries exactly such a cell at `:195` (`evidence: &[]`, cluster B), which the suite therefore passes over. The verdict (matrix exists, refusal mechanised) survives; the stated scope does not — the build fails on a statement with no test **and no tracked gap** | VERDICT-RIGHT-REASONING-OVERSTATED |
