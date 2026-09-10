<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Shard 1 verification — RELEASE-4.0.0-criteria-status.md lines 1-134

Range claimed: lines 1-134 of `docs/requirements/RELEASE-4.0.0-criteria-status.md`.
Boundary confirmed against the landed shard reports rather than assumed: shard-3 covers 210-285,
shard-4 covers 285-360, shard-6 covers 432-502; rows 135-210 are held by another agent this pass.
Lines 1-134 are the preamble (status vocabulary, methodology warnings) plus the first criteria
tables. Prose lines carry no `file:line` citations and are audited only where they make a
checkable factual claim about source.

Method per row: read the claim, then check every `file:line`, symbol and commit SHA it cites at
source (`sed -n`, `rg -n`, `git show <sha>:<path>`, `git log`). Classified MATCH / DRIFT
(right symbol+body, stale line number) / CONTRADICTION (source says otherwise).

Not re-reported here, already assigned for repair: row 100 (MIK-7214.HEADER.3a) citing
`era.rs:37` for the -32020 constant that lives at `era.rs:55`.

Written incrementally, one row appended as each is checked.

## Findings


**Measurement basis.** Working tree of `fix/mrtr2-continuation-handle` (the tree the ledger was written against). `src/gateway/meta_mcp/invoke.rs` and `src/cache.rs` are unmodified here, so their line numbers are HEAD's.

### MIK-7213.CACHE.4a (line 93) — PARTIAL — DRIFT (2 citations), core claim MATCH
- `src/cache.rs:279` = `pub fn response_key(` — MATCH.
- `src/cache.rs:101-113` = the `KeyContext` struct carrying `routing_profile` (:103), `protocol_revision` (:105), `policy_epoch` (:108) — MATCH; the "both are `KeyContext` fields" claim holds.
- `meta_mcp/invoke.rs:1214` (read) and `:1787` (write) — **DRIFT**. Line 1214 is the caller-principal `.map(...)` selection; 1787 is inside the cost-suggestion block. The two `response_key` call sites are at **`invoke.rs:1307` and `:1828`** (the only two production `policy_epoch: 0` literals). Off by ~93 and ~41 lines. Both rows 93 and 94 repeat this pair.

### MIK-7213.CACHE.4b (line 94) — ABSENT — verdict CONFIRMED; 2 citations DRIFT
- Negative claim re-run with `rg -uu` over `src/` and `tests/` (untracked-inclusive, per the preamble's own ABSENT rule): `policy_epoch` occurs **five** times only — definition `src/cache.rs:108`, hash `src/cache.rs:119`, and three `policy_epoch: 0` literals (`invoke.rs:1307`, `invoke.rs:1828`, `meta_mcp/tests.rs:4410`). **No writer exists anywhere**, tracked or untracked. The ABSENT verdict and its "every entry keys under generation 0 forever" reasoning are correct. This is a checked-and-confirmed negative, not an unchecked one.
- `src/cache.rs:112` for `policy_epoch` — **DRIFT**: the field is at `:108`; `:112` is a doc-comment line inside `impl KeyContext`. `:119` (hashed unconditionally) — MATCH.
- `MetaMcp::set_identity_grants` at `meta_mcp/mod.rs:890` — **DRIFT**: the fn is at `mod.rs:919` (`:890` lands mid-error-construction). Symbol exists and is the sole definition; the "sole writer" framing is sound (one caller, `src/gateway/server/mod.rs:754`).

### MIK-7213.CACHE.1a / 1b (lines 88, 89) — MET — **CONTRADICTION (wrong-target production citation)**
Both rows cite `handlers.rs:1385-1391,1398-1433` as the production evidence that `ttlMs` / `cacheScope` are emitted on every cacheable method. That region is not the emission site: `:1385-1391` is the `state.meta_mcp.handle_tools_call(...)` call and `:1398-1433` is the `MetaMcpCallerContext { ... }` literal (`verified_identity`, `is_admin`, `input_capabilities`, …). Neither `ttlMs` nor `cacheScope` appears anywhere in that span.
The real site is ~250 lines later: `handlers.rs:1636` (`/// The methods whose results carry ttlMs and cacheScope`), with the fields inserted at `:1676` (`object.insert("ttlMs", …)`) and `:1681` (`"cacheScope"`), scope resolved at `:1683`. Everything the rows *claim* is true of the code — it is the pointer that is wrong. Verdict MET is unaffected; the citation must be re-anchored to `handlers.rs:1636-1690`.
Named symbols all resolve: `ac_cache_1_both_fields_are_present_on_every_cacheable_method` (`tests/mik_7213_acs.rs:293`), `every_cacheable_method_gets_both_fields` (in-module, `handlers.rs:1867`).

### MIK-7213.CACHE.2 (line 90) and CACHE.3b (line 92) — MET — **CONTRADICTION (wrong-target production citation)**
Both rows cite `handlers.rs:998,1535` as where `scope_for_method` is read. Neither line calls it: `:998` is `let owner = session_owner_key(client.as_ref());` and `:1535` is `Ok(result) => JsonRpcResponse::success(id, result),`. The only two production call sites are **`handlers.rs:1163`** (the `tools/list` audit record) and **`handlers.rs:1683`** (the cacheable-response path) — confirmed exhaustively with `rg -uu` across `src/` and `tests/`. Verdicts hold; the citations do not.
Correct in the same rows: `cacheable.rs:46` = `pub const fn for_list(caller_dependent: bool) -> Self` (MATCH); `ac_cache_2_this_gateways_list_is_private` at `tests/mik_7213_acs.rs:97` and `ac_cache_3_a_filtered_list_is_never_public` at `:89` (both MATCH).

### MIK-7213.CACHE.3a (line 91) — MET — MATCH
`cacheable.rs:62` = `const SCOPE_TABLE: &[(&str, CacheScope)] = &[`; the table body runs to `:73` and the cited range `62-75` overshoots by two lines onto the following doc comment. Immaterial. `mik_7213_acs.rs:336` resolves inside the test module as claimed.

> Anchor warning. Between my first and second read the ledger grew by 5 lines above the CACHE block (another agent holds the write lock). Everything below is keyed by criterion ID, not by line number; the line numbers quoted are the ones the rows sat at when I extracted them (CACHE.1a at 88). Add 5 for the current file, and re-check before acting.

### MIK-7214.HEADER.2c (was line 99) — MET — CONTRADICTION (verdict rests on a false statement about the code)
The row's evidence: "`mcp_name_body_field` is a total match with `_ => None` (`src/protocol/headers.rs:64`), so `mcp_name_required` is false for every method not in the three-case list". The function (`headers.rs:63-70`) has FOUR `Some` cases covering SIX methods: `"tools/call" | "prompts/get" => Some("name")` (`:65`), `"resources/read" => Some("uri")` (`:66`), `"tasks/get" | "tasks/update" | "tasks/cancel" => Some("taskId")` (`:67`), then `_ => None` (`:68`).
So `mcp_name_required` is TRUE for `tasks/get`, `tasks/update` and `tasks/cancel` — three methods beyond the three the criterion names. The criterion is "`Mcp-Name` required for no other method"; the code requires it for three others, deliberately (the doc comment at `:59-61` argues the task methods must mirror `params.taskId`). The MET verdict is asserted on a description of the code that is not true of the code. Either the criterion text is stale (task methods added later, criterion never widened) or the verdict is wrong — a human must pick. Citation `:64` is also off: that line is `match method {`; the default case is `:68`.
The same false "exactly those three" statement appears in HEADER.2b (was line 98), whose evidence reads "returns a field for exactly those three". Six.

### MIK-7214.HEADER.2a (was line 97) — MET — CONTRADICTION (wrong-target citation)
Criterion: "`Mcp-Method` required on every modern request". Cited: `src/protocol/headers.rs:43-65`. That span is `mcp_name_required` (`:43`) and the head of `mcp_name_body_field` (`:63`) — the Mcp-Name rule, which has nothing to do with `Mcp-Method`. The `Mcp-Method` requirement lives in `HeaderCheck::header_method` (`headers.rs:159-160`, "`Mcp-Method`. Required on every modern request.") and is enforced by the compare impl at `headers.rs:169+`. The verdict may hold; the evidence as cited does not support it.

### MIK-7214.HEADER.1b — MET — CONTRADICTION (wrong-target citation)
Evidence reads "`src/protocol/headers.rs:156-162` compares the two and rejects on inequality". Lines 154-167 are the `HeaderCheck<'a>` struct DECLARATION; `:156-162` are four `pub` field declarations with their doc comments. No comparison and no rejection occurs there. The comparison is `impl HeaderCheck<'_>` at `headers.rs:169+` ("Compare every mirrored field, and say which one disagreed... Returns the first field whose header and body do not agree").

### MIK-7214.HEADER.2b (was line 98) — MET — DRIFT
`mcp_name_body_field` cited as `headers.rs:59-65`; the function is `:63-70`. The cited range stops at `:65` and so excludes `"resources/read" => Some("uri")` (`:66`) — the exact case the row's argument depends on. Re-anchor to `:63-70`. (See HEADER.2c for the separate false claim in the same row.)

### MIK-7214.HEADER.1a (was line 95) — MET — DRIFT (weak anchor)
`headers.rs:149-155` is the `HeaderCheck` doc comment, derive, struct opening and the doc line for `header_protocol_version`. It names the requirement but contains no enforcement; the check is at `:169+`. Declaration-only anchor, not a wrong target.
