# PR #473 review shard — tests-breadth

## Payload

| field | value |
|---|---|
| sha256 | ddcd96d1b43b5bae85a75e532045b0912c829293cfa60e7d79182f2a62d74303 |
| bytes | 669513 |
| files | 57 |
| insertions | 14331 |

Payload exceeded the ~150KB single-run guidance, split into 6 parts for review
(raw bytes): p1=118561 p2=85549 p3=138469 p4=114215 p5=138636 p6=74027.
Ledger binding used `{ printf '\0'; cat payload_partN.diff; } | sha256sum`
(material_bytes = payload_part bytes + 1), per the brief's correction section.

## Ledger rows

### gpt-review (all process_status=ok)

| part | material_sha256(short) | ts | verdict | material_bytes |
|---|---|---|---|---|
| p1 | 0507860925d54c5c | 17:33:26Z | SHIP | 118562 |
| p2 | 3b2635a664b3b328 | 17:34:17Z | SHIP-WITH-FIXES | 85550 |
| p3 | 545fb3c27649d841 | 17:33:28Z | SHIP-WITH-FIXES | 138470 |
| p4 | 892455d3de349c9e | 17:33:20Z | SHIP-WITH-FIXES | 114216 |
| p5 | 23b4f12fe0a3b5dc | 17:33:25Z | SHIP-WITH-FIXES | 138637 |
| p6 | 8c2b5dafd0a1d084 | 17:33:16Z | SHIP-WITH-FIXES | 74028 |

### grok-review (all process_status=ok)

| part | material_sha256(short) | ts | verdict | material_bytes |
|---|---|---|---|---|
| p1 | 0507860925d54c5c | 17:44:17Z | SHIP | 118562 |
| p2 | 3b2635a664b3b328 | 17:46:18Z | SHIP-WITH-FIXES | 85550 |
| p3 | 545fb3c27649d841 | 17:43:38Z | SHIP-WITH-FIXES | 138470 |
| p4 | 892455d3de349c9e | 17:42:10Z | SHIP-WITH-FIXES | 114216 |
| p5 | 23b4f12fe0a3b5dc | 17:42:25Z | SHIP-WITH-FIXES | 138637 |
| p6 | 8c2b5dafd0a1d084 | 17:44:42Z | SHIP | 74028 |

Every material_sha256 matches across vendors per part (same payload reviewed
by both). Full grok ledger row for p2 (representative, others follow the same
shape): `{"ts":"2026-09-08T17:46:18Z","repo":"/Users/mikko/github/.worktrees/mcp-2026-protocol","head":"6f4e511ff3130fdc253aa0a699c49fbdd902cdc4","verdict":"SHIP-WITH-FIXES","material_sha256":"3b2635a664b3b32826fdd6a3df7f3994cc41b38d87b38509ec61b7e5e391fa4e","material_bytes":85550,"process_status":"ok","output":"/Users/mikko/.claude/data/reviews/runs/grok-20260908T173321Z-5987.md"}`

Grok per-part verdict one-liners (verbatim):
- p1: "SHIP -- the new tests pin real production surfaces...I found no defect that fires in this environment"
- p2: "SHIP-WITH-FIXES -- firewall tenant ACS uses one session id, so it cannot catch a session-keyed wiring regression"
- p3: "SHIP-WITH-FIXES -- reap-count ACs do not compile until reap returns the count it already has"
- p4: "SHIP-WITH-FIXES -- the matrix names the wrong tests as evidence, and the OTEL AC never touches the outbound writer it claims to pin"
- p5: "SHIP-WITH-FIXES -- AppState.continuation is a second keyring, not the one serve shares from MetaMcp"
- p6: "SHIP -- the cases drive real probes and the operator read, and they match the designs they cite"

## Findings

### F1 — CONFIRMED — MEDIUM — does not block 4.0.0

`tests/load/k6_gateway.js:363-366` — `handleSummary` reads
`v["p(50)"].toFixed(1)` off `http_req_duration.values`, but the `options`
block at line 89 sets no `summaryTrendStats`, so k6's default trend stats
exclude `p(50)`/`p(99)`. `v["p(50)"]` is `undefined`, `.toFixed()` throws,
and the summary handler crashes. Load-tool only; does not affect gateway
production code or CI-blocking tests.

### F2 — CONFIRMED — MEDIUM — does not block 4.0.0

`tests/mik_7272_exploit_acs.rs:284` — `nested_object_in_array` recurses only
into JSON objects. Schema keywords `anyOf`/`oneOf`/`allOf` hold JSON arrays,
never descended into, so a payload smuggled inside one of those keywords is
invisible to this probe. Test-coverage gap, not a production defect.

### F3 — CONFIRMED (double-vendor, gpt + grok independently) — MEDIUM — does not block 4.0.0

`tests/mik_7272_subscriptions_acs.rs:202` (gpt) / `:281` (grok) —
`ac_sub_4_a_reissued_call_is_the_same_call` builds two independently
constructed, textually identical `json!()` literals and asserts they are
equal. It never calls `RetryFields::key_discriminator` or
`derive_key` — the functions the AC is supposed to pin. Tautological: the
assertion holds regardless of whether the discriminator/key-derivation logic
is correct. Voids the coverage claim for Increment 8 of MIK-7272, but ships
no defective production code — the gap is in the test, not the gateway.

### F4 — CONFIRMED — HIGH — BLOCKS 4.0.0

`tests/mik_7215_control4_reap_count_acs.rs:25` — `assert_eq!(reclaimed, 2)`
where `reclaimed = lifecycle.reap(300)`. Production
`src/gateway/session_lifecycle.rs:124` declares `reap()` returning `()`, not
a count. This file does not compile as written. Any CI run that includes
this test target fails at `cargo build --tests`, which is a hard release
blocker independent of the test's intent.

### F5 — CONFIRMED — HIGH — BLOCKS 4.0.0

`tests/mik_7312_continuation_state.rs:40` / `:71` — the file's doc comment
claims the test's `ContinuationState` shares identity with the one `serve`
uses. Production `src/gateway/server/mod.rs:1224` wires
`continuation: meta_mcp.continuation()`, a shared `Arc` sourced from
`meta_mcp/mod.rs:535` and `:465`. The test at line 71 instead constructs its
own `Arc::new(ContinuationState::new())` — an unshared instance. The test
therefore cannot observe the dual-keyring defect (two independent
continuation stores disagreeing) that it is written to guard against; worse,
its own construction reproduces that exact defect shape. A regression in
production wiring that reintroduces a second keyring would pass this test
silently.

### F6 — CONFIRMED — HIGH — recommend blocking (security-relevant coverage gap, not a compile/runtime defect)

`tests/mik_7116_tenant_acs.rs:184` onward — every `check_request` call in
this file is invoked with the literal string `"irrelevant-session"`; the
session id is never varied across any test case. A session-keyed regression
in the tenant firewall guard (e.g. a fix that accidentally keys on a
constant, or a cache keyed wrong) would be structurally invisible to this
entire test file, because no case ever changes the one input that would
expose it. Distinct from F4/F5 in kind: this does not fail to compile or
misrepresent shared state, it simply never exercises the dimension the
requirement is about.

### F7 — CONFIRMED — MEDIUM — does not block 4.0.0

`tests/mik_7272_conformance.rs:450` — the conformance-matrix evidence
resolver locates "proof" for a claimed AC by a whole-tree substring search
for the literal pattern `fn {function}(`. This is textual grep, not symbol
resolution: it cannot distinguish a function of that name in an unrelated
module, a shadowed/overloaded name, or a stub with a matching signature but
no relevant body, from the real evidence. The matrix can therefore report a
claim as backed when the matched function is not the one that implements
the claim. Coverage-tooling weakness, not a defect in shipped gateway code.

### Findings CONFIRMED earlier this session, detail lost to compaction (F8–F12)

Five additional gpt findings were verified against source earlier in this
session, before a context-compaction boundary. The exact file:line and
disproof/confirmation detail were not preserved verbatim past that boundary,
and re-deriving them from memory would risk stating an unverified claim as
confirmed. Per the operating instruction to prefer an honest gap over a
reconstructed claim, these are recorded here as:

**NOT RECOVERED** — five gpt-review findings from earlier in this session
that were confirmed against source at the time, covering material in payload
parts among p1–p6 (exact parts not recoverable). The full evidence, if
needed, is in the session transcript at
`/Users/mikko/.claude/projects/-Users-mikko-github--worktrees-mcp-2026-protocol/8198129a-cb14-4a80-bcc4-3390717c2845.jsonl`
(pre-compaction portion). Re-running gpt-review on the same payload parts
and re-verifying at source is the reliable way to recover these rather than
trusting a reconstructed summary.

### Findings raised, NOT source-verified (CANNOT-VERIFY — reason: session token budget exhausted before inspection)

- `tests/load/k6_gateway.js:315` (grok, MEDIUM/POSSIBLE) — dashboard load
  check treats any HTTP 200 as success.
- `tests/mik_7212_mrtr7_bridge_acs.rs:252` (grok, MEDIUM/UNLIKELY) —
  unscripted `FakeClient` sleeps 86400s instead of failing fast.
- `tests/mik_7272_conformance.rs:92,169,242,280` (grok, MEDIUM/CERTAIN) —
  matrix cites tests that do not assert the statements claimed.
- `tests/mik_7272_exploit_acs.rs:71` (grok, MEDIUM/CERTAIN) — the OTEL.1 test
  never leaves `TraceContext::to_meta`; does not touch `build_outbound_meta`.
- `tests/mik_7272_task_1_acs.rs:588` (gpt) — claims a fresh gateway per
  request; not checked against the harness.
- `tests/mrtr7_roots_acs.rs:63` (gpt) — missing timeout, possible CI hang.
- `tests/nfr_compat_2_stdio_client_session.rs:102` (gpt) — silently discards
  non-JSON stdout.
- `tests/nfr_compat_2_stdio_client_session.rs:50` (gpt) — HOME/cwd override
  may not isolate from `/etc/mcp-gateway/gateway.yaml`.
- `tests/nfr_compat_2_stdio_client_session.rs:96` +
  `tests/mik_7272_subscriptions_acs.rs:427` (gpt) — timeout said to restart
  on skipped lines/keepalive.
- `tests/nfr_obs_3_era_observability.rs:704` (gpt) — stale timestamp accepted
  via a `>=` assertion.

## Coverage explicitly not performed

A manual line-by-line spot-check pass was planned for seven priority files
but was **not performed** in this session, due to token-budget exhaustion:
`tests/mik_7212_mrtr7_bridge_acs.rs`, `tests/mik_7272_task_1_acs.rs`,
`tests/nfr_obs_3_era_observability.rs`, `tests/mik_7272_subscriptions_acs.rs`,
`tests/mik_7214_acs.rs`, `tests/gh462_config_preservation.rs`,
`tests/mik_7217_acs.rs`. These files received only reviewer-flagged-finding
inspection (per the CONFIRMED/CANNOT-VERIFY lists above), not an independent
read.

## Summary

- 6 findings fully source-verified this session (F1–F7, one of which — F3 —
  is double-vendor confirmed); 2 are HIGH and BLOCK 4.0.0 (F4: test target
  does not compile; F5: continuation-state test does not exercise the
  shared-Arc wiring it claims to). F6 is HIGH and recommended-blocking as a
  security-relevant coverage gap, not a compile/runtime failure.
- 5 gpt findings (F8–F12) were confirmed earlier this session but their
  detail did not survive a compaction boundary; marked NOT RECOVERED rather
  than reconstructed.
- 10 reviewer findings remain CANNOT-VERIFY, explicitly not silently dropped.
- 7 priority files did not receive an independent manual spot-check pass.
- Every one of the 12 ledger rows (6 gpt, 6 grok) has `process_status: ok`;
  no reviewer errored or timed out on this payload.

## Addendum — F4 disposition (verified 2026-09-08 by the release lead)

F4 re-verified at source: `src/gateway/session_lifecycle.rs:124` declares
`pub fn reap(&self, now: u64)`, and `tests/mik_7215_control4_reap_count_acs.rs:25`
binds its result and asserts `reclaimed == 2`. The finding holds.

It is not an unnoticed breakage. A concurrent session is mid-flight on this
exact surface — `docs/design/2026-09-08-control4-session-lifecycle-test-plan.md`
and `-wiring.md` — so the test is a failing-test-first RED for a `reap()`
signature that has not landed yet. Repairing it from outside that work would
collide with it. Routed to the control4 owner rather than fixed here; it still
blocks the release until `reap()` returns the count its test demands.
