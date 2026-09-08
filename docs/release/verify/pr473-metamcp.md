# PR #473 unreviewed-slice review — `src/gateway/meta_mcp/` shard

Shard: the eleven `src/gateway/meta_mcp/` files of the PR #473 unreviewed slice,
plus the two source files their findings reach (`src/idempotency.rs`,
`src/protocol/mrtr.rs`, both read as evidence, neither in the payload).

Pinned revision: `BASE=c3626cf8`, `HEAD=60b138bb10a869703254eae2fe500f055d96f8d7`.

## Payload

Built from the pinned SHAs, not the worktree. The payload exceeded the ~150KB
brief limit and was **split in two**; each half was reviewed by both vendors on
identical material, and the two halves together are the whole shard.

| payload | files | insertions | deletions | bytes | sha256 |
|---|---:|---:|---:|---:|---|
| whole shard (`payload.diff`) | 11 | 5,995 | 575 | 319,550 | `7e2025a36258394ed5117c88e35441605592dbbb5109e27531f4f7f559b084e0` |
| half A — source (`pA-src.diff`) | 8 | 2,512 | 326 | 166,594 | `01b75623fd0e88441bc7e1d2ecd3f74b7246492c60c1f1fda388c41d05617180` |
| half B — tests (`pB-tests.diff`) | 3 | 3,483 | 249 | 152,956 | `7c1341632d2a2a3ccef3e65165a13811a492bcc87ea029c9b3fe40ac0a1e455a` |

Files: `authz_tests.rs`, `invoke.rs`, `mod.rs`, `prompt_cache.rs`, `resources.rs`,
`search.rs`, `spec_preview.rs`, `support.rs`, `surfaced.rs` (half A);
`tests.rs`, `trace_correlation_tests.rs` (half B). `authz_tests.rs` and
`surfaced.rs` carry test code but sit in half A by size.

## Ledger rows

Four rows, all `process_status: ok`. `material_sha256` is the brief's corrected
digest — `{ printf '\0'; cat payload.diff; } | sha256sum` — and `material_bytes`
is payload bytes + 1, as the brief's correction predicts.

| leg | ts (UTC) | verdict | material_sha256 | material_bytes | run file |
|---|---|---|---|---:|---|
| gpt / half A | 2026-09-08T16:27:13Z | SHIP-WITH-FIXES | `7a1573ae…8fbccc6e` | 166,595 | `gpt-20260908T162225Z-70144.md` |
| gpt / half B | 2026-09-08T16:24:42Z | SHIP-WITH-FIXES | `cf99892c…5b61e4b01b` | 152,957 | `gpt-20260908T162235Z-76133.md` |
| grok / half A | 2026-09-08T16:31:54Z | SHIP-WITH-FIXES | `7a1573ae…8fbccc6e` | 166,595 | `grok-20260908T162229Z-72734.md` |
| grok / half B | 2026-09-08T16:32:53Z | SHIP-WITH-FIXES | `cf99892c…5b61e4b01b` | 152,957 | `grok-20260908T162243Z-78432.md` |

Both halves matched both vendors' digests exactly, so every verdict is bound to
material this shard actually built. The `head` field is non-binding and differs
between vendors (`e68082bc` vs `0a1af1fe`) because the wrapper stamps it from
repo HEAD at launch on a shared branch other sessions were committing to.

## Tally

| verdict | count |
|---|---:|
| CONFIRMED | 13 |
| DEAD | 1 |
| CANNOT-VERIFY | 7 |

CANNOT-VERIFY = 5 grok findings outside this shard's payload (see the
out-of-shard section) plus 2 reachability residuals named inside confirmed
findings A2 and A11.

## Blocking a 4.0.0 release

Five findings block. Each is CONFIRMED at source and each breaks something the
PR itself claims to deliver.

### BLOCK-1 — interim envelopes are stringified before they reach the client
`src/gateway/meta_mcp/mod.rs:1743`, `src/gateway/meta_mcp_helpers.rs:753-762`
(gpt half A). CONFIRMED. `gateway_invoke` and single-tool `gateway_execute` pass
the invocation result through `wrap_tool_success`, which serialises the whole
envelope into a text block. `inputRequests`, `requestState` and `resultType`
survive only as characters inside that string, so a protocol client cannot
recognise an input-required round, let alone continue it. The interim path is
what this PR adds; delivering it through a wrapper that hides it is the defect
that makes the feature unusable rather than merely imperfect.

### BLOCK-2 — every chain and playbook step shares one idempotency key
`src/gateway/meta_mcp/invoke.rs:1227-1231`, `src/gateway/meta_mcp/mod.rs:1585`
(gpt half A). CONFIRMED. The client-supplied key is inherited unchanged by each
step, so distinct steps collide on one key and identical steps replay a cached
result instead of executing. A multi-step protected operation therefore stops
partway or silently skips an action — the exact failure idempotency exists to
prevent.

### BLOCK-3 — `_meta` is injected into backend tool arguments
`src/gateway/router/handlers.rs:1183-1187` ->
`src/gateway/meta_mcp/mod.rs:603` -> `src/gateway/meta_mcp_tool_defs.rs:867-872`
-> `src/gateway/router/helpers.rs:234-250` (gpt half A). CONFIRMED. `is_exposed` returns true for any name that is
not a governed meta-tool name (`meta_mcp_tool_defs.rs:870`), so
`exposes_meta_tool` answers true for backend tool names too, and
`merge_client_meta` then inserts the client's `_meta` object into a surfaced
backend tool's arguments (`helpers.rs:239-250`). Two consequences:
strict backend schemas reject the call, and — worse — the added field can shift
the continuation digest, so a legitimate continuation fails its own integrity
check.

### BLOCK-4 — a released reservation is completed anyway, with an empty fingerprint
`src/idempotency.rs:355-358` and `:150-151`, driven from
`src/gateway/meta_mcp/invoke.rs:1836-1837` (gpt half A **and** grok half A —
the only finding both vendors raised independently). CONFIRMED.
`IdempotencyReservation::complete` ignores the `settled` flag, so a dispatch
error that has already called `release()` still runs the common `complete()`
tail. The stored entry is `Completed` with an empty fingerprint, and the
empty-fingerprint wildcard at `idempotency.rs:150-151` makes it match any
subsequent request on that key for the full 24-hour window: a later, unrelated
call gets the earlier error back instead of a mismatch. Cross-vendor
corroboration on a 24-hour-lived wrong answer is why this is blocking rather
than merely NOW.

### BLOCK-5 — the backend's raw `requestState` leaks in `structuredContent`
`src/gateway/meta_mcp/invoke.rs:1585-1602` with `:145-236` (this shard's own
source read, not a reviewer finding). CONFIRMED, with a stated nuance.
`enforce_output_schema` runs inside `dispatch_to_backend` (`invoke.rs:2652`)
**before** the MRTR envelope is minted at `:1585-1602`, despite the higher line
numbers. When a schema-bearing tool returns no `structuredContent` and its
content is not a single JSON-parsing text item,
`extract_output_validation_target` returns `None`, and `apply_validated_output`
(`:214-236`) then inserts the **entire MCP envelope** — including the backend's
raw `requestState`, `resultType` and `inputRequests` — under
`structuredContent`. The mint at `:1602` replaces only the top-level
`requestState`; the copy inside `structuredContent` keeps the backend's own
string. That directly breaks the invariant this PR states for itself at
`invoke.rs:1574-1580`: "the backend's own requestState never reaches the
client".

NUANCE, stated because it changes who owns the fix: `apply_validated_output`,
`extract_output_validation_target` and `enforce_output_schema` produce zero
changed lines in this payload — they are pre-existing code. `mint_continuation`
adds two. So this is pre-existing behaviour that **the PR's new interim path
makes reachable**, not a defect the PR wrote. Side effect worth naming
separately: for any schema-bearing tool whose result has a single non-JSON text
item, `apply_validated_output` overwrites that human-readable text with a
pretty-printed JSON dump — a plain-text regression surface with the same
pre-existing caveat.

## Confirmed, not blocking

All from gpt half A unless noted. Line numbers are the reviewer's; each was
read at source before being relayed.

| # | severity | where | defect | residual |
|---|---|---|---|---|
| C1 | CRITICAL / POSSIBLE | `invoke.rs:1421` | dropping the invocation mid-dispatch releases the idempotency reservation even though the backend may already have acted, so a retry duplicates the external side effect | the cancellation path itself is CANNOT-VERIFY — the release is confirmed, that a real client drop reaches it was not established |
| C2 | HIGH | `invoke.rs:1513` | an `input_required` result whose `inputRequests` fails to parse skips both continuation sealing and the capability check, and is delivered carrying the backend's raw `requestState` | — |
| C3 | MEDIUM | `invoke.rs:404` | a failed continuation mint returns without releasing `payload.hold_key`, so the in-flight slot stays occupied until expiry | — |
| C4 | MEDIUM | `invoke.rs:1587` | a continuation minted before the response-contract and inspection gates keeps its slot when those gates refuse delivery | — |
| C5 | MEDIUM | `invoke.rs:2215` | context-integrity transformation keeps the input-required handle while stripping the structured questions needed to answer it, so the round can be neither completed nor abandoned cleanly | — |
| C6 | MEDIUM | `invoke.rs:1878-1885` | a modern HTTP call with no incoming trace context selects `Some("")` as its transparency-log correlation key instead of the generated trace ID | whether production actually presents `Some("")` rather than `None` is CANNOT-VERIFY from the diff; the test half (below) shows the new test does not pin it either way |

C2, C3, C4 and C6 all sit on the interim/continuation path this PR introduces.
C1 and C5 are the two whose blast radius reaches outside it.

## Test half

Both vendors reviewed `tests.rs` and `trace_correlation_tests.rs`; each found
one defect the other missed.

**T1 — the modern trace-correlation test cannot fail on the defect it names.**
`trace_correlation_tests.rs:165-168` (gpt half B, and grok half B
independently). CONFIRMED. The test calls
`meta.invoke_tool(&args, None, &ctx())` — `session_id` is `None`, while the
production modern-HTTP path presents `Some("")`. The `(None, Some(session))`
arm at `invoke.rs:1882-1885` is therefore never exercised with an empty string,
so the empty-correlation-key defect C6 describes can hold in production while
this test stays green. Coverage gap, not a wrong assertion.

**T2 — `b07` asserts a success the profile it builds makes impossible.**
`tests.rs:4704` (grok half B only). CONFIRMED, statically. The fixture
`meta_with_echo_hidden_by_profile` (`tests.rs:4649-4665`) installs a default
routing profile whose `deny_tools` is `["echo"]`. `invoke_tool` runs
`profile.check(server, tool)` at `invoke.rs:1136-1139` and returns
`Error::Protocol` when `tool_filter` refuses the name
(`src/routing_profile/mod.rs:139-144`). The test then asserts
`invoked.is_ok()`. The assertion cannot hold: the deny-list that hides `echo`
from the list is the same filter the invoke passes through. The test is
gated behind `#[cfg(feature = "spec-preview")]`, so it fails only in a
feature-enabled run — which is what `cargo test --all-features` is.

Not run: the suite itself. This shard had read-only access and did not compile
or execute `cargo test`. T2 in particular is a static proof of an impossible
assertion, not an observed failure — worth 60 seconds of a build to confirm
before anyone acts on it.

## Dead on inspection

**D1 — "authenticated callers without a verified identity share cache and
idempotency entries."** `invoke.rs:1208-1215`, raised CRITICAL by gpt half A.
DEAD. `CallerIdentity::select` (`support.rs:105-115`) returns `None` only when
both the cache binding and the verified subject are absent — a caller the
operator has deliberately chosen to run unauthenticated. Any caller with either
one is tagged, and the two arms (`Binding`, `Subject`) are distinct variants, so
they cannot collide with each other. The pooling the finding describes is the
documented behaviour for genuinely unauthenticated callers, not a leak between
authenticated ones. The team lead already held this as known context; it is
recorded here so it is not re-derived a third time.

## Out of shard — relayed, NOT verified

grok half A left the submitted payload and reviewed files this shard was never
given. Those five findings are **not about this shard**, were **not checked at
source**, and must not be counted as this review's coverage. They are relayed
only so they are not lost, and whoever owns those files should treat each as an
unverified lead.

| where | claim |
|---|---|
| `src/oauth/metadata.rs:134` | authorization-server discovery follows redirects, then compares `metadata.issuer` to the *original* URL, so a redirected body can satisfy the new RFC 8414 §3.3 check |
| `src/oauth/client/mod.rs:891` | `token_endpoint` / `authorization_endpoint` / `registration_endpoint` from discovery are used as-is over a redirect-following client, with no HTTPS-or-loopback rule like `reject_cleartext_credentials` |
| `src/security/firewall/mod.rs:361` | `check_request` returns `Allow` when `scan_requests` is false, so the tenant guard and the principal budget never run even when those sections are enabled |
| `src/oauth/metadata.rs:219` | protected-resource discovery never checks `metadata.resource` against the URL it was fetched from, and that field is then sent as the RFC 8707 audience |
| `src/oauth/client/mod.rs:846` | the authorization code is written to the debug log in cleartext, beside the new mix-up check |

## Improvements (relayed, unverified, non-blocking)

From grok half A: delete the public `mark_in_flight` and the empty-fingerprint
wildcard now that `admit` is the live path (`idempotency.rs:150`); cap the
tenant-string length before `record` (`firewall/principal_window.rs:109`); stop
allocating a `HashSet` per `record` (`principal_window.rs:161`). The first one
is BLOCK-4's own wildcard and would close it by deletion rather than by patch.

From both vendors on the test half: exercise successful recovery after an
undeclared-capability refusal (`tests.rs:3577`); replace whole-log substring
checks with parsed-field assertions (`trace_correlation_tests.rs:119`); return
the `NamedTempFile` guard instead of `mem::forget`-ing it
(`trace_correlation_tests.rs:69`); extract the Strip-policy backend fixture the
five transform tests each rebuild (`tests.rs:2897`, duplicated at 3033, 3111,
3190, 3261); pin membership rather than builder order in `b10`
(`tests.rs:4611`); build `MetaMcpCallerContext` from `allow_all_ctx()` plus the
differing field instead of restating it (`tests.rs:32`).

## Coverage — what this review did not do

- **Nothing was fixed.** This is a review pass; every finding above is for the
  operator to dispose of.
- **The suite was never run.** Read-only access, no build. Every verdict is a
  source read. T2 especially deserves a real `cargo test --all-features`.
- **The payload was split.** Each half was reviewed by both vendors, but no
  reviewer saw the whole shard at once, so a defect whose two halves straddle
  the source/test boundary could survive both legs.
- **Five grok findings were out of shard** and are recorded as such above, not
  as coverage.
- **Two reachability residuals stand** inside C1 (does a client cancellation
  actually reach the release?) and C6 (does the modern router present `Some("")`
  or `None`?). Both need a runtime observation this shard could not make.
