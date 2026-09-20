# Simplification census

Evidence base for the post-4.0 simplification passes. Two sweeps: mechanical
duplication (bottom-up) and structural complexity (top-down).

Scanned tree: `origin/main` at `f35cf6e3`. 579 Rust files, ~250K lines —
~151K non-test source across 407 files, ~141K test lines across 295 files.

Confidence marks used below:

| Mark | Meaning |
|---|---|
| **V** | Verified — every site named was read |
| **I** | Inferred — one site read, the rest matched mechanically |
| **A** | Assumption — pattern-level, not yet confirmed at each site |

## Headline

**Mechanical duplication in production source is near-absent, and that is a
real result, not a failed sweep.** A structural-hash scan with identifiers and
string literals masked — so that two blocks differing only by a type name or a
constant still collide — found **zero** 15-line or 25-line blocks repeated
across three or more sites in 151K non-test lines. The two 15-line pairs it did
find are both intra-file (`src/trust/lab.rs:253`/`:327`,
`src/kubernetes/evidence.rs:27`/`:65`).

The duplication that exists is concentrated in **test harness setup**, and the
largest single item is a **half-finished migration**: a shared fixture builder
already exists and fifteen integration tests have not moved to it.

Total removable lines across the confirmed cleanups: **~708** (B1 510 + B2 90 +
B3 12 + B5 96), of which B1 alone is 72%. B4's ~380 lines are **excluded from
that total** — collapsing them is a change to a secret-redaction boundary, not a
line-count cleanup, and it should be budgeted as security work. Against 250K
lines the cleanup total is 0.3%. Anyone planning a simplification pass should
spend their budget on the top-down section, not this one.

## Sweep 1 — mechanical duplication

Ranked by (sites x lines saved).

### B1. Fifteen integration tests hand-build `AppState` past an existing builder — **V**, ~510 lines

`tests/common/mod.rs:91` already exposes the shared form:

```rust
pub async fn state(f: Fixture) -> (Arc<AppState>, tempfile::TempDir)
```

Only five files under `tests/` declare `mod common`. Fifteen others open an
`AppState { .. }` literal and set the same ~30 fields by hand. Brace-matched
spans, measured at five of the fifteen sites, run 34-38 lines
(`tests/gh452_session_owner.rs:87-120`, `tests/mik_7213_acs.rs:171-204`,
`tests/mik_7272_task_1_acs.rs:595-628`, `tests/nfr_obs5_flag.rs:111-144` all 34;
`tests/mik_7217_acs.rs:360-397` is 38). The ~510 total takes the floor of that
range across all fifteen. The shared fields (`gateway_key_pair`, `capability_dirs`,
`config_path`, `firewall`, `agent_identity_config`, `control_plane_store`,
`live_config`, `export_status`, `transparency_log`, `dashboard_bootstrap`,
`auth_config`, `key_server`, `tool_policy`, `mtls_policy`, `sanitize_input`,
`ssrf_protection`, `trust_configured_backends`, `inflight`, `agent_auth`) are
identical or differ only in an `expect` string.

Literal start lines:

| Site | `AppState {` | `gateway_key_pair:` |
|---|---|---|
| `tests/gh452_session_owner.rs` | 87 | 108 |
| `tests/mik_7212_mrtr_component_acs.rs` | 113 | 130 |
| `tests/mik_7213_acs.rs` | 171 | 190 |
| `tests/mik_7214_acs.rs` | 305 | 324 |
| `tests/mik_7215_acs.rs` | 268 | 289 |
| `tests/mik_7215_control3b_acs.rs` | 127 | 145 |
| `tests/mik_7217_acs.rs` | 360 | 381 |
| `tests/mik_7272_sub4_adr012_acs.rs` | 350 | 368 |
| `tests/mik_7272_sub4_three_routes.rs` | 186 | 204 |
| `tests/mik_7272_subscriptions_acs.rs` | 312 | 331 |
| `tests/mik_7272_task_1_acs.rs` | 595 | 614 |
| `tests/mik_7312_continuation_state.rs` | 60 | 78 |
| `tests/nfr_obs5_flag.rs` | 111 | 130 |
| `tests/nfr_obs_3_era_observability.rs` | 317 | 336 |
| `tests/nfr_obs_records.rs` | 148 | 167 |

Two further `AppState {` literals carry no `gateway_key_pair` line and were not
counted: `tests/stdio_tests.rs:109`, `tests/webui_management_tests.rs:127` and
`:212`. Confirm before folding them in.

**Why this is the top finding, not ordinary test repetition.** Tests that repeat
to stay readable are out of scope. This is not that: the abstraction was already
built and adopted by five files, and fifteen were left behind. The survivor is
`tests/common::state` — it is the newer form, it is the one a `Fixture`
parameter is designed around, and it is the only site that keeps the tempdir
alive by returning it. Every hand-written literal is a place a new `AppState`
field must be added by hand, which is why the block already drifts (`"RSA key
gen"` vs `"test key pair"` in the same `expect`).

**Collapse.** Move the fifteen onto `common::state`, widening `Fixture` for the
fields they actually vary. Do it in one pass, not file by file, so the field
list is proven complete.

### B2. Eighteen meta-tool definitions repeat the same six-field tail — **V**, ~90 lines

`src/gateway/meta_mcp_tool_defs.rs` builds 18 `Tool { .. }` literals. Each
repeats `output_schema: None`, `role: None`, `projection: None`, and writes the
same title string twice — once as `title:` and once as the argument to
`read_only_annotations(..)`:

```rust
name: "gateway_get_stats".to_string(),
title: Some("Get Gateway Statistics".to_string()),
...
output_schema: None,
annotations: Some(read_only_annotations("Get Gateway Statistics")),
role: None,
projection: None,
```

Sites (start of each repeated tail): `src/gateway/meta_mcp_tool_defs.rs:215`,
`:268`, `:404`, `:432`, `:455`, `:513`, plus twelve more `Tool` literals in the
same file — `rg -c 'output_schema: None,'` returns 18, `rg -c 'annotations:
Some\('` returns 19.

**Collapse.** One constructor — `Tool::meta(name, title, description,
input_schema)` — defaulting the three `None` tails and deriving the annotation
title from `title`. Saves ~5 lines per site and removes the class of bug where
the annotation title and the tool title drift apart.

### B3. `is_retryable` is duplicated verbatim across two retry modules — **V**, 12 lines

Identical six-variant `matches!`, byte for byte:

- `src/failsafe/retry.rs:96-107`
- `src/chains/retry.rs:179-195`

```rust
matches!(
    error,
    Error::Transport(_)
        | Error::JsonRpcRetryable { .. }
        | Error::TransportConnect(_)
        | Error::BackendTimeout(_)
        | Error::Http(_)
        | Error::Io(_)
)
```

`src/chains/retry.rs:180-185` carries a comment explaining why
`TransportPermanent` is absent and `TransportConnect` present. That comment
justifies the *contents* of the list, not the fact that the list exists twice —
so this stays a finding.

**Two occurrences would normally not justify an abstraction. This one is not an
abstraction.** `crate::failsafe` is already the public home of retry policy
(`src/failsafe/mod.rs:15` re-exports `RetryPolicy` and `with_retry`);
`chains::retry` should call it. The failure mode is concrete: add a retryable
error variant to one list and the chain executor silently stops retrying it.

### B4. Hand-written redacting `Debug` impls — **I**, ~48 sites, ~380 lines

Every impl spells out `f.debug_struct(..).field(..)..finish()` with a
`<redacted>` placeholder for each secret. Densest files: `src/oauth/client/mod.rs`
(7), `src/identity_propagation/mod.rs` (4), `src/config/features/security.rs` (4),
`src/config/features/auth.rs` (4), `src/security/message_signing.rs` (3),
`src/protocol/continuation.rs` (3), `src/oauth/storage.rs` (3),
`src/key_server/handler.rs` (3), `src/capability/executor/credentials.rs` (3);
then 2 each in `src/security/transparency_log.rs`, `src/key_server/store.rs`,
`src/identity_propagation/account_strategies.rs`, `src/gateway/oauth/jwks.rs`,
`src/gateway/oauth/agents.rs`, `src/gateway/meta_mcp/invoke.rs`,
`src/config/mod.rs`, `src/config/features/key_server.rs`,
`src/capability/definition/mod.rs`; and 1 each in
`src/personal_accounts/config/descriptor_debug.rs`,
`src/identity_propagation/token_exchange.rs`, `src/gateway/auth_quota.rs`.

One pair is verbatim across a config/domain split:
`src/gateway/oauth/agents.rs:51-64` and `src/config/features/auth.rs:243-256`
(same seven fields, same `redact_opt` closure, same order).

**Listed, not recommended as a flagship.** A `redacted_debug!` macro collapses
~8 lines per site, but this is a secret-redaction boundary: a macro that takes a
field list makes it easier to add a field and silently not redact it, and the
compiler will not catch that. If this is done, the macro must default to
redacting and require an explicit opt-in per visible field. Rank it below B1-B3
and treat it as a security change, not a cleanup.

### B5. Router test setup repeated at nine sites — **V**, ~96 lines

One 12-line harness block, colliding exactly (no masking needed) at **9 distinct
sites**: `src/gateway/router/tests.rs:120`, `:178`, `:234`, `:313`, `:402`,
`:461`, `:534`, `:602` and
`src/gateway/router/tests/meta_firewall_verdict.rs:177`.

A shorter 8-line prefix of the same block appears at six further offsets
(`src/gateway/router/tests.rs:104`, `:217`, `:296`, `:385`, `:444` and
`meta_firewall_verdict.rs:160`); those are the same setup detected one line
earlier, not extra sites, and they are not counted in the 96.

**Collapse.** One `fn router_under_test(..)` in the module. Lower value than B1
because it is contained in one module pair, so drift is visible in review.

### Below the bar — named so nobody re-derives them

- `src/registry/server_registry.rs` has ~16 eight-line runs (`:62`, `:72`, `:82`,
  `:92`, `:103`, `:113`, `:124`, `:134`, `:175`, `:185`, `:195`, `:205`, `:225`,
  `:246`, `:256`, `:267`, `:288`, `:349`, `:359`, `:369`, `:380`, `:503`, `:524`).
  These are entries in a `static REGISTRY: &[RegistryEntry]` table. Repetition is
  the data, not the code. **Not a finding.**
- `src/trust/lab.rs:253`/`:327` and `src/kubernetes/evidence.rs:27`/`:65` — two
  sites, ~15 lines each. Two occurrences; leave them.
- `src/gateway/ui/import.rs:94`, `:128` and `src/gateway/ui/backends.rs:148`,
  `:224`, `:272` — five sites of an 8-line shape, but they are axum handler
  preambles on distinct routes. **A**; check the trust boundary before touching.

## Sweep 2 — structural complexity

### T1. Four independent retry loops — **V**

One concept, four implementations, each with its own backoff and its own
retryability predicate:

| Implementation | Predicate | Consumer |
|---|---|---|
| `src/failsafe/retry.rs:69` `with_retry` | `:96` `is_retryable` | `src/backend/ops.rs:371` |
| `src/chains/retry.rs:118` `retry_step` | `:179` `is_retryable` | `src/chains/executor.rs:43` |
| `src/capability/executor/mod.rs:123` `send_with_retry` | inline | `src/capability/executor/jsonrpc.rs:186`, `:580` |
| `src/gateway/server/warmstart.rs` slow phase | `:100` `is_readiness_error` | warm-start only |

The fourth is **deliberately separate and says so** —
`src/gateway/server/warmstart.rs:82-98`:

> Deliberately enumerated rather than delegated to `chains::retry_step`, whose
> predicate rejects `BackendUnavailable` — the variant `start_entry` returns
> while a backend is mid-lifecycle. Since the slow phase runs indefinitely,
> anything not listed here must stop the loop [...]

That is real evidence on a real boundary. **Leave warmstart alone.**

The first two are the collapse: identical predicates (B3), and
`ChainRetryPolicy` (`src/chains/retry.rs:45`) duplicates the role of
`RetryPolicy` (`src/failsafe/retry.rs:16`). `crate::failsafe` is the survivor —
it is the one with a module-level public re-export (`src/failsafe/mod.rs:15`)
and the one wired into `FailsafeState` (`src/failsafe/mod.rs:29`, `:41`).
`src/capability/executor::send_with_retry` is worth a look in the same pass but
was not read end to end — **A**.

### T2. Two files carry a module's whole surface — **V**

| File | Lines | Shape |
|---|---|---|
| `src/gateway/meta_mcp/invoke.rs` | 5996 | 124 functions, only two of them public (`:2694`, `:2714`); capability calls (`:133`), continuation minting (`:374`), continuation redemption (`:594`) |
| `src/gateway/server/mod.rs` | 5002 | `struct Gateway` (`:312`) and a single `impl Gateway` (`:475`) holding 27 methods over ~2700 lines |
| `src/gateway/meta_mcp/tests.rs` | 5986 | tests for the above |

These are not duplication; they are the place a simplification pass buys the
most readability per edit. The natural seams are already visible in `invoke.rs`:
continuation minting and redemption (`:374`, `:594`) are a distinct concern from
tool invocation and would move to `src/gateway/meta_mcp/continuation.rs`
alongside the existing `src/protocol/continuation.rs`.

For `server/mod.rs`, the 27-method `impl Gateway` is the unit to split, not the
struct. Note the precedent already set in the same directory —
`src/gateway/server/warmstart.rs` (1086) and `src/gateway/server/support.rs`
(1028) are prior extractions from this file. Continuing that pattern is cheaper
than inventing a new decomposition.

### T3. The `config/features` mirror layer is deliberate — **V**, dropped

`src/config/features/*.rs` (2608 lines over 15 files) declares a `*Config`
struct for nearly every runtime type. It looks like duplication and is not.
Evidence, `src/security/transparency_log.rs:80-81`:

> Serialisation lives in `src/config/features/security.rs` alongside the other
> security configs; this struct is the "resolved" in-memory copy.

The mechanical discriminator confirms it rather than resting on the comment: the
config-side structs carry `Serialize, Deserialize` and the domain-side ones
often do not (`src/security/transparency_log.rs:82` is `#[derive(Clone)]` only),
and the conversion exists — `src/config/features/runtime.rs:147`
`RuntimeAvailabilityConfig::runtime_availability() -> RuntimeAvailability`,
constructing `src/runtime/provider.rs:72`.

**Do not collapse this layer.** The only cost it imposes that is worth paying
down is the naming: `TransparencyLogConfig` exists at
`src/config/features/security.rs:29` *and* `src/security/transparency_log.rs:83`
with the same name in both roles. Rename the wire-side one to
`TransparencyLogSettings` (or the resolved one to `ResolvedTransparencyLog`,
matching `ResolvedAuthConfig` at `src/gateway/auth.rs:94`) so a reader can tell
which is which. Pure naming, no behaviour.

### T4. Single-implementor traits — checked, all three are real seams

Grepped because the brief asks for abstractions that cost more than they buy.
All three one-implementor traits are used behind `dyn`, so they are injection
points, not pure cost:

- `BackendInvoker` — `src/gateway/input_bridge.rs:357`, used at `:381` as `&'a dyn BackendInvoker`
- `BridgeObserver` — `src/gateway/input_bridge.rs:371`, used at `:383` as `&'a dyn BridgeObserver`
- `TokenStore` — `src/key_server/store.rs:92`, used at `src/key_server/mod.rs:61` and `src/key_server/store.rs:245` as `Arc<dyn TokenStore>`

**No finding.** Recorded so the next sweep does not re-open them.

### T5. Name collisions that cost reading time, not lines — **V**

Same name, different concept, no shared code. Renaming is the whole fix.

| Name | Sites | Reality |
|---|---|---|
| `RegistryEntry` | `src/registry/mod.rs:23`, `src/registry/server_registry.rs:38`, `src/tool_registry.rs:51` | Capability-registry entry, curated-MCP-server static entry, tool-registry entry. Three different things. |
| `Finding` + `Severity` | `src/security/response_inspect.rs:33`, `src/security/firewall/mod.rs:263` | Two severity scales in one module tree — `Critical` in one, `High/Medium/Low` in the other. |
| `ProfileRegistry` | `src/tool_profiles/mod.rs:170`, `src/routing_profile/mod.rs:331` | Tool profiles vs routing profiles. |
| `SearchResult` | `src/ranking/mod.rs:28`, `src/semantic_search/mod.rs:49` | Ranked result vs embedding hit. |
| `Registry` | `src/registry/mod.rs:139`, `src/protocol_revision_telemetry.rs:162` | Capability registry vs telemetry counter registry. |
| `CacheConfig` | `src/capability/definition/mod.rs:747`, `src/config/features/cache.rs:19` | Per-capability cache vs gateway response cache. |

The `Severity` pair is the one worth acting on: both live under `src/security/`,
both are serialized, and a reader who assumes one scale while looking at the
other misreads a security verdict.

## Findings examined and dropped

Recorded with evidence so they are not rediscovered.

- **`src/security/message_signing_v2.rs` is not a half-finished migration.** It
  is a `#[path]` submodule (`src/security/message_signing.rs:41-42`,
  `mod v2;`) holding 123 lines that extend `impl MessageSigner` with
  `sign_json_rpc_response_at` (`:55`). One type, one implementation, split
  across two files. Both sides are live. The `v2` name is misleading; a rename
  to `message_signing_jsonrpc.rs` costs nothing and removes the false signal.
- **`src/gateway/server/warmstart.rs:100` `is_readiness_error`** — documented
  deliberate divergence, quoted in T1.
- **`TransparencyLogConfig` declared twice** — documented deliberate split,
  quoted in T3.
- **262 single-expression functions** found by `ast-grep -p 'fn $NAME($$$ARGS)
  -> $RET { $RECV.$M($$$A) }'` are overwhelmingly small pure helpers and
  method-chain one-liners (e.g. `src/gateway/auth.rs:46`
  `bearer_token_fingerprint`, `src/protocol_revision_telemetry.rs:816`
  `counter_delta`), not a pass-through layer. The hypothesis that
  `router/handlers.rs -> backend_handlers.rs -> server` is a forwarding stack
  was tested and **did not hold**: `handlers.rs` matches are request-parsing
  helpers, not forwards. No layer-collapse finding.
- **`src/registry/server_registry.rs` repeated runs** — static data table, see
  Sweep 1.

## Method

Reproducible, so the next pass can re-measure rather than re-argue.

- Structural duplication: 8/10/15/25-line sliding windows, whitespace
  normalized, string literals replaced with a token and every identifier masked
  to a single symbol, then hashed. Masking is what makes two blocks differing
  only by a type name or a constant collide; an unmasked scan reports a clean
  tree and is wrong.
- `#[cfg(test)]` handling: the attribute appears mid-file on `mod tests;`
  declarations, so cutting each file at its first occurrence silently drops
  production code — it reduced `src/gateway/server/mod.rs` from 5002 lines to 8.
  Test blocks must be brace-matched and skipped, not truncated at.
- Structural patterns: `ast-grep` (`sg`) for function shapes; `rg` for names,
  derives and call sites.
- Every site in this document was opened. Counts marked **I** were produced by
  `rg -c` after reading one representative site; counts marked **A** were not
  confirmed per site and say so.
