# ASI10 multi-agent collusion detection: design (4.0)

Status: FINAL r5 (rounds 1-3 + delta review applied; maintainer decisions recorded). Owner decision (binding): build ASI10 collusion detection for 4.0;
defined narrowly enough to be falsifiable, stating where no sound definition exists.

## 1. What can and cannot be detected (verdict first)

**Not possible at a gateway:** sound detection of *adaptive* collusion. Agents can coordinate
out of band, by timing or tool choice, or by re-encoding. ASI10 is not claimed COVERED.

**Buildable and falsifiable for 4.0: verbatim cross-principal relay.** Sensitive data delivered
to principal A leaves through an egress tool called by principal B != A, who never got it from
that source. Per-principal controls (`firewall/mod.rs:412-499`) see A and B each as ordinary.

## 2. Existing mechanisms reused (source file:line at b22970a7a)

- **Control identity.** `CallerKey`, defined in the HARDENED design and built in #1785 plus
  HARDENED increment 3. Today the direct route keys every caller as `direct:{backend}`
  (`router/backend_handlers.rs:110-120`), so `A != B` can never hold there. **ASI10 therefore
  depends on #1785.** Colluders behind one credential with no subject count as one principal,
  which is out of scope by definition.
- **Source sensitivity.** Context-integrity findings `GuardedMaterial`, `PersonalData` and
  `FinancialData` (`context_integrity/mod.rs:128-150`), evaluated for live `gateway_invoke`
  results (`config/features/security.rs:527`). Direct-route results are not classified today;
  increment 2 calls the same classifier there.
- **Egress signals.** None is usable:
  - `ToolCategory::classify` (`data_flow.rs:65-95`) and the prepared hints
    (`backend/annotations.rs:25-39`) mark search and fetch tools read-only, and those tools still
    send their arguments out;
  - `open_world_hint` is inferred true for almost every tool (`:103-118`).
  Egress is therefore "any backend call", minus the operator's `non_egress` globs (section 3).
- **Delivery point.**
  - Meta route: after the response pass (`router/response_pass.rs:34-85`), which can replace a
    blocked result.
  - Direct route: after `scan_direct_backend_response` (`router/backend_handlers.rs:1233-1264`),
    on the final value that is actually sent. That scan redacts but never refuses, so recording
    reads the redacted value.
  - `ResponseCorrelation` (`security/response_policy.rs:23-28`) gains a crate-internal
    `caller_key` field. That is not a visibility widening.
- **Request chokepoint.** `Firewall::check_request` (`firewall/mod.rs:362-499`), on both routes.
- **Not reused: `PrincipalWindow`.** It keeps 4,096 observations per key and can only count, not
  list. The detector's own state (section 3) is bounded, in process only, and adds no store.

## 3. Definition (signals, thresholds, action)
**Fingerprint.** Text is NFC-normalized and whitespace-collapsed, then winnowed:
- k = 48-char k-grams at **every offset**, 64-bit keyed hash (SipHash, per-process random key);
  keep the minimum of each window of w = 16 hashes (standard winnowing; offset-independent).
- Winnowing property: a shared substring of at least k + w − 1 = 63 chars yields at least one
  common fingerprint when its k-gram hashes are distinct (no two-match floor is claimed).
- Results keep at most 1,024 fingerprints (~8 KB of text; rest counted as `source_truncated`);
  egress arguments are fingerprinted in full within the request-size limit.

**State.** `fp -> {tuples: [(source_id, principal_id, sensitive, last_seen)], principals: n}`,
with the ids stored as keyed 64-bit hashes.
- Tuples are deduplicated per (source, principal), keeping the latest time. A fingerprint holds
  at most 8 tuples. When a 9th arrives, it becomes `Saturated`: no tuples are evicted, and it
  never counts toward a finding (counted in a metric). Eviction could otherwise erase B's
  same-source excuse and turn an excused copy into a block.
- Once `common_principals` distinct principals hold a fingerprint, it becomes `Common` and stops
  growing.
- At most 250,000 fingerprints: 250k × (8 + 8 × 25 + ~64) ≈ 68 MB. At the cap the oldest
  fingerprint is evicted and counted. Entries expire after `window_secs`, swept on access.

**Receipt event (every delivered result).** Record (T, A, sensitive) for each fingerprint, where
`sensitive` means T had a sensitive context-integrity finding or is listed in `sources`. Every
delivered result is recorded, not just sensitive ones, so the same-source excuse works whichever
side is delivered first.

**Egress event.** Principal B calls **any** backend tool U. Read-only hints cannot be trusted
here: a search or fetch tool sends its arguments to the outside (`annotations.rs:39`,
`data_flow.rs:65`). The only exceptions are tools the operator lists in `non_egress` (globs).

**Relay finding.** Raised when at least `min_matches` (default 2) distinct fingerprints of B's
arguments each satisfy, within `window`:
- the fingerprint is held as (T, A, sensitive = true) with A != B;
- it is not held as (T, B, any) for the same T;
- it is not `Common`.

The excuse deliberately does not cover content from another source: writing to a shared store
and reading it back still counts. Winnowing gives **no** hard length floor. Repetitive text can
share one hash, and short repeated matches can yield two. Row 7 therefore tests typical
behaviour, not a bound.

**Action** (the enum `collusion.action`):
- `off` (default): no state is kept.
- `observe`: emit the audit finding `ScanType::CollusionRelay` (Medium; digests of A and B, T, U
  and the count, never content) and increment `mcp_gateway_collusion_relay_total{action}`.
- `block`: the same, and B's call is refused with `-32002` before dispatch
  (`handlers.rs:1436-1440`).

Unkeyed egress: under `block` the collusion check refuses it itself; under `observe` it is
counted and allowed (so `observe` never breaks an auth-off gateway). Independent of the
anomaly detector, whose unkeyed refusal (`firewall/mod.rs:415-446`) exists only when anomaly is on. New module
`src/security/firewall/collusion.rs`.

## 4. False positives

| Source | Handling |
|---|---|
| Real collaboration: A shares a doc and B posts it | Content alone cannot tell this from collusion. `observe` is the default rollout; `block` is opt-in; `allowed_flows` allowlists (source, egress) pairs. |
| Public or boilerplate text | `common_principals` (5) |
| B fetched it itself from the same source | the same-source excuse |
| Short shared phrases or IDs | 48-char k-grams and `min_matches: 2` (typical, not a bound) |
| One shared account | one principal cannot relay to itself (identity: HARDENED M2) |
| Writes to internal stores (memory, notes), now egress by default | list them in `non_egress`; `observe` rollout shows which |

Findings carry T, U and principal digests (never content), enough to decide an allowlist
entry; the metric is the rate to watch before `block`.

## 5. Limits and evasion (these keep ASI10 PARTIAL)

- **Missed:** re-encoding, paraphrase, splits under about 63 chars, and anything past a result's
  first 1,024 fingerprints (`source_truncated`).
- **`Common` can be poisoned:** colluders who control `common_principals` identities can each
  receive the content and so promote it to `Common`, exempting B. This is accepted: excluding
  sensitive tuples from `Common` would bring back the boilerplate false positives.
- **Per replica only:** A and B on different replicas are never correlated.
- **Flush:** every delivered result is recorded, so ordinary traffic fills the 250k map; the
  effective window is `min(window_secs, 250,000 / total fingerprint rate)`: about 244 large
  (1,024-fingerprint) results from anyone evict the oldest evidence. Evictions are counted.
- **Depends on #1785 and HARDENED increment 3.** Until both land, the direct route has a single
  identity, so the relay rule cannot fire there.

## 6. Config surface (names approved, M1) and failure modes

`security.firewall.collusion`:
- `action`: `off | observe | block` (enum, default `off`)
- `window_secs`: 600
- `min_matches`: 2
- `common_principals`: 5
- `sources`, `non_egress`, `allowed_flows`: globs; `allowed_flows` takes `[{source, egress}]`

The HARDENED posture does not force this (M2). When `action != off`, startup refuses if:
- the `firewall` feature is absent or `firewall.enabled` is false (`firewall/mod.rs:371`);
- a glob is invalid;
- `min_matches` is 0;
- `common_principals` is below 2.

## 7. Migration / UPGRADING

Default `off`: nothing changes. UPGRADING and CHANGELOG `[Unreleased]` describe the opt-in. The
OWASP ASI10 row says "verbatim cross-principal relay detection (opt-in)" and stays PARTIAL.

## 8. Test table

| # | Rule | Test name | Mutant that must redden it |
|---|---|---|---|
| 1 | A reads, B egresses the content: finding (meta route, real calls) | `relay_a_to_b_detected` | skip recording |
| 2 | `block` refuses with `-32002` before dispatch | `relay_blocked_before_dispatch` | treat block as observe |
| 3 | a copy with a one-char prefix, and an excerpt embedded mid-payload, both match | `prefixed_copy_detected`, `embedded_excerpt_detected` | fixed stride / global bottom-N sampling |
| 4 | B's own copy from the same source is excused | `same_source_self_copy_excused` | drop the excuse |
| 5 | a shared-store relay is not excused | `shared_store_relay_not_excused` | excuse any source |
| 6 | common content is skipped | `common_content_skipped` | drop the `Common` state |
| 7 | exactly one matching fingerprint does not flag; two do | `one_match_not_flagged`, `two_matches_flagged` | `min_matches` 1 |
| 8 | one principal never flags | `self_relay_not_flagged` | drop A != B |
| 9 | window expiry (`record_at` arithmetic, no sleep) | `relay_outside_window_not_flagged` | ignore expiry |
| 10 | repeated observations dedupe; at the cap the oldest is evicted and counted | `dedup_per_pair`, `cap_evicts_oldest_counted` | append duplicates / evict silently |
| 11 | only delivered values recorded (meta after response pass; direct after its scan, redacted value) | `undelivered_result_not_recorded`, `direct_records_redacted_value` | record before the pass / record raw |
| 12 | a read-only-hinted search tool carrying A's content is egress; a `non_egress` tool is not | `read_only_search_is_egress`, `non_egress_listed_skipped` | honour read-only hints / ignore the list |
| 13 | unkeyed egress: refused under `block`, counted and allowed under `observe`, with anomaly off; allowlisted flow passes | `unkeyed_egress_block_refused`, `unkeyed_egress_observe_allowed`, `allowed_flow_not_flagged` | rely on anomaly / refuse in observe / ignore allowlist |
| 14 | findings carry no content; `off` keeps no state | `finding_has_no_content`, `off_records_nothing` | put text in `matched` / record while off |
| 15 | direct route (after #1785) | `direct_route_relay_detected` | wire the meta route only |
| 16 | `action != off` with `firewall.enabled: false` refuses to start | `collusion_needs_enabled_firewall` | allow start |
| 17 | same-source excuse holds when B's non-sensitive copy was delivered first | `excuse_holds_when_b_first` | record sensitive results only |
| 18 | a 9th tuple saturates the fingerprint: B's excuse is not evicted, no finding | `saturated_fingerprint_never_flags` | evict the oldest tuple |

## 9. Out of scope

Covert and timing channels; paraphrase; cross-replica state; backend-caller collusion;
correlation across chained gateways (ASI07 gives provenance, not correlation).

## 10. Maintainer decisions (2026-09-28)

- M1: names approved (`security.firewall.collusion.*`, `mcp_gateway_collusion_relay_total`,
  `CollusionRelay`).
- M2: hardened does not force `observe`.
- M3 (2026-09-28): ASI10 stays PARTIAL for 4.0. The detector's PR updates the OWASP ASI10 row
  with the retention limits and observe-by-default/opt-in block; until then the row lists only
  controls that exist.

## 11. Build increments (after #1785 and HARDENED increment 3)

1. Pure module: winnowing, bounded state and the relay predicate (rows 3-10, 14, 17, 18).
2. Wiring: delivered-value recording on both routes with classification; the cached-definition
   egress lookup; the check in `check_request` (rows 1, 2, 11-13, 15, 16).
3. Allowlist, metrics, docs and the OWASP row.

## 12. Review dispositions (all verified at source; all ACCEPTED; test rows in brackets)

r1: stride missed shifts; winnowing [3]. Bottom-32 dropped excerpts; per-window min [3]. Window
could not list pairs; own dedup state [10]. Disabled firewall accepted; refused [16].
`direct:{backend}` A == B; needs #1785 [15]. Undelivered recorded; delivery only [11]. r2: cold
cache, Admin, `openWorldHint` inferred true (`annotations.rs:103-118`) [12]; tuple overflow
[18]; false 79-char claim [7]; sensitive-only broke excuse [17]; direct route records delivered
value (`backend_handlers.rs:1233`) [11]. r3: read-only tools leak (`annotations.rs:39`); all
tools egress but `non_egress` [12]. Eviction erased excuse; `Saturated` [18]. Unkeyed guard
independent of anomaly [13]. One-match test [7]. `Common` poisoning disclosed (5). Improvements:
`CollusionRelay` -> `-32002` on both routes (increment 2); `Common` = spread, not public; hard
bound: nothing under 48 chars matches; ReadOnly corner moot. Seat A = first reviewer; B =
fallback second seat (preferred second seat: HTTP 429 in rounds 1-2; it reviewed round 3).

## 13. Increment 2 wiring (addendum r2, 2026-09-30; scope 2a ruled by the coordinator)

The pure module landed in #2433. This section records how increment 2 wires it in, measured
against the release line at 6198c9e84. Where it disagrees with §2, this section wins. Revision r2
addresses review round 1.

**Corrections to §2.**
- No `CallerKey` type exists. The control key is the string from `identity::caller_key`
  (`router/identity.rs:350`).
- When there is no identity, each route falls back before the firewall sees the call: meta uses
  the session id (`handlers.rs:1390-1392`), direct uses `direct:{backend}`
  (`backend_handlers.rs:58-72`).
- The router and `MetaMcp` build separate `Firewall` instances (`server/mod.rs:1235`, `:1788`).
- The router's pre-check misses `gateway_run_playbook` and chains. Every meta backend call instead
  passes through `MetaMcp::accounted_dispatch` (`invoke.rs:3370`).
- The direct delivery point is `DirectRouteGuards::after_dispatch` (`direct_guards.rs:45-83`), but
  idempotency cache hits return before it runs (`backend_handlers.rs:1042-1045`).

**One detector.** `Gateway` builds one `Arc<CollusionDetector>` when `action != off` and injects
it into both firewalls with a crate-internal `with_collusion`. Recording and checking therefore
share state.

**Caller.** A crate-internal `RelayCaller` is either `Keyed(key)` (`caller_key` was non-empty) or
`Unkeyed(fallback)`. It is decided before the fallback:
- meta: in the router, then carried to dispatch as a `pub(crate)` field on
  `MetaMcpCallerContext`, which playbook steps inherit (`support.rs:391-404`);
- direct: in `direct_control_identity`.

**Egress check (rows 2, 12, 13).** `Firewall::check_relay(caller, server, tool, args)` runs:
- meta: in `accounted_dispatch`, before dispatch, on the resolved arguments. This covers invoke,
  execute, playbooks and chains in one place.
- direct: next to `check_request`.

The check:
1. A `server:tool` matching `non_egress` is skipped.
2. Under `block`, `Unkeyed` is refused, whether or not anomaly detection is on. Under `observe`,
   an `Unkeyed` egress increments an internal counter (the exported metric is increment 3) and is
   then checked under its fallback key. It is never refused.
3. Otherwise `check_egress_at` runs on the argument text. A finding becomes a `CollusionRelay`
   `Finding` (Medium) whose `matched` is `"{T} -> {U}"` plus the A/B digests and match count, never
   content. If T's name has been evicted from the name map, `matched` carries T's digest instead.
4. Under `block` the call is refused with `-32002`. On meta this is an `Error` mapped to `-32002`,
   kept intact through playbook error wrapping; on direct it goes through the existing
   `is_anomaly_block` branch.
5. `is_anomaly_block()` keeps its SequenceAnomaly/High test and adds "or every finding is
   `CollusionRelay`".
6. The verdict is audited.

**Recording (rows 1, 11, 15, 17), staged then committed.**
- meta: `accounted_dispatch` stages `(caller, "server:tool", value)` for each successful backend
  result, after that call's own response gates (context integrity included), into a per-request
  `RelayReceipts` collector (a `pub(crate)` field on `MetaMcpCallerContext`). The router commits
  the collector after `finalize_response_after_inspection` only if the delivered response is not
  an error or refusal; a refused delivery commits nothing (row 11). Each stage carries its own
  source, so a chain or multi-target response is attributed per step, not per aggregate.
  Pre-redaction caveat: staged values precede the router's response firewall pass. That pass
  redacts credentials, which are mostly shorter than the 63-char match floor.
- direct: a delivery-only helper records the final value at `after_dispatch`'s `Ok(response)`,
  after redaction and the provenance stamp, and also on the idempotency cache-hit return. There is
  no accounting replay.

**Sensitivity.** A staged or recorded value is sensitive when:
- its source matches `sources`, or
- the gateway's own context-integrity result for that call reports `personal_data`,
  `financial_data` or `guarded_material`.
On meta this is read from the evaluation at the stage point, where the value is not yet wrapped;
on direct, from the `_context_integrity` metadata the gateway attached. A backend-forged field can
only mark its own content sensitive: extra findings, never fewer.

**Text extracted.** A bounded walker joins JSON string leaves with newlines. On responses it
excludes the gateway-owned `_context_integrity` subtree. On arguments it walks every string,
including any caller-supplied `_context_integrity`. It stops at 64 KiB of text, cuts on a UTF-8
boundary, and counts cuts in its own counter (`source_truncated` counts fingerprints, not bytes).
Arguments get no text cap, since a cap would let a padded payload hide a relay; the request body
limit bounds them (`server.max_body_size`, 10 MiB). Past the cut, results can relay undetected,
and repetitive text can exhaust the 1,024-fingerprint keep limit before 64 KiB.

**Startup validation (row 16).** When `action != off`, a collusion check in
`FirewallConfig::validate`, run before its anomaly-off early return, refuses:
- `firewall.enabled: false`;
- `min_matches == 0`;
- `common_principals < 2`;
- `window_secs == 0`;
- invalid globs.
Without the `firewall` feature, strict keys already refuse the unread `security.firewall`, and
`missing_feature()` gains that entry so the error names the feature. That test runs in the
post-merge feature-combinations job, and a red result there blocks.

**Config and public API (pending operator approval).**
- `FirewallConfig.collusion: CollusionConfig { action: CollusionAction, window_secs, min_matches,
  common_principals, sources, non_egress }`;
- `ScanType::CollusionRelay`;
- `is_anomaly_block()` widened.
`allowed_flows` with its test, and the metric, are increment 3.

**Tests.** The §8 rows 1, 2, 11, 12, 13 (minus the allowlist), 15 and 16, plus:
- one relay per dispatch entry (invoke, execute, playbook, chain) to prove the chokepoint;
- a direct cache-hit record;
- an argument-side `_context_integrity` relay;
- a chain attribution case (T unrelated, V relays);
- the result cap;
- name-map eviction.

### 13.1 Increment 2a-i (delta r3, 2026-09-30; split ruled by the coordinator)

Reviewed in one round by two independent seats, both SHIP-WITH-FIXES with no HIGH finding; the
fixes are folded in below. Deferred, as LOW: a relay-specific refusal prefix instead of the
shared "Anomaly detection blocked:", and a pre-merge run of the no-default `validate` step.

Increment 2a is split. **2a-i** is the direct route plus the shared config and state.
**2a-ii** covers the meta route (`accounted_dispatch` check, delivery-boundary recording on HTTP
and stdio, outer sync replay, composite source, playbook projection, pre-dispatch refusal error
variant, egress-argument cap). It gets its own design round on the r3 direction in the handoff.
In 2a-i the meta route is untouched: no check and no recording.
The r2 findings about the meta route (receipt staging, meta cache hits, refusal propagation
through `dispatch_error_result`, chain/bridge codes, stdio and playbook argument bounds) are
2a-ii items. 2a-i does not claim to close them.

**One detector.** `Gateway` builds one `Arc<CollusionDetector>` when `action != off`.
`response_firewall` attaches that same `Arc` to both firewalls it builds, the `MetaMcp` one
(`server/mod.rs:1235`) and the `AppState` one (`:1789`), through a crate-internal
`Firewall::with_collusion`. In 2a-i only `AppState`'s is exercised; 2a-ii reuses the same `Arc`.
`RelayAction` gains `Block`.

**Config (public, pending operator approval).**
`FirewallConfig.collusion: CollusionConfig`, `#[serde(default)]`:
- `action: CollusionAction` (`off` | `observe` | `block`, default `off`);
- `window_secs` (600), `min_matches` (2), `common_principals` (5);
- `sources: Vec<String>` and `non_egress: Vec<String>`: globs over `server:tool`, compiled once
  with the `glob` crate as `FirewallRule` is.

It maps onto `RelayParams`; `max_fingerprints` stays internal.
`ScanType::CollusionRelay` is added.
`FirewallVerdict::is_anomaly_block()` becomes: not allowed, non-empty, and every finding is
either `SequenceAnomaly`/`High` or `CollusionRelay`.

**Startup validation.** In `FirewallConfig::validate`, before the anomaly-off early return, when
`collusion.action != off`, each of these is refused with an error naming
`security.firewall.collusion.<field>`:
- `enabled: false`;
- `min_matches == 0`;
- `common_principals < 2`;
- `window_secs == 0`;
- any `sources`/`non_egress` pattern that does not compile.

`action: off` loads exactly as before, whatever the other fields hold.

**Caller.** `RelayCaller::{Keyed(key), Unkeyed(fallback)}` (crate-internal). On direct it is
decided from `identity::caller_key(grant_subject, cert, client)` before the `direct:{backend}`
fallback. One helper, shared with `direct_control_identity`, returns both the key and whether it
fell back, so the relay key cannot drift from the anomaly, tenant and budget identity. The same
value is used for the check and for recording.

**Egress check (direct).** `Firewall::check_relay(caller, server, tool, args) -> FirewallVerdict`
runs in `apply_backend_tool_call_security` immediately after `check_request` allows the call.
It is a separate method, not a step inside `check_request`, because `check_request` also serves
the meta pre-check and meta is 2a-ii.
1. `action == off`, or `server:tool` matching `non_egress`: allow.
2. `Unkeyed` under `block`: refuse (finding `CollusionRelay`, "relay check needs an
   authenticated caller"). Under `observe`, check under the fallback key and never refuse.
3. Text: every string leaf of the whole forwarded `params` object, joined with `\n`. That covers
   `arguments`, `_meta` and any other sibling, because the direct route forwards the whole object
   (r3 review: `_meta` would otherwise be a side channel). It includes any caller-supplied
   `_context_integrity`. No cap. The direct route is HTTP-only, so `server.max_body_size`
   (10 MiB) bounds it. That bound is not claimed for meta or stdio.
4. A hit becomes a `CollusionRelay` finding (`Medium`, `RequestArgs`) whose `matched` is the
   hex digests of source, receiver and sender plus the match count, never content. Under
   `observe` the verdict is `Warn` and the call proceeds. Under `block` it is refused through
   the existing `is_anomaly_block` branch: `-32002`, HTTP 403. Nothing is dispatched and no
   idempotency reservation is taken, because the check runs before `direct_route_idempotency`
   (#2445 ordering).
5. The verdict is audit-logged like `check_request`'s.
Passthrough backends are checked too: their early return in `apply_backend_tool_call_security`
(`backend_handlers.rs:184`) comes after `check_request`, and `check_relay` sits beside it.

**Recording (direct).** A helper `record_direct_delivery(state, caller, server, tool, &response)`
runs on the final delivered response. That is after `after_dispatch` (gates, response-firewall
redaction, refusal) and after `stamp_direct_provenance`, immediately before
`build_http_response`, on both `tools/call` arms (sanitised and passthrough). It also runs on
the idempotency `CachedResult` return (`backend_handlers.rs:1042`). It records whenever the
delivered response carries a `result`, whether or not an `error` sits beside it. `CachedError`,
refusals (a fresh response with no `result`) and transport failures record nothing.
The source is `server:tool`.
- Text: string leaves of `result`, joined with `\n`, skipping the `_context_integrity` subtree.
  Capped at 64 KiB of text: the first and last 32 KiB, each cut on a UTF-8 boundary, so a
  tail-only excerpt still matches. Each cut is counted; the middle of a larger result is the
  known, observable residual.
- Sensitive: `server:tool` matches `sources`, OR the result's gateway-attached
  `_context_integrity.classification` reports `personal_data`, `financial_data` or
  `guarded_material`. The gateway's own attach overwrites any backend-supplied
  `_context_integrity`, so a backend can forge the field only where the gateway attached none,
  and then only to mark its own content sensitive: that adds findings and never removes them.

**Absent feature.** `security.firewall` is already refused by strict keys when built without
`firewall`. `missing_feature()` gains `security.firewall` -> `firewall`, so the message names the
feature. The table logic takes the feature predicate as a parameter, so a default-build unit test
exercises the no-firewall entry in the required Tests job. The behavioural proof is a new step in
the post-merge feature-combinations job: the `--no-default-features` binary runs
`mcp-gateway validate` on a fixture holding `security.firewall.collusion`. It must exit non-zero
with the exact text `built without feature "firewall"` and the key `security.firewall`, which the
old generic message lacks. That job runs post-merge only. "A red result blocks the next merge"
is lane policy (operator decision 2026-09-29), not something the workflow enforces.

**2a-i tests.** Direct route only:
- §8 rows 1 (relay refused under block, `-32002`, HTTP 403, backend not called; the same
  idempotency key re-issued without the relay then executes, so no reservation was taken),
  2 (observe: `Warn`, call proceeds), 11 (a refused/error delivery records nothing),
  12 (`non_egress` skip), 13 (unkeyed: refused under block, checked under observe),
  15 (own copy excuses), 16 (every validation refusal and `off` untouched);
- a cache-hit delivery excuses its receiver;
- argument-side `_context_integrity` relay, and a relay carried only in `params._meta`;
- a passthrough backend is relay-checked;
- a result carrying both `result` and `error` is recorded;
- a tail-only excerpt of an over-cap result matches;
- a backend-forged `_context_integrity` is overwritten where the gateway attaches its own;
- `sources` and `_context_integrity` sensitivity;
- result-text cap counted;
- `is_anomaly_block` truth table;
- the shared detector: the `MetaMcp` and `AppState` firewalls hold the same `Arc`;
- the absent-feature table test.
