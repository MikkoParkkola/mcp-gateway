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
**Fingerprint.** Text is NFC-normalized and whitespace-collapsed, then sampled:
- k = 48-char k-grams at **every offset**, 64-bit keyed hash (SipHash, per-process random key);
  keep a k-gram when its hash is 0 mod 4 (MIK-8083). The decision depends on the k-gram alone, so
  two texts sharing a k-gram keep it in both or in neither, wherever it sits: the same-source
  excuse is exact. (Winnowing, used before, kept window minima whose choice near a copy's edge
  depended on the surrounding text, and refused about 1 in 70 callers' own split copies.)
- Sampling has no hard floor: a shared run of n distinct k-grams keeps fewer than the two
  matches a finding needs with probability (3/4)^n (1 + n/3): 79 chars 1.2e-3, 87 chars 1.4e-4,
  100 chars 4.5e-6, 127 chars 2.8e-9. The key is per process, so which k-grams are kept cannot be
  predicted from outside.
- Results keep at most 4,096 fingerprints per delivery (both forms of a capped split copy are
  expected to fit, about 3,050; the rest is counted as `source_truncated`);
  egress arguments are fingerprinted in full within the request-size limit.

**State.** `fp -> {tuples: [(source_id, principal_id, sensitive, last_seen)], principals: n}`,
with the ids stored as keyed 64-bit hashes.
- Tuples are deduplicated per (source, principal), keeping the latest time. No tuple count
  switches a fingerprint off (MIK-8123): a caller keeps up to 64 exact tuples per fingerprint,
  the first 8 inline and the rest from one pool of 65,536 shared by every fingerprint (at most
  10 MiB of records). A tuple that does not fit is dropped when plain (only an excuse is lost)
  and, when sensitive, kept as its caller's overflow: evidence for any other caller's egress of
  that text, whatever its flows, with no same-source excuse (its source is gone). Overflow
  expires with its own sensitive deliveries. Both are counted in a metric.
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

Or (MIK-8123) some caller A != B holds it as *overflow* (a sensitive tuple past A's cap or the
pool): overflow has no source left, so no (T, B) tuple excuses it and no `allowed_flows` entry
allows it. Do not add an excuse for overflow: it would reopen the relay a dropped tuple hid.

The excuse deliberately does not cover content from another source: writing to a shared store
and reading it back still counts. Sampling gives **no** hard length floor (§3). Repetitive text can
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

Which of these are accepted, and the numeric budget, are fixed by §14.

- **Missed:** re-encoding, paraphrase, splits under 48 chars, about 1 in 1,000 copies of 79 chars
  (fewer for longer ones, §3), and anything past a delivery's first 4,096 fingerprints
  (`source_truncated`).
- **`Common` can be poisoned:** colluders who control `common_principals` identities can each
  receive the content and so promote it to `Common`, exempting B. This is accepted: excluding
  sensitive tuples from `Common` would bring back the boilerplate false positives.
- **Per replica only:** A and B on different replicas are never correlated.
- **Flush:** every delivered result is recorded, so ordinary traffic fills the 250k map; the
  effective window is `min(window_secs, 250,000 / total fingerprint rate)`: about 61 large
  (4,096-fingerprint) results from anyone evict the oldest evidence. Evictions are counted.
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
| 18 | nine tuples stay exact: B's excuse holds, and without it A's copy witnesses B's relay | `many_holders_stay_exact` | switch the fingerprint off past 8 tuples |

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
tools egress but `non_egress` [12]. Eviction erased excuse; exact tuples past 8 [18]. Unkeyed guard
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
and repetitive text can exhaust the 4,096-fingerprint keep limit before 64 KiB.

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
fixes are folded in below. Deferred, as LOW: a pre-merge run of the no-default binary probe.
Found while writing the tests, after review: the recording cap had to shrink from 64 KiB to 6 KiB
to fit the detector's fingerprint keep limit (see Recording). The final review covers it.

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
   its own branch beside the anomaly one: `-32002`, HTTP 403, message "Relay detection
   blocked: ..." (a relay-specific prefix, as review seat 2 suggested). Nothing is dispatched and no
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
  Capped at 6 KiB of text: the first and last 3 KiB, each cut on a UTF-8 boundary, so a
  tail-only excerpt still matches. The cap sits under the detector's 4,096-fingerprint keep
  limit (about 8K characters in each of a split copy's two forms, kept in text order); the
  64 KiB first proposed would have
  dropped every tail fingerprint. Each cut is counted. The middle of a larger result is an
  in-model gap, not a stated residual: §14.5 (MIK-8066 CAP.2) governs.
- **Evasion bound (stated for operators and the final review).** Per delivered result, only its
  first and last 3 KiB of text are compared, at most 4,096 fingerprints. Content taken only from
  the rest of a larger result is never detected today, so a source that pads a result can move
  content out of view; this is an open in-model gap (§14.5, MIK-8066 CAP.2), not an accepted bound. The egress side has no cap: every string of the forwarded params is checked, so
  padding the relayed payload hides nothing. Below the fingerprint size nothing matches: a shared
  run under 48 characters never counts, a longer run keeps about 1 in 4 of its k-grams (§3), and
  `min_matches` (default 2) are needed. Acceptable for `observe`; whether `block` needs sampling
  across the whole result is put to the final review.
- Sensitive: `server:tool` matches `sources`, OR the result's gateway-attached
  `_context_integrity.classification.data_classes` holds `personal_data`, `financial_data` or
  `guarded_material`. The gateway's own attach overwrites any backend-supplied
  `_context_integrity`, so a backend can forge the field only where the gateway attached none,
  and then only to mark its own content sensitive: that adds findings and never removes them.

**Absent feature.** `security.firewall` is already refused by strict keys when built without
`firewall`. `missing_feature()` gains `security.firewall` -> `firewall`, so the message names the
feature. The table logic takes the feature predicate as a parameter, so a default-build unit test
exercises the no-firewall entry in the required Tests job. The behavioural proof is a new step in
the post-merge feature-combinations job: the `--no-default-features` binary is started as
`mcp-gateway -c <fixture>` on a fixture holding `security.firewall.collusion` (`validate` is the
capability validator and never loads gateway config). It must exit non-zero at config load
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

### 13.2 Review fixes at rebuild (#2644, replaces #2484)

- **Sanitize parity.** Fingerprinting first drops every character input sanitization strips
  (`security/sanitize.rs` `is_unsafe_control`: C0/C1 controls, zero-width characters, BOM,
  U+2028/2029), then NFC and whitespace collapse. Before this, a copy interleaved with such
  characters every < 48 chars matched nothing, and sanitization then delivered the clean text to
  the backend. Applies to both recording and egress, so it covers every route.
- **`common_principals` is at most 9.** The boilerplate guard stays meaningful only for text a
  handful of callers share; every caller seen counts toward it, tuples kept or not (MIK-8123).
  A larger value is refused at load.
- **Delivery point.** Direct-route recording runs after `finish_direct` (scope clamp, chain
  strip and origin link), on the value the caller receives; replays record the stored value.
- **Signing before recording.** The direct route signs, then records (`sign_and_record`). A signing
  failure replaces the result with a refusal, which records nothing.
- **Text read.** String leaves first, newline-joined, so content split over short fields at word
  boundaries still matches. On egress the leaves are read once more run together, so a copy split
  mid-word over fields shorter than a fingerprint still matches. Keys come after. Egress reads every key, since a key reaches the backend
  like a value. A delivery reads only keys of at least k = 48 chars, so short schema keys never
  make unrelated results look alike. A delivery skips only the top-level `_context_integrity`, the
  gateway's verdict slot. A nested one is content. A backend that writes its own content into
  that slot is backend collusion (§9).

### 13.3 Meta-route wiring (delta r2, 2026-10-02; r1 + round-1 seat fixes)

Completes COLLUDE.1 on the meta route, for the same surface as the direct route: `tools/call`
egress and delivered tool results. Reuses #2644 unchanged: `Firewall::check_relay`,
`Firewall::record_delivery`, `RelayCaller`, the shared detector, the text walker (string leaves AND
object keys; only the gateway's own top-level `_context_integrity` skipped), the record cap and the
sensitivity read. Where it disagrees with §13, this section wins.

**Corrections to §13 (verified at source).**
- Context integrity is evaluated in `gate_payload` (`invoke.rs:2467`), AFTER `accounted_dispatch`
  returns; staging inside `accounted_dispatch` would read ungated values.
- An `Err` inside `accounted_dispatch` is flattened to `isError`, commits the idempotency key, is
  metered as a backend failure, rewrapped `-32603` by chains and retried by playbooks. The check
  therefore runs before `accounted_dispatch`.
- `accounted_dispatch` receives no `caller_key` (`InvokeScope`, `mod.rs:256-264`).
- The router pre-check (`handlers.rs:1311-1378`) misses playbooks and every stdio call.

**Caller (`MetaMcpCallerContext::relay_caller(session_id)`, crate-internal).**
- `caller_key` Some and non-empty -> `Keyed(caller_key)` (HTTP; inherited by playbooks
  `support.rs:398`, chains `mod.rs:320`, HTTP tasks `context.rs:218`).
- `stdio_nonce` Some -> `Keyed(LOCAL_OPERATOR_PRINCIPAL)` (`mod.rs:139`): the local operator is one
  principal, distinct from every HTTP caller (the `\0` prefix cannot be a `caller_key`). Stdio tasks
  rebuild the context without a caller key (`stdio_tasks.rs:229`) but keep `stdio_nonce`.
- Otherwise `Unkeyed(session_id or "meta:unkeyed")`; under `block` it is refused (§13 rule 2).

**What is checked: the outbound params as the backend receives them, minus injected secrets.**
One crate-internal builder `outbound_params(tool, arguments, inbound_meta, prompt_cache_key,
outbound_retry) -> Value` produces `{name, arguments, _meta, requestState, inputResponses}`;
`dispatch_to_backend` (`invoke.rs:~3570-3580`) is refactored to call it after secret injection, and
the check calls it on the pre-injection arguments. So `_meta.progressToken`, the trace context
(`baggage`, `tracestate`) and `prompt_cache_key` (`prompt_cache.rs:235-259`) are checked, and the two
can never drift. Injected secrets are neither fingerprinted nor written to the relay audit.

**Egress sites (one helper `MetaMcp::relay_refusal(ctx, server, tool, params) -> Option<Error>`).**
1. `invoke_tool_traced`, after `redeem_retry`'s `Err` arm and BEFORE `execution.mark_dispatched()`
   (`invoke.rs:2013-2020`): on refusal release the idempotency reservation (as the `redeem_retry`
   error arm does) and return `Error::Forbidden { code: -32002, status: 403, "Relay detection
   blocked: ..." }`. Not marked dispatched, so sync admission treats it as pre-dispatch. Covers
   gateway_invoke, surfaced tools, gateway_execute single and chain steps, playbooks, tasks (worker
   `:201`) and stdio `tools/call`.
2. Bridged retry `BridgeDispatcher::invoke` (`invoke.rs:~810-885`), before `arm(...)`, on
   `outbound_params(...)` built from the round's `retry_params`. The refusal is stored in a
   crate-internal slot on the dispatcher (`relay_refused: Mutex<Option<Error>>`) and the round returns
   `BridgeError::NotAdmitted`. The call site reads the slot FIRST, before the `Err(round) if
   parked.is_some()` arm and the generic arm (`invoke.rs:~2355-2420`): reservation released, the
   stored `Forbidden -32002` returned. No new public `BridgeError` variant (operator ruling: minimise
   surface).
`non_egress` globs apply as on direct. Response-cache and idempotency hits make no backend call.

**Refusal semantics through composites.** Chains keep `Forbidden` and its code (`search.rs:542-549`):
`-32002` survives. Playbooks: `MetaMcpInvoker` rewrites every `Forbidden` to `-32003 "step not
permitted for this caller"` (`support.rs:403-415`, A3: refusal reasons must not name operator
targets), and under `Continue`/`Retry` the step is null-filled with its reason in `step_errors`
(`engine/mod.rs:199-228`). r1's claim that `-32002` survives playbooks was wrong and is withdrawn.
The security property holds either way: the refused step never reaches its backend. Changing the
A3 rewrite or the playbook error strategy would change anomaly-block behaviour too and is out of
COLLUDE scope.

**Recording: staged per call, committed at delivery.**
- Collector: a `tokio::task_local!` `RelayReceipts` (Vec of `(caller key, keyed, "server:tool",
  Value)`, each value capped at the record cap). It is scoped by the delivery owner: the HTTP
  `tools/call` handler, the stdio `tools/call` handler, the task worker's spawned execution
  (`execution.rs:211`) and the input-round spawn (`input_round.rs:337`). A scope must be entered on
  the spawned task itself, since task-locals do not cross `tokio::spawn`. With no scope (unit paths)
  staging is a no-op. Chain and playbook steps run in the owner's task and stage into its collector,
  each under its own `server:tool`.
- Stage points (value as gated, before `shape_meta_result` wraps it, `mod.rs:2434`):
  a. after `gate_payload` (`invoke.rs:2467`) on success, `isError` results included;
  b. the idempotency `CachedResult` (`:1774-1798`) and the response-cache hit (`:1884-1913`): the
     stored value, which already carries its first run's `_context_integrity`.
- Commit (one `record_delivery` per staged entry) when the final response is neither a JSON-RPC
  error nor a delivery refusal (`delivery_refusal`). An `isError` result is delivered content and is
  committed (parity with direct, which records any `result`, `backend_handlers.rs:1257`):
  - HTTP: after `finalize_response_after_inspection` (`handlers.rs:1853-1855`);
  - stdio: after `finalize_response_for_delivery` (`server/mod.rs:3020-3037`);
  - tasks: at settlement after `inspect_settled` (`worker.rs:256, 507-540`; upstream-followed jobs
    `:387-396`).
  - outer sync replays (`handlers.rs:1633,1658`; `server/mod.rs:3365-3380`) record nothing.
- A refused or failed delivery commits nothing (M5).
- Bridged prompts (legacy clients, `input_bridge.rs:526, 695`): the backend's `sampling` /
  `elicitation` prompt is content delivered to the caller. `run_input_bridge` wraps its
  `ClientChannel` in a crate-internal recorder that calls `record_delivery(caller, server, tool,
  prompt params)` when `send_request` returns `Ok` (the client received and answered it), at once
  and independent of the call's final outcome. The caller's answers go back out through site 2.
- Sensitivity: `sources` globs, or the gateway-attached
  `_context_integrity.classification.data_classes` (meta attaches it whenever there are findings,
  `invoke.rs:2738-2753, 2865-2886`). Same function as direct.

**Request check `is_anomaly_block`.** Unchanged; #2644 made the `-32002` widening the crate-internal
`is_asi10_block`, already used at the meta router sites.

**Scope: `prompts/get` and `resources/read` are out, as on the direct route.** r1 added both through
`forward_for_caller` (`caller_forward.rs:123-133`). §3 defines egress as a call to a backend tool and
a receipt as a delivered result. The direct route checks and records `tools/call` only
(`backend_handlers.rs:160-165, 1257`). Round 1 showed that the r1 additions were also unsound:
`forward_for_caller` has no caller context, the stdio catalogue keys as principal `stdio`
(`stdio_catalogue.rs:52-67`), and forwarded results get no context-integrity classification
(`response_security.rs:177`). Removed rather than half-built. If they are wanted, it is one
follow-up for both routes, tracked in Linear. The lead decides whether it is in 4.0.

**Limits (added to §5).**
- Meta replays renew no receipt. The direct route renews; a meta replay is the same caller's own
  earlier delivery, recorded then.
- A task result is recorded at settlement. The owner is entitled to exactly that value through
  `tasks/get`, so recording before the read gives no undue excuse. A `tasks/get` more than
  `window_secs` after settlement finds the receipt expired, and a relay of that text by another
  caller is then missed (false negative only).
- Playbook steps record their own results, including steps an output mapping leaves out of the
  playbook's answer. This is not row M5's case. M5 covers a delivery the gateway refused, where the
  caller is not entitled to the content. Every step here ran under the caller's own authorization
  (`support.rs:391-404`), and the caller could call it directly. The omission is a presentation
  choice of the playbook author, not a security decision. The effect is a same-source excuse for
  content the caller is authorized to fetch: a false negative bounded by its own access.
- `resources/subscribe` notifications, `logging/setLevel`, `server/discover`: no caller text out and
  no per-caller delivered result.

**Round-1 dispositions (all verified at source).**
| Finding | Seat | Disposition |
|---|---|---|
| `_meta` (progressToken, baggage, tracestate, cache key) unchecked | gpt CRIT, grok HIGH | FIXED: the shared `outbound_params` builder is checked at sites 1 and 2 (M4) |
| sampling/elicitation prompts unrecorded | gpt CRIT | FIXED: recording `ClientChannel` wrapper (M6) |
| playbook output mapping over-records | gpt HIGH | NOT-A-DEFECT for row M5 (entitlement distinction above); documented limit |
| task receipt before `tasks/get`, none after expiry | gpt HIGH | premature: NOT-A-DEFECT (the owner is entitled to the settled value); late read: documented limit |
| forwarded results lack classification | gpt HIGH | FIXED by deletion: `prompts/get`/`resources/read` out of scope, parity with direct; Linear follow-up |
| `forward_for_caller` has no caller; stdio catalogue split | grok HIGH | FIXED by deletion, same |
| `isError` results not committed | grok MED | FIXED: committed, parity with direct (M13) |
| playbook refusal becomes `-32003`, swallowed under Continue | gpt MED, grok MED | design claim corrected; nothing egresses; M2 asserts what is true |
| bridge `NotAdmitted` -> generic `-32003` | gpt MED | FIXED: dispatcher slot read before the parked and generic arms (M3) |
| task-local scope on spawned worker / input round | grok IMPR | ACCEPTED: stated above, M9 covers the worker |
| `_meta` test | grok IMPR | ACCEPTED: M4 |
| site 1 before `mark_dispatched` | grok IMPR | ACCEPTED |
| tests must tell a missing receipt from a same-source excuse | gpt IMPR | ACCEPTED: M5/M7 use a second caller with no copy of its own |

**Tests (red first; route-level unless noted).**
| # | Rule | Test | Mutant that must redden it |
|---|---|---|---|
| M1 | A reads via gateway_invoke, B gateway_invokes a send with it: -32002, backend not called, key released | `meta_invoke_relay_refused` | drop the check at site 1 |
| M2 | chain step: -32002 survives; playbook step: refused (-32003 step not permitted), its backend not called | `meta_chain_relay_refused`, `meta_playbook_relay_not_sent` | drop the check at site 1 |
| M3 | bridged retry round carrying A's text in inputResponses: -32002, key released, also on a managed (parked) account | `meta_retry_round_relay_refused` | skip site 2 / read the slot after the parked arm |
| M4 | A's text in `_meta.progressToken` and in `_meta.baggage`: refused | `meta_relay_in_outbound_meta_refused` | check `arguments` only |
| M5 | A's delivery refused by the response firewall records nothing: B (no copy of its own) sending it is sent | `meta_refused_delivery_not_recorded` | commit unconditionally |
| M6 | a bridged elicitation prompt delivered to A is a source: B sending its text is refused | `meta_bridged_prompt_recorded` | drop the channel recorder |
| M7 | a cache hit renews A's receipt after expiry of the first | `meta_cache_hit_recorded` | skip stage b |
| M8 | stdio operator is one principal: its own content passes under block; an HTTP caller's content sent from stdio is refused | `stdio_operator_is_one_principal` | treat stdio as Unkeyed |
| M9 | task settlement commits; a failed task commits nothing | `task_settlement_records`, `failed_task_records_nothing` | commit at submit |
| M10 | unkeyed meta egress refused under block, allowed under observe | `meta_unkeyed_block_refused`, `meta_unkeyed_observe_allowed` | refuse in observe |
| M11 | chain attribution: step T unrelated, step V relays -> the finding names V's target | `meta_chain_attribution_per_step` | stage the aggregate target |
| M12 | injected secrets never reach the relay audit | `relay_audit_has_no_injected_secret` (unit) | check post-injection params |
| M13 | an `isError` result A was delivered is a source | `meta_is_error_result_recorded` | skip `isError` at commit |

**r3 amendments (round 2, both seats SHIP-WITH-FIXES; design FROZEN after this round).**
These amend the r2 text above; where they disagree, r3 wins.
1. Collector scope (grok HIGH): the `RelayReceipts` scope wraps the whole JSON-RPC dispatch future
   *including* finalize: HTTP through `handlers.rs:1853-1855`, stdio through
   `dispatch_single_with_sink` up to `server/mod.rs:3037`, not only the `tools/call` arm. Dropping
   the collector discards it. Only the explicit post-finalize / post-settlement commit records.
2. Upstream task results (both seats, HIGH/CRIT): stage point c = the gated `Complete` value in
   `recover_task_result` (`upstream.rs:412-452`) after its inspection, committed with the worker's
   settlement (`worker.rs:387-396`). The owner-read recovery path (`router/handlers/tasks.rs:372`)
   commits the same staged value after its own delivery gates.
3. Redelivery renews (gpt MED): a successful outer replay (`handlers.rs:1633,1658`;
   `server/mod.rs:3365-3380`) and a `tasks/get` that delivers a completed result record the
   delivered value again under the call's own `server:tool` when the call has a single target
   (`gateway_invoke`, a surfaced tool, a task over either). A multi-step replay (chain, playbook)
   renews nothing: documented limit, possible false positive for the replaying caller after its
   receipt expired while another caller holds a fresh one.
4. Final-check mutation (gpt MED): if the final response artifact check
   (`response_security.rs:187`) changes the result (redaction), that delivery commits nothing
   (result hash compared before/after). False negative only, never an excuse for undelivered text.
5. Capability dispatch (gpt MED): for the capability server (`mcp_backend == false`,
   `invoke.rs:~2028`) the check reads `arguments` only; `_meta` is never forwarded there.
6. Bridged prompts (gpt CRIT, grok MED):
   - recorded when the prompt is handed to `send_request`, before the reply is awaited, so a
     timeout after delivery still leaves a receipt (gpt CRIT). An unsuccessful send also records
     it: the over-record is bounded to a prompt the caller's own call raised;
   - classified: a recording-only copy of the prompt params goes through the same
     context-integrity evaluation as a tool result (`apply_context_integrity`). Sensitivity is read
     from the copy's classes, and the copy's top-level `_context_integrity` is removed before its
     text is recorded. M6 runs with `sources` empty.
7. Gateway metadata: `Walk::Delivery` skips the top-level `_context_integrity`, the gateway's
   verdict slot (§13.2), so every stage point stages the gated value as is, and `record_delivery`
   reads its sensitivity from that slot.
8. Added rows:
   - M14 `meta_modern_retry_relay_refused`: a modern (non-bridged) retry whose redeemed
     `inputResponses` carry A's text is refused at site 1 (mutant: omit `outbound_retry` from the
     checked params).
   - M5 mutant extended: commit at the end of the `tools/call` arm instead of after finalize.
   - M15 `meta_upstream_task_result_recorded`.
   - M16 `meta_capability_meta_not_checked`: capability-call `_meta` is not checked.

### 13.4 Increment 3: allowlist and metric (MIK-7797, 2026-10-03)

- `allowed_flows` is a list of `{source, egress}` `server:tool` glob pairs, at most 64 (one bit
  each), checked at load like the other globs. A delivery records the entries whose source glob
  matched its source; an egress computes the entries whose egress glob matched its target; a
  holder sharing a bit with the egress is skipped when looking for a relay witness. Other holders
  still count, and no state beyond one `u64` per (source, principal) pair is added. Allowing a
  flow never changes what is recorded, so a later non-allowed egress is still checked.
- `mcp_gateway_collusion_relay_total{action}` (`observe` or `block`) counts every reported relay.
  `mcp_gateway_collusion_unkeyed_egress_total{action}` counts egress checks made without an
  authenticated caller (the §13.1 internal counter, now exported).
  `mcp_gateway_collusion_plan_receipts_dropped_total` counts plans whose step receipts were
  dropped because the answer was over the bound they are kept against (MIK-7934.PLANRCPT.2).
- Tests: `allowed_flow_not_flagged` (detector, gate, direct, meta), `allowed_flow_globs_match`,
  `allowed_flows_are_checked_at_load`, `a_reported_relay_increments_the_metric`. Mutants: skip
  the flow mask in the witness search; drop the relay counter increment.

### 13.5 Catalogue reads (MIK-7765, 2026-10-03; reopens the r1 drop of prompts and resources)

Why reopened: `resources/read` and `prompts/get` deliver backend content and `prompts/get` sends
caller text to a backend, so a caller could relay a resource's text through `prompts/get`
arguments with no finding. Round 1 dropped them for parity with the direct route and because the
first wiring was unsound; both reasons are gone (the direct route now covers them, and the
delivery path is the staged-receipts path of 13.3/13.4).

- Egress: the forwarded params of `prompts/get` (name and arguments) and of `resources/read`
  (the URI) are checked as a `tools/call`'s are, against target `backend:method`
  (`prompts/get`, `resources/read`). `block` refuses with `-32002` before the backend is called.
  On the meta route a URI is first resolved against the backends' catalogues, so a free-form URI
  carries nothing; the direct route forwards any URI and is checked.
- Recording: a successful result is staged as a delivery from `backend:method` (sensitivity from
  `sources` globs such as `backend:*`, or the context-integrity classification of a copy) and
  committed with the other receipts, after the answer's last replacer.
- Principals: the same key `tools/call` uses on each route: the HTTP caller key (or the session
  bucket when unkeyed), the direct route's caller key, and `LOCAL_OPERATOR_PRINCIPAL` on stdio
  (the stdio catalogue previously keyed nowhere).
- Plumbing: the meta handlers read the caller from a task-local set by the route
  (`relay::as_caller`), so their public signatures do not change; no scope, no check.
- Tests: `*_resource_read_then_prompt_argument_is_refused`, `*_prompt_result_then_tool_call_is_refused`,
  `direct_resource_read_then_uri_is_refused`, `stdio_catalogue_is_inside_relay_detection`.
  Mutants: skip the egress check, skip staging, skip the direct check and staging, key stdio as
  `"stdio"`.


### 13.6 Receipts follow the delivered result (MIK-7887, 2026-10-03)

- A final check that changes a single-target call's delivered result (a redaction) rebuilds that
  call's receipt from what is delivered, keeping the sensitivity the delivery was judged to have:
  text the caller still got keeps its receipt, removed text stops being tracked.
- A plan (`gateway_run_playbook`, `gateway_execute`) stages one receipt per step. The plan's answer
  is not any step's text, so a step receipt is never rebuilt from it. At the final answer each is
  kept to what the answer still delivers: a step leaf delivered verbatim stays whole, and any
  other leaf keeps only the fingerprints whose k-gram occurs in a delivered leaf. Text the engine
  wrote is attributed to no backend, and a changed plan receipt that never reached the final answer
  is not committed (MIK-7887.RECEIPT.2).
- A receipt's text is fingerprinted in runs that never cross a seam: the cap's cut between head
  and tail, a dropped middle leaf, or a leaf a change removed. No fingerprint joins text the source
  never produced contiguously.
- Reading a failed task hands the reader the backend's error, so the read renews a receipt for it,
  classified like a pending prompt. Only an error the gateway established as the peer's (stored
  author `Peer`: every screen and the audit passed it unchanged) is receipted, at settlement and on
  a read; the gateway's own errors, substitutes, and errors on older rows whose author is unknown
  renew nothing (MIK-7887.RECEIPT.1).
- A stdio answer whose `result` is `null` delivers a result, as a typed response and the judge do.
- Known limits, stated because Block mode can over-refuse as well as miss: (1) a multi-target
  task's read stages nothing, so the reader loses the same-source excuse for it; (2) a plan answer
  over 1 MiB of text drops its step receipts, as before, and the drop is counted; (3) a step whose
  text is over the receipt cap keeps no receipt for its dropped middle leaves; (4) a k-gram a step
  produced stays on its receipt when the caller got it through another step or engine text, even
  if it was removed from that step (source-attribution coarseness).

### 13.7 Receipts at the delivery point (MIK-7887.RECEIPT.3/.4, 2026-10-04)

- A bridged prompt's receipt commits where the channel confirms delivery, not when it is handed
  over. HTTP: once `send_to_session` has put it in the live session's stream (SSE has no write
  acknowledgement, so that is the confirmation). Stdio: once the writer reports stdout took the
  frame. A send that finds no session, or is cancelled before that point, leaves no receipt; one
  cancelled after it keeps its receipt, and the receipt exists while the reply is awaited, so no
  second caller can relay the prompt during the wait. A channel without its own commit point
  commits after the call returns (never on `NoSession`), which under-receipts a cancelled send
  rather than receipting one nobody saw.
- A false receipt is not only an over-refusal risk: it grants its holder the same-source excuse,
  so it can also let a relay through. That is why a receipt follows delivery, not hand-off.
- A single-target answer's receipt is rebuilt from the answer as finally delivered, after the
  scope clamp, the chain, the modern `serverInfo` stamp and any redaction, on the HTTP and stdio
  routes. Members the gateway wrote on that route (its chain, the clamped `cacheScope`, a modern
  answer's `serverInfo`) are left out, since they are not backend text; a legacy answer's backend
  `serverInfo` reaches the caller and stays in. A `gateway_invoke` answer is read decoded.

## 14. Threat model and stop rule (MIK-8035, 2026-10-09)

Relay detection kept producing tickets because each review found another way to spell the same
text: a lexical matcher under adversarial review never runs out of spellings. This section fixes
which inputs the control must handle, which it does not, how much it may miss by, and the rule
that decides any future finding without another design round. Three review rounds by two
independent reviewers; maintainer decisions are marked.

### 14.1 Three error directions

| Direction | Harmed | In model | Out of model |
|---|---|---|---|
| **D1 missed relay** | data owner | Principal B sends a contiguous run (after NFC and whitespace collapse) that a sensitive delivery to A carried; B holds no same-source copy; same replica; inside the window. Where the run sat in the delivery is not a reason to exclude it: the cuts and caps are gaps to close or to state in the budget (14.3). | Transforms the matcher cannot see: re-encoding, paraphrase, translation, case or punctuation changes, interleaving, splits under 48 chars, homoglyphs, and invisible characters the sanitizer does not strip (U+2060, U+00AD and others; U+200B-U+200D and U+FEFF are stripped before matching). Also §5 and §9. |
| **D2 false refusal of an honest holder** (block; a false finding under observe) | legitimate caller | A delivery in shapes S1-S4, forwarded honestly: verbatim, its pieces re-joined in delivered order, or a subset of whole pieces. | Text the holder did not receive from that source; a copy spread over leaves of different key paths or interleaved with other text; the bounds in 14.3. |
| **D3 false excuse** | data owner | An excuse covers only text the excused caller received from the same source, except the bounded Bloom rate B3, confined to the holder's own (source, caller) pair. | n/a |

**Delivery shapes in model for D2:**
- S1 one text leaf;
- S2 MCP content items: an array of objects whose text sits under one key (`text`);
- S3a a copy split over the values of one object's fields (the existing all-values forms);
- S3b a copy split over the string values that share one key path across a consecutive run of array
  elements (e.g. `[{"part": p1, "kind": "chunk"}, ...]`, key path `part`);
- S4 a plan step or a plan's final answer built from S1-S3.

**Key path**: the object keys from the delivery root to a leaf, with array indices elided. Elements
are taken in array order, and fields in `serde_json::Map` order (sorted by key, since the crate does
not enable `preserve_order`). A run is a maximal sequence of consecutive sibling elements whose leaf
at that key path is a string.

**Join rule** (MIK-8209, residuals 1, 3, 4 split from MIK-8035): besides the all-values forms, a delivery records, for
each key path, the run-together of each run's values in order. A verbatim forward matches the
all-values form; a re-join of one key path's pieces matches only the per-key-path form. No list of
metadata keys is needed. The per-key-path form is text the caller received, so it is valid as
evidence and as excuse. The mid-word evasion row (A3c) must stay red on revert.

**Subsets.** A subset forward of whole pieces is excused for every k-gram inside a kept piece or a
delivered join of consecutive kept pieces. A k-gram spanning a seam the forward created is evidence
only if some other caller was delivered that exact join. A source is a tool name (`{server}:{tool}`,
`collusion_gate.rs:612`), so one tool may return one text split on one call and joined on another.
If it delivered another caller the exact join of the kept pieces, sensitively, the holder's subset
forward is refused. That is an in-model defect: MIK-8205.

### 14.2 Cross-tool copies: the per-source excuse is load-bearing (MIK-8206)

An honest caller delivered the same text verbatim by a second tool is refused, because the excuse
needs the copy from the same source. The rule closes an in-model laundering path:
1. A, delivered sensitive P by `docs:read`, writes P with `notes:write`. That passes: the check skips
   the sender's own records (`collusion.rs:631`), as it must.
2. B reads P with `notes:read`.
3. B sends P with `mail:send`. B holds P only from `notes:read`, so B is refused and the relay is
   caught. With a per-caller excuse it would leave unseen (row `shared_store_relay_not_excused`).

Saving what one read and forwarding what one found are both ordinary, so the path is in model.
**Decision:** the per-source rule stays, as a stated bound. Refusals where the sender holds the text
from another tool are counted in an exported metric and the refusal names that reason (MIK-8206).

**Rejected: an egress ledger** that excuses a cross-tool copy unless another caller sent the text
out before the copy arrived (exact records, ordered by a sequence number under the detector lock,
kept in the fingerprint's entry). Both reviewers showed it unsound:
1. A writes P to `notes:write`; the ledger records it.
2. Traffic sweeps or evicts P's entry (§5, flush), and the ledger goes with it.
3. B reads P from `notes:read`.
4. A reads P from `docs:read` again: evidence returns with an empty ledger.
5. B sends P and is excused.

The store outlives the detector's memory; history kept elsewhere fails the same way at its own bound.

### 14.3 Budget: what the control may miss or refuse

A finding that shows only a budgeted effect, at or under its stated rate, is not a defect. A change
that makes a budgeted rate worse is a regression and is in model.

**B1 sampling (D1).** Let n be the number of distinct k-grams of the forwarded run not excused for
the sender. It is missed when fewer than 2 are kept: P_miss(n) = (3/4)^n (1 + n/3). Length gives
only an upper bound on n (a copy of L chars has at most L - 47 distinct k-grams, an unreceived tail
of s chars at most s); repetitive text has fewer (100 repeated "a" chars: one k-gram, always missed).
The examples assume no repeated k-grams.

| n | Example | Per text | 1 in | Per 100 texts |
|---|---|---|---|---|
| 19 | 20-char unreceived tail, one k-gram held through the join (MIK-8196 measurement) | 3.10e-02 | 32 | 9.57e-01 |
| 32 | 79-char copy, or 32-char tail | 1.17e-03 | 853 | 1.11e-01 |
| 40 | 87-char copy, or 40-char tail | 1.44e-04 | 6,937 | 1.43e-02 |
| 53 | 100-char copy, or 53-char tail | 4.46e-06 | 224,226 | 4.46e-04 |
| 55 | 56-char tail (MIK-8196 failing row) | 2.60e-06 | 384,879 | 2.60e-04 |
| 80 | 127-char copy, or 80-char tail | 2.80e-09 | 357,389,749 | 2.80e-07 |

"Per 100 texts" is 1 - (1 - P)^100: how often a 100-text row fails if it asserts "always".
**Acceptance test** (B1 only): over N >= 10,000 independent texts of one n, the miss count M is within budget
when M <= N·P + 3·sqrt(N·P·(1 - P)). MIK-8196 measured M = 625 at N = 20,000, n = 19, against a
bound of 694; with every k-gram kept, 0.

**Determinism.** The sampling key is drawn once per process (`collusion.rs:303-305`), so which
k-grams are kept cannot be predicted from outside. Inside one process a text always gets the same
verdict, so a retry cannot draw a new sample (row `a_retried_relay_gets_the_same_verdict`). A row
that depends on the draw keeps every k-gram or asserts the B1 rate.

**B2 capacity bounds.** Each is accepted only if an operator can see it as a metric and a refusal it
causes names it (MIK-8201):
- 4,096 fingerprints per delivery: D1 past that point (a standing bound).
- 250,000 tracked fingerprints, oldest evicted: D1 for evidence older than the effective window.
- 64 records per caller per fingerprint and a 65,536-record pool: a sensitive record that does not
  fit becomes overflow, which refuses any other caller's egress of that text even with a
  same-source copy (D2). Needs one text delivered to one caller from over 64 sources, or the pool
  exhausted, inside one window.
- The per-source excuse (14.2), with its own metric and named refusal (MIK-8206).
- Cut-delivery sketches (MIK-8200). A sketch lives as long as its delivery's window, with no count
  cap. Memory: at most 32 MiB of sketches across every pair, live and being built, and at most
  8 MiB for one (source, caller) pair; past either, the oldest live sketch goes (the pair's own for
  its 8 MiB). A sketch still being built is never evicted. A sketch that cannot fit even then is
  not built: the delivery is recorded without one, and the refusal is counted. A 1 MiB delivery's
  sketch is about 735 KiB, so 7 fit one pair's budget.

**B3 Bloom false excuse (D3).** A pair's sketch at position i is sized for a target rate of
0.35% × 2^-i, using the classic ideal-hash rate with independent per-probe mixing (splitmix64);
sizing is bounded by the byte cap. The guarantee is the measured aggregate across all of a pair's
live sketches: 0.69% (95% CI [0.67%, 0.71%], 800,000 trials) for 8 sketches of 10,000 then 40 of
16 fingerprints, against a stated bound of 0.8% for production-sized sketches. It applies only to
the holder's own (source, caller) pair. A relay with exactly 2 matches is lost if either is falsely
excused: under 2%.

### 14.4 Falsifier

The model must keep what already proved real. MIK-8113 (a run across a seam missed, D1), MIK-8123
(fan-out dropped holder records, D2 and D1) and MIK-8066's merged excuse (a holder refused for the
middle of its own long answer, D2) are all in model.

### 14.5 Members classified

| Ticket | Direction | Class | Disposition |
|---|---|---|---|
| MIK-8066 CAP.2: the middle of a delivery over 6 KiB is never receipted | D1 | in model | Fix: a thinned sample of the cut middle as evidence, safe for holders because the cut-delivery sketch excuses their own copy; its miss rate is stated in B1 terms when it lands; after MIK-8200 |
| MIK-8066 BIG.3 and remainder: plan answers or steps over 1 MiB lose receipts and excuses | D1, D2 | in model | Fix: streaming sketch build; the thinned sample |
| MIK-8209 (from MIK-8035) residuals 1, 3: content items, labelled parts | D2 | in model | Fix: the per-key-path join |
| MIK-8209 (from MIK-8035) residual 4: plan path has no run-together form | D2 and D1 | in model | Fix: the per-key-path join applied to the plan answer's k-grams |
| MIK-8209 (from MIK-8035) residual 2: over the cap, flat and split receipts cut differently | D2 | in model | Pin with one row; likely met by MIK-8066's sketch |
| MIK-8196: a 56-char tail missed once on one platform | D1 | in model, inside B1 | Row keeps every k-gram; determinism row added |
| MIK-8200: sketch eviction refuses a holder | D2 | in model | Fix (High): see B2 |
| MIK-8201: capacity bounds not metered or named | B2 visibility | in model | Fix |
| MIK-8205: subset forward refused against the same tool's exact join | D2 | in model | Fix |
| MIK-8206: cross-tool verbatim copy refused | D2 | stated bound (14.2) | Fix: metric and named refusal |
| MIK-8136 (1): a run of over 256 bytes of combining marks without a starter may normalize differently near the forced cut | D1 only | out of model | Pathological input; a miss, never a refusal |
| MIK-8136 (2): cut rule not checked against the Unicode corpus | none | not a finding | No concrete input |

### 14.6 Stop rule

A relay finding blocks a PR, reopens a ticket, or creates one only if it carries all four:
1. a concrete input (bytes, not a description);
2. an in-model case under 14.1. The accepted misses stay out of model by name: `Common` poisoning by
   colluders who control `common_principals` identities, flushing the fingerprint map,
   cross-replica relay, and the rest of §5 and §9;
3. its direction. An unbudgeted D1 or D2 has zero tolerance: one deterministic reproduction suffices.
   A budgeted rate needs a measured rate over the 14.3 bound, or a regression raising a stated rate;
4. a red row at a production path: recording through `Firewall::delivery_digest` or
   `receipt_digest`, plan retention through `retain_delivered` and `cap_kept`, seams through
   `seam_fingerprints`, then `record_digest`; egress through `check_relay` or
   `relay_block_message`. A gateway-level reproduction through `router/backend_handlers/relay.rs`
   or `meta_mcp/invoke/relay*.rs` also counts.
   `record_delivery` is a test shorthand for `delivery_digest` plus `record_digest`.

Anything else gets one line in the ledger below and no ticket. Reviews of relay PRs receive this
section and grade their own findings against it.

| Date | Finding | Failed item |
|---|---|---|
| 2026-10-09 | MIK-8136 (1): combining-mark run over 256 bytes | 2 |
| 2026-10-09 | MIK-8136 (2): Unicode corpus coverage | 1, 4 |
