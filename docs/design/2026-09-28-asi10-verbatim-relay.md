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
