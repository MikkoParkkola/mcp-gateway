# HARDENED posture switch: design (4.0)

Status: FINAL r5 (rounds 1-3 + delta review applied; maintainer decisions recorded). Owner decision (binding): one opt-in switch extending `team_shared`
with five controls, plus a startup WARN and `doctor` finding when multi-user runs without it.

## 1. Problem, and the existing mechanisms (source file:line at b22970a7a)

| Control | Existing mechanism | Gap that flipping the existing flag does NOT close |
|---|---|---|
| Preset | `ContextIntegrityPresetConfig::TeamShared` `src/config/features/security.rs:468-512`; `from_preset` `src/context_integrity/mod.rs:303-330` | The preset covers only context integrity. None of the four other controls is tied to it. |
| Message signing | `MessageSigningConfig` `security.rs:145-216`; v2 delivery MAC `src/security/message_signing_v2.rs:55`; signing context `src/gateway/meta_mcp/signing.rs:41-60` | Signing is off by default. It signs only a literal external `gateway_invoke` (`signing.rs` `capture`), so `tools/call` results and direct routes go unsigned. |
| Anomaly blocking | `AnomalyDetector` `src/security/firewall/anomaly.rs:95-178`; block branch `firewall/mod.rs:448-483`; config `firewall/mod.rs:65-142` | **Inert (filed as #1756).** Both firewalls get a fresh `TransitionTracker` (`server/mod.rs:1211`, `:1753`) that nothing records into. The only production `record_transition` is `meta_mcp/invoke.rs:2689`, which feeds the meta tracker. `predict_next` is therefore always empty, every score is 0.5, and no threshold above 0.5 ever fires. Scoring is also non-monotonic: a transition never seen scores 0.95, while one seen once in 100 scores 0.99 (`anomaly.rs:169-172`). |
| SSRF on backend URLs | proxy-time check `src/gateway/router/authorization.rs:321-339`; `validate_url_not_ssrf` `src/security/ssrf/mod.rs:131-185`; `PinningResolver` `ssrf/resolver.rs:60-100` | `trust_configured_backends=true` by default skips the check. With the skip off, only IP literals are refused and hostnames pass (`ssrf/mod.rs:182-184`). The backend HTTP client has no `PinningResolver` (`src/transport/http/mod.rs:632-650`), and neither does the websocket client (`transport/websocket.rs:347`). A hostname that resolves to 10.x or 169.254.x reaches the backend. |
| Per-caller identity | `caller_grant_subject` `src/gateway/router/identity.rs:97-110` (OIDC > trusted-proxy or Access header > mTLS > OAuth agent), called at `router/handlers.rs:547` and `router/backend_handlers.rs:571`; `CredentialKind` `src/security/audit.rs:16-31` | A shared static bearer or API key with no subject is still served. The firewall, tenant and budget key is `session_owner_key` = `credential:<principal digest>` (`handlers.rs:134-142`), so every person behind one token shares one bucket. |
| Elicitation | `Declared::from_handshake` `src/protocol/meta.rs:445-470`; era fork `handlers.rs:1545-1549`; `ConfirmationPolicy::for_legacy` = proceed-with-warning `src/gateway/destructive_confirmation.rs:111-113` | A legacy client that declares no elicitation is served, and its destructive calls proceed on a WARN. (Context-integrity `Confirm` withholds content, `context_integrity/mod.rs:492`, so that path is not a second bypass.) |
| Multi-user detection | `AuthConfig::implies_multi_user(has_oidc)` `src/config/features/auth.rs:94-100`, used at `server/mod.rs:1711-1715` | No finding when a multi-user deployment is unhardened. `doctor` (`src/commands/doctor.rs:169-230`) has no security row. |

## 2. Behaviour

Enum `security.posture: standard (default) | hardened`, resolved once in `Config::load` before
`message_signing.resolve_with_env` (`config/mod.rs:588-590`; it returns early when signing is off,
`security.rs:227-229`). New module `src/security/posture.rs`. Hardened logs one startup info
line listing the five forced controls and their effective values. When `hardened`:

1. **Preset floor.** `monitor_only`/`local_developer`/`audit_only` become `team_shared`;
   `team_shared`/`enterprise_strict` are kept; `non_bypassable=true`.
2. **Signing.** `message_signing.enabled` is forced; no secret refuses start. Every successful
   `tools/call` result on both routes whose nonce was admitted is signed with the v2 MAC
   (`sign_json_rpc_response_at`); its nonce comes from `params._meta["io.mcp-gateway/nonce"]` and
   is checked before dispatch, like `gateway_invoke`'s (`meta_mcp/signing.rs:48-60`);
   an answer given before admission (the task-augmented gate's challenge or refusal and, on the
   direct route, a tool-policy or undeclared-key refusal) is delivered unsigned and leaves the
   nonce unspent (increment 5, row 7). `require_nonce` stays operator choice.
3. **Anomaly blocking.** `firewall.enabled` and `anomaly_detection` are forced; the block
   threshold is 1.0 unless set within `[0.9, 1.0]`. At 1.0 only a transition never seen after a
   warmed predecessor blocks; at 0.95 all 20 distinct successors of a diverse predecessor would.
   Increment 1 provides:
   - (a) **Two-step learning per control identity.** `observe` returns the pending pair and
     changes nothing; `commit` runs only when the final verdict (`firewall/mod.rs:502-507`) is not
     Block and updates predecessor and pair count. A striped `Mutex<()>` array indexed by a hash of
     `CallerKey` is taken before `observe` and released after `commit`, so one identity's calls are
     scored serially, never against a stale predecessor. No DashMap guard is held across another
     operation on the same map: the capacity path's `len()`/`iter()` (`anomaly.rs:138-150`) would
     self-deadlock, as the comment there records. Both routes (`handlers.rs:1420`, `backend_handlers.rs:114`) learn via the
     crate-internal `TransitionTracker::record_pair`, never the unbounded `last_per_session`
     (`transition.rs:60`). Pairs cap at 100k. At the cap, an unretainable call is counted (metric and doctor row).
     Hardened refuses it as `Unobservable`. Standard lets it through unscored, so log-only
     users never get a new refusal.
   - (a2) **Forced block, every posture.** At or above the block threshold the call is forced to
     Block after `resolve_action`, like `anomaly_blind` (`firewall/mod.rs:502-506`).
   - (b) **Monotonic scores.** Never-seen = 1.0; seen = `1 - confidence`. A first call, or a
     predecessor with fewer than `anomaly_min_observations` (20) *total* recorded transitions,
     is `Observation::WarmingUp`: not a score, never flagged or blocked, only counted. Today
     no-data scores 0.5 (`anomaly.rs:157,167`).
   - (c) **Load checks** (detection on only): `anomaly_threshold` in `(0.5, 1.0]`, block threshold
     in `(anomaly_threshold, 1.0]` (`firewall/mod.rs:96-99`), `anomaly_min_observations > 0`. The
     meta tracker (`server/mod.rs:928`) is not reused: session-only (`invoke.rs:2685`), persisted.
4. **SSRF.** `ssrf_protection` forced on, `trust_configured_backends` off. A per-backend
   `DestinationPolicy` denies private ranges; `private_backends` members may reach loopback, RFC
   1918 and ULA, never 169.254/16 or fe80::/10. Hostnames: `.no_proxy()` plus a `PinningResolver`
   with the policy on the backend HTTP client (`transport/http/mod.rs:632`) and OAuth client
   (`backend/lifecycle.rs:526`); websocket validates once, connects TCP to that address, then
   runs TLS and upgrade with the original SNI/Host (`client_async_tls`). IP literals are checked
   before backend start; before OAuth discovery, registration (the discovered registration endpoint, `oauth/client/destination.rs` `check_advertised_endpoints`) and
   token requests; and on each redirect hop (`ssrf/redirect.rs:54`). Denial: typed error →
   `-32600 "SSRF blocked"`. stdio unaffected.
5. **Per-caller identity.** Every HTTP MCP request on both routes must resolve a grant subject
   (`caller_grant_subject`), else 403 and
   `-32600 "per-caller identity required (security.posture=hardened)"` before the body is read. All credential kinds: the
   `DashboardSession` principal is shared (`auth.rs:706-719`) and key-server tokens are not per
   person. The one exemption is an API key with `kind: personal` (a new enum on `ApiKeyConfig`,
   `auth.rs:25`, default `shared`), which is a per-person identity by maintainer decision M2. The
   dashboard has no exemption (M5). stdio is exempt. **`CallerKey`**, length-prefixed like
   `stable_actor_id` (`personal_accounts/identity.rs:179`), is `Subject(authority, id)` with no
   credential digest when a subject exists (a new key-server token keeps its buckets, as the
   quota does, `key_server/mod.rs:112-114`), else `Credential(digest)`. It keys the per-caller
   buckets: `session_owner_key` (`handlers.rs:134-142`), the legacy-session control key
   (`handlers.rs:1401-1405`) and the direct route's `direct:{backend}` (`backend_handlers.rs:110-120`,
   fixed in #1785). **Session ownership** (`session_owner`, `handlers.rs:56-62`) is `(CallerKey,
   credential digest)`. Keeping the credential in it matters: a resumed session's held credential
   is overwritten (`streaming.rs:269-279`), so same-subject credentials with different scopes must
   never share a session.
6. **Legacy clients without elicitation.** A legacy handshake not declaring `elicitation` is
   refused with `-32600 "client must declare elicitation (security.posture=hardened)"`, after
   parsing `initialize` and before `get_or_create_session_scoped` (`handlers.rs:631`), on POST and
   GET (the identity check still runs first, before the body). The direct route keeps no handshake state,
   and none is added (no new store): under hardened it refuses every legacy-shaped request except an
   `initialize` that declares elicitation (`backend_handlers.rs:764`). Second line: the legacy fork (`handlers.rs:1545-1549`) uses
   `for_modern()` (refuse); stdio already refuses (`server/mod.rs:4210-4225`). Direct-route
   destructive backend tools are out of scope (M3: refuse at connect). On `/mcp`, every other
   legacy request, a sessionless `ping` included, only resumes a session a declaring `initialize`
   opened, and is refused when there is none (amendment, increment 5:
   `2026-10-01-hardened-increment-5-signing-elicitation.md` §2 Row 10).

**Startup refuses** under hardened: no `firewall` feature; signing secret under 32 bytes;
`private_backends` naming no configured backend; block threshold below 0.9. `posture` is
restart-only (`config_reload/mod.rs:1896-1909` pattern). **WARN + doctor** share
`posture::unhardened_multi_user(&Config)` = `implies_multi_user(!key_server.oidc.is_empty()) &&
posture == standard`: one startup `warn!` (`server/mod.rs:1711`) and the doctor row
`security-posture` (category `security`; also names the hardened dashboard 403).

## 3-4. Config surface (names approved, M1) and failure modes

Config: `security.posture: standard|hardened` (enum, default standard);
`security.hardened.private_backends: []`; `firewall.anomaly_min_observations: 20` (all postures);
`auth.api_keys[].kind: shared|personal` (enum, default `shared`; M2).

Failure modes:
| Condition | Result |
|---|---|
| startup check fails | refuse to start |
| posture changed on reload | reload refused |
| no subject, or no elicitation | 403 / `-32600` before the body is read; no session |
| private destination | `-32600 "SSRF blocked"` |
| score >= block threshold | `-32002` |
| no identity, or pair cap full | refused unscored (`firewall/mod.rs:436-446`) |

## 5. Migration / UPGRADING (item number from the coordinator)

**Default config: no behaviour change.** `anomaly_detection`, the block threshold, the tenant
guard and the budget all default to off (`firewall/mod.rs:137-142`, `tenant_guard.rs:74`,
`budget_guard.rs:68`). The items below affect only operators who already opted in, and each is
listed with its reason:
- **U1 (#1756).** Opt-in anomaly scoring and blocking now actually work; until now the control
  never fired. When the pair cap is full, standard only counts the event: it never refuses.
- **U2.** With a block threshold set, rules can no longer downgrade an anomaly block. The
  operator asked for blocks.
- **U3.** With detection on, a threshold <= 0.5 refuses to start, because it would flag every
  call.
- **U4 (#1785).** With a per-caller guard on, each direct-route caller gets its own bucket.
  Today they all share one.
- **U5 (`CallerKey`, all postures).** Where a subject resolves (OIDC/key-server, trusted proxy,
  Access, mTLS), per-caller buckets key on the subject, not the credential, and a key-server token
  exchange keeps its buckets. Session ownership also adds the subject, so it only gets narrower.
  Reason: one person, one identity.

**Adopting `hardened`:** list private backends, give every caller a subject, make sure clients
declare elicitation, and set the signing secret. **Dashboard MCP calls are refused (403)** unless
an IdP or Access subject is present: the dashboard principal is shared. Doctor names this.
CHANGELOG `[Unreleased]`; OWASP ASI03/ASI07/ASI10 cite this.

## 6. Test table (red-first; every test drives production constructors and real calls, no hand-trained trackers)

| # | Rule | Test name | Mutant that must redden it |
|---|---|---|---|
| 1 | firewall detector learns from real calls on both routes | `real_direct_calls_train_the_router_firewall`, `real_meta_calls_train_the_router_firewall` (`tests/anomaly_learning_e2e.rs`; firewall built by the server wiring; drive meta and direct calls; assert a score != 0.5 and a block) | restore the unfed `TransitionTracker::new()` |
| 2 | a never-seen transition scores above a rarely-seen one | `never_seen_scores_one_and_above_rare` | revert 1.0 to 0.95 |
| 3 | warm-up: a predecessor with fewer than min observations is neither flagged nor blocked | `cold_predecessor_is_warming_up` | return `Scored(0.5)` for warm-up |
| 3b | a threshold <= 0.5 refuses load; at 0.51 a warm-up call is not flagged and increments the `WarmingUp` counter, not a score | `anomaly_ranges_refused_at_load`, `warmup_has_no_score_and_is_counted` | drop the range check / return `Scored(0.5)` |
| 3c | a warmed predecessor with 20 equally likely successors (each scores 0.95) does not block at the hardened default | `diverse_warm_predecessor_not_blocked_at_default` | default block threshold 0.95 |
| 4 | recording leaves `last_per_session` empty; pair cap full: hardened refuses (`Unobservable`), standard counts and passes | `record_pair_leaves_session_map_empty`, `pair_cap_full_hardened_refuses`, `pair_cap_full_standard_counts_and_passes` | call `record_transition` / same outcome in both postures |
| 4b | a blocked A->B moves nothing; one identity's concurrent calls serialize (B->C scored against B), also at the identity cap without deadlock | `blocked_call_is_not_learned`, `stripe_lock_serializes_one_identity`, `committed_pairs_form_one_path`, `serialized_at_identity_cap_no_deadlock` | update in `observe` / hold a DashMap entry guard |
| 4c | an Allow rule cannot downgrade an anomaly block, in both postures | `anomaly_block_survives_allow_rule_standard`, `..._hardened` | force only under hardened |
| 5 | hardened raises the preset floor and keeps enterprise_strict | `hardened_raises_monitor_only_to_team_shared`, `hardened_keeps_enterprise_strict` | skip the floor / overwrite strict |
| 6 | hardened with a secret set only via env still resolves it; no secret refuses start | `hardened_resolves_env_secret_before_signing_check`, `hardened_without_signing_secret_refuses` | resolve posture after `resolve_with_env` / warn instead |
| 7 | a `tools/call` result is signed under hardened, on both routes | `hardened_signs_tools_call_on_both_routes` | keep the `external_gateway_invoke`-only guard |
| 8 | no subject → 403 on both routes, dashboard session included; a `kind: personal` API key passes, a `shared` one does not | `hardened_refuses_without_subject_meta`, `..._direct`, `..._dashboard`, `personal_api_key_is_identity` | remove the check on one route / treat `shared` as personal |
| 9 | subjects behind one token get separate buckets and sessions; same subject across token exchanges keeps one bucket; same subject, two credentials with different scopes, never share a session | `caller_key_separates_subjects`, `cross_subject_session_refused`, `token_exchange_keeps_bucket`, `same_subject_other_credential_new_session` | key on the credential / drop the credential from session ownership |
| 10 | no elicitation: refused before session on POST and GET; on the direct route every legacy request except an elicitation-declaring `initialize` is refused | `hardened_refuses_legacy_without_elicitation_no_session`, `..._get`, `hardened_direct_legacy_refused` | check after mint / skip GET / skip direct |
| 11 | a legacy-shaped destructive call is refused | `hardened_legacy_confirmation_policy_refuses` | keep `for_legacy()` |
| 12 | private hostname or literal refused at start, OAuth discovery, registration, redirect; websocket keeps SNI; an `HTTPS_PROXY` env does not bypass the policy | `hardened_startup_backend_is_pinned`, `hardened_oauth_refuses_private_authorization_server`, `hardened_oauth_refuses_private_registration`, `hardened_oauth_client_refuses_a_literal_redirect`, `pinned_websocket_keeps_sni`, `proxy_env_does_not_bypass_policy` | skip registration / connect by IP / drop `no_proxy` |
| 12b | under hardened, a set `capabilities.egress_proxy` refuses startup (#1881) | `hardened_refuses_capability_egress_proxy` | accept the key under hardened |
| 13 | listed backend reaches an RFC 1918 literal and hostname but never 169.254.169.254 | `listed_private_backend_policy` | apply the list to the resolver only |
| 14 | a posture change on reload is refused | `reload_refuses_posture_change` | drop the posture diff check |
| 15 | the WARN and doctor agree | `startup_warn_matches_unhardened_table` and `doctor_row_matches_unhardened_table` (one shared table over auth shapes) | doctor passes `has_oidc=false` |
| 16 | `standard` applies none of the posture overrides (rows 5-8, 10-14); row 9's `CallerKey` is posture-independent | `standard_posture_applies_no_override` | apply any override under standard |
| 17 | each startup refusal fires: no firewall feature, short secret, no configured backend named, block threshold < 0.9 | `hardened_startup_refusals` (table) | drop any one check |

As built (MIK-7633). Rows 3c and 4c run on the firewall a hardened `Config::load` produces
(`src/security/firewall/anomaly_learning_tests.rs`). Row 15 is two tests over one table: the
startup warning is crate-private and `doctor` lives in the binary, so one test cannot drive
both. `src/security/posture_auth_shapes_tests.rs` is the single table, declared by `#[path]` from
`posture.rs` and `commands/doctor/posture.rs`; it is read by `startup_warn_matches_unhardened_table`
and `doctor_row_matches_unhardened_table`. Row 17's short secret is set under `enabled: false`,
so only the posture's forcing makes it refuse.
Row 9's session half is also driven under `hardened`, where a resume never mints:
`hardened_resume_refuses_another_owner` (`src/gateway/router/hardened_elicitation_tests.rs`)
has a second personal key name the first key's session on POST and GET, and both are refused.
Row 12 has one test per destination check rather than one test for all of them.

## 7. Out of scope: forced `require_nonce`; tracker persistence, cross-replica state (new store);
A2A; stdio identity; #1441; ASI04; the `direct:{backend}` fix itself (#1785; `CallerKey` is here).

## 8. Maintainer decisions (2026-09-28)

M1 names approved (`security.posture`, `security.hardened.private_backends`,
`firewall.anomaly_min_observations`, `api_keys[].kind`, wire key `io.mcp-gateway/nonce`). M2 a
`kind: personal` API key is a per-person identity; every other hardened HTTP caller needs a
subject. M3 refuse non-elicitation legacy clients at connect. M4 block 1.0, floor 0.9. M5
dashboard MCP without IdP identity refused, no escape hatch. M6 `require_nonce` not forced.

## 9. Build increments

1. #1756 (all postures): two-step learning, bounded pairs, monotonic, warm-up, ranges, forced
block. 2. Posture resolver, preset floor, restart-only, WARN + doctor. 3. Subject requirement +
`CallerKey` (after #1785; the unreviewed session-ownership fix gets a design delta review first). 4. `DestinationPolicy`, pinning, literals; under hardened, startup also refuses a set `capabilities.egress_proxy` (#1881: all postures ignore env proxies; the key is the only proxy route). 5. Signing + elicitation.

**Amendment A1 (2026-09-28, maintainer ruling; reviewed with the increment-2 test plan).** Gap: the
hardened anomaly forcing stated at :31-33 (`firewall.enabled` and `anomaly_detection` forced; block
threshold 1.0 unless set within `[0.9, 1.0]`) and its row-17 refusal (block threshold below 0.9)
were assigned to no increment: increment 1 (:34-54, :175-176) lists only posture-independent items,
and increments 4 and 5 name SSRF and signing. Ruling: increment 2 (the posture resolver) owns the
anomaly forcing and the `< 0.9` refusal. They land after #1756 merges (they rely on its threshold
semantics); increment 2 freezes only then. Tests: rows 16 and 17 gain the forcing and the refusal;
new row 5b `hardened_forces_anomaly_blocking` (mutant: skip the forcing).

## 10. Review dispositions (all verified at source; all ACCEPTED; test rows in brackets)

r1 A: blocked retries train [4b]; `direct:{backend}` (`backend_handlers.rs:110`) [9, #1785];
direct route outside elicitation gate (both routes now; direct destructive tools out of scope);
literals bypass pinning [12]; rules downgrade block (`firewall/mod.rs:502`) [4c]; colon key
collides [9]; dashboard/key-server not per person (`auth.rs:706`) [8]; unbounded pairs [4];
session minted before `initialize` (`handlers.rs:631`) [10]. Coordinator: threshold <= 0.5 flags
all: `WarmingUp` + load ranges [3b]. r1 B: 0.95 blocks diverse successors, so 1.0 [3c]; listed
backend unpinned [13]; resolve order (`security.rs:227`) [6]; `io::Error` denial [12].

r2: A->B moved predecessor; two-step commit [4b]. Token exchange split a subject; `Subject` key
[9]. Sessions credential-only (`handlers.rs:56`); `CallerKey` [9]. OAuth registration unchecked
[12]. Cap left predecessors warming [4]. One `DestinationPolicy` [13]. Websocket SNI [12].
Forced block in all postures, U2 [4c]. Direct elicitation [10]. Row 3c fixture. Coordinator:
default unchanged; U1-U5 listed; ranges only with detection on. r3: stale-predecessor race [4b];
`no_proxy` [12]; direct and GET-first sessions [10]; dashboard 403 is an UPGRADING line (M5);
ranges collapsed; improvements taken (rows 3b, 16, 17; nonce placement; check order; warm-up
counts total transitions; startup summary). REJECTED: basing the WARN on hard multi-user signals;
the fail-closed `implies_multi_user` (`auth.rs:94-100`) is intended. Self-check: striped mutex
[4b]; direct route store-free [10]; U5. Delta review (rd, 2 seats: SHIP, SHIP-WITH-FIXES): the
subject-only session owner shared a session across credentials (`streaming.rs:269`); ownership now
`(CallerKey, credential)` [9]. No pair-cap split test; added [4]. Continuity test: already row 9. Seats: A first reviewer, B fallback second seat.
