# PR 473 unreviewed slice — security shard

Shard scope: the 16 security-relevant files of the PR 473 unreviewed slice
(firewall, idempotency, OAuth, trust). Pinned range `c3626cf8..60b138bb`.

## Payload

| item | value |
|---|---|
| whole shard | `5f004be8a5caf7326a2f57b72e9ba0d527fcb11ef5340f7c26c3333761ae2eaa`, 167,988 B, 16 files, ~3,046 insertions |
| half a (firewall) | diff `9d225683c75e415a7895d6ec1bbfc8308198728fe27323fab5fbe384c9e7c6df`, 96,757 B, 10 files, 1,872 ins |
| half b (idempotency+OAuth+trust) | diff `b82bb9f0626efa5244314c2c042fb1b849b6e3495d38cf541717eecdcedef200`, 71,231 B, 6 files, 1,174 ins |
| half a submitted material | `c505e477f774391eef072d393b231e946701f7174cd22bc4f8c52a1a650f7d6c`, 98,911 B (diff + review brief) |
| half b submitted material | `b68a2a86133217b197e6e7686c18aa4816486a0408db72dc4fd52b7e3dd41001`, 73,385 B (diff + review brief) |

Files: `src/idempotency.rs`, `src/oauth/{callback,client/mod,client/tests,metadata,mod}.rs`,
`src/security/firewall/{anomaly,budget_guard,input_scanner,mod,principal_window,tenant_guard}.rs`,
`src/security/transparency_log.rs`, `src/trust/{descriptor,mod,schema_bounds}.rs`.

### Deviations from the brief

- The payload exceeded the ~150 KB single-run guidance, so it was split in two
  and each half reviewed independently. Both halves carry the same review brief.
- The brief asks for foreground runs. The Bash tool caps at 120,000 ms and the
  reviewers need minutes, so the four runs were launched detached with a
  return-code file. Return codes were read from that file, verdicts from the
  ledger only.

## Ledger rows

Vendor 1 — `~/.claude/data/gpt-review-ledger.jsonl`, model `codex-default`:

| half | ts | verdict | material_sha256 | process_status |
|---|---|---|---|---|
| a | 2026-09-08T16:27:45Z | SHIP-WITH-FIXES | `1f3fc219fd665bc1425b30d665444bc345143ff2bab7bf5737f6a5e0ef258408` | ok |
| b | 2026-09-08T16:26:55Z | SHIP-WITH-FIXES | `f87ddbf6497915099b47c0ed56259960ff5a7575d8eb9b49d6688fc1c1d37c4f` | ok |

Vendor 2 — `~/.claude/data/grok-review-ledger.jsonl`:

| half | ts | verdict | material_sha256 | process_status |
|---|---|---|---|---|
| a | 2026-09-08T16:33:55Z | SHIP-WITH-FIXES | `1f3fc219fd665bc1425b30d665444bc345143ff2bab7bf5737f6a5e0ef258408` | ok |
| b | 2026-09-08T16:32:18Z | SHIP-WITH-FIXES | `f87ddbf6497915099b47c0ed56259960ff5a7575d8eb9b49d6688fc1c1d37c4f` | ok |

Both vendors carry byte-identical `material_sha256` per half, which is the proof
they read the same material. Rows are bound to this shard by `material_bytes`
98,912 and 73,386 — the wrapper digests `scope + NUL + material`, so the recorded
count is the submitted material plus one. Both vendors record `head e68082bc`,
the wrapper's live `HEAD` reading rather than the pinned review revision; the
material hash is the binding, not `head`.

A third run (`kimi-review`, which dispatches to `synthetic-review`) was launched
for half a while vendor 2 was still believed dead, and returned SHIP at
2026-09-08T16:33:07Z on `material_sha256 1f3fc219…`, `process_status ok`. It is
recorded here as corroboration, not as a gate leg. Half b of that third run was
abandoned once vendor 2 landed.

Vendor 2 initially looked dead: at 16:27Z its capture files held only progress
narration and it had written neither a return code nor a ledger row. It was still
running. **A reviewer that has not exited is not a reviewer that has failed** —
the brief's own rule, and the fallback was launched a few minutes early against it.

## Findings

15 vendor-1 items (9 half a, 6 half b) plus 6 improvements not triaged here, and
19 vendor-2 items across the same two halves. Numbering is this report's own.

### Confirmed

| # | finding | deciding source | severity | blocks 4.0.0 |
|---|---|---|---|---|
| 1 | Firewall master switch: `scan_requests=false` returns an unconditional allow before the budget and tenant guards run, so disabling argument scanning silently disables both explicitly-enabled controls | `src/security/firewall/mod.rs:361` — `if !self.config.enabled \|\| !self.config.scan_requests { return FirewallVerdict::allow(); }`, with the budget and tenant checks later in the same function | HIGH | YES — an operator-visible control does nothing |
| 2 | Direct backend calls share one control identity across every caller: `direct:{backend_name}` | `src/gateway/router/backend_handlers.rs:98`; passed as `control_identity` at `:108` | HIGH | YES — callers consume each other's budgets and pollute each other's tenant history |
| 3 | Session-keyed controls: when a session exists the per-principal budget and tenant guards key on the session id, so a fresh session is a fresh budget | `src/gateway/router/handlers.rs:1298-1302` — `control_identity = if session_id.is_empty() { session_owner_key(..) } else { session_id.clone() }` | HIGH | YES — the limit is evadable by reconnecting |
| 4 | Tenant guard yields zero observations for a list or filter object under a configured key, and zero observations is an allow | `src/security/firewall/tenant_guard.rs:141-146` — key match requires `tenant_name(child)` to be `Some`; `tenant_name` returns `None` for arrays and objects, and the fallback `collect` ignores bare scalars inside an array (`_ => {}` at `:154`) | HIGH | YES for any backend accepting `{"customer_id": ["a","b"]}` |
| 5 | Live history truncates at 4,096 observations per principal, so a configured budget at or above that ceiling can never be exceeded and tenant history is lost before the window expires | `src/security/firewall/principal_window.rs:45` (`MAX_OBSERVATIONS_PER_PRINCIPAL = 4_096`), `:109-111` (`pop_front` on overflow) | MEDIUM | NO — bounded by whether any deployment configures a limit that large |
| 6 | Eviction self-deadlock at capacity: the DashMap iterator's shard read lock is alive across the `remove` inside the same `if let` body | `src/security/firewall/principal_window.rs:177-179` — `if let Some(victim) = self.entries.iter().next().map(\|e\| e.key().clone()) { self.entries.remove(&victim); }` | HIGH | NO — requires 100,000 tracked principals, but it hangs the executor thread permanently when reached |
| 7 | Idempotency reservation released on drop while the backend call may already have executed | `src/idempotency.rs:546-551` — `Drop` takes the `OnDrop::Release` arm and calls `cache.remove(&self.key)` with no record of dispatch | HIGH | YES — a cancelled or timed-out call loses its duplicate-suppression |
| 8 | Idempotency entries are identified by key alone, so a stale guard's `Drop` can settle or delete a newer admission under the same key | `src/idempotency.rs:549` (`remove`), `:553` (`mark_completed(&self.key, result)`) — no admission generation or token anywhere on the path | HIGH | YES — a retry can receive another call's result |

### Confirmed at HEAD, not introduced by this diff

| # | finding | evidence |
|---|---|---|
| 9 | OAuth discovery accepts `http://` token and authorization endpoints; nothing enforces TLS on the credential-bearing requests | `src/oauth/metadata.rs` at HEAD has zero scheme comparisons; base `c3626cf8:src/oauth/metadata.rs` has none either (only `parsed.scheme()` at `:189`, inside base-URL extraction). Gap is real; this diff did not create it |
| 10 | Discovered authorization-server URLs are trusted verbatim as `oauth_base_url` with no destination policy, giving a malicious discovery response reach into the gateway's private network | HEAD `src/oauth/client/mod.rs:322-324`; identical trust at base `c3626cf8:src/oauth/client/mod.rs:240-241`. Pre-existing |

### Cannot verify

| # | finding | what could not be determined |
|---|---|---|
| 11 | Client secret from a previous issuer sent to a replacement issuer | The new tests confirm the token and registered client id ARE dropped on an issuer change (`a_different_issuer_drops_the_previous_issuers_token_and_registered_id`; `credential_key()` used at the three save sites in `src/oauth/client/mod.rs`). Whether an operator-CONFIGURED secret survives the same change was not traced to a deciding line |
| 12 | Anomaly-map admission race lets concurrent inserts overshoot the memory ceiling | `src/security/firewall/anomaly.rs` was not read |
| 13 | `expire_at` has no production caller, so expired principals are never reclaimed | `expire_at` exists at `principal_window.rs:126` and its doc comment claims the ordinary access path calls it; `record_at` calls only `evict_if_full` and `retain_live`. The claim looks right, but no repository-wide caller search was run |
| 14 | Per-principal idempotency capacity starvation (one caller fills 10,000 entries) | Store-level admission accounting at `src/idempotency.rs:281` was not read |
| 15 | Unbounded byte growth from caller-controlled tenant strings | Follows from finding 5's storage shape but no byte bound was located either way |

### Second vendor's independent findings

Vendor 2 read the same two payloads without seeing vendor 1's output. Where the
two agree the finding is stronger, not merely repeated.

Agreed independently, already in the tables above: the shared `direct:` control
identity (2), the `scan_requests` master switch (1), the tenant-array bypass (4),
the eviction victim selection (6), the idempotency clobber under a reused key (8),
and both OAuth items (9, 10).

Raised only by vendor 2, verified at source here:

| # | finding | deciding source | severity | blocks 4.0.0 |
|---|---|---|---|---|
| 16 | The tenant guard is a silent no-op when enabled with an empty `arg_keys` — and empty is the shipped default, so an operator who flips `enabled` alone gets a control that enforces nothing and reports nothing | `src/security/firewall/tenant_guard.rs:72-78` (`arg_keys: Vec::new()` in `Default`); no key match means `collect` yields nothing and `:107-112` returns `Allowed` on an empty tenant list. There is no early return on empty `arg_keys` — the vendor's mechanism was wrong, the effect is real | HIGH | YES — an enabled control that enforces nothing |
| 17 | `complete()` after `release()` caches the failure result under an EMPTY fingerprint, and an empty fingerprint matches every request — so any later call on that idempotency key, whatever its arguments, is served the stored error for 24 hours | `src/idempotency.rs:518-520` — `complete` calls `mark_completed` with no `settled` check (the doc comment at `:514-516` says this is deliberate); `:354-361` — the released entry is gone, so `get(key)` yields `None` and the re-inserted entry takes `String::new()`; `:149-151` — `matches` returns true when `fingerprint.is_empty()` | HIGH | YES — this is the wildcard, not just a clobber |
| 18 | The OAuth authorization code is written to the log in cleartext | `src/oauth/client/mod.rs:846` — the code value reaches a `tracing` field | MEDIUM | NO — short-lived, single-use, but it is a credential in a log |

Raised by vendor 2, cannot verify:

- `metadata.resource` is accepted from a discovery response without validation.
  The parse path was read; no validation was found, but which callers trust the
  field was not traced.
- A redirect can defeat the issuer check: the issuer is compared against the
  requested URL, not the final URL after redirects. Consistent with what was
  read at `src/oauth/metadata.rs`, not proven at a deciding line.

Two vendor-2 findings fall outside this shard's paths — `src/gateway/meta_mcp/invoke.rs:1208`
and `src/gateway/server/mod.rs:736`. Recorded as observations per the process
document's §P0 disposal table; neither is filed and neither blocks.

Additional non-blocking items both vendors raised on the new firewall code, kept
here without individual tables: `TenantVerdict::Refused` is routed through the
operator's action policy rather than force-blocked (so a broad `Allow` rule
downgrades it) while budget failures force a block — `src/security/firewall/mod.rs:524-538`;
`check_request` takes `caller` and `control_identity` as adjacent `&str`
parameters, so a swapped argument compiles clean — `:352-360`; the
`Unattributable` budget arm emits no warning where its siblings do — `:576-590`;
refused calls are still recorded into the budget and tenant windows, refreshing
the caller's own lockout — `budget_guard.rs:108-121`, `tenant_guard.rs:117-135`.

## Both named classes: answered

- **Credential exfiltration introduced by this diff — NO.** Findings 9 and 10 are
  real exfiltration and SSRF surfaces, and both exist unchanged at `c3626cf8`.
- **Authentication or authorization bypass introduced by this diff — NO** in the
  credential sense. Findings 2, 3 and 4 ARE bypasses of the new firewall controls
  this diff adds, and they are introduced here, but they defeat rate and tenant
  limits, not authentication.

## Not covered — stated plainly

Read at source: `firewall/{mod,principal_window,tenant_guard}.rs`, `idempotency.rs`
(reservation lifecycle only), `oauth/{metadata,client/mod}.rs` (scheme and issuer
paths only), `router/{handlers,backend_handlers}.rs` call sites.

Never opened, and no finding above rests on them:

- `src/trust/schema_bounds.rs` (558 insertions, the largest new file) — signatures skimmed only
- `src/trust/descriptor.rs`, `src/trust/mod.rs`
- `src/security/transparency_log.rs` — repudiation-relevant
- `src/security/firewall/anomaly.rs`, `src/security/firewall/input_scanner.rs`
- `src/oauth/callback.rs` — redirect and CSRF state relevant
- `src/security/firewall/budget_guard.rs`
- No test was executed and no build was run for this shard.
