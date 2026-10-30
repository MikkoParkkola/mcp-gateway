# Backend upstream events per subscriber

Status: normative. This is the consolidated design for backend upstream events
(`backend.<name>.tools_changed`, `resource_updated`, `resources_changed`,
`prompts_changed`) on backends reached with a per-user credential. Where the code
and this document disagree, one of them is a bug.

## 1. Invariants

- **ISO.1** A change observed through a backend connection authenticated as
  principal P reaches only rows whose observation key is P's, through every path,
  durable replay included.
- **ISO.2** A row with an observation key is never served by a connection
  authenticated as anyone else: not the gateway's own credential, and not a stale
  lease of P (§2.5). On a backend whose propagation is `required`, no listener ever
  runs as the gateway. On an `optional` backend, a row with no verified identity (an
  API-key caller) has no observation key and may be served by the shared,
  gateway-credentialed listener, exactly as its `tools/call` falls through to the
  static credential.
- **ISO.3** State gathered under one key (a catalogue snapshot, coalescer debt, a
  confirm clock, a legacy-holder ledger, a tools debounce generation) is read and
  changed only under that key.
- **ISO.4** No listener for key K starts, reconnects or revives unless a live,
  admitted row holds K. Admission is re-checked at each of those points, not only at
  delivery.

## 2. Per-principal observation

### 2.1 The observation key `obs`

`obs` is stable for a user and changes only when which identity is asserted changes.

| Backend credential | `obs` |
|---|---|
| shared (no propagation, shared OAuth) | none |
| `signed_assertion`, `token_exchange` | the identity binding of the asserted actor and audience; for token exchange, also the endpoint and scope |
| managed account (vault) | the account and audience, with no lease fields (leases are fenced separately, §2.5) |
| `passthrough` | the identity binding of the subscriber's gateway identity, never a hash of the token (§3) |

- `obs` is **never persisted**. Each row stores the identity mint set the call path
  asserts (issuer, subject, email, groups) and an `obs_basis`: the canonical,
  non-secret operator-config tuple that defines `obs` besides the identity
  (strategy, audience, token-exchange endpoint, scope, account descriptor). Both are
  plain data, so there is no keyed digest to migrate.
- `obs` is derived wherever it is needed, from the stored identity and the live
  backend configuration, through one function that subscribe, `row_key`, restart
  and reload all share. They cannot disagree.
- A reload or restart whose recomputed `obs_basis` differs from a row's revokes the
  row (-32012) rather than re-keying it silently. This also covers a backend that
  moves between shared and identity-bound.
- `obs` is an identity digest. It never leaves process memory, and it is a
  forbidden field for logs, answers and records (it joins the census and the
  subscription-id source scans).
- The vault `obs` has its own no-lease derivation, so the lease-bearing cache
  binding is never used for routing.

### 2.2 Lifecycle and row keys

- A backend source's lifecycle key is `[obs, name, args]` for an identity-bound
  backend and `[name, args]` otherwise; `row_key(sub)` returns the same from the
  row. Restart replay, held rows and stop reconciliation therefore key identically.
- Subscribe computes the full key once and passes it to `start_key` /
  `on_first_subscriber`. The events principal is never used to derive `obs`.
- An identity-bound backend asked for a lifecycle key with no observation is a hard
  error.
- Listeners start and stop per `(backend, obs)`. `on_last_subscriber` parses both
  key shapes.
- **Every backend notification sets `lifecycle_key` to its emitter's key and is
  never `None`**, the reload announcement and the shared listener included. Fan-out
  then confines it to that key's rows. As a second line, a backend notification
  whose `lifecycle_key` is `None` matches no row that has an `obs`.

### 2.3 The listener's credential, on every request

- A listener's transport is built with
  `ListenerCredential { identity_key, source: Option<Arc<dyn CredentialSource>> }`.
- The only send path is `CredentialSource::with_credential(|headers| send)`. It
  covers every request the listener issues: the SSE GET handshake and `initialize`,
  `notifications/initialized`, the era probe, the modern listen POST and session
  GET, re-handshake and session recovery, legacy interest POSTs, and catalogue,
  confirm and refill reads.
- For a credentialed transport, headers are the protocol headers plus the source's
  headers only. It never fetches a gateway OAuth token, never sends the operator's
  static `Authorization`, and never starts a gateway OAuth login.
- An identity-bound key with no source, or a source that errors, sends nothing: a
  hard error, never a fallback. `ListenerCredential::shared()` is legal only for a
  shared key.
- For `signed_assertion`, `token_exchange` and vault, the source mints through the
  same audited path a call uses (header validation, then the minted-credential
  audit, fail closed). When required auditing is unavailable the source refuses and
  the listener backs off; it never mints unaudited. After the retry budget its rows
  end with -32012 and a named reason.
- Each listener holds its own per-`obs` transport and session. It never reuses a
  call's session; the per-user slot is shared for accounting only (§2.10).

### 2.4 tools_changed

- For an identity-bound key the listener emits a backend notification itself, with
  its own lifecycle key. It does not call the gateway-wide catalogue announcement.
- The tools debounce is keyed `(backend, obs)`.
- The tools refill reads P's catalogue through P's credential and updates only P's
  per-user catalogue entry, never the shared one.
- The gateway-wide announcement (a reload, or the shared listener) keeps the shared
  key and never reaches rows with an `obs`; those rows learn of a reload through
  their own listener's refill.

### 2.5 Vault leases: stable route, fenced state

*Required; delivered by the vault lease fence fix (in review).* Until it lands, a
vault listener mints a fresh credential on every request, so new requests use the
current lease, but nothing below fences a rotation.

- The route key carries no lease fields. A listener run is fixed on the binding its
  first mint released and never changes it, so no later request can relabel an
  older stream.
- Three things end the run before any request goes out under a new grant: a mint
  under another binding, a refused mint whose grant reads as no view, and the
  run's own 30-second fence read finding a moved or revoked grant. The run's notices, refill
  and tools debounce end with it; carried tools debt is tagged with the run that
  heard it and dropped by a run on another grant.
- Vault rotation uses the same generation registry as passthrough leases (§3.5).

### 2.6 Personal OAuth

- A raw per-backend OAuth login (enabled, not a shared account, no managed account)
  is one gateway-held login, not per-subscriber custody.
- On a multi-user gateway it stays refused with -32014 `per_user_credential`.
- It is supported only through a managed-account binding, which compiles to the
  vault strategy, where each subscriber resolves their own account.
- On a single-user gateway it is admitted as before. There is no other user.

### 2.7 Confirming reads, URI revoke, ledger: per key

- Confirm clocks, legacy-holder ledgers and gates, absent-URI revocation and the
  snapshot path are keyed `(backend, obs)`.
- Absent-URI revocation judges only rows whose `obs` matches: P's complete
  catalogue read never ends Q's `resource_updated` rows.
- The legacy-holder ledger is per key, so P's legacy `resources/subscribe` holds
  are released only by P's listener.

### 2.8 Durable delivery: outbox and dead letters

- An outbox record carries `ObservedUnder { incarnation, obs_basis, lease }`: the
  row incarnation, the observation basis and, for vault and passthrough, the lease
  binding or generation (the vault lease binding is *required*, delivered by the
  vault lease fence fix, in review; today only the passthrough generation is
  stamped). It carries no identity digest and never the token.
- For vault, the stamp is the run's binding, prefixed `vault:` so it never equals
  a passthrough generation. Delivery reads the grant afresh after every wait and
  before the signing row: custody that cannot answer in time defers the record
  unsent within its retry window (`fence_unavailable`), a grant with no view
  buries it (`grant_no_view`), and one 10-second deadline runs from that read to
  the request's end; a window that runs out before the send starts sends nothing
  (`fence_stale`).
- Fan-out writes it from the occurrence.
- A send attempt checks it twice: when the attempt is claimed, and again after the
  authorization and audit waits, against the row re-read for signing. It requires
  the same incarnation, the same `obs_basis`, and exactly the current lease (no
  successor is accepted). A mismatch, or a missing `ObservedUnder` on a row that
  has an `obs`, buries the record as `observation_changed` and never sends it.
  Nothing is signed or sent between the second check and the POST except the
  request itself.
- A same-id re-grant has a new incarnation, so it never inherits the previous
  grant's queue, even with an unchanged `obs`.
- Dead-letter replay applies the same check before re-queuing and refuses an
  incompatible record with a reason in the admin answer. *Implemented:*
  `replay_dead` runs the send path's `observed_now` comparison on the row as it
  is after the access re-check, and refuses a mismatch as `observation_changed`
  (HTTP 409 from the admin route; `replay all` lists the reason per record).
  Nothing is re-queued for a refused record. A row that changes between this
  check and the re-queue is still buried at send.
- Records written before this change have no `ObservedUnder`. They are valid only
  for rows without an `obs`, which was every row, since identity-bound
  subscriptions were refused until now.

### 2.9 Admission before work, not only at delivery

- `on_first_subscriber`, the revive sweep, every reconnect and backoff wake, and
  restart replay run the same live admission fan-out uses, for at least one row
  holding the key. If none is admitted, the listener does not start, or it stops,
  and its rows follow the existing refusal handling (-32012).
- **First subscriber.** At subscribe, the identity slot and the listener capacity
  are reserved before commit. After the row is durably committed, the listener
  starts under the lifecycle lock and re-admits the now-existing row. A failure
  after commit releases the reservation and revokes the row.
- **Revocation is pushed.** A gateway credential revocation (an API key removed on
  reload, a key-server token revoked) signals the events runtime from the same
  hooks that fire -32012. An OIDC provider or key-server policy change is not
  one of them: providers live in `key_server.oidc`
  (src/config/features/key_server.rs:67), and `key_server` is a restart-only
  section (src/config_reload/diff.rs:212, pinned by
  src/config_reload/restart_required_tests.rs:176). It takes effect on restart,
  where the rows it no longer admits are revoked before replay
  (src/events/runtime.rs:203). After a signal, on its next scheduler turn the
  runtime revokes the rows that can no longer be observed or admitted,
  which cancels their listeners and wipes their leases. As a fallback, the
  events worker's housekeeping sweep (every 30 seconds) runs the same
  revocation, so a quiet listener stops even if a signal was missed.

### 2.10 Listener ceiling

- No new setting. Per-user listeners are capped per backend at
  `MAX_PER_USER_LISTENERS` = `MAX_IDENTITY_SLOTS - MAX_SLOTS_PER_PRINCIPAL`, which
  leaves the identity-slot pool a share for calls. The cap counts listener keys.
- Listeners are capped separately and do not consume call slots, so eviction never
  displaces a call for a listener.
- A subscribe that would need a listener past the cap gets -32013 with
  `data.limit = "identity_slots"`.

## 3. Passthrough token lease

`passthrough` forwards the caller's own token and, by ADR-008's INV-4, the gateway
stores and mints nothing. One scoped exception applies: the gateway may hold a
subscriber's own passthrough token **in memory only**, solely to run that
subscriber's event listener. Calls still forward and never read a lease.

### 3.1 Source and binding

- A passthrough subscribe commits the row in state **credential needed** and
  creates no lease.
- A lease is created or replaced only by an explicit request on the direct route:
  `POST /mcp/{name}` with method `events/lease`, params `{ "subscription": <handle> }`,
  and the token in `x-mcp-passthrough-authorization`. It is accepted only when the
  caller's gateway principal owns that live row by `obs` and handle, the handle's
  row is `backend.{name}.*` for that path's `name`, the backend is `passthrough`,
  and the token passes §3.2. A handle on another backend is refused with -32012.
- `events/lease` is intercepted after caller authentication and before identity
  propagation and dispatch, so the backend never sees it. The meta surface and the
  stdio events surface refuse it (-32601).
- Subscribe and `events/lease` derive ownership and `obs` from one function, the
  events owner principal.
- No other request creates or refreshes a lease. A `tools/call` carrying a
  passthrough token is forwarded as before and never touches the lease store.
- A subscriber with no verified gateway identity cannot subscribe on a passthrough
  backend (-32012): there is no stable `obs` to bind to.

### 3.2 Expiry

- The token must carry a numeric `exp`. It is decoded after stripping a leading
  `Bearer ` (the signature is not verified; the backend verifies it). An absent or
  malformed `exp` is refused first, with -32014 `passthrough_token_no_expiry`; only
  then is `exp` judged with the gateway's one JWT time window, with a named leeway.
- A lease lives until `min(exp, subscription expiry, MAX_LEASE_TTL_SECS)`.
  `MAX_LEASE_TTL_SECS` is a code constant, 12 hours: it bounds custody of a
  long-lived token whatever its `exp` says. It is not a setting.

### 3.3 Memory only

- The token is held in `zeroize::Zeroizing` inside a `LeaseStore` that is not
  `Serialize`, not `Clone`, and has a redacting `Debug`.
- It is never written to the events store, outbox, dead letters, snapshots,
  control-plane export, a config rewrite or any file, and never placed in a log,
  span, error or answer. A source scan fails any lease value reaching `tracing`, an
  error message or a `Serialize` derive.
- Listener paths log only local error categories and codes on a credentialed
  transport, never a transport error's text, and never put `Authorization` in an
  error or `Debug`.
- Zeroized on drop. A restart loses every lease; rows wait in credential needed.

### 3.4 Parked until leased

- A passthrough key with no current lease is **parked**: it is absent from the
  lifecycle's started set, so `on_first_subscriber` is not called for it, and a
  successful `events/lease` is its first `start_key`. Revive, restart replay,
  reconnect and the snapshot tick all leave a parked key parked.
- A missing lease is never a mint failure: no hard error, no retry, no revoke. The
  retry-then-revoke path of §2.3 applies only to strategies that can mint.

### 3.5 Replace and wipe are fenced

- Every create or replace takes a fresh random 128-bit `generation`, held in memory
  and not derived from the token. Outbox records observed under a lease carry the
  generation, never the token or a digest of it; delivery requires it exactly, so
  after a restart every queued passthrough record is buried.
- The order for a wipe or replace is:
  1. bump the generation and fire its cancellation token;
  2. drain every in-flight listener request;
  3. take the write lock;
  4. zeroize, or install the new token.
- `with_credential` checks the generation under the lease lock and holds a read
  guard for the whole send. An open stream outlives its closure, so its read loop
  runs under the generation's cancellation token and a wipe or replace ends it.
- A replace runs §2.5 in full: close the session, drop the snapshot, coalescer
  debt, tools debounce and confirm clock, and reopen under the new token before
  anything is emitted.
- **Webhook deliveries.** After the bump, no new callback handoff begins for a
  record observed under the old generation. A handoff already committed is drained
  to completion and keeps the existing "possibly sent" classification: a POST whose
  body the receiver already has cannot be un-sent. Isolation is unaffected, since
  every such record was observed for the same principal while its lease was
  current. The token is zeroized as soon as the listener sends that hold it have
  drained; waiting for webhook drain is a separate "rotation complete" step and
  holds no token.

### 3.6 Wipe triggers

Each wipes the lease immediately and parks the key:

- the key's last row unsubscribed, revoked or expired;
- `exp`, the subscription expiry or `MAX_LEASE_TTL_SECS` reached;
- the backend removed, or its propagation config changed (an `obs_basis` mismatch);
- the gateway principal's credential revoked (§2.9);
- **rejection**: the listener transport reports `on_rejection(status, phase)` at
  the response boundary, before any recovery or error folding. A 401 anywhere, or
  any authentication failure on handshake, `initialize` or listen-open (a 403
  included), wipes the lease and marks the rows **credential rejected**. A 403 on a
  per-resource read or a catalogue fetch refuses that read only. The hook carries
  the generation, so a stale response cannot wipe a newer lease. Rejection cleanup
  runs after its own send guard is released.

The next successful `events/lease` resumes a rejected or expired key.

### 3.7 Visibility

- The admin and UI views (`/ui/api/events/leases`, admin only) list each held lease
  as a held credential: backend, the subscription handle (an alias, never the
  stored id), `expires_at` and state (`active`, `credential_needed`,
  `credential_rejected`). They never show the token or any digest of it.

### 3.8 Process memory

Zeroize-on-drop does not cover core dumps, swap or VM snapshots.

- **Core dumps are refused, not documented.** At startup, if any configured backend
  uses `passthrough`, and again idempotently at the first `events/lease` of a
  process reloaded into passthrough, the gateway applies a dump guard:
  - on Unix targets that support it, `setrlimit(Core, 0/0)` (lowering the hard
    limit is one-way for an unprivileged process, which is intended);
  - on Linux and Android, also `NotDumpable`, which additionally blocks same-user
    ptrace attach and `/proc/<pid>/mem` reads.
- The result is cached as `DumpGuard::{Applied, Failed(reason), Unsupported}`. Unless
  it is `Applied`, every `events/lease` is refused with -32014
  `core_dump_guard_unavailable`, `data.detail` naming the failed call
  (`setrlimit_core`, `prctl_dumpable`) or `platform_unsupported`, and no lease is
  created. Windows and other non-Unix targets are `Unsupported`, so leases are
  refused there; calls to passthrough backends are unaffected.
- **Swap is the operator's.** Run the gateway with encrypted swap or none.
  `mcp-gateway doctor` warns, when passthrough is configured, unless every active
  swap entry is verified encrypted (an entry whose status cannot be determined
  counts as unencrypted), and also reports whether this platform can apply the
  core-dump guard.
- Both calls come from `rustix`, already a direct dependency: no new crate and no
  `unsafe`.

## 4. Transports

### 4.1 SSE-handshake backends

The listener runs its own legacy session (`SseListenSession`), separate from the
calls' session:

1. GET the SSE endpoint with the key's credential (§2.3).
2. Take the `endpoint` event and keep the stream.
3. POST `initialize` to the message URL; read its result from the POST body or,
   when the body is empty, pair it by `id` from the retained stream.
4. POST `notifications/initialized`.
5. Only then run the legacy `resources/subscribe` walk.

- Frames are decoded with the existing bounded SSE decoder, never a new parser.
- The message endpoint is checked with the existing origin validation.
- `notifications/*/list_changed` and `resources/updated` feed the key's coalescer.
- The listener type is the same for every transport: the key decides the
  credential and the transport decides the channel.

### 4.2 Owned sessions

`UpstreamListen` has an additive default method,
`own_session(credential) -> Option<Arc<dyn UpstreamListen>>`, which returns a
dedicated session for streamable HTTP and SSE when the credential has a source. A
credential with a source and no owned session is a hard error: the listener never
falls back to the calls' shared transport.

### 4.3 A2A backends

- `tools_changed`: on the snapshot interval, the listener refreshes the backend's
  actual tools view through the discovery path calls use, compares every field of
  each translated tool with the previous view, and emits on any difference. The
  card is the same for every caller, so the A2A listener is shared unless the A2A
  backend itself is identity-bound, in which case §2 applies.
- `resource_updated`, `resources_changed` and `prompts_changed` are refused with
  -32014 `a2a_no_such_capability`.
- Eligibility is reason-aware where a listener starts or ends. `listener_ineligible`
  is the full ineligible set minus backends whose only reason is the A2A
  capability, and it is used for listener start, tick and revive and for the
  `tools_changed` subscribe start. Catalogue, delivery admission and reload keep the
  full set. Identity reasons are judged before the A2A reason.

## 5. Tests

These are the required tests. Each must fail on the broken implementation it
names. This section states the requirement, not current coverage: a row is covered
only when a test exists that fails on its mutant.

### Isolation

- **ISO-T1.** *Covered* by `iso_t1_signed_assertion_each_user_receives_only_their_own_changes` and
  `iso_t1_token_exchange_each_user_receives_only_their_own_changes` (tests/per_subscriber_isolation.rs).
  Users U1 and U2 subscribe to `tools_changed` and `resource_updated` on
  one identity-bound fixture whose catalogue and resources differ per asserted
  subject. U1's change reaches U1 only and U2's reaches U2 only, and each user is
  served (positive half); absence is checked with a window after the positive
  delivery. Once with `signed_assertion` and once with `token_exchange`.
- **ISO-T2.** *Covered* at the delivery layer by the `iso_t2_*` rows in src/events/worker_vault_fence_tests.rs,
  and end to end, with each user's managed-account listener on its own minted credential, by the `iso_t2_*`
  rows in src/events/lease_replace_managed_tests.rs. The same with managed accounts on a multi-user gateway,
  plus a lease rotation mid-test: nothing observed under the old lease is delivered after it.
- **ISO-T3.** *Covered.* Durable path: U1's occurrence is queued, then U1's row is re-granted or its
  lease rotates. The queued record is buried as `observation_changed`, and dead-letter replay refuses
  it. Pinned by
  `events::worker::tests::obs::a_record_queued_before_a_regrant_is_buried_as_observation_changed`
  (src/events/worker_obs_tests.rs; the burial) and
  `events::admin::replay_obs_tests::a_replay_after_a_regrant_is_refused_as_observation_changed` and
  `a_replay_after_a_lease_rotation_is_refused_by_name` (src/events/admin_replay_obs_tests.rs; the
  refusal).
- **ISO-T4.** *Covered:* the cross-user revoke by
  `iso_t4_one_subscribers_catalogue_read_never_revokes_anothers_rows` (src/events/iso_revoke_tests.rs). U1's complete catalogue read never revokes U2's `resource_updated`
  rows. One row per shared-state class, each with the mutation that shares it:
  - **ISO-T4a** (`iso_t4a_*`, src/events/upstream_session_iso_tests.rs and upstream_listener_keys_tests.rs) overlapping tools notices across keys, against a shared debounce;
  - **ISO-T4b** (`each_listener_has_its_own_confirm_clock`) confirming reads across keys, against a shared confirm clock;
  - **ISO-T4c** (`one_subscribers_unsubscribe_keeps_anothers_subscribe`) legacy subscribe and unsubscribe across keys, against a shared
    legacy-holder ledger.
- **ISO-T5 (source scan).** *Covered* by the `iso_t5_*` rows in src/events/listener_scan_tests.rs and
  sources_tests.rs. On listener paths, every backend notification sets
  `lifecycle_key` from the listener's key and none is built with `None`; every
  listener send passes a credential; every `lifecycle_key` call site is covered.
  Fixture rows prove the scan fails when either is dropped.
- **ISO-T6.** A revoked U1 has no connection open once the revocation runs (at once
  on a pushed revocation, at the latest on the next 30-second sweep), even
  with a silent backend, and nothing is emitted for U1 after it; stop on the last subscriber is covered too.
  Unit level only: key-server policy changes take effect on restart, not on a
  reload, so no reload path exists for an end-to-end row to remove one user's
  access. That is deliberate (a reload reports "restart required"); the guidance
  that offers revoking a key-server token as removing a person is corrected by the
  revocation guidance fix.
- **ISO-T7.** A required backend never connects as the gateway for an `obs` key. The
  fixture records the presented credential on every request, and the test asserts
  the minted subject on each, including cold start, era probe, SSE handshake and a
  forced session recovery. Until the shared-slot fix lands, the gateway's own
  warm-start and health probe reach the backend on its shared session with no
  credential, against ADR-007 IDP.7: the row opens its window after the
  warm-start was seen and exempts the probe's `ping` with no `Authorization`
  header. With the fix, no request without a subscriber credential reaches the
  backend, and both go.

Also: restart with an unchanged key for a stored OIDC identity and a key-server
identity; a concurrent slot-boundary row (a call slot promoted into a listener pin
at the reserve edge); and a row pinning that an identity reason plus the A2A reason
stays listener-ineligible.

### Lease

- **LEASE-T0.** A direct-route call with no `events/lease` leaves the lease store
  empty.
- **LEASE-T1.** A token with no `exp`, or a malformed one, is refused.
- **LEASE-T2.** A lease request from principal Q never touches P's lease, and Q's
  token never reaches P's listener (the fixture records presented tokens).
  **LEASE-T2b:** a replace closes and re-handshakes before the next emit.
- **LEASE-T3.** Each wipe trigger clears the lease, with zero outbound requests
  after it, retries and legacy cleanup included.
- **LEASE-T4.** A 401 from the backend wipes the lease and marks the rows credential
  rejected.
- **LEASE-T5.** After a restart the rows are in credential needed, and nothing on
  disk contains the token (the store directory is scanned for its bytes).
- **LEASE-T6.** The memory-only source scan (§3.3), plus a backend that echoes the
  presented token in an error body: no log line, span or answer contains it.
- **LEASE-T7.** *Covered* by `lease_t7_a_replace_bumps_the_generation_before_it_drains` (src/events/lease_tests.rs)
  and `lease_t7_a_handoff_on_the_wire_at_a_replace_completes` (src/events/worker_obs_tests.rs). A rotation started while a delivery is in progress: no new callback
  handoff begins after the bump; an already-committed handoff completes as
  "possibly sent".
- **LEASE-T8.** A subscribe with no lease makes zero outbound requests while
  parked; `events/lease` then starts the listener, and its first request presents
  the token.
- **LEASE-T9.** A handle on backend B is refused on `POST /mcp/A` with -32012, and
  the backend sees no request.
- **LEASE-T10.** With the dump guard forced to fail (each call separately, through a
  test seam, on the startup path and on the first lease after a reload into
  passthrough), `events/lease` is refused with `core_dump_guard_unavailable` and the
  lease store stays empty.
- **LEASE-T11 (Linux).** In an isolated child process started dumpable, after the
  startup guard runs, `getrlimit(Core)` is 0/0 and the dumpable behaviour is
  `NotDumpable`.

Races: deterministic tests cover replace plus replace, replace plus expiry, and a
stale rejection cleanup arriving after a newer lease.

### Transports

- **SSE-T1.** The SSE fixture refuses `resources/subscribe` before
  `notifications/initialized` and answers `initialize` only on the stream; the
  listener completes the order and then delivers `tools_changed`.
- **A2A-T1.** A tool difference in a field other than name or description fires
  `tools_changed`; the other three kinds are refused with `a2a_no_such_capability`.
- `tests/mik_7630_events_refusal.rs` matches every refusal reason above.
