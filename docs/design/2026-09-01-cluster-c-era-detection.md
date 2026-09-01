# Cluster C — wiring era detection into the outbound path

Status: design, unreviewed. No code exists yet.

## Scope

**FOR:** making the gateway determine each backend's protocol era by probing
`server/discover` and reading the answer's shape, so DISCOVER.4 and DISCOVER.5 are
met by the live outbound path rather than by an unused module.

**OUT:**

- DISCOVER.1/2, the inbound `server/discover` surface — shipped and assessed.
- The stdio dispatcher's always-legacy answer (`gateway/server/mod.rs:1687-1693`) —
  inbound, unaffected.
- `doctor` and operator-facing era reporting — see U5.
- Retiring the error-text parsing in `negotiate_and_retry` / `negotiate_protocol_version`
  — a Legacy classification still lands there; deleting it is a separate change.

## Problem

DISCOVER.4 (`docs/requirements/RELEASE-4.0.0-criteria-status.md:188-189`): era must be
determined by probing and reading the answer's shape, not by trusting a version string.
DISCOVER.5 (`:199`): the determination is cached **per backend for the life of that
backend's process**, and re-probed when a cached assumption fails.

## Measured constraints

**The classifier is complete and unwired.** `src/protocol/era.rs:20-198` gives `Era`,
`classify`, the three 2026-07-28 error codes and `EraCache`
(`resolve_with`/`cached`/`invalidate`). No caller outside its own tests.

**The live path decides era the way DISCOVER.4 forbids.** Transports open with
`initialize` carrying a `protocolVersion` string (`stdio.rs:275-284`,
`http/mod.rs:437-449`), read the echoed version back (`stdio.rs:326`), and on rejection
recover a version by **parsing the error message text** (`stdio.rs:310,373`;
`http/mod.rs:456-484`). Trusting a version string, twice.

**Two transports are on the outbound path, not three.** `StdioTransport::new` and
`HttpTransport::new_with_oauth` are constructed at `backend/lifecycle.rs:336,354`.
`WebSocketTransport::new` appears **only** in `websocket_tests.rs` — no production
constructor.

**A transport is not a backend.** `PoolKey::PerUser { binding }` (`backend/pool.rs:36-43`)
gives one backend one transport *per caller identity*. Per-transport state is
per-(backend, identity).

**Transports cannot see the running config.** `server.modern_protocol` occurs at
`config/mod.rs:1127,1174` and in the inbound handlers only. Transport constructors take explicit
arguments (command, env, cwd, timeout, `protocol_version`) and store no config handle
(`stdio.rs:78-99`).

**One modern revision exists.** `MODERN_VERSIONS = ["2026-07-28"]` (`protocol/meta.rs:219`).

## Options

**(a) An `EraCache` field on each transport struct, probed at connect.** *Rejected.*
`PoolKey::PerUser` means this caches per identity, so one backend is probed once per
caller where DISCOVER.5 asks once per backend — and writes the probe once per transport
type.

**(b) A central `EraCache` map at the provider/registry layer.** *Rejected.* Needs a
`BackendId` key plus an entry-lifetime rule `Backend` ownership gives free, and
invalidation raised inside the transports returns as a callback.

**(c) An `EraCache` field on `Backend`, probed from `start_entry`.** **Recommended.**
One `Backend` per enabled config entry, built in one loop over `enabled_backends()`
(`gateway/server/mod.rs:410-421`), held by name in `BackendRegistry`; a reload stops the
old instance and builds a replacement (`config_reload/mod.rs:889-905`) — the restart
DISCOVER.5's "life of that backend's process" already means. Keying falls out of
ownership: no map, no key type, no lifetime rule. The probe is written **once**, against `Arc<dyn Transport>` via
`Transport::request` (`transport/mod.rs:22`), which both live transports implement.
`start_entry` (`backend/lifecycle.rs:302`) is the single place a transport becomes
reachable, so request, warm start and `force_restart` are one call site.

Ordering: HTTP calls `initialize()` inside `start_entry`, stdio inside `start()`.
**This design probes after `initialize` on both and does not split `start()`** — the era
comes from the probe's answer shape either way, so DISCOVER.4 holds. Ordering only
becomes load-bearing if U1 says the gateway must *speak* 2026-07-28 on its first send,
and splitting `start()` is then work inside U1's answer.

Invalidation hangs off the existing version-mismatch branch inside each transport and
must reach the `Backend` — the one piece of coupling this option pays for.

**(d) Lazy probe on first request.** *Rejected as primary.* Splits era determination
from the connect it belongs to, and the first request pays an unasked round-trip.
Revisit if U2 comes back badly.

**(e) Infer era from the `initialize` response.** *Rejected* — current behaviour, and what
DISCOVER.4 names wrong.

**(f) Detection only: probe, cache, record, keep sending `initialize` regardless.**
Depends on U1: if the answer is detection-only, (f) rides on (c) and is the change.

## Open questions

### Resolved

- **U3 — does any configured backend advertise a 2026 revision today?** Surveyed configured
  and example backends: `gateway.example.yaml:54,66,78` set `protocol_version: null`;
  `examples/gateway-full.yaml:241` shows `2025-03-26`; `2026-07-28` appears in `src/` only.
  **Zero.** Changed: forward-compatibility work with no peer to benefit today, weakening
  the eager-probe case (feeds U2).
- **U4 — is outbound detection gated by the same `server.modern_protocol` switch as
  inbound?** Read `backend/lifecycle.rs:329-366` and `stdio.rs:78-99`. **No — a transport
  cannot reach the running config at all.** Changed: the probe is unconditional unless
  `modern_protocol` is threaded through `Backend` — free under (c), which already holds
  that config.

### Deferred — nothing depending on these gets built

| # | Question | Owner | What resolves it | When | If it resolves badly |
|---|---|---|---|---|---|
| U1 | Does 4.0.0 ship the gateway *speaking* 2026-07-28 outbound, or only detecting the era while `initialize` still carries every send? | operator | ask | before the design review closes | Detection-only ⇒ (f) is the whole change; the modern outbound request path is never written. |
| U2 | Is one extra round-trip before `initialize` acceptable at connect? | operator decides; measurement mine | measure connect fan-out latency × backend count | before implementation | Unacceptable ⇒ fall back to (d), lazy, keeping (c)'s ownership. |
| U5 | Is NFR.OBS.3 (`criteria-status.md:269` — which era, by what evidence, when re-probed) in this change? | operator | ask | with U1 | In scope ⇒ the probe must record evidence and probe time, not just an `Era`. |
