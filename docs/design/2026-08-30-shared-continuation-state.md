<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Shared continuation state across replicas

Queue item 1a. Tracks MIK-7312. Blocks the MRTR wiring suite, because the wiring's storage owner
cannot be built twice.

## Problem

Two acceptance criteria in MIK-7212 are written as MUST and neither holds on a deployment with more
than one gateway process.

> **MRTR.5** — A continuation MUST be single-use and MUST expire. Enforcement MUST be atomic and
> MUST hold across every replica that can receive the retry. Integrity protection alone does not
> satisfy this.

> **MRTR.6** — When a legacy backend is holding an RPC open, the retry MUST reach the replica
> holding that exchange, or fail explicitly. It MUST NOT silently start a second exchange.

The operator held the 4.0.0 release for both on 2026-08-30, rejecting both ship-with-a-stated-limit
and drop-the-feature.

The gap is storage, not logic. `ConsumedLedger` (`src/protocol/continuation.rs:437`) is already
atomic — one `tokio::sync::Mutex` around a check-and-consume — and `InFlight` (:558) is already
replica-aware, keying `{backend_id}:{uuid}` to `(holder, deadline)` and answering `route()` with
`Here` or `Elsewhere { replica }`. Both hold their state in a process-local `HashMap`. Two replicas
therefore keep two ledgers, and a token spent on one is unspent on the other: an attacker who
replays a captured continuation against a second replica redeems it a second time, which is exactly
what MRTR.5's last sentence forbids.

## Two problems, not one

Reading MRTR.5 and MRTR.6 as a single "shared state" problem is what makes an external store look
like the answer. They are different problems with different lower bounds.

**MRTR.6 cannot be solved by any shared store.** The thing that must be reached is a live RPC held
open in one process's memory — a socket and a pending future. No amount of shared *data* moves it.
The only two mechanisms that satisfy MRTR.6 are pinning the retry to the replica that holds the
exchange, or forwarding the retry to it. A Redis satisfies neither; it can record *where* the
exchange lives, which is a fact `origin_replica` already carries inside the sealed envelope with no
lookup at all.

**MRTR.5 is then satisfied by construction, not by consensus.** If a continuation is redeemable on
exactly one replica, the set of replicas that can redeem it twice is empty, and the one replica that
can redeem it at all already does so atomically under a local mutex. A shared store does not improve
this — it *degrades* it, by introducing partition, `maxmemory` eviction and stale-follower reads,
each of which resolves to two callers both seeing a token unspent. That is precisely the failure the
requirement's last sentence exists to forbid, reintroduced by the mechanism chosen to prevent it.

## Constraints, measured

- **The gateway already requires session affinity.** `NotificationMultiplexer` holds
  `sessions: RwLock<HashMap<String, Arc<ClientSession>>>` (`src/gateway/streaming.rs`) — process
  local — and `src/gateway/router/handlers.rs` branches on `state.multiplexer.has_session(id)`. A
  streamable-HTTP client whose follow-up lands on a second replica is already an unknown session
  today. Pinning continuations therefore adds **no** deployment requirement that a multi-replica
  deployment does not already have; it extends an existing one to a second kind of state.
- **The gateway already mints the affinity carrier.** `streaming.rs` issues `gw-{uuid}` when a
  client presents no `Mcp-Session-Id`. An origin hint can ride in the identifier the protocol already
  defines and the gateway already controls, rather than in a bespoke header nobody's ingress knows.
- **No shared store exists to reuse.** `Cargo.toml` carries no `redis`, `sqlx`, `rusqlite`,
  `postgres`, `etcd`, `nats` or `object_store` dependency; the only storage-shaped crate is
  `dashmap = "6.2"` (`Cargo.toml:99`), which is process-local. A shared store is a new runtime
  dependency and a new operational surface, not a library swap.
- **No peer discovery exists.** `src/kubernetes/cluster.rs` is an apply-plan adapter for operator
  commands, not cluster membership; nothing under `src/` resolves sibling replica addresses. A
  replica cannot today forward anything to another replica, because it cannot name one.
- **The token already carries its origin.** `Payload::origin_replica` travels sealed inside the
  envelope, so every replica knows the origin from the token alone.
- **The keyring is per-run.** Standing decision, unchanged here: persistent key material is
  permitted only alongside a durable ledger. A restart kills continuations in flight, deliberately.

## What is in scope

Making MRTR.5 and MRTR.6 hold on a multi-replica deployment, and nothing else. Out: the
legacy-client bridge (queue item 1b, MRTR.7), the MRTR wiring itself (item 1), key persistence, and
any change to what a continuation *contains*.

## The mechanism

**A continuation is redeemable only on the replica that minted it, and the origin travels in the
session identifier the protocol already carries.**

- The response side stamps `origin_replica` into the sealed payload, as it already can, and returns
  the interim result under a session id whose prefix is the origin's stable identity. A client that
  speaks streamable HTTP echoes `Mcp-Session-Id` on the retry because the protocol tells it to; an
  ingress steers on that header or on the cookie mirroring it, which nginx, Envoy and ALB all do with
  stock configuration.
- The retry side opens the envelope, compares `origin_replica` to its own identity, and on a
  mismatch refuses with a distinct, typed error **before the spent-list is consulted at all**. There
  is no path on which a non-origin replica evaluates redeemability, so there is no state for a
  partition or a stale read to disagree about.
- On the origin, enforcement is the existing atomic check-and-consume, unchanged.

This satisfies MRTR.6 in the requirement's own words — "or fail explicitly" — and satisfies MRTR.5
by construction rather than by agreement between processes.

### Why not an external store

Rejected on the merits, not on cost: it does not satisfy MRTR.6 at all, and for MRTR.5 it replaces a
guarantee that holds by construction with one that holds only while the store is healthy. It also
makes an external service a hard requirement of the gateway's headline feature — a single-binary
deployment that today needs nothing would need a Redis to answer a tool call that asks a question.

### Why not replica-to-replica forwarding, yet

Forwarding is the eventual answer for deployments that cannot configure affinity, and it is strictly
*this* design plus a forwarder: the forwarder's routing input is the origin pin introduced here. It
needs peer discovery, peer authentication, a hop timeout and loop prevention, none of which exist.
Building it now would be building the second half first.

## The shape

One trait, one implementation, one owner.

```
trait ContinuationStore {
    async fn consume(&self, jti: &str, expires_at: u64, now: u64) -> bool;
    async fn hold(&self, backend_id: &str, expires_at: u64) -> Option<String>;
    async fn route(&self, key: &str) -> Routing;
}
```

`LocalStore` wraps the `ConsumedLedger` and `InFlight` that already exist, unchanged in behaviour.
The trait is a seam for the forwarding work above, which needs to consult the same table from a
second call site; it is not a placeholder for a store this release argues against.

`AppState` constructs the store once and owns it, keyring beside it, with one lifecycle — the
standing decision that a keyring outliving its ledger is a replay window.

## Decisions this design makes

1. **A continuation presented to a non-origin replica is refused, not evaluated.** The origin check
   precedes the spent-list, so redeemability is never decided by a replica that does not hold the
   exchange.
2. **The refusal is explicit and typed**, distinct from "expired", "tampered" and "already spent", so
   an operator reading a log can tell an affinity misconfiguration from a replay attempt. The
   client-facing message stays the existing constant; the replica identity is not in the body.
3. **The origin rides in `Mcp-Session-Id`**, not a bespoke header, so that steering it is stock
   ingress configuration rather than a custom rule.
4. **Affinity is documented as an existing requirement being extended**, not as a new one — the
   deployment documentation states what streaming already needs and notes that continuations now
   need the same.

## Open questions, scheduled

- *What names a replica?* — checkable. The identity must be stable for at least one continuation
  lifetime and unique per process, and it is now also a session-id prefix, so it must be safe in a
  header value. A configuration value defaulting to the hostname; the check is a test-plan row, not
  an assumption here.
- *Does a client that does not echo `Mcp-Session-Id` exist on the retry path?* — checkable against
  the specification's client requirements and the gateway's own stdio dispatcher, which has no
  session header at all. Stdio is single-process by construction, so the question is whether any
  HTTP client may omit it; if one may, the refusal in decision 1 is the outcome and the release
  notes say so. Resolved before implementation, not assumed.
