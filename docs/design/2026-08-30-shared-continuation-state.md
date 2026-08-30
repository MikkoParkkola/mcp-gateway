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

## Constraints, measured

- **No shared store exists to reuse.** `Cargo.toml` carries no `redis`, `sqlx`, `rusqlite`,
  `postgres`, `etcd`, `nats` or `object_store` dependency; the only storage-shaped crate is
  `dashmap = "6.2"` (`Cargo.toml:99`), which is process-local. A shared store is a new runtime
  dependency and a new deployment requirement, not a library swap.
- **No peer discovery exists.** `src/kubernetes/cluster.rs` is an apply-plan adapter for operator
  commands, not cluster membership; nothing under `src/` resolves sibling replica addresses. A
  replica cannot today forward anything to another replica, because it cannot name one.
- **The token already carries its origin.** `Payload::origin_replica` travels sealed inside the
  envelope. Any replica that opens a continuation already knows, from the token alone and with no
  lookup, which replica minted it.
- **The keyring is per-run.** Standing decision, unchanged here: persistent key material is
  permitted only alongside a durable ledger. A restart kills continuations in flight, deliberately.

## What is in scope

Making MRTR.5 and MRTR.6 hold on a multi-replica deployment, and nothing else. Out: the
legacy-client bridge (queue item 1b, MRTR.7), the MRTR wiring itself (item 1), key persistence, and
any change to what a continuation *contains*.

## Options considered

### A. An external shared store

Redis or equivalent behind a `ContinuationStore` trait; `ConsumedLedger::consume` becomes a Lua
`SETNX`-with-TTL and `InFlight` becomes a hash with the same TTL.

Rejected as the 4.0.0 mechanism. It satisfies both criteria and it is the textbook answer, but it
makes an external store a **hard** requirement of the gateway's headline feature: a single-binary
deployment that today needs nothing would need a Redis to answer a tool call that asks a question.
It also moves the atomicity guarantee out of the process and into a script whose failure modes
(partition, eviction under `maxmemory`, a replica reading a stale follower) are new, and each of
them degrades to *double redemption* — the failure MRTR.5 exists to prevent. Buying that with a new
operational dependency, in the release that first ships the feature, is the expensive direction.

Kept as a later, additive backend: the trait is the point of the shape below, and adding a Redis
implementation behind it is a change with no callers to revisit.

### B. Origin-pinned continuations — the mechanism this design chooses

A continuation is redeemable **only on the replica that minted it**. Every other replica opens the
envelope, reads `origin_replica`, sees it is not itself, and refuses explicitly — a distinct error,
never a silent second exchange, never a fall-through to "unspent, therefore proceed".

Enforcement then holds across every replica that can receive the retry, which is what MRTR.5
requires: on the origin the local ledger is authoritative and already atomic; on every other replica
the answer is a refusal before the ledger is consulted at all. There is no replica on which a
replayed token is redeemable a second time. MRTR.6 is satisfied by the same sentence it is written
in — "or fail explicitly" is the requirement's own permitted outcome, and the refusal names the
replica that holds the exchange so a router or a client can act on it.

The cost is real and belongs in the release notes: behind a round-robin load balancer with N
replicas, a retry lands on the right process 1/N of the time. The deployment requirement is that
retries route back to their origin — session affinity on the load balancer, keyed on the
continuation's replica hint, which the gateway surfaces in a response header so a proxy can steer on
it without parsing the token.

### C. Replica-to-replica forwarding

The receiving replica proxies the retry to `origin_replica` over the gateway's own HTTP.

Rejected for 4.0.0: it needs peer discovery, peer authentication, and a forwarding hop with its own
timeout and its own loop prevention, none of which exist (see constraints). It is the right answer
once membership exists, and B is a strict prerequisite for it — C is B plus a forwarder, because the
forwarder needs exactly the origin pin B introduces to know where to send.

## The shape

One trait, two implementations, one owner.

```
trait ContinuationStore {
    async fn consume(&self, jti: &str, expires_at: u64, now: u64) -> bool;
    async fn hold(&self, backend_id: &str, expires_at: u64) -> Option<String>;
    async fn route(&self, key: &str) -> Routing;
}
```

- `LocalStore` — the current `ConsumedLedger` plus `InFlight`, unchanged in behaviour, wrapping the
  maps they already own. This is what 4.0.0 ships.
- The trait exists so that A is additive later. It is not speculative generality: the release notes
  will state the affinity requirement, and the store boundary is the sentence in the code that the
  statement is about.

`AppState` constructs the store once and owns it, keyring beside it, with one lifecycle — the
standing decision that a keyring outliving its ledger is a replay window.

## Decisions this design makes

1. **A replayed continuation on a non-origin replica is refused, not evaluated.** The origin check
   comes before the spent-list, so a wrong-replica retry cannot be answered from the ledger's state
   at all — there is nothing for a partition or a stale read to disagree about.
2. **The refusal is explicit and typed**, distinct from "expired", "tampered" and "already spent", so
   that an operator reading a log can tell an affinity misconfiguration from an attack. The
   client-facing message stays the existing constant: the replica identity is not disclosed in the
   body, only in the header a proxy is meant to steer on.
3. **Session affinity becomes a documented deployment requirement of 4.0.0.** Stated in the release
   notes and in the deployment documentation, not implied.

## Open questions, scheduled

- *Is affinity on the retry path acceptable as a deployment requirement, or must 4.0.0 ship a shared
  store?* — **asked of the operator**; this is a deployment-contract decision, not an engineering
  one. Answer pending; the shape above is the recommendation. Nothing depending on it is
  implemented until it lands.
- *What names a replica?* — checkable. The identity must be stable for at least one continuation
  lifetime and unique per process. A configuration value defaulting to the hostname; resolved in the
  test plan rather than assumed here.
