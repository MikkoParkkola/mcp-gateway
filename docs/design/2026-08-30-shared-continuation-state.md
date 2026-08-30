<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Continuation state across replicas

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

`ConsumedLedger` (`src/protocol/continuation.rs:437`) is already atomic — one `tokio::sync::Mutex`
around a check-and-consume — and `InFlight` (:558) is already replica-aware, keying
`{backend_id}:{uuid}` to `(holder, deadline)` and answering `route()` with `Here` or
`Elsewhere { replica }`. Both hold their state in a process-local `HashMap`.

## Two problems, not one

**MRTR.6 cannot be solved by a shared store.** The thing that must be reached is a live RPC held
open in one process's memory — a socket and a pending future. Shared *data* does not move it. The
two mechanisms that satisfy MRTR.6 are forwarding the retry to the holder, or failing explicitly on
a recorded holder. The requirement names the second in its own words. `origin_replica` already
carries that fact inside the sealed envelope, with no lookup.

**MRTR.5 is satisfied by the key material, not by consensus.** If a continuation can be *opened* on
exactly one replica, the set of replicas that can spend it twice is empty, and the one replica that
can spend it at all already does so atomically under a local mutex.

That second sentence is a design decision, not an observation, and it is the one this document
makes. Nothing in the tree constructs a `Keyring` outside tests today (`Keyring::new` has 24 call
sites, all in `tests/mik_7212_acs.rs`), so the key-material policy is still open, and it is the
thing that decides whether MRTR.5 holds.

## What is in scope

Making MRTR.5 and MRTR.6 hold on a multi-replica deployment, and nothing else. Out: the
legacy-client bridge (queue item 1b, MRTR.7), the MRTR wiring itself (item 1), key persistence, and
any change to what a continuation *contains*.

## Constraints, measured

- **No shared store exists to reuse.** `Cargo.toml` carries no `redis`, `sqlx`, `rusqlite`,
  `postgres`, `etcd`, `nats` or `object_store` dependency; the only storage-shaped crate is
  `dashmap = "6.2"` (`Cargo.toml:99`), which is process-local.
- **No peer discovery exists.** `src/kubernetes/cluster.rs` is an apply-plan adapter for operator
  commands, not cluster membership; nothing under `src/` resolves a sibling replica's address. A
  replica cannot forward anything today, because it cannot name a peer.
- **The modern path has no steerable identifier.** MIK-7215.STATELESS.3 requires that the gateway
  MUST NOT emit `Mcp-Session-Id` on the modern path. The continuation travels in the request
  *body*, as `requestState`. There is therefore no header, cookie or path an ingress can steer on:
  affinity is not merely unconfigured on this path, it is unavailable. `docs/DEPLOYMENT.md:141`
  already says so — "continuations are presented by whichever client holds one, and session
  affinity does not constrain which replica that reaches".
- **The gateway does not already require affinity on this path.** `has_session` is consulted on
  DELETE only (`src/gateway/router/handlers.rs:264`); the POST path calls `get_or_create`
  (:169-214), which inserts on whichever replica receives the request. The shipped chart defaults
  to two replicas (`deploy/helm/mcp-gateway/values.yaml:11-16`).
- **The token already carries its origin.** `Payload::origin_replica` travels sealed inside the
  envelope.
- **The envelope is `b64(version ‖ kid ‖ nonce ‖ ciphertext)`** with `[version, kid]` as
  additional authenticated data (`continuation.rs:367-404`). Anything outside that b64 is
  unauthenticated by construction, and is visible without a key.

## The mechanism

**A continuation is openable only on the replica that minted it. Every other replica refuses it,
explicitly, without being able to evaluate it.**

The outcome is total over where a retry lands:

| the retry reaches | what happens | which requirement |
|---|---|---|
| the minting replica, first time | opens, consumed under the local mutex, resumes | MRTR.5 single-use |
| the minting replica, again | refused as already spent, by the same mutex | MRTR.5 single-use |
| the minting replica, after `expires_at` | refused as expired | MRTR.5 expiry |
| any other replica | refused: the envelope does not authenticate under that process's key | MRTR.5 cross-replica |
| the minting replica after a restart | refused: the key died with the process | MRTR.5 cross-replica |

No row silently starts a second exchange, which is what MRTR.6 forbids. Every refusal is a refusal —
the requirement asks the retry to reach the holder *or fail explicitly*, and rows 2 through 5 are
that failure.

Two operational consequences follow from that matrix and belong in the release notes. A client
retrying against a round-robin service is refused on every replica but the minting one, so a retry
is a coin flip rather than a rare miss. And a rolling restart invalidates every continuation
outstanding against each replaced process, because the key goes with it.

### 1. Key material is per process, and is never shared

Each process generates its continuation key at startup and never writes it anywhere. This is the
standing keyring decision — persistent key material only alongside a durable ledger — stated as the
*enforcement mechanism* rather than as a caveat.

The consequence is the requirement: a token sealed on replica A is `NotAuthentic` on replica B,
because B does not hold A's key. B cannot evaluate redeemability, so there is no second ledger for
a partition or a stale read to disagree about. MRTR.5's cross-replica clause holds
cryptographically, with no shared store, no new dependency and no affinity.

The invariant to carry forward, because a future change could quietly break it:

> Continuation key material is never shared between processes unless the consumed-ledger is shared
> in the same change.

A configured, shared key without a shared ledger is exactly the deployment MRTR.5 forbids, and it
would look like an ordinary configuration convenience.

### 2. The origin stays sealed, and nothing outside the envelope claims it

An earlier revision put the minting replica's identity in a cleartext prefix, `{origin}.{envelope}`,
so a non-origin replica could name the holder in its refusal. That is deleted.

It was unauthenticated and client-controlled, so the identity it named was whatever the caller
wrote. The diagnostic it bought — "wrong replica, minted on *X*" — is therefore forgeable, and an
operator log that confidently names the wrong process is worse than one that names none: it is a
false lead presented as a fact. It also changed the wire form of a token for a benefit the
requirement never asked for. MRTR.6 requires the retry to *fail explicitly*, not to be *diagnosed
accurately*, and a typed refusal satisfies the words as written.

`Payload::origin_replica` therefore stays where it already is, sealed inside the envelope, and is
read only by the replica that can open it — where it is a consistency assertion rather than a
routing input.

### 3. The pin binds only where the requirement binds

MRTR.6 is about a legacy backend holding an RPC open. A continuation for a modern backend is
self-contained — `backend_request_state` is the backend's own state
(`src/protocol/continuation.rs:74-76`), so resuming it needs nothing that lives outside the token
and the key that sealed it. The pin is therefore enforced only where the mint recorded a live
`InFlight` hold, which is the case the requirement names.

Note that clause 1 already confines *every* continuation to its origin, because only the origin can
open it. What clause 3 adds is the case that survives on the origin itself: a continuation minted
against a live `InFlight` hold, redeemed after that hold is gone — the deadline passed, or the
backend dropped the connection. The token still opens and the ledger still has it unspent, so
without the pin the gateway would do the one thing MRTR.6 forbids and open a *second* exchange with
the legacy backend. With it, the missing hold is a refusal.

### Why not an external store

Rejected on the merits. It does not satisfy MRTR.6 at all — no store moves a live RPC — and for
MRTR.5 it is not needed once key material is per process. It would also make an external service a
hard requirement of the gateway's headline feature: a single-binary deployment that today needs
nothing would need a Redis to answer a tool call that asks a question.

The honest form of the rejection matters. It is **not** that every store fails open: a linearizable
conditional write (`SET NX` against a single primary, a unique-constraint insert) fails *closed*,
and would satisfy MRTR.5 correctly on its own terms. The rejection is that it buys a guarantee we
already have by construction, at the price of a runtime dependency, an availability coupling and an
operational surface — and that the failure modes it does add (partition, `maxmemory` eviction,
stale-follower reads on a replicated deployment) are only avoided by choosing the strict
configuration and keeping it.

### Why not session affinity

It cannot be built on the modern path: MIK-7215.STATELESS.3 forbids the identifier it would steer
on, and the continuation rides in the request body where no proxy can see it. This is the same
conclusion `docs/DEPLOYMENT.md:141` already reached.

### Why not replica-to-replica forwarding, yet

Forwarding is the eventual answer for the deployment that wants a retry to *succeed* on any
replica. It needs a routing input this design deliberately does not supply — the origin is sealed,
so a non-origin replica cannot read it — plus peer discovery, peer authentication, a hop timeout,
loop prevention, and, because key material is per process, a way to hand the exchange over rather
than the token. None of those exist. MRTR.6 is satisfied without it, in the requirement's own
words.

## The shape

`AppState` constructs the keyring and the `ConsumedLedger` once, as one owner with one lifecycle —
the standing decision that a keyring outliving its ledger is a replay window. `InFlight` sits
beside them.

No trait. An earlier draft introduced a `ContinuationStore` seam for the forwarding work; there is
no second implementation and no second call site, so it is an abstraction over one thing. It can be
extracted when the forwarder exists and has a shape to fit.

## Decisions this design makes

1. **Continuation key material is generated per process and never shared**, and sharing it without
   sharing the ledger is forbidden in the same breath. This is what makes MRTR.5 hold across
   replicas.
2. **A continuation presented to a non-origin replica is refused, not evaluated.** The origin check
   precedes any key lookup, so redeemability is never decided by a replica that cannot hold the
   exchange.
3. **The refusal is explicit and typed**, distinct from "expired" and "already spent", so an
   operator can tell a continuation that cannot be authenticated here from a replay attempt. It
   deliberately does **not** name the replica that could have served it: nothing outside the sealed
   envelope can make that claim without being forgeable.
4. **A single-replica deployment is no longer a documented requirement** of the modern protocol
   path. `docs/DEPLOYMENT.md:125-142` is rewritten in this change to say what now holds — which is
   that a retry is *refused* unless it lands on the minting process, not that multi-replica is now
   free. An operator reading the second thing would file every origin-miss refusal as a regression.

## Residual, named

**The mint counter is still process-local.** `Keyring::minted` (`continuation.rs:237-249`) bounds
how many envelopes one key may seal, and two replicas each count their own. That is correct here
rather than a gap: the bound exists because AES-GCM with random nonces degrades after a number of
seals *under one key*, and with per-process keys each counter bounds exactly the key it belongs to.
It would become a real gap the moment key material were shared — which decision 1 forbids. Recorded
so the two are never separated. `CHANGELOG.md:110-114` states this.

## Open questions, scheduled

- *What names a replica?* — answered by the deletion above. With no routing decision resting on the
  name, `origin_replica` is a sealed assertion read only by the process that minted it, so any
  per-process value works; a value generated at startup is the candidate. The StatefulSet case that
  motivated this question — a restarted replica reusing its predecessor's name — is answered by row
  5 of the outcome matrix: the key died with the process, so nothing the successor is handed opens.
- *What does a wrong-replica refusal look like on the wire?* — deferred to the increment that
  builds the refusal. Owner: the MRTR.5 increment. What resolves it: read how
  `src/gateway/router/handlers.rs` returns a typed error today and follow that shape rather than
  inventing one. It matters because the refusal is the one error a client can usefully retry — a
  retry against a round-robin service reaches the origin roughly one time in *n* — so if the
  transport carries a retryable signal at all, this refusal earns it. If it resolves badly, and no
  retryable signal exists on this path, the refusal is still correct and the release notes carry
  the consequence instead.
- *Does any client fail to echo the continuation on the retry?* — checkable against the
  specification's client requirements and the gateway's stdio dispatcher, which has no session
  concept at all. Stdio is single-process by construction. If an HTTP client may omit it, the
  refusal in decision 2 is the outcome and the release notes say so.
