<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: MIT
-->

# Design — wiring the outbound era probe (MIK-7217 DISCOVER.4, DISCOVER.5)

Status: proposed · Date: 2026-08-31
Tracking: MIK-7217 · Criteria: `docs/requirements/RELEASE-4.0.0-criteria-status.md:178-193`

## §P0 Scope

**FOR:** making the gateway learn a *backend's* protocol era by probing it, and caching that
answer per backend — so DISCOVER.4 and DISCOVER.5 stop being UNWIRED.

**OUT:**

- the modern outbound request path (`_meta` envelopes, modern framing). That is
  MIK-7214.HEADER.9, currently ABSENT and blocking; this design reserves a seam for it and
  builds nothing on it.
- adding `2026-07-28` to `SUPPORTED_VERSIONS`. `src/protocol/mod.rs:38-42` states plainly the
  revision is absent "until the modern request path exists… It is added in the increment that
  makes it true." This is not that increment.
- **stdio backends.** A deferred unknown below, with the four fields. A decision, not an omission.
- A2A backends — `src/backend/lifecycle.rs:372-383` refuses them on this path outright ("must be started via A2aProvider, not the legacy Backend::start() path").
- the `src/lib.rs:23` `2024-10-07` doc residual noted under DISCOVER.7. One-line doc fix,
  unrelated mechanism, does not travel with this change.

## Problem

Seven criteria carry the `MIK-7217.DISCOVER` prefix. Four are MET, one MET with a residual, and
two are UNWIRED — and the two UNWIRED ones are the entire outbound half:

| criterion | verdict | what it asks |
|---|---|---|
| DISCOVER.1 | MET (caveat) | server answers `server/discover` with a complete document |
| DISCOVER.2 | MET | answerable before `initialize`, without a session |
| DISCOVER.3 | MET | `initialize` result unchanged for a 2025 client |
| **DISCOVER.4** | **UNWIRED** | **gateway MUST detect a backend's era by probing, not by trusting a version string** |
| **DISCOVER.5** | **UNWIRED** | **detected era MUST be cached per backend and re-probed when a cached assumption fails** |
| DISCOVER.6 | MET | slow backend retried on a pinned schedule |
| DISCOVER.7 | MET (residual) | `2024-10-07` absent from advertised version lists |

The detector for DISCOVER.4 is complete, adversarially reviewed and heavily unit-tested at
`src/protocol/era.rs`. Nothing calls it. Stronger than uncalled: **no outbound `server/discover`
request is constructed anywhere in `src/`** — there is no sender to wire it to. The criteria file
files this under the shape already logged for EXT.1, OTEL.1 and TASK.1: built, tested, unreachable.

What the MET rows constrain, and this design must not break:

- **DISCOVER.1's caveat** — the stdio arm passes `modern_enabled: false` unconditionally
  (`src/gateway/server/mod.rs:1687-1693`), self-documented as a known limitation. This design does
  not touch the inbound document, and must not make that caveat harder to lift.
- **DISCOVER.3's goldens** — `tests/mik_7217_acs.rs:213` compares the `initialize` result
  byte-for-byte against captured goldens. Nothing here changes the inbound result; if a golden
  moves, this design is wrong.
- **DISCOVER.6's pinned budgets** — `warmstart.rs:751` pins `attempt_timeout` 120s,
  `initial_gap` 2s, `max_gap` 30s. A probe inside the start path spends from that budget, so its
  timeout is chosen against those numbers, not freely.

## Measured constraints

### 1. Where the probe may run is fixed by a lock, not by taste

The blocking constraint is `start_lock`, and it is worth stating precisely because the obvious
reading blames the wrong thing.

A client request enters `Backend::call_tool` (`src/backend/ops.rs:198`), acquires a semaphore
permit, and then at `:210` calls `ensure_entry_started` (`lifecycle.rs:187`), which takes the pool entry's
`start_lock` (`src/backend/lifecycle.rs:209`, a `tokio::sync::Mutex` per `pool.rs:12,:62`) and runs `start_entry` beneath it. So the existing
legacy handshake **already** runs while a permit is held. The probe does not introduce that
position; it inherits it.

The hard failure is narrower and worse: **a probe issued through the ordinary
`Backend::request*` surface re-enters `ensure_entry_started` for the same entry, and the entry's
`start_lock` is a non-reentrant `tokio::sync::Mutex`. That self-deadlocks.** Permit exhaustion
(`Semaphore::new(100)`, `lifecycle.rs:140`, hardcoded, no config path) is a secondary
degradation on top of it, not the primary defect.

The repository has already solved this exact shape once and wrote down why. `ops.rs:104` records
that a cold tool cache "mirrors nothing rather than issuing a `tools/list` while this request
holds its semaphore permit, which a concurrency-limited backend could not satisfy." This design
follows that precedent rather than inventing a rule: **the probe is issued directly against the
already-constructed transport, inside `start_entry`, never through `Backend::request*`.**

Stated as an invariant the implementation must hold: **lock order is `start_lock` → era lock,
never reversed, and the probe closure touches nothing that re-acquires `start_lock`.** That
second clause is load-bearing because `EraCache::resolve_with` holds its own lock *across* the
probe await by design (`era.rs:143-170`) — deliberately, so concurrent resolution collapses onto
one probe rather than stampeding a peer that is by hypothesis already struggling
(`era.rs:127-131`).

### 2. Ordering: HTTP separates spawn from handshake, stdio does not

For HTTP, `lifecycle.rs:353-368` constructs the transport and `:369` then calls `transport.initialize()` as
a separate statement. A probe can be issued in between — which is where it belongs, because the
whole point is to learn the era *without* trusting the handshake.

For stdio, `stdio.rs:256`: `start()` calls `initialize()` internally, inside the
spawn-then-teardown-on-failure block at `:246-261`. There is no seam. Probing before the
handshake on stdio requires splitting `start()` into spawn and handshake halves, which means
reworking teardown logic that exists for a stated reason.

**Decision: the first increment covers HTTP backends only.** Stdio is deferred with the four
fields below. Naming this as a decision rather than a scope note, per §P3.

### 3. The era must eventually be readable where headers are built, and today it is not

`build_mcp_headers` (`src/transport/http/mod.rs:544`) is documented as the single source of truth
for all outgoing request headers in that transport. It is `async fn` on `&self` of the transport,
and reads `self.protocol_version` — the field the legacy handshake writes. **A transport has no
reference to its `Backend`, so a `Backend`-owned era is not reachable there at all.** HEADER.9
will therefore have to retrofit a path regardless of what this design does.

What this design does about it: resolve the era **once, at start**, and snapshot it next to
`protocol_version` on the transport, rather than leaving HEADER.9 to await a `Backend`-owned
mutex per outbound request on a path that is reachable while a permit is held. That is a seam
reserved deliberately, and it is stated here so cluster D does not have to argue for it.

## The design

### Where the era lives

`EraCache` becomes a **field on `Backend`**, alongside `tools_cache` and the other per-backend
caches. The key *is* the instance: `BackendRegistry` already keys backends by name, so the
existing single-`Option<Era>` shape at `era.rs:114-170` becomes correct unchanged, and "per
backend" in DISCOVER.5 acquires the representation the criteria row says it lacks. Lifetime is
the `Backend`'s — dropped on reload or removal. No TTL, because the spec caches for the peer's
process lifetime, and `Backend` is reconstructed rather than revived on reload
(`src/backend/mod.rs:200-207`).

Two alternatives, both rejected:

- **A global name-keyed `HashMap<String, Era>`.** Rejected: it re-asks a keying and eviction
  question the registry already answers, and it puts the era further from the transport, making
  HEADER.9 harder rather than easier.
- **One `EraCache` per `PoolKey` slot.** Rejected: every slot for one backend talks to one peer,
  so per-slot caching means N probes at a peer that is by hypothesis already struggling — exactly
  the thundering herd `era.rs:127-131` was written to prevent.

### How the era is learned

Inside `start_entry`, on the HTTP arm only, between transport construction and
`transport.initialize()` (the seam is between `lifecycle.rs:368` and `:369`): resolve the backend's era through
`EraCache::resolve_with`, whose probe closure sends a `server/discover` request **directly on the
constructed transport**, and maps the reply into `ProbeOutcome` — a result document into
`Result`, a JSON-RPC error into `Error(code)`, and a timeout or transport failure into `NoAnswer`.
`classify` then decides. The legacy `initialize` runs afterwards regardless, because
`SUPPORTED_VERSIONS` still has no modern revision to negotiate; the era is recorded, not yet
acted on.

The probe's timeout is chosen against DISCOVER.6's pinned budgets, not freely: it runs inside a
warm-start attempt bounded by `attempt_timeout` 120s (`warmstart.rs:751`), so a probe timeout must
be a small fraction of that — the increment picks a value and pins it in a test beside the
existing budget assertions, so a later edit that lets the probe eat the attempt fails a build.

### Why the probe is sound and not merely correlated

`classify` treats **only positive evidence** as Modern (`era.rs:60-100`):

- a document whose `capabilities` is an object **and** whose `supportedVersions` array contains a
  member of `MODERN_VERSIONS` (`era.rs:179-197`, `meta.rs:219`) — the peer's own statement of
  what it will accept, contents rather than presence, which is the distinction adversarial review
  added on 2026-08-29 for the dual-era peer mid-migration; or
- one of `-32022` / `-32020` / `-32021` (`era.rs:34-39`). Sound because 2026-07-28 reserves
  `-32020..=-32099` for the specification, so only a 2026 implementer knows those numbers.

Everything else — `-32601`, an arbitrary application error, silence — is Legacy. The justification
for that asymmetry is a **cost asymmetry**: a false Modern sends a request the peer cannot parse;
a false Legacy costs one handshake the gateway was going to perform anyway.

The one direction it is *not* sound: a modern peer that is merely unreachable reads Legacy. The
mitigation already exists in the detector — `NoAnswer` is not cached (`era.rs:164-167`), so a
transient outage does not pin a peer to the legacy path for the process lifetime.

### Re-probing, and the honest limit on it

DISCOVER.5's second half — "re-probed when a cached assumption fails" — has **no trigger that can
fire today**, and this design says so rather than papering over it. A cached era can only be
*wrong in a way the gateway notices* once the gateway sends something era-dependent, and it sends
nothing era-dependent: `2026-07-28` is absent from `SUPPORTED_VERSIONS` by design
(`src/protocol/mod.rs:38-42`), and no outbound `_meta` envelope exists (HEADER.9, ABSENT).

So the invalidation path is designed and wired now, and becomes *fireable* when HEADER.9 lands.
Its guard, mirroring `classify`'s asymmetry: **invalidate only on a recognised era-mismatch
error**, never on a generic failure — otherwise a persistently failing peer re-probes on every
request, which is the herd again by another route.

### One owner of the era, and the rule that keeps the snapshot honest

`Backend`'s `EraCache` is the owner. The transport's snapshot (constraint 3) is a copy, and two
copies of one fact is the shape the repair protocol tells us to eliminate rather than patch. The
elimination is an ordering rule, not a checker: **an era invalidation and a transport rebuild are
the same event.** Invalidating the era means the next start re-probes, and a start on the HTTP arm
constructs a new transport, which takes a fresh snapshot. There is no path that changes the era
without replacing the transport that snapshotted it, so the two cannot drift — and the defect
"transport holds a stale era" cannot be stated, rather than being detectable.

This is a design decision made here, not by the criterion, and is named as one per §P3.

### Interaction with the two existing caches

- **Response cache** (`src/backend/cache.rs:223`, key `{server}:{tool}:{args_hash}`): the era stays
  **out of the key**, as a stated decision. Era affects transport framing, not tool semantics, so
  the same call with the same arguments has the same answer under either era. The one case that
  would break it — a `_meta` value the backend echoes into a result — cannot arise here: the probe
  response goes direct to the transport and never enters the tool-call path, and no outbound
  `_meta` exists to echo (HEADER.9, OUT of scope). If HEADER.9 introduces an echoed `_meta`, this
  decision is the thing it must revisit.
- **`CachedMetadata`** (tools, resources, prompts): an era flip can change a peer's tool list, and
  `invalidate_if` already exists at `cached_metadata.rs:100`. The era is resolved at start, before
  any metadata for that transport is fetched, so within a single `Backend` lifetime there is no
  window where metadata cached under one era is read under another. The invalidation hook is
  therefore not wired in this increment; it becomes necessary at the same moment the re-probe
  trigger does, and is named here so HEADER.9 inherits it as a known obligation rather than
  discovering it.

## Options considered

| option | why rejected |
|---|---|
| probe lazily on first tool call | that is the path holding a semaphore permit and, through `ensure_entry_started`, the `start_lock`. Re-entry self-deadlocks; `ops.rs:104` already records the repo's answer to this shape. |
| probe from the warm-start task instead of `start_entry` | warm start is not the only way a backend starts — a cold client request starts one too (`ops.rs:210`, and again at `:343,:353` on the notify path), so the era would be resolved on one path and absent on the other. |
| trust the `initialize` result's `protocolVersion` | this is exactly what DISCOVER.4 forbids: "by probing, not by trusting a version string". A legacy server does not answer a probe with "I am legacy" (`era.rs:5-19`); nor does its handshake prove modernity. |
| split `stdio::start()` now, to cover both transports in one increment | touches teardown logic at `stdio.rs:246-261` that exists for a stated reason, in the same change that first wires a probe. Deferred below with its four fields. |
| a background era-refresh task | invents a schedule nothing asks for and re-probes peers with no failure to justify it. YAGNI; the spec caches for the peer's process lifetime. |

## Open questions

Resolved — question, what was run, what came back, what it changed:

1. **Does the 100-permit semaphore have a configuration path?** — `rg -n 'semaphore|concurrency|max_concurrent' src/config/` (whole directory) — no matches; the limit at `lifecycle.rs:140` is hardcoded — **changed:** removed "raise the limit" from the options, and ranked permit exhaustion as a secondary degradation behind the `start_lock` re-entry, which is the real failure.
2. **Can anything at header-build time reach a `Backend`-owned era?** — `rg -n 'build_mcp_headers|self.protocol_version' src/transport/http/mod.rs` — `build_mcp_headers` is `&self` on the transport and reads only `self.protocol_version`; a transport holds no `Backend` reference — **changed:** added the transport snapshot as a reserved seam (constraint 3) with a stated single-owner rule, instead of leaving HEADER.9 to await a `Backend`-owned mutex per outbound request.
3. **Does stdio's `start()` separate spawning from the handshake?** — read `src/transport/stdio.rs:246-261` — it does not; `start()` calls `initialize()` at `:256` inside the spawn-then-teardown block — **changed:** cut stdio from this increment and deferred it below.
4. **Is there an existing outbound `server/discover` sender to attach the detector to?** — `rg 'discover'` over `src/backend/`, `src/provider/`, `src/transport/` — only the prose word "discoverable" (`metadata.rs:43`, `cached_metadata.rs:96,:245`, `lifecycle.rs:985`) — **changed:** the increment must build the request path, not merely call `classify`; "wire up the detector" underestimates the work.
5. **Does `start_entry` already run under `start_lock` while a request permit is held?** — read `src/backend/ops.rs:198,:210` and `src/backend/lifecycle.rs:209` — it does; `start_lock` is a non-reentrant `tokio::sync::Mutex` (`pool.rs:12,:62`) — **changed:** the probe is issued directly on the constructed transport rather than through `Backend::request*`, and the lock-order invariant is stated explicitly.

Deferred:

| field | value |
|---|---|
| question | whether stdio backends should be probed in this release, given that it requires splitting `stdio::start()` into spawn and handshake halves |
| owner | MIK-7217, follow-up increment; the requester decides whether it lands before 4.0.0 |
| what would resolve it | the requester's call on whether HTTP-only coverage of DISCOVER.4/.5 is acceptable for the release, plus a design pass over the teardown block at `stdio.rs:246-261` |
| when | before the criteria file's DISCOVER.4/.5 rows move off UNWIRED to a full MET |
| what if it resolves badly | if stdio must be covered, `stdio::start()` splits and the teardown path is redesigned — a larger change than this one. It does not invalidate this increment: the HTTP wiring, the `Backend` field and the probe soundness argument all stand unchanged. |

Nothing in this increment depends on that answer. The HTTP path is complete on its own, and the
criteria rows move from UNWIRED to a partial MET with a named caveat — the same shape DISCOVER.1
already uses for its own stdio limitation.

## What this increment does and does not claim

It claims DISCOVER.4 for HTTP backends: an era learned by probing, from positive evidence only.
It claims DISCOVER.5's caching half outright — per backend, in the type, with the herd collapse
the detector was written for. It **does not** claim DISCOVER.5's re-probe half as live, because no
trigger can fire until HEADER.9 lands, and the criteria file should record that rather than a
mechanism that has never run.
