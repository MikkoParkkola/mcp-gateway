<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: MIT
-->

# Keying the shared response cache on every response-varying input

Design for MIK-7213.CACHE.3 and MIK-7213.CACHE.4. Reviewed before any code
exists (development-process §P1). No implementation is proposed here beyond
the shape a reviewer must be able to reject.

## §P0 Scope

**FOR:** deciding what the gateway's shared response caches are keyed on, and
what a `public` `cacheScope` is allowed to mean, so that a response produced
for one caller can never be served to another.

**OUT:**

- editing `src/idempotency.rs` (a sibling change owns that file right now)
- the idempotency cache's own key discipline (`resolve_idempotency_key`)
- the OpenAI-compatible prompt-cache helpers (`prompt_cache.rs`) — a
  pass-through hint for backends that call LLM APIs, not a gateway cache
- outbound protocol-era negotiation (`src/protocol/era.rs`,
  `negotiate.rs`) — structurally distinct from CACHE.1-4, per
  `RELEASE-4.0.0-criteria-status.md:73`

**Both doors, and only one of them reaches this cache.** The gateway is
reachable two ways: the meta-MCP surface (`gateway_invoke` and friends, served
by `router/handlers.rs`) and the direct per-server route `POST /mcp/{name}`
(`router/backend_handlers.rs`). The first review draft of this paragraph
asserted that both land in `invoke_tool_traced`. **That was wrong, and the code
says so in its own words**: `backend_handlers.rs:724` states "the direct backend
route bypasses `invoke_tool_traced`", and `:594` states the direct route "keeps
no per-user cache". So the response cache, the idempotency store and the
chokepoint all sit on the meta-MCP door alone; the direct door is out of reach
of this design by construction, not by assumption. It is named here because a
reader who assumes symmetry will look for a second key shape that does not
exist.

**This closes a question that was being carried as an operator one.** The
two-route reading has been treated as an open ask across sibling scopes. It is
not an ask: it is a **checkable**, and the two lines above are the check. Which
routes reach `invoke_tool_traced` is a fact in the source, answerable by reading
it, and an unknown a source read can close never needed the operator. Recorded
in one line so the next design that inherits the assumption inherits the answer
with it. The clause this does *not* close is the transport-scope one below —
that one is genuinely askable. One clause does *not* follow automatically: the `proto` segment is read
from the meta-MCP POST handler's `declared_version` (`handlers.rs:572`), which
an HTTP request carries and a **stdio** session does not — stdio negotiates a revision at `initialize`
(`handle_initialize` in `meta_mcp/mod.rs`) and the value is currently only logged. For stdio,
`proto` is either threaded from the negotiated value or the transport does not
cache. The scope question this
paragraph used to hedge — whether the design must cover both doors — is
**settled by the two lines above, not by an assumption**: the second door
neither reaches `invoke_tool_traced` nor keeps a cache, so there is nothing on
it to key. What remains an assumption is narrower and is marked as one: that
CACHE.1-4 are read at full transport scope rather than HTTP-only is **the team
lead's reading of the release plan, not an operator confirmation**. If it
narrows to HTTP, the stdio exit is what changes, and nothing else does.

**Scope moved in revision 3, and this is the receipt.** Revisions 1 and 2 put
*all* of `invoke.rs` OUT, because a sibling change owns the file. Revision 3
specifies a change inside it — moving grant enforcement above the cache read —
so the boundary has moved from "no `invoke.rs` change is specified" to "one
ordering change is specified here, sequenced after the sibling change lands".
The file is still not edited by this design; the edit is named, ordered, and
owned. Calling that a wording clarification would be the thing the §P0 freeze
exists to catch.

**Scope moved again in revision 4, and this is that receipt.** R9 specifies a
*second* edit inside `invoke.rs`, at a different place from revision 3's and
with a different observable effect: revision 3 moves grant enforcement above the
cache read, revision 4 moves the per-caller provenance stamp below the cache
write and adds it to the hit path. Two named edits, not one. The boundary is now
"two ordering changes are specified here, both sequenced after the sibling
change lands". The reason the second one is in scope rather than a neighbouring
concern is stated where the repair is: a body stamped with another caller's
subject is exactly what §P0 says this change exists to prevent, which is why the
same finding was wrongly disposed as an observation twice. Recorded because §P0
freezes scope at the first dual review, and moving it a second time costs a
paragraph, not a silent edit.

**Source anchors.** Every `file:line` below is against **`5c7e64f4`**. The
anchor that carries the meaning is the **symbol name**; the line number is a
convenience that drifts — revision 2's `invoke.rs` numbers had already drifted
six lines when this revision was written, because the sibling change is editing
that file. Read the symbol, then look for it.

## Problem

Two shared caches live in this binary. Both are read *after* authorization has
already succeeded, and neither key contains the principal unconditionally.

| cache | key | built | read | written |
|---|---|---|---|---|
| response cache | `{server}:{tool}:{args_hash}` + two conditional suffixes | `ResponseCache::build_key`, `cache.rs:223-226` | `invoke_tool_traced`, `invoke.rs:835-838` | `invoke.rs:1286-1291` |
| capability executor cache | `{capability.name}:{params_hash}` | `capability/executor/params.rs:245-258` | `executor/mod.rs:301` | `executor/mod.rs:334` |

Caching is **on by default** (`config/features/cache.rs:21,32` —
`enabled: true`), so this is the shipped configuration, not an opt-in.

### Threat model

The attacker is an *authorized* caller. Authorization is not bypassed; it
succeeds, and the caller is then handed a response assembled for a different
principal because the key could not tell them apart. Confidentiality loss, no
privilege escalation, no audit trace — the second caller's request looks
identical to a cache hit for its own earlier call.

Reachable today wherever a backend's answer depends on who asked and the
key's identity component is empty. The response-cache key's identity suffix is
built from `caller_credential.cache_binding` and is
`String::default()` — empty — whenever that is `None`
(`invoke.rs:773-777`), which is the static-credential path. The capability
cache has no identity component at all, on a path that calls
`validate_personal_capability_identity` immediately above it.

### Current key, quoted

```rust
// src/cache.rs:223-226
pub fn build_key(server: &str, tool: &str, arguments: &Value) -> String {
    let args_hash = Self::hash_arguments(arguments);
    format!("{server}:{tool}:{args_hash}")
}
```

Both call sites then append the same two suffixes by hand:

```rust
// src/gateway/meta_mcp/invoke.rs:835-836 (read) and 1288-1289 (write)
let base = ResponseCache::build_key(server, tool, &arguments);
format!("{base}{projection_key_suffix}{identity_suffix}")
```

Two independent `format!` calls that must agree. A divergence between the
read key and the write key is silent: the cache simply stops hitting, or
starts hitting wrongly. That is the second defect in this file and it is
fixed by construction, not by vigilance — one owner, one constructed value.

## The elimination — authorization runs before the cache read

Revision 2 rested the whole safety argument on one claim: *the key encodes every
authorization-deciding input*. Each review round then found one more input it
did not encode — `agent_id`, `api_key_name`,
`CapabilityExecutionContext.allow_loopback_egress`. Enumerating a fourth is a
patch, and the finding stays permanently stateable, because the next round finds
a fifth. The level is wrong, not the list.

**The file already states the rule this design restores.** `invoke.rs:544-558`
is labelled "THE AUTHORIZATION CHOKEPOINT (MIK-7252)" and says why it sits at
the top of `invoke_tool_traced`:

> It is the earliest point at which the target is known, so nothing has yet
> happened that a refused call is not entitled to: no nonce consumed, **no cache
> read**, no idempotency entry, no credential minted, no budget consulted.

Grant enforcement is the one gate that escaped it. `enforce_identity_grants`
(`invoke.rs:1437`) is called at `:1842`, inside `dispatch_to_backend` — *after*
the cache read at `:838`. So a caller denied by `GrantAgent::Exact` can be
served another agent's cached body, exactly as both vendors said.

**Above WHICH cache read: the answer is all of them.** Revision 3 said "above
the response-cache read at `:838`" and that is not far enough. The idempotency
cache short-circuits *first*, at `:796-810`, returning `GuardedValue::from_cache`
on a hit. A chokepoint inserted at `:837` leaves a second shared cache on the
same path still serving a denied caller. The predicate is not "above the
response cache" but **above the first line that can return a cached body**,
which on HEAD is `:796`.

**And not only grants.** `CapabilityBackend::execute` runs
`validate_personal_capability_identity` and `validate_oauth_isolation`
(`backend.rs:401-406`) — the OAuth-account guard for multi-user deployments —
*inside dispatch*, so a cache hit never reaches them either. Naming that as a
third patch would repeat revision 2's mistake. The rule is the elimination:
**no authorization predicate may live below a cache read.** Enumerated today:
grants (`invoke.rs:1842`), personal-capability identity and OAuth isolation
(`backend.rs:401-406`). The rule is what holds when a fourth appears; the list
is only what the rule currently binds.

**The repair for the ordering created a second defect, and that is repaired
here, not deferred.** Moving grants above the cache means the definition is
authorized at `:796` and dispatch re-fetches it at `:1839` — and the capability
registry has a live writer: `CapabilityWatcher` calls `backend.reload()` on file
change (`src/capability/watcher.rs:159`). Two lookups of one name across a
reload boundary can return two different definitions, so a caller may be
authorized against the old definition and executed against a newly personal one.
Adding the early check *and keeping* the dispatch check is the patch — it leaves
the finding stateable, because two checks against two lookups still authorize
something other than what runs. The elimination is to **carry one immutable
authorized definition through dispatch**: resolve `cap_def` once at the
chokepoint, authorize *that value*, and pass it down rather than re-resolving by
name. After that, "authorized one definition, executed another" cannot be
stated.

**The move is free, and this was verified rather than assumed.**
`enforce_identity_grants` is synchronous, has no `.await`, takes no permit, and
holds one read lock. All five of its arguments are already in scope at the
chokepoint: `api_key_name` (`:535`), `agent_id` (`:536`), `caller_identity`
(`:537`), `tool` (`:542`). Its `cap_def` argument comes from a pure
`get_capabilities()` + `server == capabilities.name` + `capabilities.get(tool)`
lookup — the *same* lookup the chokepoint already performs at `:589-593` for the
admin gate. Nothing the cache read produces is an input to it.

One implementation trap, named because the naive move steps in it: the call is
**conditional on the capability path**, and the condition to mirror is
`dispatch_to_backend`'s own predicate at **`invoke.rs:1839-1842`** — the
`cap.get(tool)` that immediately precedes the grant call — *not* the admin gate
at `:589-593`. The admin gate carries `!caller_is_admin` and
`creates_caller_addressed_external_state`; copying it would skip grants for
callers the current dispatch path still checks, which is a privilege regression
wearing the costume of a faithful mirror.

### A bump published before its mutation is worse than no bump

Every epoch increment must be **released after** the mutation it describes is
visible, and every reader must take its snapshot with an acquire load. Stated
because the reverse interleaving is the default one gets by writing the bump
first: a reader that observes the new epoch while the old policy is still the
one in effect builds a *fresh* key over *stale* state and caches the result
under it. The stale body then survives every later read, because the epoch that
would have invalidated it has already been consumed. A missing bump serves one
stale response; a mis-ordered bump installs one.

This binds at each of the three bump sites, not once globally, and each carries
a case asserting the opposite interleaving cannot be observed — the test plan's
4.f.1/4.f.2/4.f.3 rows are where that lands.

### Three escapees, not one — and the same elimination closes all three

Revision 4 named the rule correctly and then applied it to a single predicate.
That gap is this revision's finding, raised independently by both vendors: the
document enumerates `enforce_identity_grants` (`invoke.rs:1842`),
`validate_personal_capability_identity` and `validate_oauth_isolation`
(`backend.rs:401-406`) as living below a cache read, moves the first, and states
the invariant as though all three had moved. Verified at source: both remaining
validators run inside `CapabilityBackend::execute`, immediately after that
function's own `self.get(name)` — a **third** by-name lookup of the same
capability, on top of the chokepoint's and `dispatch_to_backend`'s.

They are not a second case needing a second mechanism. Their inputs are the
capability definition and the execution context, both of which the chokepoint
already holds, and the multi-user flag, which is an atomic load. Carrying one
immutable authorized definition through dispatch — already this design's chosen
elimination — removes the third lookup and makes the chokepoint the only place
any of the three can run. Moving grants alone would leave the finding stateable
in its original words against a different function, which is the test §P0's
repair protocol sets for an elimination.

The invariant is therefore stated once, over the whole class: **no authorization
predicate may live below a cache read**, enforced by there being exactly one
resolution of the definition and exactly one place predicates run against it.
A fourth predicate added later inherits the ordering by construction rather than
by remembering to move it.

### The safety argument, now two claims instead of one

A reviewer who remembers revision 2 will read this as a weakening. It is not;
it is a split, and both halves are load-bearing.

| claim | what it covers | why it holds |
|---|---|---|
| **gate ordering** | every authorization gate runs before every cache read | the chokepoint's own stated invariant, with all three escapees returned to it |
| **response-varying keying** | the key carries every input that varies the *body* | the key's actual job; a missing input is a correctness bug, bounded and testable |

This is what makes the finding class unstateable rather than merely shorter. A
fifth dimension found in a future round is now one of two things: a
**gate**, which is covered by construction because gates run first, or a
**response-varying input**, which is a keying bug with a test. Neither is "a
denied caller was served another principal's body". That sentence stops being
constructible.

**Do not read this as "drop the identity segments".** A dimension that both
gates access *and* varies the body stays in the key on correctness grounds. The
routing profile is the clear case: it restricts which backends a session may
reach (`routing_profile/mod.rs:55-58`), so it decides what the response
*contains*. So does the credential — an API key's scope decides which backends a
caller sees (`cacheable.rs:53-58`). What changed is the *reason* they are there.
Key completeness is no longer the safety argument.

`allow_loopback_egress` is disposed by the same split, and it is the clean
demonstration: it gates whether an SSRF-protected URL may execute
(`execution_context.rs:41-48`) and does not vary the body of a request that was
permitted. It gets **no key segment**. Instead, a context with
`allow_loopback_egress == true` **must not cache** — neither read nor write.
That is the `TrustLab` local-sandbox path (`execution_context.rs:35`), which is
rare, short-lived, and has no business sharing a cache with production traffic.

## What the requirement asks, counted honestly

`RELEASE-4.0.0-requirements.md:126` names **seven** inputs — authorization
binding, routing profile, Code Mode, preview query, cursor, backend, protocol
revision — "plus a policy epoch". `criteria-status.md:60` records this as
"8 response-varying inputs + policy epoch", which counts the epoch twice, and
scores the key at "2 of 8". Both numbers are corrected here from source.

| # | input | in the key today? | evidence |
|---|---|---|---|
| 1 | backend | **yes, unconditional** | `server` is the first field of `build_key` (`cache.rs:225`) |
| 2 | authorization binding | **conditional** — empty on the static-credential path | `invoke.rs:773-777`, `unwrap_or_default()` |
| 3 | routing profile | no | `RoutingProfile` (`routing_profile/mod.rs:82-84`), selected per session by `MetaMcp::active_profile` (`meta_mcp/mod.rs:971-981`) and already called on this path at `invoke.rs:710`, before the cache read at `:838`. Its `name` is not in any cache key |
| 4 | Code Mode | **not response-varying — no component needed** | `code_mode_execute` re-enters `invoke_tool` with `{server, tool, arguments}` and returns its result unmodified (`meta_mcp/search.rs:466-479`). Same inputs, same path, same response. A key component would partition the cache without protecting anything |
| 5 | preview query | **cannot reach this cache today** | spec-preview is a list surface (`meta_mcp/spec_preview.rs:3-6`); `ResponseCache` sits only on the `tools/call` invoke path |
| 6 | cursor | **cannot reach this cache today** | every `next_cursor` site is a list/read surface: `spec_preview.rs:57`, `protocol.rs:176`, `resources.rs:268,348` |
| 7 | protocol revision | no | `src/protocol/era.rs`, `negotiate.rs`; no cache-key occurrence |
| 8 | policy epoch | no | nothing bumps a generation on grant, profile or config change |

So, counting the eight rows above and nothing else: **one unconditional**
(row 1), **one conditional** (row 2), **three absent** (rows 3, 7, 8), **two
structurally unreachable** (rows 5, 6), **one disposed as not
response-varying** (row 4). 1+1+3+2+1 = 8.

Outside the eight, the key already carries one component the requirement never
named: `projection_key_suffix` (`projection/mode.rs:115-122`) encodes response
*shape*, A or B. It is correct to key on and it is not Code Mode. The audit
note mapped it there.

Rows 5 and 6 are not dismissals. They are the fail-closed rule stated in
advance: **an input that cannot vary a cached response today becomes a
required key component the moment that surface is wired to a shared cache.**
The alternative formulation is the same rule from the other side, and both
must hold: key the input, *or* refuse to cache a response that varies on it.

## Target key shape

One owner, one constructed value, no caller-side concatenation. Segments are
**length-prefixed**, not colon-joined:

```
v=<schema_ver>|e=<epoch>|<len>:<server>|<len>:<tool>|<len>:<principal>|<len>:<profile>|<len>:<proto>|<len>:<shape>|<len>:<args_hash>
```

A raw colon join is not injective here, because at least one segment contains
colons: `cache_binding` is built as `cache_binding(subject_key, audience)`
(`identity_propagation/mod.rs:291`) and the module's own test feeds it
`"oidc:11:https://idp:1:a"` (`:707`). Today's `|idp:` suffix avoided regrouping
by accident — it is last, so nothing follows it to be absorbed. Put a segment
after it and the accident stops holding. Length prefixes make "two different
inputs produced one key" unstateable rather than untested.

Two properties, kept apart because they are proved differently. The **framing**
is *injective*: distinct segment tuples produce distinct byte strings, and that
is a property of the encoder alone, provable by inspection. The **finished key**
is *collision-resistant*, not injective, because `args_hash` is a digest —
fixed-width SHA-256 (`ResponseCache::hash_arguments`, `cache.rs`), 256 bits, and
any digest maps a larger domain onto a smaller one. Calling the whole key
injective would claim a property no hash has; calling the framing
collision-resistant would understate what the length prefixes buy.

| segment | source | absent value |
|---|---|---|
| `schema_ver` | a constant bumped when this shape changes | — |
| `epoch` | the policy epoch, below | — |
| `server`, `tool`, `args_hash` | as today (`cache.rs:223-226`) | — |
| `principal` | the caller identity, resolved below | **must fail closed** |
| `profile` | `RoutingProfile::name` from `active_profile(session_id)` (`meta_mcp/mod.rs:971-981`), already resolved at `invoke.rs:710` | none — `active_profile` always returns a profile, falling back to `profile_registry.default_name()` |
| `proto` | the caller's declared protocol revision, threaded from the POST handler's `declared_version` (`router/handlers.rs:572`) | **must fail closed** — no revision, no cache |
| `shape` | today's `projection_key_suffix` | fixed literal |

The `profile` segment has **no** feature-gated absent case. `routing_profile`
is compiled unconditionally (`lib.rs:69`, no `cfg`), and it is genuinely
response-varying: a profile restricts which backends a session may reach
(`routing_profile/mod.rs:55-58`), and a non-admin caller may switch its own
session's profile (`gateway/router/tests.rs:2983-3019`). The unrelated
`tool_profiles` module — per-user *usage counters*, `ToolProfile { user_id,
usage, created_at }` (`tool_profiles/mod.rs:83-89`) — is telemetry, is not on
the invoke path, and cannot vary a response. Revision 1 cited it here; that was
the wrong type.

### Resolving the principal

Ordered, and the order matters because the last rung is the defect:

1. `caller_credential.cache_binding` when present (`invoke.rs:773-777`) — the
   strongest binding: user *and* audience, collision-safe by construction.
2. otherwise `api_key_name` (already unpacked at `invoke.rs:535`), composed
   with the verified subject when the request carries one (`grant_subject` /
   `verified_identity`, `meta_mcp/mod.rs:120-126`).
3. otherwise **do not cache** — neither read nor write.

"Composed" is not string concatenation. Rung 2's principal is itself a
**length-prefixed tuple** — `<len>:<binding-or-key>|<len>:<subject>` — built by
the same encoder as the outer key. Concatenation would collapse two different
(key, subject) pairs into one principal string, reintroducing one level down the
cross-caller hit the outer length prefixing exists to make unstateable.

**Revision 3 still broke that, in the absent-subject case, and this is the
repair.** As written, a principal with no verified subject emitted the raw
`api_key_name` while a principal with one emitted `<len>:<key>|<len>:<subject>`.
Two shapes from one rung is not an encoding; a raw key whose text happens to
read as a length-prefixed pair collides with the pair it spells. **Always emit
the two-segment tuple.** A missing subject is length 0 — `<len>:<key>|0:` — never
a shorter shape. The rule generalises: an optional field is encoded as present-
and-empty, never as absent, because absence is what makes two encodings share a
byte string.

Rung 2 exists because rung 3 alone would take the default-on cache
(`config/features/cache.rs:21,32`) dark for the most common deployment: a
static credential with identity propagation off never produces a
`cache_binding`, so a design that only knows rungs 1 and 3 disables caching for
almost every installation and will be reverted by whoever notices. The
composition with the verified subject is what stops rung 2 from re-opening the
hole one level up: two end users behind one API key, whose responses differ
because the *gateway's* grant evaluation differs, are two principals even
though one credential reached the backend.

`agent_id` is **not** a principal component, and that is the split doing its
work rather than an omission. It is a grant input — `GrantAgent::Exact` is
evaluated by `enforce_identity_grants`, which now runs before the read — and it
does not vary the body of a call that was permitted. Both vendors asked for it
in the key; under gate ordering it belongs to the gate.

Named residual: rung 2 does not distinguish two callers who share an API key,
carry no verified identity, and are nonetheless told apart by something outside
this design. That case is unreachable through the gateway's own identity
surfaces today, and it is stated rather than assumed away.

The empty-principal case is the whole defect and it does not get a default. A
cache that silently degrades to a shared namespace is what
`unwrap_or_default()` already does.

The type carries this: the key constructor takes the principal as a value
that cannot be empty, and returns `Option<CacheKey>`; `None` means the call
runs uncached. That is the elimination, not a patch — after it, "the read key
and the write key disagreed" and "the principal was missing" are both
unstateable rather than merely unlikely.

### One seam, so two in-flight designs cannot fork the key

This constructor is declared the **single** seam where the MRTR.10
continuation-identifier fold from `docs/design/2026-08-30-mrtr-wiring.md`
lands. That design and this one are in flight simultaneously; if each adds its
own key shape, the gateway ends up with two, and the divergent-read/write
defect this section eliminates comes back one layer up. Whichever lands second
extends the constructor's input type — it does not build a second key.

### Fail-closed inputs, named in advance

`MetaMcpCallerContext.retry` (`meta_mcp/mod.rs:145`) is a fail-closed input
under the same rule already stated for cursor and preview query. It is
`&RetryFields`, documented at `:141-144` as "still attacker-controlled", and
MRTR.10a will make one logical call span two continuations. Two continuations
of one call must not share a cached body, so: key the retry fields, *or* refuse
to cache a response produced on a continuation. It is named here so MRTR.10a
cannot land without choosing one.

`MetaMcpCallerContext.input_capabilities` sits beside it under the same rule
(GPT's SCOPE-CHALLENGE, accepted). A continuation response shaped to what the
*client* declared it can accept must not be served to a client that declared
something else. Same two exits: key it, or refuse to cache the continuation.

`proto` is the third, and revision 2 recorded it as a *stated limit* — a fixed
literal "covering nothing" until some future revision threads a version through.
That was an unmet requirement wearing an honest-limit costume, and the check
that settles it is one grep, run rather than deferred.

**The constant is not admissible.** `SUPPORTED_VERSIONS` holds four revisions
concurrently (`protocol/mod.rs`), the caller's declared revision is read
**per request** at the transport edge (`router/handlers.rs:572`), and the
gateway already branches on it. A single literal therefore asserts a
one-revision world that does not exist. `handle_initialize` computes
`negotiate_version(client_version)` (`handle_initialize` in `meta_mcp/mod.rs`) and only *logs* it
— nothing stores or forwards it, which is why revision 2 could mistake "not
plumbed" for "not applicable".

So `proto` takes the same two exits as the two inputs above, and neither is
future work: **thread the declared revision from `handlers.rs:572` into
`MetaMcpCallerContext` and key it, or refuse to cache.** The value already
exists at the edge, so this is plumbing, not a new negotiation mechanism.
Whichever is chosen ships **with** the keyed cache — CACHE.4's protocol
dimension is not met by a constant, and this design no longer claims it is.

### What the cache stores — the body without its per-caller stamp

Three review rounds raised the same finding: the cached value carries the
*writer's* `_context_integrity` provenance — the subject at `:1500` and the
`trace_id` at `:1497` — because `apply_context_integrity` (`:1486`) runs at
`invoke.rs:1246` and the cache write is downstream of it (`:1286-1291`, verified
at `5c7e64f4`). Two rounds recorded it as an out-of-scope observation. That was
wrong, and the third sighting is what made it visible: §P0 says this change
exists so that *a response produced for one caller can never be served to
another*, and a body stamped with another caller's subject is precisely that.
The disposition was reading "provenance" as a separate subsystem when the leak
is the one this design is FOR.

The repair is an ordering move, the same shape as the chokepoint: **the cache
stores the guarded body without its per-caller stamp, and the stamp is applied
after the read, on both paths.**

The distinction between *guard* and *stamp* is load-bearing, and the first draft
of this repair got it wrong by saying "move `apply_context_integrity` below the
cache write". `apply_context_integrity` (`invoke.rs:1486`) does two jobs in one
call: it evaluates the context-integrity kernel (the render guard) and it writes
the per-caller provenance (`provenance.subject` at `:1500`, the trace id at
`:1497`). Only the second is per-caller. Moving the whole call below the write
would put an **unguarded** body in the store, and the type says so in its own
documentation — `GuardedValue::from_cache` (`invoke.rs:88-92`) reads "Cached
results were guarded at store time (the cache is populated only after
`apply_context_integrity`), so re-serving them is in-policy without re-running
the guard." A repair that silently falsifies the precondition a sealing
constructor documents is not an ordering move; it is a change to what
`GuardedValue` guarantees, and it would have to say what replaces the seal.

So: the guard call stays above the cache write, and the cached body is the
post-guard body with the per-caller provenance fields omitted; the stamp is
applied after the read on the hit path and after the write on the miss path.
`from_cache`'s stated precondition holds unchanged and its comment needs no
edit. Then "the
cached value carries a foreign subject" is unstateable, rather than partitioned
by a key segment — the stamp is never in the store to be served. The
idempotency-hit path already re-stamps (`invoke.rs:813-821` passes
`CacheOutcome::Hit` to `maybe_stamp_provenance`), so the shape has a working
precedent in this file; the response cache simply never adopted it.

Sequenced, like the chokepoint move, after the sibling change that owns
`invoke.rs` lands.

## Policy epoch

A monotonic `u64` generation, mixed into every key. It is **one process-level
atomic** that both key constructors snapshot — not a field on either cache
instance. The two caches are different types with no shared owner, so a
generation stored per instance would let a grant revocation bump the Meta-MCP
cache while `capability/response_cache.rs` keeps serving pre-revocation hits to
anything that reaches the executor without a gateway miss. One counter, two
readers. Bumped on:

| bump site | evidence |
|---|---|
| grant mutation | `MetaMcp::set_identity_grants` (`meta_mcp/mod.rs:814-816`) — the sole writer of `self.identity_grants` |
| capability registry reload | `CapabilityWatcher` calls `backend.reload()` on file change (`capability/watcher.rs:159`). A reload can change credentials, provider, exposure and transforms, so entries produced under the old definition must not survive it |
| config reload | `config_reload::LiveConfig` (`config_reload/mod.rs:243-268`) |

The routing-profile registry row is **deleted**, for the same reason the
tool-policy row was: it cannot fire. `routing_profile::ProfileRegistry` is a
plain `HashMap` behind an `Arc`, with no `&mut self` method and no interior
mutability, and its own doc comment reads "Immutable registry of all named
routing profiles, built once at startup" (`routing_profile/mod.rs:310-317`). It
is constructed at `gateway/server/mod.rs:508` and never written again. A bump
site with no writer is coverage theatre.

A session's own profile switch does **not** bump either. `profile` is already a
key segment, so a switch changes that session's keys and nobody else's; bumping
would make every *other* caller's entries unreachable until TTL eviction, and a
non-admin caller can trigger it at will (`non_admin_may_set_its_own_routing_profile`,
`gateway/router/tests.rs:2983-3019`). Revision 2 listed the switch as a bump
site. It is deleted, not softened.

A tool-policy row is also deleted. Revision 2 cited it as "the policy write
path", which is not a location. Searching `config_reload/mod.rs` and
`invoke.rs` for `tool_policy` returns nothing; the type is consulted by the
authorizer at the chokepoint, and no live-swap seam was found. An unlocatable
bump site is a bump that never fires, dressed as coverage.

**Build once, carry.** The key is constructed **once**, at the read, and the
same value is used at the write. This is the mechanism that disposes of the
epoch race — a request authorized at epoch N whose response inserts after a bump
to N+1 lands under N and is unreachable, rather than being published under the
post-revocation epoch. Revision 2 said "one owner, one constructed value" but
never said *built once and carried*; the second half is the half that does the
work, and it is the same elimination that already kills the divergent
read/write key.

**Built once *where*, though — and revision 3 named the wrong point.** "Once, at
the read" leaves a window: a bump between authorization and the cache read makes
the request snapshot N+1 and publish a body it was authorized to produce under
N — a pre-revocation response entering the post-revocation namespace. The
snapshot must be taken **at the chokepoint, before authorization runs**, and
carried through read and write. Then a bump anywhere after it lands the entry
under the epoch the request was actually authorized in, where post-bump readers
cannot reach it. This costs nothing extra now that authorization has moved to
the chokepoint: one atomic load, one line above the grant call, on the value the
key already carries.

Row 1 is not a duplicate of row 4. `set_identity_grants` replaces the store
outright (`*self.identity_grants.write() = grants;`) and `config_reload` has no
grant hook, so keying invalidation to `LiveConfig` alone leaves a window where a
grant is revoked and a pre-revocation response is still served from a hit. The
epoch must be bumped where the grant store is written, which is that function.

**What happens to existing entries.** Nothing walks the map. A bump changes
every future key, so every pre-bump entry becomes unreachable and ages out by
TTL and `max_entries` eviction. Unreachable entries are never served — which
is the property the requirement asks for, obtained without a scan. The
`schema_ver` prefix does the same job for a shape change.

## CACHE.3 — the decision table

`cacheable.rs:18-21` already states the burden of proof:

> `public` is a claim about **every future caller**, made by a server that has
> seen exactly one. So the burden runs one way — a response is private unless
> it provably does not depend on who asked.

| endpoint | scope | why |
|---|---|---|
| `tools/list` | private | varies by credential — an API key's scope decides which backends a caller sees (`cacheable.rs:53-58`) |
| `prompts/list` | private | same assembly, same caller-dependence |
| `resources/list` | private | same |
| `resources/templates/list` | private | same |
| `resources/read` | private | content is backend- and grant-dependent |
| anything not listed | **private** | a scope that has not been proven fails closed; a new endpoint enters this table as private and is promoted only by a recorded proof of invariance |

No row is `public` today. That is the honest state, and the table's value is
that it says so explicitly instead of leaving the reader to infer it.

The criterion has two clauses and the second is the one that gets skipped:
the table must be **referenced from the code that emits the field**. A
doc-comment on `CacheScope::for_list` (`cacheable.rs:41-45`) pointing at the
table discharges it. Made 2026-09-01: `SCOPE_TABLE` (`cacheable.rs:62-75`) is
read by `handlers.rs:998,1535` through `scope_for_method`. The second anchor
this section originally named, `current_for_tools_list`, was deleted rather
than documented — it had no production caller once the table existed.

## Options considered

| option | rejected because |
|---|---|
| bypass the cache whenever the principal is unbound | this *is* the chosen rule for the principal; rejected as the *whole* answer, because it leaves profile, protocol revision and epoch unkeyed and a bound principal still gets a stale post-revocation answer |
| hash the entire request into one opaque digest | correct and undebuggable — a cache miss becomes unexplainable, and no reviewer can check which inputs were included |
| a sub-cache per principal | moves the same key problem into a map lookup and adds an unbounded map keyed on an attacker-chosen value |
| do nothing; rely on authorization | the *transport* gate runs before the read and correctly says yes; grant evaluation ran after it. Moving grant evaluation up is half this design — but a caller authorized for a tool can still be handed a body assembled for a different profile, protocol revision or credential scope, and no ordering fixes that |
| enumerate the missing dimensions in the key (`agent_id`, `api_key_name`, `allow_loopback_egress`) | the patch each review round asks for, and the reason there is a next round. It leaves "the key omits an authorization input" permanently stateable. Rejected in favour of the ordering move, which makes the class unconstructible |

## The capability executor cache

`capability/executor/params.rs:245-258` builds `{capability.name}:{params_hash}`
with no principal component, read at `executor/mod.rs:301` and written at
`executor/mod.rs:334`, on a path that calls
`validate_personal_capability_identity` immediately above the lookup. The
requirement's words are "**any** shared cache the gateway keeps".

§P0 disposal: **fix it in this change.** CACHE.4 cannot honestly be claimed
MET while a second shared cache in the same binary is keyed without a
principal, and the epoch plumbing is shared — one owner, one key discipline,
one epoch is cheaper than a ticket and a second design.

Its key is stated here as **its own tuple**, not as "the same discipline as
`tools/call`":

```
v=<schema_ver>|e=<epoch>|<len>:<capability>|<len>:<principal>|<len>:<params_hash>
```

Five segments, and there is no `server`, `tool`, `profile`, `proto` or `shape`
slot on this path. Saying "same discipline" invites an implementer to reuse the
nine-segment constructor and fill four slots with empty strings — which
reintroduces exactly the empty-segment default this design exists to kill, in a
new place, and reads as compliance while doing it. Same *constructor module*,
same epoch, same length prefixing, different tuple.

**What supplies the principal here.** `CapabilityExecutionContext` — the
argument `execute_with_context` already takes and already hands to
`validate_personal_capability_identity` two lines above the cache read
(`executor/mod.rs:284-290`). Nothing new needs plumbing; the identity is in
scope and unused by the key.

**Two contexts that must not cache at all**, both fail-closed rather than keyed:

- `allow_loopback_egress == true` (`execution_context.rs:19,35`) — the SSRF gate
  is relaxed for this context (`validate_capability_url_for_context`,
  `:41-48`), so a body fetched under it must never be reachable from a context
  where the gate is enforced. Refusing to cache is the elimination; a key
  segment would merely partition the two.
- `exposure: Shared` with no `caller_identity` resolves to an explicit
  **shared-namespace principal**, not to rung 3. That principal is emitted by
  the *same* encoder as every other, with a leading discriminant: `0:` for the
  shared namespace, `1:` followed by the identity tuple otherwise. Without the
  discriminant a shared capability and a `GrantSubject` whose text spells the
  chosen sentinel serialize to one byte string, which is the collision this
  section exists to remove. A capability whose exposure is
  declared `Shared` has opted into a caller-invariant answer, and taking its
  cache dark would be the same revert-pressure that rung 2 exists to avoid.
  Rung 3 stays for `Personal` with no identity.

The fail-closed rung applies unchanged, and it has a concrete trigger:
`CapabilityExecutor::execute` (`executor/mod.rs:266-269`) calls
`execute_with_context` with `CapabilityExecutionContext::default()`. A default
context carries no principal, so that entry point resolves to rung 3 and **must
not cache** — neither read nor write.

Not in scope, and named so it is not silently dropped: the per-backend
metadata list cache (`backend/metadata.rs:136`, `get_tools_shared`) caches a
backend's own `tools/list` under a single shared `Arc`. Whether that is
caller-invariant is a real question and it is CACHE.2's, not CACHE.4's —
recorded as an observation for the CACHE.2 owner, not filed.

## Open questions, and what answered them

| question | how it was resolved | answer | what it changed |
|---|---|---|---|
| does Code Mode vary the response? | read `src/gateway/meta_mcp/search.rs` lines 460-480 | no — pure pass-through into `invoke_tool`, result returned unmodified | dropped a key component the requirement named; row 4 above states the evidence instead |
| can cursor or preview query reach `ResponseCache`? | searched for `next_cursor` and `build_key` call sites | no — those are list surfaces, the cache is on `tools/call` | replaced two key components with the fail-closed rule that fires if they are ever wired |
| is the identity suffix ever empty? | read `src/gateway/meta_mcp/invoke.rs` lines 770-780 | yes — `unwrap_or_default()` on `cache_binding` | made the principal non-defaultable and the key `Option` |
| is caching on by default? | read `src/config/features/cache.rs` | yes, `enabled: true` at line 32 | the defect is in the shipped configuration, not an opt-in |
| what bumps the epoch? | listed the public surface of `src/config_reload/mod.rs`, then looked for the grant-store writer | `LiveConfig` at lines 243-268 is the reload seam; `MetaMcp::set_identity_grants` (`meta_mcp/mod.rs:814-816`) is the *only* writer of the grant store and `config_reload` has no grant hook | named the bump sites, and made the grant one a separate row rather than folding it into config reload. Revision 3 cut the list to three: the session profile-switch row and the tool-policy row are both deleted below |
| which type is the routing profile? | read `src/tool_profiles/mod.rs:83-89` and `src/routing_profile/mod.rs:82-84`, then traced the invoke path | `RoutingProfile`, resolved by `active_profile` at `invoke.rs:710`. `tool_profiles` is per-user usage telemetry, not on this path | corrected row 3's evidence and the `profile` segment's source; removed a feature-gated absent case that does not exist |
| is a colon join injective over these segments? | read `identity_propagation/mod.rs:291` and its test at `:707` | no — `cache_binding` contains colons | length-prefixed segments instead of a raw colon join |
| can grant enforcement move above the cache read, and what does the move cost? | read `invoke.rs:524-593` (chokepoint), `:1437` (`enforce_identity_grants`), `:1842` (its call site inside `dispatch_to_backend`) | yes, and it is free — the function is synchronous, awaits nothing, takes no permit, holds one read lock, and all five arguments are in scope at `:534-542`; its `cap_def` comes from the same `get_capabilities()`/`get(tool)` lookup the chokepoint already does at `:588-591` | made ordering the elimination, split the safety argument in two, and dropped `agent_id` from the principal as a gate input rather than a keying one |
| what bumps the epoch on a tool-policy change? | searched `config_reload/mod.rs` and `invoke.rs` for `tool_policy` | nothing — no live-swap seam exists on either path; the type is consulted by the authorizer at the chokepoint | deleted the row. Revision 2's "the policy write path" named no location, and a bump site that cannot be found never fires |
| does the epoch race survive the ordering move? | traced the key's lifetime across the read at `:838` and the write at `:1294` | no, but not because of the move — because the key is built once and carried, so a mid-flight bump makes the insert land under the old epoch and be unreachable | stated "build once, carry" explicitly; revision 2 implied it and never said it |
| can an old-shape key be read after the change? | `rg` for every `ResponseCache` mention outside `cache.rs`, then read the store's declaration and `CachedResponse`'s derives | no — `entries` is a private `DashMap` (`cache.rs:21`), `CachedResponse` (`:29`) is private and derives no `Serialize`, no constructor accepts prior contents, and nothing outside `cache.rs` reaches the map; the only handle other modules hold is `Arc<ResponseCache>` inside one process | turned the rollback cost below from an estimate into a fact, and set the condition that would void it |

**Deferred:** one — the stdio `proto` question. It was none when this design froze; building the test plan turned the `proto` disjunction (§L48-53) into an unanswered operator question. The four fields live in the test plan's Deferred section, which governs.

## Reversibility

The reversal is **deploy the previous binary**. There is no migration to undo, no
schema to downgrade and no data to rewrite, because the only thing this change
altered is the *shape of a key* in a store that does not outlive the process
holding it.

The cost is **one cold cache**, once, on the restart that swaps the binary. Every
entry written under the new shape is unreachable to the old code and every entry
written under the old shape is unreachable to the new — and that asymmetry costs
nothing, because neither set exists at the moment the other starts. A restart
empties the store regardless of which binary comes back.

That is cheap for one reason and it is worth naming, because the reason is what
would have to change for this paragraph to stop being true: **the store does not
outlive the process.** `entries` is a private `DashMap` (`cache.rs:21`),
`CachedResponse` is private and derives no `Serialize` (`:29`), no constructor
takes prior contents, and no module outside `cache.rs` holds anything but an
`Arc<ResponseCache>` within a single process. No old-shape key survives a process
boundary to be read back, so the failure mode a key-shape change normally carries
— a stale entry read under a key that now means something else — has no path here.

**What voids this.** Any path that lets an old-shape key be read after the swap:
a warm handoff between processes, a persisted snapshot of `entries`, an external
or shared backing store, or a second process attached to the same map. Adding any
of those makes the key shape a migration concern and this paragraph must be
rewritten before that lands — which is what row `4.l.2` of the test plan asks for
with its version segment, still unbuilt.

## Test plan

The full §P2 test plan is a sibling document:
[`2026-08-31-cluster-f-response-cache-keying-test-plan.md`](2026-08-31-cluster-f-response-cache-keying-test-plan.md).
It decomposes CACHE.4 into one row per response-varying input, carries the
fixture doctrine (hit control + miss half) that a single cross-principal row
cannot, records the A1-A9 sweep, and declares the one rule carried by review
rather than by the suite.

**Scope receipt — the direct route moves from OUT to IN-as-guarded.** This
document settles `POST /mcp/{name}` as out of scope on the ground that it keeps
no cache, so there is nothing on it to key. The team lead reads CACHE.4 as
binding on *any shared cache the gateway keeps*, which makes "no cache here
today" a claim needing a **guard** rather than an exemption. The test plan
carries that guard (row 5.g). No second key shape is designed and none is
implied: what exists is a case that goes red if a shared cache ever appears on
that door.

## Disproof artifact

CACHE.4's evidence type is `T, I` and the test plan currently marks its own
case `I`.

**The premise revision 1 got wrong.** It said "two callers with different
bindings". Two *different* `cache_binding`s already hash to different identity
suffixes (`invoke.rs:773-777`), so the two keys already differ, the test goes
green against today's code, and it proves nothing. A case that cannot fail
today is not a disproof artifact — it is a coverage line. Both review vendors
raised this independently.

**The premise that actually fails today** is the *static-credential* path,
where `unwrap_or_default()` empties the suffix for **both** callers.

### Case 1 — response cache, keys collide across principals

Two callers with **different authorization identities** and **no**
`cache_binding` (identity propagation off — the shipped default) invoke the
same `{server, tool, arguments}`.

No backend and no cache instance are needed. The assertion is
**`assert_ne!(key(alice), key(bob))`**, and it **fails on `HEAD`**: with
`cache_binding == None` for both callers, `identity_suffix` is
`String::default()` for both, every other input is equal by construction, and
the two keys are byte-identical. It passes only once the key carries a
principal.

Revision 2 specified this as an *equality* assertion and called the equality
"the defect, asserted as an equality". That was backwards: an equality passes on
`HEAD`, which makes it a regression test *for the bug* — green now, red after
the fix. Both vendors caught it. The sentence is deleted, not softened.

**The case must call a named seam that exists on `HEAD`**, not hand-inline the
formula. A helper taking the two principals as arguments — mirroring today's
`build_key(...) + projection_key_suffix + identity_suffix`, with the principal
arguments *unused* — and delegating to the new constructor once it exists. A
test that inlines the formula itself makes the principal arguments decorative
and passes whatever the production key does.

Under the ordering move, this case no longer stands for "a denied agent is
served another agent's body" — a denied caller never reaches the read. It
falsifies **cross-principal sharing between two callers who are both
authorized**, which is precisely the threat model stated above: the attacker is
an authorized caller.

A key-level assertion is preferred over a live-cache round trip for one reason:
a cache test that stands up a backend can go green for reasons unrelated to the
key (a TTL, an eviction, a cacheability predicate), and then it is measuring
the harness. The key is the thing under test.

### Case 2 — capability executor, mirrored

Two **different principals** execute the same capability with the same params.
The second must not receive the first's response body.

Same shape, same inversion: `assert_ne!(key(alice), key(bob))` against
`build_cache_key` (`capability/executor/params.rs:245-258`), which is
`{capability.name}:{params_hash}` with no principal term at all. The two keys
are byte-identical for *any* two principals — the collision does not even need
the static-credential premise — so the case fails on `HEAD` and passes once the
tuple carries a principal. Asserted at the key, with the body-level statement as
the property it stands for.

### Case 3 — a denied agent must not be served from cache

Cases 1 and 2 falsify **key collision**. The ordering move demoted that claim:
the primary safety argument is now *authorization runs before the read*, and an
argument carried by prose while its two siblings carry tests is the weaker half
of this design, not the stronger one.

A caller denied by `GrantAgent::Exact` invokes a capability for which a warm
entry exists under the same `{server, tool, args_hash}`, written by a caller the
grant does allow. The assertion is that the denial is returned and **no body is
returned**.

It **fails on `HEAD`** for the reason already traced above: the cache read is at
`invoke.rs:838` and `enforce_identity_grants` is reached at `:1842`, inside
`dispatch_to_backend`. A hit short-circuits before the grant is ever evaluated,
so today the denied caller receives the body. It passes once the call moves to
the chokepoint at `:544-558`.

**The case must also go red against the half-move**, not only against `HEAD`.
Insert `enforce_identity_grants` above the response-cache read at `:838` and
leave the idempotency short-circuit at `:796-810` untouched: Case 3 must still
fail, because a warm idempotency entry returns `GuardedValue::from_cache` before
line 840 is ever reached. A case that only separates `HEAD` from the full move
cannot tell a correct chokepoint from one placed hundreds of lines too low, and
"above the cache read" is exactly the phrasing an implementer would satisfy by
placing it at `:837`. Concretely: the harness runs the denied caller twice —
once with the idempotency store warm, once cold — and both must return the
denial.

This case needs a live cache, unlike the other two — the thing under test is
*which code runs first*, and that is not observable at the key. Accepted
deliberately: the harness risk named in Case 1 is the price of testing an
ordering claim, and the alternative is testing nothing.

**Design event, named here rather than left for a vendor to find (§P3).**
Moving `enforce_identity_grants` to the chokepoint makes it fire on paths that
never reached `dispatch_to_backend` — a cache hit, and any early return between
`:558` and `:1842`. Callers who previously received a cached body, or a
different error, now receive the grant denial. That is a change to an observable
contract for refused callers, it is deliberate, and it is what the fix *is*: the
denial is the correct answer and the body was the defect. Existing tests
asserting the old error shape on those paths are expected to move.

### Case 4 - the store must hold no per-caller stamp

R9 asserts a new blocking behaviour, so it carries a case; an acceptance
criterion with an empty evidence cell *is* the finding (§P2 Q1).

Populate the cache as caller A, then read the **stored** value directly - not
the returned one - and assert its `_context_integrity` carries neither a
`subject` nor A's `trace_id`. Then invoke the same tool as caller B on a key
that hits, and assert the *returned* body carries B's subject and B's trace id.

It is red against `HEAD` by construction: `apply_context_integrity` runs at
`invoke.rs:1246` and the cache write is downstream at `:1286-1291`, so the
stored value cannot be unstamped. The first assertion is the one that must go
red - a case that only checks the second half passes on `HEAD` whenever A and B
happen to share an api-key name.

### What "passing" means

All four cases must **fail against `HEAD`** before the implementation lands.
Cases 1 and 2 fail on the `assert_ne!` named — not on a missing import, a panic
or a setup error. Read the assertion, not the exit code. Both pass once the key
carries a principal and refuses to cache when there is none.

Case 3 fails on the returned body, never on a setup error, and it has a second
red state that is the point of it: it must **also** fail against a chokepoint
placed above the response-cache read alone. It passes only when the grant check
runs above the first line that can return a cached body, with the idempotency
store warm and cold.

## Revision 4 — dispositions

Every finding from round 4 — both vendors, blocking and not — with what happened
to it. A recurrence that is declined says why, in one line, so it does not
arrive a fourth time as though it had never been read.

| # | source | finding | disposition |
|---|---|---|---|
| R1 | Grok (HIGH) | rung 2 encodes an absent subject as a raw `api_key_name` but a present one as a two-segment tuple, so the two shapes are not injective | **repaired.** Always emit the tuple; a missing subject is length 0 (`0:`), never a shorter shape. Written into "Resolving the principal" as a general rule: an optional field is encoded present-and-empty, because absence is what lets two encodings share a byte string |
| R2 | Grok (MEDIUM, CERTAIN) | `proto` is threaded from `handlers.rs:210-219`, which is `get_era_refusal` on `GET /mcp` and is not an input on the `tools/call` path | **repaired, claim verified at source first.** The cited range is the GET refusal path; the POST handler's `declared_version` (`handlers.rs:572`) is the value that exists per request. Corrected in the target-key table, in the fail-closed section, and in the revision-3 row that carried the wrong anchor. stdio is named explicitly: negotiated at `initialize` (`handle_initialize` in `meta_mcp/mod.rs`) or the transport does not cache |
| R3 | Grok (IMPR) | cite `dispatch_to_backend`'s own capability predicate as the grant-move condition, not the admin gate at `:588-591` | **already in the design, and it stays.** The trap paragraph names `invoke.rs:1839-1842` — the `cap.get(tool)` immediately preceding the grant call — and states why copying the admin gate's `!caller_is_admin` would be a privilege regression. Recorded here because the two vendors reached the same line independently, which is evidence the paragraph is load-bearing rather than decorative |
| R4 | Grok (IMPR) | give the executor's shared-namespace principal a discriminant in the same encoder | **repaired.** `0:` for the shared namespace, `1:` for the identity tuple. Without it a `GrantSubject` whose text spells the sentinel collides with shared-namespace entries — the same defect as R1, one level down |
| R5 | Grok (IMPR) | delete the `ProfileRegistry` epoch bump; the registry has no live writer | **already deleted in revision 3**, on the same "a bump site with no writer is coverage theatre" reasoning, with the immutability quoted from `routing_profile/mod.rs:310-317` |
| R6 | Grok (IMPR) | state that the chokepoint sits above the idempotency hit, and make Case 3 fail if grants are inserted only above `:838` | **repaired in the case, not only in the prose.** Revision 3 already moved the predicate to "above the first line that can return a cached body" (`:796`); what was missing is a case that can tell the two placements apart. Case 3 now runs the denied caller twice — idempotency store warm and cold — and both must return the denial. A case that only separates `HEAD` from the full move cannot catch a chokepoint placed at `:837` |
| R7 | GPT (IMPR) | the key is described as injective, which a digest cannot be | **repaired.** Two properties, proved differently: the *framing* is injective (a property of the encoder, provable by inspection), the *finished key* is collision-resistant because `args_hash` is a 256-bit SHA-256 digest. Calling the whole key injective claims a property no hash has |
| R8 | GPT (SCOPE-CHALLENGE) | `MetaMcpCallerContext.input_capabilities` is a dependency on cluster A before MRTR continuation responses can be cacheable | **accepted as a named dependency, and deliberately not designed here.** Cluster A owns that surface and is in flight; this design names the field, binds it to the same two exits as `retry` and `proto` (key it, or do not cache), and stops. Designing it here would fork a surface with an owner |
| R9 | GPT (recurrence, third sighting) | request-specific `_context_integrity` provenance — subject and trace ID — is stored inside the cached body | **reversed and repaired.** Two rounds recorded it as an out-of-scope observation; the third sighting is what exposed the misreading. §P0 declares this change is FOR "a response produced for one caller can never be served to another", and a body stamped with the writer's subject *is* that. New section "What the cache stores": the store holds the guarded body minus its per-caller stamp, and the stamp is applied after the read, on both hit and miss. Precedent already in the file — the idempotency-hit path re-stamps at `invoke.rs:815-822`. Corrected once inside this revision: the first draft said "move `apply_context_integrity` below the cache write", which would store an **unguarded** body and falsify the precondition `GuardedValue::from_cache` documents at `invoke.rs:88-92`. Guard stays, stamp moves. Carries Case 4 — a blocking behaviour claim with no disproof case is an empty evidence cell |

Anchors: every `file:line` in this revision was regenerated against **`5c7e64f4`**
and the doc header records that commit. Revision 3 mixed committed and
working-tree line numbers, which is how the `:210-219` anchor survived a round.

## Revision 3 — dispositions

Both vendors returned SHIP-WITH-FIXES on revision 2, and both verdict lines
named the same thing: a cache hit reaches the caller before the gateway has
evaluated that caller's grants. That is not a keying defect, and revision 3
stops treating it as one.

### Blocking

| # | vendor | finding | disposition |
|---|---|---|---|
| B1 | GPT (CRITICAL) + Grok (HIGH, as the `agent_id` omission) | grant evaluation, including agent binding and expiry, runs *after* the cache read | **eliminated.** Verified at source: `enforce_identity_grants` (`invoke.rs:1437`) is called at `:1842`, inside `dispatch_to_backend`, and the read is at `:838`. The move to the chokepoint (`:543-557`) is free — synchronous, no `.await`, no permit, one read lock, every argument already in scope at `:534-542`, and its `cap_def` from the lookup the chokepoint already runs at `:588-591`. With it moved, the safety argument is *gate ordering*, and the key's job shrinks to response-varying inputs. Two vendors asked for `agent_id` in the key; under ordering it belongs to the gate, and that is written into the principal section rather than left as a silent omission. The ordering claim carries its own disproof artifact (Case 3), because a claim promoted to primary while its evidence stays prose is the half of this design most likely to be wrong |
| B2 | GPT (CRITICAL) | an epoch bump between authorization and insert publishes a response under the post-revocation epoch | **eliminated by construction.** The key is built once at the read and the same value carried to the write, so a mid-flight bump makes the insert land under the *old* epoch — unreachable, not newly reachable. Revision 2 implied this and never said it; it is now stated, and it is the same elimination that already kills a divergent read/write key. No snapshot-validation protocol is needed, so none is specified |
| B3 | GPT (HIGH) | the principal drops `api_key_name` and `agent_id` | **split.** `api_key_name` was already rung 2 in revision 2 and stays, now with the injective encoding Grok's K5 asked for. `agent_id` is **disposed, not added**: it is a grant input evaluated by `enforce_identity_grants`, which now runs first, and it does not vary the body of a call that was permitted |
| B4 | GPT (HIGH) | the capability tuple omits `allow_loopback_egress`, which changes whether the request may execute | **accepted, inverted.** Not a key segment: `allow_loopback_egress == true` (`execution_context.rs:19`, gate at `:41-48`) means **do not cache**. A bit that decides whether a request may execute at all is an authorization input, and keying it would leave a permitted-context body sitting in the store waiting for the next key collision to find it |
| B5 | GPT (HIGH, CERTAIN) + Grok (HIGH) | Case 1 specifies an *equality* assertion, which passes on `HEAD` | **repaired, and the sentence deleted rather than softened.** Both cases now assert `assert_ne!(key(alice), key(bob))`, which fails on `HEAD` and passes only after the principal lands. Revision 2's equality was a regression test *for the bug*: green now, red after the fix. Grok's shaping accepted too — the case calls a named seam that exists on `HEAD` with the principal arguments unused, then delegates to the new constructor |
| B6 | Grok (MEDIUM) | the epoch is specified as held "on the cache", but the two caches are different types with no shared owner | **repaired.** One process-level atomic that both key constructors snapshot. A per-instance generation bumped on the gateway cache leaves `capability/response_cache.rs` serving pre-revocation hits to anything reaching the executor without a gateway miss |
| B7 | Grok (MEDIUM) | the session profile-switch bump over-invalidates a cache whose key already carries `profile` | **deleted, not softened.** Any non-admin `gateway_set_profile` (`gateway/router/tests.rs:2983-3019`) would have made every other caller's entries unreachable until TTL eviction. Bump only on `ProfileRegistry` content change |
| B8 | Grok (MEDIUM) | rung 2 composes `api_key_name` with the verified subject without giving an injective encoding | **repaired.** The principal is itself a length-prefixed tuple built by the same encoder as the outer key. Concatenation would collapse two different (key, subject) pairs into one principal string — the exact hole the outer length-prefix was added to close |

### Non-blocking

| # | vendor | item | disposition |
|---|---|---|---|
| N1 | GPT (MEDIUM) | request-specific `_context_integrity` provenance — trace ID and subject — stays inside the cached value | **recorded as an observation, not a ticket.** Verified real: `apply_context_integrity` runs at `:1246` and is defined at `:1486`, writing subject (`:1500`) and `trace_id` (`:1497`), and `:1291` caches the decorated body. It is a pre-existing property of what today's cache stores, unchanged by this design, and outside what §P0 declares this change is FOR. **Superseded by R9: that reading was wrong and the finding is repaired, not observed.** Filing it would buy a queue entry and a human's attention for a defect nobody is currently paying for; recording it costs a line and survives |
| N2 | GPT (LOW) + Grok | source anchors mix committed `HEAD` with the dirty working tree, and the `invoke.rs` cache-site lines point at an idempotency debug log | **repaired.** Every citation regenerated against one named commit, recorded in the document; the cache sites now read `:838` and `:1291` |
| N3 | GPT | SCOPE-CHALLENGE: name `MetaMcpCallerContext.input_capabilities` beside `retry` | **accepted**, added to the fail-closed section under the same two exits |
| N4 | Grok | treat protocol revision as fail-closed rather than a fixed-literal segment | **accepted in full, after a first pass got it wrong.** That pass recorded a *stated limit* — a constant "covering nothing" until some future revision plumbed a value. Running the check instead of deferring it killed that: four revisions are served concurrently (`protocol/mod.rs`), the caller's declared revision is read per request by the POST handler (`declared_version`, `router/handlers.rs:572`; the `handlers.rs:210-219` cited in the first pass is `get_era_refusal` on the GET path and is not an input to `tools/call`), and `handle_initialize` (`meta_mcp/mod.rs`) computes the negotiated value and only logs it. A constant asserts a one-revision world that does not exist, so `proto` now takes the same two exits as `retry` — key it from the value already at the edge, or refuse to cache — and ships with the change. An honest limit against a MUST is an unmet requirement, not a disclosure |
| N5 | Grok | give `exposure: Shared` with no `caller_identity` an explicit shared-namespace principal instead of rung 3 | **accepted.** An opted-in shared capability stays cacheable without reopening `Personal` isolation, which is the same revert-pressure argument that produced gateway rung 2 |
| N6 | Grok | replace "the policy write path" with a file:line, or fold it into the `LiveConfig` row | **row deleted.** Searching `config_reload/mod.rs` and `invoke.rs` for `tool_policy` returns nothing: there is no live-swap seam. An unlocatable bump site is a bump that never fires, dressed as coverage |
| N7 | GPT | property-based injectivity tests over arbitrary Unicode and delimiter-containing segments, for both encodings | **accepted, into the §P2 test plan** for CACHE.4 — not into the disproof artifact, which has one job: fail on `HEAD`. A property test over a not-yet-existing encoder cannot do that |
| N8 | GPT | an integration test proving an unresolved principal performs neither a read nor a write | **accepted, same place.** Rung 3 is currently proven only at the constructor; the assertion that matters is about two call sites, so it belongs at the level where both are exercised |

**Rejected:** none, again — but two findings were disposed *against* what the
vendor asked for. `agent_id` was requested in the key and belongs to the gate;
`allow_loopback_egress` was requested in the key and belongs to a refusal to
cache. In both cases the vendor found a real hole and named the patch; the
ordering move closes the hole the other way.

## Revision 2 — dispositions

Both vendors returned SHIP-WITH-FIXES on revision 1 and converged on one
blocking defect. Every finding and improvement below carries its disposition.

### Blocking

| # | finding | disposition |
|---|---|---|
| B1 | the disproof artifact cannot fail today under its own stated premise — two *different* `cache_binding`s already produce different suffixes (`invoke.rs:773-777`) | **eliminated**, not patched. The premise is replaced with the static-credential path (two identities, no `cache_binding`, both suffixes `String::default()`), the assertion moved to the key itself so no backend or cache instance is involved, and a mirrored executor case added. After the rewrite the finding is unstateable: the case asserts an equality that holds only on today's code. Revision 3 retracts that assertion — an equality passes on `HEAD`, so it was a regression test for the bug; see B5 in the revision 3 table |

Test applied: *can the finding still be stated?* No. "The test passes against
HEAD" was true of a premise where the suffixes differ; the new premise is the
one branch where they are equal, and the artifact now names the failure mode
it must fail on.

### Verdict claim with no supporting finding

| claim | verdict |
|---|---|
| "the profile segment points at the wrong type" — asserted in one vendor's verdict line, with **no** finding in its report | **REAL — repaired.** Verified at source, not taken on trust. Revision 1 cited `ToolProfile`/`ProfileRegistry` (`tool_profiles/mod.rs:83-89,166-179`). That is a per-user *usage counter* store — `ToolProfile { user_id, usage: DashMap<String, UsageEntry>, created_at }` — consumed only inside `src/tool_profiles/*` and `lib.rs`, absent from `invoke.rs`, and incapable of varying a response. The right type is **`RoutingProfile`** (`routing_profile/mod.rs:82-84`), resolved per session by `MetaMcp::active_profile` (`meta_mcp/mod.rs:971-981`) and already called on this path at `invoke.rs:710`. Repaired in row 3 and in the target-key table. A second error travelled with it: revision 1 gave the segment a "fixed literal when the `tool-profiles` feature is off" absent case, but `routing_profile` is compiled unconditionally (`lib.rs:69`, no `cfg`) and `active_profile` always returns a profile. That row is gone |

### Improvements

| # | improvement | disposition |
|---|---|---|
| 1 | use `api_key_name` as the principal when `cache_binding` is `None`, rather than skipping the cache | **accepted**, with one addition. A design that only knows "binding or nothing" takes the default-on cache dark for the commonest deployment and gets reverted. Added as rung 2 of an ordered resolution — but composed with the verified subject when one is present, because `api_key_name` alone would re-open the hole for two end users behind one API key whose responses differ by the gateway's own grant evaluation. Rung 3 (do not cache) survives unchanged, and the residual is named rather than assumed away |
| 2 | length-prefix the segments rather than a raw colon join | **accepted.** Verified at source first: `cache_binding` is built by `cache_binding(subject_key, audience)` (`identity_propagation/mod.rs:291`) and the module's own test feeds it `"oidc:11:https://idp:1:a"` (`:707`) — colons, confirmed. Today's `|idp:` suffix is injective only because nothing follows it. The key shape is now length-prefixed |
| 3 | state the capability-executor key as its own tuple, and name what supplies the principal | **accepted.** Written as a five-segment tuple with no `server`/`tool`/`profile`/`proto`/`shape` slots, and the reason spelled out — "same discipline as `tools/call`" invites an implementer to reuse the nine-segment constructor with four empty slots, which is the empty-principal default in new clothes. Principal source named: `CapabilityExecutionContext`, already in scope at `executor/mod.rs:284-290`. Added beyond the suggestion: `CapabilityExecutor::execute` (`:266-269`) passes `CapabilityExecutionContext::default()`, so that entry point resolves to rung 3 and must not cache |
| 4 | name `MetaMcpCallerContext.retry` as a fail-closed input | **accepted.** Added under the same rule as cursor and preview query, with the field's own doc-comment (`meta_mcp/mod.rs:141-145`, "still attacker-controlled") as evidence, so MRTR.10a cannot land with two continuations of one call sharing a cached body |
| 5 | bump the epoch at `set_identity_grants`, not only on `LiveConfig` | **accepted.** The bump sites are now a table with evidence per row, and the reason row 1 is not row 4 is stated: `set_identity_grants` (`meta_mcp/mod.rs:814-816`) is the sole writer of the grant store and `config_reload` has no grant hook, so a `LiveConfig`-only epoch leaves a revoked grant servable from a pre-revocation hit |
| 6 | declare the new constructor the single seam for the MRTR.10 continuation-identifier fold | **accepted.** Stated as a constraint on both in-flight designs: whichever lands second extends the constructor's input type, it does not build a second key |
| 7 | fix the summary count after the input table | **accepted.** Now 1 unconditional + 1 conditional + 3 absent + 2 unreachable + 1 disposed = 8, with the row numbers named. Revision 1 said "four absent" while only rows 3, 7 and 8 are absent — row 4 is disposed as not response-varying — and folded `projection_key_suffix` into a count it is not part of. It is now stated separately as a component outside the eight |

**Rejected:** none. Every finding and improvement was accepted, repaired, or —
in B1's case — eliminated. The one item that arrived without supporting
evidence (the profile-segment claim) was verified at source before being acted
on, and turned out to be real.

## Design event, 2026-09-02 — the retry discriminator composes with the principal, it does not replace it

This document and the MRTR.10 work were written against different versions of the same key.
Integrating them forced a decision neither had made, so it is named here rather than left in a
merge resolution.

The two versions disagreed on what identifies the caller. This document keys the response cache on
`caller_principal` — the propagated binding when identity propagation is minting per-user
credentials, otherwise the verified subject — because keying on the binding alone let two
authenticated callers share one entry whenever propagation was off, which is the shipped default.
The MRTR.10 builder keyed on `identity_suffix`, the binding alone, and added a retry discriminator
so that two continuations answering one gate differently cannot share an entry.

Each side carried a property the other lacked, so taking either wholesale would have shipped a
known defect: the MRTR side reintroduces the cross-caller collision this document exists to close,
and this side drops the discriminator that stops a declined booking being served the accepted
booking's result.

The resolution is composition, not choice. `response_cache_key_for` now delegates its base to
`ResponseCache::response_key`, which owns the principal, and appends only the retry discriminator.
One key builder, two independent contracts, neither able to silently drop the other — the
discriminator cannot be removed without failing `response_cache_key_separates_two_answers_to_one_gate`,
and the principal cannot be removed without failing `response_cache_key_separates_two_principals`.

What this changes for anything already deployed: nothing. `NO_RETRY.key_discriminator()` is empty,
so an ordinary call derives exactly the key the principal-scoped builder derives on its own. That
is what `response_cache_key_is_unchanged_for_an_ordinary_call` asserts, and it is the assertion
that would fail if a future discriminator became non-empty for ordinary calls and quietly emptied
every cache.
