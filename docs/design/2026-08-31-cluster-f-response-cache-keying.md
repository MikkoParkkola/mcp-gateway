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

- editing `src/gateway/meta_mcp/invoke.rs` or `src/idempotency.rs` (a sibling
  change owns both files right now)
- the idempotency cache's own key discipline (`resolve_idempotency_key`)
- the OpenAI-compatible prompt-cache helpers (`prompt_cache.rs`) — a
  pass-through hint for backends that call LLM APIs, not a gateway cache
- outbound protocol-era negotiation (`src/protocol/era.rs`,
  `negotiate.rs`) — structurally distinct from CACHE.1-4, per
  `RELEASE-4.0.0-criteria-status.md:73`

## Problem

Two shared caches live in this binary. Both are read *after* authorization has
already succeeded, and neither key contains the principal unconditionally.

| cache | key | built | read | written |
|---|---|---|---|---|
| response cache | `{server}:{tool}:{args_hash}` + two conditional suffixes | `cache.rs:223-226` | `invoke.rs:835-836` | `invoke.rs:1288-1289` |
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
| 3 | routing profile | no | `RoutingProfile` (`routing_profile/mod.rs:82-84`), selected per session by `MetaMcp::active_profile` (`meta_mcp/mod.rs:971-981`) and already called on this path at `invoke.rs:710-711`, before the cache read at `:835`. Its `name` is not in any cache key |
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

| segment | source | absent value |
|---|---|---|
| `schema_ver` | a constant bumped when this shape changes | — |
| `epoch` | the policy epoch, below | — |
| `server`, `tool`, `args_hash` | as today (`cache.rs:223-226`) | — |
| `principal` | the caller identity, resolved below | **must fail closed** |
| `profile` | `RoutingProfile::name` from `active_profile(session_id)` (`meta_mcp/mod.rs:971-981`), already resolved at `invoke.rs:710` | none — `active_profile` always returns a profile, falling back to `profile_registry.default_name()` |
| `proto` | negotiated protocol revision | fixed literal |
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

Rung 2 exists because rung 3 alone would take the default-on cache
(`config/features/cache.rs:21,32`) dark for the most common deployment: a
static credential with identity propagation off never produces a
`cache_binding`, so a design that only knows rungs 1 and 3 disables caching for
almost every installation and will be reverted by whoever notices. The
composition with the verified subject is what stops rung 2 from re-opening the
hole one level up: two end users behind one API key, whose responses differ
because the *gateway's* grant evaluation differs, are two principals even
though one credential reached the backend.

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

## Policy epoch

A monotonic `u64` generation held on the cache (an atomic), mixed into every
key. Bumped on:

| bump site | evidence |
|---|---|
| grant mutation | `MetaMcp::set_identity_grants` (`meta_mcp/mod.rs:814-816`) — the sole writer of `self.identity_grants` |
| tool-policy change | the policy write path |
| routing-profile change | a profile edit, and a session's profile switch |
| config reload | `config_reload::LiveConfig` (`config_reload/mod.rs:243-268`) |

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
doc-comment on `CacheScope::for_list` (`cacheable.rs:45`) and
`current_for_tools_list` (`cacheable.rs:64`) pointing at this section
discharges it. Those edits are named here, not made here.

## Options considered

| option | rejected because |
|---|---|
| bypass the cache whenever the principal is unbound | this *is* the chosen rule for the principal; rejected as the *whole* answer, because it leaves profile, protocol revision and epoch unkeyed and a bound principal still gets a stale post-revocation answer |
| hash the entire request into one opaque digest | correct and undebuggable — a cache miss becomes unexplainable, and no reviewer can check which inputs were included |
| a sub-cache per principal | moves the same key problem into a map lookup and adds an unbounded map keyed on an attacker-chosen value |
| do nothing; rely on authorization | authorization runs *before* the cache read and correctly says yes. The disclosure happens after it |

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
| what bumps the epoch? | listed the public surface of `src/config_reload/mod.rs`, then looked for the grant-store writer | `LiveConfig` at lines 243-268 is the reload seam; `MetaMcp::set_identity_grants` (`meta_mcp/mod.rs:814-816`) is the *only* writer of the grant store and `config_reload` has no grant hook | named four bump sites, and made the grant one a separate row rather than folding it into config reload |
| which type is the routing profile? | read `src/tool_profiles/mod.rs:83-89` and `src/routing_profile/mod.rs:82-84`, then traced the invoke path | `RoutingProfile`, resolved by `active_profile` at `invoke.rs:710`. `tool_profiles` is per-user usage telemetry, not on this path | corrected row 3's evidence and the `profile` segment's source; removed a feature-gated absent case that does not exist |
| is a colon join injective over these segments? | read `identity_propagation/mod.rs:291` and its test at `:707` | no — `cache_binding` contains colons | length-prefixed segments instead of a raw colon join |

**Deferred:** none. Nothing in this design waits on an unanswered question.

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

No backend and no cache instance are needed. Assert directly on the key that
`invoke.rs:835-836` and `:1288-1289` construct today:

```
build_key(server, tool, arguments) + projection_key_suffix + identity_suffix
```

With `cache_binding == None` for both callers, `identity_suffix` is
`String::default()` for both, every other input is equal by construction, and
the two keys are **byte-identical**. That equality is the defect, asserted as
an equality — the test fails the moment the key includes a principal, which is
what makes it a falsifier rather than a description.

A key-level assertion is preferred over a live-cache round trip for one reason:
a cache test that stands up a backend can go green for reasons unrelated to the
key (a TTL, an eviction, a cacheability predicate), and then it is measuring
the harness. The key is the thing under test.

### Case 2 — capability executor, mirrored

Two **different principals** execute the same capability with the same params.
The second must not receive the first's response body.

Same shape, one rung lower: `build_cache_key`
(`capability/executor/params.rs:245-258`) is `{capability.name}:{params_hash}`
with no principal term at all, so the two keys are byte-identical for *any* two
principals — the collision does not even need the static-credential premise.
Asserted at the key, with the body-level statement as the property it stands
for.

### What "passing" means

Both cases must **fail against `HEAD`** before the implementation lands, on the
assertion named — not on a missing import, a panic, or a setup error. Read the
assertion, not the exit code. Both then pass once the key carries a principal
and refuses to cache when there is none.

## Revision 2 — dispositions

Both vendors returned SHIP-WITH-FIXES on revision 1 and converged on one
blocking defect. Every finding and improvement below carries its disposition.

### Blocking

| # | finding | disposition |
|---|---|---|
| B1 | the disproof artifact cannot fail today under its own stated premise — two *different* `cache_binding`s already produce different suffixes (`invoke.rs:773-777`) | **eliminated**, not patched. The premise is replaced with the static-credential path (two identities, no `cache_binding`, both suffixes `String::default()`), the assertion moved to the key itself so no backend or cache instance is involved, and a mirrored executor case added. After the rewrite the finding is unstateable: the case asserts an equality that holds only on today's code |

Test applied: *can the finding still be stated?* No. "The test passes against
HEAD" was true of a premise where the suffixes differ; the new premise is the
one branch where they are equal, and the artifact now names the failure mode
it must fail on.

### Verdict claim with no supporting finding

| claim | verdict |
|---|---|
| "the profile segment points at the wrong type" — asserted in one vendor's verdict line, with **no** finding in its report | **REAL — repaired.** Verified at source, not taken on trust. Revision 1 cited `ToolProfile`/`ProfileRegistry` (`tool_profiles/mod.rs:83-89,166-179`). That is a per-user *usage counter* store — `ToolProfile { user_id, usage: DashMap<String, UsageEntry>, created_at }` — consumed only inside `src/tool_profiles/*` and `lib.rs`, absent from `invoke.rs`, and incapable of varying a response. The right type is **`RoutingProfile`** (`routing_profile/mod.rs:82-84`), resolved per session by `MetaMcp::active_profile` (`meta_mcp/mod.rs:971-981`) and already called on this path at `invoke.rs:710-711`. Repaired in row 3 and in the target-key table. A second error travelled with it: revision 1 gave the segment a "fixed literal when the `tool-profiles` feature is off" absent case, but `routing_profile` is compiled unconditionally (`lib.rs:69`, no `cfg`) and `active_profile` always returns a profile. That row is gone |

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
