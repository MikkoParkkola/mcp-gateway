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
| 3 | routing profile | no | `ToolProfile`/`ProfileRegistry` (`tool_profiles/mod.rs:83-89,166-179`); no occurrence in any cache key |
| 4 | Code Mode | **not response-varying — no component needed** | `code_mode_execute` re-enters `invoke_tool` with `{server, tool, arguments}` and returns its result unmodified (`meta_mcp/search.rs:466-479`). Same inputs, same path, same response. A key component would partition the cache without protecting anything |
| 5 | preview query | **cannot reach this cache today** | spec-preview is a list surface (`meta_mcp/spec_preview.rs:3-6`); `ResponseCache` sits only on the `tools/call` invoke path |
| 6 | cursor | **cannot reach this cache today** | every `next_cursor` site is a list/read surface: `spec_preview.rs:57`, `protocol.rs:176`, `resources.rs:268,348` |
| 7 | protocol revision | no | `src/protocol/era.rs`, `negotiate.rs`; no cache-key occurrence |
| 8 | policy epoch | no | nothing bumps a generation on grant, profile or config change |

So: **one unconditional, one conditional, four absent, two structurally
unreachable** — plus one component the requirement never asked for. The
`projection_key_suffix` (`projection/mode.rs:115-122`) encodes response
*shape*, A or B; it is correct to key on and is not Code Mode. The audit note
mapped it there.

Rows 5 and 6 are not dismissals. They are the fail-closed rule stated in
advance: **an input that cannot vary a cached response today becomes a
required key component the moment that surface is wired to a shared cache.**
The alternative formulation is the same rule from the other side, and both
must hold: key the input, *or* refuse to cache a response that varies on it.

## Target key shape

One owner, one constructed value, no caller-side concatenation:

```
{schema_ver}:{epoch}:{server}:{tool}:{principal}:{profile}:{proto}:{shape}:{args_hash}
```

| segment | source | absent value |
|---|---|---|
| `schema_ver` | a constant bumped when this shape changes | — |
| `epoch` | the policy epoch, below | — |
| `server`, `tool`, `args_hash` | as today (`cache.rs:223-226`) | — |
| `principal` | the caller's authorization binding | **must fail closed** |
| `profile` | routing-profile identity, or a fixed literal when the `tool-profiles` feature is off | fixed literal |
| `proto` | negotiated protocol revision | fixed literal |
| `shape` | today's `projection_key_suffix` | fixed literal |

The empty-principal case is the whole defect and it does not get a default.
When no binding is available, **do not cache** — neither read nor write. A
cache that silently degrades to a shared namespace is what
`unwrap_or_default()` already does.

The type carries this: the key constructor takes the principal as a value
that cannot be empty, and returns `Option<CacheKey>`; `None` means the call
runs uncached. That is the elimination, not a patch — after it, "the read key
and the write key disagreed" and "the principal was missing" are both
unstateable rather than merely unlikely.

## Policy epoch

A monotonic `u64` generation held on the cache (an atomic), mixed into every
key. Bumped on: grant mutation, tool-policy change, routing-profile change,
config reload (`config_reload::LiveConfig`, `config_reload/mod.rs:243-268`).

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
| what bumps the epoch? | listed the public surface of `src/config_reload/mod.rs` | `LiveConfig` at lines 243-268 is the reload seam | named config reload as one of four bump sites |

**Deferred:** none. Nothing in this design waits on an unanswered question.

## Disproof artifact

CACHE.4's evidence type is `T, I` and the test plan currently marks its own
case `I`. The falsifying test, named here and written by the implementation:
two callers with different bindings invoke the same `{server, tool,
arguments}`; the second must not receive the first's response body. It fails
against today's key on the static-credential path, where the identity suffix
is empty for both.
