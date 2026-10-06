# MIK-7211.PARENT.6: a public `cacheScope` cannot be built

**Status**: adopted, shipped in #2474 (a2359c9ba); envelope recognition narrowed by MIK-7734. **Criterion**: MIK-7211.PARENT.6 (scope-update.md:136): "No surface emits
cacheScope public on a response computed from session-scoped state, enforced by a type or a lint
that is named in the closing record". **Tier**: STANDARD. It changes what the direct route forwards: a backend's `public` becomes
`private`.

## Problem, at source

- `src/protocol/cacheable.rs:23-28` has `pub enum CacheScope { Public, Private }`. Any code in the
  crate, or any lib user, can write `CacheScope::Public`.
- `CacheScope::for_list(false)` (`:46-52`) returns `Public` for any caller that passes `false`.
  Nothing checks the boolean.
- `SCOPE_TABLE` (`:62-73`) is all `Private`, so today's wire is right. That is a convention: a
  one-token edit (`for_list(true)` to `false`, or a `CacheScope::Public` row) would ship `public`
  on `tools/list`. That list is assembled from the credential, the profile and the session
  (`src/gateway/meta_mcp/visibility.rs`, `search.rs`). The type does not stop the edit.
- The only wire writer is `shape_modern_response` (`src/gateway/router/handlers.rs:2030-2040`),
  and it reads `scope_for_method(method)`. Nothing stops a second writer that inserts a
  `"cacheScope"` key with a literal.
- RFC-0060 "The cache hazard" (:171-173) asks for "a type that prevents attaching a
  `CacheableResult` to a session-scoped computation, not a convention". MIK-7213.CACHE.3a is MET
  only vacuously (criteria-status :96).

## Round 1 review (2026-09-30): REDESIGN, adopted

- **HIGH, confirmed at source.** The direct backend route forwards a backend's own result
  unchanged for every method except `tools/list`. That covers `resources/read`, `prompts/list`,
  `resources/list` and `resources/templates/list`. See `src/gateway/router/backend_handlers.rs:1102-1162`
  (`dispatch_in_scope`, then `build_http_response`). The call is made in the caller's scope, with
  the identity key and propagated headers. It never passes `shape_modern_response`, and it never
  passes the shared finalizer. So a backend's `"cacheScope": "public"` reaches the client on a
  response computed from session-scoped state. The enum guard cannot see it.
  Direct `tools/list` rebuilds `{tools}` and drops sibling fields (`direct_list.rs:106-109`), so it
  is not affected.
- **HIGH.** A key-literal count is a drift check, not enforcement. The claim moves to a single
  enforced function plus a behavioural proof on every result-carrying route.
- **MEDIUM.** The compile-fail doctest is green before the change. It is dropped as evidence.
- **MEDIUM.** The existing wire tests assert only `!= "public"`, on responses that may be errors.
  New tests assert exact `"private"` on successful responses.

## Decision

**1. Type: the gateway cannot claim `public`.**

```rust
pub enum CacheScope {
    /// Uninhabited until a method is proven invariant across authorization contexts.
    Public(std::convert::Infallible),
    Private,
}
```

- No expression builds a `CacheScope::Public` value. `as_str` matches `Public(never) => match never {}`.
- `for_list` is deleted; its `false` arm was the only way to produce `Public`. The four table rows
  that call it (`cacheable.rs:65-68`) become `CacheScope::Private`, each with its reason kept.
- `Infallible` rather than a new named type: no new public item. The doc comment carries the
  meaning.
- To allow `public` one day, someone must replace `Infallible` with a proof type. That is a design
  change in one file, and review will see it.

**2. Boundary: the wire serializer clamps every delivered result.**

`pub(crate) fn clamp_delivered_scope(result: &mut serde_json::Value)` in `src/protocol/cacheable.rs`:
- If the result object has a `cacheScope` key whose value is not `"private"`, set it to `"private"`.
  For `"public"` this is a downgrade the spec permits (`private` is the restrictive scope). For
  null, a number or an unknown string it is malformed-field normalization. Both are documented.
- If it has no such key, leave it alone. Legacy results keep having no key, which spec
  compatibility requires. Nested tool data and JSON strings are never rewritten.

It is applied by serialization, not by call sites. Round 2 showed that call-site placement misses
exits: idempotency replay, the sanitized-dispatch arm and the task envelope. A
`#[serde(serialize_with = "…")]` attribute on the only two protocol-defined result slots that reach
the wire runs it on every serialization:
- `JsonRpcResponse.result` (`src/protocol/messages.rs:49-57`). Every HTTP builder
  (`router/helpers.rs:66,111`), batch, SSE framing, the stdio writer and the direct route's three
  success exits (`backend_handlers.rs:1016` replay, `:1089` sanitized dispatch, `:1135`
  passthrough) serialize this type. The audit found no delivery path that hand-builds a
  `"result"`: `rg '"result"\s*:'` over `src/gateway/{router,server,streaming.rs}` finds only test
  fixtures and audit rows.
- The task snapshot's retained `result` (`src/protocol/tasks.rs:108-109`), which `tasks/get` and
  completed-task admission replay deliver inside the envelope. The attribute applies to every
  serialization of the snapshot, including the task store's (`task_service/store.rs:664`), so
  newly stored records are private as well. Records stored before this change are clamped when
  they are served.

`finalize_response_after_inspection` (`response_security.rs:80`) also calls the clamp before
signing. The signed bytes are therefore already private, and the serializer's clamp is a no-op on
signed paths: the signature stays valid. The firewall's single-inspection behaviour
(`AlreadyInspected`) is unchanged, because replacing a scope with the constant `"private"` needs
no re-scan.

The webhook `message` path is the one raw delivery that serializes neither type
(`webhooks/mod.rs:581-603` keeps the whole payload; `streaming.rs:486-489` writes it as SSE data).
It is closed in this change, because the criterion says "no surface". Before emission, a `message`
payload that is a JSON-RPC response (it has an `id` and a `result` object) gets
`clamp_delivered_scope` on its `result`. Requests and notifications pass unchanged. This resolves
#2471.

**Ordering contract (closing record).** The firewall inspects the canonical backend artifact first.
Then the clamp runs, then signing, then audit, then serialization. The pre-sign clamp is required,
not redundant: the signer authenticates the in-memory result map, not the serialized bytes
(`message_signing_v2.rs:55-95`).

**3. Proof: behaviour on every exit, plus a source check on the two attributes.**
- Functional tests assert exact `"private"` on successful responses. The exits and the tests that
  cover them are listed under "Tests".
- Source check, labelled as one: both result slots carry the `serialize_with` attribute, and
  `"cacheScope"` is written only by `shape_modern_response` and `clamp_delivered_scope`.
- Honest limit: a new wire type that carries a result without going through `JsonRpcResponse` or
  the task snapshot would bypass the clamp. The audit found none; the source check does not prove
  none can appear.

**4. Out of scope, stated.** `protocol_revision_telemetry::CacheScope` (`:115-131`) is a
measurement label for the U1 shadow counter. It never reaches a response, and any value that did
reach one would be clamped by point 2. It is left unchanged, so the telemetry schema stays stable
while the measurement window runs.

## Public API effect

- Narrowing only: `CacheScope::Public` changes from a unit variant to a tuple variant, and
  `CacheScope::for_list` is removed. Both sit in the 4.0.0 major. No new public item. An
  UPGRADING/changelog entry names both.
- Callers in the tree: `tests/mik_7213_acs.rs:93,113,115` (`for_list`, `Public`) and the doc lint
  at `:566`, which quotes the `for_list` signature. They are rewritten to assert the new property.
  No production caller uses `for_list` or `Public`
  (`rg 'CacheScope::|for_list\(' src`, excluding the telemetry type).

## Ledger effect

- MIK-7211.PARENT.6 becomes MET, with two mechanisms named separately:
  - construction: the uninhabited `Public` payload means the gateway cannot build a public scope;
  - delivery: the `serialize_with` clamp on both wire result slots rewrites any delivered
    non-private scope.

  The source check is a drift check, recorded as one.
- MIK-7213.CACHE.2 / CACHE.3a / CACHE.3b cite `for_list` (`cacheable.rs:46`). Their evidence
  cells are re-pointed to the table rows and the new tests. Their status does not change.

## Tests (the red commit)

Each test asserts a successful response and exactly `"private"`. A stub backend answers with
`"cacheScope": "public"` at the top level of its result.

1. **Direct route, all three success exits** (red today):
   - ordinary `tools/call` through the sanitized-dispatch arm (`backend_handlers.rs:1089`);
   - a passthrough backend (`:1135`);
   - an idempotency replay of a stored result (`:1016`).
2. **Direct `resources/read`** (red today). It needs a fixture that can answer `resources/read`
   successfully; the existing one cannot (`tests/mik_7213_acs.rs:350-357`).
3. **A surfaced backend tool on the meta route, over HTTP and over stdio.** Its envelope is
   returned directly (`meta_mcp/mod.rs:2090-2113`), so the key survives. `gateway_invoke` is not
   used: it wraps the result into `content[0].text`, and the case could not go red.
4. **`tasks/get` on a completed task** whose retained result carries `public`. This includes a
   record written before the change, served through the envelope's `result` slot (red today).
5. **The existing five-method wire test, tightened.** All five methods must succeed, each with
   exactly `"private"`. It should be green today, and it stops the loose `!= "public"` form coming
   back.
6. **Source check on the `Public(std::convert::Infallible)` payload.** Red before the change; it
   carries the construction half of the closing record.
7. **Source check that both result slots carry `serialize_with = clamp`,** and that no other
   writer of `"cacheScope"` exists. Red before the change.
8. **Webhook `message` to legacy SSE:** the payload
   `{"jsonrpc":"2.0","id":1,"result":{"cacheScope":"public"}}` arrives as `"private"`. A
   notification payload passes byte-identical.
9. **Signed delivery.** A public top-level result goes through the signing-enabled finalizer. The
   MAC must verify against the serialized delivery, including the request id and nonce, and the
   scope must be `"private"`. Also covered: a blocked response stays result-free and unsigned, and
   `AlreadyInspected` triggers no second inspection.
10. **Fixtures that cannot pre-clean the evidence.**
    - Upstream frames and old-format stored task records are raw bytes. Each test first asserts
      that its fixture contains `"public"`.
    - The idempotency replay test proves the stored input is public and that no backend dispatch
      happens.
11. **Serializer unit cases.**
    - An absent key stays absent. `private` is unchanged. `public`, `null`, a number and an
      unknown string all become `private`.
    - A nested `"cacheScope"` inside tool data, and JSON strings, are preserved exactly.
    - Batch and response-bearing SSE output are covered.
12. **Completed-task retry.** A repeated task-producing `tools/call` with the same idempotency key
    returns the stored envelope (`execution.rs:73-79`) with the retained result `"private"`.

## Resolution of round 3 (both seats ADOPT-WITH-CHANGES)

| Finding (seat, severity) | Resolution |
|---|---|
| The webhook exception contradicts "no surface" (seat 1 HIGH, seat 2 MEDIUM) | Closed in this change (Decision 2) and test 8; #2471 is resolved by it. |
| The pre-sign clamp is unprotected by tests (seats 1 and 2, MEDIUM) | Test 9, plus the ordering contract in the closing record. |
| Fixtures can normalize away the evidence (seat 1, MEDIUM) | Test 10; the storage statement is corrected. |
| Compatibility and transports are not covered (seat 1, MEDIUM) | Test 11. |
| Completed-task replay on create (seat 2, LOW) | Test 12. |

## Resolution of round 2 (seat 1 REDESIGN; the seat 2 output was empty)

| Finding (severity) | Resolution |
|---|---|
| Two direct-route success exits bypass the clamp (HIGH) | The clamp moves from call sites into the serializer of `JsonRpcResponse.result`; test 1 covers all three exits. |
| Retained task results remain public inside the envelope (HIGH) | The same serializer clamp sits on the task snapshot's `result` slot, and applies to records written before the change; test 4. |
| Webhook `message` events carry raw results (MEDIUM) | Filed as #2471, then closed in scope in round 3. |
| The meta/stdio red test could not go red (MEDIUM) | Test 3 uses a surfaced backend tool; test 2 names a fixture that can answer `resources/read`. |
| The closing record overstated structural enforcement (MEDIUM) | Construction and delivery are named separately; the source checks are recorded as drift checks, with their limit stated. |

## Rejected

- **Clippy `disallowed_methods` on `for_list`.** It cannot target an enum variant constructor. It is
  a config-file convention that `#[allow]` defeats, and the operator gate forbids ad hoc allows
  anyway.
- **A proof type with a private constructor.** It needs a new public type, which needs approval,
  and it adds a constructor with no caller today (YAGNI). The `Infallible` payload gives the same
  guarantee until a first invariant method exists.
- **Removing the `Public` variant outright.** The wire value set would then say nothing about
  `public` existing in the spec, and re-adding it later means editing every match. The uninhabited
  variant keeps the spec's two values visible.
