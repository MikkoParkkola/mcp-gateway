<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# MRTR.7 — bridging a modern backend's question to a legacy client

`MIK-7212.MRTR.7` (`docs/requirements/RELEASE-4.0.0-requirements.md:143`), verbatim: *"Given a
modern backend returning `InputRequiredResult` and a legacy client, When the gateway bridges,
Then it MUST issue the equivalent server-initiated request on the client's connection and retry
the backend with the collected responses."*

`ASM.3` (`:288`) expects backends to adopt the revision before clients do, which makes this the
common direction rather than the rare one. `mrtr-wiring` says each bridge direction gets its own
design and the test plan (`RELEASE-4.0.0-test-plan.md:352`) says the same. This is that document.

## The mechanism is not missing. That is the whole finding.

The test plan records the gap as *"issuing them over the client's transport mid-call, which is
its own design"*. It is already built, one module over, and shipping:
`ProxyManager::forward_elicitation_with_response` (`src/gateway/proxy.rs:243`) registers a
pending id, sends a JSON-RPC request down the originating session's SSE stream, and awaits the
matching response under a timeout. `require_destructive_confirmation`
(`src/gateway/destructive_confirmation.rs:188`) is a shipped caller of it.

So MRTR.7 is a wiring problem, not an invention — but the wiring must decide four things the
existing caller never had to: what may be asked, over what, who may be asked, and how many times.

## 1. A closed request type, not a generalised method string

`forward_elicitation_with_response` (`src/gateway/proxy.rs:243`) hard-codes `"method":
"elicitation/create"` and a typed `ElicitationCreateParams`. `Bridge::to_legacy_client`
(`src/protocol/mrtr.rs:241`) emits `OutboundRequest { key, method, params: Value }` — an
arbitrary method with raw params, because a modern backend may ask for sampling or roots and not
only elicitation.

The obvious edit is `forward_request_with_response(session_id, method: &str, params: &Value, …)`.
**Rejected.** It forwards a backend-chosen string to a client on the gateway's authority, and the
gateway is the only party in the exchange that can tell the two apart. A compromised or merely
buggy backend then reaches any method the client implements, including ones the gateway has never
audited. Nothing downstream can re-impose the restriction, because by then the method is just a
string in a JSON-RPC envelope.

Instead the bridge carries a closed type:

```rust
enum ServerRequest {
    Sampling(SamplingCreateMessageParams),
    Elicitation(ElicitationCreateParams),
}
```

A `Roots` variant was drafted and **removed**. `roots/list` returns a roots list, not an answer
filed under the backend's key, so it does not fit `retry_params`'s `(key, answer)` contract at all;
carrying it would have bought a third id prefix and an ingress-gate widening to deliver a value the
retry cannot use. `MRTR.9`'s per-method refusal stays meaningful with two variants — everything
outside the pair is still refused by name.

`to_legacy_client` maps each `inputRequest` onto a variant or refuses. Three properties follow
from the type rather than from a check somewhere:

- **The method string is ours.** Each variant names its own wire method. A backend cannot
  introduce a method the gateway did not compile.
- **The id prefix is ours, and the ingress gate already knows both.** `handlers.rs:633` admits a
  POST-back only when its id starts with `sampling-` or `elicitation-`. With `Roots` gone the enum
  and the prefix set are the same two members, and no ingress edit is needed. What makes that a
  compile-time property rather than an aspiration is a `const fn prefix(&self) -> &'static str` on
  the enum, matched exhaustively, with the ingress gate's set built from it: adding a variant then
  fails to compile until the prefix exists, instead of failing at runtime as a caller timeout.
- **`MRTR.9` stays reachable.** Narrowing the bridge to elicitation alone would make its
  per-`inputRequest`-method refusal unreachable rather than unnecessary; a closed set of two
  keeps the refusal meaningful for everything outside it.

### The helper returns an answer, not an envelope

`resolve_pending` is handed the whole client message (`handlers.rs:637`,
`request.clone()`) and `forward_elicitation_with_response` returns it verbatim
(`proxy.rs:278`, `Ok(Ok(response)) => Ok(response)`). So today a caller receives
`{"jsonrpc":…,"id":…,"result":{…}}` — and a JSON-RPC **error** reply resolves through the same
success arm.

For a confirmation gate that is survivable: the caller inspects the body it wanted and treats
anything else as "no confirmation". For MRTR.7 it is not, because the value goes straight into
`inputResponses` and is sent to a backend as the user's answer.

**And the `result` member is not the answer either.** `ElicitationCreateResult`
(`src/protocol/messages.rs:486-494`) is `{ action, content }` where `action` is `accept`, `decline`
or `cancel` and `content` is present only on `accept`. A refusal is a *successful* JSON-RPC result,
so returning `result` verbatim forwards `{"action":"decline"}` to the backend as what the user
said. That is the §4 failure — a backend acting as though its question were answered — arriving
through a door §4 does not cover, because nothing failed.

So the helper returns `Result<Value, DeliveryError>` and the `Ok` value is the *answer*, projected
per variant, never the envelope and never the whole result:

| reply | projection |
|---|---|
| `Elicitation`, `action = "accept"` | `content`, or `Malformed` if it is absent |
| `Elicitation`, `action = "decline"` or `"cancel"` | `DeliveryError::Declined { action }` |
| `Elicitation`, any other `action` | `DeliveryError::Malformed` |
| `Sampling`, a `SamplingCreateMessageResult` | the result, which *is* the answer for this variant |
| a JSON-RPC `error` member | `DeliveryError::ClientRefused { code, message }` |
| neither `result` nor `error` | `DeliveryError::Malformed` |

**The bridge does not validate `content` against the `requestedSchema` it sent.** It checks that
`content` is present and is a JSON object, and forwards it. The schema belongs to the backend, and
the backend is reachable by paths that never went through this bridge, so it must handle a
non-conforming answer regardless — a second validator here would be a second opinion about the
backend's own contract, diverging the moment either side changes. A mismatched accept is a bad
answer, not a non-answer: `Declined` exists to keep the "user said no" case out of the answer path,
and an accept, however poorly filled in, is the user having answered.

`Declined` is a distinct arm rather than a `ClientRefused` alias because it is the one outcome that
is neither a fault nor an answer: the user was asked and said no. §4's rule applies to it unchanged
— the call fails and the backend is not retried — but the reason reported is the user's, which is
what an operator reading `NFR.OBS.4`'s counter needs to tell a declining human from a broken client.

### Backend params in, typed params out

The other direction needs the same specificity. An `inputRequest`'s params arrive as a
`serde_json::Value` (`src/protocol/mrtr.rs:194-202`) and must become a typed
`ElicitationCreateParams` (`messages.rs:478`) or `SamplingCreateMessageParams` (`:502`) — the mapping is the
document's central mechanism and was previously asserted rather than stated:

| variant | from the `inputRequest` | refusal |
|---|---|---|
| `Elicitation` | `message` (required, string), `requestedSchema` (optional, object) | absent or non-string `message` |
| `Sampling` | the params object deserialized as `SamplingCreateMessageParams` whole | any field `serde` rejects |

A payload that fails its row is refused **before anything is sent to the client**, as a bridge
refusal with the backend's key named, counted through `NFR.OBS.4`. It is never repaired, defaulted
or forwarded half-formed: a backend that asks a malformed question gets an error, not a user prompt
built from guesses.

## 2. The client's connection, not the client's SSE stream

`send_to_session` (`src/gateway/streaming.rs:254`) writes to the SSE multiplexer. Every existing
server-initiated request goes through it (`proxy.rs:211`, `:269`, `:313`, `:343`, `:372`), so a
design written against `send_to_session` inherits "HTTP+SSE only" without ever deciding it.

`MRTR.7` says *the client's connection*. It names no transport, and refusing stdio here would be
a stated limit against a MUST, which is an unmet requirement wearing an explanation.

An earlier draft justified stdio with "the gateway already writes to a child server's stdin
(`src/transport/stdio.rs:856`)". **That evidence was wrong twice** and is withdrawn: line 856 is
inside the `#[cfg(test)]` module beginning at `:577`, so it is a fixture; and the production
version of it (`stdio.rs:462-468`) writes to a *child backend's* stdin, which is the opposite
direction from the one at issue. The client-facing stdio path is the gateway's own stdout, driven
by the serve loop in `src/gateway/server/mod.rs`.

Reading that loop is what the transport question actually turned on, and it does not say yes:

```rust
while let Ok(Some(line)) = reader.next_line().await {   // server/mod.rs:1564
```

One task, one line at a time, each dispatched to completion before the next is read. A bridge that
blocks inside that dispatch awaiting the client's reply blocks *the only reader that could deliver
it* — a guaranteed deadlock until the timeout, then a failed call, on every stdio client. The
send half was never the obstacle; the receive half is, and it is absent.

So stdio support is a stated part of this increment with three named changes, not an inherited
property:

- **dispatch concurrently.** The serve loop spawns each request rather than awaiting it inline, so
  the reader stays free while a bridged prompt is outstanding.
- **route replies before parsing them as requests.** An incoming line whose `id` carries a bridge
  prefix (§1) is handed to `resolve_pending` and never reaches request parsing — the stdio analogue
  of the SSE ingress branch at `handlers.rs:633`, which exists because the same problem was already
  solved once on the other transport.
- **serialize the writer.** The loop owns the sink outright — `let mut stdout = stdout;`
  (`server/mod.rs:1557`) and `write_response(stdout: &mut tokio::io::Stdout, …)` (`:1631`). A
  `Stdout` handle is not `Clone`, so spawned tasks cannot each take one, and two interleaved
  `write_all` calls splice two JSON-RPC lines into one that every client's parser rejects. The
  writer becomes a single owned sink behind a mutex, or an outbound channel drained by one task —
  either is fine, and picking neither is not. This is the same edit as the first bullet, not a
  follow-up to it: making dispatch concurrent without making the framing safe is the defect.

With those, the bridge takes a `ClientChannel` — send a request, await the correlated reply, or
fail — with an SSE implementation that is today's `send_to_session` path and a stdio implementation
over the serve loop's stdout and the routing branch above. The pending-id map and its session
ownership check (`proxy.rs:466-533`) are transport-independent already and are reused unchanged.

One ordering guarantee the single-threaded loop provides today is known and must survive, so it is
stated as a check rather than left as a caveat: **`initialize` completes before any other request
is dispatched.** A session whose capability store (§6) is written by `initialize` and read by a
bridged prompt has a race the sequential loop made impossible; the boundary test drives an
`initialize` immediately followed by a call and asserts the store is populated when the second is
served. Owner is this increment — the change that introduces the concurrency owns the guarantee it
removes.

If concurrent dispatch proves to have consequences *beyond* that one — further ordering the loop
was silently providing — that is a finding about the serve loop and is resolved there, before
MRTR.7 claims stdio. It is not resolved by narrowing the requirement.

## 3. The session id at the call site names a backend, not a client

`src/gateway/router/backend_handlers.rs:98` (and `:926`, `:973`) builds
`format!("direct:{backend_name}")` and passes it as `session_id` to the firewall. That string is a
firewall correlation key. Handing it to `send_to_session` finds nothing and returns
`SamplingError::NoSession` — a bridge that silently never asks anybody.

The client's real session id must reach the bridge site. `MetaMcpCallerContext` already carries
shape-derived facts the ~500 lines from `handlers.rs:597` to the construction site (DE-4 in
`docs/design/2026-08-30-mrtr-wiring.md:418`), which is the established carrier, and the same
context is where `input_capabilities` lives (`src/gateway/meta_mcp/mod.rs:139`). Threading it
there is the same edit twice, not two.

## 4. The neighbour's error handling is exactly wrong here, and copying it is the likely bug

`require_destructive_confirmation` maps `NoSession`, `Timeout` and every other delivery failure to
`ConfirmationOutcome::Unsupported` and **proceeds**. That is correct for a confirmation gate: the
MCP guidance is that a server must not break because a client omitted an optional capability.

It is catastrophic here. Proceeding means retrying the backend with no answers, and `retry_params`
(`src/protocol/mrtr.rs:264`) faithfully renders "no answers" as an omitted `inputResponses` — which
tells the backend its questions were never posed. The backend then either asks again or answers
without the input it required. MRTR.7 must fail the call on every one of those errors and report
the reason, never fall through. Recorded because the copy-paste is one line away and reads correct.

## 5. Three bounds, because one of them is not a bound

A backend may return `input_required` again after being retried. Unbounded, a backend drives a
client into unlimited prompts on the gateway's authority — a legacy client cannot tell the
difference between the gateway asking and the backend asking, which is the point of the bridge and
also the abuse.

Capping *rounds* alone does not cap prompts: one `InputRequiredResult` may carry an arbitrary
number of `inputRequest` entries, so a single round reaches the same abuse with a larger array.
Three limits, each on the original call rather than on a round:

| bound | value | enforced |
|---|---|---|
| retry rounds | 3 | before re-invoking the backend |
| prompts in total | 8 | before sending any prompt of a batch that would exceed it |
| aggregate wall time | 120s | checked before each send, and as a deadline on the whole call |
| per-prompt wait | `min(remaining, 30s)` | on each send; a send with no remaining budget is not attempted |
| dispatch within a batch | sequential | one prompt in flight at a time, budget re-checked between |

Five rows, not three: the last two were prose beneath this table and are what an implementer
transcribes into constants alongside the first three. The paragraphs below say *why* each value is
what it is; the table is the contract.

The values are stated here rather than deferred to a named constant so that the boundary tests and
the implementation converge on one contract; they are named constants in code, and changing one is
a change to this document. The batch check runs *before the first send* deliberately: refusing
after prompt 8 of 20 has already asked the user eight questions the gateway then discards.

Refusals and deadlines count separately, on the two counters `NFR.OBS.4` already separates
(`docs/design/2026-09-01-continuation-telemetry.md`): a bound refused before or during a round
increments `rejected_total{phase="bridge"}`, a per-prompt or aggregate deadline passing increments
`expired_total{phase="bridge", detected="awaited"}`. Routing a deadline to the refusal counter
would put a timeout on the same series as a user declining, which is the distinction `phase` was
added to preserve.

### What the table above does not say, and must

**A per-prompt timeout, and it is not the obvious constant.** `ELICITATION_TIMEOUT`
(`src/gateway/destructive_confirmation.rs:53`) is 120s — the same number as the aggregate. Reusing
it makes the aggregate a no-op: one unanswered prompt consumes the entire budget, so the bound that
exists to cap a *sequence* never binds until the sequence is already over. Each send waits
`min(remaining_budget, 30s)` instead, and a send with no remaining budget is not attempted.

**Prompts in a batch go out sequentially.** Firing eight simultaneous prompts at a legacy client is
a different product than asking eight questions, and the aggregate deadline cannot be reasoned
about when the waits overlap. Sequential also lets the budget check run between prompts, which is
where a batch that overruns should stop.

**Prompt order is alphabetical, and that is now a stated property rather than an accident.**
`InputRequired::requests` is collected from a `serde_json::Map` (`src/protocol/mrtr.rs:194-202`)
and `serde_json` is not built with `preserve_order` (`Cargo.toml`), so the backend's authoring
order is already lost before the bridge sees it. The bridge does not pretend otherwise: order is
unspecified, the key is the only correlation between question and answer, and a backend that needs
a particular order must ask across rounds. Recorded because it is invisible in tests and visible
to every human who fills in the form.

**The aggregate is bounded by the originating request, not only by itself.** The 120s runs inside
the inbound HTTP POST the backend call is serving; a proxy or client timeout below it kills that
request while the bridge is still collecting, and the answers then arrive for a session with
nobody waiting. So the deadline is `min(120s, time remaining on the originating request)` where
that is knowable, and a bridge whose channel reports the client session gone stops immediately
rather than finishing a collection nobody will receive.

## 6. Nothing records what a legacy client said it could do

The gate on "may this client be asked" has to be the client's own `initialize` capabilities —
`elicitation` and `sampling`. `rg 'client_capabilities|ClientCapabilities' src/` returns
`src/protocol/messages.rs` and `src/protocol/types.rs` only: the types are parsed and dropped.
There is no per-session store, so a design saying "inherit the per-request capability slice" would
inherit an empty one and refuse every legacy client — a bridge that reads as correct and never
asks anybody.

So the increment builds the store: on `initialize`, the declared capability object is retained
against the session id; the bridge looks the session up and refuses a variant the client did not
declare. A real addition, not a lookup — recorded because the requirement presupposes it and
nothing in the tree provides it.

### Which source wins when the two disagree

The store is not the only capability fact in the tree. `MetaMcpCallerContext.input_capabilities`
(`meta_mcp/mod.rs:139`) already carries a per-request slice, derived from the caller's `_meta` on
the call being served, and when `MRTR.9`'s per-method gate lands it reads that slice. The gate is
not shipped: every occurrence of the field in `src/` is an assignment, and the only non-empty one
is `handlers.rs:1284`. Stating the precedence now is still worth a paragraph, because two sources
with no stated precedence is an implementer's coin toss the moment the second one gains a reader:

**The session store is authoritative for the bridge, and the per-request slice may only narrow it.**

A capability is a statement about what the client's *connection* can do, which is settled at
`initialize` and cannot be enlarged by a claim inside one request — a per-request slice that
widened the store would let any caller assert its way into being prompted. Narrowing is honoured
because it is a caller saying "not on this call", which costs nothing and can only refuse. Absent
slice = no narrowing, not an empty set: an empty `input_capabilities` (`server/mod.rs:1737` passes
`&[]`) means the request said nothing, not that the client can do nothing. That distinction is the
whole reason this paragraph exists — reading `&[]` as a denial refuses every client, silently, on
the path that looks correct.

**So the field becomes `Option<&[String]>` when its first reader lands.** The paragraph above exists
only because `&[]` has to carry two meanings — "said nothing" and, one careless refactor later,
"can do nothing". `None` versus `Some(&[])` says both without prose, makes "narrow to nothing on
this call" expressible rather than unreachable, and retires the trap instead of documenting it.
Named here because the change belongs with `MRTR.9`'s gate, which is the first code that reads the
field; the bridge reads the store and is unaffected either way.

**This supersedes `mrtr-wiring` DE-4 for the stdio path.** DE-4 refused stdio on the grounds that a
stdio client's `initialize` capabilities were not readable anywhere. The session store is where they
become readable, and §2 puts the transport in scope, so the premise DE-4 rested on no longer holds.
Recorded by name because both documents are in the tree and a reader who finds DE-4 first would
otherwise have no way to tell which one won.

## Refusals, before any of the above runs

Two, both explicit failures rather than silent completion: the client declared no capability for
the variant being asked (§6), or the call has no client session to reach at all. In each case the
call fails with its reason and the backend's interim result is dropped rather than answered
emptily. Transport is *not* a refusal reason (§2).

## Trust boundary and threats

Recorded here because DoR `C15` and `C6` ask for it, and because **the accepted sibling designs in
this family carry neither** — `2026-08-30-mrtr-wiring.md` and `2026-08-30-shared-continuation-state.md`
were reviewed and accepted without a trust-boundary line or a STRIDE pass. That is a family-wide gap
this document does not introduce and cannot close alone; it is named so the next revision of those
two has a shape to copy.

**C15.** Client side: `auth-user` over HTTP/SSE, `unauth` for a local stdio caller — the process on
the other end of a pipe presents no credential, so a stdio client is trusted exactly as far as the
user who launched the binary. Backend side: `mesh-peer`. Data locality: `local` — a prompt and its
answer live in one process for the duration of one round and are not persisted. Partition
behaviour: `CP`. A round that cannot be completed fails with its reason (§"Refusals") rather than
proceeding on an assumed answer, which is the same fail-explicitly arm `MRTR.6` takes.

**C6.** The new surface is one thing: *the gateway asks a human a question on a backend's behalf*.

| | threat here | mitigation |
|---|---|---|
| **S** | a reply forged for a pending request the attacker did not receive | the pending key is gateway-minted and resolved only on the connection it was issued to (§1, §2); a reply on another connection matches nothing |
| **T** | prompt text is backend-controlled and reaches a human | the gateway never interprets it — it is data in transit; the client renders it under its own display rules, as it already does for `elicitation` |
| **R** | a user denies having answered | `NFR.OBS.4` counts each round with `phase="bridge"` (`2026-09-01-continuation-telemetry.md`); answer *bodies* are deliberately not logged |
| **I** | a hostile backend phrases a prompt to extract a secret from the user | not fully mitigable by the gateway — a prompt is text. Bounded by §6 (a backend can only ask what the client declared it accepts) and §5 (a bounded number of asks). Stated as residual, not solved |
| **D** | a backend drives unbounded rounds, or one blocked round stalls the client's reader | §5's three bounds cap rounds, prompts and aggregate deadline; §2's concurrent dispatch means a bridge waiting on a human does not hold the single reader |
| **E** | a backend asks for a variant the client never offered | §6's capability store is the ceiling and the per-request slice may only narrow it, never widen |

The **I** row is the one with a real residual. It is the price of the feature: a mechanism whose
purpose is to relay a backend's question to a person cannot also guarantee the question is benign.

## Unknowns

| unknown | state |
|---|---|
| Does the bridge site have the client's session id? | **Resolved.** Read `backend_handlers.rs:98`: it has `direct:{backend_name}`, a firewall key, not a session. Changed the design: §3 exists because of it. |
| Can `MetaMcpCallerContext` carry the session id to the site? | **Deferred.** Owner: the MRTR.7 implementation increment. Resolved by reading the construction sites at `handlers.rs:597` and `server/mod.rs:1733`. When: first line of the implementation. If it resolves badly: the id is threaded as a separate parameter, which is uglier and equally correct — so nothing downstream is blocked on the answer. |
| Is the per-request capability slice sufficient to gate this? | **Resolved: no.** The question was first written against `may_request_input`, which appears nowhere in `src/` — it was read from a sibling document rather than from the tree. What shipped is `input_capabilities: &'a [String]` (`meta_mcp/mod.rs:139`), a per-request slice with no session store behind it. Changed the design: §6 builds the store and states that the slice may only narrow it. |
| Does the response ingress admit a reply for a third request kind? | **Resolved: no, and the question is now moot.** `handlers.rs:633` gates on `sampling-` and `elicitation-`. Rather than widen it, §1 dropped the `Roots` variant that needed the widening — it never fitted `retry_params`'s `(key, answer)` contract. Enum and prefix set are now the same two members, tied by an exhaustive `const fn prefix()`. |
| Does the helper hand back the client's answer? | **Resolved: no.** `handlers.rs:637` passes the whole message to `resolve_pending` and `proxy.rs:278` returns it verbatim, so a JSON-RPC `error` reply resolves through the success arm. Changed the design: §1 returns the `result` member or a typed `DeliveryError`. |
| Can a stdio client be asked at all? | **Resolved: not as the tree stands — the increment must change the serve loop.** The first answer here was "yes, the gateway already writes to a child's stdin (`transport/stdio.rs:856`)", which was wrong twice: that line is inside `#[cfg(test)]` (from `:577`), and its production form (`:462-468`) writes to a *backend*, not to a client. Reading the actual client path, `server/mod.rs:1564` is a single sequential reader, so a bridge blocking inside dispatch deadlocks the only task that could deliver the reply. Changed the design: §2 now specifies concurrent dispatch and a reply-routing branch as part of this increment, instead of inheriting a capability the tree does not have. |

## Out of scope

The legacy-backend/modern-client direction (`MRTR.6`'s forwarding half), which has its own
deferred question in `docs/design/2026-08-30-shared-continuation-state.md`. Nothing here changes
what a modern client is sent.
