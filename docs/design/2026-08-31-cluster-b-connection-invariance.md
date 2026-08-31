<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
# Cluster B — connection invariance and request-scoped notifications

Design only. No production code, no test, no `Cargo.toml` edit. A later
increment implements what this decides.

Two criteria, both release-blocking, both `ABSENT` in
`docs/requirements/RELEASE-4.0.0-criteria-status.md`:

| criterion | line | clause |
|---|---|---|
| `MIK-7272.ORDER.2` | 140 | tool set MUST NOT vary per connection nor as a side effect of other requests on the connection; MAY vary by authorization |
| `MIK-7272.SUB.2` (second clause) | 152 | request-scoped notifications MUST flow on the response stream of their own request |

## 0. They were grouped on a hypothesis. The hypothesis is half right.

The cluster was formed on "both are session scope used where request scope
belongs". That reading holds for ORDER.2 and does not hold for SUB.2's blocking
clause.

- **ORDER.2 is genuinely session-scope-where-request-scope-belongs.** A store
  keyed by session id decides a server-visible property. The fix is to stop
  reading that key on this path.
- **SUB.2's blocking clause is an ABSENCE.** Nothing in production emits
  `notifications/progress` or `notifications/message`, nothing forwards a
  backend's, and no per-request response stream exists for any method except
  `subscriptions/listen`. There is no misused session scope to correct, because
  there is no delivery at all. The fix builds a mechanism that does not exist.

They do not share a root and they will not share a fix. This note therefore
carries two independent sections and no shared frame. The one place the themes
touch is recorded as a finding in Part III, not as a bridge: `RequestFields::log_level`
(`src/protocol/meta.rs:79`) is parsed per request at `meta.rs:196` and never
read, while a session-global `MetaMcp::log_level` (`meta_mcp/mod.rs:192`,
written by `logging/setLevel` at `meta_mcp/protocol.rs:279`) governs instead.
That is a constraint on how SUB.2 emits, not evidence of a common cause. Leaning
on it to unify the two would be a false unification, and it is named here so a
later reader does not attempt one.

---

# Part I — ORDER.2

## I.1 Problem

The set of tools returned by `tools/list` varies by connection. The variation is
uncredentialed and it is also a side effect of an ordinary request, which is the
second half of the same criterion.

Two inputs produce it, both keyed on session id:

1. **Routing profile.** `resolve_surfaced_tool` gates every surfaced tool
   through `active_profile(session_id)` (`src/gateway/meta_mcp/surfaced.rs:106-108`).
   The profile is selected at `initialize` from a request body field or the
   `X-MCP-Profile` header, with no credential, and can be changed mid-connection
   by calling `gateway_set_profile`.
2. **Session-promoted tools** (`spec-preview` feature). `handle_tools_list_for_session`
   appends `promoted_tools_for_session(session_id)` (`meta_mcp/mod.rs:1156`).

Calling `gateway_set_profile` and then `tools/list` on the same connection
returns a different set than `tools/list` alone. That is the "side effect of
other requests on the connection" clause, violated by a shipped meta-tool whose
entire purpose is to cause it.

## I.2 Every input to the listed tool set, classified

`ORDER.3` (line 141, `MET (I)`) already records a classification, in
`RFC-0061-protocol-2026-07-28-release-scope.md:60-79`, naming the routing profile
and the `spec-preview` promotion list as the two connection-derived filters. That
classification is correct as far as it goes and this design adopts it. It is not
complete: it enumerates two inputs where the code path has six. The table below
is the full enumeration, read off the call chain
`handlers.rs:920 -> handle_tools_list_with_url_override -> handle_tools_list_with_params -> handle_tools_list_for_session`.

| input | site | derived from | verdict |
|---|---|---|---|
| `code_mode_enabled` | `mod.rs:1117` | static config | server-global — legal |
| `url_override` (`?codemode=`) | `handlers.rs:924`, `mod.rs:1210` | this request's URL | request input — legal |
| `params.query` (`spec-preview`) | `mod.rs:1186` | this request's params | request input — legal |
| backend/tool counts, stats, webhook registry, reload context | `mod.rs:1120-1128` | server state | server-global — legal |
| `meta_route_isolation_refused` | `surfaced.rs:118` | backend OAuth mode + multi-user config | server-global — legal |
| backend tool-cache readiness | `surfaced.rs:130-137` | async backend discovery | server-global — legal, time-varying |
| **routing profile** | `surfaced.rs:106-108` | **session id** | **connection-derived — illegal** |
| **session-promoted tools** | `mod.rs:1156` (`spec-preview`) | **session id** | **connection-derived — illegal** |

Two of eight are illegal. `ORDER.3` names exactly those two, so its `MET` status
survives this design — but its evidence cell should gain the other six, because
an enumeration that lists only the failures cannot be checked for completeness.
Recorded in Part III.

The last row was added in review and is worth its own sentence, because it is the
one input that is legal and still varies. A surfaced tool is omitted from the list
when its backend cache has no entry yet (`surfaced.rs:130-137` returns `None` and
logs *"Surfaced tool not in backend cache — omitting from tools/list"*), so two
callers asking at different times get different lists. That is **not** an ORDER.2
violation: the criterion is that the list does not depend on *which connection*
asks, and this depends on *when*, identically for every connection. It is
therefore classified, not designed for. The reviewer's proposed remedy — atomic
server-global publication with a `tools/list_changed` broadcast after every
published change — is a real improvement and is **out of scope here** (Part VI):
it depends on the same never-fired announce path as Part III item 1, which is held
pending §4.1. Both collapse or land together; neither should be designed twice.

## I.3 Measured constraints

Four facts bound the option space. Each was checked, not assumed.

**A profile can only narrow.** `RoutingProfile::check` is an allow/deny filter
over the already-surfaced set (`src/routing_profile/mod.rs:21-24`); no profile
grants access to a tool the gateway would otherwise withhold. So no client can
escalate by choosing a profile, and this is a **conformance** problem, not a
security one. That kills the framing that would have justified the most invasive
fix, and it is why "leave it, it is not exploitable" is a coherent position the
options below have to argue against on conformance grounds alone.

**There is a recorded prior decision to keep profile selection uncredentialed.**
`src/gateway/router/authorization.rs:41-70` records a deliberate call not to gate
profile selection at `initialize`. Any option that removes or credentials the
profile contradicts a decision this repository already made on purpose. That does
not make it wrong — it makes it a decision the operator has to re-take, which is
why it appears in Part IV rather than being settled here.

**The era is available one argument away.** `is_modern` is computed at
`handlers.rs:683`; the `tools/list` dispatch is at `handlers.rs:920` in the same
function. Passing it costs one parameter. The `GET /mcp` era gate closed for
`SUB.1`/`SUB.3` on 2026-08-31 is the in-repo precedent for branching on era at a
dispatch site, so an era-gated fix is a pattern this codebase already uses rather
than a new one.

**`tools/list` is not narrowed by authorization at all.** `handle_tools_list_for_session`
takes `(id, params, session_id)` and no caller context; the admin gate lives at
dispatch instead (`handle_tools_call`, `mod.rs:1256`). Admin meta-tools are
therefore listed to every caller and refused when called. That is spec-legal — the
criterion says the set *MAY* vary by authorization, not that it must — but it is
the fact that prices option (c): making the surface authorization-derived means
first plumbing a caller context into a list path that has never had one.

## I.4 Options

**(a) Ignore the session profile when `is_modern`.** Thread `is_modern` into
`handle_tools_list_*` and skip both illegal inputs on the modern path; legacy
clients keep today's behaviour unchanged. The skip has to reach **four** sites,
not two — the `spec-preview` path is a second entry to both illegal inputs and was
missing from this note before review: `surfaced.rs:106-108` and `mod.rs:1156` on
the plain path, plus `spec_preview.rs:46` (`active_profile`) and `:111`
(`promoted_tools_for_session`), the latter merged into the returned results. A
skip that misses either `spec_preview` site leaves the criterion open on a live
path.
*For:* smallest diff that closes the criterion; no mechanism removed, so the
prior decision in `authorization.rs` stays true for the clients it was made
about; matches the `GET /mcp` era-gate precedent.
*Against:* the gateway then behaves two ways, and `gateway_set_profile` becomes a
tool that silently does nothing to a modern client's list while still changing
dispatch — a split between what is listed and what is callable. That split needs
its own answer (refuse the meta-tool in modern mode, most likely), or it is a new
inconsistency traded for the old one.
*And `gateway_set_profile` is not the only writer.* `handle_initialize` binds a
profile from the `X-MCP-Profile` header with no credential check
(`src/gateway/meta_mcp/mod.rs:1060-1068`, read at `invoke.rs:710`), so a modern
`initialize` can bind a profile that dispatch honours while a profile-blind list
ignores it. Skipping `active_profile` on the list path alone therefore does not
close listed-versus-callable; it moves the writer. Option (a) is only complete if
the modern path is profile-blind on **both** sides: the list ignores the session
profile *and* modern dispatch does not read it. Which means (a)'s real content is
"modern connections use the default profile, everywhere" — and it must then be
true that the default profile denies nothing the list advertises, or the split
reappears with the deny arriving at dispatch instead.

**(b) Remove per-session routing profiles entirely, for every era.**
*For:* eliminates the finding rather than patching it — after this, the finding
cannot be restated, which is the repair-protocol test. One code path, no era
split, no listed-vs-callable divergence.
*Against:* deletes a shipped feature, and directly reverses the recorded decision
at `authorization.rs:41-70`. Per the repair protocol, removing a *requirement*
needs the requester's recorded agreement first — so this option cannot be chosen
inside this design. §4.1 asks for that agreement.

**(c) Re-key the profile on the authenticated principal.** Variation becomes
authorization-derived, which the criterion explicitly permits.
*For:* keeps the capability while making it conformant; aligns with the
cross-cluster observation that session identity is the wrong key in several
places.
*Against:* the most expensive option by a wide margin — it needs a caller context
in a list path that has none (§I.3), plus a principal-to-profile mapping that
does not exist and would be new configuration surface. It also changes who may
choose a profile, which is a product decision, not an engineering one.

**(d) Keep profiles, announce `notifications/tools/list_changed` on change.**
**Rejected.** Announcing a forbidden variation does not make it conformant: the
criterion forbids the variation, not the silence about it. Recorded because the
option is attractive and because looking at it surfaced a real defect — the
gateway advertises `tools.list_changed: true` (`meta_mcp_helpers.rs:152`) and the
only announce path (`router/mod.rs:161`) is never fired by a profile change, so
today's clients already see a stale list after `gateway_set_profile`. That is a
separate bug, recorded as Part III item 1, where its disposal waits on §4.1.

## I.5 Recommendation

**(a) now, with (b) as the intended end state**, contingent on the operator
answering §4.1. (a) is the only option available without a product decision, it
closes the blocking criterion, and it does not foreclose (b). If the operator
answers that per-session profiles need not be preserved, go straight to (b) and
skip the era split entirely — (b) is strictly better engineering and the only
reason it is not the recommendation is that this design lacks the authority to
delete a shipped capability.

Whichever is chosen, **every writer of the session profile** must be closed on the
modern path, not just the meta-tool: `gateway_set_profile` refused under (a) or
removed under (b), *and* `initialize`'s `X-MCP-Profile` binding refused under (a)
or removed under (b), *and* modern dispatch made not to read the session profile
at all. Leaving any path that changes dispatch but not the list is the
inconsistency this criterion exists to prevent, in a new place. This was found in
review: the original recommendation named one writer and there are two.

---

# Part II — SUB.2, second clause

## II.1 Problem

The criterion requires request-scoped notifications to flow on the response
stream of the request that caused them. Three separate things are missing, and
each would block the criterion on its own.

1. **No emitter.** `git grep -n "notifications/progress\|notifications/message" -- src`
   finds the two method names only in `subscription_registry.rs`'s exclusion
   list and a stdio test. No production code constructs either notification.
2. **No forwarder.** When a backend emits progress or a log message during a
   `tools/call`, the gateway drops it. There is no path from a backend
   notification to the caller of the request that provoked it.
3. **No per-request response stream.** Every delivery primitive in
   `src/gateway/streaming.rs` is session-keyed or global: `broadcast` (:271),
   `subscribe_backend` (:292), `auto_subscribe` (:318), `first_session_id` (:335),
   `create_sse_response` (:344), `subscription_stream` (:418). Only
   `subscriptions/listen` returns a stream, and it returns the *session's*
   stream, not the request's.

The first clause of SUB.2 — that these notifications must **not** appear on the
subscription stream — is `MET` (line 151) and is out of scope here. Note the
shape: the gateway correctly refuses to deliver them on the wrong channel, and
has no right channel to deliver them on. Passing the negative half of a
requirement by having built nothing is not the same as meeting it.

## II.2 Measured constraints

**The POST path never negotiates `text/event-stream`.** The `Accept` check at
`src/gateway/router/handlers.rs:276-287` belongs to the `GET /mcp` handler — its
own error text says *"Use POST to send JSON-RPC requests to /mcp"*. The POST
handler inspects `Accept` nowhere. So the gateway cannot today switch a
`tools/call` response to a stream, and cannot tell whether a client would accept
one. Content negotiation on POST is a prerequisite for every option below, and it
is not optional: the specification requires the server to return JSON when the
client did not offer to accept a stream.

**The subscription registry is admission-capped by a semaphore.**
`SubscriptionRegistry::subscribe` takes an owned permit or returns `None`
(`src/gateway/subscription_registry.rs:124`), and the ceiling exists against
callers who open streams and abandon them. Reusing that registry per request
would change what the cap means — it would start counting in-flight tool calls
rather than long-lived listeners, and a busy gateway would begin refusing
subscriptions because it was busy. Any per-request stream needs its own
accounting, not this one's.

**The backend's notifications are destroyed in the transport, below anything the
router can key.** This was the design's worst error before review, and correcting
it moves SUB.2's capture site down a layer — a design decision this note did not
originally make, named here as one (§P3).

The transports do not lose notifications by accident; they drop them by
construction, before any router-level channel could see them:

| transport | what happens | site |
|---|---|---|
| HTTP | on `text/event-stream`, the loop returns the **first** `data:` line parsed as the response and discards every other line | `src/transport/http/mod.rs:929-944` |
| stdio | a message with no `id` is logged and dropped | `src/transport/stdio.rs:416-431` |

WebSocket is **not** a third site, though it deserializes `JsonRpcResponse` too.
`classify_frame` tests `has_id && has_method` first and routes such a frame to
`McpFrame::Request` (`src/transport/websocket.rs:128-130`); the response branch
is reached only when `has_id && has_result_or_error` (`:131-132`). Two
independent guards, so a stricter response type cannot change its behaviour and
it needs no test of its own. Verified at source 2026-08-31 while implementing
the fix — the earlier recon that named three sites was wrong.

and the interface above them returns exactly one value — `dispatch_to_backend`
does `backend.request("tools/call", params).await?`
(`src/gateway/meta_mcp/invoke.rs:1955-1961`), so there is no second thing for a
request key to carry. A request-keyed sink installed at the router would be a
**dead pipe**: correctly addressed, never written to.

Worse than lossy. On HTTP the first-`data:`-line rule is a correctness bug in its
own right, independent of SUB.2: a backend that emits a `notifications/progress`
before its result returns *the notification* as the `tools/call` response. Today
that costs nothing only because no backend we drive emits one — which is exactly
what §0's absence evidence found, and is a property of our backends, not of our
code.

*Disposal (chosen, not overlooked):* this bug is **fixed inside this change**,
not filed. It is a correctness defect in shipping code rather than a design gap,
and the SUB.2 work moves the capture site into these same transports regardless —
so the repair lands in the edit that already has to touch these lines. Filing it
would buy a separate ticket and a human's attention and change nothing about when
or where the fix happens. Recorded here so a later reader can see the disposal
was made deliberately (team-lead, this round).

So SUB.2's real prerequisite is **not** "a request key at the dispatch boundary".
It is: each backend transport must read its stream to completion, separate
notifications from the response, and hand the notifications to a per-invocation
sink whose lifetime is the upstream response. The key is necessary; it is not
sufficient, and stating only the key is what made this design look cheaper than
it is. The plumbing is still shared with the MRTR retry work — see §II.5, restated
after review to say what is genuinely shared and what is not.

## II.3 Options

**(a) Response-stream mechanism only.** Add `Accept` negotiation on POST and let
a `tools/call` return `text/event-stream`, reusing the framing of
`subscription_stream` with its own admission accounting. Emit nothing new; the
stream carries the single response and closes.
*For:* smallest step that makes the criterion reachable; unblocks a client that
asks for a stream; no request-keyed routing needed yet.
*Against:* on its own it does not meet the criterion — a stream that never
carries a notification satisfies the letter of "may stream" and none of the
requirement. It is a prerequisite, not an answer.

**(b) Mechanism plus backend forwarding.** (a), plus transports that read a
backend's stream to completion and a per-invocation sink, so a backend's
`notifications/progress` and `notifications/message` are relayed to the caller of
the provoking request, filtered by that request's `log_level`.
*For:* meets the criterion for the case that actually arises — the gateway is a
proxy, and the notifications a client wants are the backend's.
*Against:* needs the shared identity **and** the transport work described in §II.2
— every backend transport reading its stream to completion instead of discarding
non-response messages — and the per-request `log_level` currently parsed and
dropped (Part III) has to start being honoured. The transport half is the larger
of the two and was under-priced in this note before review.

**(c) Mechanism plus gateway-originated progress.** (a), plus the gateway
emitting its own progress for long meta-tool operations.
*For:* the gateway does have slow operations worth reporting on.
*Against:* largest, and it invents a policy — which operations report progress,
at what granularity — that nobody has asked for. Speculative; not recommended.

## II.4 Recommendation

**(b), sequenced as (a) then the forwarder**, with the shared plumbing built
jointly with the MRTR retry-forwarding work rather than twice.

Stated without softening, because review found this design implying otherwise:
**option (a) does not satisfy `SUB.2`.** The criterion's second clause requires
request-scoped notifications to reach the caller that provoked them; (a) forwards
none, so shipping (a) leaves a release-blocking criterion ABSENT and the release
nonconformant against its own requirements file. (a) is a *sequencing step toward*
(b), not an alternative to it.

That does not make it this design's call to shrink the release. Amending `SUB.2`
is the operator's decision and it is put to them as one in §4.3 — the question is
"must v4.0.0 emit, or is the criterion being amended", not "may we ship less".
Until it is answered, SUB.2 carries a **deferred open question that blocks
implementation**: the design cannot specify what is emitted until someone says
whether anything must be.

| field | value |
|---|---|
| owner | operator, via §4.3 |
| what would resolve it | the answer to "must v4.0.0 emit, or only be able to stream" |
| when | before any SUB.2 implementation increment starts |
| what if it resolves badly | if v4.0.0 must emit, SUB.2 grows the §II.2 transport rewrite as well as the shared identity, stops being a small change, and the release scope — not the design — absorbs it |

## II.5 Shared prerequisite — one identity threaded to the transport, two payloads

This is not a cluster-B item. It is one seam with two consumers in two clusters,
in the same tree, being approached by two sessions, and the duplication is
already paid for once this release. Stated here so it is built once.

**Corrected after review.** This section previously claimed the two clusters need
"one request key". They do not. What they share is the **identity and the seam**;
what each hangs off it is different, with a different lifetime. The corrected
claim is narrower and survives inspection:

| | |
|---|---|
| genuinely shared | a per-invocation identity threaded through `dispatch_to_backend` (`src/gateway/router/handlers.rs:930-955` has no request state to key on today), so that anything a backend produces can be attributed to the call that provoked it |
| consumer 1 — cluster A | hangs `RetryFields` off it; lifetime spans the **retry decision**, and it is consumed at the router, above the transport |
| consumer 2 — this note | hangs a notification **sink** off it; lifetime ends when the upstream response is written, and it must be consumed **inside the transport**, at the sites in §II.2 that discard notifications today |
| **not** shared | the payload, the lifetime, and the layer at which each is read. A single object serving both is a worse design than two, threaded on one identity |
| build order | whichever consumer starts first threads the identity; the second hangs its own payload on it and does not re-thread |

Why it still belongs in this note: the *threading* is the expensive part and it is
one edit, in the same function, on the same release. Two sessions each inventing
their own identity is the duplication worth preventing; forcing one shared payload
is not.

Decided here, because SUB.2 cannot be specified without it: the sink is registered
**before** dispatch and removed **before** the final response is written, so a
notification arriving after completion has nowhere to go and is dropped and
counted rather than delivered to whatever occupies the slot next. That closes the
duplicate-JSON-RPC-id and late-arrival cases a reviewer raised — the sink is keyed
by our per-invocation identity, never by the backend's `id`, which is the
backend's to reuse.

Still **not** decided here: the identity's representation and where it is stored.
Those belong to whichever increment threads it, with both consumers' requirements
in hand. Cluster A is owned by another session; coordination sits with the team
lead, not with this note.

---

# Part III — findings that fall out of this design

These are not the criteria. They were found while establishing the constraints
above, and each is disposed of explicitly rather than dropped.

1. **`tools/list_changed` is advertised and never fired for the change that
   matters.** The gateway advertises `tools.list_changed: true`
   (`src/gateway/meta_mcp_helpers.rs:152`); the only announce path
   (`src/gateway/router/mod.rs:161`) has UI callers only and is not fired by
   `gateway_set_profile`. A client that changes profile today is left holding a
   stale list with no notification. *Disposal: pending §4.1, and expected to
   collapse rather than be filed.* If profiles are removed there is no
   per-session profile change left to announce and the defect stops existing —
   a ticket filed today would describe a bug nobody can reproduce. If profiles
   stay, the announce belongs to the ORDER.2 increment that is already editing
   that path, and a repair smaller than the ticket describing it does not get a
   ticket. Either answer disposes of it; neither leaves a ticket. Recorded here
   so the answer collapses something visible rather than closing a gap nobody
   wrote down.
2. **The per-request `log_level` is parsed and dropped.**
   `RequestFields::log_level` (`src/protocol/meta.rs:79`, parsed `:196`) has no
   reader; the session-global `MetaMcp::log_level` (`src/gateway/meta_mcp/mod.rs:192`,
   written by `logging/setLevel` at `src/gateway/meta_mcp/protocol.rs:279`, read
   by `current_log_level` `:311`) governs instead. *Disposal: write it into this
   design* — it is a constraint on SUB.2 option (b), which cannot filter per
   request until the per-request value is read. No separate ticket.
3. **`ORDER.3`'s evidence cell enumerates only the illegal inputs.** The
   classification is correct and stays `MET`; its cited source names two
   connection-derived filters where the list path has seven inputs (§I.2). An
   enumeration listing only its failures cannot be checked for completeness.
   *Disposal: fix it in this change* — §I.2 is the complete table, and the
   criteria-status evidence cell should point here.
4. **`tools/list` receives no caller context at all** (§I.3). Spec-legal today,
   because authorization-derived variation is permitted and not required. It is
   recorded because it is what makes ORDER.2 option (c) expensive, and because
   any future decision to narrow the surface by principal starts here.
   *Disposal: record as an observation* — nothing to do unless (c) is chosen.

---

# Part IV — questions only the operator can settle

Collected, not answered. Each changes what gets built.

**§4.1 — Are per-session routing profiles a supported product feature that must
be preserved for existing clients, or may they be removed outright?**
This decides between ORDER.2 option (a) and option (b). It cannot be answered
from the code: `src/gateway/router/authorization.rs:41-70` records a deliberate
decision to leave profile selection uncredentialed, so removing the feature
reverses a call this repository made on purpose, and the repair protocol forbids
dropping a requirement without the requester's recorded agreement.
*Recommendation:* if no external client depends on it, remove it (option b) — it
is the only response after which the finding cannot be restated. *Cost of the
alternative:* option (a) leaves two behaviours and a meta-tool that has to be
refused on one of them.

**§4.2 — Should tool-surface selection become authorization-derived, keyed on the
authenticated principal rather than the session?**
This is ORDER.2 option (c), and it is a policy choice about who may choose a
surface, not an engineering one. It is also the expensive answer: `tools/list`
has no caller context today (§I.3), and a principal-to-profile mapping would be
new configuration surface. *Recommendation:* not for v4.0.0 — it is a larger
change than the criterion requires, and (a) or (b) closes the criterion without
it. Worth answering anyway because the same question is open in other clusters
where session identity is used as a key.

**§4.3 — `SUB.2`'s second clause requires emitting. Does v4.0.0 meet it, or is the
criterion being amended?**
Reframed after review, which was right that the earlier wording let a
nonconformant release look like a design option. It is not one: `SUB.2` as written
requires request-scoped notifications to reach the caller that provoked them, so
shipping option (a) alone leaves a release-blocking criterion ABSENT. The
honest question is therefore not "may we ship (a)" but which of two things you
want:

| | consequence |
|---|---|
| **(i) v4.0.0 meets `SUB.2` as written** | (b) is in scope now: the transport rewrite in §II.2 plus the shared identity in §II.5. Larger than this note originally implied, and it overlaps the MRTR increment, so the two should land together |
| **(ii) `SUB.2`'s second clause is amended for v4.0.0** | the criterion is edited in `docs/requirements/RELEASE-4.0.0-criteria-status.md` to require the *capability* (a stream that can carry them) and defer *emission*; (a) then conforms, and the release is honest about what it ships |

*No recommendation, deliberately.* Every other question in this note carries one;
this one cannot. (ii) narrows what a release-blocking criterion demands, which the
repair protocol puts on the requester's side of the line and requires recorded
agreement for **before** it happens — so a design note that recommended it would
be nudging the one decision it just said was not its own.

What the design can say, as input rather than verdict: *for (ii)* — the §II.2
transport fix is worth doing on its own correctness merits (an HTTP backend that
emits a notification before its result currently corrupts the `tools/call`
response) and rushing it to a release date is how that gets done badly; the
capability, once shipped, makes emission an additive change later. *For (i)* —
the criterion was written deliberately, an amended criterion is a permanent
narrowing of what v4.0.0 promised, and SUB.2 then stops being a small change
because the release scope absorbs a transport rewrite. If (ii) is chosen the edit
belongs in `RELEASE-4.0.0-criteria-status.md`, not in this note.

Until one is chosen, SUB.2's implementation is blocked on a deferred question,
recorded with its four fields in §II.4.

---

# Part V — questions this design asked and answered

Each is recorded as: question — what was run — what came back — what it changed.

- **Does any production code emit `notifications/progress` or
  `notifications/message`?** — `git grep -n "notifications/progress\|notifications/message" -- src`
  — only `subscription_registry.rs`'s exclusion list and a stdio test — changed
  the framing of SUB.2 from "wired to the wrong scope" to "absent", which is what
  broke the cluster's shared-root hypothesis (§0).
  *Tightened after review: a name grep also matches comments, exclusion lists and
  tests, so it is weak evidence for absence.* The claim now rests on the stronger
  structural check, which is what §II.2's table records: the two backend
  transports discard non-response messages at `http/mod.rs:929-944` and
  `stdio.rs:416-431`, and `dispatch_to_backend` returns a single value
  (`invoke.rs:1955-1961`). Absence is proved by there being no path, not by no
  string matching.
- **Can a routing profile widen a client's access?** — read
  `src/routing_profile/mod.rs:21-24` — no: it is an allow/deny filter over the
  already-surfaced set — killed the security framing of ORDER.2 and made it a
  conformance argument. Changed nothing else, and saying so is the point: the
  most invasive option lost its strongest justification.
- **Is `is_modern` reachable at the `tools/list` dispatch site?** — read
  `src/gateway/router/handlers.rs:683` and `:920` — yes, same function, one
  argument away — made ORDER.2 option (a) cheap enough to recommend.
- **Is the per-request `log_level` consumed anywhere?** — `git grep -n log_level -- src`
  — no reader; a session-global value governs — named a second SUB.2 gap and
  became a constraint on option (b) (Part III, item 2).
- **Is `tools/list_changed` fired when a profile changes?** — `git grep -n announce_tools_changed`
  — only UI callers in `src/gateway/ui/backends.rs`; `router/mod.rs:161` is never
  reached by `gateway_set_profile`, and equally never reached by backend discovery
  completing, which is why §I.2's cache row has no notification either — added the stale-list finding (Part III,
  item 1) and rejected ORDER.2 option (d).
- **Does the POST path negotiate `text/event-stream`?** — read
  `src/gateway/router/handlers.rs:265-290` and checked which handler owns it — no;
  the `Accept` check is the `GET /mcp` handler's — made content negotiation a
  prerequisite of every SUB.2 option.
- **Is the subscription registry's admission cap reusable per request?** — read
  `src/gateway/subscription_registry.rs:100-147` — it is a semaphore sized for
  long-lived listeners — ruled out reusing it, and added an accounting
  requirement to SUB.2 option (a).
- **Does authorization narrow the list today?** — read
  `handle_tools_list_for_session` (`src/gateway/meta_mcp/mod.rs:1112`) and the
  admin gate at `:1256` — no caller context reaches the list path; the gate is at
  dispatch — priced ORDER.2 option (c) and became Part III item 4.

---

# Part VI — out of scope

Declared before review, per the process. Findings in these areas are recorded in
Part III and disposed of there; none of them blocks this design.

- **SUB.2's first clause** (line 151, `MET`) — the exclusion of these
  notifications from the subscription stream is already correct and tested.
- **`SUB.4`, `EXT.1`, `OTEL.1`, `TASK.1`** — adjacent criteria in the same
  ticket, each with its own design note.
- **Clusters A (MRTR) and E (session identity as a key)** — this note names where
  it touches them (the shared per-invocation identity, §II.2 and §II.5; principal
  keying, §4.2) and
  designs nothing in either. §II.5 states a shared prerequisite and names its two
  consumers; it does not decide cluster A's approach to it.
- **Any code or test edit.** This is a design increment. The test plan is the
  next step and is not written here. A reviewer asked for
  `docs/requirements/RELEASE-4.0.0-test-plan.md:219` to be rewritten now, with
  scenarios for two callers, lazy cache publication, duplicate JSON-RPC ids and a
  post-completion notification. *Disposal: adopted as the content of the next
  increment, not edited here.* The named scenarios are recorded so the test plan
  step inherits them. That file also carries another session's uncommitted work,
  and it is not this note's to touch.
- **Atomic publication of the backend tool cache, and hot reload.** Classified in
  §I.2 as legal-but-time-varying. *Disposal: deferred to Part III item 1's
  answer.* Its remedy needs the `tools/list_changed` announce path that item 1
  shows is never fired, so designing it before §4.1 returns would design against a
  mechanism that may be removed.
- **The `spec-preview` promotion feature itself.** Its session-keyed input is
  classified in §I.2 and must be closed by whichever ORDER.2 option is chosen,
  but whether the feature should exist is not this note's question.

The test plan named as the next step above is now written, as the sibling file
`docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md`.
