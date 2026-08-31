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
| **routing profile** | `surfaced.rs:106-108` | **session id** | **connection-derived — illegal** |
| **session-promoted tools** | `mod.rs:1156` (`spec-preview`) | **session id** | **connection-derived — illegal** |

Two of seven are illegal. `ORDER.3` names exactly those two, so its `MET` status
survives this design — but its evidence cell should gain the other five, because
an enumeration that lists only the failures cannot be checked for completeness.
Recorded in Part III.

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
clients keep today's behaviour unchanged.
*For:* smallest diff that closes the criterion; no mechanism removed, so the
prior decision in `authorization.rs` stays true for the clients it was made
about; matches the `GET /mcp` era-gate precedent.
*Against:* the gateway then behaves two ways, and `gateway_set_profile` becomes a
tool that silently does nothing to a modern client's list while still changing
dispatch — a split between what is listed and what is callable. That split needs
its own answer (refuse the meta-tool in modern mode, most likely), or it is a new
inconsistency traded for the old one.

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

Whichever is chosen, `gateway_set_profile` must be refused on the modern path
under (a), or removed under (b). Leaving a meta-tool that changes dispatch but
not the list is the inconsistency this criterion exists to prevent, in a new
place.

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

**A request-keyed channel does not exist and is the real cost.** Delivery today
is keyed by session because a session is what the transport gives you. Routing a
backend's notification back to one in-flight request means carrying a request key
from the router, through `dispatch_to_backend`, to wherever the backend's
notifications are read — the same plumbing problem the MRTR retry work hit when
it needed request state at the dispatch boundary and found none
(`src/gateway/router/handlers.rs:930-955`). These two should be built once, not
twice.

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

**(b) Mechanism plus backend forwarding.** (a), plus a request-keyed channel so a
backend's `notifications/progress` and `notifications/message` are relayed to the
caller of the provoking request, filtered by that request's `log_level`.
*For:* meets the criterion for the case that actually arises — the gateway is a
proxy, and the notifications a client wants are the backend's.
*Against:* needs the request-key plumbing described above, and the per-request
`log_level` currently parsed and dropped (Part III) has to start being honoured.

**(c) Mechanism plus gateway-originated progress.** (a), plus the gateway
emitting its own progress for long meta-tool operations.
*For:* the gateway does have slow operations worth reporting on.
*Against:* largest, and it invents a policy — which operations report progress,
at what granularity — that nobody has asked for. Speculative; not recommended.

## II.4 Recommendation

**(b), sequenced as (a) then the forwarder**, with the request-key plumbing built
jointly with the MRTR retry-forwarding work rather than twice. But whether
v4.0.0 must ship (b) or may ship (a) is a scope decision with a large cost delta
and it is not this design's to take — see §4.3. Until it is answered, SUB.2
carries a **deferred open question that blocks implementation**: the design
cannot specify what is emitted until someone says whether anything must be.

| field | value |
|---|---|
| owner | operator, via §4.3 |
| what would resolve it | the answer to "must v4.0.0 emit, or only be able to stream" |
| when | before any SUB.2 implementation increment starts |
| what if it resolves badly | if v4.0.0 must emit, SUB.2 grows the request-key plumbing and stops being a small change; the release scope, not the design, absorbs it |

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

**§4.3 — Must v4.0.0 actually emit request-scoped notifications, or only be able
to carry them on a response stream?**
This is the scope fork in Part II and the cost delta is large: option (a) is
content negotiation plus a stream shape; option (b) adds request-keyed routing
through the dispatch boundary. Until this is answered, SUB.2's implementation is
blocked on a deferred question, recorded with its four fields in §II.4.
*Recommendation:* ship (a) in v4.0.0 and (b) in the increment that also lands the
MRTR retry plumbing, so the request key is built once. *Cost of the alternative:*
if v4.0.0 must emit, SUB.2 stops being a small change and the release scope
absorbs it.

---

# Part V — questions this design asked and answered

Each is recorded as: question — what was run — what came back — what it changed.

- **Does any production code emit `notifications/progress` or
  `notifications/message`?** — `git grep -n "notifications/progress\|notifications/message" -- src`
  — only `subscription_registry.rs`'s exclusion list and a stdio test — changed
  the framing of SUB.2 from "wired to the wrong scope" to "absent", which is what
  broke the cluster's shared-root hypothesis (§0).
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
  reached by `gateway_set_profile` — added the stale-list finding (Part III,
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
  it touches them (the request key in §II.2, principal keying in §4.2) and
  changes nothing in either.
- **Any code or test edit.** This is a design increment. The test plan is the
  next step and is not written here.
- **The `spec-preview` promotion feature itself.** Its session-keyed input is
  classified in §I.2 and must be closed by whichever ORDER.2 option is chosen,
  but whether the feature should exist is not this note's question.
