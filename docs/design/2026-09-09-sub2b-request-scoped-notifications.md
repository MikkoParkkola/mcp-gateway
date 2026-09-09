# SUB.2b — request-scoped notifications on their own response stream

Date: 2026-09-09
Criterion: `MIK-7272.SUB.2b` (`docs/requirements/RELEASE-4.0.0-requirements.md:228`, Spec §4, level T) —
"request-scoped notifications MUST flow on the response stream of their own request".
Ledger: `docs/requirements/RELEASE-4.0.0-criteria-status.md:230` — ABSENT, both legs.

**Ticket-id discrepancy, settled (2026-09-09):** the lane brief names `MIK-7212.SUB.2b`; every document
in this repo names `MIK-7272.SUB.2b`, and `v4.0.0-gap-closure-plan.md` names `MIK-7414` as the lane's
tracking ticket. The repo's spelling stands and nothing is renamed — see the decisions section below.

## Governing design

§II of `docs/design/2026-08-31-cluster-b-connection-invariance.md` is the design for this criterion.
This note is an **increment** under it and re-argues none of it — specifically not §4.3 (operator,
2026-08-31: option (i), v4.0.0 meets SUB.2 as written, criterion NOT amended) and not §II.6's
recommendation. Scope of this note: the **inbound transport leg** — what the HTTP client transport does
with a notification a backend interleaves on a request's own SSE response stream.

## What the spec revision requires

Revision 2026-07-28 lets a server answer a POST that carries a JSON-RPC request with a
`text/event-stream` body, and lets that stream carry notifications *related to that request* before the
final response frame. Two obligations follow, and they are independent:

- **Inbound (client leg).** A client reading such a stream must treat interleaved notifications as
  deliverable content of that call, not as noise.
- **Outbound (server leg).** A server that has request-scoped notifications to emit must emit them on
  that request's own response stream, not on some other connection.

## What we do today

**Inbound: the notification is parsed and then discarded.**
`src/transport/http/mod.rs:285-306`, `fn parse_sse_response(text: &str) -> Result<JsonRpcResponse>`.
Every `data:` line is classified into `JsonRpcMessage`. `Response(r)` returns; `Request(r)` is refused as
a call addressed to this client; `Notification(n)` hits `debug!(method = %n.method, "Skipping
notification on response stream")` at `mod.rs:294-296` and is dropped on the floor. The doc comment at
`mod.rs:276-284` states outright that a server may interleave notifications — and the code then throws
them away. Sole call site: `mod.rs:1204-1211`, inside `send_request_with_headers`, on the
`content_type.contains("text/event-stream")` branch, with the body already read to completion (the
"first `data:` line wins" defect §II.2 describes is **already fixed**; the loop scans every line).

There is no notification sink anywhere in the client transports: `notification_handler`,
`on_notification`, `NotificationSink` and `set_notification*` match only `src/gateway/router/tests.rs`.
There is no progress-token plumbing either: `progressToken`/`progress_token` match nothing under `src/`.
`RequestFields::log_level` (`src/protocol/meta.rs:78-80`, parsed at `meta.rs:193`) has zero production
readers and is a placeholder, not a half-implementation.

The same discard exists on stdio (`src/transport/stdio.rs:416-431`); websocket is not a site
(`classify_frame`, `src/transport/websocket.rs:128-132`). Both are outside this note's scope.

**Outbound: the surface does not exist.**
`POST /mcp` routes to `handlers::meta_mcp_handler` (`src/gateway/router/mod.rs:239`) and inspects `Accept`
nowhere; it has no SSE branch. The `text/event-stream` negotiation at
`src/gateway/router/handlers.rs:379-390` belongs to `mcp_sse_handler` (`handlers.rs:355`), which
`router/mod.rs:240` wires to **GET** `/mcp` — a standalone notification stream, by definition not the
response stream of any request. So the gateway cannot today place a notification on a request's own
stream, whatever it decides to send.

## Ordering guarantees

Whatever delivers these must preserve **stream order**: notifications arrive in the order the server
wrote them, and every notification that precedes the response frame is delivered before the caller sees
the result. That is free if capture and result travel together out of the parse, and is not free if a
sink delivers asynchronously beside the call — which is the reason to prefer the former.

Nothing in the criterion requires ordering *between* two concurrent requests, and nothing here provides
it.

## A notification whose request has already completed

Two sub-cases, and only one of them is a real question:

1. **After the response frame, same body.** The parse returns at the first `Response` frame, so a
   notification on a later line is dropped one line down from the discard above. Decision: **out of
   scope for the inbound leg as specified.** The criterion is about notifications flowing *on* the
   request's stream, and a conforming server places request-scoped notifications ahead of the result.
   A body with a trailing frame is not refused; the frame is ignored. Stated so it is not mistaken for
   an oversight.
2. **After the call has returned to its caller.** Cannot arise if capture rides out with the response:
   there is no orphan lifetime to specify, no late-delivery race, and no sink outliving its request.
   This is the decisive argument for the shape below.

## The design event this note names

Dropping versus delivering a notification changes an observable contract, so the shape is named here
rather than decided at the keyboard (development-process §P3):

**Shape.** `parse_sse_response` stops discarding and **returns** the notifications it saw alongside the
response — capture and result in one value, out of one function, with stream order intact. Its single
call site (`mod.rs:1211`) is the single consumer point, and the forwarder increment attaches there.

**Rejected: a sink field on `HttpTransport`.** A field on the shared struct is not request-scoped — the
criterion's whole content is that these notifications belong to *one* request — and it needs a wirer
that lives outside this domain. §II.2 already scores a router-side sink as "a dead pipe: correctly
addressed, never written to"; a transport-side sink nothing reads is the same defect mirrored, and the
ledger's own wording for this row ("a parsed field with no reader is a placeholder, not a
half-implementation") is how it would be scored.

**Rejected: changing the `Transport` trait.** `Transport::request` / `request_with_headers`
(`src/transport/mod.rs:24,41`) return `Result<JsonRpcResponse>`. Threading a per-call sink through the
trait changes every implementor — stdio, websocket, and the gateway call sites — none of which is in
this domain. If the forwarder needs it, that is a scope change for the lead, not an edit.

**Not reused: `SubscriptionRegistry::subscribe`** (`src/gateway/subscription_registry.rs:124`). Its
semaphore is sized for long-lived subscriptions; taking a permit per request would couple request
throughput to subscription capacity.

## Why the inbound leg is not implemented in this increment

§II.6 (2026-09-09) records a **deferred blocking operator question** on the correlation key:
(i) forward only what a backend sends unprompted (recommended) versus (ii) the gateway mints and
translates tokens. Owner: operator. Resolves by answering (i)/(ii). When: before the forwarder
increment starts — "the §II.2 transport work and the §II.5 identity are unaffected and may proceed".
If (ii): a token-allocation table keyed by the §II.5 identity, and a scope change.

Under §P1 a deferred unknown blocks anything whose correctness turns on it. Capture does not turn on it;
**the forwarder does** — the answer determines what a captured notification is correlated *to*, and
therefore who it is delivered to. Building the capture now with no forwarder produces exactly the dead
pipe rejected above, so this increment stops at the design and the criterion stays open.

## Consequence for the criterion

SUB.2b is **BLOCKING**, and it is **escalated to the operator as a scope question** — explicitly NOT
narrowed, NOT dropped, NOT amended. It is not closable in this domain today, on two independent blockers,
neither of which this note may overrule:

1. The forwarder (correlate a captured notification to its caller and emit it) is blocked on the §II.6
   operator question.
2. The outbound leg needs POST content negotiation in `src/gateway/router/handlers.rs` /
   `router/mod.rs`, which is peer-owned and out of this domain — and has no mechanism to reintroduce,
   so no falsifier probe is possible there; the surface is absent, not defective.

The inbound leg's discard at `mod.rs:294-296` is real, present, and probe-able. It is the first thing
the forwarder increment should remove, using the shape above.

## Decisions: one answered, one open, and where the criterion now sits

**Answered — the `Transport` trait does not change on this release branch** (team lead, 2026-09-09).
Changing `Transport::request` / `request_with_headers` (`src/transport/mod.rs:24,41`) touches stdio,
websocket and every gateway call site, on a branch being stabilised for 4.0.0, to serve a leg that is
itself blocked on an unanswered operator question. In the lead's own words: "a cross-cutting refactor
whose consumer does not exist yet is the worst-timed change available… that is a release-scoped decision
the operator makes with the cost visible, not one I authorise underneath them".

**Consequence, recorded rather than worked around.** With the trait fixed, a captured notification has no
in-domain consumer whichever way §II.6 lands. The shape above is still the right shape; it has nowhere to
deliver to yet. So the inbound leg is not merely unimplemented — it is unimplementable within this domain
on this branch, and that is a fact about scope, not about the design.

**Open — the §II.6 correlation key**, (i) or (ii), deferred with its four fields at
`2026-08-31-cluster-b-connection-invariance.md:455-460`. Owner: operator. It travels up **with** the
`Transport`-scope question, as one escalation rather than two.

**SUB.2b stays BLOCKING and is not narrowed.** "The fix is expensive" is not a reason to redefine what was
asked for; narrowing a criterion is not available on this release. It escalates to the operator as a scope
question, never as a request to drop it.

**Ticket spelling stands as the repo spells it**: `MIK-7272` throughout the requirements and status
documents, `MIK-7414` as the lane's tracker (`docs/release/v4.0.0-gap-closure-plan.md:51`). Nothing is
renamed to reconcile them.

**Dual-vendor review of this note is deferred deliberately.** Its load-bearing section is the pair of
decisions above; reviewing a document that is about to change there spends two vendors on a draft. It goes
to review once §II.6 is answered and the trait question is settled by that answer.

---

# Revision 2026-09-09 (later the same day) — the check came back

The sections above are kept in place rather than rewritten, because two of their load-bearing claims
are now false and a reader must be able to see which. This revision supersedes them where they conflict.

## Correction 1 — the §II.6 operator question is ANSWERED, not deferred

`docs/design/2026-08-31-cluster-b-connection-invariance.md:463-469` now reads, verbatim:

> **ANSWERED 2026-09-09 (operator): (i), pass through only.** The gateway forwards a backend's own
> progress token when it matches one a caller supplied on that request, and never mints one. The
> four fields above are discharged — this is a resolved question, not a deferred one, and the
> forwarder increment is unblocked on it.

So "the forwarder is blocked on the §II.6 operator question" — this note's blocker #1, and the whole
of its "Why the inbound leg is not implemented in this increment" section — is **discharged**. There is
no deferred unknown under §P1 here any more. Anyone re-escalating it is re-asking a settled question.

## Correction 2 — the `Transport` trait was never what blocked capture

This note claimed the inbound leg is "unimplementable within this domain" because `Transport::request`
is fixed. That is wrong, and the counter-example is in the tree: `src/backend/lifecycle.rs:379` calls
`transport.attach_era(Arc::clone(&self.era))` on the **concrete** `HttpTransport`, at construction,
before it is ever used through the trait. Attaching a collaborator to `HttpTransport` needs no trait
change and has a blessed precedent. Correlation is not a problem either: capture happens inside
`send_request_with_headers`, which holds the request id, so the id travels in the *call*, not in the
field — which is what this note's rejection of a sink ("a field on the shared struct is not
request-scoped") missed.

Capture, then, is buildable in-domain today, touching only `src/transport/**`. The lead's ruling
against changing `Transport::request` still stands and is not challenged — it simply never bound this.

## What actually blocks SUB.2b, and it is one thing

**A captured notification has no destination.** The criterion is satisfied only when the notification
reaches the caller *on the response stream of the caller's own request*. In this gateway that stream
would have to be a `text/event-stream` body on `POST /mcp`, and that surface does not exist:
`src/gateway/router/mod.rs:237-242` wires `/mcp` as
`post(handlers::meta_mcp_handler).get(handlers::mcp_sse_handler).delete(handlers::mcp_delete_handler)`,
so SSE is GET-only and POST answers JSON. The only `Accept: text/event-stream` negotiation in the tree
(`src/gateway/router/handlers.rs:379-389`) sits inside `mcp_sse_handler`, i.e. on the GET stream — by
definition not the response stream of any request.

Creating that surface means editing `src/gateway/router/handlers.rs` and `src/gateway/router/mod.rs`.
Both are modified in the working tree by another session (`git status`: `MM`), and this lane is
instructed not to touch a file another session is holding. A new handler in a new file does not escape
this: its route must still be registered in `src/gateway/router/mod.rs`.

Building capture alone under that constraint produces exactly the dead pipe §II.2 scored and this note
rejected — parsed, addressed, never delivered — so it is not built.

## Consequence — this is the check §II.6's ruling was waiting for

`docs/design/2026-08-31-cluster-b-connection-invariance.md:471-480` rules out the `Transport` signature
change "PROVISIONALLY … conditional on there being another path", and says that if the forwarder turns
out to have no deliverable path, ruling out the mechanism "would make a blocking criterion unmeetable
this release — a requirement narrowing in mechanism clothing, which is the operator's recorded call and
not the lead's. The provisional ruling holds only until that check comes back."

**The check has come back, and the answer does not turn on the trait at all.** The path that is absent
is the outbound one. So the operator's decision is not "may the trait change" but:

1. assign the POST content-negotiation work to whoever holds `router/handlers.rs` and `router/mod.rs`; or
2. authorise this lane to take those two files, accepting the conflict with the session holding them; or
3. accept `MIK-7272.SUB.2b` red for 4.0.0, with the gap recorded.

**SUB.2b stays BLOCKING** — not narrowed, not dropped, not amended. Ledger row unchanged; the release
counter is unmoved (`count-release-criteria.py --check`: 146 criteria, 183 rows, 5 blocking, exit 0).

**Review status.** The deferral above ("once §II.6 is answered") has fired, so this revision goes to the
two vendors on the one question that could overturn it: can SUB.2b's outbound obligation be met without
editing those two files? Everything before this revision was never reviewed and is superseded where it
conflicts.

## Superseding rulings (2026-09-09, after this note was written)

This note closes by concluding SUB.2b is unimplementable in this domain on this branch. Both blockers
behind that conclusion have since been resolved, so the conclusion no longer holds and the sections
above that rest on it are superseded rather than deleted — they record what was true when written.

**Ruling (operator, 2026-09-09): SUB.2b is built before v4.0.0.** The `Transport` trait
(`src/transport/mod.rs:24,41`) may change on this release branch, and the outbound leg's POST content
negotiation in `src/gateway/router/` is in scope. The team-lead ruling quoted above — that the trait is
fixed on this branch — is superseded by this one. The cost was put to the operator explicitly (stdio,
websocket and every gateway call site, plus peer-owned router code, on a branch being stabilised) and
that path was chosen with the cost visible. The criterion is not narrowed and not amended.

**Assumption, not a ruling, on the §II.6 correlation key: option (i).** The gateway forwards a
notification only when a backend sends one unprompted, correlated by the request stream it arrived on.
It does not mint or translate progress tokens, so there is no token-allocation table and no lifetime to
manage. The operator was asked and did not answer within the window; (i) is this note's own
recommendation and the smaller scope, and adding (ii)'s allocation table on top of a refactor the
operator had just authorised would widen scope they did not ask for. Recorded as assumed so a later
reader can see it was never decided. An implementation finding that makes (i) untenable escalates
rather than switching silently.

---

# Repairs 2026-09-09 — round 1, both legs returned

## Repair 1 — the note's premise was false: POST /mcp already answers with an event stream

The revision above states that SSE is GET-only and that POST answers JSON. That is wrong, and it is
inverted. Verified at source today:

- `src/gateway/router/handlers.rs:1120-1126` returns `crate::gateway::streaming::subscription_stream(...)`
  from the POST dispatch, for the `subscriptions/listen` arm at `:1063`. A POST to `/mcp` therefore
  already produces a `text/event-stream` body in this gateway.
- `src/gateway/router/handlers.rs:333` refuses the GET: `"GET /mcp was removed in MCP 2026-07-28; use
  subscriptions/listen"`, `405 Method Not Allowed` with `Allow: POST`, for callers on a modern era.
  The GET stream this note leaned on is the legacy surface, not the modern one.
- `src/gateway/streaming.rs` is unmodified in the working tree, so the streaming machinery itself is
  not held by another session.

So the shape SUB.2b needs is not architecturally absent. What is absent is narrower and still decides
the same way: nothing chooses an event-stream body over a JSON body for an **ordinary** request, and
the place that choice would be made is the method dispatch inside `src/gateway/router/handlers.rs` —
the file this lane was told not to take. `subscription_stream` is also not the destination: SUB.2a
forbids request-scoped notifications on the subscription stream, asserted at
`src/gateway/subscription_registry.rs:211`. It proves the shape, and it is the wrong pipe.

The conclusion is unchanged. The reason it was written down was wrong, and a reader acting on the old
sentence would have looked for a surface that already exists.

## Repair 2 — the tower middleware escape is eliminated, not assumed

Both legs named the same escape route: wrap the router in a tower layer so request-scoped
notifications are emitted without editing either held file. Checked, and it closes.

`checkable:` can a tower layer reach `POST /mcp` without editing `src/gateway/router/mod.rs`? —
`rg -n "\.layer\(|ServiceBuilder|from_fn" src` — every layer application site for this router is in
that same held file (`:262`, `:267`, `:268`, `:269`, `:270`, `:311`). The only other sites in the
tree are `src/gateway/server/support.rs:249` and `:440`, which attach peer-certificate identity to
the connection service, and `src/gateway/ui/control_plane.rs:55`, which layers a different router. —
it changed nothing: a middleware still has to be applied in the file this lane may not take.

GPT's alternative anchor, `src/gateway/server/mod.rs`, is held by another session as well
(`git status`: `MM`), which that same finding concedes in its own text.

## Repair 3 — the correlation citation the second leg asked for

`send_request_with_headers` is `src/transport/http/mod.rs:1106`, taking `request: &JsonRpcRequest`.
That binding is in scope for the whole body, including the event-stream branch at `:1204-1211` where
`parse_sse_response` drops notifications on the floor. The request id therefore travels in the call,
not in a field on the shared struct — which is what Correction 2 asserted. Grade: V, read at source.

## Repair 4 — provenance of the operator answer

`git blame` on `docs/design/2026-08-31-cluster-b-connection-invariance.md:463`: commit `2746ff89e`,
dated 2026-09-09. The ANSWERED block is a committed record, not prose authored inside this note.

## Review status — round 1 closed

- Reviewed by GPT-5.x (`gpt-review`, exit 0): **SHIP-WITH-FIXES** — "correct the design's
  impossibility argument while retaining SUB.2b as blocking."
- Reviewed by the second leg (`kimi-review`, exit 0, ledger row `synthetic-20260909T094834Z-56838`):
  **SHIP-WITH-FIXES** — "No — no concrete mechanism in the pasted evidence meets SUB.2b's outbound
  obligation without editing handlers.rs and mod.rs."

Both answered the one question that could have overturned this note with **No**. The four repairs
above are the confirmation pass. Everything before the "Revision 2026-09-09" heading is a prior
session's baseline, was never reviewed, and is superseded where it conflicts.

**SUB.2b stays BLOCKING.** The ledger row is untouched and the release counter is unmoved
(`count-release-criteria.py --check`: 146 criteria, 183 rows, 5 blocking, exit 0). The three operator
options are unchanged by this round.

---

# Revision 2 — 2026-09-09 (operator ruling: build it)

Revision 1 closed on a three-way operator choice. **The operator took option 1-and-2 together and
ruled BUILD SUB.2b BEFORE v4.0.0.** This revision records what that ruling changes, what it does not,
and what now blocks the work. Everything above stands except where contradicted here.

## What the ruling supersedes

| superseded | by |
|---|---|
| "**Answered — the `Transport` trait does not change on this release branch**" (this note, above) | The trait **MAY** change. `src/transport/mod.rs:24,41` is in scope. |
| "the outbound leg needs POST content negotiation … which is peer-owned and out of this domain" | Outbound POST content negotiation in `src/gateway/router/` **IS** in scope. |
| Revision 1 option 3, "accept `MIK-7272.SUB.2b` red for 4.0.0" | Withdrawn. The criterion is built, not narrowed and not deferred. |

The lead's earlier ruling is superseded, not deleted, and is left in place above so a reader can see
which sentence stopped binding. The operator made this call **with the cost visible** — stdio,
websocket, every gateway call site, peer-owned router code, on a stabilising branch — and chose it
anyway. The cost is therefore not a reason to re-narrow the criterion later; it is a price already
accepted on the record.

## Scope note — the trait change is permitted, not thereby required

Correction 2 above stands and now bounds the work rather than unblocking it. `attach_era`
(`src/backend/lifecycle.rs:379` calling `src/transport/http/mod.rs:573`, both re-verified at source
at `b28ad089`) attaches a collaborator to the **concrete** `HttpTransport` with no trait change. The
inbound capture shape — `parse_sse_response` returning the notifications it saw alongside the
response, one value, one function, sole call site `src/transport/http/mod.rs:1211` — likewise needs
no trait change. Authorisation to widen `Transport::request` should be spent only if the outbound
leg genuinely demands it. Permission granted is not permission that must be used.

## §II.6 correlation key — recorded as an ASSUMPTION, with its reasoning

**This lane proceeds on option (i): pass-through only.** The gateway forwards a notification only when
a backend sends one unprompted on a request's own stream, correlated by which request's stream it
arrived on. No token minting, no translation, no token-allocation table.

Two things are true at once and a reader needs both:

- `docs/design/2026-08-31-cluster-b-connection-invariance.md:463` records this as **ANSWERED by the
  operator** ("(i), pass through only … never mints one"). Re-read at source today at `b28ad089`.
- **This lane's own escalation of the same question went unanswered in its window.** The lead
  therefore instructed that (i) be carried **as an assumption, not as a ruling this lane received.**

Reasoning for choosing (i) as the assumption, so the choice is checkable rather than inherited: it is
the design's own recommendation; it is the smaller scope; and (ii) would add a token-allocation table
the operator did not ask for, on top of a refactor the operator has just authorised.

**If implementation makes (i) untenable, this lane STOPS and escalates.** It does not silently switch
to (ii). A correlation key changed under an assumption is a design event (§P3) and an operator
question, in that order.

## What blocks the outbound leg now: file ownership, not scope

Revision 1 blocked on **scope** (nobody had authorised the router work). That blocker is discharged.
What replaces it is narrower and is a different kind of thing:

`src/gateway/router/handlers.rs`, `helpers.rs`, `mod.rs` and `tests.rs` are all `MM` in `git status` —
staged **and** unstaged edits belonging to another session. Under §P5, uncommitted work in a live
checkout **is** the running system, and `git commit -o <path>` takes that path's whole working tree,
so committing the outbound leg would ship a stranger's in-flight edit under this lane's message.
Editing without committing is worse, not a compromise: it stacks two sessions' changes in one file.

This is the lead's call, not this lane's and not the operator's: the operator authorised **scope**,
the lead owns **sequencing in a shared worktree**. Raised, not worked around.

`src/transport/**` is clean (`git status --porcelain src/transport/` returns nothing, checked at
`b28ad089`), so the inbound half is takeable the moment the outbound half has an owner.

**The inbound leg is deliberately NOT built alone.** §II.2 scored a capture with no destination as "a
dead pipe: correctly addressed, never written to", and the ledger row scores the same shape as "a
parsed field with no reader is a placeholder, not a half-implementation". Building capture while the
outbound surface is absent produces exactly the artefact this criterion's own review standard fails.

## stdio — explicitly in or out, since the old scope no longer inherits

`src/transport/stdio.rs:416-431` discards peer notifications the same way ("A peer notification is
accepted and ignored"). Under the old trait-frozen ruling that site was outside this note's scope by
default. That default is gone with the ruling, so it is stated rather than inherited: **stdio is OUT
of this increment's FOR**, because SUB.2b names *the response stream of their own request* and the
stdio transport has no per-request response stream to flow them on — it multiplexes one stdout. If
the criterion is later read to bind stdio, that is a §P0 scope move needing a receipt update, not a
silent extension of this note.

## Ledger status unchanged

`MIK-7272.SUB.2b` remains **ABSENT / blocking = yes** at
`docs/requirements/RELEASE-4.0.0-criteria-status.md:230`. Nothing is flipped by a ruling; only shipped
code with tests flips a row. The release counter is untouched.

## Review status of this revision

Revisions 1 and 2 have **never been dual-reviewed** — that is disclosed here on the artefact rather
than assumed. This revision is the material for the pair (`gpt-review` + `kimi-review`, on stdin), on
the one question that can overturn it: does the operator's build ruling reach anything this revision
records as out of scope or assumed?
