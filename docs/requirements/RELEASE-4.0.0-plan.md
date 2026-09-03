# v4.0.0 release plan — closing the blocking criteria

Companion to `docs/requirements/RELEASE-4.0.0-criteria-status.md`, which is the status SSOT.
This file is the ORDER OF WORK, not a second status table. When the two disagree, the status
doc wins.

The standing counts are not repeated here. `docs/requirements/RELEASE-4.0.0-criteria-status.md`
carries them, `scripts/release/count-release-criteria.py --check` verifies its headline against
its own tables, and nothing checks a copy. Every earlier revision of this file carried a count
that drifted from the ledger within days, which is the argument against carrying one at all.
`docs/requirements/RELEASE-4.0.0-blocking-rollup.md` groups the blocking rows by the work they
share, and derives that grouping from the ledger too.

## The blocking count is a floor, and what remains unverified is named

The gap this section previously recorded — no row anywhere for any of the 22 non-functional
requirements in section 4 of `docs/requirements/RELEASE-4.0.0-requirements.md` (lines 204-253)
— is closed. Every NFR ID has a row in the status doc, and as of 2026-09-01 every one of
those rows carries a verdict and the evidence it rests on. The eleven that were recorded
without an assessment no longer are.

Of the blocking NFRs, six are not independent work: NFR.SEC.2-4, NFR.OBS.4 and NFR.PERF.3
all verify the MIK-7212 continuation envelope, and NFR.OBS.3 verifies MIK-7217 era detection.
Both are unwired, so those rows cannot close before the clusters below — and closing a cluster
does not close them either, since each still needs its own evidence.

Two are known without a sweep. NFR.SEC.5 is now met: all four of its command gates were run on
this worktree on 2026-09-01 — `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
and `cargo audit` each exited zero, and the secret scan is clean in both halves CI runs it in,
`trufflehog --only-verified` finding nothing across 33,935 chunks and the CWE-532 leak lint
clean over 400 files. `#![deny(unsafe_code)]` holds at `src/lib.rs:1`. NFR.SEC.6 names four
tickets as closed in this release and two of them, MIK-7249 and MIK-7262, have no reference
anywhere under `src/` or `tests/`.
NFR.PERF.1-2 required a measurement against 3.5.0 that no code read could substitute for, and
it was run on 2026-09-03 — `v3.5.0` (`32f135a6`) against `5c29494a` on `spark`, recorded in
`RELEASE-4.0.0-performance.md`. NFR.PERF.2 is MET by its own consequence: header-first routing
did not ship, and the numbers show the most it could have saved is about 1.2% of a per-call
composite. NFR.PERF.1 is PARTIAL, not MET: nothing regressed near either budget, but criterion
measures in-process component work and produces no P50 and no P99, which is what the clause
names.

Each NFR row now also carries the verification method its requirement states — T, M, I or D —
and `scripts/release/count-release-criteria.py` refuses when a row's letter disagrees with the
requirements file. The point is not the letter but the mismatch it exposes: a row citing a code
read against a requirement that says M is not weak evidence, it is the wrong kind of evidence,
and that was invisible while the method lived only in the requirements document.

Assessing the eleven unassessed rows was therefore item zero of this plan, and it is done. It
paid for itself immediately: the sweep found that `docs/ARCHITECTURE.md:65` advertised a
protocol revision the gateway does not serve, now corrected.

It also found that the Meta-MCP surface's published 17-tool scenario
(`benchmarks/public_claims.json:4-6`) exceeds the 14-16 ceiling NFR.PERF.4 states, with nothing
clamping the count. The operator ruled on 2026-09-02: the ceiling stands and the seventeenth
stops counting. The requirement is NOT widened to 14-17, which would raise the ceiling to match
whatever shipped and reverse a locked decision. The seventeenth is `gateway_webhook_status`
(`src/gateway/meta_mcp_tool_defs.rs:565`), pushed behind `webhooks_enabled`.

NFR.PERF.4 stays blocking and stays ABSENT. What the ruling changed is its kind: it is no
longer an open operator call, so it left the compatibility cluster of the blocking rollup, and *how* the
seventeenth stops counting is an unmade engineering decision — a §P1 design event like the
rest of wave 1, not an edit.

### The MRTR implemented-but-unwired split, deferred here, has landed

A reviewer asked for the MIK-7212 rows to be split by whether each clause is implemented and
unwired or genuinely absent, on the ground that the two carry very different remaining work.
An earlier revision of this file deferred that until the session working the cluster landed.
It has, and the split is in the ledger: `MRTR.1-8` is eight criterion names carrying seventeen
rows, and an UNWIRED clause is now scored apart from its absent sibling — `MIK-7212.8a` and
`MIK-7212.8b` are the worked example. Read the cluster tables' criterion names as a key to
where a row belongs, never as a count of rows.

The split changed what the tests have to prove, which is the part a re-audit is for. MRTR.8's
three existing cases (`tests/mik_7212_acs.rs:439`, `:457`) exercise `InFlight` and
`ConsumedLedger` directly and pass today — which is precisely why 8a and 8b are UNWIRED rather
than failing. The test plan now carries the wiring case that none of the three supplies.

### One thread that looked in flight and was not

The cluster-C era-detection design is written: `docs/design/2026-08-31-discover-outbound-era-probe.md`.
An earlier revision of this file recorded it as never started, because the subagent briefed to
write it died on an output ceiling and a task ID that stops resolving was read as evidence the
work stopped. The NFR sweep briefed alongside it had also returned. Neither absence was real.

The dual review of the two ledger commits that added the verification-method column is likewise
recorded as MISSING, not as passed: the Codex run produced no verdict line and the second
reviewer stopped inside its own preamble. A verdict scraped from the body of a review whose
subject is verdict-keeping is exactly the failure the verdict-authority rule exists to prevent,
so nothing is claimed for it here.

## The shape of the problem

Two thirds of the blocking set is not missing code. It is code that exists and is not
reachable. That changes the plan: for UNWIRED criteria the expensive part is deciding *where*
the wiring belongs and what it changes for existing deployments, and the cheap part is the
edit. Every one of those decisions is a §P1 design event and none of them is an edit.

## Clusters, in dependency order

### MRTR continuation envelope — MIK-7212 (rollup cluster A)

MRTR.1 through MRTR.10a: sealed continuation envelopes minted by the gateway, principal and
request binding, single-use with expiry holding across replicas, replica affinity on retry,
the modern-to-legacy `InputRequiredResult` bridge, bounded in-flight state, and never sending
an `inputRequest` type the client has not declared.

The mechanism is built. `redeem_retry` (`src/gateway/meta_mcp/invoke.rs:529`) is called from the
tool-invoke path at `:1301`, and MRTR.4, MRTR.5, MRTR.6 and MRTR.9 are met with their call sites
and tests recorded. MRTR.9a was the last of them: a client's declaration no longer flattens to
the capability *name*, so a mode it never declared is refused instead of passing by construction.
What is left is fourteen rows of EVIDENCE over that path — recorded runs for MRTR.1/3/7/8/10a
and the five NFR rows that verify the envelope — not mechanism. Still the deepest security
surface in the release, and still the cluster whose evidence is easiest to fake by re-running
a test that was already green.
Blocks: CONFIRM.2, and MRTR.10a feeds MIK-7272's SUB.4 key contents.

### Revision surface — MIK-7272 (rollup cluster C)

The small self-contained half of this cluster has landed. What remains splits two ways:

- **Design-first**: SUB.4 (idempotency wiring — design at revision 4, see
  `docs/design/2026-08-31-sub-4-idempotency-wiring.md`. Larger than it looked: seven verified
  implementation defects are prerequisites, and no advertised way exists for a client to send a
  retry key at all. The tool-surface question that blocked all code is decided PROVISIONALLY:
  both the meta-MCP surface and the direct `POST /mcp/{name}` route are in scope. The operator
  was asked on 2026-08-31 and was away; the call is the team lead's, made on the full-scope
  direction recorded at the foot of this file, and it is not operator-confirmed),
  ORDER.2 (tool set must not vary per connection nor as a side effect of another request —
  the variation has one chokepoint, `MetaMcp::active_profile` at
  `src/gateway/meta_mcp/mod.rs:996-1005`, which its own doc comment names as "the one site
  `surfaced`, `invoke` and `spec_preview` read the profile through". A second axis, the
  `codemode` query parameter in `src/gateway/router/handlers.rs`, is reported and not yet
  read. The design choice is to stop varying or to move the variation under authorization,
  and one chokepoint means either is an edit rather than a sweep),
  SUB.2's surviving clause (request-scoped notifications on the request's own response stream),
  EXT.1 (declare the gateway's own extensions through server capabilities),
  OTEL.1 (`traceparent`/`tracestate`/`baggage` through `_meta`).
- **Whole feature**: TASK.1, the `io.modelcontextprotocol/tasks` extension for long-running
  backend calls. Largest single item outside MRTR. It is also SUB.4's alternative
  branch, so a decision to build it changes SUB.4's scope.

### Era detection — MIK-7217 (rollup cluster B)

DISCOVER.4 (detect a backend's protocol era by probing, never by trusting a version string)
and DISCOVER.5 (cache the detected era per backend, re-probe when a cached assumption fails).
DISCOVER.1-3 are met; one coherent design covers what is left.
Blocks: HEADER.9, which is conditioned on what the peer negotiated.

### Header forwarding — MIK-7214.HEADER.9 (rollup residue)

HEADER.9 alone: outbound requests carry the modern `_meta` envelope and the standard headers,
and only where the peer negotiated them. Cannot be finished before era detection.

### Principal-keyed security — MIK-7215.CONTROL.4 (rollup residue)

CONTROL.4: session-lifecycle TTL reaping owns the cleanup that disconnect used to do.
TENANT.1, CONTROL.2 and CONTROL.3 closed — the theme they shared, that session identity was
the wrong key, is settled everywhere except reaping.

### Response-cache keying — MIK-7213 (rollup cluster D)

CACHE.3 (public scope only, with proof and a decision table) and CACHE.4 (shared cache keyed
on all eight response-varying inputs plus a policy epoch). Both are correctness-of-caching
questions, independent of everything above, and safe to run in parallel.

### Schema validity — closed

An earlier revision of this file carried a cluster here for `MIK-6865.SCHEMA.1`: schemas valid
under JSON Schema 2020-12, no validator in the dependency tree, a crate decision before a test.
That decision was taken and the test landed on 2026-09-01 — `tests/schema_2020_12_validity.rs`
validates every emitted `inputSchema` against the meta-schema through the `jsonschema` crate,
in both Traditional and Code Mode, with a falsifier proving the validator rejects an invalid
schema. `SCHEMA.1` is not a row: the split scored it `1a`/`1b`/`1c`, and `1a` and `1b` are MET.
What is left of MIK-6865 is `SCHEMA.1c`, the `$ref` and composition bounds, which is a test
against the same emitted surface and sits in the ledger-split residue.

The letter is retired rather than reused. A reused letter makes two different plans read alike.

### Confirmation-gate reachability — MIK-7246.CONFIRM.2 (rollup residue)

The destructive-action confirmation gate must be reachable through the MRTR path so a modern
client can actually confirm. CONFIRM.1b closed 2026-08-31 and CONFIRM.1a is answered in the
working tree (see the stdio dispatch path below); this is the other half of the pair and it
cannot be built before MRTR lands.

### Stdio dispatch path — NFR.OBS.1, NFR.OBS.2, MIK-7246.CONFIRM.1a (rollup cluster G)

One wiring question answers all three rows. The gateway serves MCP over two transports and
all three controls started in the HTTP router only: both migration-telemetry records in
`handlers.rs`, and `require_destructive_confirmation`, whose module
`src/gateway/destructive_confirmation.rs` had exactly one consumer. **CONFIRM.1a is answered
in the working tree and awaiting a commit, a green suite and a review**: the gate moved out
of `handlers.rs` into `dispatch_single` (`src/gateway/server/mod.rs:1656`), which `run_stdio`
(`:1495`) routes every request through. The mechanism is not a check that runs ahead of
`MetaMcp::handle_tools_call` — it is the confirmation channel the dispatcher hands that call.
`dispatch_single` builds the `tools/call` context with
`ConfirmationChannel::Unavailable` (`:1750`), on the stated ground that stdio speaks to one
process over two pipes and has no elicitation channel, so no operator exists for this
transport to ask. `handle_tools_call` routes every call through
`destructive_confirmation_gate` (`src/gateway/meta_mcp/mod.rs:1389`, defined `:1614`), which
sees an unavailable channel and refuses with `-32001` instead of executing (`:1656`). The two telemetry rows are unchanged: over stdio both
migration records are still absent.

CONFIRM.1a is the reason this cluster is not filed under telemetry. Two of the rows are a
missing record; the third is a security control that reached only one of two shipped
transports until this change. The HTTP half was always evidenced — it was a reachability
gap, not a broken gate.

The design starts from an argument the code already makes. The stdio arm withholds admin
capability on the ground that the client *spawned* the process and so already holds whatever
the operator holds. That reasoning is sound for authorization and does not carry to
confirmation: a confirmation gate asks whether a destructive act was *intended*, which is a
question a fully privileged caller can still answer wrongly. The design must say so explicitly
or it will be re-litigated at review.

Design first, and it is one design: where the shared dispatch seam belongs, whether stdio grows
the same middleware or the gate moves below both routers, and what either does to an existing
stdio deployment that has never been asked to confirm anything.

### Residue from the ledger splits (rollup residue)

`MIK-6704.IDENT.1a`, `MIK-6865.SCHEMA.1c` and `MIK-7215.CONTROL.3a` became blocking when their
parents were split, and they are grouped only by that shared origin — nothing else connects
them. Each is a clause the parent's evidence does not hold. IDENT.1a is the clearest: deriving
authorization from the authenticated credential is implemented and consumed (`principal_of`,
`src/gateway/auth.rs:38-43`) and all three IDENT.1 tests prove the negative clause instead,
now scored as `IDENT.1b`. A test, not a mechanism.

Sequenced last of the design-free work, and deliberately not merged into a cluster they do not
belong to.

The letters here are this file's own. The blocking rollup groups the same rows under its own
scheme for its own purpose, and the two do not correspond; the criterion IDs are what join them.

### The fifteen blocking NFR rows are placed by wave, not by cluster

The clusters above are ticket work. Not one NFR row appears in them, and the heading
"Clusters, in dependency order" reads as though it covered everything — it covers 37 of the 52.
An NFR row mostly verifies a property of a mechanism some cluster builds, so it cannot be
scheduled independently of that cluster; the four that stand alone are the exceptions.

| row | where it lands |
|---|---|
| SEC.2, SEC.3, SEC.4, PERF.3, OBS.4 | with MRTR — each verifies the continuation envelope, and none can be written against an unwired path |
| OBS.3 | with era detection — there is nothing to observe until it lands |
| OBS.1, OBS.2 | the stdio dispatch path, above |
| COMPAT.1 | with MIK-7272 — the ABSENT clause is the modern revision being served at all, which the `server.modern_protocol` default gates and B's work unblocks, not a separate task |
| PERF.1, PERF.2 | wave 0, measured 2026-09-03 on `spark`. PERF.2 is MET; PERF.1 stays open as PARTIAL — the harness yields no P50 or P99, and only an end-to-end comparison against a 3.5.0 binary does |
| PERF.4 | wave 1 — the operator's ruling left the ceiling standing and the counting mechanism undecided |
| SEC.1 | wave 3 — twelve of fifteen controls carry a refusal test; two remain, and one is blocked on files another session owns |
| SEC.6 | wave 3 — one test on the MIK-7262 early return, plus a ruling on whether an unlabelled fix counts as closed |
| COMPAT.4 | last — the dual-role matrix grades every other row, so it is written once the rows it grades are settled |

Nine of the fifteen therefore have no schedule of their own: they land when their cluster does,
and a cluster is not done until they read MET. The other six are named in a wave above.

## Order of work

**Wave 0 — the NFR sweep.** Done on 2026-09-01: all 22 rows exist and all 22 are assessed
against the verification method the requirements table names for each. NFR.SEC.5's four
command gates were run and it is met; NFR.SEC.6 remains open on MIK-7249 and MIK-7262, which
have no reference anywhere in `src/` or `tests/`.
Alongside them, NFR.PERF.1-2 were recorded ABSENT rather than unassessed, because they needed a
latency measurement against 3.5.0 that no read of the source could close. That run happened on
2026-09-03 and moved PERF.2 to MET and PERF.1 to PARTIAL; see `RELEASE-4.0.0-performance.md`. The six that
verify the continuation envelope and era detection are NOT in this wave — they follow their
clusters. This wave changes the size of every wave after it, which is why it runs first
rather than last.

**Wave 1 — designs only, no code, all parallel.** C, F, I, the design-first half of B,
and NFR.PERF.4's counting decision, which the operator's ruling converted from a question
about the ceiling into a question about the mechanism.
Each is a §P1 note reviewed by two vendors before an edit. This is the wave that decides
things, and it is the one most likely to be skipped under release pressure.

**Wave 2 — cleared.** ERROR.2, RESULT.2 and HEADER.5 are met. Nothing is queued here; the
heading stays so the wave numbering below does not silently shift.

**Wave 3 — implementation behind a reviewed design.** Response-cache keying (MIK-7213) is the
only cluster whose design *and* test plan have both cleared dual review — 2026-09-03, both legs
`process_status: ok`, both SHIP-WITH-FIXES — so it is the one item here that can start on code
today. HEADER.9 follows era detection; CONTROL.4 depends on nothing and can move earlier if a
slot opens. The ledger-split residue is tests against mechanisms that already exist and fills
any slot. The stdio dispatch path lands here too, and its confirmation-gate half should not be
the part that slips: it is the only row in the set where the gap is a security control rather
than a missing assertion.

**Wave 4 — the long pole is now MIK-7272, not MRTR.** The continuation envelope is wired,
redeemed on the tool-invoke path and green (`redeem_retry`, `src/gateway/meta_mcp/invoke.rs:529`,
called at `:1301`; 18 + 25 passing at `b5d4ce7f`). Its fourteen remaining rows are EVIDENCE over
a path that exists — recorded runs and the five NFR rows that verify it — not mechanism, which
is why they can be produced alongside other work rather than gating it. CONFIRM.2 follows it.
What is left with no design, no test plan and no code is the revision surface (MIK-7272, seven
rows, five separate half-wirings) and era detection's `NFR.OBS.3`. Those are the schedule now.

**Wave 5 — the two measurements.** `NFR.PERF.1` needs a P50 and a P99 that the component
session on `spark` could not produce: no wire, no backend, no queue, therefore no latency
distribution. Only an end-to-end comparison against a 3.5.0 binary closes it. `NFR.COMPAT.4`
needs the dual-role matrix run. Neither turns on any other cluster, and neither can be
satisfied by reading source, which is why they are last and why they must not be discovered
last.

**The one-line flip that is not a one-line change.** `NFR.COMPAT.1` is `server.modern_protocol`
defaulting to true (`src/config/mod.rs:1174`). The operator ruled on it 2026-09-02. It cannot
land before the revision surface does, because default-on turns every gap there into a
first-run defect rather than an opt-in one.

Ownership: `src/protocol/continuation.rs`, `src/security/firewall/` and their test files are
touched by other sessions. Coordinate before editing them.

## Open for the operator

Four decisions are the requester's, not the team lead's, and are recorded here rather than in the
design that raised each one so they survive a session boundary. None blocks the work that does not
turn on it. Each names what changes either way, so an answer costs a sentence.

**1. SUB.2's second clause — RESOLVED against amending it; what remains is scheduling.** The
question was put to the operator on 2026-08-31 and came back as a question: what does the standard
require. It was checkable, and the check was a spec read. Answer, quoted from
`https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http`: a
server "**MAY** send JSON-RPC *notifications* — for example, `notifications/progress` or
`notifications/message` — before the final response", those notifications "**MUST** relate to the
originating client request", and "the final JSON-RPC *response* **SHOULD** terminate the stream".
The stdio page carries the same provision and no revision of the spec, in any of the three we
serve, permits a receiver to discard a message because it has no `id`.

That makes our two transports non-conforming today, independently of SUB.2's wording. `http/mod.rs:929-944`
returns the first `data:` line of an SSE response and discards the rest, so a conforming backend that
emits a progress notification before its result has that **notification returned as the `tools/call`
result**. `stdio.rs:416-431` drops every message without an `id`, which is every notification. Amending
SUB.2 would not make either legal; it would only stop the criterion from mentioning it. A stated limit
against a MUST is an unmet requirement, and here the MUST is the protocol's, not ours.

The work is smaller than "rewrite the transports". Revision 2026-07-28 **removed** server-to-client
requests from the stream entirely — "the server **MUST NOT** send independent JSON-RPC *requests* on
this stream", with sampling, elicitation and list-roots now embedded in an `InputRequiredResult`
(the MRTR pattern). So no bidirectional request routing is needed on the response stream:
read to the final response instead of stopping at the first event, and stop discarding id-less
messages. Two reads and a routing rule, not a redesign.

It also **eliminates** SUB.2's routing design rather than patching it. Correlation is by the stream,
which is scoped one-to-one to the request that opened it — there is no request key to route by, and
building one would invent a mechanism the protocol already provides. MIK-7272's design must drop
that clause, not shrink it.

Both follow-on questions were checked on 2026-08-31 and only one of them was a worry.
`Last-Event-ID` resumability is implemented and already gated correctly: `get_era_refusal` runs first
in `mcp_sse_handler` (`handlers.rs:262-264`) and returns `405` to any caller declaring the modern era,
so the replay code at `streaming.rs:241-386` is unreachable from a 2026-07-28 peer, and the modern
`subscriptions/listen` stream carries no event ids at all (`streaming.rs:416-459`). Nothing to do.

The compatibility question is the real one, and it is larger than "read past the first line". A
server-to-client *request* — which 2025-06-18 and 2025-11-25 both permit and we serve both — does not
fail to parse. It parses **successfully into an empty response**. `JsonRpcResponse`
(`src/protocol/messages.rs:44-56`) carries no `deny_unknown_fields` and holds `result` and `error` as
bare `Option<Value>`, so `{"jsonrpc":"2.0","id":5,"method":"sampling/createMessage","params":{...}}`
deserializes into `JsonRpcResponse{id:Some(5), result:None, error:None}` with `method` and `params`
silently discarded. On HTTP the mis-parsed request is returned to the caller as the answer to their
call. On stdio it is worse: `handle_response` looks the id up in `self.pending`
(`stdio.rs:210-219`, `:416-434`), so an unrelated in-flight caller that happens to hold that id is
**completed with an empty result**. No test on either transport exercises a line carrying both a
`method` and an `id` (`stdio.rs:628-700`).

That relocates the fix. The defect is not two independent transport bugs but one permissive type
used as a parse target on every read path, so a guard added in each transport would leave every
other caller of `JsonRpcResponse` still able to swallow a request. Dispatch by message shape before
parsing as a response, once, where all readers pass through.

**2. SCHEMA.1b — what happens to a backend that publishes an invalid schema.** The criterion says
tool schemas MUST remain valid under JSON Schema 2020-12, unqualified, and the gateway republishes
proxied backend schemas. Three postures: refuse the backend, publish and flag, or degrade the
schema. The row now reads MET on a test that enumerates the schemas `MetaMcp::handle_tools_list`
emits — which scopes backend-supplied schemas OUT without saying so, and leaves a stated limit
against a MUST. An unmet requirement in a MET row's clothing, until this is answered.

**3. ~~Whether 2025-11-25 clients are still served.~~ RESOLVED against the code, and it moved the
release gate.** The `tasks` capability types are dead, not a hazard: `ServerCapabilities.tasks` is
`None` in every response the gateway builds, so a 2025-11-25 client is told "no task support", which
is what capability negotiation is for. Nothing mis-serves anyone and deleting them buys nothing this
release needs.

The audit found the real gap one level up, and the first reading of it was wrong. `SUPPORTED_VERSIONS`
(`src/protocol/mod.rs`) lists four legacy revisions and omits `2026-07-28`, and this plan used to
call adding the string the release gate. It is not: `initialize` is legacy-only in this revision
([lifecycle](https://modelcontextprotocol.io/specification/2026-07-28/basic/lifecycle) scopes the
handshake to "`2025-11-25` and earlier"), so a modern client never negotiates through it and the
constant must stay as it is.

The gate is the `server.modern_protocol` default, defined once in
`docs/requirements/RELEASE-4.0.0-blocking-rollup.md` under "The two gates that are not rows",
together with the specification citation that settles the constant. That paragraph is the
definition; this one must not restate it.

The interim behaviour is conforming, checked rather than assumed. Both 2025-06-18 and 2025-11-25
carry identical version-negotiation text: "If the server supports the requested protocol version, it
MUST respond with the same version. Otherwise, the server MUST respond with another protocol version
it supports. This SHOULD be the latest version supported by the server", and separately, "If the
client does not support the version in the server's response, it SHOULD disconnect"
(https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle#version-negotiation).
`negotiate_version` echoes on an exact match and otherwise returns `PROTOCOL_VERSION`, which is the
newest entry of `SUPPORTED_VERSIONS` — both halves satisfied, and the mismatch burden sits with the
client by design. So a 2026-07-28 client today is told `2025-11-25` and should disconnect: the
gateway refuses the revision it cannot serve instead of silently mis-serving it, which is the
outcome the constant's comment was protecting. Nothing to fix before the flip.

Within the legacy tier the compatibility question is smaller than it looked. `build_initialize_result`
(`meta_mcp_helpers.rs:144`) uses the negotiated version for the `protocol_version` string and nothing
else; `handle_tools_list_with_url_override` and `handle_tools_call` (`meta_mcp/mod.rs:1222`, `:1252`)
take no version parameter at all. One behaviour is served to all four legacy revisions. The hard fork
is legacy-versus-modern in `classify_request` (`handlers.rs:660-920`), not per-revision.

**4. What the direct route needs, now that reachability is settled.** The two-route question was
half a code fact and nobody had read the code. `backend_handlers.rs:724` says the direct
`POST /mcp/{name}` route bypasses `invoke_tool_traced`, and `:594` says it keeps no per-user cache,
so the cache, idempotency and chokepoint machinery sits on the meta-MCP surface alone and the second
door is out of reach by construction, not by assumption. That half needed a source read, not an
operator. Two clauses survive it and are genuinely yours: whether the direct route should get its
own instrumentation rather than merely being out of the shared path, and whether CACHE.1-4 bind on
HTTP only or across all transports — the second moves where stdio exits and nothing else.

**5. ORDER.2 — RESOLVED by adopting the issue-449 design; the release absorbs it.** The question
looked like "may per-session routing profiles be removed", and it was asked in that form on
2026-08-31. That framing was wrong, and the operator caught it: the work already exists.
`docs/design/2026-08-31-meta-tool-exposure.md` answers GitHub issue 449 (Bruce-Poating, open,
"allow operators to trim the exposed `gateway_*` meta-tool surface"), and both vendors reviewed it
and rejected its first shape — an operator-configured allow-list — in favour of an
**authorization-derived** surface. Its `449.EXPOSE.1-7` are superseded; `449.DERIVE.1-9` replace
them.

That shape is what `ORDER.2` permits in its own text: the tool set MUST NOT vary per connection but
MAY vary by the authorization presented on the request
(`docs/requirements/RELEASE-4.0.0-requirements.md:128`). So the conforming answer and the answer a
user asked for are the same answer, and it is already designed and reviewed.

**Decision (operator, 2026-08-31): implement `449.DERIVE.1-9` inside v4.0.0.** Profiles are not
removed — `449.DERIVE.5` lists the profile tools only when routing profiles are configured. The two
options this closes off are recorded so they are not re-proposed: shipping the modern path
profile-blind while legacy keeps profiles (leaves two behaviours and a restatable finding), and
holding `ORDER.2` open (ships a knowingly non-conforming release).

*What this costs, stated plainly:* nine acceptance criteria move into the release, and `tools/list`
has no caller context today, so that plumbing is real work standing between here and the version
flip. *What it retires:* the `gateway_set_profile` stale-list defect — a profile change never fires
`notifications/tools/list_changed`, so clients are handed a stale list today.

## One commit's history is wrong, and it is staying that way

`b55116d1 docs(cluster-f): plan the response-cache keying tests as tests` contains, besides its
cluster-F plan, four `src/` changes that belong to the protocol mis-parse repair: the extraction of
`parse_sse_response` (`src/transport/http/mod.rs:273`) and the three tests that fail against the
current deserializer — `response_deser_rejects_frame_carrying_method`,
`message_enum_still_classifies_both_frame_shapes` and
`handle_response_rejects_inbound_request_and_leaves_caller_pending`. They were swept in by a
whole-tree stage from a session that did not own them. Nothing was lost and the fix is not in that
commit, so the branch was red from `b55116d1` onward.

That red window is closed, and not by the repair. `88532501 revert(cluster-f): cut the sampling-frame
hunks that rode the test-plan commit` restored all four files to their content at `b55116d1^`, so the
tests are out of the tree and the build is green again. Two of the three review vendors caught the
breakage independently, which is what a review is for. The cost landed on a third party: the restore
also discarded the uncommitted repair another session had in those same files, because a checkout of
a path does not distinguish work that arrived by a bad stage from work being written on top of it.
Explicit-path staging was supposed to be the answer to the first incident and it is no defence
against this one — the two failures run in opposite directions through the same shared checkout.

What the pair of them actually says: a test that fails on a shared branch is not evidence of
discipline, it is a broken build every other session has to work around, and it invites exactly the
restore that then eats somebody's afternoon. Tests are written before the fix and run red **locally**;
the commit that reaches the branch carries both halves and is green on arrival. SUB.2 now lands that
way — five tests and the shape check in one commit. The tests survive verbatim in history at
`b55116d1` and are recoverable with `git show b55116d1:<path>`.

The history is not being rewritten. Several sessions hold this branch checked out, and rebasing
underneath them costs more than a wrong commit message does. What the rewrite would have bought is
bought here instead: a reader who bisects into the red window, or who wonders why tests for a
protocol defect arrived inside a caching plan, has the answer without having to reconstruct it. The
repair commit names the same thing from the other end.

Staging by explicit path — never `git add -A`, never `git commit -a` — is now the rule for every
session on this branch, and `git status --porcelain` before each commit is what enforces it: a
modified file you did not touch is somebody's work in progress, and committing it is not tidiness.

It happened a second time, in the other direction, and the rule as written does not stop it.
`e7448fc9 docs(cluster-g): close the confirmation pass` carries the cluster-B connection-invariance
test plan's review repairs — 219 insertions the cluster-G session did not write. That session staged
by explicit path. So did the cluster-B session, moments earlier. **The index is shared across every
worktree on this branch**, so a file staged by one session and not yet committed is picked up by the
next session's commit whatever paths that commit names. Explicit-path staging protects the other
sessions from you; it does not protect you from them. What does: stage and commit in one step, close
together, and re-read `git log -1 --format=%H -- <your path>` afterwards rather than trusting that
`git commit` reported your own work. Again not rewritten, for the same reason — sessions are live on
this branch, and a wrong author line costs less than a rebase underneath four of them.

## What would make this plan wrong

- ~~If TASK.1 is dropped from v4.0.0, SUB.4 loses its alternative branch.~~ CLOSED: the operator
  directed the full scope on 2026-08-31, so TASK.1 ships in v4.0.0 and SUB.4 keeps both routes.
  The design says how the two coexist, not which one wins.
- ~~If the two-route assumption is wrong, OTEL.1 and SUB.4 both shrink.~~ CLOSED for reachability
  on 2026-08-31 by reading the source rather than asking: the direct `POST /mcp/{name}` route
  bypasses `invoke_tool_traced` (`backend_handlers.rs:724`) and holds no per-user cache (`:594`),
  so the shared machinery cannot reach it whatever the scope decision says. The assumption had been
  carried through three designs unread. What is still open is narrower and is item 4 above: whether
  that route deserves its own instrumentation, and whether CACHE.1-4 are HTTP-only.
- If the era cache should be keyed per pool slot rather than per backend name, era detection's
  DISCOVER.5 changes by one field, one lookup and one section. It is keyed per backend NAME on the
  team lead's call, provisional and not operator-confirmed: era is a property of the peer process,
  and every slot of one named backend dials the same command or URL, so per-slot keying means one
  probe per user slot against the same remote. The named residual is that one slot's mis-detection
  reaches its siblings; DISCOVER.5's re-probe half is what pays for it, and per-slot has no
  equivalent.
- If MRTR slips, CONFIRM.2 slips with it and MRTR.10a's key contents stay open, which leaves
  SUB.4 implementable but not fully specified.
