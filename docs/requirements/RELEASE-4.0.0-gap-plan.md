<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# 4.0.0 release: gap assessment and plan to shippable

Assessed 2026-08-30 by four independent audits (requirements-vs-code, unwired production paths,
test-plan coverage, docs and release mechanics). Every gap below was verified by reading source,
never inferred from a document. The requirements sweep has since run to completion -- section 1
carries its final counts, and they amended the totals without invalidating the sequence.

A second audit died on an output ceiling partway through emitting its rows. What
it had produced is recovered in `RELEASE-4.0.0-audit-partial.md` and is a floor
on the blocking count, not a total: at least eight of its findings sit outside
MRTR entirely, which is the first measured evidence of how far section 2 was
undersized. Section 2 now carries them as increments 10-17.

## 1. Where the release actually stands

The 2026 protocol surface is **advertised but not reachable**. `discover_document` announces
`MODERN_VERSIONS` once `modern_protocol=true`, and the retry that the announcement invites is
refused at the door.

| gap | evidence | blocks |
|---|---|---|
| MRTR is unwired end to end | `handlers.rs:879-895` returns -32602 "retry forwarding is not available on this build" for every retry | MRTR.1-.10 |
| Legacy-client bridge never called | `Bridge::to_legacy_client` has no caller | MRTR.7 |
| Outbound era probing unwired | `EraCache::resolve_with`/`classify` implemented and tested, zero callers in `src/backend` or `src/transport` | outbound modern/legacy negotiation |
| Tasks extension is dead code | `protocol::tasks::Task`/`TaskStatus` have no production call site; `tasks/get`/`tasks/update` fall through to method-not-found honestly | nothing — needs a keep/delete decision |
| Header/result/error/cache/order criteria | six gaps found, six criteria confirmed clean | see requirements sweep |
| Blocking criteria outside MRTR | tenancy, stateless confirmation, session expiry, log correlation, cache invalidation, error codes, tasks, extensions and discovery. The count is not quoted here — it moved twice while this row said otherwise | increments 10-17; source rows in `RELEASE-4.0.0-audit-partial.md`, live count from `scripts/release/count-release-criteria.py --check` |
| Diff coverage under floor | 61 branch-touched files average 77.40% lines against an 80% Standard floor; mutation coverage unmeasured. Measured before increments 1 and 2a landed their tests, so it is a starting point, not the current number | DoD §4 |

Test position, separately: six acceptance criteria have no case at any level, two cases cannot fail
against the defect they are attached to, and the existing `tests/mik_7212_acs.rs` exercises
primitives directly rather than the dispatcher — so it stays green whatever the wiring does. The
test plan says this itself at lines 327-330.

Re-verified on 2026-08-31 against the current tree: the retry refusal, the uncalled
`Bridge::to_legacy_client`, the zero-caller `EraCache` and the dead tasks extension all still hold
exactly as the audit described. Only the continuation-state row had gone stale, and it is removed
above. One in five of the section 1 rows re-read that day
had moved, and it moved because the work was done, not because the reading was wrong. That is a rate
over five rows, not over the audit.

### The completed sweep: the blocking rows do not cost the same

Every criterion in `RELEASE-4.0.0-requirements.md` now has a row in
`RELEASE-4.0.0-criteria-status.md`. That file's headline states the totals and
`scripts/release/count-release-criteria.py --check` recounts them from its tables, so the number is
not quoted a second time here — this section quoted `31 blocking` against a 77-row ledger and was
still saying so at 99 rows. The audit's "at least eight outside MRTR" was a floor, and the
figure that replaced it went stale in turn. SUB.1's GET clause and SUB.3 came off the list on
2026-08-31 when the `GET /mcp` era gate landed; what they left behind is a ledger row count,
not a number this file restates.

| status | what it means | the work |
|---|---|---|
| UNWIRED | the code exists and has zero non-test callers | find the production path, call it, test through it |
| ABSENT | no implementing code at all | design, test plan, failing tests, implementation |
| UNTESTED | wired, but no test crosses the production path | write the test -- and expect some to go red |

The per-status counts that stood here are gone for the same reason the total is: they were
transcribed, they went stale, and the ledger derives them on demand. The classes are the part
worth keeping.

Reading UNWIRED as the easy pile is the trap. A symbol is unwired because nobody could see where
it belonged, so wiring it is a design question in plumbing costume. UNTESTED is the only class that
can produce a *new* defect rather than a known one: a test that has never run against production
is a chance the row itself is wrong. **Take whatever rows the ledger currently reads UNTESTED
first.** A red one moves a row from "needs a test" to "needs a fix", and learning that after the
ABSENT increments are scheduled is learning it too late. The membership of that set moves as rows
close, which is why it is not listed here — `RELEASE-4.0.0-criteria-status.md` is the list.

The per-ticket split lives in `RELEASE-4.0.0-blocking-rollup.md`, which derives it and is checked
against the ledger total.

Four further rows read MET with a qualifier -- `MET (I)`, `MET (caveat)`, `MET (residual)` -- and no
blocking count includes them, which is exactly where work hides.

| row | what the qualifier holds | disposal |
|---|---|---|
| `DISCOVER.7` | `src/lib.rs:23` still lists `2024-10-07` in a crate doc-comment | one-line deletion; do it with the DISCOVER wiring |
| `DISCOVER.1` | the stdio arm passes `modern_enabled: false`, so a stdio client sees the legacy tool list | self-documented at `src/gateway/server/mod.rs:1687-1693`; decide before release whether stdio ships modern |
| `ORDER.3` | the classification is on record, the remediation it prescribes is not | already counted as ORDER.2 |
| `CONTROL.5` | every removed mechanism names a replacement; two replacements are not built | already counted as CONTROL.2 and .3 |

Two of the four are already counted as blocking rows in the ledger. The other two are small. Neither is a reason to add a
status to the vocabulary: fix them and the qualifier goes away.

Shared checkout, 2026-08-31: other sessions hold uncommitted work on MRTR
(`src/gateway/meta_mcp/`, `tests/mik_7212_acs.rs`), TENANT (`src/security/firewall/`) and
CONTROL.2 (`tests/mik_7215_control_2_budget_acs.rs`). Those increments wait on the holding session;
their files are not ours to stash or clean.

Release ready means every blocking row reads MET with a file:line for production code and a
file:line for a test reaching it through a production path. Not "implemented", not "tests pass".
Two things that does not promise: the clean MET rows are not guaranteed to hold, since wiring the
unwired symbols touches paths they cover, so the full suite gates every increment; and the count is not
guaranteed to fall monotonically, because an UNTESTED row that goes red splits into a defect and a
test.

### Observed while closing the first UNTESTED row

Eight integration-test files each hand-build the same ~45-line `AppState` fixture
(`mik_7213_acs.rs`, `mik_7214_acs.rs`, `mik_7215_acs.rs`, `mik_7217_acs.rs`,
`mik_7272_subscriptions_acs.rs`, `mik_7312_continuation_state.rs`, `stdio_tests.rs`,
`webui_management_tests.rs`). Every new field on `AppState` is therefore an eight-file
edit, and the CONFIRM.1 test below was written into `mik_7215_acs.rs` rather than beside
its sibling unit tests purely because that is where a usable harness already existed.

Recorded here rather than filed: no criterion depends on it, and the remaining rows
will each land in one of these files, so the right moment to extract a shared fixture is
after the sweep, when the field set has stopped moving. Extracting it now would conflict
with every in-flight increment.

## 2. The sequence

Each increment is independently reviewable and mergeable. Delivery order within every increment is
the standing one: failing tests first, then implementation, then dual-vendor review.

**1 — Continuation state has one owner (S). DONE — closed MIK-7312.** Re-read of the source on
2026-08-31 found this already landed, so the audit row that reported no production owner was written
against an earlier tree and has been removed from section 1. `ContinuationState`
(`protocol/continuation.rs:664-742`) owns the keyring, ledger and in-flight table behind one
lifecycle, generates its key material and replica name per process, and is constructed in the
production `AppState` builder at `gateway/server/mod.rs:1171` — not under `cfg(test)`. Both test rows
this increment asked for exist in `tests/mik_7312_continuation_state.rs`: reachability from an
`AppState`, and a token minted by one `AppState` refused by another. The reachability test builds its
own `AppState` with the same `ContinuationState::new()` call the server makes rather than invoking
the server's builder, so it proves the state is usable through the struct, not that production
constructs it. That second half is evidence from reading `server/mod.rs:1171`, and a test could only
carry it by driving `serve` itself. Design recorded in
`docs/design/2026-08-30-shared-continuation-state.md`. Nothing is left to do here; increment 2b is
the next open item.

**2a — The mint site can see who is calling (S). Reviewed and shipped.** Both vendors returned
SHIP on `ddf12582`: GPT-5.x on the confirmation pass, Grok on the first. Neither found a behaviour
defect. What they did find was three stale citations and one missing test, all repaired here: the
seam table pointed at the wrong two arms of the retry branch (the `is_retry` arm is
`handlers.rs:879-896`, the `is_malformed` arm that stays is `867-878` -- the reviewer's own repair
was a line short on the second, which is why a cited line gets re-read rather than copied), a design
paragraph cited the `client_info_name` docs for a rule that lives eight lines above them, and the
method's doc comment named a false case no test constructed. That last one is the only defect of the
four that could have reached a user: a mutant flipping the malformed arm to `true` would have
survived, because production returns on a failed classification before the field is read and so
never exercises it.

Line citations have now drifted three times in this document. The seam-table rows name their arm
predicate as well as their range, so the next drift is self-correcting rather than misleading.

No behaviour change, so the existing suite
green before and after is the evidence. Review added five tests anyway, on the capability string the
new `RequestShape::may_request_input` compares against: a typo there compiles and reads as a
correct no-op, so the string needs a test even when the caller of the method does nothing yet. `invoke_tool_traced`
takes `caller: &MetaMcpCallerContext<'_>` in place of its six flattened caller fields, and the
client's declared capabilities reach the scope where that context is built. Two source facts make
this mechanical rather than a design question: `invoke_tool` already takes the context whole, and
the comment at `invoke.rs:419-421` gives the reason in the codebase's own words — the authorizer
travels with the identity it authorizes. `invoke_tool_traced` is private with exactly one call
site. The alternative, two more loose parameters taking it from eleven to thirteen, is rejected by
that same comment.

**2b — Retry reaches the backend (M).** Closes MRTR.1, .2, .3, .9, .10. Delete the `is_retry` arm at
`handlers.rs:879-895` and leave the malformed-envelope arm above it alone; open the envelope, forward
retry fields to the backend as siblings of `arguments` rather than merged into them, mint at the
call site after the result, pass `complete` and legacy results through unchanged. Inbound
`RetryFields` is attacker-controlled client shape and the outbound state is the backend's own
opaque value recovered from the token — conflating the two is the MRTR.2 defect, so they stay
separate types. One defect drives the increment: an `input_required` result is today neither a
success nor an error, so it falls through the `mark_completed` at `invoke.rs:1276` and is cached as
a final answer. MRTR.10 has a second half on the same path: `resolve_idempotency_key`
(`support.rs:31-46`, called from `invoke.rs:779-790`) derives the key from server, tool and
arguments alone, so two retries carrying different `inputResponses` collide on one key and the
second is answered from cache. A sweep note calls that a different call path from `tools/call`;
reading the call site shows it is the same one. The fix must cover both branches of that helper:
an explicit client-supplied `idempotency_key` returns at `support.rs:38-43` before the derivation
runs, so extending the derivation alone leaves a client that reuses its own key colliding exactly
as before. Either both branches carry the continuation fields, or the plan says a reused client
key is the client's problem — it cannot leave the question open. Tests: the integration rows the plan already names, plus a pass-through row and a
fresh-JSON-RPC-id row that a fixture transport can fail. Pass-through asserts value equality and
that no `requestState` key was added, not byte identity — the crate does not preserve key order.

**3 — Single-use and expiry hold across replicas (S).** Closes MRTR.5. Origin refusal precedes any
key lookup; typed and distinct from expired and already-spent. Tests: expiry on redeem with an
injected clock, two `AppState`s racing one token, redeem after the minting process is replaced.

**4 — No second exchange with a legacy backend (M).** Closes MRTR.6. Pin the continuation to a live
`InFlight` hold where the mint recorded one; a missing hold is a refusal. Tests: minted against a
live hold, redeemed on the origin after the hold is gone.

**5 — Legacy-client bridge (M).** Closes MRTR.7 — currently `NOT YET` by design with no test row at
all. Wire `Bridge::to_legacy_client`; decide and record what a legacy client sees when a modern
backend asks. Tests: the whole row set, which does not exist yet.

**6 — Outbound era negotiation (M).** Wire `EraCache` into backend connection setup so outbound
calls probe rather than assuming legacy. Not previously tracked; found by the wiring audit.

**7 — Request binding and per-scheme fingerprint (S).** Closes MRTR.4 properly: same tool with
different arguments is refused, and the fingerprint distinguishes API key, agent JWT and mTLS
callers. The current binding test is generic and one row cannot fail against a short-circuiting
comparison, by its own comment.

**8 — Tasks extension decision (S).** Keep as a documented placeholder or delete. A design event,
not a wiring fix — it needs an owner's call, not an implementation.

**9 — Gate and release mechanics (S).** Raise diff coverage over the 80% floor on branch-touched
files, run mutation coverage and record it, reconcile the three disagreeing clippy invocations
across docs and CI, and add a local guard for the npm version rather than relying on the publish
step to overwrite it. Put the two operational consequences in the release notes: a retry against a
round-robin service is refused on every replica but the minting one, and a rolling restart
invalidates every outstanding continuation. The `docs/DEPLOYMENT.md` rewrite this increment
originally carried is already committed — its "Replica Count and `server.modern_protocol`" section
states the refusal, names the per-process key material as the mechanism, and rules out a
sticky-session workaround. Nothing is left to do there.

**Increments 10-17 come from the recovered audit rows**, which sit outside MRTR entirely. Each row
is the killed agent's claim with a file:line, verified here only as far as the cited location
existing — so re-reading the source is the first step of every increment below, not an optional
check. Sizes differ by more than an order of magnitude and that difference is the point: 10 is
plausibly a one-line change, 16 is a subsystem that does not exist.

**10 — Resource-not-found returns the code the spec names (XS).** Closes MIK-7272.ERROR.2.
`resources.rs:276-280` returns -32002 where the row says the spec requires -32602. Confirm the spec
text before editing — the requirement is the claim under test here, not the code. Tests: one row per
error path, and a check that no existing client contract asserts -32002.

**11 — The gateway declares its own extensions (S).** Closes EXT.1.
`ExtensionSet::gateway_declares()` at `protocol/extensions.rs:59-64` has zero callers, so the
gateway advertises nothing about itself while requiring declarations from clients. Wire it into the
initialize response; deciding what the set actually contains is a design question with a short
answer, not a wiring fix.

**12 — Transparency-log correlation is a real request id (S).** Closes MIK-7215.CONTROL.3. The
correlation key is the literal string it falls back to on every stateless request, because the live
`trace_id` is never passed in (`invoke.rs:1299-1314,429`). This lands next to increment 2a, which
already moves caller identity into that scope — sequence it after 2b so the two do not collide on
the same signatures. Tests: a stateless request whose log entry carries the request's own id.

**13 — Session expiry is reachable (M).** Closes MIK-7215.CONTROL.4. The `session_lifecycle` module
is declared at `gateway/mod.rs:19` and referenced nowhere else. Either wire expiry into the session
path or delete the module and record why — a declared-but-unreferenced lifecycle is worse than an
absent one, because it reads as coverage.

**14 — Cache invalidation on policy change (M).** Closes MIK-7213.CACHE.4. Invalidation is TTL-only
at `invoke.rs:835-839`, so a revoked grant keeps being honoured until the entry ages out. Needs a
policy epoch that participates in the cache key. Overlaps increment 2b, which already touches the
key derivation in that file; do 2b first and extend the same key rather than adding a second
mechanism beside it.

**15 — Destructive-op confirmation on the stateless path (M, design first).** Closes
MIK-7215.CONFIRM.2. Confirmation requires an SSE session today (`proxy.rs:213-260`) and the modern
stateless path has no session to hold one in. That is a design event, not a wiring gap: the question
is what a confirmation *is* without a session, and the continuation machinery from increments 1-4 is
the obvious candidate to carry it. Design reviewed before any code.

**16 — Cross-tenant data minimisation (L, requirements first).** Closes MIK-7215.TENANT.1. The audit
found no guard anywhere in `src/`. This is the only item in the plan with nothing to read, so it
starts with requirements rather than a design: what a tenant boundary means here, what crosses it
today, and what the criterion is actually asking for. It is the largest item and the one most likely
to move the release date — sizing it honestly is the first deliverable, not a commitment to build it
in this release.

**17 — NFR.SEC.6 owner decision (S, owner call).** MIK-7262 is open: the
`registers_external_callback` override is silently skipped for read-only, non-mutating and no-schema
methods (`capability/definition/mod.rs:1113-1152`). Shipping with a known bypass of an
external-callback declaration is an owner's decision in the same shape as increment 8, not something
an increment can close on its own authority.

**All eight cited locations re-read on 2026-08-31.** Six hold as the rows describe: the -32002
return, `gateway_declares` with its single definition and no caller, `session_lifecycle` declared at
`gateway/mod.rs:19` and referenced nowhere else, a cache key built only from server, tool, arguments,
projection and identity, `forward_elicitation_with_response` taking a `session_id`, and the
`registers_external_callback` check at `capability/definition/mod.rs:1150`. Two moved:

- **12 is smaller than S.** The live `trace_id` is in scope at the log call (`invoke.rs:1298`) — the
  `warn!` three lines below already uses it. The correlation key is the session id with a literal
  fallback, so the fix is an argument, not plumbing. Size XS.
- **16 is not a blank page.** Per-user backend pooling exists with stated isolation invariants
  (`backend/pool.rs`, IDP.3 and IDP.5) and cross-tenant isolation tests. The audit row's "no guard
  anywhere in `src/`" is wrong as stated. What the criterion asks — data minimisation across
  tenants — is a different question from backend isolation, and separating the two is now the first
  deliverable rather than writing requirements from nothing.

Two of ten rows checked across both passes were stale, both in the direction of the work being
further along than the audit recorded.

**18 — The destructive-confirmation gate governs every annotated tool (S, one design question open).** Closes
MIK-7246.CONF.3. `destructive_tools_from_annotations()` (`gateway/destructive_confirmation.rs:117`)
derives destructive tools from the `destructiveHint` annotation, is unit-tested, and has no
production caller — verified 2026-08-31, the only references in `src/` are its own doc comment and
its own tests. The live gate at `router/handlers.rs:1024` calls `is_destructive_meta_tool()`, which
is `matches!(tool_name, "gateway_kill_server")`. A backend tool shipping tomorrow with
`destructiveHint: true` inherits no gate.

The design decision this needs is already written down and does not have to be made again: the
doc comment at `destructive_confirmation.rs:143-147` says the two checks compose rather than
replace — the annotation is the source of truth for tools the gateway did not write, the match arm
is the floor for the one it did, so an annotation dropped by accident cannot quietly ungovern it.
So the shape of the fix is an `||` at the call
site rather than a redesign.

What that leaves open is availability, not semantics, and it is why this is not the XS it first
looked like. Checked on 2026-08-31: the gate at `handlers.rs:1024` has only `tool_name: &str` in
scope. `destructive_tools_from_annotations()` takes a whole `tools/list` payload, and `tools/list` is
served from a different match arm (`handlers.rs:834`, via `state.meta_mcp`). There is no derived set
at the gate to ask. So the increment carries a design question before it carries code: **where does
the annotation-derived set live, who populates it at list time, and what invalidates it when a
backend re-lists?** That is new state, the same class of question as the stdio-capability one
deferred out of increment 2a — and it is a cache over a security decision, so a stale entry
ungoverns a tool rather than merely slowing something down.

This is still the plan's cleanest example of DoD D7: the mechanism exists, the tests pass, and
production does not call it.

**19 — The unconfirmable-refusal test drives the router (XS).** Closes MIK-7246.CONF.4 properly.
The current test asserts `ConfirmationPolicy::for_modern().on_unconfirmable() == REFUSE` at the
struct level. That satisfies the criterion's literal text and cannot catch a call site that never
consults the policy — the same shape as increment 18's defect, one layer down. MIK-7214's suite
already has the pattern worth copying: real axum-router integration tests under its `mod http`.

**20 — The header contract's outbound half (M).** Closes the emission side of
MIK-7214.HEADER.2, the encode side of HEADER.4, and HEADER.5. Sized M rather than the S carried by
earlier drafts: the emission and encode work share one seam and are S together, and HEADER.5 adds an
unopened parameter-to-header path on top. Inbound validation is done and green
(`protocol/headers.rs:148-213`, wired at `handlers.rs:600-687`, mismatch to -32020, 32 tests).

This increment carried its own numbering defect, corrected here. Earlier drafts of this plan wrote
`HDR.2` and `HDR.4`, a local scheme that does not map onto the canonical criteria. In
`requirements.md` the identifiers are `MIK-7214.HEADER.1-6`, `x-mcp-header` is **HEADER.5** rather
than HDR.4, and **HEADER.4** is the sentinel-encoding criterion — "in both directions", which is
precisely the encode half this increment closes. The tests already use the canonical names
(`tests/mik_7214_acs.rs`, `ac_header_{1..4}`), so the drift lived only in the planning documents.
Same failure class as the `SESSION.*`/`CONTROL.*` mismatch recorded for MIK-7215.

Two things are absent, verified by search on 2026-08-31: outbound `Mcp-Method`/`Mcp-Name` emission
has zero hits in `src/backend` or `src/transport`, and `x-mcp-header` has zero hits anywhere in
`src/`. Both go through one seam — `build_mcp_headers` (`transport/http/mod.rs:544-637`), whose own
doc comment calls itself the single source of truth for outgoing request headers and which already
inserts `MCP-Protocol-Version`. `HeaderMode::Request` (`transport/http/mod.rs:249`) carries only
`method`, so the name value is not reachable at the seam yet; widening that enum is the change.
`encode_header_value` does not exist — `decode_header_value` (`protocol/headers.rs:79-98`) has no
counterpart anywhere in `src/`, which is the encode gap stated as code.

**Two more records overstate what shipped, and this is now the fourth and fifth case.**
`criteria-status.md:35` marks HEADER.2 MET on the strength of inbound validation. The criterion says
`Mcp-Method` MUST be required on *every modern request*, and the gateway is a client to its own
backends, so its outbound requests are in scope and carry neither header. `criteria-status.md:37`
marks HEADER.4 MET while its own evidence column records "decode-only, no encode/emit path found
anywhere in src/" — a caveat that contradicts the verdict beside it. Neither row is dishonest; both
read the criterion as the inbound half only. The plan's rule of thumb now has both directions
represented: rows claiming something is missing get re-read first, and rows claiming MET get checked
against the *whole* criterion, not the half the implementation covered.

**HEADER.5 is a MUST with no opt-out, so declination is not this plan's call.** Earlier text here
floated a recorded declination as a viable close. Re-reading the criterion at
`docs/requirements/RELEASE-4.0.0-requirements.md:104` — "Custom headers supplied through tool parameters (`x-mcp-header`) MUST be
accepted and forwarded" — there is no support-or-decide language in it; that reading came from
applying the development process's disposal table to a conformance criterion, which is not
something the criterion grants. RFC-0061:251 lists `x-mcp-header` in scope and records no
declination either. Building it is M, not XS: it is a new parameter-to-header path with no existing
seam. Dropping it is a scope reduction, and per the repair protocol that needs the operator's
recorded agreement before it happens, not a note afterwards. **This is the one open question in
this increment that no command can answer** — and it is already answered. The instruction governing
this plan is to fix all gaps "with the full scope", stated twice. That is a standing decision by the
person entitled to make it, covering exactly this class of choice, so HEADER.5 is **built**. Recorded
here as answered rather than assumed: asked of the operator, answered "full scope", and what it
changed is that the M-sized parameter-to-header path stays in this increment instead of becoming a
declination note.

Also to fix regardless of that decision: `tests/mik_7272_conformance.rs:194-201` bundles HEADER.1-6
under a single row claiming `x-mcp-header` support, on evidence that only covers the inbound
tests. That table currently self-reports coverage for a criterion with zero implementing code.

MIK-7214's own ticket comment dated 2026-08-30 says "no code implementing any part of the header
contract" and cites a search returning nothing. The code is there, wired and tested. That comment is
stale in the same direction as the two audit rows above, and it is the third such case: a written
record of absence has now been wrong three times in this plan's evidence base, always by claiming
less had shipped than had. The rows claiming something is *missing* are the ones to re-read first.

Increment 18 runs the other way and is worth naming as the opposite failure: there, the record says
a mechanism exists and the tests agree, and only the call site tells the truth.

### Three increments designed, and two were undersized

**2b is M, and the version this plan described would have shipped a silent no-op.** Replacing the
`is_retry()` refusal arm at `handlers.rs:879-896` cannot work alone, for two reasons verified at
source on 2026-08-31.

There is no envelope for a client to retry *with*. `Keyring::mint`, `Keyring::open` and
`ConsumedLedger::consume` have no call site outside `continuation.rs`'s own definitions and tests.
Nothing seals a continuation on the way out, so the outbound leg is a prerequisite, not a follow-up.

Worse, the naive fix fails quietly. The idempotency key is `derive_key("{server}:{tool}", arguments)`
(`support.rs:31-46`); the response-cache key is `ResponseCache::build_key(server, tool, &arguments)`
plus projection and identity suffixes. Neither carries a continuation identifier. A retry sends the
same server, tool and arguments and differs only in its answers, so it hashes to the original call's
entry — an entry already populated, because `invoke.rs:1265-1270` calls `cache.set` and then
`mark_completed` with no test of the result discriminator anywhere in that file (`rg -n
"resultType|input_required"` over it returns nothing). An `input_required` result is an `Ok(value)`,
so it is stored as final. Every retry then returns the stale first-round prompt and never reaches
the backend.

This increment was scoped against a double-side-effect risk. The real defect is availability, and it
is invisible — the client receives a well-formed response every time. The cache-key fix ships in the
same change or the feature is worse than the refusal it replaces. Held-open RPC for legacy backends
is explicitly out of scope and filed separately.

**18 has no cache, so the open question this plan recorded was the wrong question.** The destructive
set is derived at gate time from stores that already exist: compile-time meta-tool definitions, the
per-backend `tools_cache` read through the non-blocking `get_cached_tool()`, and the capability tool
set. The list path reads the same store at `surfaced.rs:130`, so gate and `tools/list` cannot
disagree by construction. `normalize_tool_annotations()` runs in the cache-fill closure, so every
cached tool carries `destructive_hint: Some(_)` and there is no absent-hint case to fail open on.

The shape is a `&self` method on `MetaMcp` composing the two checks exactly as
`destructive_confirmation.rs:143-147` already specifies, reached through `state.meta_mcp` — which
also dissolves the "only a `&str` is in scope at `handlers.rs:1024`" blocker recorded earlier here.
Fail-closed is scoped, not blanket: a name already admitted as callable whose tool cannot be
resolved right now counts as destructive. Blanket "unknown means destructive" would prompt on every
read-only call, and unadmitted names never reach a backend. `destructive_tools_from_annotations()`
keeps its name and takes the live store instead of a detached `Value` array — that detachment is
precisely why it has unit tests and no production caller.

Two questions here are the operator's and neither blocks the design. The stdio path
(`server/mod.rs:1711`) has no destructive gate and its own comment argues the spawning client
already holds operator authority; recording that as N/A-with-reason is the cheap disposal. And
TTL-only staleness for a re-listing backend is the same window `tools/list` already ships to
clients, where what goes stale is a courtesy prompt rather than the control.

**One citation died on inspection.** The 2b analysis placed `build_modern_response` at
`invoke.rs:1313-1348`; that file contains no `resultType` at all. The mechanism is real and lives
elsewhere. Worth recording for the ratio: of today's design findings checked at source, the
substantive claims held and the line numbers did not.

### The design review moved two increments and rewrote one requirement

Codex reviewed the 18/20/2b designs on 2026-08-31 and returned SHIP-WITH-FIXES. Its findings were
checked at source before being accepted; the six below survived, and one of them says the
requirement itself is wrong.

**Increment 20 rests on an outbound path that does not exist.** The design added header emission to
`transport/http/mod.rs` on the assumption that a modern request leaves the gateway. None does. The
transport still opens with a legacy `initialize` handshake carrying `protocolVersion` in `params`
(`mod.rs:430-452`), and `rg '_meta'` across `src/transport/` and `src/backend/` returns no JSON-key
hit at all: outbound requests carry no `_meta` envelope. HEADER.1 requires the emitted header to
equal `_meta.protocolVersion`, and outbound that field is not merely unset, it is unbuilt. The
`MCP-Protocol-Version` header at `mod.rs:570` is emitted from the legacy-negotiated version. So 20
must first consume an outbound era negotiation and construct the modern envelope, then emit the new
headers only on requests negotiated modern. Emission on a legacy peer is a regression, not a
partial implementation.

**`x-mcp-header` is not what this plan said it was.** The row read "custom headers supplied through
tool parameters MUST be accepted and forwarded". The specification says something else. From
`docs/specification/2026-07-28/server/tools.mdx:342-344`, the annotation "is placed directly within
the JSON Schema of the property to be mirrored", and its value "specifies the name portion of the
resulting `Mcp-Param-{name}` HTTP header". It is a backend's declaration on its own tool schema,
not a caller-supplied parameter. A client owes six MUST-level checks on it — non-empty, HTTP
field-name token syntax, no CR or LF, case-insensitively unique across the `inputSchema`, primitive
types only with `number` forbidden, integers inside the safe range — and a tool violating any of
them MUST be excluded from `tools/list` entirely.

That last duty is the one that changes the work. Excluding a tool is a change to the surfaced tool
set, which is the same store increment 18 gates on. HDR.4 is therefore not a plumbing task that
could be closed by a recorded declination; it is validation plus an exclusion rule sharing a seam
with 18, and increment 20 moves from S to L. Our own requirement text would have passed our own
tests while shipping a non-conformant client, which is what a requirement written from a summary
rather than the specification buys.

**Increment 20 also misses the notification path.** `HeaderMode` (`mod.rs:246-251`) has four arms —
`Sse`, `Request { method }`, `Notify`, `Close` — and the design widened only `Request`. Modern
notification POSTs would go out without the required `Mcp-Method`. The standard headers want
deriving once for every outbound JSON-RPC POST rather than per call site.

**Increment 2b needs a state, not just a key.** The cache-key discriminator recorded above is
necessary and insufficient. `input_required` is an `Ok(value)`, so it still enters the generic
response cache and still marks the idempotency record `Completed` (`invoke.rs:1260-1270`). An
awaiting-input result needs its own state: excluded from the response cache, and completed only
when the continuation finishes. Separately, an explicit `idempotency_key` bypasses derived-key
construction at `support.rs:31`, so a client reusing one operation key can never complete a
multi-round exchange — the continuation digest has to be appended after the explicit-or-derived
choice, not inside the derivation.

**One finding is real and deferred with its reason.** Continuation keys are process-local
(`continuation.rs:651`), so a retry landing on another replica, or arriving after a restart, cannot
decrypt. Single-process deployments are unaffected; this blocks multi-replica production, not the
release. Owner: deployment. Resolution: shared key material with an atomic consumed ledger, or
authenticated origin-routing. Trigger: before the first multi-replica deployment. If it resolves
badly, the fallback is pinning continuations to an origin.

The review also asked for three test surfaces the plan had not named: an end-to-end multi-round
matrix covering the response cache, both key forms, repeated rounds and replay; outbound header
generation checked against independent spec vectors rather than our own reading; and router-level
tests proving the destructive gate governs backend and capability tools while missing cached
metadata fails closed.

### The second reviewer shrank increment 18 and found the header bypass

Grok reviewed the same three designs and also returned SHIP-WITH-FIXES. Two of its findings change
the work, and the first of them contradicts what this plan recorded an hour earlier.

**Increment 18 must not govern backend tools yet.** The plan treated "every cached tool carries a
`destructive_hint`" as the reason there is no fail-open case. That is the defect, not the comfort.
`infer_destructive_tool()` (`backend/annotations.rs:71-82`) sets the hint by substring match on the
tool name against `archive, bash, clear, delete, forget, kill, login, post, remove, run, send,
submit, type, write` — so `send_email`, `write_file`, `run_query` and `create_post` are all
destructive by guess, not by a backend's declaration. `ConfirmationPolicy::for_modern()`
(`destructive_confirmation.rs:88-91`) is an unconditional refusal, deliberately, because the modern
revision has no session to elicit over. Composing the two would refuse a large slice of the tool
surface outright, with no path for a user to confirm, until the elicitation increment exists.

So CONF.3 closes on the compile-time meta-tool definitions plus the `gateway_kill_server` floor, and
backend and capability tools stay out until there is a confirmation path to send them to. The
increment gets smaller and its blast radius disappears. This is the second time in this plan that a
mechanism looked ready because its data was populated; the question worth asking of a populated
field is who wrote it.

**The header mirroring has an ordering duty.** `x-mcp-header` values reach the same seam that
`insert`s `Authorization`, `MCP-Protocol-Version` and session headers
(`transport/http/mod.rs:544-637`, overlaid at `:853-861`). The specification's mandatory
`Mcp-Param-` prefix is what keeps a declared name from colliding with a gateway-owned one, so the
bypass needs an implementation that drops the prefix — but the margin is one mistake wide. Mirrored
headers are applied before the identity headers, and hop-by-hop and gateway-owned names are dropped
regardless, so credentials win by construction rather than by ordering luck.

Grok also caught that outbound `Mcp-Name` must come from `mcp_name_body_field(method)`
(`protocol/headers.rs:59-64`) rather than a generic name slot, or `resources/read` emits `params.name`
where the spec wants `uri` — the same decoy-name confusion the inbound check was written to stop,
reappearing on the way out. And `ConsumedLedger::consume` should be called on a successful open in
2b: the method exists, is tests-only, and calling it stops a redeemed continuation being replayed on
the minting replica without waiting for the shared-key work.

Both reviewers independently found the `x-mcp-header` design under-specified, from opposite
directions — one that it was more than plumbing, one that it was a bypass. Two vendors converging on
one requirement row is the signal that the row, not the design, was wrong.

### Still open, and it will not resolve itself

The recovered audit is a floor, not a total. One row (SCHEMA.1, concerning `gateway_execute`'s
`chain` parameter) was truncated mid-emit and its finding is unrecoverable. Some criterion groups
were never reached at all, and the four-group sweep in `RELEASE-4.0.0-criteria-status.md` covers a
different, also partial, slice. Re-running the sweep to completion is a prerequisite for calling this
plan sized — not an increment, because its output changes what the increments are.

### The direct route is not exempt, and the requirement text says so

`POST /mcp/{name}` routes straight to one named backend. It bypasses `invoke_tool_traced`
(`src/gateway/backend_handlers.rs:724`) and keeps no per-user cache (`:594`), so on that path there is
today no trace propagation and no cache keying. Whether that matters looked like an owner question —
does the release's caching and tracing work bind on every transport, or only on the meta-MCP invoke
path? It is not an owner question. Both criteria answer it in their own text.
`MIK-7213.CACHE.4` binds "**any** shared cache the gateway keeps"
(`docs/requirements/RELEASE-4.0.0-requirements.md:126`) and `MIK-7272.OTEL.1` binds propagation
"across the gateway hop" (`:197`) — the direct route is a gateway hop and any cache behind it is a
cache the gateway keeps. Neither is scoped to a transport or to a handler.

So the direct route is wired, not excused: trace `_meta` propagates through it and any cache it grows
is keyed on the same request-derived inputs as the meta path. Removing the route instead would
eliminate the divergence at the source and is the cheaper diff, but it deletes a documented HTTP
surface, and no evidence has been gathered that nothing calls it — that is an owner decision and it
is not needed to satisfy the criteria. Wiring it is ordinary engineering and it is what the
requirements already ask for.

### The one decision the source cannot make

Three cluster designs are reviewed and carry a `SHIP-WITH-FIXES` verdict from each vendor: cluster B
connection invariance, cluster B capability and trace metadata, and cluster F response-cache keying.
Their findings are disposed inside the designs, so what remains there is implementation, not more
design rounds.

One item is not implementation. `MIK-6865.SCHEMA.1` requires that "tool schemas exposed by the
gateway ... remain valid under JSON Schema 2020-12"
(`docs/requirements/RELEASE-4.0.0-requirements.md:200`). The cluster G design scopes upstream backend
schemas out of the validity work and records that exclusion as a deferred unknown against a MUST,
not as a clean boundary
(`docs/design/2026-08-31-cluster-g-tool-schema-2020-12-validity.md:47,247`) — the population the MET
clause was measured over includes backend tools. What to do when a backend publishes an invalid
schema is a routing-policy choice with a user-visible cost either way: refusing the backend trades
availability for conformance, publishing it with a flag leaves the MUST unmet, and stripping the
offending subschema changes what the client is told a tool accepts. No specification settles it,
because MCP has no notion of a gateway aggregating backends.

The owner settled it on 2026-08-31: **drop the failing tool and keep the rest of the backend.** Each
backend tool's schema is validated at registration; one that fails is neither listed nor routable,
and the rejection is logged and surfaced in diagnostics. The cluster G design has withdrawn its
exclusion and carries the check, its scope receipt and the mixed-backend acceptance case. SCHEMA.1 no
longer has an open decision in front of it — what remains is implementation.

### The era design is reviewed, and both vendors found the same wall

`docs/design/2026-08-31-discover-outbound-era-probe.md` (revision 5) now carries a `SHIP-WITH-FIXES`
from each vendor, and the two findings are one finding seen from two sides. GPT: the unchanged
`EraCache` API cannot re-probe a cached era while preserving it on `NoAnswer` and atomically
rejecting a stale transport result. Grok: start-path fatal errors and the identity write-gate cannot
pass through `resolve_with` as it stands. Both name the same cause — the design froze the
`src/protocol/era.rs` surface and then specified safety properties that surface cannot express.

Under the repair protocol the response is elimination, not a patch: either the API gains a
conditional commit operation, or the safety claims come out of the design. Patching around a frozen
surface leaves the finding still statable, which is the test. Two consequences are already settled.
The 30s re-probe limiter belongs on `Backend` beside the cache, not inside `EraCache`, so the
surface has one owner. And the italic discriminator "would the next request on this transport fail
for the same reason?" is replaced by `Transport::is_connected()`, which exists — under the gloss a
live peer's HTTP 404 reads as a permanent failure, which would fail every legacy start the era table
was written to save.

Test row 9 moves to `HEADER.9`. It requires a request shaped for the modern revision, and modern
outbound shaping is explicitly out of this increment, so the row could certify a trigger no
production request can reach. Row 10 has the same shape and the design says so in its own last
column — "nothing probes, so this row passes vacuously on `HEAD`". A discriminating test that is
reachable both before and after implementation replaces it: two backends in one run, one answering
`-32602` and one `-32022`, asserted as a pair against a single fixture.

### `NFR.COMPAT.1` is owned by the `server.modern_protocol` default, and it is a dependency

`SUPPORTED_VERSIONS` (`src/protocol/mod.rs`) names four revisions and `2026-07-28` is not among
them, permanently: the 2026-07-28 lifecycle scopes `initialize` to "`2025-11-25` and earlier".
`MODERN_VERSIONS` (`src/protocol/meta.rs:219`) names the modern revision alone, for the stateless
path that serves it. `COMPAT.1` requires the modern revision be *served*, which the legacy list
cannot do and was never going to. The row's single gate is the `server.modern_protocol` default
(`src/config/mod.rs:1174`), today `false`. GPT's era finding reaches the same wall from the other
direction: a test cannot exercise a modern-shaped request while no modern request path exists.
Work that assumes a served modern revision is blocked behind the header and era increments, so
`COMPAT.1` is a dependency of them, not a parallel item.

### One clusterF finding is not yet disposed

The cluster F design's findings table runs R1-R9 and disposes both vendors' rounds. One later finding
is not in it: the design does not state reversibility, which the Definition of Ready requires as an
element. There are zero occurrences of `reversib`, `rollback` or `cache.enabled` in the design
(V, `rg` at `HEAD`). The rollback path exists and is cheap to state — `cache.enabled = false` for the
gateway cache plus zero capability-cache TTLs — together with the conditions for re-enabling it.
A second lead needs the design owner rather than a claim here: whether test row `4.f.1` can pass
without the epoch in the key when the grant insert happens before the warm. If it can, it is a test
that goes green while the property it guards is absent.

## 3. Not blocking the release

- Stale npm version in `npm/package.json:3` — CI syncs it at publish; the guard is hygiene.
- Homebrew formula staleness — `release.yml` regenerates it in the tap repo.
- Clippy invocation drift — cosmetic until a gate disagreement actually lets something through.

## 4. State on 2026-09-02 — what moved, what still blocks, and the order to finish in

Sections 1-3 were written on 2026-08-30 against a tree where cluster A had neither designs nor
code. Two clusters have moved since. This section records the delta and the sequence; it amends no
count in the ledger, which stays the source of truth for status.

### Cluster A — designs are done and reviewed; no implementation exists

Three documents now settle what the earlier audits found undefined, and each has a recorded verdict:

| document | settles | verdict |
|---|---|---|
| `docs/design/2026-09-01-mrtr7-legacy-client-bridge.md` | prompting a pre-round client on a backend's behalf | Grok `SHIP`, on a head the document has since moved past |
| `docs/design/2026-09-01-nfr-perf3-reclamation.md` | reclaiming abandoned in-flight exchanges, and how a soak observes it | GPT `SHIP-WITH-FIXES` (blocking finding repaired), Grok `SHIP` |
| `docs/design/2026-09-01-continuation-telemetry.md` | what each continuation counter means and what bounds each series | Kimi `SHIP-WITH-FIXES`, both findings repaired |

**Zero lines of MRTR implementation exist.** `handlers.rs` still refuses every retry, exactly as
section 1 records. The clusterwide claim "nothing mints or opens a continuation on the live path"
is unchanged — what changed is that the questions blocking that code are now answered in writing
rather than in one session's context.

Two review gaps are open and are stated rather than assumed closed. The bridge design's `SHIP` was
stamped against a head that predates the commit widening its refusal clause from "the variant being
asked" to "what is being asked", so the verdict does not cover the contract as it now reads; it
also has one vendor, not two. The telemetry design has one vendor. Both need a second leg at the
current head before any of this merges, and the pair is Grok plus Kimi until 2026-09-07, because
the GPT reviewer is usage-limited until then.

### Cluster B — the era prober is built and mounted, and still decides nothing

`src/backend/era.rs` exists and `Backend` carries an `Arc<EraCache>` that lifecycle resolves once
per start. That closes the "called from nothing" half of the cluster-B row in the rollup. It does
not close the cluster: **no request path reads the cached era to choose a request shape**, so
`DISCOVER.4` and `DISCOVER.5` remain blocking on the consuming side, and `NFR.OBS.3` still has no
counter.

Two lifetime limits of the cache are recorded here rather than filed, because they bound what the
consuming side may assume. The cache is per-`Backend` and shared across every `PoolKey` slot, so
under `session_mode = per_user` only the first slot probes and the rest inherit that answer; and
`force_restart` does not clear it, so a peer that restarts into a different era keeps its old
classification until the backend is rebuilt. Neither is a defect in the prober. Both are reasons a
consumer must not treat the cached era as a live fact about the current process.

### The order the remaining work runs in

Cluster A is the largest of the blocking clusters by a wide margin, so it goes first —
but the first step is not code. Per the delivery process the sequence inside A is a test plan with
one row per acceptance criterion, reviewed as a plan; then failing tests, reviewed as tests; then
implementation, which is done when they pass. Skipping to implementation is the path that produced
thirty-five review rounds elsewhere in this repo's history.

Three things can run alongside it without waiting:

- **Cluster E is measurement, not code, and it is Spark-only.** No run against 3.5.0 exists. It
  needs no design and blocks nothing else, so it can start immediately; a Mac number would be worse
  than no number.
- **Cluster B's consuming side** is a small change once someone decides what reads the era, and it
  is independent of the continuation envelope.
- **Cluster F is three operator decisions, not four pieces of work.** Whether
  `exposed_meta_tools` enforcement ships as a breaking change, whether a dual-role matrix is
  required, and whether the 17-tool scenario or the documented 14-16 ceiling is the one that moves.
  Each is a stated fact awaiting a call. They are the cheapest rows on the board and they are
  blocked on nobody writing code. The fourth — whether the modern revision joins
  `SUPPORTED_VERSIONS` — is decided and closed: it does not, because the handshake it belongs to
  does not reach the modern revision. What remains there is the `server.modern_protocol` default.

Clusters C and D follow A, because both need a served modern request path to test against — the
dependency section above already establishes that, and nothing since has changed it.

### One of cluster F's four decisions is now made

`NFR.COMPAT.1` — whether 4.0.0 serves the 2026 revision — asked of the operator on 2026-09-02,
answered **serve it in this release**, not advertise-only and not drop the advertisement.

The question was put as "does the revision join `SUPPORTED_VERSIONS`", and that half was not the
operator's to answer. Checked at the specification the same day: the 2026-07-28 lifecycle scopes
`initialize` to "`2025-11-25` and earlier", so the constant stays legacy-only whatever the operator
rules, and what the ruling settles is the `server.modern_protocol` default alone. The gate is
defined once, in `docs/requirements/RELEASE-4.0.0-blocking-rollup.md` under "The two gates that are
not rows".

What it changes: cluster A moves onto the critical path for the whole release rather than being the
largest of several parallel tracks. A served revision is one the continuation envelope has to
actually carry, so nothing in C or D can be finished ahead of it, and the release cannot go out on
the work already done. It also settles the audits' central complaint — a revision announced by
`discover_document` and refused at the door — by closing the gap from the serving side instead of
retracting the announcement.

The other three remain open and remain operator calls, not engineering: whether
`exposed_meta_tools` enforcement ships as a breaking change, whether a dual-role compatibility
matrix is required for 4.0.0, and whether the 17-tool scenario or the documented 14-16 ceiling is
the number that moves.

### A second cluster-F decision is now made

`NFR.COMPAT.3` -- whether `exposed_meta_tools` enforcement ships as a breaking change -- asked of
the operator on 2026-09-02, answered **enforce now and accept the break**. The alternatives put were
a warn-in-4.0/enforce-in-4.1 deprecation, a second opt-in flag governing the first, and dropping the
field outright.

What it changes: the criterion is waived rather than met, and the ledger row now says so in those
words. This is not the same as the requirement being satisfied, and writing it down as N/A without
the reason would have hidden a real break behind a status code. An operator who set
`exposed_meta_tools` and upgrades without editing anything will lose tools that used to answer.
Two obligations transfer to the release in exchange: the break stays named in the release notes
where `docs/release/v4.0.0-release-notes-DRAFT.md:38` already names it, and the upgrade path has to
tell an operator *which* tools they will stop seeing -- a warning that a field is now enforced is
useless without the list it now restricts.

Two decisions remain open, and both are operator calls rather than engineering: whether a dual-role
**BOTH CLOSED 2026-09-02. Cluster F holds no open operator calls.** `NFR.COMPAT.4`: role clause stays
unqualified, inapplicability recorded at the matrix cell. `NFR.PERF.4`: the 14-16 ceiling stands and
`gateway_webhook_status` stops counting against it. Both become implementation work. Original framing kept below.

compatibility matrix is required for 4.0.0 (`NFR.COMPAT.4`), and whether the 17-tool scenario or the
documented 14-16 ceiling is the number that moves (`NFR.PERF.4`).

### Cluster F decision 3 — the criterion has a defect, and repairing it is the operator's call

**RULED 2026-09-02: the role clause stays unqualified; inapplicability is recorded at the matrix cell
under `NO-SURFACE-IN-ROLE`. Cluster F decision 3 is closed.** The reasoning that produced the
question is kept below because it names what the ruling decided against.

`NFR.COMPAT.4` was listed above as an operator call: *is a dual-role compatibility matrix required
for 4.0.0?* Half of that question is already answered and half is sharper than it was.

**Answered, without a decision.** Release acceptance condition 2 already requires the conformance
matrix — one row per normative statement, crossed with role, transport, revision and outcome, with
no empty evidence cell. The matrix is required and has been since the requirements were written.
`NFR.COMPAT.4` was naming a second artifact for evidence the matrix already carries, so the row now
points at the matrix. That changes where evidence lives, not what is demanded.

**Still open, and now named.** The criterion demands verification in **both** roles without
qualification while qualifying transports with *that implements it*. A requirement with no
client-role manifestation therefore cannot satisfy it by any amount of work — the criterion is
undecidable for server-only requirements, and every one of them is scored against it.

The obvious repair is to qualify the role clause the same way. It was drafted and reverted before it
shipped, for a reason worth stating: *who decides whether a requirement has a client-role
manifestation?* The implementer does, in the same pass that fills the matrix. A gap that closes
because the person filling the cell judged the role inapplicable is a gap closed by definition, and
the operator asked for gaps fixed. Two candidate resolutions, and the operator picks:

| option | what it costs | what it risks |
|---|---|---|
| qualify the role clause — *in each role that implements it* | one edit; server-only rows become decidable | self-graded scope: the implementer decides what has no client manifestation |
| leave it absolute, and let §9 acceptance 1 carry N/A-with-reason at the matrix cell | no edit; the judgement moves to a cell a reviewer reads | the criterion stays literally unsatisfiable, so its status is argued rather than read |

Recommendation: **the second.** The judgement cannot be removed — something must decide that
`NFR.SEC.2` has no client-role half — but at the matrix cell it is written down with its reason and
a reviewer sees it, whereas in the criterion it is exercised silently and leaves no trace. §9
acceptance 1 already provides the mechanism, so this option adds nothing to maintain.

What remains ABSENT either way is the matrix itself, and that was never optional.

Cluster F therefore keeps two open operator calls, not one: this, and whether the 17-tool scenario
or the documented 14-16 ceiling is the number that moves (`NFR.PERF.4`).

**A second defect the same reading found.** The test plan defined the matrix as *one row per
normative statement in the 2026-07-28 changelog*. Release acceptance 2 says *one row per normative
statement*. The narrower population drops `NFR.COMPAT.1` and `NFR.COMPAT.2` — both are about
revisions older than 2026-07-28, so neither is a statement the changelog contains — and those two
rows are backward compatibility, where a missing role cell costs most. The test plan is corrected to
the requirements' population. This one was a straightforward inconsistency between two documents, so
it is repaired rather than raised.

### Meta-tool consolidation — analysed, and smaller than it looks

Asked in service of `NFR.PERF.4`: can the meta-tool surface be cut by merging tools? Three candidate
clusters, one survivor.

`gateway_search`/`gateway_execute` are **not** duplicates of `gateway_search_tools`/`gateway_invoke`.
They are the Code Mode surface (`src/gateway/meta_mcp_tool_defs.rs:720-730`) — two tools exposed
*instead of* the standard surface, not alongside it. The 19 names in that file are 17 standard plus
2 Code Mode, and there is no free deduplication.

| cluster | tools | slots saved | verdict |
|---|---|---|---|
| status | `get_stats`, `cost_report`, `webhook_status`, `list_disabled_capabilities` | 3 at most, 1 in the minimal 14-tool scenario | viable — all four take no arguments, so a merged `gateway_status(section)` has a flat schema with nothing conditionally required |
| admin | `kill_server`, `revive_server`, `reload_config`, `reload_capabilities`, `set_state` | 4, always present | rejected — kill and revive need a server id, `set_state` needs a state, the reloads need nothing. Merging makes required-ness depend on the action, which is the shape the flat-argument principle exists to avoid |
| profiles | `list_profiles`, `get_profile`, `set_profile` | 2, `tool-profiles`-gated | rejected on the same ground, and it saves nothing in the minimal scenario |

The honest figure is 1-3 tools off a 14-17 tool surface. The 14/16/17 spread is feature gating, and
two of the three mergeable status tools are themselves gated — the merge saves least exactly where
the surface is already smallest.

Recommendation, put to the operator and not yet answered: **status cluster only, after 4.0.0.** A
1-3 slot win does not justify a design event and its review rounds while blocking rows are open.
The counter-argument is real and is the operator's to weigh: 4.0.0 already breaks this surface
through `exposed_meta_tools` enforcement, and a surface that breaks once is cheaper for consumers
than one that breaks twice.

## 5. State on 2026-09-03 — cluster A reached its second step, and the review pair is down to one leg

Three things moved in a day. None of them is implementation.

### Cluster A is now at "failing tests", not at "designs done"

`tests/mik_7212_mrtr_component_acs.rs` exists on `fix/mrtr2-continuation-handle` and holds 13
component-level acceptance cases (`0b200023`, `8b6d771e`). Twelve are red. That is the prescribed
state, not a regression: the sequence section above says test plan, then failing tests reviewed as
tests, then implementation which is done when they pass. Reading those twelve as breakage is the
misreading to guard against — they are the specification, asserted before the code exists.

What this changes about the order: cluster A's remaining cost is now implementation against a
written spec rather than implementation plus discovering what the spec is. Section 4 said the first
step was not code. That step is taken.

Two limits on the claim. The component tests exercise components, so passing them is necessary and
not sufficient — `handlers.rs` still refuses every retry, and a dispatcher-level case is what
proves the refusal is gone. And the file is another session's in-flight work; the count above is
what the branch holds, not a promise about what it will hold.

### The dual-vendor review pair has one working leg

Section 4 records the pair as Grok plus Kimi until 2026-09-07, because the GPT reviewer is
usage-limited. Grok is now returning HTTP 402 as well. For work this agent authors, `claude-review`
is barred — that is the author reviewing the author — which leaves Kimi alone.

This is not a code problem and it blocks code rows anyway. **No criterion can move to MET on review
evidence while the pair cannot be assembled**, because the gate wants two independent vendors and
one is not two. The rows it holds are every row whose remaining work is a verdict rather than an
implementation, `CONFIRM.1a` among them.

Two ways out, and the choice is the operator's: wait for the GPT limit to lift on 2026-09-07 and
accept that verdict-blocked rows idle until then, or restore a second paid leg now. Nothing else in
the plan changes either way — the implementation clusters keep running, they just cannot close.

### `CONFIRM.1a` — the test now compares two refusals instead of transcribing one

The stdio-refusal case asserted a literal error string, and the literal had gone stale against the
wording the production path actually emits. It now calls the live fallback in the same test and
asserts the two refusals agree, with the falsifier recorded: appending a marker at the hidden site
breaks the comparison (`97ecabf4`). The row stays PARTIAL, held by the paragraph above and by
nothing else.

### What did not move

Everything else. The ledger is unchanged, no blocking row flipped to MET, and section 4's ordering
stands: cluster A first, with E (Spark measurement), B's consuming side and F's operator decisions
running alongside; C and D after A, because they need a served modern request path to test against.
