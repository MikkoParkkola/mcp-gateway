# DoD check — MCP 2026-07-28 support (branch `feat/mcp-2026-protocol`)

**Date**: 2026-08-29 · **Base**: `main` at 3.5.0 (`cdd52622`) · **Head**: `fa811e4b`
**Requirements**: `RELEASE-4.0.0-requirements.md` · **Plan**: `RELEASE-4.0.0-test-plan.md`

Gates were **run**, not asserted. Where a verdict is N/A it carries its reason, because an N/A
without one is a skipped gate wearing a label. Where a gate was run against an *earlier* commit than
the head, that is said in the same line rather than rounded up.

## Verdict, first

**The branch does not meet the Definition of Done for a 4.0.0 tag, and the gap is larger than the
previous revision of this document claimed.** It is sound as an increment behind a switch that
defaults off. It is not a shippable modern protocol implementation.

**HEAD contains code that has never been compiled.** Commit `2c774d4c` changes the mirrored-header
security check — the field it validates and its handling of repeated header lines — and was authored
while the machine's build guard blocked every `cargo` command. It is committed so the work is
durable, not because it is verified. Nothing in this document should be read as evidence about that
commit until the gates are re-run against it.

Two things changed the picture since the last revision, both from review:

1. Independent review of the transport wiring returned **ten findings — one CRITICAL and seven
   HIGH, every one rated CERTAIN**. None is gated NOW *only* because `server.modern_protocol`
   defaults off. Four are gated BEFORE-DEPLOY.
2. Two surfaces this document previously recorded as **wired** are reachable and hollow. That is a
   correction to this document's own record, not a new regression.

Detail below.

## §3 Static checks — PASS at `c850cdc4`, unverified at head

| Gate | Command | Result |
|---|---|---|
| Linter | `cargo clippy --all-targets -- -D warnings` | 0 warnings |
| Formatter | `cargo fmt --check` | clean |
| Secret scan | private-key / API-key patterns over the branch diff | 0 |

The head commit `a2319c8c` adds an envelope size bound and removes a constructor. Its own test
module passes (50/50). **The full suite and the linter have not been run against it**: the machine's
build guard halted all `cargo` commands at 4.6 GB free disk, and clearing another session's build
cache was not mine to decide. Stated rather than assumed away.

## §4 Testing — PASS at `c850cdc4`, partially verified at head

- **4,456 tests passing across 45 binaries, 0 failing** — measured at `c850cdc4`, not quoted from a previous run.
- **41 doc-tests pass.**
- **23 tests are `#[ignore]`d.** Twelve are doc-test examples and ten are pre-existing integration tests needing Docker or a live API. **One is this branch's**: `ac_discover_1_advertises_the_target_revision`, which asserts the gateway advertises 2026-07-28 — deliberately false while the switch is off. The previous revision of this document said "one test is ignored" and meant one of *mine*; as written it was a false claim about the suite, and this corrects it.

### Falsification — every control was made to fail, and two could not be

The rule this release ran on: a control you cannot make fail is not a control. Thirty-one probes
across the branch. The fourteen from earlier increments are unchanged; the thirteen run against this
round's security repairs are below, each failing **only** the rows that observe it.

| Control | Probe | Rows that failed |
|---|---|---|
| `Payload` redaction | `Debug` derived again | 1 |
| Routing under contention | `route` back to `try_lock` → `Gone` | 1 |
| Explicit completion | `complete` releases nothing | 2 |
| Ledger capacity policy | evict the soonest live entry again | 1 |
| Keyring construction | duplicate key ids allowed | 1 |
| Client-facing error | internal cause leaked into the message | 1 |
| Mint budget | budget never exhausts | 2 |
| Mint budget | ceiling clamp removed | 1 |
| Mint budget | counter never advances | 3 |
| Envelope bound, opening | size check removed | 1 |
| Envelope bound, minting | size check removed | 1 |
| Envelope bound, value | bound lowered below real backend state | 13 — it is load-bearing on the ordinary path |

**Two probes exposed holes in the controls rather than in the code**, which is the point of running
them:

- The **mint budget shipped with no control at all**. The first probe disabled it and nothing failed. The bound was 2^32 envelopes, which no test can reach, so it was untestable by construction. It now has a clamped builder and a remaining-budget reader, and three probes that fail.
- The **constant-time comparison has no honest failing row, and this is recorded rather than papered over**. Reverting `redeemable_by` to the short-circuiting slice comparison passes all rows — verified by running it, not assumed. A unit test cannot observe timing. The behavioural row beside it was renamed to `a_wrong_binding_of_any_length_is_refused_identically`, which is what it actually proves; the timing property itself is assured by reading the code, and that is a weaker assurance, stated as one.

## §5 Change safety — PASS

Every modern behaviour has a **legacy regression row** beside it: session header still sent, `ping`
still served, `initialize` byte-identical against a captured golden per revision, no `resultType` or
`_meta` added to a 2025 result, headers not required of a client that never sent one. The legacy
path is the thing most likely to break, so it is the thing most tested.

## §8 Security — PASS on tooling, with open findings below

- `cargo audit`: **0 vulnerabilities**, 425 dependencies. One `yanked` warning, identical on `main`.
- `#![deny(unsafe_code)]` holds; no dependency added.
- Nine security findings from review were closed in this round; three remain open and are listed below.

## §12 Review — one vendor, three rounds, findings recorded

The operator set single-vendor review (codex/gpt) for this session, so the dual-vendor gate is
**deliberately not met** and this is a known, authorised deviation rather than a passed gate.

Reviews are chunked per module. An earlier attempt sent the whole 2,893-line diff and died at zero
bytes five times; the cause was payload size, diagnosed by a minimal smoke test returning in seconds.

| Round | Material | Findings | Verdict |
|---|---|---|---|
| 1 | `src/protocol/continuation.rs` | 7 — 3 CRITICAL, 2 HIGH, 1 MEDIUM, 1 LOW | SHIP-WITH-FIXES |
| 2 | repairs to round 1 | 1 CRITICAL (BEFORE-PRODUCTION) | **SHIP** |
| 3 | `src/gateway/router/handlers.rs` | 10 — 1 CRITICAL, 7 HIGH, 2 MEDIUM, all CERTAIN | SHIP (none gated NOW) |

**A process failure worth recording**: round 1's findings were first read from a truncated tool
output showing only the last three. Work proceeded on three findings while four — including two
CRITICAL — sat unread in the authoritative run file. They were found only when that file was opened
directly. The lesson is the one already written down: read the source, not a rendering of it.

### Round 1 and 2 — disposition of all eight

Nine repairs, each with a probe above, re-checked by the vendor that raised them (**SHIP**):

| Finding | Repair |
|---|---|
| CRITICAL — ledger evicts a live entry at capacity | refuses instead, reclaiming only entries past a deadline |
| CRITICAL — `for_test()` ships a publicly known key in production builds | constructor deleted; tests build their own keyring |
| CRITICAL — process-local ledger across replicas | **open**, gated BEFORE-PRODUCTION, documented in the module |
| HIGH — `open` decodes an unbounded client token | 8 KiB bound checked before decoding, enforced at both ends |
| HIGH — `Payload` derives `Debug` over sealed state | hand-written redacting `Debug` |
| MEDIUM — `route` maps lock contention to `Gone` | awaits the lock; the old code contradicted its own comment |
| LOW — binding comparison short-circuits on length | compares SHA-256 digests of both sides |
| (round 2) CRITICAL — mint budget resets on restart | **open**, gated BEFORE-PRODUCTION; the doc comment that overclaimed a per-key guarantee was corrected to say it bounds one process |

Four improvements were also taken: per-key mint budget, explicit completion release, duplicate-key-id
rejection, and one generic client-facing refusal message.

## What is honestly NOT finished

Stated plainly, because a DoD report that hides its gaps is worth less than no report.

### 1. Two surfaces are reachable and hollow — a correction to this document

The previous revision recorded `subscriptions/listen` and `tasks/get` as **wired**. They are
reachable, and they do not work. Verified at source, not inferred:

- `subscriptions/listen` (`handlers.rs:641`) parses the request, **discards it** (`Some(_)`), mints an id and returns an ordinary JSON-RPC success. There is no stream and no filter registration. The comment beside it describes a design that was not built.
- `tasks/get` (`handlers.rs:670`) returns `{"status": "not_found"}` as a **success** for every handle. There is no task store, and `not_found` is not in the protocol's task model. `tasks/update` does not exist.

Moving these from unreachable to reachable-and-plausible is arguably worse than leaving them out: a
client can now call them and receive an answer that looks like an answer.

### 2. The modern request path has a classification bypass

`classify_request` reads the **body only** (`handlers.rs:513`). A request carrying modern routing
headers with no body metadata classifies as legacy, bypassing the feature gate and all header/body
mirror validation — so upstream policy can authorise one method while the gateway executes another.
CRITICAL, CERTAIN, gated BEFORE-DEPLOY.

### 3. Retry fields are forwarded at the wrong level — the defect this ticket was filed for

`handlers.rs:716` inserts `inputResponses` and `requestState` **into the `arguments` object**. The
specification makes them siblings of `name` and `arguments`. So continuations fail, and a tool with
legitimate arguments of those names has them overwritten. The code comment justifies the placement
as avoiding a widened signature — a design decision taken during implementation and never named as
one, which is precisely the failure mode `development-process.md` §P3 exists to catch.

### 4. Five further HIGH findings, all CERTAIN, gated BEFORE-PRODUCTION

`resultType` unconditionally overwritten with `complete`; modern destructive calls execute when
confirmation is `Unsupported`; every sessionless modern request creates an unreachable multiplexer
session and defeats sequence anomaly detection; enabling the switch does not add 2026-07-28 to
`server/discover`; notifications return 202 before any modern validation runs.

### 5. Two shared-state gaps block multi-replica production

The consumed-continuation ledger and the mint counter are both process-local. Documented in the
module, gated BEFORE-PRODUCTION, and not addressable inside this change.

### 6. The dual-vendor review gate is not met

Single-vendor by operator instruction for this session. An authorised deviation, not a pass.

## What this means for the release

`server.modern_protocol` defaulting to **off** is what makes the above an honest state rather than a
broken one: no client can reach any of it. That is also the only thing holding eight CERTAIN defects
away from users, which is a thinner margin than "the switch is off" sounds.

**Not ready to tag.** The 2025 path is unchanged and fully tested and could ship today; the 2026 path
needs items 1–4 closed and re-reviewed. The realistic options are to ship 4.0.0 as the legacy-safe
groundwork with the modern path documented as preview, or to hold the tag until the transport
findings are closed. That is a scope decision, and it is the operator's.

---

## Rounds 4–7 — and the root cause they expose

Four further module reviews returned **eighteen more findings**, every one gated NOW.

| Round | Material | Findings | Verdict |
|---|---|---|---|
| 4 | `meta.rs` + `era.rs` (the era classifier) | 5 — 2 HIGH, 3 MEDIUM | SHIP-WITH-FIXES |
| 5 | `headers.rs` + `mrtr.rs` | 3 — 2 CRITICAL, 1 HIGH | SHIP-WITH-FIXES |
| 6 | `subscriptions.rs` + `tasks.rs` + `extensions.rs` | 7 — 4 HIGH, 2 MEDIUM, 1 LOW | SHIP-WITH-FIXES |
| 7 | the security controls | 3 — all HIGH | SHIP-WITH-FIXES |

### The root cause: three protocol areas were built without their specification

This is the finding that matters, and it was found by checking a reviewer's claim at source
rather than by accepting it.

**The subscription model is wrong in four independent ways, and the specification says so
directly.** Fetching `/specification/2026-07-28/basic/patterns/subscriptions` — a page that was
**never cached during implementation** — confirms all four:

| What the code does | What the specification says |
|---|---|
| parses filters at the `params` root | they nest under `params.notifications` |
| treats `resourceSubscriptions` as a boolean | it is an array of URI strings: `["file:///project/config.json"]` |
| mints a fresh `SubscriptionId` | *"The value is the JSON-RPC ID of the `subscriptions/listen` request"* |
| tags `_meta` at the notification root | the example puts it under `params._meta` |

The scratchpad holds seven cached specification pages. **There is no subscriptions page and no
tasks page**, and `spec-caching.md` is **0 bytes** — a fetch that returned nothing and was never
noticed, because nothing checked. Three protocol areas were implemented from the changelog and the
index rather than from their own pages.

**Why the conformance matrix did not catch this**: it compared the code against the requirements
document, and the requirements document was written from the same incomplete reading. Both agreed,
so the matrix went green. A conformance check that never reaches the specification is checking a
copy of its own assumptions — which is the same defect class as a fixture that reimplements the
production code it is meant to test, recorded earlier in this branch.

### What was checked and found sound

Not everything the reviewers raised survived contact with the source, and saying so is part of the record:

- **`cacheable.rs` is correct.** It defaults to `private`, which is the conservative direction: the specification confirms `public` responses "may be shared between callers even if the Result is coming from an authenticated endpoint". Its doc comment cites the schema, so despite the empty cached page it was not written from nothing. One real gap: the specification requires the same `cacheScope` across all pages of a paginated list, which is not implemented — though a uniform `private` default satisfies it by accident rather than by design.
- **The tasks findings are UNVERIFIED, not accepted.** The specification page for tasks returns 404 at the path the index itself links to. The reviewer's claims about required `createdAt`/`lastUpdatedAt`/`ttlMs` fields and `input_required`/`cancelled` states have no source this session could reach, so they are recorded as unverified rather than treated as fact.

### Two security controls fail open

- `firewall/mod.rs:346` converts an **unobservable** anomaly check into "no finding" and allows the request. A control that cannot observe its subject must refuse, not wave through — this is the exact failure mode already recorded in this repository's own lessons.
- `session_lifecycle.rs:83` retains every deadline when one key is tracked twice, so a stale deadline can reclaim refreshed state and run cleanup on a live caller.

## Revised verdict

**Not ready to tag, and further from ready than rounds 1–3 suggested.** Seven review rounds,
**thirty-six findings**.

The severity is not uniform across the three areas, and the earlier draft of this section
overstated it by treating them as one. Held to the same standard as everything else here:

| Area | State | Response |
|---|---|---|
| subscriptions | 4 defects **confirmed at the specification page** | **repair** — the page names each correct shape outright |
| caching | checked and **sound**; one paginated-scope gap | repair the gap |
| tasks | the specification page **404s at the path its own index links** | cannot be judged conformant or not; resolve the source first |

That is one module confirmed wrong, one confirmed right, and one with no reachable conformance
target. It supports **fixing subscriptions**, not rebuilding the surface: the mechanism is sound and
the four defects are local to it, which is the repair-protocol's own test for repairing rather than
eliminating. The one broadening that *is* warranted — re-read the whole subscriptions page against
the module, rather than fixing only the four defects a reviewer happened to catch.

**The process finding is the prize, not the protocol defects.** The conformance matrix compared the
code against a requirements document written from the same incomplete reading, so both agreed and
the matrix went green over four wire-format errors. Its remedy is to re-derive the matrix from the
specification pages themselves. That is worth more than any individual fix here, because it is what
allowed all four to pass unnoticed.

## The decision, which is the operator's

The 2025 path is unchanged, fully tested and shippable. `server.modern_protocol` defaults **off**,
and that already is the isolation — no client can reach any of the open findings. Two real options:

1. **Ship 4.0.0 as the legacy-safe groundwork**, modern path documented as preview with the findings listed. The default-off switch is what makes this honest.
2. **Hold the tag** until the transport findings and the subscription model are closed and re-reviewed.

Removing the modern path is *not* a third option worth its cost: the switch already achieves the
isolation removal would buy, and it would mean a large deletion on a branch that currently has
unbuilt code in it.
