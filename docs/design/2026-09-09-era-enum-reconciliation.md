# Design — reconciling the two `Era` enums

- Date: 2026-09-09
- Anchor commit: `5659af11cb634d43018cf5c694ef46768fa25d79` (every `path:line` below is read at that SHA, not at the working tree — three lanes are editing `src/gateway/router/handlers.rs` concurrently)
- Status: proposal, docs only. No code changed by this document.

## Verdict

**The two enums are not duplicates, and this design rejects the merge.** They model two
different things about two different processes. What is duplicated is the *name*, and the
name is what this design changes.

- `src/protocol/era.rs:25` `pub enum Era` — an **outbound, per-backend, probed belief** about
  the process on the other end of a transport.
- `src/protocol/meta.rs:106` `pub enum Era` — an **inbound, per-request, declared** fact about
  the message currently being handled.

Proposal: rename `protocol::era::Era` to `PeerEra` and `protocol::meta::Era` to `RequestEra`.
Both survive. Variant names (`Modern`, `Legacy`) do not change.

## What the request premise got right, and where it is wrong

The premise was that the two enums meet in `src/gateway/router/handlers.rs`. They do not.
At the anchor SHA, `handlers.rs` touches `protocol::era` only for two **constants**:

- `src/gateway/router/handlers.rs:287` — `crate::protocol::era::UNSUPPORTED_PROTOCOL_VERSION`
- `src/gateway/router/handlers.rs:992` — `crate::protocol::era::MISSING_REQUIRED_CLIENT_CAPABILITY`

The only `Era` **enum** in `handlers.rs` is the meta one:

- `src/gateway/router/handlers.rs:827` — `let is_modern = era == crate::protocol::meta::Era::Modern;`

So the collision in `handlers.rs` is between a module path and two error codes, not between
two types. No production file imports both enums. No conversion function between them exists.

One file does name both, in two separate `mod` blocks with no shared scope:
`tests/mik_7217_acs.rs:234` uses `meta::Era::Legacy`; `tests/mik_7217_acs.rs:487` and
`tests/mik_7217_acs.rs:625` import from `protocol::era`. That is a single ticket's acceptance
file covering both axes of MIK-7217, not a place where the values mix.

## Blast radius, per enum, at the anchor SHA

Counted by the module path plus the `use` site, because a bare `Era::Modern` in
`src/backend/era.rs` is the **peer** enum (`src/backend/era.rs:14` imports it).

| Enum | Production files | Test files |
|---|---|---|
| `protocol::era::Era` (peer) | `src/backend/era.rs`, `src/backend/lifecycle.rs`, `src/backend/mod.rs`, `src/transport/http/mod.rs` (`src/transport/http/mod.rs:29`), plus the two constants in `src/gateway/router/handlers.rs` | `tests/mik_7212_acs.rs`, `tests/mik_7213_acs.rs`, `tests/mik_7217_acs.rs`, `tests/mik_7217_era_probe_acs.rs`, `tests/nfr_compat1_revisions.rs` |
| `protocol::meta::Era` (request) | `src/gateway/meta_mcp/invoke.rs`, `src/gateway/meta_mcp/mod.rs`, `src/gateway/meta_mcp_helpers.rs`, `src/gateway/router/handlers.rs`, `src/gateway/server/mod.rs` | `src/gateway/meta_mcp/authz_tests.rs`, `src/gateway/meta_mcp/tests.rs`, `src/gateway/meta_mcp/trace_correlation_tests.rs`, `src/gateway/meta_mcp_helpers_tests.rs`, `src/gateway/router/tests.rs`, `tests/mik_7217_acs.rs`, `tests/stdio_tests.rs` |

The two sets of production files are disjoint apart from `handlers.rs`, and there the overlap
is the two constants.

## Why two exist: nine days apart, not one session

Corrected during review — the first draft of this section was wrong, and the correction
sharpens the argument rather than weakening it.

- `062f68e7` 2026-08-29 03:37:31 +0300 — `feat(protocol): classify a peer's protocol generation from one probe`. Creates `src/protocol/era.rs` with `pub enum Era`. Refs MIK-7217.DISCOVER.4.
- `5882f3e1` 2026-08-29 04:23:01 +0300 — `feat(protocol): tell a modern request from a legacy one, per request`. **Creates** `src/protocol/meta.rs` (139 lines, alongside `src/protocol/mod.rs` and `tests/mik_7215_acs.rs`). `src/protocol/meta.rs` does not exist at `062f68e7` — `git cat-file -e 062f68e7:src/protocol/meta.rs` fails.
- `71c5fbd4` 2026-09-07 08:32:18 +0300 — `feat(mik-7272.task.1.10b): serve the tasks extension from initialize`. **This** is the commit that adds `pub enum Era` and `fn era(&self)` to `src/protocol/meta.rs`. `git log -S'pub enum Era' -- src/protocol/meta.rs` names it and nothing else.

So the per-request era *concept* arrived 46 minutes after the peer era, but the second **type
named `Era`** arrived **nine days later**, in a commit whose headline subject is about serving
the tasks extension. The collision was introduced as a side effect of unrelated work, by an
author working in a tree where `protocol::era::Era` had been established for over a week.

That is a stronger case for the rename than the "same session, time pressure" story this
document first told: the name was not chosen under a deadline, it was chosen without anyone
looking. The doc comment at `src/protocol/meta.rs` gives the local reason the type exists —
a named two-variant type instead of a `bool` parameter, so that a call site reads as something
other than a bare `true` — and that reason is sound. It is orthogonal to what the type should
be called.

## The guarantee a merge would delete

Both enums have a field named exactly `era`, both `Copy`, both `Modern | Legacy`:

- `src/protocol/era.rs:461` — `pub era: Era` on `EraObservation`, a probed belief about a **backend process**.
- `src/gateway/meta_mcp/mod.rs:173` — `pub era: crate::protocol::meta::Era` on the invoke context, a **client's declaration** on one request.

Unify the type and `observation.era = ctx.era` compiles silently. Today the compiler refuses
it. That refusal is the load-bearing reason to keep two types: a peer's probed generation and
a request's declared generation are not interchangeable, and the type system is currently the
only thing saying so. This is the rejection reason, not a style preference.

## Options considered

**A. Merge into one enum, drop the other.** Rejected: deletes the compile-time separation
above. There is no call site that wants both, so the merge buys no call-site simplification —
it only removes a guard.

**B. Keep one enum, add a `newtype` wrapper on the other.** Rejected: a wrapper preserves the
guarantee but adds a conversion surface that nothing needs. No code converts between the two
today, and creating a legal conversion is exactly the thing that should stay illegal.

**C. Keep both, rename both. (Recommended.)** `PeerEra` and `RequestEra`. Preserves the
guarantee, removes the ambiguity a reader hits when `Era` in one file means something else in
the next, and needs no new code — only renames.

**D. Keep both, rename neither, document the difference.** Rejected as the primary plan, but
it is the fallback if the operator declines a semver-visible rename before 4.0.0 ships (see
"Open question"). The doc comments already distinguish them; the name still does not.

**E. Move the two error-code constants out of `protocol::era`.** Deferred, not rejected.
`UNSUPPORTED_PROTOCOL_VERSION` and `MISSING_REQUIRED_CLIENT_CAPABILITY` are request-side error
codes living in the peer-side module, which is the *actual* reason `handlers.rs` names
`protocol::era` at all. Worth its own change; keeping it out of the rename keeps the rename
mechanical.

## Duplication check: nominal only

`protocol::era::Era` carries `#[derive(..., serde::Serialize)]` at `src/protocol/era.rs:23`
with `#[serde(rename_all = "snake_case")]` at `src/protocol/era.rs:24`, and
`pub const fn as_str` at `src/protocol/era.rs:36` returning
`"modern"` / `"legacy"`. `protocol::meta::Era` carries neither.

A grep for the literals `"modern"` and `"legacy"` across `src/` finds the era spellings only at
`src/protocol/era.rs:38` and `src/protocol/era.rs:39`. Every other hit is an unrelated backend
name or a discovery stopword. **Nothing re-spells the request era as a string**, so there is no
duplicated method to consolidate. The duplication is the identifier `Era` and nothing else.

## Open question for the operator

`src/protocol/mod.rs` declares `pub mod era;` and `pub mod meta;`, and `src/lib.rs:65` declares
`pub mod protocol;`. Neither enum is re-exported at the crate root, but both are reachable as
`mcp_gateway::protocol::era::Era` and `mcp_gateway::protocol::meta::Era`. A rename is therefore
**semver-visible on a published crate heading into 4.0.0**.

Two ways to settle it, operator's call:

1. Rename now, inside the 4.0.0 major bump, where a breaking public-path change is free.
2. Defer to 4.1.0 with option D as the interim, if 4.0.0's public surface is already frozen.

3. Rename now **and** leave `#[deprecated] pub use PeerEra as Era;` in `src/protocol/era.rs`
   (and the matching alias in `src/protocol/meta.rs`). The old paths keep resolving with a
   warning, so the rename stops being semver-breaking at all and the freeze question
   dissolves. Costs two lines and a deprecation note in the changelog.

Option 3 is the recommendation if the operator wants this unblocked without a ruling; option 1
is cleaner if the 4.0.0 major bump is genuinely open. Either way the choice of *whether the
public path breaks* is the operator's, not this document's.

## Invariant the change must preserve

**Variant names are unchanged; only type names change.** `as_str` and the `serde` rename both
derive their output from the variant identifiers, so a careless rename of `Modern` or `Legacy`
would silently alter wire output and recorded observability labels. The test plan pins this.

## Review record — round 1

Two independent legs, both exit code 0, run on the design and test plan together.

| Leg | Verdict | Disposition |
|---|---|---|
| gpt-review | 3 findings, all MEDIUM / CERTAIN | 3 applied |
| kimi-review | SHIP-WITH-FIXES; 3 findings, 4 improvements | 3 applied, 4 applied |

Both legs independently found the same blocking defect: the test plan's row 3 forbade any diff
to two files that the rename must mechanically edit. Reworded to forbid assertion and
expected-string changes only.

gpt-review found the history section false. Verified at source and confirmed: `src/protocol/meta.rs`
does not exist at `062f68e7`, and `pub enum Era` entered it at `71c5fbd4` on 2026-09-07, not at
`5882f3e1` on 2026-08-29. The "46 minutes apart, same session" narrative was wrong and has been
replaced with the nine-day version, which argues the rename more strongly.

Both legs rejected the claim that pinning the two-type separation requires `trybuild`; a
`compile_fail` doctest does it dependency-free. Added as row 9 of the test plan.

Applied from kimi-review: the `#[deprecated] pub use` third path for the semver question;
`EraObservation` named as the top textual-rename hazard; `cargo public-api` added to the gates.

Not applied: kimi-review could not verify the line-level citations from its environment and
flagged them as unverified. They were re-verified at the anchor SHA during this round, and the
one inconsistency it did catch by inspection — the serde derive cited at `:23` in one document
and `:24` in the other — turned out to be two adjacent, correct lines, now cited explicitly as
both.

**Baseline disclosure:** the two documents were written before this review round. Nothing in
either document has been reviewed for a second round after the repairs above were applied.
