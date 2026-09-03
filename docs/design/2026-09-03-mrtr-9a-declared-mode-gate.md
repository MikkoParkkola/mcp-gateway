# MRTR.9a — refusing a request in a mode the client never declared

Status: **design, submitted for review as a design.** No code exists for it, and none is proposed
here beyond the shape a reviewer needs to judge.

## Scope (§P0)

FOR: enforcing declared *modes* on requests the gateway relays to a client, and the shape a
declaration must have for that enforcement to be possible at all. The criterion is
`MIK-7212.MRTR.9a` — the gateway must never relay a request in a mode the client did not declare —
recorded ABSENT and blocking at `docs/requirements/RELEASE-4.0.0-criteria-status.md:128`.

OUT: MRTR.9's type half, which is met and closed (`e1713f64`); the continuation-envelope work on
this branch; every cluster other than `MIK-7212.MRTR.*`. Out-of-scope findings are named where they
touch this design and left where they are — none is repaired in passing.

## The problem, in one sentence

The gate compares a fully parsed request against a flattened list of capability *names*, so the
mode half of the comparison has nowhere to live.

The asymmetry matters, because it halves the change. The **request** side already carries its mode:
`undeclared` holds the whole request `Value` and reads `method` out of it
(`src/protocol/mrtr.rs:296-309`), with `params.mode` sitting beside it untouched. Only the
**declaration** side lost its structure — `classify_request` keeps the names of non-null entries and
discards the objects under them (`src/protocol/meta.rs:185-192`), so
`{"elicitation":{"form":{}}}` and `{"elicitation":{"form":{},"url":{}}}` are the same value by the
time any gate runs. The comparison is then `name == name`
(`src/protocol/mrtr.rs:302-306`), which no amount of care at the call site can make mode-aware.

This is not a newly discovered defect. `docs/design/2026-08-30-mrtr-wiring.md` DE-8 recorded it as a
decision that design made, in terms: a URL-mode question relayed to a form-only client "passes this
gate by construction — no code path can refuse it, because by the time the gate runs the mode is no
longer in the data." This document is the repair DE-8 deferred.

## What the specification requires

Fetched live from `https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation`
(HTTP 200, 2026-09-03). Four sentences bind this design, and they are separate sentences — a design
that normalises once will get one of them wrong.

1. Declaration is per request: clients supporting elicitation "**MUST** declare the `elicitation`
   capability in `_meta.io.modelcontextprotocol/clientCapabilities` on each request", with the modes
   as keys — `{"elicitation":{"form":{},"url":{}}}`.
2. Declaration default: "For backwards compatibility, an empty capabilities object is equivalent to
   declaring support for `form` mode only" — `"elicitation": {}` ≡ `{ "form": {} }`.
3. Request default: "servers **MAY** omit the `mode` field for form mode elicitation requests.
   Clients **MUST** treat requests without a `mode` field as form mode."
4. The obligation itself: "Servers **MUST NOT** send elicitation requests with modes that are not
   supported by the client." The gateway is the server in that sentence.

Plus one that decides an edge below: "Clients declaring the `elicitation` capability **MUST**
support at least one mode (`form` or `url`)."

Rules 2 and 3 both resolve to form mode and are still two rules: one is about an empty *capability
object*, the other about an absent *request field*. They are cited separately here so that an
implementation cannot satisfy both with a single default in one place.

## The constraint any option must satisfy

The flattening is not an oversight, and reversing it wholesale would reopen a decision that was made
deliberately. `src/protocol/meta.rs:58-70` records why the subtree is not retained: keeping the whole
`clientCapabilities` object "copied an attacker-sized, arbitrarily deep object out of every request,
on a path that runs before anything has decided the request is even wanted."

So the bar is not "keep more of the object". It is: **retain a bounded, fixed-vocabulary summary**.
Whatever is kept must have a size that does not depend on what the caller sent — a known set of
capability names, each carrying a known set of mode flags, unknown keys dropped at parse. Depth is
not retained; a small closed enumeration is.

## Options considered

### Where the mode is decided — at the declaration boundary, or at the relay site

**Rejected: decide at the relay site.** Leave the parse as it is, and have the gate reach for the
raw `_meta` object again when it needs a mode. The gate already receives enough context to do it,
and it changes nothing about the parsed type.

It is rejected for two reasons, and the second is the one that settles it. First, it re-reads
attacker-shaped JSON at a point far downstream of the parse, which is the arrangement
`meta.rs:58-70` exists to prevent — the depth bound would have to be re-established at a second
site, and a bound enforced twice is a bound that will disagree with itself. Second, it leaves the
defect *stateable*: with a name list and a raw object both in scope, a caller comparing only names
still compiles and still passes review, because nothing about the types says the comparison is
incomplete. Every future call site is a fresh opportunity to make the same mistake DE-8 recorded.

**Chosen: decide at the declaration boundary.** The parse produces a value that already knows which
modes were declared, and the comparison is performed by code that has both halves in hand.

### What the declaration becomes — a richer type, or a raw object consulted on demand

**Rejected: the raw JSON consulted on demand.** Same site as above, so the same objections, plus one
of its own — it makes the backwards-compatibility default (rule 2) a property of whoever reads the
object rather than of the value itself. Two readers, two defaults, and the disagreement is invisible.

**Chosen: the declaration type gains mode structure, and the comparison happens at one level.**
`declared_capabilities: Vec<String>` becomes a bounded typed summary — capability names, each with
the set of modes recognised for it. `Undeclared` is then decided by a single accessor that takes the
request and answers the whole question: capability and mode resolved in the same arm, with both
defaults applied where the value is built rather than where it is read.

**The elimination bar this is aiming at.** If the new type merely *exposes* mode information beside
the names, a name-only comparison still compiles, and the defect has been made detectable rather
than impossible. The finding could still be stated. The shape worth having is the one where there is
no accessor that answers half the question: `undeclared` takes the request and the declaration and
returns `Option<Undeclared>`, and nothing else on the declaration type is reachable from the gate.
Then "the gate compared names and ignored modes" is not a defect one can describe, because the code
it describes cannot be written.

**Why that is affordable here.** `declared_capabilities()` has exactly one non-test consumer:
`src/gateway/router/handlers.rs:693`, which copies it into `MetaMcpCallerContext.input_capabilities`
(`:1152`). Narrowing or retiring that accessor is a one-caller change in `src/`. The cost lands in
fixtures, not in production paths — see the coordination note below.

### Whether the rewrite is a design event

It is. Per `rules-source/workflows/development-process.md` §P3, a change that moves a type across
the boundary between what a parse produces and what a downstream module compares is a design
decision, not a convenience edit — which is why it is written here, before any code, rather than
noticed in a diff. It changes an observable contract (what the gateway refuses), so it does not
belong in an implementation commit that claims to be doing something else.

## The regression this design is most likely to cause

It is the inverse of the defect, and it is worth stating before the shape is settled: **an absent
capability is not an empty capability object.**

Rule 2 makes `"elicitation": {}` mean form mode. It says nothing about a request that never mentions
`elicitation` at all — that client declared nothing, and MRTR.9's type gate already refuses it. But
around twenty-two construction sites pass an empty `input_capabilities` slice, including stdio
(`src/gateway/server/mod.rs`, which has no per-request declaration to read) and legacy clients. If
the new type's empty or default value normalises to *form mode declared*, every one of those callers
silently acquires form-mode elicitation and the closed MRTR.9 refusal stops firing.

So the two states are distinct constructors in the value, not two spellings of the same thing:
nothing declared, and declared with an empty mode object. Only the second gets rule 2's default. A
type whose empty value is ambiguous between them re-opens a criterion that is currently met.

## A decision this design makes, with its warrant

**A declaration naming only unrecognised modes declares no mode, and every request under it is
refused.** For example `{"elicitation":{"voice":{}}}`.

Warrant: rule 2's default is scoped to an *empty* object, and this object is not empty; and the
specification states that a client declaring `elicitation` "**MUST** support at least one mode
(`form` or `url`)". A client sending only names the specification does not define has either
declared something the gateway cannot honour or is malformed, and inventing form-mode support on its
behalf is the overclaim rule 2 was written to bound.

Observable consequence, stated so it is not a surprise: such a client receives a refusal rather than
form-mode service it never asked for. No client in the field can depend on the current behaviour,
because the gateway does not read mode names at all today.

## Unknowns

Each is closed by a recorded answer, or deferred with the four fields §P1 requires. There is no
third state.

**Does the refusal payload need a new shape to name a mode?** — checkable.
Question: what consumes the `requiredCapabilities` field the existing refusal emits, and would
naming a mode in it break a parser?
Ran: a repository search for `REQUIRED_CAPABILITIES_DATA_KEY` and `requiredCapabilities`.
Came back: the key is defined once (`src/gateway/meta_mcp/invoke.rs:626`), written once with a
one-element array (`:649`), and forwarded verbatim by `error_response_preserving_status`
(`src/gateway/meta_mcp/mod.rs:194-197`). Nothing in the gateway parses its contents; the only
readers are two tests asserting on a value they construct.
What it changed: it removed a supposed constraint. A mode refusal can name what it refused without
inventing a mechanism, because `Undeclared` already carries `key`, `method` and `capability`
separately (`src/protocol/mrtr.rs:319-329`) and the payload has no downstream parser to break.
Note the contrast with the continuation path, where `client_message()` deliberately collapses every
variant to one constant (`src/protocol/continuation.rs:234-236`). That collapse is a property of
*that* refusal, not of this one, and this design does not extend it.

**Does the declaration shape depend on the negotiated protocol version?** — checkable.
Question: which requests can carry a mode declaration at all?
Ran: read `classify_request` and `RequestShape` (`src/protocol/meta.rs:185-280`).
Came back: the version argument already selects between the modern `_meta` shape and Legacy, and
Legacy yields an empty declaration.
What it changed: nothing structural — mode parsing lives inside the branch that already handles the
2026-07-28 shape, and legacy clients keep being refused by the type gate.

**Does the refused-mode case belong to DE-9's open error-code question?** — deferred.
A request naming an undefined mode (`"mode":"voice"`) is a new instance of the question DE-9 left
open: `-32021` reads as *capability missing*, which is the wrong reason for *this is not a thing*.
DE-8 recorded in writing that the error-code change "travels with `MRTR.9a`" — so either it lands
with this work, or that recorded promise becomes false and something has to say so.

| field | answer |
|---|---|
| owner | cluster lead, as a scope call on this change |
| what would resolve it | a decision either to widen this change's §P0 FOR to include the refusal's error code, or to re-defer DE-9 with a note that its stated carrier has passed |
| when | before the test plan row for this criterion is written — the plan's assertions differ by the answer |
| what if it resolves badly | excluding the code change ships a refusal correct in behaviour and misleading in code, and DE-9's finding #2 stays open against a second document |

Recorded rather than assumed: the behaviour is the same either way. Only what a client reads off the
error changes.

## Coordination — what the chosen shape invalidates

Retyping the declaration breaks fixtures that construct or assert on the flat list, for reasons
unrelated to what those fixtures are testing. Naming them is this document's deliverable; changing
them is not, because they belong to another change in flight.

- `tests/mik_7212_acs.rs` — the `elicitation_mode_gate` fixtures call
  `classify_request(...).declared_capabilities()` and assert the result equals `["elicitation"]`.
  Those two cases are the RED test for this criterion, and the accessor they use is the one this
  design narrows. They break on the type, not on their own assertion.
- `src/gateway/meta_mcp/mod.rs` — `MetaMcpCallerContext.input_capabilities: &'a [String]` is the
  field the new type replaces, and every construction site follows it.
- Roughly twenty-two construction sites across `src/gateway/router/`, `src/gateway/server/`,
  `src/gateway/meta_mcp/` and the integration tests pass an empty slice today; each becomes an
  explicit "declared nothing" under the shape above.

Sequencing is the lead's call. The point of listing them is that the fixture cost is concentrated in
files this change does not own, so it cannot be absorbed quietly inside an implementation commit.

## What this design does not decide

The test plan. `docs/design/2026-09-02-mrtr-test-plan.md:34` already names the row — a form-only
declaration driven to relay a URL-mode elicitation, plus an empty declaration for the default and a
declared-mode positive control, at component level, at the wire. Two cases this design adds to that
row: the absent-versus-empty pair from the regression section, and the unrecognised-mode-only
declaration. Both are written as a plan under §P2 before any test code, not here.

## Findings named and left

Neither is repaired by this change; both are recorded so they are not rediscovered as new.

- DE-9's finding #2 — an unrecognised method refused with `-32021` — is the deferred unknown above,
  and it is the only one of the two that this change can be argued to carry.
- `docs/design/2026-08-30-mrtr-wiring.md` DE-9a's observation about `client_message()` costing tests
  their oracle belongs to the continuation refusal contract, which is out of scope here and is left
  untouched by every option considered above.
