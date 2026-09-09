# MIK-7246.CONFIRM.2 — blocked: CONFIRM.1a asserts the opposite outcome for the same request

Status: STOPPED before any source edit, per the brief's "if an assertion contradicts the
design doc, STOP and report". Zero lines of `src/` changed by this lane.

## The contradiction

Three tests issue the SAME request and assert two incompatible outcomes.

| test | request | asserts |
|---|---|---|
| `tests/mik_7215_acs.rs:690-745` (CONFIRM.1a) | HTTP `tools/call`, `gateway_kill_server`, modern `_meta` with `clientCapabilities: {}`, `admin-key` | `/error/message` contains `none could be obtained` |
| `tests/mik_7215_acs.rs:965-992` (CONFIRM.1a row 17) | identical but for the sentinel string | same refusal |
| `tests/mik_7246_confirm2_acs.rs:70-106` (CONFIRM.2) | identical but for the sentinel string (`common::modern` emits the same `_meta`, `tests/common/mod.rs:31-39`) | `/result/resultType == "input_required"` |

Every discriminator the gate can see is equal: transport (HTTP `tools/call`), era
(`2026-07-28`), tool name, admin credential, and declared capabilities (`{}`). Only the
`server` argument string differs, and nothing reads it but
`describe_destructive_action` (`src/gateway/destructive_confirmation.rs:149-160`).

W4 of `docs/design/2026-09-09-confirm-2-in-band-schema-and-wiring.md:120-130` places
`InBand` on the HTTP path unconditionally. Under that wiring all three calls take the same
branch, so exactly one of the two criteria goes red whichever way the branch is built. This
is not a bug an implementation can route around.

## What the design says, and why it does not settle it

W5 (`:132-141`) orders the gate `describe → capability check (K3) → mint → ask`, and
constrains the capability refusal to remain a superset of the `none could be obtained`
sentence *because `mik_7215_acs.rs` closes CONFIRM.1a on that substring*. So the design is
aware of the coexistence and answers it with a capability check. But K3 (`:34`) names
`input_capabilities: Declared` and `retry: &RetryFields` as plumbing, not a predicate, and
two readings of "capability check" survive:

- **`Declared` reading** — refuse when the client declared nothing. CONFIRM.1a stays green;
  CONFIRM.2 can never go green, because its fixture declares `{}`.
- **identity reading** — refuse when `principal_fingerprint(caller.verified_identity)` is
  `None`, which is what `mint_continuation` already requires
  (`src/gateway/meta_mcp/invoke.rs:401-422`). CONFIRM.2 goes green; both CONFIRM.1a rows go
  red, since an admin-key caller has an identity.

Note the `Declared` gate that exists today — `interim.undeclared(caller.input_capabilities)`
(`src/protocol/mrtr.rs:302-327`) — governs relaying a **backend's** interim request to a
client. A gateway-authored confirmation question is not one, so that function does not
answer the question by itself.

## What the operator/lead must decide (one of)

1. **CONFIRM.1a's two modern rows are superseded.** CONFIRM.2 replaces the modern refusal
   with an ask; those rows move to a channel that genuinely cannot ask (stdio /
   `ConfirmationChannel::Unavailable`, which W4 leaves untouched) or are retired with the
   clause reopened deliberately.
2. **The ask is gated on a declaration.** CONFIRM.2's fixture must then declare that
   capability, i.e. `tests/mik_7246_confirm2_acs.rs` stops using bare `common::modern`. The
   design must also name the capability string, which it currently does not.

Either is a scope move under §P0 and a §P3 design event; neither is mine to take.

## Second, smaller finding (recorded, not acted on)

On the CONFIRM path the gate returns `None` and dispatch falls through to
`route_direct_backend_call` (`src/gateway/meta_mcp/mod.rs:1714`), whose
`route_retry_to_origin_backend` re-opens the very envelope the gate just spent
(`invoke.rs:582-599`) and routes to `payload.backend_id`. W3 (`:108-118`) answers this with
W1's typed `origin` on `Payload`, but `src/protocol/continuation.rs` is DO-NOT-EDIT in the
amendment and is under concurrent edit (` M`).

A local alternative needing no edit to that file: give the gate a three-outcome return
(`Refuse(response) | Proceed | ProceedConfirmed`) and skip `route_direct_backend_call`
entirely on `ProceedConfirmed`. Every tool the gate governs is a meta-tool
(`DESTRUCTIVE_META_TOOLS`, built from `meta_mcp_tool_defs.rs`), never a surfaced backend
tool, so skipping backend routing for a confirmed destructive call loses nothing and keeps
the spent token out of the redeem path on all three branches. Two call sites in
`src/gateway/meta_mcp/tests.rs:3708,3745` would need the new return type. The
design-rejected sentinel `backend_id` is NOT this.

## Adjudication of the second finding — reverted, scope held (2026-09-09)

The second finding above was acted on, then reverted in full. Recorded because the
reasoning, not the diff, is the durable part.

**The ordering claim in the finding is wrong.** The gate runs at
`src/gateway/meta_mcp/mod.rs:1709`; `route_direct_backend_call` at `:1731` is reached only
under `!confirmed_in_band`. The gate precedes the route and already excludes it on the
confirmed branch, so the spent envelope never reaches `route_retry_to_origin_backend` on
that path. The three-outcome `GateOutcome` alternative this note proposed is already in the
tree at `:1712-1714`/`:1730` with the two `tests.rs` call sites converted. The hazard is
closed; what was left was defence-in-depth, not a defect.

**What was built and then reverted.** A `ContinuationPurpose` (`Backend` |
`GatewayConfirmation`) sealed into `Payload`, threaded through both mint sites and both
redeem sites, refusing a cross-purpose presentation before the handle is spent. Reverted
for three independent reasons, any one sufficient:

1. It edits `src/protocol/continuation.rs`, which the amendment marks DO-NOT-EDIT and which
   was under concurrent edit. That is a scope marker, not a judgement call.
2. The in-tree `GateOutcome` alternative was chosen *because* that file is off-limits, and
   it already holds the same ground.
3. No test can be written that fails only for the absence of `purpose`: the payload's
   `original_request_digest` and `redeemable_by` already refuse a cross-presentation, so any
   such case would pass with the mechanism deleted. Under the standing constraint — every
   case must be able to fail only for the reason it names — the mechanism was unprovable as
   built, which is itself the argument against shipping it.

Two deviations the reverted work had taken, both undone with it: a flat `purpose` field
rather than W3's typed `origin`, and `VERSION` 1 → 2. `VERSION` is back to 1 and
`src/protocol/continuation.rs` is byte-identical to `HEAD`.

## The gap this leaves, and the test that would close it

Nothing pins `!confirmed_in_band` at `mod.rs:1730`. Delete that guard and a confirmed retry
falls through into backend routing, re-opens the envelope the gate has already spent, and
dies as a stale retry instead of running the approved action — a confirmed destructive
operation silently not performed, with no test observing it. `tests/mik_7246_confirm2_acs.rs`
covers the ask and the decline; the `true` → `ProceedConfirmed` arm is untested.

The discriminating case: answer the in-band ask with JSON `true`, assert the approved action
actually ran, and confirm the case goes red with the guard removed. Not written here — it
cannot be measured on this host (see below), and an unmeasured case in a destructive-guard
suite is exactly what this file argues against.

## Measurement status: none

`/System/Volumes/Data` is at 2.1G free against the build guard's 5G floor (it was 4.4G
earlier the same day and is falling). No `cargo` build, test, or clippy run was performed
for any claim on this page. `docs/requirements/RELEASE-4.0.0-criteria-status.md:249`
therefore stays `ABSENT`: the row is unmeasured, not closed.

## Third finding — CONFIRM.1a is now unreachable as written, and `for_modern()` is dead

Found while trying to repair `tests/mik_7215_acs.rs` for the era split, and it is the reason
that repair was withdrawn rather than committed. Read from source only; nothing was run.

The channel is chosen by era and only by era (`src/gateway/router/handlers.rs:1441-1451`):
`Era::Modern` gets `ConfirmationChannel::InBand`, `Era::Legacy` gets `Elicit { policy }`.
`confirmation_policy` is computed from `is_modern` at `:1378-1382`, and its only consumer in
the file is `policy: confirmation_policy` at `:1449` — inside the `Era::Legacy` arm. So on a
modern request the policy is built and discarded, and
`ConfirmationPolicy::for_modern()` (`REFUSE`) has no live consumer on the HTTP path. The
`policy.on_unconfirmable() == REFUSE` branch at `src/gateway/meta_mcp/mod.rs:2201-2204` is
reachable only with a legacy era, whose policy is `PROCEED_WITH_WARNING`; it therefore never
fires from this call site.

Consequences, both confirmed by reading the three sites:

- **A legacy destructive call proceeds.** `Unsupported` + `PROCEED_WITH_WARNING` falls
  through to `GateOutcome::Proceed` (`mod.rs:2201-2210`). It never emits `none could be
  obtained`. Re-labelling a CONFIRM.1a fixture as legacy to keep its refusal assertion alive
  therefore asserts an outcome the source cannot produce — the fix attempted here, and wrong.
- **A modern destructive call is asked, not refused.** So CONFIRM.1a's stated outcome is not
  produced by either era through `Elicit`. On HTTP, `none could be obtained` now survives in
  exactly one place: the `InBand` mint failing (`mod.rs:2141-2155`), i.e. an unnameable
  principal or no in-flight slot. `ConfirmationChannel::Unavailable` still refuses
  (`mod.rs:2135-2137`), but that is the stdio and server paths, not this row's.

Neither `HEAD` nor the withdrawn repair is right: `HEAD` asserts a modern refusal that the
in-band ask replaced, and the repair asserts a legacy refusal that the legacy policy
contradicts. The fixture CONFIRM.1a needs is one where the mint genuinely cannot happen —
an unnameable caller, or an exhausted in-flight table — and neither can be written blind,
because whether an admin-authorized caller can also be unnameable is a source question with
a compile behind it. The withdrawn diff is not preserved: the approach it took is the one
this section rejects, and the two candidate fixtures above are the whole of what a
build host would need.

Also unresolved and larger than a fixture: whether `for_modern()`'s refusal was meant to
survive the in-band ask at all. If it was, `handlers.rs:1441-1451` splits on era where it
should split on era *and* channel availability, and the dead `for_modern()` is the symptom.
That is a design question for the CONFIRM.2 author, not a test repair.
