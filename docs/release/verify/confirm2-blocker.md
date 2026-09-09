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
